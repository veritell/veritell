//! Session tokens and proof-of-work challenges.
//!
//! A token records that a client passed a challenge. It is:
//! - signed (HMAC-SHA256), so it cannot be forged;
//! - bound to the client's fingerprint, so it fails when copied elsewhere;
//! - budgeted, so one solved challenge buys a limited number of requests.
//!
//! PUBLIC API IS FIXED. Implement the bodies; do not change signatures.
//! All times are Unix seconds supplied by the caller (no clock access here).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

const SESSION_VERSION: u8 = 0x01;
const CHALLENGE_VERSION: u8 = 0x02;
const SESSION_PAYLOAD_LEN: usize = 53;
const CHALLENGE_PAYLOAD_LEN: usize = 42;
const MAC_LEN: usize = 32;
/// Upper bound on the length of any token/challenge string we will look at.
const MAX_WIRE_LEN: usize = 512;

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    // HMAC accepts keys of any length, so `new_from_slice` cannot fail; the
    // fallback is unreachable but keeps this panic-free.
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        return [0u8; 32];
    };
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for &b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

/// Strict lowercase hex decoder: rejects uppercase, odd length, anything else.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        }
    }
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    b.as_chunks::<2>().0.iter()
        .map(|p| Some((nibble(p[0])? << 4) | nibble(p[1])?))
        .collect()
}

/// `<hex payload>.<hex mac>` where the MAC covers the payload text as written.
fn sign(key: &[u8; 32], payload: &[u8]) -> String {
    let text = hex_encode(payload);
    let mac = hmac_sha256(key, text.as_bytes());
    let mut out = text;
    out.push('.');
    out.push_str(&hex_encode(&mac));
    out
}

/// Format check, signature check, then payload decode. Returns payload bytes.
fn open(key: &[u8; 32], wire: &str) -> Result<Vec<u8>, TokenError> {
    if wire.len() > MAX_WIRE_LEN {
        return Err(TokenError::Malformed);
    }
    let mut parts = wire.split('.');
    let (Some(payload), Some(mac), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(TokenError::Malformed);
    };
    if payload.is_empty() || mac.is_empty() {
        return Err(TokenError::Malformed);
    }
    let mac_bytes = hex_decode(mac).ok_or(TokenError::Malformed)?;
    if mac_bytes.len() != MAC_LEN {
        return Err(TokenError::Malformed);
    }
    let Ok(mut m) = HmacSha256::new_from_slice(key) else {
        return Err(TokenError::Malformed);
    };
    m.update(payload.as_bytes());
    m.verify_slice(&mac_bytes).map_err(|_| TokenError::BadSignature)?;
    hex_decode(payload).ok_or(TokenError::Malformed)
}

static ID_COUNTER: AtomicU64 = AtomicU64::new(0);

fn random_id(now: u64, binding: &Binding) -> [u8; 16] {
    let mut id = [0u8; 16];
    if getrandom::fill(&mut id).is_ok() {
        return id;
    }
    // Fallback if the OS RNG fails (should not happen): hash of the time, a
    // process-wide counter and the binding. Unique per call but predictable;
    // acceptable only because the id is not a secret (the MAC provides integrity).
    let n = ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut h = Sha256::new();
    h.update(now.to_be_bytes());
    h.update(n.to_be_bytes());
    h.update(binding.0);
    let d = h.finalize();
    id.copy_from_slice(&d[..16]);
    id
}

fn be_u64(b: &[u8]) -> Option<u64> {
    Some(u64::from_be_bytes(b.try_into().ok()?))
}

fn arr16(b: &[u8]) -> Option<[u8; 16]> {
    b.try_into().ok()
}

struct SessionPayload {
    id: [u8; 16],
    issued_at: u64,
    expires_at: u64,
    budget: u32,
    binding: [u8; 16],
}

fn parse_session(p: &[u8]) -> Option<SessionPayload> {
    if p.len() != SESSION_PAYLOAD_LEN || p.first() != Some(&SESSION_VERSION) {
        return None;
    }
    Some(SessionPayload {
        id: arr16(p.get(1..17)?)?,
        issued_at: be_u64(p.get(17..25)?)?,
        expires_at: be_u64(p.get(25..33)?)?,
        budget: u32::from_be_bytes(p.get(33..37)?.try_into().ok()?),
        binding: arr16(p.get(37..53)?)?,
    })
}

struct ChallengePayload {
    id: [u8; 16],
    expires_at: u64,
    difficulty: u8,
    binding: [u8; 16],
}

fn parse_challenge(p: &[u8]) -> Option<ChallengePayload> {
    if p.len() != CHALLENGE_PAYLOAD_LEN || p.first() != Some(&CHALLENGE_VERSION) {
        return None;
    }
    Some(ChallengePayload {
        id: arr16(p.get(1..17)?)?,
        expires_at: be_u64(p.get(17..25)?)?,
        difficulty: *p.get(25)?,
        binding: arr16(p.get(26..42)?)?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    /// The secret is shorter than 32 bytes.
    WeakSecret,
    /// Not in the expected format.
    Malformed,
    /// The MAC does not match: forged or tampered.
    BadSignature,
    /// Valid, but past `expires_at`.
    Expired,
    /// Valid, but issued to a different client.
    BindingMismatch,
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            TokenError::WeakSecret => "secret must be at least 32 bytes",
            TokenError::Malformed => "malformed token",
            TokenError::BadSignature => "bad signature",
            TokenError::Expired => "expired",
            TokenError::BindingMismatch => "issued to a different client",
        })
    }
}

impl std::error::Error for TokenError {}

/// Signing keys derived from one operator secret. Session tokens and
/// challenges use different derived keys so one can never be replayed as the other.
#[derive(Clone)]
pub struct Keys {
    session: [u8; 32],
    challenge: [u8; 32],
}

impl Keys {
    pub fn from_secret(secret: &[u8]) -> Result<Keys, TokenError> {
        if secret.len() < 32 {
            return Err(TokenError::WeakSecret);
        }
        Ok(Keys {
            session: hmac_sha256(secret, b"veritell/session/v1"),
            challenge: hmac_sha256(secret, b"veritell/challenge/v1"),
        })
    }
}

/// A 16-byte digest of what identifies a client at the network layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Binding(pub [u8; 16]);

impl Binding {
    /// SHA-256 over the JA4 string, the IP prefix (/24 for IPv4, /48 for IPv6)
    /// and the User-Agent, truncated to 16 bytes. Fields are length-prefixed so
    /// different inputs cannot collide by concatenation.
    pub fn derive(ja4: Option<&str>, ip: IpAddr, user_agent: Option<&str>) -> Binding {
        fn opt(h: &mut Sha256, v: Option<&str>) {
            match v {
                None => h.update([0u8]),
                Some(s) => {
                    h.update([1u8]);
                    // Lengths above u32::MAX cannot occur for real headers; clamp.
                    let len = u32::try_from(s.len()).unwrap_or(u32::MAX);
                    h.update(len.to_be_bytes());
                    h.update(s.as_bytes());
                }
            }
        }
        let mut h = Sha256::new();
        opt(&mut h, ja4);
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
            v4 => v4,
        };
        match ip {
            IpAddr::V4(a) => {
                h.update([4u8]);
                h.update(&a.octets()[..3]);
            }
            IpAddr::V6(a) => {
                h.update([6u8]);
                h.update(&a.octets()[..6]);
            }
        }
        opt(&mut h, user_agent);
        let d = h.finalize();
        let mut out = [0u8; 16];
        out.copy_from_slice(&d[..16]);
        Binding(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claims {
    /// Random per-token identifier; the key for budget accounting.
    pub id: [u8; 16],
    pub issued_at: u64,
    pub expires_at: u64,
    /// How many requests this token may be used for.
    pub budget: u32,
}

/// Issues a session token. The result contains only `[A-Za-z0-9_.-]`, so it
/// is safe as a cookie value.
pub fn issue(keys: &Keys, binding: &Binding, now: u64, ttl_secs: u64, budget: u32) -> String {
    let mut p = Vec::with_capacity(SESSION_PAYLOAD_LEN);
    p.push(SESSION_VERSION);
    p.extend_from_slice(&random_id(now, binding));
    p.extend_from_slice(&now.to_be_bytes());
    p.extend_from_slice(&now.saturating_add(ttl_secs).to_be_bytes());
    p.extend_from_slice(&budget.to_be_bytes());
    p.extend_from_slice(&binding.0);
    sign(&keys.session, &p)
}

/// Verifies a session token. Checks, in this order: format, signature,
/// expiry (`now >= expires_at` is expired), binding.
pub fn verify(
    keys: &Keys,
    token: &str,
    binding: &Binding,
    now: u64,
) -> Result<Claims, TokenError> {
    let payload = open(&keys.session, token)?;
    let p = parse_session(&payload).ok_or(TokenError::Malformed)?;
    if now >= p.expires_at {
        return Err(TokenError::Expired);
    }
    if p.binding != binding.0 {
        return Err(TokenError::BindingMismatch);
    }
    Ok(Claims {
        id: p.id,
        issued_at: p.issued_at,
        expires_at: p.expires_at,
        budget: p.budget,
    })
}

/// Counts uses per token id. Also used to make challenge solutions single-use
/// (a budget of 1).
pub trait BudgetStore: Send + Sync {
    /// Records one use of `id`. Returns `true` if this use is within `budget`,
    /// `false` if the budget is already spent. `expires_at` lets the store
    /// discard the entry later; `now` is the current time.
    fn consume(&self, id: &[u8; 16], budget: u32, expires_at: u64, now: u64) -> bool;
}

/// In-process store. Bounded: at capacity it first drops expired entries, and
/// if still full it refuses new ids (returns `false`) rather than growing.
pub struct MemoryBudgetStore {
    map: Mutex<HashMap<[u8; 16], (u32, u64)>>,
    max_entries: usize,
}

impl MemoryBudgetStore {
    pub fn new(max_entries: usize) -> Self {
        MemoryBudgetStore {
            map: Mutex::new(HashMap::new()),
            max_entries,
        }
    }

    pub fn len(&self) -> usize {
        self.map.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// What [`MemoryBudgetStore::try_consume`] did with one use.
///
/// `consume` (the [`BudgetStore`] method) says only yes or no, and so answers
/// "no" both for an id whose budget is spent and for a new id the store has
/// no room for. Those are different events: the first is a replay or an
/// overused token, the second is the store's own limit, which anyone can
/// reach by asking for enough fresh ids. A caller that punishes a client for
/// a "no" must use this method and punish only [`Consumed::Spent`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Consumed {
    /// The use was counted and is within the budget.
    Used,
    /// The id's budget was already spent (or the budget is 0).
    Spent,
    /// A new id, and the store is full of live entries: nothing was counted.
    Full,
}

impl MemoryBudgetStore {
    /// Records one use of `id`, as [`BudgetStore::consume`] does, and says
    /// which of the three outcomes it was.
    pub fn try_consume(&self, id: &[u8; 16], budget: u32, expires_at: u64, now: u64) -> Consumed {
        if budget == 0 {
            return Consumed::Spent;
        }
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((used, _)) = map.get_mut(id) {
            if *used < budget {
                *used = used.saturating_add(1);
                return Consumed::Used;
            }
            return Consumed::Spent;
        }
        if map.len() >= self.max_entries {
            map.retain(|_, (_, exp)| *exp > now);
            if map.len() >= self.max_entries {
                return Consumed::Full;
            }
        }
        map.insert(*id, (1, expires_at));
        Consumed::Used
    }
}

impl BudgetStore for MemoryBudgetStore {
    fn consume(&self, id: &[u8; 16], budget: u32, expires_at: u64, now: u64) -> bool {
        self.try_consume(id, budget, expires_at, now) == Consumed::Used
    }
}

mod snapshot;
pub use snapshot::SnapshotError;

pub mod pow {
    //! Proof of work: find `counter` such that
    //! `SHA-256(challenge_string || ":" || decimal(counter))` starts with at
    //! least `difficulty` zero bits. Imposes cost; proves nothing about humanity.

    use super::{
        hex_decode, open, parse_challenge, random_id, sign, Binding, Keys, Sha256, TokenError,
        CHALLENGE_VERSION,
    };
    use sha2::Digest;

    pub const MIN_DIFFICULTY: u8 = 8;
    pub const MAX_DIFFICULTY: u8 = 24;

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum PowError {
        /// The challenge string failed token checks.
        Challenge(TokenError),
        /// The counter does not meet the difficulty.
        WrongSolution,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Solved {
        /// Challenge identifier, to be recorded as used (budget 1).
        pub id: [u8; 16],
        pub expires_at: u64,
        pub difficulty: u8,
    }

    /// Issues a signed challenge. `difficulty_bits` is clamped to
    /// `MIN_DIFFICULTY..=MAX_DIFFICULTY`. The string contains only `[A-Za-z0-9_.-]`.
    pub fn issue_challenge(
        keys: &Keys,
        binding: &Binding,
        now: u64,
        ttl_secs: u64,
        difficulty_bits: u8,
    ) -> String {
        let difficulty = difficulty_bits.clamp(MIN_DIFFICULTY, MAX_DIFFICULTY);
        let mut p = Vec::with_capacity(super::CHALLENGE_PAYLOAD_LEN);
        p.push(CHALLENGE_VERSION);
        p.extend_from_slice(&random_id(now, binding));
        p.extend_from_slice(&now.saturating_add(ttl_secs).to_be_bytes());
        p.push(difficulty);
        p.extend_from_slice(&binding.0);
        sign(&keys.challenge, &p)
    }

    fn zero_bits_ok(challenge: &str, counter: u64, difficulty: u8) -> bool {
        let mut h = Sha256::new();
        h.update(challenge.as_bytes());
        h.update(b":");
        h.update(counter.to_string().as_bytes());
        let d = h.finalize();
        let mut need = u32::from(difficulty);
        for &b in d.iter() {
            if need == 0 {
                return true;
            }
            if need >= 8 {
                if b != 0 {
                    return false;
                }
                need -= 8;
            } else {
                return b.leading_zeros() >= need;
            }
        }
        need == 0
    }

    /// Verifies a solution. Checks the challenge (format, signature, expiry,
    /// binding) before spending any effort on the hash.
    pub fn verify_solution(
        keys: &Keys,
        challenge: &str,
        counter: u64,
        binding: &Binding,
        now: u64,
    ) -> Result<Solved, PowError> {
        let payload = open(&keys.challenge, challenge).map_err(PowError::Challenge)?;
        let p = parse_challenge(&payload).ok_or(PowError::Challenge(TokenError::Malformed))?;
        if now >= p.expires_at {
            return Err(PowError::Challenge(TokenError::Expired));
        }
        if p.binding != binding.0 {
            return Err(PowError::Challenge(TokenError::BindingMismatch));
        }
        if !zero_bits_ok(challenge, counter, p.difficulty) {
            return Err(PowError::WrongSolution);
        }
        Ok(Solved {
            id: p.id,
            expires_at: p.expires_at,
            difficulty: p.difficulty,
        })
    }

    /// The difficulty of a challenge this gateway issued, whatever else is
    /// wrong with it (expired, issued to another client, a wrong counter).
    /// `None` if the string is not a challenge signed with these keys, so a
    /// client cannot name its own difficulty. Used to set the next
    /// challenge after a failed attempt at the same level as the failed one.
    pub fn issued_difficulty(keys: &Keys, challenge: &str) -> Option<u8> {
        let payload = open(&keys.challenge, challenge).ok()?;
        parse_challenge(&payload).map(|p| p.difficulty)
    }

    /// Difficulty for a risk score (1 = certainly automated, 99 = clean):
    /// score >= 70 -> 8 bits, 40..=69 -> 14, 20..=39 -> 18, below 20 -> 20.
    pub fn difficulty_for_score(score: u8) -> u8 {
        match score {
            70..=u8::MAX => 8,
            40..=69 => 14,
            20..=39 => 18,
            _ => 20,
        }
    }

    /// Reference solver for tests and tools. Tries counters `0..max_iterations`.
    /// Does not check the signature.
    pub fn solve(challenge: &str, max_iterations: u64) -> Option<u64> {
        let difficulty = parse_unverified(challenge)?.difficulty;
        (0..max_iterations).find(|&c| zero_bits_ok(challenge, c, difficulty))
    }

    /// Parses a challenge string without checking its signature.
    fn parse_unverified(challenge: &str) -> Option<super::ChallengePayload> {
        if challenge.len() > super::MAX_WIRE_LEN {
            return None;
        }
        let mut parts = challenge.split('.');
        let (Some(payload), Some(mac), None) = (parts.next(), parts.next(), parts.next()) else {
            return None;
        };
        if payload.is_empty() || mac.is_empty() || hex_decode(mac)?.len() != super::MAC_LEN {
            return None;
        }
        parse_challenge(&hex_decode(payload)?)
    }

    /// Path the challenge page posts its solution to.
    pub const VERIFY_PATH: &str = "/__veritell/verify";

    /// A self-contained HTML page (inline script, no external resources) that
    /// solves `challenge` in the browser and POSTs a form to `VERIFY_PATH`
    /// with fields `challenge`, `counter` and `return_to`.
    ///
    /// `return_to` is where the visitor goes afterwards. It is only honoured
    /// when it is a same-origin path; anything else becomes `/`.
    pub fn challenge_page(challenge: &str, return_to: &str) -> String {
        let difficulty = parse_unverified(challenge).map_or(0, |p| p.difficulty);
        let challenge = escape_html(challenge);
        let return_to = escape_html(sanitize_return_to(return_to));
        let mut page = String::with_capacity(PAGE_TEMPLATE.len() + 512);
        for (i, part) in PAGE_TEMPLATE.split("{{SLOT}}").enumerate() {
            if i > 0 {
                match i {
                    1 => page.push_str(&difficulty.to_string()),
                    2 => page.push_str(&challenge),
                    _ => page.push_str(&return_to),
                }
            }
            page.push_str(part);
        }
        page
    }

    /// Escapes the five HTML-special characters for use in text or attributes.
    pub(crate) fn escape_html(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for c in s.chars() {
            match c {
                '&' => out.push_str("&amp;"),
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                '"' => out.push_str("&quot;"),
                '\'' => out.push_str("&#39;"),
                _ => out.push(c),
            }
        }
        out
    }

    /// Page skeleton. Slots, in order: difficulty, challenge, return_to. The
    /// untrusted values only ever land in escaped HTML attributes.
    pub(crate) const PAGE_TEMPLATE: &str = include_str!("challenge_page.html");

    /// Returns `return_to` if it is a safe same-origin path, else `"/"`.
    /// Safe means: starts with a single `/`, the second character is neither
    /// `/` nor `\`, and it contains no control characters.
    pub fn sanitize_return_to(return_to: &str) -> &str {
        let mut chars = return_to.chars();
        let ok = chars.next() == Some('/')
            && !matches!(chars.next(), Some('/') | Some('\\'))
            && !return_to.chars().any(char::is_control);
        if ok {
            return_to
        } else {
            "/"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::pow::{self, escape_html};
    use super::*;

    const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef-unit";
    const NOW: u64 = 1_800_000_000;

    fn keys() -> Keys {
        Keys::from_secret(SECRET).unwrap()
    }

    #[test]
    fn ipv4_mapped_ipv6_equals_ipv4() {
        let v4: IpAddr = "203.0.113.9".parse().unwrap();
        let mapped: IpAddr = "::ffff:203.0.113.9".parse().unwrap();
        assert_eq!(
            Binding::derive(Some("j"), v4, Some("ua")),
            Binding::derive(Some("j"), mapped, Some("ua"))
        );
    }

    #[test]
    fn altered_version_byte_is_malformed_even_when_resigned() {
        let k = keys();
        let b = Binding([3u8; 16]);
        let t = issue(&k, &b, NOW, 600, 5);
        let mut payload = open(&k.session, &t).unwrap();
        assert_eq!(payload[0], SESSION_VERSION);
        payload[0] = 0x02;
        let forged = sign(&k.session, &payload);
        assert_eq!(verify(&k, &forged, &b, NOW), Err(TokenError::Malformed));
        // Wrong length is also malformed.
        payload[0] = SESSION_VERSION;
        payload.push(0);
        let forged = sign(&k.session, &payload);
        assert_eq!(verify(&k, &forged, &b, NOW), Err(TokenError::Malformed));
    }

    #[test]
    fn html_escaping_of_each_special_char() {
        assert_eq!(escape_html("&"), "&amp;");
        assert_eq!(escape_html("<"), "&lt;");
        assert_eq!(escape_html(">"), "&gt;");
        assert_eq!(escape_html("\""), "&quot;");
        assert_eq!(escape_html("'"), "&#39;");
        assert_eq!(escape_html("plain"), "plain");
    }

    #[test]
    fn solve_with_zero_iterations_is_none() {
        let ch = pow::issue_challenge(&keys(), &Binding([1u8; 16]), NOW, 60, 8);
        assert_eq!(pow::solve(&ch, 0), None);
    }

    #[test]
    fn page_carries_difficulty_and_escaped_values() {
        let ch = pow::issue_challenge(&keys(), &Binding([1u8; 16]), NOW, 60, 13);
        let page = pow::challenge_page(&ch, "/a?x=1&y='2'");
        assert!(page.starts_with("<!doctype html>"));
        assert!(page.contains("data-difficulty=\"13\""));
        assert!(page.contains("/a?x=1&amp;y=&#39;2&#39;"));
        let bad = pow::challenge_page("junk", "/");
        assert!(bad.contains("data-difficulty=\"0\""));
    }
}
