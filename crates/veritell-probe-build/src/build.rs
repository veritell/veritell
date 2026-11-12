//! Building. Implement the bodies; do not change signatures.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::seal::{OpenError, Opened};
use crate::{BUILD_TOKEN, CONFIG_TOKEN, MAX_TEMPLATE_BYTES, RENAME_PREFIX, SHUFFLE_CLOSE, SHUFFLE_OPEN, VOCAB};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BuildError {
    /// The server secret is shorter than 32 bytes.
    WeakSecret,
    /// Longer than `MAX_TEMPLATE_BYTES`.
    TooLarge,
    /// `BUILD_TOKEN` or `CONFIG_TOKEN` does not occur exactly once. The
    /// payload names the token.
    Token(&'static str),
    /// A shuffle region is not closed, is nested, is closed without being
    /// open, or is empty. The payload is the 1-based line number.
    Marker(usize),
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildError::WeakSecret => write!(f, "secret must be at least 32 bytes"),
            BuildError::TooLarge => write!(f, "probe template too large"),
            BuildError::Token(t) => write!(f, "template must contain {t} exactly once"),
            BuildError::Marker(line) => write!(f, "bad shuffle marker at line {line}"),
        }
    }
}

impl std::error::Error for BuildError {}

/// One generated probe script.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Build {
    /// Identifies the build and authenticates its expiry. Only
    /// `[A-Za-z0-9_-]`, at most 64 characters.
    pub id: String,
    /// The script. Still contains `CONFIG_TOKEN` exactly once.
    pub script: String,
    pub expires_at: u64,
    /// Version 1 key to this build's name for it, for every `VOCAB` entry.
    pub key_map: BTreeMap<String, String>,
}

/// Label mixed into the operator secret so the derived key cannot collide
/// with any other use of the same secret.
const KEY_LABEL: &[u8] = b"veritell/probe-build/v1";

const DOMAIN_TAG: u8 = 0x01;
const DOMAIN_BUILD_KEY: u8 = 0x02;
const DOMAIN_KEY_MAP: u8 = 0x03;
const DOMAIN_FALLBACK_SEED: u8 = 0x04;
const DOMAIN_IDENTS: u8 = 0x05;
const DOMAIN_SHUFFLE: u8 = 0x06;

/// Length of the raw build id: seed (16) || expiry (8) || tag (16) || two
/// zero bytes. 42 bytes is a multiple of 3, so the base64url form has no
/// padding and no ignorable bits: every character matters.
const ID_RAW_LEN: usize = 42;
const ID_CHARS: usize = 56;
const TAG_LEN: usize = 16;

type HmacSha256 = Hmac<Sha256>;

/// HMAC-SHA256 over the concatenation of `parts`. HMAC accepts keys of any
/// length, so the error arm is unreachable in practice.
pub(crate) fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = match HmacSha256::new_from_slice(key) {
        Ok(mac) => mac,
        Err(_) => return [0; 32],
    };
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// One piece of the template: a line that stays in place or a shuffle region.
#[derive(Clone)]
enum Segment {
    Line(String),
    Region(Vec<String>),
}

/// Holds a validated template and the server secret.
#[derive(Clone)]
pub struct Builder {
    server_key: [u8; 32],
    segments: Vec<Segment>,
}

/// Deterministic byte stream: HMAC blocks keyed with the server key over
/// `label || seed || expiry || counter`.
struct Stream<'a> {
    key: &'a [u8; 32],
    label: u8,
    seed: [u8; 16],
    expiry: [u8; 8],
    counter: u64,
    block: [u8; 32],
    pos: usize,
}

impl<'a> Stream<'a> {
    fn new(key: &'a [u8; 32], label: u8, seed: [u8; 16], expires_at: u64) -> Stream<'a> {
        Stream { key, label, seed, expiry: expires_at.to_be_bytes(), counter: 0, block: [0; 32], pos: 32 }
    }

    fn next_byte(&mut self) -> u8 {
        if self.pos >= self.block.len() {
            self.block = hmac(
                self.key,
                &[&[self.label], &self.seed, &self.expiry, &self.counter.to_be_bytes()],
            );
            self.counter = self.counter.wrapping_add(1);
            self.pos = 0;
        }
        let byte = self.block.get(self.pos).copied().unwrap_or(0);
        self.pos = self.pos.saturating_add(1);
        byte
    }

    fn next_u32(&mut self) -> u32 {
        let mut x = 0u32;
        for _ in 0..4 {
            x = (x << 8) | u32::from(self.next_byte());
        }
        x
    }

    /// Uniform in `0..n` by rejection sampling (no modulo bias).
    fn below(&mut self, n: u32) -> u32 {
        if n <= 1 {
            return 0;
        }
        let limit = (u32::MAX / n) * n;
        loop {
            let x = self.next_u32();
            if x < limit {
                return x % n;
            }
        }
    }

    fn pick(&mut self, set: &[u8]) -> char {
        let n = u32::try_from(set.len()).unwrap_or(1);
        let i = usize::try_from(self.below(n)).unwrap_or(0);
        set.get(i).map_or('a', |b| char::from(*b))
    }

    /// Unbiased Fisher-Yates.
    fn shuffle<T>(&mut self, items: &mut [T]) {
        let len = items.len();
        for i in (1..len).rev() {
            let bound = u32::try_from(i.saturating_add(1)).unwrap_or(u32::MAX);
            let j = usize::try_from(self.below(bound)).unwrap_or(0);
            if i < len && j < len {
                items.swap(i, j);
            }
        }
    }
}

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const LOWER_DIGIT: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

/// `_` plus 6 to 10 characters of `[a-z0-9]` starting with a letter.
fn gen_identifier(stream: &mut Stream<'_>) -> String {
    let len = 6 + usize::try_from(stream.below(5)).unwrap_or(0);
    let mut out = String::from("_");
    for i in 0..len {
        out.push(stream.pick(if i == 0 { LOWER } else { LOWER_DIGIT }));
    }
    out
}

/// 2 to 4 characters of `[a-z]`.
fn gen_key_name(stream: &mut Stream<'_>) -> String {
    let len = 2 + usize::try_from(stream.below(3)).unwrap_or(0);
    (0..len).map(|_| stream.pick(LOWER)).collect()
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

enum Piece<'a> {
    Text(&'a str),
    Ident(&'a str),
}

/// Splits `s` into text and renamable identifiers (`RENAME_PREFIX` followed
/// by one or more identifier characters, taken greedily, so `$$a`, `$$ab`
/// and `$$a_b` are three different identifiers).
fn pieces(s: &str) -> Vec<Piece<'_>> {
    let mut out = Vec::new();
    let mut rest = s;
    while let Some(at) = rest.find(RENAME_PREFIX) {
        let Some((head, tail)) = rest.split_at_checked(at) else { break };
        let after = tail.get(RENAME_PREFIX.len()..).unwrap_or("");
        let n = after.bytes().take_while(|b| is_ident_byte(*b)).count();
        if n == 0 {
            // A bare prefix: not an identifier. Keep one character and go on.
            let Some((keep, next)) = rest.split_at_checked(at.saturating_add(1)) else { break };
            out.push(Piece::Text(keep));
            rest = next;
            continue;
        }
        let total = RENAME_PREFIX.len().saturating_add(n);
        let Some((ident, next)) = tail.split_at_checked(total) else { break };
        out.push(Piece::Text(head));
        out.push(Piece::Ident(ident));
        rest = next;
    }
    out.push(Piece::Text(rest));
    out
}

/// Step 2 and 3: drop comment-only lines, trim, drop blank lines.
fn strip_and_trim(lines: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_block = false;
    for line in lines {
        let t = line.trim();
        if in_block {
            if t.contains("*/") {
                in_block = false;
            }
            continue;
        }
        if t.starts_with("//") {
            continue;
        }
        if let Some(rest) = t.strip_prefix("/*") {
            if !rest.contains("*/") {
                in_block = true;
            }
            continue;
        }
        if !t.is_empty() {
            out.push(t.to_string());
        }
    }
    out
}

/// Key map for a build: every `VOCAB` key to a distinct name. Depends only
/// on the server key, seed and expiry, so `open` can rebuild it.
pub(crate) fn derive_key_map(server_key: &[u8; 32], seed: [u8; 16], expires_at: u64) -> BTreeMap<String, String> {
    let mut stream = Stream::new(server_key, DOMAIN_KEY_MAP, seed, expires_at);
    let mut used = BTreeSet::new();
    let mut map = BTreeMap::new();
    for key in VOCAB {
        let name = loop {
            let name = gen_key_name(&mut stream);
            if used.insert(name.clone()) {
                break name;
            }
        };
        map.insert(key.to_string(), name);
    }
    map
}

static FALLBACK_COUNTER: AtomicU64 = AtomicU64::new(0);

impl Builder {
    /// Validates the template (see [`BuildError`]).
    pub fn new(template: &str, secret: &[u8]) -> Result<Builder, BuildError> {
        if secret.len() < 32 {
            return Err(BuildError::WeakSecret);
        }
        if template.len() > MAX_TEMPLATE_BYTES {
            return Err(BuildError::TooLarge);
        }
        if template.matches(BUILD_TOKEN).count() != 1 {
            return Err(BuildError::Token(BUILD_TOKEN));
        }
        if template.matches(CONFIG_TOKEN).count() != 1 {
            return Err(BuildError::Token(CONFIG_TOKEN));
        }
        let segments = parse_segments(template)?;
        Ok(Builder { server_key: hmac(secret, &[KEY_LABEL]), segments })
    }

    /// A new build with a random seed, valid until `now + ttl_secs`
    /// (saturating).
    pub fn build(&self, now: u64, ttl_secs: u64) -> Build {
        let mut seed = [0u8; 16];
        if getrandom::fill(&mut seed).is_err() {
            let n = FALLBACK_COUNTER.fetch_add(1, Ordering::Relaxed);
            let mixed = hmac(&self.server_key, &[&[DOMAIN_FALLBACK_SEED], &n.to_be_bytes(), &now.to_be_bytes()]);
            for (dst, src) in seed.iter_mut().zip(mixed.iter()) {
                *dst = *src;
            }
        }
        self.build_with_seed(seed, now, ttl_secs)
    }

    /// The build for a given seed. Everything about a build (names, order,
    /// key map, build key, id) is a deterministic function of the secret,
    /// the template, `seed` and the expiry time.
    ///
    /// The script is produced from the template in these steps:
    /// 1. Shuffle regions: the lines strictly between a `SHUFFLE_OPEN` line
    ///    and the next `SHUFFLE_CLOSE` line are reordered as whole lines.
    ///    The two marker lines are removed.
    /// 2. Lines whose trimmed text starts with `//` are removed. A block
    ///    comment that starts at the beginning of a trimmed line is removed
    ///    through the line on which it ends. Other comments are left alone.
    /// 3. Every line is trimmed and empty lines are removed. Lines are
    ///    joined with `\n`.
    /// 4. Each distinct identifier made of `RENAME_PREFIX` followed by one
    ///    or more of `[A-Za-z0-9_]` is replaced, everywhere it occurs, by a
    ///    build-specific name: `_` followed by 6 to 10 characters of
    ///    `[a-z0-9]` starting with a letter. Distinct identifiers get
    ///    distinct names, and an identifier that is a prefix of another is
    ///    never confused with it.
    /// 5. `BUILD_TOKEN` is replaced by a JSON object
    ///    `{"id":"<id>","k":"<base64 of the 32-byte build key>","map":{...}}`
    ///    where `map` is `key_map`. Key map names are 2 to 4 characters of
    ///    `[a-z]`, all distinct.
    pub fn build_with_seed(&self, seed: [u8; 16], now: u64, ttl_secs: u64) -> Build {
        let expires_at = now.saturating_add(ttl_secs);
        let id = self.make_id(seed, expires_at);
        let key = self.build_key(seed, expires_at);
        let key_map = derive_key_map(&self.server_key, seed, expires_at);

        // 1. shuffle regions
        let mut shuffle = Stream::new(&self.server_key, DOMAIN_SHUFFLE, seed, expires_at);
        let mut lines: Vec<String> = Vec::new();
        for segment in &self.segments {
            match segment {
                Segment::Line(line) => lines.push(line.clone()),
                Segment::Region(region) => {
                    let mut region = region.clone();
                    shuffle.shuffle(&mut region);
                    lines.extend(region);
                }
            }
        }
        // 2 and 3. comments, whitespace
        let text = strip_and_trim(&lines).join("\n");

        // 4. identifiers
        let parts = pieces(&text);
        let mut idents = Stream::new(&self.server_key, DOMAIN_IDENTS, seed, expires_at);
        let mut names: BTreeMap<&str, String> = BTreeMap::new();
        let mut taken: BTreeSet<String> = key_map.values().cloned().collect();
        let distinct: BTreeSet<&str> = parts
            .iter()
            .filter_map(|p| if let Piece::Ident(i) = p { Some(*i) } else { None })
            .collect();
        for ident in distinct {
            let name = loop {
                let name = gen_identifier(&mut idents);
                if taken.insert(name.clone()) {
                    break name;
                }
            };
            names.insert(ident, name);
        }
        let mut renamed = String::with_capacity(text.len());
        for part in &parts {
            match part {
                Piece::Text(t) => renamed.push_str(t),
                Piece::Ident(i) => renamed.push_str(names.get(i).map_or(i, String::as_str)),
            }
        }

        // 5. build configuration
        let config = serde_json::json!({
            "id": id,
            "k": STANDARD.encode(key),
            "map": key_map,
        })
        .to_string();
        let script = renamed.replacen(BUILD_TOKEN, &config, 1);

        Build { id, script, expires_at, key_map }
    }

    /// Opens a sealed report body. See `seal.rs`.
    pub fn open(&self, body: &[u8], now: u64) -> Result<Opened, OpenError> {
        crate::seal::open(self, body, now)
    }

    /// Seals a version 1 report the way the browser does. Used by tests and
    /// by the bot lab to produce forgeries; the gateway never calls it.
    /// `iv` is the 12-byte AES-GCM nonce.
    pub fn seal(
        &self,
        build_id: &str,
        nonce: &str,
        v1_json: &[u8],
        iv: [u8; 12],
    ) -> Result<Vec<u8>, OpenError> {
        crate::seal::seal(self, build_id, nonce, v1_json, iv)
    }

    pub(crate) fn server_key(&self) -> &[u8; 32] {
        &self.server_key
    }

    fn tag_mac(&self, seed: &[u8; 16], expires_at: u64) -> Option<HmacSha256> {
        let mut mac = HmacSha256::new_from_slice(&self.server_key).ok()?;
        mac.update(&[DOMAIN_TAG]);
        mac.update(seed);
        mac.update(&expires_at.to_be_bytes());
        Some(mac)
    }

    fn make_id(&self, seed: [u8; 16], expires_at: u64) -> String {
        let tag = self.tag_mac(&seed, expires_at).map(|m| m.finalize().into_bytes());
        let mut raw = Vec::with_capacity(ID_RAW_LEN);
        raw.extend_from_slice(&seed);
        raw.extend_from_slice(&expires_at.to_be_bytes());
        if let Some(tag) = tag {
            raw.extend_from_slice(tag.get(..TAG_LEN).unwrap_or(&[]));
        }
        raw.resize(ID_RAW_LEN, 0);
        URL_SAFE_NO_PAD.encode(raw)
    }

    /// The seed and expiry of an id issued under this secret; `None` for
    /// anything else. The tag is compared in constant time and is checked
    /// before anything else about the id is trusted.
    pub(crate) fn authenticate(&self, id: &str) -> Option<([u8; 16], u64)> {
        if id.len() != ID_CHARS {
            return None;
        }
        let raw = URL_SAFE_NO_PAD.decode(id).ok()?;
        if raw.len() != ID_RAW_LEN {
            return None;
        }
        let (seed, rest) = raw.split_at_checked(16)?;
        let (expiry, rest) = rest.split_at_checked(8)?;
        let (tag, pad) = rest.split_at_checked(TAG_LEN)?;
        let seed: [u8; 16] = seed.try_into().ok()?;
        let expiry: [u8; 8] = expiry.try_into().ok()?;
        let expires_at = u64::from_be_bytes(expiry);
        let tag_ok = self.tag_mac(&seed, expires_at)?.verify_truncated_left(tag).is_ok();
        let pad_ok = pad.iter().all(|b| *b == 0);
        (tag_ok && pad_ok).then_some((seed, expires_at))
    }

    pub(crate) fn build_key(&self, seed: [u8; 16], expires_at: u64) -> [u8; 32] {
        hmac(&self.server_key, &[&[DOMAIN_BUILD_KEY], &seed, &expires_at.to_be_bytes()])
    }
}

fn parse_segments(template: &str) -> Result<Vec<Segment>, BuildError> {
    let mut segments = Vec::new();
    // Line of the opening marker and the lines collected so far.
    let mut open: Option<(usize, Vec<String>)> = None;
    for (index, line) in template.split('\n').enumerate() {
        let number = index.saturating_add(1);
        let trimmed = line.trim();
        if trimmed == SHUFFLE_OPEN {
            if open.is_some() {
                return Err(BuildError::Marker(number));
            }
            open = Some((number, Vec::new()));
        } else if trimmed == SHUFFLE_CLOSE {
            match open.take() {
                None => return Err(BuildError::Marker(number)),
                Some((opened_at, lines)) => {
                    if lines.is_empty() {
                        return Err(BuildError::Marker(opened_at));
                    }
                    segments.push(Segment::Region(lines));
                }
            }
        } else if let Some((_, lines)) = open.as_mut() {
            if !trimmed.is_empty() {
                lines.push(line.to_string());
            }
        } else {
            segments.push(Segment::Line(line.to_string()));
        }
    }
    match open {
        Some((opened_at, _)) => Err(BuildError::Marker(opened_at)),
        None => Ok(segments),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";
    const BASE: &str = "var c = \"__VERITELL_CONFIG__\", b = \"__VERITELL_BUILD__\";\n";

    fn names_of(text: &str) -> Vec<String> {
        pieces(text)
            .into_iter()
            .filter_map(|p| if let Piece::Ident(i) = p { Some(i.to_string()) } else { None })
            .collect()
    }

    #[test]
    fn identifiers_are_greedy_and_bare_prefixes_are_left_alone() {
        assert_eq!(names_of("$$a $$ab $$a_b $$ x$$y $$$z $$"), ["$$a", "$$ab", "$$a_b", "$$y", "$$z"]);
        assert_eq!(names_of("no identifiers $ here"), Vec::<String>::new());
    }

    #[test]
    fn marker_line_numbers() {
        let t = |tail: &str| Builder::new(&format!("{BASE}{tail}"), SECRET).err();
        assert_eq!(t("a;\n/*@shuffle*/\nb;\n"), Some(BuildError::Marker(3)));
        assert_eq!(t("/*@shuffle*/\na;\n/*@shuffle*/\nb;\n/*@end*/\n/*@end*/\n"), Some(BuildError::Marker(4)));
        assert_eq!(t("a;\n/*@end*/\n"), Some(BuildError::Marker(3)));
        assert_eq!(t("/*@shuffle*/\n/*@end*/\n"), Some(BuildError::Marker(2)));
    }

    #[test]
    fn validation_order_secret_before_size() {
        let big = "x".repeat(MAX_TEMPLATE_BYTES + 1);
        assert_eq!(Builder::new(&big, b"short").err(), Some(BuildError::WeakSecret));
        assert_eq!(Builder::new(&big, SECRET).err(), Some(BuildError::TooLarge));
        // Tokens are checked before markers.
        assert_eq!(Builder::new("/*@end*/\n", SECRET).err(), Some(BuildError::Token(BUILD_TOKEN)));
    }

    #[test]
    fn below_is_in_range_and_roughly_uniform() {
        let key = [7u8; 32];
        let mut stream = Stream::new(&key, 9, [1; 16], 5);
        let mut counts = [0u32; 7];
        for _ in 0..7000 {
            let x = stream.below(7);
            assert!(x < 7);
            if let Some(c) = counts.get_mut(x as usize) {
                *c += 1;
            }
        }
        assert!(counts.iter().all(|c| (800..1200).contains(c)), "{counts:?}");
        assert_eq!(stream.below(0), 0);
        assert_eq!(stream.below(1), 0);
    }

    #[test]
    fn shuffle_is_a_permutation() {
        let key = [7u8; 32];
        let mut stream = Stream::new(&key, 9, [1; 16], 5);
        let mut v: Vec<u32> = (0..50).collect();
        stream.shuffle(&mut v);
        let mut sorted = v.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..50).collect::<Vec<u32>>());
        assert_ne!(v, sorted);
        let mut empty: Vec<u32> = Vec::new();
        stream.shuffle(&mut empty);
    }

    #[test]
    fn generated_names_never_collide_with_key_map_names() {
        let tpl = format!("{BASE}{}", (0..200).map(|i| format!("var $$v{i} = {i};\n")).collect::<String>());
        let b = Builder::new(&tpl, SECRET).unwrap();
        let build = b.build_with_seed([3; 16], 10, 10);
        let idents: BTreeSet<&str> = build.script.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .filter(|w| w.len() > 6 && w.starts_with('_') && w != &"__VERITELL_CONFIG__")
            .collect();
        assert_eq!(idents.len(), 200);
        for name in build.key_map.values() {
            assert!(!idents.contains(name.as_str()));
        }
    }

    #[test]
    fn id_authentication() {
        let b = Builder::new(BASE, SECRET).unwrap();
        let build = b.build_with_seed([9; 16], 100, 50);
        assert_eq!(build.id.len(), ID_CHARS);
        assert_eq!(b.authenticate(&build.id), Some(([9; 16], 150)));
        let other = Builder::new(BASE, b"ffffffffffffffffffffffffffffffff").unwrap();
        assert_eq!(other.authenticate(&build.id), None);
        assert_eq!(b.authenticate(""), None);
        assert_eq!(b.authenticate(&format!("{}A", build.id)), None);
    }

    #[test]
    fn ttl_saturates_and_comment_blocks_end() {
        let tpl = format!("{BASE}/*\nmulti\n*/\nkeep;\n/* one */\n// gone\nalso;\n");
        let b = Builder::new(&tpl, SECRET).unwrap();
        let build = b.build_with_seed([1; 16], u64::MAX, u64::MAX);
        assert_eq!(build.expires_at, u64::MAX);
        assert!(build.script.ends_with("keep;\nalso;"), "{}", build.script);
    }

    #[test]
    fn fallback_seed_path_gives_distinct_seeds() {
        let key = [1u8; 32];
        let a = hmac(&key, &[&[DOMAIN_FALLBACK_SEED], &0u64.to_be_bytes(), &5u64.to_be_bytes()]);
        let b = hmac(&key, &[&[DOMAIN_FALLBACK_SEED], &1u64.to_be_bytes(), &5u64.to_be_bytes()]);
        assert_ne!(a, b);
    }
}
