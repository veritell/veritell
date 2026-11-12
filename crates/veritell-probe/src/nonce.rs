//! Probe nonces. Implement the bodies; do not change signatures.
//!
//! A nonce ties a report to the connection that fetched the script and to a
//! short time window. It is an HMAC-SHA256 authenticated value over a random
//! 16-byte id, the expiry time and the caller's 16-byte binding. The binding
//! itself is not recoverable from the nonce.
//!
//! Layout (72 bytes, base64url without padding, 96 characters, no slack
//! bits so the encoding is canonical): id (16) | expiry big-endian (8) |
//! binding tag (16) | MAC (32).

use std::sync::atomic::{AtomicU64, Ordering};

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::types::{NonceError, NonceInfo};

type HmacSha256 = Hmac<Sha256>;

const LABEL: &[u8] = b"veritell/probe/v1";
const RAW_LEN: usize = 72;
const ENCODED_LEN: usize = 96;

const DOMAIN_TAG: u8 = 0x01;
const DOMAIN_MAC: u8 = 0x02;
const DOMAIN_FALLBACK: u8 = 0x03;

static FALLBACK_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Key for probe nonces, derived from the operator secret so that a nonce can
/// never be confused with a session token or a challenge.
#[derive(Clone)]
pub struct ProbeKey {
    key: [u8; 32],
}

impl ProbeKey {
    /// `HMAC-SHA256(secret, "veritell/probe/v1")`. Returns `None` when the
    /// secret is shorter than 32 bytes.
    pub fn from_secret(secret: &[u8]) -> Option<ProbeKey> {
        if secret.len() < 32 {
            return None;
        }
        let mut mac = HmacSha256::new_from_slice(secret).ok()?;
        mac.update(LABEL);
        let out = mac.finalize().into_bytes();
        let key = take::<32>(out.as_slice(), 0)?;
        Some(ProbeKey { key })
    }
}

/// Copies `N` bytes starting at `start`, if present.
fn take<const N: usize>(bytes: &[u8], start: usize) -> Option<[u8; N]> {
    let end = start.checked_add(N)?;
    bytes.get(start..end)?.try_into().ok()
}

fn mac_over(key: &ProbeKey, domain: u8, parts: &[&[u8]]) -> Option<HmacSha256> {
    let mut mac = HmacSha256::new_from_slice(&key.key).ok()?;
    mac.update(&[domain]);
    for p in parts {
        mac.update(p);
    }
    Some(mac)
}

fn binding_tag(key: &ProbeKey, id: &[u8; 16], exp: &[u8; 8], binding: &[u8; 16]) -> Option<MacTag> {
    let out = mac_over(key, DOMAIN_TAG, &[id, exp, binding])?.finalize().into_bytes();
    take::<16>(out.as_slice(), 0)
}

type MacTag = [u8; 16];

fn sextet_char(v: u8) -> char {
    match v {
        0..=25 => char::from(b'A'.wrapping_add(v)),
        26..=51 => char::from(b'a'.wrapping_add(v.wrapping_sub(26))),
        52..=61 => char::from(b'0'.wrapping_add(v.wrapping_sub(52))),
        62 => '-',
        _ => '_',
    }
}

fn char_sextet(b: u8) -> Option<u32> {
    let v = match b {
        b'A'..=b'Z' => b.wrapping_sub(b'A'),
        b'a'..=b'z' => b.wrapping_sub(b'a').wrapping_add(26),
        b'0'..=b'9' => b.wrapping_sub(b'0').wrapping_add(52),
        b'-' => 62,
        b'_' => 63,
        _ => return None,
    };
    Some(u32::from(v))
}

fn encode(raw: &[u8]) -> String {
    let mut out = String::with_capacity(ENCODED_LEN);
    for &[a, b, c] in raw.as_chunks::<3>().0 {
        let n = (u32::from(a) << 16) | (u32::from(b) << 8) | u32::from(c);
        for shift in [18u32, 12, 6, 0] {
            out.push(sextet_char(((n >> shift) & 63) as u8));
        }
    }
    out
}

/// Strict decode: exactly 96 alphabet characters, nothing else.
fn decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.len() != ENCODED_LEN {
        return None;
    }
    let mut out = Vec::with_capacity(RAW_LEN);
    for &[a, b, c, d] in bytes.as_chunks::<4>().0 {
        let n = (char_sextet(a)? << 18)
            | (char_sextet(b)? << 12)
            | (char_sextet(c)? << 6)
            | char_sextet(d)?;
        out.push(((n >> 16) & 0xff) as u8);
        out.push(((n >> 8) & 0xff) as u8);
        out.push((n & 0xff) as u8);
    }
    Some(out)
}

fn fresh_id(key: &ProbeKey, now: u64, ttl_secs: u64) -> [u8; 16] {
    let mut id = [0u8; 16];
    if getrandom::fill(&mut id).is_ok() {
        return id;
    }
    // Random source failed: derive a per-call unique id from a counter.
    let counter = FALLBACK_COUNTER.fetch_add(1, Ordering::Relaxed);
    let derived = mac_over(
        key,
        DOMAIN_FALLBACK,
        &[&counter.to_be_bytes(), &now.to_be_bytes(), &ttl_secs.to_be_bytes()],
    )
    .map(|m| m.finalize().into_bytes());
    derived
        .and_then(|d| take::<16>(d.as_slice(), 0))
        .unwrap_or_else(|| {
            let mut fallback = [0u8; 16];
            if let Some(s) = fallback.get_mut(..8) {
                s.copy_from_slice(&counter.to_be_bytes());
            }
            fallback
        })
}

/// Issues a nonce valid until `now + ttl_secs` for this binding.
///
/// The result contains only `[A-Za-z0-9_-]` and is at most 128 characters,
/// so it can be embedded in JavaScript and JSON without escaping. Two calls
/// with the same arguments return different nonces.
pub fn issue_nonce(key: &ProbeKey, binding: &[u8; 16], now: u64, ttl_secs: u64) -> String {
    let id = fresh_id(key, now, ttl_secs);
    let exp = now.saturating_add(ttl_secs).to_be_bytes();
    let Some(tag) = binding_tag(key, &id, &exp, binding) else {
        return String::new();
    };
    let Some(mac) = mac_over(key, DOMAIN_MAC, &[&id, &exp, &tag]) else {
        return String::new();
    };
    let mac = mac.finalize().into_bytes();
    let mut raw = Vec::with_capacity(RAW_LEN);
    raw.extend_from_slice(&id);
    raw.extend_from_slice(&exp);
    raw.extend_from_slice(&tag);
    raw.extend_from_slice(mac.as_slice());
    encode(&raw)
}

/// Verifies a nonce.
///
/// Order of checks: shape and length (`Malformed`), MAC in constant time
/// (`BadMac`), expiry (`Expired` when `now > expires_at`), binding
/// (`BindingMismatch`). The MAC covers the binding, so a nonce presented
/// with the wrong binding must be told apart from a forged one: authenticate
/// the id and expiry first, then check a binding tag.
pub fn verify_nonce(
    key: &ProbeKey,
    nonce: &str,
    binding: &[u8; 16],
    now: u64,
) -> Result<NonceInfo, NonceError> {
    let raw = decode(nonce).ok_or(NonceError::Malformed)?;
    let id = take::<16>(&raw, 0).ok_or(NonceError::Malformed)?;
    let exp = take::<8>(&raw, 16).ok_or(NonceError::Malformed)?;
    let tag = take::<16>(&raw, 24).ok_or(NonceError::Malformed)?;
    let mac = take::<32>(&raw, 40).ok_or(NonceError::Malformed)?;

    let expected = mac_over(key, DOMAIN_MAC, &[&id, &exp, &tag]).ok_or(NonceError::BadMac)?;
    expected.verify_slice(&mac).map_err(|_| NonceError::BadMac)?;

    let expires_at = u64::from_be_bytes(exp);
    if now > expires_at {
        return Err(NonceError::Expired);
    }

    let tag_check =
        mac_over(key, DOMAIN_TAG, &[&id, &exp, binding]).ok_or(NonceError::BindingMismatch)?;
    tag_check
        .verify_truncated_left(&tag)
        .map_err(|_| NonceError::BindingMismatch)?;

    Ok(NonceInfo { id, expires_at })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> ProbeKey {
        ProbeKey::from_secret(&[9u8; 40]).unwrap()
    }

    #[test]
    fn encoding_is_96_chars_and_round_trips() {
        let raw: Vec<u8> = (0..72u8).collect();
        let text = encode(&raw);
        assert_eq!(text.len(), 96);
        assert_eq!(decode(&text), Some(raw));
        assert_eq!(decode(&text.replace('A', "+")), None);
    }

    #[test]
    fn nonce_is_96_chars() {
        assert_eq!(issue_nonce(&key(), &[1; 16], 5, 5).len(), 96);
    }

    #[test]
    fn ttl_saturates() {
        let n = issue_nonce(&key(), &[1; 16], u64::MAX, u64::MAX);
        assert_eq!(verify_nonce(&key(), &n, &[1; 16], u64::MAX).unwrap().expires_at, u64::MAX);
    }

    #[test]
    fn expired_is_reported_before_binding() {
        let n = issue_nonce(&key(), &[1; 16], 10, 5);
        assert_eq!(verify_nonce(&key(), &n, &[2; 16], 16), Err(NonceError::Expired));
        assert_eq!(verify_nonce(&key(), &n, &[2; 16], 15), Err(NonceError::BindingMismatch));
    }

    #[test]
    fn non_ascii_of_right_byte_length_is_malformed() {
        let s = "é".repeat(48);
        assert_eq!(s.len(), 96);
        assert_eq!(verify_nonce(&key(), &s, &[1; 16], 0), Err(NonceError::Malformed));
    }

    #[test]
    fn fallback_ids_differ_per_call() {
        let k = key();
        let a = mac_over(&k, DOMAIN_FALLBACK, &[&FALLBACK_COUNTER.fetch_add(1, Ordering::Relaxed).to_be_bytes()]);
        let b = mac_over(&k, DOMAIN_FALLBACK, &[&FALLBACK_COUNTER.fetch_add(1, Ordering::Relaxed).to_be_bytes()]);
        assert_ne!(a.unwrap().finalize().into_bytes(), b.unwrap().finalize().into_bytes());
    }
}
