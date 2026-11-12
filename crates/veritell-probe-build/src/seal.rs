//! Sealed report format. Types are fixed; put helper code for `Builder::open`
//! and `Builder::seal` here.
//!
//! A sealed report body is a JSON object:
//!
//! ```json
//! { "b": "<build id>", "n": "<nonce>", "d": "<base64>" }
//! ```
//!
//! `d` is standard base64 (with padding) of `iv (12 bytes) || ciphertext ||
//! tag (16 bytes)`: AES-256-GCM with
//!
//! - key = SHA-256(build key (32 bytes) || nonce as UTF-8)
//! - additional data = the build id as UTF-8
//! - plaintext = the version 1 report as JSON with every object key, at any
//!   depth, replaced by the build's name for it
//!
//! The build key is HMAC-derived from the server secret and the build id's
//! contents, so it never has to be stored.

use std::collections::BTreeMap;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::build::{derive_key_map, Builder};
use crate::{MAX_NONCE_BYTES, MAX_SEALED_BYTES};

const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpenError {
    /// Longer than `MAX_SEALED_BYTES`.
    TooLarge,
    /// Not the JSON shape above, bad base64, a nonce longer than
    /// `MAX_NONCE_BYTES`, or `d` shorter than an IV plus a tag.
    Malformed,
    /// The build id was not issued under this secret.
    UnknownBuild,
    /// The build id is genuine and `now` is past its expiry.
    ExpiredBuild,
    /// Decryption failed: wrong nonce, wrong build, or altered data.
    Decrypt,
    /// The plaintext is not JSON, or contains an object key that is not one
    /// of this build's names. (`Builder::seal` returns this for a version 1
    /// report with a key outside `VOCAB`.)
    Keys,
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            OpenError::TooLarge => "sealed report too large",
            OpenError::Malformed => "sealed report is malformed",
            OpenError::UnknownBuild => "unknown probe build",
            OpenError::ExpiredBuild => "probe build has expired",
            OpenError::Decrypt => "sealed report does not decrypt",
            OpenError::Keys => "sealed report has unexpected keys",
        };
        f.write_str(text)
    }
}

impl std::error::Error for OpenError {}

/// A report that opened correctly. Checks happen in the order of the
/// [`OpenError`] variants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opened {
    pub build_id: String,
    /// The nonce from the outer object. It is authenticated: decryption only
    /// succeeds with the nonce the key was derived from.
    pub nonce: String,
    /// The report as version 1 JSON, ready for `veritell_probe::parse_report`.
    pub report_json: Vec<u8>,
}

fn cipher(build_key: &[u8; 32], nonce: &str) -> Result<Aes256Gcm, OpenError> {
    let mut hash = Sha256::new();
    hash.update(build_key);
    hash.update(nonce.as_bytes());
    Aes256Gcm::new_from_slice(&hash.finalize()).map_err(|_| OpenError::Decrypt)
}

/// Replaces every object key at every depth using `rename`; `None` from
/// `rename` fails the whole walk. Uses an explicit work list, so the depth of
/// the value cannot exhaust the stack.
fn remap_keys(root: &mut Value, rename: &dyn Fn(&str) -> Option<String>) -> Result<(), OpenError> {
    let mut work: Vec<&mut Value> = vec![root];
    while let Some(value) = work.pop() {
        match value {
            Value::Object(map) => {
                let old = std::mem::take(map);
                let mut renamed = Map::new();
                for (key, child) in old {
                    let new_key = rename(&key).ok_or(OpenError::Keys)?;
                    renamed.insert(new_key, child);
                }
                *map = renamed;
                work.extend(map.values_mut());
            }
            Value::Array(items) => work.extend(items.iter_mut()),
            _ => {}
        }
    }
    Ok(())
}

pub(crate) fn open(b: &Builder, body: &[u8], now: u64) -> Result<Opened, OpenError> {
    if body.len() > MAX_SEALED_BYTES {
        return Err(OpenError::TooLarge);
    }
    let outer: Value = serde_json::from_slice(body).map_err(|_| OpenError::Malformed)?;
    let object = outer.as_object().ok_or(OpenError::Malformed)?;
    let text = |key: &str| object.get(key).and_then(Value::as_str).ok_or(OpenError::Malformed);
    let (id, nonce, data) = (text("b")?, text("n")?, text("d")?);
    if nonce.len() > MAX_NONCE_BYTES {
        return Err(OpenError::Malformed);
    }
    let data = STANDARD.decode(data).map_err(|_| OpenError::Malformed)?;
    if data.len() < IV_LEN + TAG_LEN {
        return Err(OpenError::Malformed);
    }

    let (seed, expires_at) = b.authenticate(id).ok_or(OpenError::UnknownBuild)?;
    if now > expires_at {
        return Err(OpenError::ExpiredBuild);
    }

    let (iv, ciphertext) = data.split_at_checked(IV_LEN).ok_or(OpenError::Malformed)?;
    let iv: [u8; IV_LEN] = iv.try_into().map_err(|_| OpenError::Malformed)?;
    let key = b.build_key(seed, expires_at);
    let plaintext = cipher(&key, nonce)?
        .decrypt(&Nonce::from(iv), Payload { msg: ciphertext, aad: id.as_bytes() })
        .map_err(|_| OpenError::Decrypt)?;

    let mut report: Value = serde_json::from_slice(&plaintext).map_err(|_| OpenError::Keys)?;
    let inverse: BTreeMap<String, String> = derive_key_map(b.server_key(), seed, expires_at)
        .into_iter()
        .map(|(key, name)| (name, key))
        .collect();
    remap_keys(&mut report, &|name| inverse.get(name).cloned())?;
    let report_json = serde_json::to_vec(&report).map_err(|_| OpenError::Keys)?;
    Ok(Opened { build_id: id.to_string(), nonce: nonce.to_string(), report_json })
}

pub(crate) fn seal(b: &Builder, build_id: &str, nonce: &str, v1_json: &[u8], iv: [u8; 12]) -> Result<Vec<u8>, OpenError> {
    let (seed, expires_at) = b.authenticate(build_id).ok_or(OpenError::UnknownBuild)?;
    if nonce.len() > MAX_NONCE_BYTES {
        return Err(OpenError::Malformed);
    }
    let mut report: Value = serde_json::from_slice(v1_json).map_err(|_| OpenError::Keys)?;
    let forward = derive_key_map(b.server_key(), seed, expires_at);
    remap_keys(&mut report, &|key| forward.get(key).cloned())?;
    let plaintext = serde_json::to_vec(&report).map_err(|_| OpenError::Keys)?;

    let key = b.build_key(seed, expires_at);
    let ciphertext = cipher(&key, nonce)?
        .encrypt(&Nonce::from(iv), Payload { msg: &plaintext, aad: build_id.as_bytes() })
        .map_err(|_| OpenError::Decrypt)?;
    let mut data = Vec::with_capacity(IV_LEN.saturating_add(ciphertext.len()));
    data.extend_from_slice(&iv);
    data.extend_from_slice(&ciphertext);
    let body = serde_json::json!({ "b": build_id, "n": nonce, "d": STANDARD.encode(data) });
    let body = serde_json::to_vec(&body).map_err(|_| OpenError::Malformed)?;
    if body.len() > MAX_SEALED_BYTES {
        return Err(OpenError::TooLarge);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";
    const TEMPLATE: &str = "var c = \"__VERITELL_CONFIG__\", b = \"__VERITELL_BUILD__\";\n";

    #[test]
    fn nested_values_survive_and_extra_outer_keys_are_tolerated() {
        let b = Builder::new(TEMPLATE, SECRET).unwrap();
        let build = b.build_with_seed([2; 16], 10, 100);
        let report = br#"{"main":{"engine":{"features":{"error_line":true}},"tamper":[{"target":"x","kinds":["proxy"]}]},"v":1}"#;
        let body = b.seal(&build.id, "n", report, [1; 12]).unwrap();
        let opened = b.open(&body, 10).unwrap();
        let expected: Value = serde_json::from_slice(report).unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&opened.report_json).unwrap(), expected);

        let mut outer: Value = serde_json::from_slice(&body).unwrap();
        outer["extra"] = Value::Null;
        assert!(b.open(outer.to_string().as_bytes(), 10).is_ok());
    }

    #[test]
    fn oversized_nonce_is_refused_when_sealing() {
        let b = Builder::new(TEMPLATE, SECRET).unwrap();
        let build = b.build_with_seed([2; 16], 10, 100);
        let nonce = "n".repeat(MAX_NONCE_BYTES + 1);
        assert_eq!(b.seal(&build.id, &nonce, b"{}", [0; 12]), Err(OpenError::Malformed));
    }

    #[test]
    fn expired_builds_can_still_be_sealed_for() {
        let b = Builder::new(TEMPLATE, SECRET).unwrap();
        let build = b.build_with_seed([2; 16], 10, 100);
        let body = b.seal(&build.id, "n", b"{\"v\":1}", [0; 12]).unwrap();
        assert_eq!(b.open(&body, 111), Err(OpenError::ExpiredBuild));
    }
}
