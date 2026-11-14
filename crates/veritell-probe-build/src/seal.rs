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
use serde_json::Value;
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

/// A JSON value that keeps object keys in the order they were written (a
/// `serde_json::Value` sorts them), so that the order the browser wrote can
/// be checked against the build (see `Builder::key_order`). Duplicate keys
/// are kept as they are; the version 1 parser refuses them.
enum Ordered {
    Object(Vec<(String, Ordered)>),
    Array(Vec<Ordered>),
    Scalar(Value),
}

impl<'de> serde::Deserialize<'de> for Ordered {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Ordered;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("JSON")
            }
            fn visit_bool<E>(self, v: bool) -> Result<Ordered, E> {
                Ok(Ordered::Scalar(Value::Bool(v)))
            }
            fn visit_i64<E>(self, v: i64) -> Result<Ordered, E> {
                Ok(Ordered::Scalar(Value::from(v)))
            }
            fn visit_u64<E>(self, v: u64) -> Result<Ordered, E> {
                Ok(Ordered::Scalar(Value::from(v)))
            }
            fn visit_f64<E>(self, v: f64) -> Result<Ordered, E> {
                Ok(Ordered::Scalar(Value::from(v)))
            }
            fn visit_str<E>(self, v: &str) -> Result<Ordered, E> {
                Ok(Ordered::Scalar(Value::String(v.to_string())))
            }
            fn visit_string<E>(self, v: String) -> Result<Ordered, E> {
                Ok(Ordered::Scalar(Value::String(v)))
            }
            fn visit_unit<E>(self) -> Result<Ordered, E> {
                Ok(Ordered::Scalar(Value::Null))
            }
            fn visit_none<E>(self) -> Result<Ordered, E> {
                Ok(Ordered::Scalar(Value::Null))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Ordered, A::Error> {
                let mut items = Vec::new();
                while let Some(item) = seq.next_element()? {
                    items.push(item);
                }
                Ok(Ordered::Array(items))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Ordered, A::Error> {
                let mut entries = Vec::new();
                while let Some((key, value)) = map.next_entry::<String, Ordered>()? {
                    entries.push((key, value));
                }
                Ok(Ordered::Object(entries))
            }
        }
        d.deserialize_any(V)
    }
}

impl serde::Serialize for Ordered {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{SerializeMap, SerializeSeq};
        match self {
            Ordered::Scalar(v) => v.serialize(s),
            Ordered::Array(items) => {
                let mut seq = s.serialize_seq(Some(items.len()))?;
                for item in items {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
            Ordered::Object(entries) => {
                let mut map = s.serialize_map(Some(entries.len()))?;
                for (key, value) in entries {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }
    }
}

/// Replaces every object key at every depth using `rename`, keeping its
/// place; `None` from `rename` fails the whole walk. Uses an explicit work
/// list, so the depth of the value cannot exhaust the stack.
fn remap_keys(root: &mut Ordered, rename: &dyn Fn(&str) -> Option<String>) -> Result<(), OpenError> {
    let mut work: Vec<&mut Ordered> = vec![root];
    while let Some(value) = work.pop() {
        match value {
            Ordered::Object(entries) => {
                for (key, child) in entries.iter_mut() {
                    *key = rename(key).ok_or(OpenError::Keys)?;
                    work.push(child);
                }
            }
            Ordered::Array(items) => work.extend(items.iter_mut()),
            Ordered::Scalar(_) => {}
        }
    }
    Ok(())
}

/// Puts the keys of every object that a build's script writes in a fixed
/// order into that order, the way a run of the build does: the places those
/// keys take in the object stay, the keys are moved among them.
fn reorder_keys(root: &mut Ordered, orders: &[Vec<String>]) {
    let mut work: Vec<&mut Ordered> = vec![root];
    while let Some(value) = work.pop() {
        match value {
            Ordered::Object(entries) => {
                for order in orders {
                    let rank = |key: &str| order.iter().position(|k| k == key);
                    let slots: Vec<usize> =
                        (0..entries.len()).filter(|i| entries.get(*i).is_some_and(|(k, _)| rank(k).is_some())).collect();
                    let mut moving: Vec<(String, Ordered)> = Vec::with_capacity(slots.len());
                    for slot in slots.iter().rev() {
                        moving.push(entries.remove(*slot));
                    }
                    moving.sort_by_key(|(k, _)| rank(k));
                    for (slot, entry) in slots.into_iter().zip(moving) {
                        entries.insert(slot.min(entries.len()), entry);
                    }
                }
                work.extend(entries.iter_mut().map(|(_, v)| v));
            }
            Ordered::Array(items) => work.extend(items.iter_mut()),
            Ordered::Scalar(_) => {}
        }
    }
}

fn cipher(build_key: &[u8; 32], nonce: &str) -> Result<Aes256Gcm, OpenError> {
    let mut hash = Sha256::new();
    hash.update(build_key);
    hash.update(nonce.as_bytes());
    Aes256Gcm::new_from_slice(&hash.finalize()).map_err(|_| OpenError::Decrypt)
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

    // Keys stay in the order the browser wrote them.
    let mut report: Ordered = serde_json::from_slice(&plaintext).map_err(|_| OpenError::Keys)?;
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
    let mut report: Ordered = serde_json::from_slice(v1_json).map_err(|_| OpenError::Keys)?;
    // In the order a run of this build writes the keys, as the browser would.
    reorder_keys(&mut report, &b.key_order(build_id).unwrap_or_default());
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

    /// Seals `plain` (already mapped JSON) the way the browser does, without
    /// the reordering `seal` applies.
    fn seal_as_is(b: &Builder, id: &str, nonce: &str, mapped: &str) -> Vec<u8> {
        let (seed, expires_at) = b.authenticate(id).unwrap();
        let ct = cipher(&b.build_key(seed, expires_at), nonce)
            .unwrap()
            .encrypt(&Nonce::from([3; 12]), Payload { msg: mapped.as_bytes(), aad: id.as_bytes() })
            .unwrap();
        let mut data = vec![3u8; 12];
        data.extend_from_slice(&ct);
        serde_json::json!({ "b": id, "n": nonce, "d": STANDARD.encode(data) }).to_string().into_bytes()
    }

    #[test]
    fn open_keeps_the_order_the_browser_wrote() {
        let b = Builder::new(TEMPLATE, SECRET).unwrap();
        let build = b.build_with_seed([2; 16], 10, 100);
        let m = |k: &str| build.key_map[k].clone();
        // Not alphabetical, so a sorting map would show.
        let mapped = format!(r#"{{"{}":1,"{}":{{"{}":"a","{}":"b"}}}}"#, m("v"), m("page"), m("tz"), m("plugins"));
        let opened = b.open(&seal_as_is(&b, &build.id, "n", &mapped), 10).unwrap();
        assert_eq!(String::from_utf8(opened.report_json).unwrap(), r#"{"v":1,"page":{"tz":"a","plugins":"b"}}"#);
    }

    #[test]
    fn seal_writes_keys_in_the_build_order() {
        let tpl = "var c = \"__VERITELL_CONFIG__\", b = \"__VERITELL_BUILD__\";\n\
                   /*@shuffle*/\n$$p.tz = 1;\n$$p.plugins = 2;\n$$p.screen = 3;\n/*@end*/\n";
        let b = Builder::new(tpl, SECRET).unwrap();
        for seed in 0..12u8 {
            let build = b.build_with_seed([seed; 16], 10, 100);
            let order = b.key_order(&build.id).unwrap();
            let report = br#"{"v":1,"page":{"globals":[],"screen":1,"tz":2,"window":0,"plugins":3}}"#;
            let opened = b.open(&b.seal(&build.id, "n", report, [1; 12]).unwrap(), 10).unwrap();
            let text = String::from_utf8(opened.report_json).unwrap();
            // Keys outside the order keep their places; the others follow it.
            let page: Vec<&str> = text
                .split('"')
                .filter(|w| ["globals", "screen", "tz", "window", "plugins"].contains(w))
                .collect();
            assert_eq!(page.first(), Some(&"globals"));
            assert_eq!(page.get(3), Some(&"window"));
            let rest: Vec<&str> = page.iter().copied().filter(|k| *k != "globals" && *k != "window").collect();
            assert_eq!(rest, order[0]);
        }
    }

    #[test]
    fn duplicate_keys_survive_opening_for_the_parser_to_refuse() {
        let b = Builder::new(TEMPLATE, SECRET).unwrap();
        let build = b.build_with_seed([2; 16], 10, 100);
        let v = build.key_map["v"].clone();
        let opened = b.open(&seal_as_is(&b, &build.id, "n", &format!(r#"{{"{v}":1,"{v}":2}}"#)), 10).unwrap();
        assert_eq!(String::from_utf8(opened.report_json).unwrap(), r#"{"v":1,"v":2}"#);
        // Deep nesting is refused, not a crash.
        let deep = format!("{}{}", "[".repeat(10_000), "]".repeat(10_000));
        assert_eq!(b.open(&seal_as_is(&b, &build.id, "n", &deep), 10), Err(OpenError::Keys));
    }

    #[test]
    fn expired_builds_can_still_be_sealed_for() {
        let b = Builder::new(TEMPLATE, SECRET).unwrap();
        let build = b.build_with_seed([2; 16], 10, 100);
        let body = b.seal(&build.id, "n", b"{\"v\":1}", [0; 12]).unwrap();
        assert_eq!(b.open(&body, 111), Err(OpenError::ExpiredBuild));
    }
}
