//! Acceptance tests written by the project lead. DO NOT EDIT.

use std::collections::BTreeMap;
use std::sync::Arc;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use veritell_feed::*;
use serde_json::{json, Value};

const SEED: [u8; 32] = [7; 32];
const OTHER_SEED: [u8; 32] = [9; 32];
const CREATED: u64 = 1_700_000_000;
const EXPIRES: u64 = CREATED + 7 * 86_400;
const NOW: u64 = CREATED + 3_600;

fn files() -> BTreeMap<String, Vec<u8>> {
    let mut f = BTreeMap::new();
    f.insert("truth_v1.json".to_string(), br#"{"version":1}"#.to_vec());
    f.insert("engine_v1.json".to_string(), vec![0u8, 1, 2, 255, 254]);
    f.insert("empty".to_string(), Vec::new());
    f
}

fn keys() -> Vec<FeedKey> {
    vec![public_key(&SEED)]
}

fn sealed() -> Vec<u8> {
    seal(&files(), 7, CREATED, EXPIRES, &SEED).unwrap()
}

/// Builds a bundle by hand so that tests can produce ones `seal` refuses to.
fn handmade(manifest: &Value, carried: &[(&str, &[u8])], seed: &[u8; 32]) -> Vec<u8> {
    let manifest_bytes = manifest.to_string().into_bytes();
    let signature = SigningKey::from_bytes(seed).sign(&manifest_bytes);
    let mut out = serde_json::Map::new();
    for (name, content) in carried {
        out.insert(name.to_string(), json!(STANDARD.encode(content)));
    }
    json!({
        "manifest": STANDARD.encode(&manifest_bytes),
        "signature": STANDARD.encode(signature.to_bytes()),
        "files": Value::Object(out),
    })
    .to_string()
    .into_bytes()
}

fn sha_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

fn manifest(version: u64, created: u64, expires: u64, listed: &[(&str, &[u8])]) -> Value {
    let mut m = serde_json::Map::new();
    for (name, content) in listed {
        m.insert(name.to_string(), json!({ "sha256": sha_hex(content), "len": content.len() }));
    }
    json!({ "format": 1, "version": version, "created": created, "expires": expires, "files": Value::Object(m) })
}

// ---------- the good path ----------

#[test]
fn round_trip() {
    let b = open(&sealed(), &keys(), NOW, 0).unwrap();
    assert_eq!((b.version, b.created, b.expires), (7, CREATED, EXPIRES));
    assert_eq!(b.names(), ["empty", "engine_v1.json", "truth_v1.json"]);
    assert_eq!(b.file("truth_v1.json"), Some(&br#"{"version":1}"#[..]));
    assert_eq!(b.file("engine_v1.json"), Some(&[0u8, 1, 2, 255, 254][..]));
    assert_eq!(b.file("empty"), Some(&[][..]));
    assert_eq!(b.file("nope"), None);
}

#[test]
fn sealing_is_deterministic_and_matches_a_handmade_bundle() {
    assert_eq!(sealed(), sealed());
    let listed: Vec<(&str, &[u8])> = vec![("a.json", &b"one"[..]), ("b.json", &b"two"[..])];
    let hand = handmade(&manifest(3, CREATED, EXPIRES, &listed), &listed, &SEED);
    let b = open(&hand, &keys(), NOW, 0).unwrap();
    assert_eq!(b.version, 3);
    assert_eq!(b.file("b.json"), Some(&b"two"[..]));
}

#[test]
fn any_trusted_key_is_enough() {
    let both = vec![public_key(&OTHER_SEED), public_key(&SEED)];
    assert!(open(&sealed(), &both, NOW, 0).is_ok());
}

#[test]
fn public_key_parsing() {
    let key = public_key(&SEED);
    let text = URL_SAFE_NO_PAD.encode(key.0);
    assert_eq!(FeedKey::from_base64url(&text), Some(key));
    assert_eq!(FeedKey::from_base64url(""), None);
    assert_eq!(FeedKey::from_base64url("AAAA"), None);
    assert_eq!(FeedKey::from_base64url("not base64 !!"), None);
    assert_eq!(FeedKey::from_base64url(&format!("{text}A")), None);
}

#[test]
fn time_limits() {
    let s = sealed();
    assert!(open(&s, &keys(), EXPIRES, 0).is_ok());
    assert_eq!(open(&s, &keys(), EXPIRES + 1, 0), Err(FeedError::Expired));
    assert!(open(&s, &keys(), CREATED - CLOCK_SKEW_SECS, 0).is_ok());
    assert_eq!(open(&s, &keys(), CREATED - CLOCK_SKEW_SECS - 1, 0), Err(FeedError::NotYetValid));
    assert!(open(&s, &keys(), u64::MAX, 0).is_err());
    assert!(open(&s, &keys(), 0, 0).is_err());
}

#[test]
fn rollback_is_refused() {
    let s = sealed();
    assert!(open(&s, &keys(), NOW, 7).is_ok());
    assert_eq!(open(&s, &keys(), NOW, 8), Err(FeedError::Rollback { minimum: 8, got: 7 }));
}

// ---------- tampering ----------

#[test]
fn wrong_or_missing_key_is_refused() {
    assert_eq!(open(&sealed(), &[public_key(&OTHER_SEED)], NOW, 0), Err(FeedError::Signature));
    assert_eq!(open(&sealed(), &[], NOW, 0), Err(FeedError::Signature));
}

#[test]
fn a_changed_manifest_is_refused_before_it_is_read() {
    // Re-encode a manifest with a higher version and a far expiry, keeping the old signature.
    let outer: Value = serde_json::from_slice(&sealed()).unwrap();
    let mut m: Value =
        serde_json::from_slice(&STANDARD.decode(outer["manifest"].as_str().unwrap()).unwrap()).unwrap();
    m["version"] = json!(999);
    m["format"] = json!(2);
    let mut forged = outer.clone();
    forged["manifest"] = json!(STANDARD.encode(m.to_string()));
    // Not `Format(2)`: the signature is checked first.
    assert_eq!(open(forged.to_string().as_bytes(), &keys(), NOW, 0), Err(FeedError::Signature));
}

#[test]
fn a_changed_file_is_refused() {
    let mut outer: Value = serde_json::from_slice(&sealed()).unwrap();
    outer["files"]["truth_v1.json"] = json!(STANDARD.encode(br#"{"version":2}"#));
    assert_eq!(
        open(outer.to_string().as_bytes(), &keys(), NOW, 0),
        Err(FeedError::Hash("truth_v1.json".into()))
    );
    // Same length, different content.
    let mut outer: Value = serde_json::from_slice(&sealed()).unwrap();
    outer["files"]["engine_v1.json"] = json!(STANDARD.encode([0u8, 1, 2, 255, 253]));
    assert_eq!(
        open(outer.to_string().as_bytes(), &keys(), NOW, 0),
        Err(FeedError::Hash("engine_v1.json".into()))
    );
}

#[test]
fn missing_and_unlisted_files_are_refused() {
    let mut outer: Value = serde_json::from_slice(&sealed()).unwrap();
    outer["files"].as_object_mut().unwrap().remove("empty");
    assert_eq!(
        open(outer.to_string().as_bytes(), &keys(), NOW, 0),
        Err(FeedError::Missing("empty".into()))
    );
    let mut outer: Value = serde_json::from_slice(&sealed()).unwrap();
    outer["files"]["extra.json"] = json!("");
    assert_eq!(
        open(outer.to_string().as_bytes(), &keys(), NOW, 0),
        Err(FeedError::Unlisted("extra.json".into()))
    );
}

#[test]
fn every_single_byte_change_is_refused() {
    let good = sealed();
    // Flip one bit at a spread of positions across the whole bundle.
    let step = (good.len() / 400).max(1);
    for i in (0..good.len()).step_by(step) {
        let mut bad = good.clone();
        bad[i] ^= 0x01;
        assert!(open(&bad, &keys(), NOW, 0).is_err(), "bit flip at byte {i} was accepted");
    }
    for cut in (0..good.len()).step_by(step) {
        assert!(open(&good[..cut], &keys(), NOW, 0).is_err(), "prefix of {cut} bytes was accepted");
    }
}

// ---------- signed but wrong ----------

#[test]
fn signed_manifests_with_bad_content_are_refused() {
    let none: Vec<(&str, &[u8])> = vec![];
    let cases: Vec<(Value, FeedError)> = vec![
        (json!({ "format": 2, "version": 1, "created": CREATED, "expires": EXPIRES, "files": {} }), FeedError::Format(2)),
        (json!({ "version": 1, "created": CREATED, "expires": EXPIRES, "files": {} }), FeedError::Manifest),
        (json!({ "format": 1, "version": -1, "created": CREATED, "expires": EXPIRES, "files": {} }), FeedError::Manifest),
        (json!({ "format": 1, "version": 1, "created": CREATED, "expires": EXPIRES, "files": [] }), FeedError::Manifest),
        (json!([1, 2, 3]), FeedError::Manifest),
        (json!({ "format": 1, "version": 1, "created": CREATED, "expires": CREATED - 1, "files": {} }), FeedError::Expired),
    ];
    for (m, want) in cases {
        assert_eq!(open(&handmade(&m, &none, &SEED), &keys(), NOW, 0), Err(want), "{m}");
    }
    // Signed bytes that are not JSON at all.
    let raw = b"\xff\xfenot json".to_vec();
    let sig = SigningKey::from_bytes(&SEED).sign(&raw);
    let bundle = json!({ "manifest": STANDARD.encode(&raw), "signature": STANDARD.encode(sig.to_bytes()), "files": {} });
    assert_eq!(open(bundle.to_string().as_bytes(), &keys(), NOW, 0), Err(FeedError::Manifest));
}

#[test]
fn file_names_are_restricted() {
    for bad in ["", ".hidden", "../etc/passwd", "a/b", "UPPER.json", "sp ace", "é.json", &"n".repeat(MAX_NAME_BYTES + 1)] {
        let listed: Vec<(&str, &[u8])> = vec![(bad, &b"x"[..])];
        let bundle = handmade(&manifest(1, CREATED, EXPIRES, &listed), &listed, &SEED);
        assert_eq!(open(&bundle, &keys(), NOW, 0), Err(FeedError::Name(bad.to_string())), "{bad:?}");
        let mut f = BTreeMap::new();
        f.insert(bad.to_string(), b"x".to_vec());
        assert_eq!(seal(&f, 1, CREATED, EXPIRES, &SEED), Err(FeedError::Name(bad.to_string())), "{bad:?}");
    }
    let longest = "n".repeat(MAX_NAME_BYTES);
    let ok = ["a", "a-b_c.d", "0.json", longest.as_str()];
    for good in ok {
        let mut f = BTreeMap::new();
        f.insert(good.to_string(), b"x".to_vec());
        let s = seal(&f, 1, CREATED, EXPIRES, &SEED).unwrap();
        assert!(open(&s, &keys(), NOW, 0).is_ok(), "{good:?}");
    }
}

#[test]
fn file_count_is_limited() {
    let mut f = BTreeMap::new();
    for i in 0..MAX_FILES {
        f.insert(format!("f{i:02}"), vec![i as u8]);
    }
    assert!(open(&seal(&f, 1, CREATED, EXPIRES, &SEED).unwrap(), &keys(), NOW, 0).is_ok());
    f.insert("one-more".to_string(), vec![]);
    assert_eq!(seal(&f, 1, CREATED, EXPIRES, &SEED), Err(FeedError::Name(String::new())));

    let owned: Vec<(String, Vec<u8>)> = f.into_iter().collect();
    let listed: Vec<(&str, &[u8])> = owned.iter().map(|(n, c)| (n.as_str(), c.as_slice())).collect();
    let bundle = handmade(&manifest(1, CREATED, EXPIRES, &listed), &listed, &SEED);
    assert_eq!(open(&bundle, &keys(), NOW, 0), Err(FeedError::Name(String::new())));
}

#[test]
fn seal_refuses_bad_times() {
    assert_eq!(seal(&files(), 1, CREATED, CREATED - 1, &SEED), Err(FeedError::Expired));
    assert!(seal(&files(), 1, CREATED, CREATED, &SEED).is_ok());
}

// ---------- hostile outer documents ----------

#[test]
fn malformed_outer_documents() {
    let good: Value = serde_json::from_slice(&sealed()).unwrap();
    let mut no_sig = good.clone();
    no_sig.as_object_mut().unwrap().remove("signature");
    let mut short_sig = good.clone();
    short_sig["signature"] = json!(STANDARD.encode([0u8; 63]));
    let mut bad_b64 = good.clone();
    bad_b64["manifest"] = json!("***");
    let mut files_array = good.clone();
    files_array["files"] = json!([]);
    for doc in [no_sig, short_sig, bad_b64, files_array, json!(null), json!([]), json!({})] {
        assert_eq!(open(doc.to_string().as_bytes(), &keys(), NOW, 0), Err(FeedError::Malformed), "{doc}");
    }
    for raw in [&b""[..], b"{", b"\xff", b"null"] {
        assert_eq!(open(raw, &keys(), NOW, 0), Err(FeedError::Malformed));
    }
    let deep = "[".repeat(100_000);
    assert_eq!(open(deep.as_bytes(), &keys(), NOW, 0), Err(FeedError::Malformed));

    // A listed file whose content is not base64.
    let mut not_b64 = good.clone();
    not_b64["files"]["empty"] = json!("%%%");
    assert_eq!(open(not_b64.to_string().as_bytes(), &keys(), NOW, 0), Err(FeedError::Malformed));
}

#[test]
fn oversized_bundles_are_refused() {
    let big = vec![b' '; MAX_BUNDLE_BYTES + 1];
    assert_eq!(open(&big, &keys(), NOW, 0), Err(FeedError::TooLarge));
    let mut f = BTreeMap::new();
    f.insert("big".to_string(), vec![0u8; MAX_BUNDLE_BYTES]);
    assert_eq!(seal(&f, 1, CREATED, EXPIRES, &SEED), Err(FeedError::TooLarge));
}

// ---------- Live ----------

#[test]
fn live_values_swap_without_disturbing_readers() {
    let live = Live::new(String::from("one"));
    let before = live.load();
    live.store(String::from("two"));
    assert_eq!(*before, "one");
    assert_eq!(*live.load(), "two");
    assert_eq!(Arc::strong_count(&before), 1);
}

#[test]
fn live_is_safe_under_contention() {
    let live = Arc::new(Live::new(0u64));
    let writers: Vec<_> = (0..4)
        .map(|t| {
            let live = Arc::clone(&live);
            std::thread::spawn(move || {
                for i in 0..2_000u64 {
                    live.store(t * 10_000 + i);
                }
            })
        })
        .collect();
    let readers: Vec<_> = (0..8)
        .map(|_| {
            let live = Arc::clone(&live);
            std::thread::spawn(move || {
                let mut seen = 0u64;
                for _ in 0..20_000 {
                    seen = seen.max(*live.load());
                }
                seen
            })
        })
        .collect();
    for w in writers {
        w.join().unwrap();
    }
    for r in readers {
        r.join().unwrap();
    }
    assert!(*live.load() < 40_000);
}

#[test]
fn live_survives_a_panicking_holder() {
    let live = Arc::new(Live::new(vec![1, 2, 3]));
    let l2 = Arc::clone(&live);
    let _ = std::thread::spawn(move || {
        let _snapshot = l2.load();
        panic!("reader died");
    })
    .join();
    live.store(vec![4]);
    assert_eq!(*live.load(), vec![4]);
}
