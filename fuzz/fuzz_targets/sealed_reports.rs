#![no_main]
// What a browser POSTs when the gateway serves per-build sealed probes: the
// sealed report body, opened by `veritell_probe_build::Builder::open` with the
// gateway's real probe template. The first byte picks the mode:
//
// - 0 mod 4, raw: the input is the body as sent.
// - 1 mod 4, sealed: the input is a version 1 report and a nonce (separated
//   by 0xFF), sealed by `Builder::seal` for one of eight builds.
// - 2 or 3 mod 4, forged: the build key is in the script every client
//   receives, so a client can encrypt anything. The input is the plaintext
//   (in mode 2 every quoted version 1 key is first renamed to the build's
//   name for it), encrypted with that key the way the browser does. This
//   reaches the key mapping with arbitrary JSON.
//
// Properties checked, beyond "does not panic":
// - Forgery: a raw body never opens (no build id is genuine without the
//   server secret), and no raw text is a genuine build id.
// - Round trip: a sealed report opens to the same JSON value; opening and
//   sealing again gives the same bytes.
// - Binding: a body opened after its build's expiry is `ExpiredBuild`;
//   under another secret it is `UnknownBuild`; with any one byte changed it
//   is refused or opens to the same report.
// - Keys: an opened report has only `VOCAB` keys, at every depth.
use std::sync::OnceLock;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::Value;
use sha2::{Digest, Sha256};
use veritell_probe_build::{Build, Builder, OpenError, VOCAB};

const TEMPLATE: &str = include_str!("../../probe/probe.js");
const SECRET: &[u8] = b"fuzz secret, not used anywhere else, 32+ bytes";
const OTHER_SECRET: &[u8] = b"another fuzz secret, also at least 32 bytes long";
const NOW: u64 = 1_800_000_000;
const TTL: u64 = 600;

fn builder() -> &'static Builder {
    static B: OnceLock<Builder> = OnceLock::new();
    B.get_or_init(|| Builder::new(TEMPLATE, SECRET).expect("probe template"))
}

fn other() -> &'static Builder {
    static B: OnceLock<Builder> = OnceLock::new();
    B.get_or_init(|| Builder::new(TEMPLATE, OTHER_SECRET).expect("probe template"))
}

/// Eight builds and the 32-byte key each one's script hands to the client.
fn builds() -> &'static [(Build, [u8; 32])] {
    static B: OnceLock<Vec<(Build, [u8; 32])>> = OnceLock::new();
    B.get_or_init(|| {
        (0u8..8)
            .map(|n| {
                let build = builder().build_with_seed([n; 16], NOW, TTL);
                let key = leaked_key(&build);
                (build, key)
            })
            .collect()
    })
}

/// The build key as the script carries it: `{"id":"<id>","k":"<base64>",...`.
fn leaked_key(build: &Build) -> [u8; 32] {
    let head = format!("{{\"id\":\"{}\",\"k\":\"", build.id);
    let start = build.script.find(&head).expect("build configuration in the script") + head.len();
    let end = start + build.script[start..].find('"').expect("end of k");
    STANDARD.decode(&build.script[start..end]).expect("k is base64").try_into().expect("k is 32 bytes")
}

fn split(data: &[u8]) -> (&[u8], &[u8]) {
    match data.iter().position(|&b| b == 0xFF) {
        Some(i) => (&data[..i], &data[i + 1..]),
        None => (data, b""),
    }
}

fn only_vocab(value: &Value) {
    let mut work = vec![value];
    while let Some(v) = work.pop() {
        match v {
            Value::Object(map) => {
                for (key, child) in map {
                    assert!(VOCAB.contains(&key.as_str()), "opened report has key {key:?}");
                    work.push(child);
                }
            }
            Value::Array(items) => work.extend(items),
            _ => {}
        }
    }
}

/// Equal JSON values, except that numbers may differ in the last bits:
/// serde_json without `float_roundtrip` reads some decimals one unit in the
/// last place off, so a float can move when the report is read and written.
fn same(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => match (x.as_f64(), y.as_f64()) {
            _ if x == y => true,
            (Some(x), Some(y)) => (x - y).abs() <= x.abs().max(y.abs()) * 1e-12,
            _ => false,
        },
        (Value::Array(x), Value::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(x, y)| same(x, y)),
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| same(v, w)))
        }
        _ => a == b,
    }
}

/// What every successful open must satisfy, for a body sealed for `build`.
fn check_opened(body: &[u8], build: &Build, report_json: &[u8], tweak: usize) {
    let report: Value = serde_json::from_slice(report_json).expect("opened report is not JSON");
    only_vocab(&report);

    // Sealing what came out and opening it again changes nothing.
    let opened = builder().open(body, NOW).expect("opens once, opens twice");
    assert_eq!(opened.report_json, report_json, "open is not deterministic");
    if let Ok(again) = builder().seal(&build.id, &opened.nonce, report_json, [7; 12]) {
        let reopened = builder().open(&again, NOW).expect("a resealed report does not open");
        let reopened: Value = serde_json::from_slice(&reopened.report_json).expect("reopened report is not JSON");
        assert!(same(&reopened, &report), "open(seal(open(x))) differs from open(x)");
    }

    assert_eq!(builder().open(body, build.expires_at + 1).err(), Some(OpenError::ExpiredBuild), "opens after expiry");
    assert_eq!(builder().open(body, build.expires_at).map(|o| o.report_json).ok().as_deref(), Some(report_json));
    assert_eq!(other().open(body, NOW).err(), Some(OpenError::UnknownBuild), "opens under another secret");

    // Any one byte changed: refused, or the same report (no change to what
    // the gateway reads can get through).
    if !body.is_empty() {
        let mut changed = body.to_vec();
        let at = tweak % changed.len();
        changed[at] ^= 1 << (tweak / changed.len() % 8);
        if let Ok(o) = builder().open(&changed, NOW) {
            assert_eq!(o.report_json, report_json, "a changed byte at {at} opened to another report");
            assert_eq!(o.build_id, build.id, "a changed byte at {at} opened under another build");
        }
    }
}

fn forge(build: &Build, key: &[u8; 32], nonce: &str, plaintext: &[u8], iv: [u8; 12]) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(key);
    hash.update(nonce.as_bytes());
    let cipher = Aes256Gcm::new_from_slice(&hash.finalize()).expect("32-byte key");
    let ct = cipher.encrypt(&Nonce::from(iv), Payload { msg: plaintext, aad: build.id.as_bytes() }).expect("encrypt");
    let mut data = iv.to_vec();
    data.extend_from_slice(&ct);
    serde_json::to_vec(&serde_json::json!({ "b": build.id, "n": nonce, "d": STANDARD.encode(data) })).expect("body")
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some((&pick, rest)) = data.split_first() else { return };
    let (build, key) = &builds()[usize::from(pick >> 2) % 8];
    let tweak = usize::from(pick >> 5) * 7919 + rest.len();
    match pick & 3 {
        0 => {
            assert!(builder().open(rest, NOW).is_err(), "a body made without the secret opened");
            if let Ok(text) = std::str::from_utf8(rest) {
                assert!(builder().key_order(text).is_none(), "{text:?} passed as a genuine build id");
            }
        }
        1 => {
            let (report, nonce) = split(rest);
            let nonce = String::from_utf8_lossy(nonce);
            let Ok(body) = builder().seal(&build.id, &nonce, report, [pick; 12]) else { return };
            let opened = builder().open(&body, NOW).expect("a sealed report does not open");
            assert_eq!(opened.nonce, nonce, "nonce changed");
            let sent: Value = serde_json::from_slice(report).expect("seal took a report that is not JSON");
            let got: Value = serde_json::from_slice(&opened.report_json).expect("opened report is not JSON");
            assert!(same(&got, &sent), "a sealed report opened to another value: {got} vs {sent}");
            check_opened(&body, build, &opened.report_json, tweak);
        }
        mode => {
            let (plain, nonce) = split(rest);
            let nonce = String::from_utf8_lossy(nonce);
            let mut plain = plain.to_vec();
            if mode == 2 {
                if let Ok(text) = std::str::from_utf8(&plain) {
                    let mut text = text.to_string();
                    for (k, name) in &build.key_map {
                        text = text.replace(&format!("\"{k}\":"), &format!("\"{name}\":"));
                    }
                    plain = text.into_bytes();
                }
            }
            let body = forge(build, key, &nonce, &plain, [pick; 12]);
            match builder().open(&body, NOW) {
                Ok(opened) => check_opened(&body, build, &opened.report_json, tweak),
                Err(e) => assert!(
                    matches!(e, OpenError::Keys | OpenError::Malformed | OpenError::TooLarge),
                    "a body encrypted with the build key failed with {e:?}"
                ),
            }
        }
    }
});
