#![no_main]
// Signed bundles: the data feed a gateway loads (`veritell_feed::open`) and
// the share bundle another install writes (`veritell_share::open_bundle`,
// `decode`). The first byte picks the mode and the clock:
//
// - 0 mod 4, raw: the input is the bundle as read from disk.
// - 1 mod 4, signed manifest: fields separated by 0xFF are the manifest
//   bytes, then file name and content pairs. The target signs the manifest
//   with a trusted key, so mutations reach everything after the signature
//   check. Bit 0x80 sends contents as given instead of base64-encoding them.
// - 2 mod 4, sealed: name and content pairs, sealed by `veritell_feed::seal`
//   and then changed in one byte.
// - 3 mod 4, share file: the input is a share file; it is decoded directly
//   and inside a signed bundle.
//
// Properties checked, beyond "does not panic":
// - Forgery: a raw bundle never opens (the trusted key's seed is not in any
//   input), and a sealed bundle changed in one byte is refused or opens to
//   the same content.
// - Every opened bundle keeps the documented rules: the format, the clock
//   window, the minimum version, at most `MAX_FILES` names that follow the
//   name rules, and every file matches its listed length and SHA-256.
// - Round trip: a sealed bundle opens to what was sealed; a decoded share
//   file encodes to a file that decodes to the same entries; a share file
//   reads the same directly and through a bundle.
use std::collections::BTreeMap;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use veritell_feed::{FeedError, FeedKey, CLOCK_SKEW_SECS, FORMAT, MAX_FILES, MAX_NAME_BYTES};

const SEED: [u8; 32] = [0x5e; 32];
const NOW: u64 = 1_800_000_000;

fn key() -> FeedKey {
    veritell_feed::public_key(&SEED)
}

fn fields(data: &[u8]) -> Vec<&[u8]> {
    data.split(|&b| b == 0xFF).collect()
}

fn files_from(pairs: &[&[u8]]) -> BTreeMap<String, Vec<u8>> {
    pairs
        .chunks(2)
        .map(|p| (String::from_utf8_lossy(p[0]).into_owned(), p.get(1).copied().unwrap_or_default().to_vec()))
        .collect()
}

fn name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_BYTES
        && !name.starts_with('.')
        && name.bytes().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-'))
}

/// Checks an opened bundle against the signed manifest it came from.
fn check_opened(bundle: &veritell_feed::Bundle, manifest: &[u8], now: u64, min_version: u64) {
    let m: Value = serde_json::from_slice(manifest).expect("an opened bundle's manifest is not JSON");
    assert_eq!(m.get("format").and_then(Value::as_u64), Some(FORMAT), "opened with another format");
    let created = m.get("created").and_then(Value::as_u64).expect("created");
    let expires = m.get("expires").and_then(Value::as_u64).expect("expires");
    assert!(created <= now.saturating_add(CLOCK_SKEW_SECS), "opened before it was created");
    assert!(now <= expires && created <= expires, "opened outside its window");
    assert!(bundle.version >= min_version, "version {} under the minimum {min_version}", bundle.version);
    assert_eq!(m.get("version").and_then(Value::as_u64), Some(bundle.version), "version is not the signed one");
    let listed = m.get("files").and_then(Value::as_object).expect("files");
    let names = bundle.names();
    assert!(names.len() <= MAX_FILES, "{} files", names.len());
    assert_eq!(names.len(), listed.len(), "opened files are not the listed ones");
    for name in names {
        assert!(name_ok(name), "opened a file named {name:?}");
        let entry = listed.get(name).expect("an opened file is not listed");
        let content = bundle.file(name).expect("a listed name has no file");
        assert_eq!(entry.get("len").and_then(Value::as_u64), Some(content.len() as u64), "{name}: length");
        let hex: String = Sha256::digest(content).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(entry.get("sha256").and_then(Value::as_str), Some(hex.as_str()), "{name}: hash");
    }
}

fn share(file: &[u8], now: u64) {
    let direct = veritell_share::decode(file);
    if let Ok(entries) = &direct {
        let again = veritell_share::encode(entries);
        assert_eq!(veritell_share::decode(&again).as_ref(), Ok(entries), "share file does not survive a round trip");
        assert_eq!(veritell_share::encode(&veritell_share::decode(&again).unwrap()), again, "encode is not canonical");
    }
    let mut files = BTreeMap::new();
    files.insert(veritell_share::FILE_NAME.to_string(), file.to_vec());
    if let Ok(bundle) = veritell_feed::seal(&files, 3, now - 10, now + 10, &SEED) {
        match veritell_share::open_bundle(&bundle, &[key()], now, 1) {
            Ok((version, entries)) => {
                assert_eq!(version, 3);
                assert_eq!(direct.as_ref().ok(), Some(&entries), "a share file reads differently in a bundle");
            }
            Err(_) => assert!(direct.is_err(), "a share file that decodes was refused in a bundle"),
        }
        assert!(veritell_share::open_bundle(&bundle, &[key()], now, 4).is_err(), "rollback accepted");
        assert!(veritell_share::open_bundle(&bundle, &[], now, 1).is_err(), "opened with no trusted key");
    }
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some((&pick, rest)) = data.split_first() else { return };
    // The clock and the minimum version move a little so the window checks
    // are reached from both sides.
    let now = NOW.wrapping_add(u64::from(pick >> 2 & 7).wrapping_mul(1000)).wrapping_sub(4000);
    let min_version = u64::from(pick >> 5 & 3);
    match pick & 3 {
        0 => {
            assert!(veritell_feed::open(rest, &[key()], now, min_version).is_err(), "a raw bundle opened");
            let _ = veritell_share::open_bundle(rest, &[key()], now, min_version);
        }
        1 => {
            let parts = fields(rest);
            let Some((manifest, pairs)) = parts.split_first() else { return };
            let mut carried = Map::new();
            for p in pairs.chunks(2) {
                let content = p.get(1).copied().unwrap_or_default();
                let text = if pick & 0x80 != 0 {
                    String::from_utf8_lossy(content).into_owned()
                } else {
                    STANDARD.encode(content)
                };
                carried.insert(String::from_utf8_lossy(p[0]).into_owned(), Value::String(text));
            }
            let signature = SigningKey::from_bytes(&SEED).sign(manifest);
            let outer = serde_json::json!({
                "files": carried,
                "manifest": STANDARD.encode(manifest),
                "signature": STANDARD.encode(signature.to_bytes()),
            });
            let bytes = serde_json::to_vec(&outer).expect("outer");
            match veritell_feed::open(&bytes, &[key()], now, min_version) {
                Ok(bundle) => check_opened(&bundle, manifest, now, min_version),
                Err(e) => assert!(!matches!(e, FeedError::Signature | FeedError::TooLarge), "{e:?} for a signed bundle"),
            }
        }
        2 => {
            let parts = fields(rest);
            let files = files_from(&parts);
            let Ok(bytes) = veritell_feed::seal(&files, 5, NOW - 100, NOW + 100, &SEED) else {
                assert!(
                    files.len() > MAX_FILES || !files.keys().all(|n| name_ok(n)),
                    "seal refused {} valid files",
                    files.len()
                );
                return;
            };
            let bundle = veritell_feed::open(&bytes, &[key()], NOW, 5).expect("a sealed bundle does not open");
            assert_eq!(bundle.names().len(), files.len());
            for (name, content) in &files {
                assert_eq!(bundle.file(name), Some(content.as_slice()), "{name} changed");
            }
            let mut changed = bytes.clone();
            let at = (usize::from(pick) * 7919 + rest.len()) % changed.len();
            changed[at] ^= 1 << (pick >> 2 & 7);
            if let Ok(b) = veritell_feed::open(&changed, &[key()], NOW, 5) {
                assert_eq!(b.version, 5, "byte {at}: version changed");
                assert_eq!(b.names(), bundle.names(), "byte {at}: names changed");
                for name in bundle.names() {
                    assert_eq!(b.file(name), bundle.file(name), "byte {at}: {name} changed");
                }
            }
        }
        _ => share(rest, now),
    }
});
