#![no_main]
// Signed bundles: the data feed a gateway loads (`veritell_feed::open`) and
// the share bundle another install writes (`veritell_share::open_bundle`,
// `decode`). The first byte picks the mode and the clock:
//
// - 0 mod 4, raw: the input is the bundle as read from disk, and also a
//   trusted key as configured (`FeedKey::from_base64url`).
// - 1 mod 4, signed manifest: fields separated by 0xFF are the manifest
//   bytes, then file name and content pairs. The target signs the manifest
//   with a trusted key, so mutations reach everything after the signature
//   check. Bit 0x80 sends contents as given instead of base64-encoding them
//   (as a JSON value when one parses and is not a string, else as text).
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
//   file encodes to a file that decodes to the same entries, and seals with
//   `seal_bundle` to a bundle that opens to them; a share file reads the
//   same directly and through a bundle; a trusted key parses only from its
//   canonical text.
// - Limits, on one input in 64 (inputs stay smaller): a bundle over
//   `MAX_BUNDLE_BYTES` is `TooLarge`; `seal` refuses an inverted window
//   (`Expired`) and content too large, both when the size is plain from
//   the content and when only the finished bundle shows it; `seal_bundle`
//   refuses more than `MAX_ENTRIES` entries, and `decode` a file with more.
// - `encode` leaves out entries of a class that is not shared.
// - A verified bundle holding anything but the share file is `Files` to
//   `open_bundle`. `Live` hands out the stored value, and a snapshot taken
//   before a store stays valid. Every error has a message.
use std::collections::BTreeMap;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use veritell_feed::{
    FeedError, FeedKey, Live, CLOCK_SKEW_SECS, FORMAT, MAX_BUNDLE_BYTES, MAX_FILES, MAX_NAME_BYTES,
};
use veritell_share::{Entry, ShareError, MAX_ENTRIES};

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
        .map(|p| {
            (
                String::from_utf8_lossy(p[0]).into_owned(),
                p.get(1).copied().unwrap_or_default().to_vec(),
            )
        })
        .collect()
}

fn name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_BYTES
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-'))
}

/// Checks an opened bundle against the signed manifest it came from.
fn check_opened(bundle: &veritell_feed::Bundle, manifest: &[u8], now: u64, min_version: u64) {
    let m: Value =
        serde_json::from_slice(manifest).expect("an opened bundle's manifest is not JSON");
    assert_eq!(
        m.get("format").and_then(Value::as_u64),
        Some(FORMAT),
        "opened with another format"
    );
    let created = m.get("created").and_then(Value::as_u64).expect("created");
    let expires = m.get("expires").and_then(Value::as_u64).expect("expires");
    assert!(
        created <= now.saturating_add(CLOCK_SKEW_SECS),
        "opened before it was created"
    );
    assert!(
        now <= expires && created <= expires,
        "opened outside its window"
    );
    assert!(
        bundle.version >= min_version,
        "version {} under the minimum {min_version}",
        bundle.version
    );
    assert_eq!(
        m.get("version").and_then(Value::as_u64),
        Some(bundle.version),
        "version is not the signed one"
    );
    let listed = m.get("files").and_then(Value::as_object).expect("files");
    let names = bundle.names();
    assert!(names.len() <= MAX_FILES, "{} files", names.len());
    assert_eq!(
        names.len(),
        listed.len(),
        "opened files are not the listed ones"
    );
    for name in names {
        assert!(name_ok(name), "opened a file named {name:?}");
        let entry = listed.get(name).expect("an opened file is not listed");
        let content = bundle.file(name).expect("a listed name has no file");
        assert_eq!(
            entry.get("len").and_then(Value::as_u64),
            Some(content.len() as u64),
            "{name}: length"
        );
        let hex: String = Sha256::digest(content)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            entry.get("sha256").and_then(Value::as_str),
            Some(hex.as_str()),
            "{name}: hash"
        );
    }
}

/// `seal`'s refusals that inputs this small cannot reach.
fn seal_limits() {
    let one = |len: usize| BTreeMap::from([("a".to_string(), vec![0u8; len])]);
    assert_eq!(
        veritell_feed::seal(&one(1), 1, NOW, NOW - 1, &SEED).err(),
        Some(FeedError::Expired)
    );
    // Base64 alone makes this content exactly the limit, so only the
    // finished bundle is over it; one byte more and the content is.
    let at_limit = MAX_BUNDLE_BYTES / 4 * 3;
    for len in [at_limit, at_limit + 1] {
        assert_eq!(
            veritell_feed::seal(&one(len), 1, NOW, NOW, &SEED).err(),
            Some(FeedError::TooLarge),
            "{len} bytes"
        );
    }
}

fn share(file: &[u8], now: u64) {
    let direct = veritell_share::decode(file);
    match &direct {
        Ok(entries) => {
            let again = veritell_share::encode(entries);
            assert_eq!(
                veritell_share::decode(&again).as_ref(),
                Ok(entries),
                "share file does not survive a round trip"
            );
            assert_eq!(
                veritell_share::encode(&veritell_share::decode(&again).unwrap()),
                again,
                "encode is not canonical"
            );
            let mut with_human = entries.clone();
            with_human.push(Entry {
                hash: [0xAB; 16],
                class: veritell_core::Class::Human,
            });
            assert_eq!(
                veritell_share::encode(&with_human),
                again,
                "encode wrote a class that is not shared"
            );
            let sealed = veritell_share::seal_bundle(entries, 2, now - 10, now + 10, &SEED)
                .expect("decoded entries do not seal");
            assert_eq!(
                veritell_share::open_bundle(&sealed, &[key()], now, 2).as_ref(),
                Ok(&(2, entries.clone())),
                "sealed entries do not open"
            );
        }
        Err(e) => assert!(!e.to_string().is_empty(), "empty error message"),
    }
    if file.len() % 64 == 63 {
        let many = vec![
            Entry {
                hash: [0; 16],
                class: veritell_core::Class::Automated
            };
            MAX_ENTRIES + 1
        ];
        let err = veritell_share::seal_bundle(&many, 1, now, now, &SEED).err();
        assert_eq!(err, Some(ShareError::TooMany));
        assert!(!err.unwrap().to_string().is_empty());
        // The count is checked before the entries are read.
        let long = format!("{{\"v\":1,\"entries\":[{}0]}}", "0,".repeat(MAX_ENTRIES));
        assert_eq!(
            veritell_share::decode(long.as_bytes()),
            Err(ShareError::TooMany),
            "a file over MAX_ENTRIES decoded"
        );
    }
    // The share file under another name, beside another file, or no file.
    let names: &[&str] = match file.len() % 3 {
        0 => &["other.json"],
        1 => &[veritell_share::FILE_NAME, "z.json"],
        _ => &[],
    };
    let wrong: BTreeMap<String, Vec<u8>> = names
        .iter()
        .map(|n| (n.to_string(), file.to_vec()))
        .collect();
    if let Ok(bundle) = veritell_feed::seal(&wrong, 3, now - 10, now + 10, &SEED) {
        let err = veritell_share::open_bundle(&bundle, &[key()], now, 1).err();
        assert_eq!(err, Some(ShareError::Files), "{:?}", wrong.keys());
        assert!(!err.unwrap().to_string().is_empty());
    }
    let mut files = BTreeMap::new();
    files.insert(veritell_share::FILE_NAME.to_string(), file.to_vec());
    if let Ok(bundle) = veritell_feed::seal(&files, 3, now - 10, now + 10, &SEED) {
        match veritell_share::open_bundle(&bundle, &[key()], now, 1) {
            Ok((version, entries)) => {
                assert_eq!(version, 3);
                assert_eq!(
                    direct.as_ref().ok(),
                    Some(&entries),
                    "a share file reads differently in a bundle"
                );
            }
            Err(_) => assert!(
                direct.is_err(),
                "a share file that decodes was refused in a bundle"
            ),
        }
        assert!(
            veritell_share::open_bundle(&bundle, &[key()], now, 4).is_err(),
            "rollback accepted"
        );
        assert!(
            veritell_share::open_bundle(&bundle, &[], now, 1).is_err(),
            "opened with no trusted key"
        );
    }
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some((&pick, rest)) = data.split_first() else {
        return;
    };
    // The clock and the minimum version move a little so the window checks
    // are reached from both sides.
    let now = NOW
        .wrapping_add(u64::from(pick >> 2 & 7).wrapping_mul(1000))
        .wrapping_sub(4000);
    let min_version = u64::from(pick >> 5 & 3);
    match pick & 3 {
        0 => {
            match veritell_feed::open(rest, &[key()], now, min_version) {
                Ok(_) => panic!("a raw bundle opened"),
                Err(e) => assert!(!e.to_string().is_empty(), "empty error message"),
            }
            if let Err(e) = veritell_share::open_bundle(rest, &[key()], now, min_version) {
                assert!(!e.to_string().is_empty(), "empty error message");
            }
            if rest.len() % 64 == 63 {
                let mut big = rest.to_vec();
                big.resize(MAX_BUNDLE_BYTES + 1, b' ');
                let err = veritell_feed::open(&big, &[key()], now, 0).err();
                assert_eq!(err, Some(FeedError::TooLarge));
                assert!(!err.unwrap().to_string().is_empty());
            }
            if let Ok(text) = std::str::from_utf8(rest) {
                if let Some(k) = FeedKey::from_base64url(text) {
                    assert_eq!(
                        URL_SAFE_NO_PAD.encode(k.0),
                        text,
                        "a trusted key parsed from non-canonical text"
                    );
                }
            }
            let mut raw = [0u8; 32];
            for (r, b) in raw.iter_mut().zip(rest) {
                *r = *b;
            }
            assert_eq!(
                FeedKey::from_base64url(&URL_SAFE_NO_PAD.encode(raw)),
                Some(FeedKey(raw))
            );
        }
        1 => {
            let parts = fields(rest);
            let Some((manifest, pairs)) = parts.split_first() else {
                return;
            };
            let mut carried = Map::new();
            for p in pairs.chunks(2) {
                let content = p.get(1).copied().unwrap_or_default();
                let value = if pick & 0x80 != 0 {
                    match serde_json::from_slice::<Value>(content) {
                        Ok(v) if !v.is_string() => v,
                        _ => Value::String(String::from_utf8_lossy(content).into_owned()),
                    }
                } else {
                    Value::String(STANDARD.encode(content))
                };
                carried.insert(String::from_utf8_lossy(p[0]).into_owned(), value);
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
                Err(e) => {
                    assert!(
                        !matches!(e, FeedError::Signature | FeedError::TooLarge),
                        "{e:?} for a signed bundle"
                    );
                    assert!(!e.to_string().is_empty(), "empty error message");
                }
            }
        }
        2 => {
            if rest.len() % 64 == 63 {
                seal_limits();
            }
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
            let bundle = veritell_feed::open(&bytes, &[key()], NOW, 5)
                .expect("a sealed bundle does not open");
            let live = Live::new(bundle.clone());
            let before = live.load();
            live.store(veritell_feed::Bundle::clone(&before));
            assert_eq!(*live.load(), bundle);
            assert_eq!(*before, bundle, "a snapshot changed under a store");
            assert_eq!(bundle.names().len(), files.len());
            for (name, content) in &files {
                assert_eq!(
                    bundle.file(name),
                    Some(content.as_slice()),
                    "{name} changed"
                );
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
