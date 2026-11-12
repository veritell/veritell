//! Acceptance tests written by the project lead. DO NOT EDIT.

use std::collections::BTreeMap;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use veritell_core::{Class, Layer};
use veritell_feed::{FeedError, FeedKey};
use veritell_share::*;
use sha2::{Digest, Sha256};

const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";
const SEED: [u8; 32] = [7; 32];
const T: u64 = 1_800_000_000;

fn key() -> ShareKey {
    ShareKey::new(SECRET).unwrap()
}

fn config() -> Config {
    Config { min_networks: 5, max_fingerprints: 100, ttl_secs: 1000 }
}

fn ledger() -> Ledger {
    Ledger::new(key(), config()).unwrap()
}

/// The n-th network.
fn net(n: u32) -> [u8; 8] {
    let b = n.to_be_bytes();
    [4, 10, b[1], b[2], b[3], 0, 0, 0]
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Notes `fingerprint` as `class` from networks `0..networks` at `now`.
fn seen(l: &Ledger, fingerprint: &str, networks: u32, class: Class, now: u64) {
    for n in 0..networks {
        l.record(fingerprint, net(n), class, now);
    }
}

// ---------- the hash ----------

#[test]
fn the_hash_is_the_documented_hmac() {
    // Computed independently: HMAC-SHA-256 with the secret over
    // "veritell share fingerprint v1" 0x00 and the fingerprint, first 16 bytes.
    assert_eq!(
        hex(&key().hash("t13d1516h2_8daaf6152771_02713d6af862|1:65536;2:0|Mozilla/5.0")),
        "0cf42c34e5c5da014e706d98ff6c2f3a"
    );
    assert_eq!(hex(&key().hash("")), "ef1a8f90a6694f62f093ce95ae598331");
}

#[test]
fn the_hash_depends_on_the_secret_and_on_every_byte() {
    let other = ShareKey::new(b"ffffffffffffffffffffffffffffffff").unwrap();
    assert_ne!(key().hash("fp"), other.hash("fp"));
    assert_eq!(key().hash("fp"), key().clone().hash("fp"));
    let long = "x".repeat(100_000);
    assert_ne!(key().hash(&long), key().hash(&format!("{long}y")));
    assert_ne!(key().hash("a"), key().hash("A"));
}

#[test]
fn a_short_secret_is_refused_and_a_key_does_not_print_itself() {
    assert!(ShareKey::new(b"").is_none());
    assert!(ShareKey::new(&[1u8; MIN_SECRET_BYTES - 1]).is_none());
    assert!(ShareKey::new(&[1u8; MIN_SECRET_BYTES]).is_some());
    assert!(ShareKey::new(&[1u8; 500]).is_some());
    let shown = format!("{:?}", key());
    assert!(!shown.contains("0123456789abcdef"), "{shown}");
    assert!(!shown.contains("48, 49, 50"), "{shown}");
}

// ---------- configuration ----------

#[test]
fn configuration_is_checked() {
    for bad in [
        Config { min_networks: MIN_NETWORKS_FLOOR - 1, ..config() },
        Config { min_networks: 0, ..config() },
        Config { max_fingerprints: 0, ..config() },
        Config { ttl_secs: 0, ..config() },
        // TooSmall is reported before TooLarge.
        Config { ttl_secs: 0, max_fingerprints: MAX_ENTRIES + 1, ..config() },
    ] {
        assert_eq!(Ledger::new(key(), bad).err(), Some(ConfigError::TooSmall));
    }
    for bad in [Config { min_networks: 1001, ..config() }, Config { max_fingerprints: MAX_ENTRIES + 1, ..config() }] {
        assert_eq!(Ledger::new(key(), bad).err(), Some(ConfigError::TooLarge));
    }
    assert!(Ledger::new(key(), Config { min_networks: 1000, max_fingerprints: MAX_ENTRIES, ttl_secs: 1 }).is_ok());
    assert!(Ledger::new(key(), Config::default()).is_ok());
    assert!(Config::default().min_networks >= MIN_NETWORKS_FLOOR);
}

// ---------- the ledger ----------

#[test]
fn a_fingerprint_is_shared_only_from_enough_networks() {
    let l = ledger();
    seen(&l, "wide", 5, Class::Automated, T);
    seen(&l, "narrow", 4, Class::Automated, T);
    // The same network many times is one network.
    for _ in 0..50 {
        l.record("loud", net(1), Class::Malicious, T);
    }
    assert_eq!(l.tracked(), 3);
    assert_eq!(l.export(T), vec![Entry { hash: key().hash("wide"), class: Class::Automated }]);
    // One more network tips the narrow one over.
    l.record("narrow", net(77), Class::Automated, T + 1);
    let out = l.export(T + 1);
    assert_eq!(out.len(), 2);
    assert!(out.contains(&Entry { hash: key().hash("narrow"), class: Class::Automated }));
}

#[test]
fn only_automated_and_malicious_are_noted() {
    let l = ledger();
    for class in [Class::Human, Class::VerifiedBot, Class::SignedAgent, Class::UnverifiedAgent] {
        seen(&l, "people", 50, class, T);
    }
    assert_eq!(l.tracked(), 0);
    assert!(l.export(T).is_empty());
    // Nor do they add networks to, or refresh, an entry that exists.
    seen(&l, "mixed", 4, Class::Automated, T);
    seen(&l, "mixed", 50, Class::Human, T + 900);
    assert!(l.export(T + 900).is_empty());
    l.record("mixed", net(60), Class::Automated, T + 900);
    assert_eq!(l.export(T + 900).len(), 1);
}

#[test]
fn the_more_severe_class_is_kept() {
    let l = ledger();
    seen(&l, "fp", 5, Class::Automated, T);
    l.record("fp", net(0), Class::Malicious, T);
    l.record("fp", net(1), Class::Automated, T);
    assert_eq!(l.export(T), vec![Entry { hash: key().hash("fp"), class: Class::Malicious }]);
}

#[test]
fn entries_age_out() {
    let l = ledger();
    seen(&l, "old", 5, Class::Automated, T);
    seen(&l, "kept", 5, Class::Automated, T);
    assert_eq!(l.export(T + 1000).len(), 2);
    // "kept" is noted again, from all its networks; "old" is not. (Changed
    // by the lead after the Phase 4 audit: a network counts only while it is
    // itself seen within the window, so one network noted again no longer
    // keeps the other four counting.)
    seen(&l, "kept", 5, Class::Automated, T + 1000);
    assert_eq!(l.export(T + 1001), vec![Entry { hash: key().hash("kept"), class: Class::Automated }]);
    assert_eq!(l.export(T + 2000).len(), 1);
    assert!(l.export(T + 2001).is_empty());
}

#[test]
fn a_clock_that_steps_back() {
    let l = ledger();
    seen(&l, "fp", 5, Class::Automated, T + 5000);
    // Earlier times are treated as T+5000: nothing is aged out by them and
    // nothing is noted in the past.
    assert_eq!(l.export(T).len(), 1);
    assert_eq!(l.export(0).len(), 1);
    seen(&l, "second", 5, Class::Automated, T);
    assert_eq!(l.export(T + 6000).len(), 2);
    assert!(l.export(T + 6001).is_empty());
}

#[test]
fn the_ledger_is_bounded() {
    let l = Ledger::new(key(), Config { min_networks: 5, max_fingerprints: 3, ttl_secs: 1000 }).unwrap();
    for name in ["a", "b", "c"] {
        seen(&l, name, 5, Class::Automated, T);
    }
    // Full, and nothing has aged: a fourth is not noted.
    seen(&l, "d", 5, Class::Automated, T + 10);
    assert_eq!(l.tracked(), 3);
    assert_eq!(l.export(T + 10).len(), 3);
    // Those already there are still updated (from all five networks: see
    // entries_age_out for why).
    seen(&l, "a", 5, Class::Malicious, T + 10);
    assert!(l.export(T + 10).contains(&Entry { hash: key().hash("a"), class: Class::Malicious }));
    // Once the others have aged out there is room again.
    seen(&l, "e", 5, Class::Automated, T + 1005);
    assert!(l.tracked() <= 3);
    let out = l.export(T + 1005);
    assert!(out.contains(&Entry { hash: key().hash("e"), class: Class::Automated }));
    assert!(out.contains(&Entry { hash: key().hash("a"), class: Class::Malicious }));
    assert_eq!(out.len(), 2);

    // Any number of fingerprints and networks leaves it within its bound.
    for n in 0..5000u32 {
        l.record(&format!("flood-{n}"), net(n), Class::Automated, T + 1006);
        l.record("a", net(n), Class::Automated, T + 1006);
    }
    assert!(l.tracked() <= 3);
}

#[test]
fn the_export_is_sorted_by_hash() {
    let l = ledger();
    for n in 0..40 {
        seen(&l, &format!("fp-{n}"), 5, Class::Automated, T);
    }
    let out = l.export(T);
    assert_eq!(out.len(), 40);
    assert!(out.windows(2).all(|w| w[0].hash < w[1].hash));
}

#[test]
fn shared_across_threads() {
    let l = std::sync::Arc::new(ledger());
    let handles: Vec<_> = (0..4u32)
        .map(|t| {
            let l = std::sync::Arc::clone(&l);
            std::thread::spawn(move || {
                for n in 0..200u32 {
                    l.record("shared", net(t * 1000 + n), Class::Automated, T);
                    let _ = l.export(T);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(l.export(T).len(), 1);
}

// ---------- the file ----------

fn entry(seed: u8, class: Class) -> Entry {
    Entry { hash: [seed; HASH_BYTES], class }
}

#[test]
fn the_file_format_is_exact() {
    let entries = [
        Entry { hash: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], class: Class::Malicious },
        entry(1, Class::Automated),
    ];
    let bytes = encode(&entries);
    assert_eq!(
        String::from_utf8(bytes.clone()).unwrap(),
        r#"{"v":1,"entries":[{"h":"00112233445566778899aabbccddeeff","c":"malicious"},{"h":"01010101010101010101010101010101","c":"automated"}]}"#
    );
    assert_eq!(decode(&bytes).unwrap(), entries.to_vec());
    assert_eq!(String::from_utf8(encode(&[])).unwrap(), r#"{"v":1,"entries":[]}"#);
    assert_eq!(decode(br#"{"v":1,"entries":[]}"#).unwrap(), vec![]);
    // Whitespace and member order are JSON's business, not ours.
    assert_eq!(
        decode(br#" { "entries" : [ { "c":"automated", "h":"01010101010101010101010101010101" } ], "v" : 1 } "#).unwrap(),
        vec![entry(1, Class::Automated)]
    );
    // A class that may not be shared is not written.
    assert_eq!(encode(&[entry(1, Class::Human), entry(2, Class::Automated), entry(3, Class::SignedAgent)]), encode(&[entry(2, Class::Automated)]));
}

#[test]
fn files_that_are_refused() {
    let h = "01010101010101010101010101010101";
    let bad: Vec<String> = vec![
        String::new(),
        "not json".into(),
        "[]".into(),
        "{}".into(),
        r#"{"v":1}"#.into(),
        r#"{"entries":[]}"#.into(),
        r#"{"v":2,"entries":[]}"#.into(),
        r#"{"v":"1","entries":[]}"#.into(),
        r#"{"v":1,"entries":{}}"#.into(),
        r#"{"v":1,"entries":[],"extra":true}"#.into(),
        r#"{"v":1,"entries":["x"]}"#.into(),
        format!(r#"{{"v":1,"entries":[{{"h":"{h}"}}]}}"#),
        r#"{"v":1,"entries":[{"c":"automated"}]}"#.to_string(),
        format!(r#"{{"v":1,"entries":[{{"h":"{h}","c":"automated","ip":"203.0.113.9"}}]}}"#),
        format!(r#"{{"v":1,"entries":[{{"h":"{h}","c":"human"}}]}}"#),
        format!(r#"{{"v":1,"entries":[{{"h":"{h}","c":"signed_agent"}}]}}"#),
        format!(r#"{{"v":1,"entries":[{{"h":"{h}","c":"Automated"}}]}}"#),
        format!(r#"{{"v":1,"entries":[{{"h":"{h}","c":7}}]}}"#),
        format!(r#"{{"v":1,"entries":[{{"h":"{}","c":"automated"}}]}}"#, &h[..30]),
        format!(r#"{{"v":1,"entries":[{{"h":"{h}00","c":"automated"}}]}}"#),
        format!(r#"{{"v":1,"entries":[{{"h":"{}","c":"automated"}}]}}"#, h.replace('0', "g")),
        format!(r#"{{"v":1,"entries":[{{"h":"{}","c":"automated"}}]}}"#, "AB".repeat(16)),
        // The same hash twice, even with different classes.
        format!(r#"{{"v":1,"entries":[{{"h":"{h}","c":"automated"}},{{"h":"{h}","c":"malicious"}}]}}"#),
    ];
    for text in &bad {
        assert!(matches!(decode(text.as_bytes()), Err(ShareError::Format(_))), "{text:.90}");
    }
    assert!(matches!(decode(&[0xff, 0xfe]), Err(ShareError::Format(_))));
}

fn many(n: usize) -> Vec<Entry> {
    (0..n)
        .map(|i| {
            let mut hash = [0u8; HASH_BYTES];
            hash[..8].copy_from_slice(&(i as u64).to_be_bytes());
            Entry { hash, class: Class::Automated }
        })
        .collect()
}

#[test]
fn the_entry_limit() {
    let most = many(MAX_ENTRIES);
    assert_eq!(decode(&encode(&most)).unwrap().len(), MAX_ENTRIES);
    let over = many(MAX_ENTRIES + 1);
    assert_eq!(decode(&encode(&over)), Err(ShareError::TooMany));
    assert_eq!(seal_bundle(&over, 1, T, T + 100, &SEED).err(), Some(ShareError::TooMany));
}

// ---------- the bundle ----------

fn trusted() -> [FeedKey; 1] {
    [veritell_feed::public_key(&SEED)]
}

#[test]
fn a_bundle_round_trips() {
    let entries = vec![entry(1, Class::Automated), entry(2, Class::Malicious)];
    let bytes = seal_bundle(&entries, 9, T, T + 3600, &SEED).unwrap();
    assert_eq!(open_bundle(&bytes, &trusted(), T + 10, 0).unwrap(), (9, entries.clone()));
    assert_eq!(open_bundle(&bytes, &trusted(), T + 10, 9).unwrap().0, 9);
    // It is an ordinary feed bundle with one file.
    let plain = veritell_feed::open(&bytes, &trusted(), T + 10, 0).unwrap();
    assert_eq!(plain.names(), vec![FILE_NAME]);
    assert_eq!(plain.file(FILE_NAME).unwrap(), encode(&entries).as_slice());
}

#[test]
fn bundles_that_are_refused_as_in_the_feed() {
    let bytes = seal_bundle(&[entry(1, Class::Automated)], 9, T, T + 3600, &SEED).unwrap();
    let stranger = [veritell_feed::public_key(&[8; 32])];
    assert_eq!(open_bundle(&bytes, &stranger, T + 10, 0), Err(ShareError::Bundle(FeedError::Signature)));
    assert_eq!(open_bundle(&bytes, &[], T + 10, 0), Err(ShareError::Bundle(FeedError::Signature)));
    assert_eq!(open_bundle(&bytes, &trusted(), T + 3601, 0), Err(ShareError::Bundle(FeedError::Expired)));
    assert_eq!(
        open_bundle(&bytes, &trusted(), T + 10, 10),
        Err(ShareError::Bundle(FeedError::Rollback { minimum: 10, got: 9 }))
    );
    let mut cut = bytes.clone();
    cut.truncate(bytes.len() / 2);
    assert!(matches!(open_bundle(&cut, &trusted(), T + 10, 0), Err(ShareError::Bundle(_))));
    assert!(matches!(open_bundle(b"", &trusted(), T + 10, 0), Err(ShareError::Bundle(_))));
}

#[test]
fn a_signed_bundle_with_the_wrong_files_or_a_bad_file() {
    let sealed = |files: &[(&str, &[u8])]| {
        let map: BTreeMap<String, Vec<u8>> = files.iter().map(|(n, c)| (n.to_string(), c.to_vec())).collect();
        veritell_feed::seal(&map, 1, T, T + 3600, &SEED).unwrap()
    };
    let good = encode(&[entry(1, Class::Automated)]);
    // A truth table signed by the same key is not a share bundle.
    assert_eq!(open_bundle(&sealed(&[("truth_v1.json", b"{}")]), &trusted(), T, 0), Err(ShareError::Files));
    assert_eq!(open_bundle(&sealed(&[]), &trusted(), T, 0), Err(ShareError::Files));
    assert_eq!(
        open_bundle(&sealed(&[(FILE_NAME, &good), ("truth_v1.json", b"{}")]), &trusted(), T, 0),
        Err(ShareError::Files)
    );
    assert!(matches!(
        open_bundle(&sealed(&[(FILE_NAME, b"{\"v\":1}")]), &trusted(), T, 0),
        Err(ShareError::Format(_))
    ));
    assert_eq!(open_bundle(&sealed(&[(FILE_NAME, &good)]), &trusted(), T, 0).unwrap().1.len(), 1);
}

// ---------- import ----------

#[test]
fn an_imported_entry_is_a_small_hint() {
    let l = ledger();
    seen(&l, "reported-fp", 5, Class::Malicious, T);
    let imported = Imported::new(&l.export(T));
    assert_eq!(imported.len(), 1);
    assert!(!imported.is_empty());

    let d = imported.detection(&key(), "reported-fp").expect("reported");
    assert_eq!(d.id, DETECTION_ID);
    assert_eq!(d.layer, Layer::Population);
    assert_eq!(d.penalty, PENALTY);
    // No class of its own: it cannot make a request malicious or automated.
    assert_eq!(d.class_hint, None);
    assert!(d.detail.contains("malicious"));
    assert!(!d.detail.contains(&hex(&key().hash("reported-fp"))));
    // Alone it leaves a request far from any blocking score.
    let verdict = veritell_core::score(vec![d], None);
    assert_eq!((verdict.score, verdict.class), (99 - PENALTY, Class::Human));
    const { assert!(PENALTY <= 10) };

    assert_eq!(imported.detection(&key(), "another-fp"), None);
    assert_eq!(imported.detection(&key(), ""), None);
    // With another secret the same list matches nothing.
    let other = ShareKey::new(b"ffffffffffffffffffffffffffffffff").unwrap();
    assert_eq!(imported.detection(&other, "reported-fp"), None);
}

#[test]
fn nothing_imported_matches_nothing() {
    assert!(Imported::empty().is_empty());
    assert_eq!(Imported::empty().len(), 0);
    assert_eq!(Imported::empty().detection(&key(), "fp"), None);
    assert_eq!(Imported::new(&[]).len(), 0);
    // A class that may not be shared is not taken in either.
    assert_eq!(Imported::new(&[entry(1, Class::Human)]).len(), 0);
}

// ---------- G10: nothing that identifies anyone leaves ----------

#[test]
fn an_export_holds_no_address_no_user_agent_and_no_fingerprint() {
    let user_agent = "Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/149.0.0.0 Safari/537.36";
    let ja4 = "t13d1516h2_8daaf6152771_02713d6af862";
    let h2 = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p";
    let fingerprint = format!("{ja4}|{h2}|{user_agent}");
    let addresses: Vec<String> = (0..8).map(|n| format!("203.0.{}.77", 100 + n)).collect();

    let l = ledger();
    for (n, _) in addresses.iter().enumerate() {
        l.record(&fingerprint, [4, 203, 0, 100 + n as u8, 0, 0, 0, 0], Class::Automated, T);
    }
    let entries = l.export(T);
    assert_eq!(entries.len(), 1);
    let bundle = seal_bundle(&entries, 1, T, T + 3600, &SEED).unwrap();

    // Everything the bundle carries, in every encoding it uses.
    let opened = veritell_feed::open(&bundle, &trusted(), T, 0).unwrap();
    let mut haystacks: Vec<Vec<u8>> = vec![bundle.clone(), opened.file(FILE_NAME).unwrap().to_vec()];
    let outer: serde_json::Value = serde_json::from_slice(&bundle).unwrap();
    haystacks.push(STANDARD.decode(outer["manifest"].as_str().unwrap()).unwrap());
    let found = |needle: &[u8]| haystacks.iter().any(|h| !needle.is_empty() && h.windows(needle.len()).any(|w| w == needle));

    let mut secrets: Vec<(String, Vec<u8>)> = vec![
        ("fingerprint".into(), fingerprint.clone().into_bytes()),
        ("user agent".into(), user_agent.as_bytes().to_vec()),
        ("ja4".into(), ja4.as_bytes().to_vec()),
        ("ja4 cipher hash".into(), b"8daaf6152771".to_vec()),
        ("h2".into(), h2.as_bytes().to_vec()),
        ("HeadlessChrome".into(), b"HeadlessChrome".to_vec()),
        ("network prefix".into(), b"203.0.1".to_vec()),
        ("the shared secret".into(), SECRET.to_vec()),
    ];
    for a in &addresses {
        secrets.push((format!("address {a}"), a.clone().into_bytes()));
    }
    // Unkeyed hashes of any of them, as raw bytes, hex and base64.
    let mut derived = Vec::new();
    for (name, value) in &secrets {
        let digest = Sha256::digest(value);
        derived.push((format!("sha256 of {name}"), digest.to_vec()));
        derived.push((format!("sha256 hex of {name}"), hex(&digest).into_bytes()));
        derived.push((format!("sha256 hex prefix of {name}"), hex(&digest[..16]).into_bytes()));
        derived.push((format!("sha256 base64 of {name}"), STANDARD.encode(digest).into_bytes()));
        derived.push((format!("sha256 base64url of {name}"), URL_SAFE_NO_PAD.encode(digest).into_bytes()));
        derived.push((format!("base64 of {name}"), STANDARD.encode(value).into_bytes()));
    }
    for (name, needle) in secrets.iter().chain(derived.iter()) {
        assert!(!found(needle), "the bundle contains {name}");
    }
    // What it does hold is the keyed hash and the class.
    assert!(found(hex(&key().hash(&fingerprint)).as_bytes()));
    assert!(found(b"automated"));
    // And no count of networks or requests: eight networks, eight requests.
    let file: serde_json::Value = serde_json::from_slice(opened.file(FILE_NAME).unwrap()).unwrap();
    assert_eq!(file["entries"][0].as_object().unwrap().len(), 2);
}
