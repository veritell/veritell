//! Acceptance tests written by the project lead. DO NOT EDIT.
//!
//! These use a small synthetic template. The real probe is checked in a
//! browser by `probe/test/run.mjs --sealed`.

use std::collections::BTreeSet;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use veritell_probe_build::*;
use serde_json::{json, Value};

const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";
const NOW: u64 = 1_700_000_000;
const TTL: u64 = 300;

const TEMPLATE: &str = r#"/*
 * Header comment that must not survive.
 */
(function () {
  "use strict";
  // a full-line comment
  var $$config = "__VERITELL_CONFIG__";
  var $$build = "__VERITELL_BUILD__";
  var $$a = 1, $$ab = 2, $$a_b = 3;
  var url = "https://example.test/x"; // trailing comments stay
  var re = /^    at /;
    /* one-line block comment at line start */
  var $$list = [
    /*@shuffle*/
    "alpha",
    "bravo",
    "charlie",
    "delta",
    "echo",
    "foxtrot",
    /*@end*/
  ];

  /*@shuffle*/
  $$a += 10;
  $$ab += 20;
  $$a_b += 30;
  /*@end*/
  return [$$a, $$ab, $$a_b, $$list, $$config, $$build];
})();
"#;

fn builder() -> Builder {
    Builder::new(TEMPLATE, SECRET).unwrap()
}

fn seed(n: u8) -> [u8; 16] {
    [n; 16]
}

fn v1() -> Value {
    json!({
        "v": 1,
        "nonce": "the-nonce",
        "main": {
            "ua": "UA", "platform": "P", "languages": ["en"], "hc": 8, "webdriver": false,
            "uad": { "platform": "macOS", "mobile": false, "brands": ["B"] },
            "engine": { "err_msg": "e", "eval_len": 33, "stack_at": true,
                        "features": { "error_line": false, "fn_to_source": false }, "math": "1" },
            "tamper": [{ "target": "t", "kinds": ["to_string"] }]
        },
        "iframe": null,
        "worker": null,
        "page": { "plugins": 5, "screen": [1, 2, 3, 4], "window": [1, 2, 3, 4], "dpr_x100": 200,
                  "touch_points": 0, "webgl_vendor": null, "webgl_renderer": "r", "chrome_obj": true,
                  "notif_permission": "default", "perm_query_notif": "prompt", "globals": [],
                  "tz": "UTC", "tz_offset_min": -60 },
        "errors": []
    })
}

fn sealed(b: &Builder, build: &Build, nonce: &str) -> Vec<u8> {
    b.seal(&build.id, nonce, v1().to_string().as_bytes(), [3; 12]).unwrap()
}

// ---------- template validation ----------

#[test]
fn template_is_validated() {
    assert_eq!(Builder::new(TEMPLATE, &SECRET[..31]).err(), Some(BuildError::WeakSecret));
    let big = format!("{TEMPLATE}{}", " ".repeat(MAX_TEMPLATE_BYTES));
    assert_eq!(Builder::new(&big, SECRET).err(), Some(BuildError::TooLarge));

    let no_build = TEMPLATE.replace("\"__VERITELL_BUILD__\"", "0");
    assert_eq!(Builder::new(&no_build, SECRET).err(), Some(BuildError::Token(BUILD_TOKEN)));
    let two_build = format!("{TEMPLATE}\nvar x = \"__VERITELL_BUILD__\";");
    assert_eq!(Builder::new(&two_build, SECRET).err(), Some(BuildError::Token(BUILD_TOKEN)));
    let no_config = TEMPLATE.replace("\"__VERITELL_CONFIG__\"", "0");
    assert_eq!(Builder::new(&no_config, SECRET).err(), Some(BuildError::Token(CONFIG_TOKEN)));
    let two_config = format!("{TEMPLATE}\nvar x = \"__VERITELL_CONFIG__\";");
    assert_eq!(Builder::new(&two_config, SECRET).err(), Some(BuildError::Token(CONFIG_TOKEN)));
}

#[test]
fn shuffle_markers_are_validated() {
    let base = "var c = \"__VERITELL_CONFIG__\", b = \"__VERITELL_BUILD__\";\n";
    let cases = [
        ("/*@shuffle*/\na;\n", 2),                            // never closed
        ("/*@end*/\n", 2),                                    // closed without being open
        ("/*@shuffle*/\na;\n/*@shuffle*/\nb;\n/*@end*/\n", 4), // nested
        ("/*@shuffle*/\n/*@end*/\n", 2),                      // empty
        ("a;\n  /*@shuffle*/  \n\n   \n/*@end*/\n", 3),       // only blank lines inside
    ];
    for (tail, line) in cases {
        let t = format!("{base}{tail}");
        assert_eq!(Builder::new(&t, SECRET).err(), Some(BuildError::Marker(line)), "{tail:?}");
    }
    let ok = format!("{base}/*@shuffle*/\na;\n/*@end*/\n/*@shuffle*/\nb;\nc;\n/*@end*/\n");
    assert!(Builder::new(&ok, SECRET).is_ok());
}

// ---------- the build ----------

#[test]
fn build_is_deterministic_for_a_seed() {
    let a = builder().build_with_seed(seed(1), NOW, TTL);
    let b = builder().build_with_seed(seed(1), NOW, TTL);
    assert_eq!(a, b);
    assert_eq!(a.expires_at, NOW + TTL);
    assert_eq!(builder().build_with_seed(seed(1), u64::MAX - 1, TTL).expires_at, u64::MAX);
}

#[test]
fn random_builds_differ() {
    let b = builder();
    let x = b.build(NOW, TTL);
    let y = b.build(NOW, TTL);
    assert_ne!(x.id, y.id);
    assert_ne!(x.script, y.script);
    assert_ne!(x.key_map, y.key_map);
}

#[test]
fn id_shape() {
    for n in 0..20 {
        let build = builder().build_with_seed(seed(n), NOW, TTL);
        assert!(!build.id.is_empty() && build.id.len() <= 64, "{}", build.id);
        assert!(build.id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-'), "{}", build.id);
    }
}

#[test]
fn tokens_and_comments() {
    let build = builder().build_with_seed(seed(1), NOW, TTL);
    let s = &build.script;
    assert_eq!(s.matches(CONFIG_TOKEN).count(), 1);
    assert_eq!(s.matches(BUILD_TOKEN).count(), 0);
    assert!(!s.contains("Header comment"));
    assert!(!s.contains("a full-line comment"));
    assert!(!s.contains("one-line block comment"));
    assert!(!s.contains("@shuffle") && !s.contains("@end"));
    assert!(!s.contains("$$"), "unrenamed identifier left: {s}");
    // Things that only look like comments are untouched.
    assert!(s.contains("var url = \"https://example.test/x\"; // trailing comments stay"));
    assert!(s.contains("var re = /^    at /;"));
    assert!(s.contains("\"use strict\";"));
    // Trimmed, no blank lines.
    for line in s.split('\n') {
        assert!(!line.is_empty(), "blank line in build");
        assert_eq!(line, line.trim(), "untrimmed line {line:?}");
    }
}

#[test]
fn embedded_build_configuration() {
    let build = builder().build_with_seed(seed(1), NOW, TTL);
    // The line that held the build token now holds a JSON object.
    let line = build.script.split('\n').find(|l| l.contains("\"map\"")).expect("no config line");
    let start = line.find('{').unwrap();
    let end = line.rfind('}').unwrap();
    let config: Value = serde_json::from_str(&line[start..=end]).unwrap();
    assert_eq!(config["id"], build.id.as_str());
    assert_eq!(STANDARD.decode(config["k"].as_str().unwrap()).unwrap().len(), 32);
    let map = config["map"].as_object().unwrap();
    assert_eq!(map.len(), VOCAB.len());
    for key in VOCAB {
        assert_eq!(map[key].as_str(), build.key_map.get(key).map(String::as_str), "{key}");
    }
}

#[test]
fn key_map_names() {
    for n in 0..20 {
        let build = builder().build_with_seed(seed(n), NOW, TTL);
        assert_eq!(build.key_map.len(), VOCAB.len());
        let names: BTreeSet<&str> = build.key_map.values().map(String::as_str).collect();
        assert_eq!(names.len(), VOCAB.len(), "duplicate key map names");
        for name in names {
            assert!((2..=4).contains(&name.len()) && name.bytes().all(|c| c.is_ascii_lowercase()), "{name}");
        }
    }
    let a = builder().build_with_seed(seed(1), NOW, TTL);
    let b = builder().build_with_seed(seed(2), NOW, TTL);
    assert_ne!(a.key_map, b.key_map);
}

/// The renamed identifiers on the `return [...]` line, in order.
fn returned_names(script: &str) -> Vec<String> {
    let line = script.split('\n').find(|l| l.starts_with("return [")).unwrap();
    line.trim_start_matches("return [")
        .trim_end_matches("];")
        .split(", ")
        .map(str::to_string)
        .collect()
}

#[test]
fn identifiers_are_renamed_consistently() {
    let mut seen = BTreeSet::new();
    for n in 0..20 {
        let build = builder().build_with_seed(seed(n), NOW, TTL);
        let names = returned_names(&build.script);
        assert_eq!(names.len(), 6);
        let distinct: BTreeSet<&String> = names.iter().collect();
        assert_eq!(distinct.len(), 6, "{names:?}");
        for name in &names {
            let body = name.strip_prefix('_').unwrap_or_else(|| panic!("{name} lacks the prefix"));
            assert!((6..=10).contains(&body.len()), "{name}");
            assert!(body.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()), "{name}");
            assert!(body.as_bytes()[0].is_ascii_lowercase(), "{name}");
        }
        // $$a, $$ab and $$a_b are three different variables everywhere.
        let (a, ab, a_b) = (&names[0], &names[1], &names[2]);
        assert!(build.script.contains(&format!("var {a} = 1, {ab} = 2, {a_b} = 3;")), "{}", build.script);
        for (name, add) in [(a, 10), (ab, 20), (a_b, 30)] {
            assert!(build.script.split('\n').any(|l| l == format!("{name} += {add};")), "{name} += {add}");
        }
        assert!(build.script.contains(&format!("var {} = [", names[3])));
        assert!(build.script.contains(&format!("var {} = \"__VERITELL_CONFIG__\";", names[4])));
        seen.insert(names);
    }
    assert!(seen.len() >= 19, "names barely vary between builds");
}

#[test]
fn shuffle_regions_keep_their_lines_and_vary() {
    let words = ["\"alpha\",", "\"bravo\",", "\"charlie\",", "\"delta\",", "\"echo\",", "\"foxtrot\","];
    let mut orders = BTreeSet::new();
    for n in 0..20 {
        let build = builder().build_with_seed(seed(n), NOW, TTL);
        let lines: Vec<&str> = build.script.split('\n').collect();
        let open = lines.iter().position(|l| l.ends_with("= [")).unwrap();
        let region: Vec<&str> = lines[open + 1..open + 7].to_vec();
        let mut sorted = region.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, words, "lines lost or changed: {region:?}");
        assert_eq!(lines[open + 7], "];");
        orders.insert(region.join(" "));
    }
    assert!(orders.len() >= 10, "only {} distinct orders in 20 builds", orders.len());
}

// ---------- sealed reports ----------

#[test]
fn seal_and_open_round_trip() {
    let b = builder();
    let build = b.build_with_seed(seed(1), NOW, TTL);
    let body = sealed(&b, &build, "the-nonce");
    assert!(body.len() <= MAX_SEALED_BYTES);
    let outer: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(outer["b"], build.id.as_str());
    assert_eq!(outer["n"], "the-nonce");
    assert!(STANDARD.decode(outer["d"].as_str().unwrap()).unwrap().len() > 28);
    assert_eq!(outer.as_object().unwrap().len(), 3);

    let opened = b.open(&body, NOW).unwrap();
    assert_eq!(opened.build_id, build.id);
    assert_eq!(opened.nonce, "the-nonce");
    let report: Value = serde_json::from_slice(&opened.report_json).unwrap();
    assert_eq!(report, v1());

    // Valid through the expiry second, on any instance with the same secret.
    let other_instance = Builder::new(TEMPLATE, SECRET).unwrap();
    assert!(other_instance.open(&body, NOW + TTL).is_ok());
    assert_eq!(b.open(&body, NOW + TTL + 1), Err(OpenError::ExpiredBuild));
}

#[test]
fn the_wire_does_not_show_report_text() {
    let b = builder();
    let build = b.build_with_seed(seed(1), NOW, TTL);
    let body = String::from_utf8(sealed(&b, &build, "the-nonce")).unwrap();
    for needle in ["webdriver", "platform", "macOS", "to_string", "eval_len"] {
        assert!(!body.contains(needle), "{needle} visible in the sealed body");
    }
    // A different IV gives a different body for the same report.
    let again = b.seal(&build.id, "the-nonce", v1().to_string().as_bytes(), [4; 12]).unwrap();
    assert_ne!(body.as_bytes(), again.as_slice());
}

#[test]
fn a_report_is_bound_to_its_nonce_and_build() {
    let b = builder();
    let build = b.build_with_seed(seed(1), NOW, TTL);
    let other = b.build_with_seed(seed(2), NOW, TTL);
    let body: Value = serde_json::from_slice(&sealed(&b, &build, "the-nonce")).unwrap();

    let mut wrong_nonce = body.clone();
    wrong_nonce["n"] = json!("another-nonce");
    assert_eq!(b.open(wrong_nonce.to_string().as_bytes(), NOW), Err(OpenError::Decrypt));

    let mut wrong_build = body.clone();
    wrong_build["b"] = json!(other.id);
    assert_eq!(b.open(wrong_build.to_string().as_bytes(), NOW), Err(OpenError::Decrypt));

    let different_secret = Builder::new(TEMPLATE, b"ffffffffffffffffffffffffffffffff").unwrap();
    assert_eq!(different_secret.open(body.to_string().as_bytes(), NOW), Err(OpenError::UnknownBuild));
}

#[test]
fn build_ids_cannot_be_forged_or_extended() {
    let b = builder();
    let build = b.build_with_seed(seed(1), NOW, TTL);
    let body: Value = serde_json::from_slice(&sealed(&b, &build, "n")).unwrap();
    let chars: Vec<char> = build.id.chars().collect();
    for i in 0..chars.len() {
        let mut changed = chars.clone();
        changed[i] = if changed[i] == 'A' { 'B' } else { 'A' };
        let mut forged = body.clone();
        forged["b"] = json!(changed.iter().collect::<String>());
        let result = b.open(forged.to_string().as_bytes(), NOW + TTL + 1_000_000);
        assert_eq!(result, Err(OpenError::UnknownBuild), "change at {i}");
    }
    for id in ["", "A", "!!!!", &"A".repeat(64), &"A".repeat(5000)] {
        let mut forged = body.clone();
        forged["b"] = json!(id);
        let result = b.open(forged.to_string().as_bytes(), NOW);
        assert!(matches!(result, Err(OpenError::UnknownBuild | OpenError::Malformed)), "{id:?}: {result:?}");
    }
    assert_eq!(b.seal("not-a-build", "n", b"{}", [0; 12]), Err(OpenError::UnknownBuild));
}

#[test]
fn altered_ciphertext_is_refused() {
    let b = builder();
    let build = b.build_with_seed(seed(1), NOW, TTL);
    let body: Value = serde_json::from_slice(&sealed(&b, &build, "n")).unwrap();
    let data = STANDARD.decode(body["d"].as_str().unwrap()).unwrap();
    for i in (0..data.len()).step_by(7) {
        let mut changed = data.clone();
        changed[i] ^= 0x80;
        let mut forged = body.clone();
        forged["d"] = json!(STANDARD.encode(&changed));
        assert_eq!(b.open(forged.to_string().as_bytes(), NOW), Err(OpenError::Decrypt), "byte {i}");
    }
    for short in [0usize, 1, 12, 27] {
        let mut forged = body.clone();
        forged["d"] = json!(STANDARD.encode(&data[..short]));
        assert_eq!(b.open(forged.to_string().as_bytes(), NOW), Err(OpenError::Malformed), "{short}");
    }
}

#[test]
fn only_the_builds_key_names_are_accepted() {
    let b = builder();
    let build = b.build_with_seed(seed(1), NOW, TTL);
    // A report with a key outside the vocabulary cannot be sealed...
    let mut extra = v1();
    extra["surprise"] = json!(1);
    assert_eq!(b.seal(&build.id, "n", extra.to_string().as_bytes(), [0; 12]), Err(OpenError::Keys));
    let mut nested = v1();
    nested["main"]["engine"]["features"]["new_feature"] = json!(true);
    assert_eq!(b.seal(&build.id, "n", nested.to_string().as_bytes(), [0; 12]), Err(OpenError::Keys));
    assert_eq!(b.seal(&build.id, "n", b"not json", [0; 12]), Err(OpenError::Keys));

    // ...and a plain version 1 report, encrypted correctly but with its keys
    // left unmapped, is refused when opened.
    let body = seal_by_hand(&build, "n", v1().to_string().as_bytes());
    assert_eq!(b.open(&body, NOW), Err(OpenError::Keys));
    // So is plaintext that is not JSON.
    let body = seal_by_hand(&build, "n", b"not json");
    assert_eq!(b.open(&body, NOW), Err(OpenError::Keys));
}

/// The build key as embedded in the script.
fn embedded_key(build: &Build) -> Vec<u8> {
    let line = build.script.split('\n').find(|l| l.contains("\"map\"")).unwrap();
    let config: Value = serde_json::from_str(&line[line.find('{').unwrap()..=line.rfind('}').unwrap()]).unwrap();
    STANDARD.decode(config["k"].as_str().unwrap()).unwrap()
}

/// Encrypts `plaintext` exactly as `seal.rs` documents, using only what the
/// script carries. This is what the browser does.
fn seal_by_hand(build: &Build, nonce: &str, plaintext: &[u8]) -> Vec<u8> {
    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(embedded_key(build));
    h.update(nonce.as_bytes());
    let cipher = Aes256Gcm::new_from_slice(&h.finalize()).unwrap();
    let iv = [9u8; 12];
    let ct = cipher
        .encrypt(Nonce::from_slice(&iv), Payload { msg: plaintext, aad: build.id.as_bytes() })
        .unwrap();
    let mut data = iv.to_vec();
    data.extend_from_slice(&ct);
    json!({ "b": build.id, "n": nonce, "d": STANDARD.encode(data) }).to_string().into_bytes()
}

#[test]
fn the_documented_wire_format_interoperates() {
    // A report mapped and encrypted by hand, from the script's own contents,
    // opens to the original. This is the contract the browser relies on.
    fn map_keys(v: &Value, map: &std::collections::BTreeMap<String, String>) -> Value {
        match v {
            Value::Object(o) => Value::Object(o.iter().map(|(k, x)| (map[k].clone(), map_keys(x, map))).collect()),
            Value::Array(a) => Value::Array(a.iter().map(|x| map_keys(x, map)).collect()),
            other => other.clone(),
        }
    }
    let b = builder();
    let build = b.build_with_seed(seed(5), NOW, TTL);
    let mapped = map_keys(&v1(), &build.key_map);
    let opened = b.open(&seal_by_hand(&build, "nonce-1", mapped.to_string().as_bytes()), NOW).unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&opened.report_json).unwrap(), v1());
    assert_eq!(opened.nonce, "nonce-1");

    // And the crate's own sealer produces something the same recipe opens.
    let ours: Value = serde_json::from_slice(&sealed(&b, &build, "nonce-1")).unwrap();
    assert_eq!(ours["b"], build.id.as_str());
}

#[test]
fn hostile_bodies() {
    let b = builder();
    let build = b.build_with_seed(seed(1), NOW, TTL);
    let big = vec![b' '; MAX_SEALED_BYTES + 1];
    assert_eq!(b.open(&big, NOW), Err(OpenError::TooLarge));

    let long_nonce = "n".repeat(MAX_NONCE_BYTES + 1);
    let cases = [
        json!(null),
        json!([]),
        json!({}),
        json!({ "b": build.id, "n": "n" }),
        json!({ "b": build.id, "n": 5, "d": "AAAA" }),
        json!({ "b": build.id, "n": "n", "d": "***" }),
        json!({ "b": build.id, "n": long_nonce, "d": STANDARD.encode([0u8; 64]) }),
        json!({ "b": 7, "n": "n", "d": STANDARD.encode([0u8; 64]) }),
    ];
    for case in cases {
        assert_eq!(b.open(case.to_string().as_bytes(), NOW), Err(OpenError::Malformed), "{case}");
    }
    for raw in [&b""[..], b"{", b"\xff\xfe", b"\"string\""] {
        assert_eq!(b.open(raw, NOW), Err(OpenError::Malformed));
    }
    let deep = "[".repeat(50_000);
    assert_eq!(b.open(deep.as_bytes(), NOW), Err(OpenError::Malformed));

    // Every truncation of a good body fails without panicking.
    let good = sealed(&b, &build, "n");
    for cut in 0..good.len() {
        assert!(b.open(&good[..cut], NOW).is_err(), "prefix of {cut} bytes opened");
    }
}

#[test]
fn deep_plaintext_does_not_overflow_the_stack() {
    let b = builder();
    let build = b.build_with_seed(seed(1), NOW, TTL);
    let deep = format!("{}1{}", "[".repeat(10_000), "]".repeat(10_000));
    let result = b.seal(&build.id, "n", deep.as_bytes(), [0; 12]);
    assert_eq!(result, Err(OpenError::Keys));
}
