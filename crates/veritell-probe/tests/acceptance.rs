//! Acceptance tests written by the project lead. DO NOT EDIT.
//!
//! Engine values in this file are synthetic test data ("TEST-BLINK" and so
//! on), not browser facts. Real values live in `data/engine_v1.json` and are
//! captured from real browsers.

use veritell_core::{Class, Detection, Layer};
use veritell_probe::*;
use serde_json::{json, Value};

const UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36";

fn realm() -> Value {
    json!({
        "ua": UA,
        "platform": "MacIntel",
        "languages": ["en-US", "en"],
        "hc": 8,
        "webdriver": false,
        "uad": { "platform": "macOS", "mobile": false, "brands": ["Chromium", "Not A Brand"] },
        "engine": {
            "err_msg": "TEST-BLINK null read",
            "eval_len": 33,
            "stack_at": true,
            "features": { "f_a": true, "f_b": false, "f_c": false },
            "math": "1,2,3"
        },
        "tamper": []
    })
}

fn clean() -> Value {
    let mut worker = realm();
    worker["webdriver"] = Value::Null;
    json!({
        "v": 1,
        "nonce": "n",
        "main": realm(),
        "iframe": realm(),
        "worker": worker,
        "page": {
            "plugins": 5,
            "screen": [1728, 1117, 1728, 1079],
            "window": [1200, 800, 1200, 887],
            "dpr_x100": 200,
            "touch_points": 0,
            "webgl_vendor": "Google Inc. (Apple)",
            "webgl_renderer": "ANGLE (Apple, ANGLE Metal Renderer: Apple M2, Unspecified Version)",
            "chrome_obj": true,
            "notif_permission": "default",
            "perm_query_notif": "prompt",
            "globals": [],
            "tz": "Europe/Paris",
            "tz_offset_min": -60
        },
        "errors": []
    })
}

fn truth() -> EngineTruth {
    parse_truth(
        r#"{
        "version": 1,
        "profiles": [
          { "engine": "blink", "verified": true,
            "err_msg": ["TEST-BLINK null read", "TEST-BLINK old wording"],
            "eval_len": [33], "stack_at": true,
            "features": { "f_a": true, "f_b": false },
            "math": ["1,2,3"] },
          { "engine": "gecko", "verified": true,
            "err_msg": ["TEST-GECKO null read"],
            "eval_len": [37], "stack_at": false,
            "features": { "f_a": false, "f_b": true } },
          { "engine": "webkit", "verified": false,
            "err_msg": ["TEST-WEBKIT null read"],
            "eval_len": [37] }
        ]}"#,
    )
    .unwrap()
}

fn claimed() -> Claimed<'static> {
    Claimed {
        user_agent: Some(UA),
        engine: Some(Engine::Blink),
        os: Some(Os::MacOs),
        mobile: false,
    }
}

fn parse(v: &Value) -> ProbeReport {
    parse_report(v.to_string().as_bytes()).unwrap()
}

fn run_with(v: &Value, c: &Claimed<'_>) -> Vec<Detection> {
    analyze(&parse(v), c, &truth())
}

fn run(v: &Value) -> Vec<Detection> {
    run_with(v, &claimed())
}

fn ids(d: &[Detection]) -> Vec<&str> {
    d.iter().map(|d| d.id.as_str()).collect()
}

/// Asserts exactly one detection and returns it.
fn only(v: &Value, c: &Claimed<'_>) -> Detection {
    let d = run_with(v, c);
    assert_eq!(d.len(), 1, "expected one detection, got {:?}", ids(&d));
    assert_eq!(d[0].layer, Layer::Client);
    d[0].clone()
}

fn check(d: &Detection, id: &str, penalty: u8, hint: Option<Class>) {
    assert_eq!((d.id.as_str(), d.penalty, d.class_hint), (id, penalty, hint));
}

// ---------- clean ----------

#[test]
fn clean_report_has_no_detections() {
    assert_eq!(ids(&run(&clean())), Vec::<&str>::new());
}

#[test]
fn missing_iframe_and_worker_are_not_detections() {
    let mut v = clean();
    v["iframe"] = Value::Null;
    v["worker"] = Value::Null;
    assert!(run(&v).is_empty());
}

#[test]
fn nothing_claimed_means_only_self_consistency_is_checked() {
    assert!(run_with(&clean(), &Claimed::default()).is_empty());
}

#[test]
fn optional_fields_may_be_absent_and_unknown_fields_are_ignored() {
    let mut v = clean();
    v.as_object_mut().unwrap().remove("errors");
    v["main"].as_object_mut().unwrap().remove("tamper");
    v["page"].as_object_mut().unwrap().remove("globals");
    v["future_field"] = json!({"x": [1, 2, 3]});
    v["main"]["also_new"] = json!(true);
    assert!(run(&v).is_empty());
}

// ---------- one rule at a time ----------

#[test]
fn rule_1_webdriver() {
    for realm in ["main", "iframe"] {
        let mut v = clean();
        // Set both so that rule 4 (iframe differs from main) stays quiet.
        v["main"]["webdriver"] = json!(true);
        v["iframe"]["webdriver"] = json!(true);
        let _ = realm;
        check(&only(&v, &claimed()), "webdriver_true", 70, Some(Class::Automated));
    }
    let mut v = clean();
    v["worker"]["webdriver"] = json!(true);
    check(&only(&v, &claimed()), "webdriver_true", 70, Some(Class::Automated));
}

#[test]
fn rule_2_automation_globals() {
    let mut v = clean();
    v["page"]["globals"] = json!(["cdc_adoQpoasnfa76pfcZLmcfl_Array", "__playwright__binding__"]);
    let d = only(&v, &claimed());
    check(&d, "automation_globals", 70, Some(Class::Automated));
    assert!(d.detail.contains("__playwright__binding__"), "{}", d.detail);
}

#[test]
fn rule_3_native_tampered() {
    for realm in ["main", "iframe", "worker"] {
        let mut v = clean();
        v[realm]["tamper"] = json!([{ "target": "Navigator.prototype.webdriver", "kinds": ["to_string"] }]);
        let d = only(&v, &claimed());
        check(&d, "native_tampered", 50, Some(Class::Automated));
        assert!(d.detail.contains("Navigator.prototype.webdriver"), "{}", d.detail);
    }
}

#[test]
fn rule_4_realm_mismatch() {
    let changes: [(&str, &str, Value); 7] = [
        ("worker", "ua", json!("Mozilla/5.0 HeadlessChrome")),
        ("iframe", "platform", json!("Linux x86_64")),
        ("worker", "languages", json!(["en-US"])),
        ("worker", "hc", json!(4)),
        ("iframe", "webdriver", json!(null)),
        ("iframe", "ua", json!("x")),
        ("worker", "platform", json!("Win32")),
    ];
    for (realm, field, value) in changes {
        let mut v = clean();
        v[realm][field] = value;
        if field == "webdriver" {
            // null against false is not a difference; only two values that disagree are.
            assert!(run(&v).is_empty());
            continue;
        }
        check(&only(&v, &claimed()), "realm_mismatch", 50, Some(Class::Automated));
    }
    for (field, value) in [("err_msg", json!("TEST-BLINK old wording")), ("eval_len", json!(34))] {
        let mut v = clean();
        v["worker"]["engine"][field] = value;
        check(&only(&v, &claimed()), "realm_mismatch", 50, Some(Class::Automated));
    }
    // webdriver false in main, true in the iframe: both rule 1 and rule 4.
    let mut v = clean();
    v["iframe"]["webdriver"] = json!(true);
    assert_eq!(ids(&run(&v)), ["webdriver_true", "realm_mismatch"]);
}

#[test]
fn rule_5_http_ua_mismatch() {
    let c = Claimed {
        user_agent: Some("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
        ..claimed()
    };
    check(&only(&clean(), &c), "http_ua_mismatch", 50, Some(Class::Automated));
}

#[test]
fn rule_6_engine_mismatch() {
    // The report's signals fit the gecko profile while the request claims blink.
    let mut v = clean();
    for realm in ["main", "iframe", "worker"] {
        v[realm]["engine"] = json!({
            "err_msg": "TEST-GECKO null read", "eval_len": 37, "stack_at": false,
            "features": { "f_a": false, "f_b": true }, "math": "9"
        });
    }
    let d = only(&v, &claimed());
    check(&d, "engine_mismatch", 60, Some(Class::Automated));
    assert!(d.detail.contains("gecko"), "{}", d.detail);

    // One dimension off is enough.
    for (field, value) in [
        ("err_msg", json!("something else")),
        ("eval_len", json!(99)),
        ("stack_at", json!(false)),
        ("math", json!("1,2,4")),
    ] {
        let mut v = clean();
        for realm in ["main", "iframe", "worker"] {
            v[realm]["engine"][field] = value.clone();
        }
        check(&only(&v, &claimed()), "engine_mismatch", 60, Some(Class::Automated));
    }
    for features in [json!({ "f_a": false, "f_b": false }), json!({ "f_b": false })] {
        let mut v = clean();
        v["main"]["engine"]["features"] = features;
        check(&only(&v, &claimed()), "engine_mismatch", 60, Some(Class::Automated));
    }

    // A second accepted wording, and a feature the profile does not list.
    let mut v = clean();
    for realm in ["main", "iframe", "worker"] {
        v[realm]["engine"]["err_msg"] = json!("TEST-BLINK old wording");
        v[realm]["engine"]["features"]["f_c"] = json!(true);
    }
    assert!(run(&v).is_empty());
}

#[test]
fn rule_6_unverified_profile_is_weak_and_unknown_engine_is_skipped() {
    let c = Claimed {
        engine: Some(Engine::Webkit),
        ..claimed()
    };
    // uad is present, which rule 8 flags for a webkit claim; remove it here.
    let mut v = clean();
    for realm in ["main", "iframe", "worker"] {
        v[realm]["uad"] = Value::Null;
    }
    check(&only(&v, &c), "engine_mismatch", 20, None);

    let c = Claimed { engine: None, ..claimed() };
    assert!(run_with(&v, &c).is_empty());

    // No profile for the claimed engine: skipped.
    let empty = parse_truth(r#"{"version":1,"profiles":[]}"#).unwrap();
    let mut bad = clean();
    bad["main"]["engine"]["eval_len"] = json!(1);
    bad["iframe"]["engine"]["eval_len"] = json!(1);
    bad["worker"]["engine"]["eval_len"] = json!(1);
    assert!(analyze(&parse(&bad), &claimed(), &empty).is_empty());
}

#[test]
fn rule_7_platform_mismatch() {
    let fits: [(Os, &str); 9] = [
        (Os::Windows, "Win32"),
        (Os::MacOs, "MacIntel"),
        (Os::Linux, "Linux x86_64"),
        (Os::ChromeOs, "Linux x86_64"),
        (Os::Android, "Linux armv81"),
        (Os::Android, "Android"),
        (Os::Ios, "iPhone"),
        (Os::Ios, "iPad"),
        (Os::Ios, "iPod"),
    ];
    for (os, platform) in fits {
        let mut v = clean();
        for realm in ["main", "iframe", "worker"] {
            v[realm]["platform"] = json!(platform);
            v[realm]["uad"] = Value::Null;
        }
        v["page"]["webgl_renderer"] = Value::Null;
        let c = Claimed { os: Some(os), ..claimed() };
        assert!(run_with(&v, &c).is_empty(), "{os:?} {platform}");
    }
    let misfits: [(Os, &str); 5] = [
        (Os::Windows, "MacIntel"),
        (Os::MacOs, "Win32"),
        (Os::Linux, "Win32"),
        (Os::Ios, "MacIntel"),
        (Os::Android, "iPhone"),
    ];
    for (os, platform) in misfits {
        let mut v = clean();
        for realm in ["main", "iframe", "worker"] {
            v[realm]["platform"] = json!(platform);
            v[realm]["uad"] = Value::Null;
        }
        v["page"]["webgl_renderer"] = Value::Null;
        let c = Claimed { os: Some(os), ..claimed() };
        check(&only(&v, &c), "platform_mismatch", 40, None);
    }
}

#[test]
fn rule_8_uad_mismatch() {
    // Wrong platform name.
    let mut v = clean();
    for realm in ["main", "iframe", "worker"] {
        v[realm]["uad"]["platform"] = json!("Windows");
    }
    check(&only(&v, &claimed()), "uad_mismatch", 40, None);

    // Mobile flag disagrees.
    let mut v = clean();
    for realm in ["main", "iframe", "worker"] {
        v[realm]["uad"]["mobile"] = json!(true);
    }
    check(&only(&v, &claimed()), "uad_mismatch", 40, None);

    // A gecko claim with userAgentData present. Engine signals are set to fit gecko.
    let mut v = clean();
    for realm in ["main", "iframe", "worker"] {
        v[realm]["engine"] = json!({
            "err_msg": "TEST-GECKO null read", "eval_len": 37, "stack_at": false,
            "features": { "f_a": false, "f_b": true }, "math": ""
        });
    }
    let c = Claimed { engine: Some(Engine::Gecko), ..claimed() };
    check(&only(&v, &c), "uad_mismatch", 40, None);

    // Expected names per platform.
    for (os, name, platform) in [
        (Os::Windows, "Windows", "Win32"),
        (Os::Linux, "Linux", "Linux x86_64"),
        (Os::Android, "Android", "Linux armv81"),
        (Os::ChromeOs, "Chrome OS", "Linux x86_64"),
        (Os::ChromeOs, "Chromium OS", "Linux x86_64"),
    ] {
        let mut v = clean();
        for realm in ["main", "iframe", "worker"] {
            v[realm]["uad"]["platform"] = json!(name);
            v[realm]["platform"] = json!(platform);
        }
        v["page"]["webgl_renderer"] = Value::Null;
        let c = Claimed { os: Some(os), ..claimed() };
        assert!(run_with(&v, &c).is_empty(), "{os:?} {name}");
    }
}

#[test]
fn rule_9_touch_mismatch() {
    let mut v = clean();
    for realm in ["main", "iframe", "worker"] {
        v[realm]["uad"]["mobile"] = json!(true);
        v[realm]["uad"]["platform"] = json!("Android");
        v[realm]["platform"] = json!("Linux armv81");
    }
    v["page"]["webgl_renderer"] = json!("Adreno (TM) 740");
    let c = Claimed { os: Some(Os::Android), mobile: true, ..claimed() };
    check(&only(&v, &c), "touch_mismatch", 25, None);
    v["page"]["touch_points"] = json!(5);
    assert!(run_with(&v, &c).is_empty());
}

#[test]
fn rule_10_gpu_platform_mismatch() {
    let mut v = clean();
    v["page"]["webgl_renderer"] =
        json!("ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)");
    check(&only(&v, &claimed()), "gpu_platform_mismatch", 40, None);

    for (os, platform, uad, renderer) in [
        (Os::Windows, "Win32", "Windows", "ANGLE (Apple, ANGLE Metal Renderer: Apple M2, Unspecified Version)"),
        (Os::Linux, "Linux x86_64", "Linux", "Apple M1"),
        (Os::Linux, "Linux x86_64", "Linux", "ANGLE (Intel, Intel(R) UHD Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ] {
        let mut v = clean();
        for realm in ["main", "iframe", "worker"] {
            v[realm]["platform"] = json!(platform);
            v[realm]["uad"]["platform"] = json!(uad);
        }
        v["page"]["webgl_renderer"] = json!(renderer);
        let c = Claimed { os: Some(os), ..claimed() };
        check(&only(&v, &c), "gpu_platform_mismatch", 40, None);
    }

    // No claimed platform: not checked.
    let mut v = clean();
    v["page"]["webgl_renderer"] = json!("Direct3D11");
    let c = Claimed { os: None, ..claimed() };
    assert!(run_with(&v, &c).is_empty());
}

#[test]
fn rule_11_gpu_software() {
    for renderer in [
        "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero) (0x0000C0DE)), SwiftShader driver)",
        "llvmpipe (LLVM 15.0.7, 256 bits)",
        "Gallium 0.4 on softpipe",
    ] {
        let mut v = clean();
        v["page"]["webgl_renderer"] = json!(renderer);
        check(&only(&v, &claimed()), "gpu_software", 25, None);
    }
}

#[test]
fn rule_12_window_implausible() {
    for (field, index) in [("window", 2), ("window", 3), ("screen", 0), ("screen", 1)] {
        let mut v = clean();
        v["page"][field][index] = json!(0);
        check(&only(&v, &claimed()), "window_implausible", 20, None);
    }
    // Inner size alone being zero (a hidden tab) is not flagged.
    let mut v = clean();
    v["page"]["window"][0] = json!(0);
    v["page"]["window"][1] = json!(0);
    assert!(run(&v).is_empty());
}

#[test]
fn rule_13_languages_empty() {
    let mut v = clean();
    for realm in ["main", "iframe", "worker"] {
        v[realm]["languages"] = json!([]);
    }
    check(&only(&v, &claimed()), "languages_empty", 30, None);
}

#[test]
fn rule_14_headless_permissions() {
    let mut v = clean();
    v["page"]["notif_permission"] = json!("denied");
    check(&only(&v, &claimed()), "headless_permissions", 30, Some(Class::Automated));
    v["page"]["perm_query_notif"] = json!("denied");
    assert!(run(&v).is_empty());
    v["page"]["notif_permission"] = Value::Null;
    v["page"]["perm_query_notif"] = Value::Null;
    assert!(run(&v).is_empty());
}

#[test]
fn detections_come_in_rule_order_without_duplicates() {
    let mut v = clean();
    v["main"]["webdriver"] = json!(true);
    v["iframe"]["webdriver"] = json!(true);
    v["worker"]["webdriver"] = json!(true);
    v["page"]["globals"] = json!(["__pw_x"]);
    v["main"]["tamper"] = json!([{ "target": "a", "kinds": ["k"] }]);
    v["iframe"]["tamper"] = json!([{ "target": "b", "kinds": ["k"] }]);
    v["worker"]["ua"] = json!("other");
    v["worker"]["hc"] = json!(1);
    v["main"]["engine"]["eval_len"] = json!(5);
    v["main"]["languages"] = json!([]);
    v["page"]["webgl_renderer"] = json!("Direct3D11 SwiftShader");
    v["page"]["window"] = json!([0, 0, 0, 0]);
    v["page"]["notif_permission"] = json!("denied");
    let c = Claimed {
        user_agent: Some("curl/8"),
        os: Some(Os::Android),
        mobile: true,
        ..claimed()
    };
    assert_eq!(
        ids(&run_with(&v, &c)),
        [
            "webdriver_true",
            "automation_globals",
            "native_tampered",
            "realm_mismatch",
            "http_ua_mismatch",
            "engine_mismatch",
            "platform_mismatch",
            "uad_mismatch",
            "touch_mismatch",
            "gpu_platform_mismatch",
            "gpu_software",
            "window_implausible",
            "languages_empty",
            "headless_permissions",
        ]
    );
}

// ---------- hostile input ----------

#[test]
fn client_text_in_detail_is_sanitized_and_bounded() {
    let mut v = clean();
    v["page"]["globals"] = json!(["<script>alert(1)</script>", "a\nb\u{202e}c\"'&", "é".repeat(200)]);
    let tamper: Vec<Value> = (0..60)
        .map(|i| json!({ "target": format!("<img src=x onerror={i}>{}", "T".repeat(300)), "kinds": ["\u{0}\r\n"] }))
        .collect();
    v["main"]["tamper"] = json!(tamper);
    for d in run(&v) {
        assert!(d.detail.chars().count() <= 256, "{} is {} chars", d.id, d.detail.len());
        assert!(
            d.detail
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || " ._-:/(),;=?".contains(c)),
            "{}: {:?}",
            d.id,
            d.detail
        );
    }
}

#[test]
fn reports_over_a_limit_are_rejected() {
    let big = vec![b' '; MAX_REPORT_BYTES + 1];
    assert_eq!(parse_report(&big), Err(ReportError::TooLarge));

    let mut v = clean();
    v["main"]["ua"] = json!("a".repeat(MAX_STRING_BYTES + 1));
    assert_eq!(parse_report(v.to_string().as_bytes()), Err(ReportError::Limit("main.ua")));

    let mut v = clean();
    v["main"]["ua"] = json!("a".repeat(MAX_STRING_BYTES));
    v["iframe"]["ua"] = v["main"]["ua"].clone();
    v["worker"]["ua"] = v["main"]["ua"].clone();
    assert!(parse_report(v.to_string().as_bytes()).is_ok());

    let mut v = clean();
    v["page"]["globals"] = json!(vec!["g"; MAX_ITEMS + 1]);
    assert_eq!(
        parse_report(v.to_string().as_bytes()),
        Err(ReportError::Limit("page.globals"))
    );

    let mut v = clean();
    v["worker"]["tamper"] = json!([{ "target": "t", "kinds": vec!["k"; MAX_ITEMS + 1] }]);
    assert_eq!(
        parse_report(v.to_string().as_bytes()),
        Err(ReportError::Limit("worker.tamper.kinds"))
    );

    let mut v = clean();
    let mut features = serde_json::Map::new();
    for i in 0..=MAX_ITEMS {
        features.insert(format!("f{i}"), json!(true));
    }
    v["iframe"]["engine"]["features"] = Value::Object(features);
    assert_eq!(
        parse_report(v.to_string().as_bytes()),
        Err(ReportError::Limit("iframe.engine.features"))
    );

    let mut v = clean();
    v["errors"] = json!(["e".repeat(MAX_STRING_BYTES + 1)]);
    assert_eq!(parse_report(v.to_string().as_bytes()), Err(ReportError::Limit("errors")));

    let mut v = clean();
    v["page"]["webgl_renderer"] = json!("r".repeat(MAX_STRING_BYTES + 1));
    assert_eq!(
        parse_report(v.to_string().as_bytes()),
        Err(ReportError::Limit("page.webgl_renderer"))
    );
}

#[test]
fn wrong_shapes_are_rejected() {
    let mut v = clean();
    v["v"] = json!(2);
    assert_eq!(parse_report(v.to_string().as_bytes()), Err(ReportError::Version(2)));

    let mut v = clean();
    v.as_object_mut().unwrap().remove("main");
    assert!(matches!(parse_report(v.to_string().as_bytes()), Err(ReportError::Json(_))));

    let mut v = clean();
    v["main"]["hc"] = json!(-1);
    assert!(matches!(parse_report(v.to_string().as_bytes()), Err(ReportError::Json(_))));

    let mut v = clean();
    v["page"]["screen"] = json!([1, 2, 3]);
    assert!(matches!(parse_report(v.to_string().as_bytes()), Err(ReportError::Json(_))));

    for body in [&b""[..], b"null", b"[]", b"{", b"\xff\xfe", b"{\"v\":1}"] {
        assert!(matches!(parse_report(body), Err(ReportError::Json(_))), "{body:?}");
    }

    // Deep nesting must not overflow the stack.
    let deep = "[".repeat(20_000);
    assert!(parse_report(deep.as_bytes()).is_err());
    let deep = format!("{{\"v\":1,\"nonce\":\"n\",\"main\":{}", "{\"a\":".repeat(5_000));
    assert!(parse_report(deep.as_bytes()).is_err());
}

#[test]
fn every_truncation_of_a_report_fails_cleanly() {
    let text = clean().to_string();
    let bytes = text.as_bytes();
    for cut in 0..bytes.len() {
        assert!(parse_report(&bytes[..cut]).is_err(), "prefix of {cut} bytes parsed");
    }
    assert!(parse_report(bytes).is_ok());
}

#[test]
fn truth_files() {
    assert_eq!(truth().profiles.len(), 3);
    assert!(matches!(parse_truth("nope"), Err(TruthError::Json(_))));
    assert_eq!(
        parse_truth(
            r#"{"version":1,"profiles":[
            {"engine":"gecko","verified":true},{"engine":"gecko","verified":false}]}"#
        ),
        Err(TruthError::Duplicate(Engine::Gecko))
    );
    // The shipped file must always load.
    let shipped = include_str!("../data/engine_v1.json");
    parse_truth(shipped).unwrap();
}

// ---------- nonce ----------

const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";
const BINDING: [u8; 16] = [7; 16];

fn key() -> ProbeKey {
    ProbeKey::from_secret(SECRET).unwrap()
}

#[test]
fn nonce_round_trip() {
    let n = issue_nonce(&key(), &BINDING, 1000, 120);
    assert!(n.len() <= 128, "{}", n.len());
    assert!(n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'), "{n}");
    let info = verify_nonce(&key(), &n, &BINDING, 1000).unwrap();
    assert_eq!(info.expires_at, 1120);
    assert_eq!(verify_nonce(&key(), &n, &BINDING, 1120).unwrap(), info);
    assert_eq!(verify_nonce(&key(), &n, &BINDING, 1121), Err(NonceError::Expired));
}

#[test]
fn nonces_are_unique() {
    let a = issue_nonce(&key(), &BINDING, 1000, 120);
    let b = issue_nonce(&key(), &BINDING, 1000, 120);
    assert_ne!(a, b);
    let ia = verify_nonce(&key(), &a, &BINDING, 1000).unwrap();
    let ib = verify_nonce(&key(), &b, &BINDING, 1000).unwrap();
    assert_ne!(ia.id, ib.id);
}

#[test]
fn nonce_is_bound() {
    let n = issue_nonce(&key(), &BINDING, 1000, 120);
    let mut other = BINDING;
    other[15] ^= 1;
    assert_eq!(verify_nonce(&key(), &n, &other, 1000), Err(NonceError::BindingMismatch));
}

#[test]
fn nonce_from_another_secret_fails() {
    let n = issue_nonce(&key(), &BINDING, 1000, 120);
    let other = ProbeKey::from_secret(b"ffffffffffffffffffffffffffffffff").unwrap();
    assert_eq!(verify_nonce(&other, &n, &BINDING, 1000), Err(NonceError::BadMac));
}

#[test]
fn weak_secret_is_refused() {
    assert!(ProbeKey::from_secret(&SECRET[..31]).is_none());
    assert!(ProbeKey::from_secret(b"").is_none());
}

#[test]
fn every_altered_nonce_fails() {
    let n = issue_nonce(&key(), &BINDING, 1000, 120);
    let chars: Vec<char> = n.chars().collect();
    for i in 0..chars.len() {
        let mut changed = chars.clone();
        changed[i] = if changed[i] == 'A' { 'B' } else { 'A' };
        let changed: String = changed.into_iter().collect();
        assert!(verify_nonce(&key(), &changed, &BINDING, 1000).is_err(), "change at {i} accepted");
        let cut: String = chars[..i].iter().collect();
        assert!(verify_nonce(&key(), &cut, &BINDING, 1000).is_err(), "prefix {i} accepted");
    }
    let longer = format!("{n}A");
    assert!(verify_nonce(&key(), &longer, &BINDING, 1000).is_err());
    for g in ["", "!", "é", "====", &"A".repeat(4096)] {
        assert_eq!(verify_nonce(&key(), g, &BINDING, 1000), Err(NonceError::Malformed), "{g:?}");
    }
}

#[test]
fn expiry_arithmetic_does_not_overflow() {
    let n = issue_nonce(&key(), &BINDING, u64::MAX - 5, 120);
    let info = verify_nonce(&key(), &n, &BINDING, u64::MAX).unwrap();
    assert_eq!(info.expires_at, u64::MAX);
}
