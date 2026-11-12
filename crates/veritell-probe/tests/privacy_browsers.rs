//! Acceptance tests written by the project lead for rule 3 and privacy
//! browsers. DO NOT EDIT.
//!
//! The DuckDuckGo User-Agent and the two patched targets are what a real
//! DuckDuckGo 27.2 on an iPhone sent (Phase 3, 2026-11-10).

use veritell_probe::*;
use serde_json::{json, Value};

const DDG_UA: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.2 Mobile/15E148 Safari/604.1 Ddg/27.2";
const SAFARI_UA: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.2 Mobile/15E148 Safari/604.1";
const CHROME_UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36 Ddg/27.2";

const HC: &str = "Navigator.prototype.hardwareConcurrency";
const PERMS: &str = "Permissions.prototype.query";

fn realm(ua: &str, tamper: Value) -> Value {
    json!({
        "ua": ua, "platform": "iPhone", "languages": ["en-US"], "hc": 4, "webdriver": false,
        "engine": { "err_msg": "x", "eval_len": 37, "stack_at": true, "features": {}, "math": "1" },
        "tamper": tamper
    })
}

fn report(ua: &str, main: Value, iframe: Value) -> ProbeReport {
    let v = json!({
        "v": 1, "nonce": "n",
        "main": realm(ua, main), "iframe": realm(ua, iframe),
        "page": {
            "plugins": 0, "screen": [390, 844, 390, 844], "window": [390, 664, 390, 664],
            "dpr_x100": 300, "touch_points": 5, "chrome_obj": false,
            "notif_permission": "default", "perm_query_notif": "prompt",
            "globals": [], "tz": "Europe/Paris", "tz_offset_min": -60
        },
        "errors": []
    });
    parse_report(v.to_string().as_bytes()).unwrap()
}

fn claimed(ua: &str, engine: Engine) -> Claimed<'_> {
    Claimed { user_agent: Some(ua), engine: Some(engine), os: Some(Os::Ios), mobile: true }
}

fn tampered(r: &ProbeReport, c: &Claimed<'_>) -> Option<String> {
    let truth = parse_truth(r#"{"version":1,"profiles":[]}"#).unwrap();
    analyze(r, c, &truth).into_iter().find(|d| d.id == "native_tampered").map(|d| d.detail)
}

fn patch(target: &str, kinds: &[&str]) -> Value {
    json!({ "target": target, "kinds": kinds })
}

#[test]
fn duckduckgo_s_own_patches_are_not_tampering() {
    let r = report(
        DDG_UA,
        json!([patch(HC, &["proxy"]), patch(PERMS, &["descriptor", "to_string", "proxy"])]),
        json!([patch(PERMS, &["descriptor", "to_string", "proxy"])]),
    );
    assert_eq!(tampered(&r, &claimed(DDG_UA, Engine::Webkit)), None);
}

#[test]
fn the_same_patches_in_safari_are_tampering() {
    let r = report(SAFARI_UA, json!([patch(HC, &["proxy"]), patch(PERMS, &["proxy"])]), json!([]));
    let detail = tampered(&r, &claimed(SAFARI_UA, Engine::Webkit)).expect("fires");
    assert!(detail.contains(HC) && detail.contains(PERMS), "{detail}");
}

#[test]
fn any_other_patch_still_counts_for_duckduckgo() {
    let r = report(
        DDG_UA,
        json!([patch(HC, &["proxy"]), patch("Navigator.prototype.webdriver", &["to_string"])]),
        json!([]),
    );
    let detail = tampered(&r, &claimed(DDG_UA, Engine::Webkit)).expect("fires");
    assert!(detail.contains("Navigator.prototype.webdriver"), "{detail}");
    assert!(!detail.contains(HC), "{detail}");
}

#[test]
fn the_marker_on_another_engine_is_not_believed() {
    let r = report(CHROME_UA, json!([patch(PERMS, &["proxy"])]), json!([]));
    assert!(tampered(&r, &claimed(CHROME_UA, Engine::Blink)).is_some());
}

#[test]
fn no_user_agent_no_exemption() {
    let r = report(DDG_UA, json!([patch(PERMS, &["proxy"])]), json!([]));
    let c = Claimed { user_agent: None, engine: Some(Engine::Webkit), os: Some(Os::Ios), mobile: true };
    assert!(tampered(&r, &c).is_some());
}
