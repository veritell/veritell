//! Acceptance tests written by the project lead. DO NOT EDIT.
//!
//! The builtin engine profiles against reports captured from real browsers
//! on this bench (`probe/test/captured-*.json`, made with
//! `probe/test/run.mjs`). If a profile is changed, a capture must still
//! agree with it.

use veritell_probe::*;

const TRUTH: &str = include_str!("../data/engine_v1.json");
const SAFARI: &str = include_str!("../../../probe/test/captured-safari.json");
const CHROMIUM: &str = include_str!("../../../probe/test/captured-chromium.json");
const FIREFOX: &str = include_str!("../../../probe/test/captured-firefox.json");

const SAFARI_UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.2 Safari/605.1.15";

fn engine_ids(captured: &str, engine: Engine) -> Vec<(String, u8)> {
    let truth = parse_truth(TRUTH).unwrap();
    let report = parse_report(captured.as_bytes()).unwrap();
    let claimed = Claimed { user_agent: None, engine: Some(engine), os: None, mobile: false };
    analyze(&report, &claimed, &truth)
        .into_iter()
        .filter(|d| d.id == "engine_mismatch")
        .map(|d| (d.id, d.penalty))
        .collect()
}

#[test]
fn each_capture_fits_its_own_engine() {
    assert_eq!(engine_ids(SAFARI, Engine::Webkit), vec![]);
    assert_eq!(engine_ids(CHROMIUM, Engine::Blink), vec![]);
    assert_eq!(engine_ids(FIREFOX, Engine::Gecko), vec![]);
}

#[test]
fn a_capture_claimed_as_another_engine_does_not() {
    // All three profiles are verified (WebKit's once three iPhone browsers
    // matched it, 2026-11-10; amended by the lead).
    assert_eq!(engine_ids(CHROMIUM, Engine::Webkit), vec![("engine_mismatch".to_string(), 60)]);
    assert_eq!(engine_ids(FIREFOX, Engine::Webkit), vec![("engine_mismatch".to_string(), 60)]);
    assert_eq!(engine_ids(SAFARI, Engine::Blink), vec![("engine_mismatch".to_string(), 60)]);
    assert_eq!(engine_ids(SAFARI, Engine::Gecko), vec![("engine_mismatch".to_string(), 60)]);
}

#[test]
fn the_safari_capture_is_a_safari_capture() {
    let report = parse_report(SAFARI.as_bytes()).unwrap();
    assert!(report.main.ua.starts_with(&SAFARI_UA[..60]), "{}", report.main.ua);
}
