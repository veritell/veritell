#![no_main]
// What a browser POSTs back: the probe report and the behaviour summary,
// parsed and then analysed as the gateway does. The first byte picks which,
// and what the request's engine, OS and mobile hint claimed. The body's
// length picks the claimed User-Agent (a fixed one, the report's own, or
// none) and the truth table (the shipped one, or a variant of it with
// `verified` flipped and a `math` list, so every branch of the engine rule
// is reached). A report body is also read as a truth file.
//
// Properties checked, beyond "does not panic": every detection has an id, a
// penalty of at most 99 and an explanation; analysis is deterministic; a
// parsed probe report, written out again, parses to the same report; a
// report that matches the claimed User-Agent gets no `http_ua_mismatch`;
// a body over `MAX_REPORT_BYTES` is `TooLarge` (checked on one input in 64
// by padding, since inputs stay smaller); a truth file read twice gives
// the same table; every error has a message.
use std::sync::OnceLock;
use veritell_core::Detection;
use veritell_probe::{analyze, parse_report, parse_truth, Claimed, Engine, EngineTruth, Os, ReportError, MAX_REPORT_BYTES};

fn truth() -> &'static EngineTruth {
    static T: OnceLock<EngineTruth> = OnceLock::new();
    T.get_or_init(|| parse_truth(include_str!("../../crates/veritell-probe/data/engine_v1.json")).unwrap())
}

/// The shipped table with `verified` flipped and a `math` list on every
/// profile: unverified profiles give the weak detection, and `math` is
/// checked.
fn variant() -> &'static EngineTruth {
    static T: OnceLock<EngineTruth> = OnceLock::new();
    T.get_or_init(|| {
        let mut t = truth().clone();
        for p in &mut t.profiles {
            p.verified = !p.verified;
            p.math = vec!["0.5".into(), "1e-300".into()];
        }
        t
    })
}

const CHROME_UA: &str =
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36";

fn sane(found: &[Detection]) {
    for d in found {
        assert!(!d.id.is_empty() && !d.detail.is_empty(), "detection without id or detail: {d:?}");
        assert!(d.penalty <= 99, "penalty {} over 99 for {}", d.penalty, d.id);
    }
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some((&pick, body)) = data.split_first() else { return };
    if pick & 1 == 0 {
        if body.len() % 64 == 63 {
            let mut big = body.to_vec();
            big.resize(MAX_REPORT_BYTES + 1, b' ');
            assert_eq!(parse_report(&big).err(), Some(ReportError::TooLarge), "an oversized report was read");
        }
        if let Ok(text) = std::str::from_utf8(body) {
            match parse_truth(text) {
                Ok(t) => assert_eq!(parse_truth(text).ok(), Some(t), "truth file read twice differs"),
                Err(e) => assert!(!e.to_string().is_empty(), "empty error message"),
            }
        }
        match parse_report(body) {
            Err(e) => assert!(!e.to_string().is_empty(), "empty error message"),
            Ok(report) => {
                let again = serde_json::to_vec(&report).expect("report does not serialise");
                assert_eq!(parse_report(&again).as_ref().ok(), Some(&report), "report does not survive a round trip");
                let engines = [None, Some(Engine::Blink), Some(Engine::Gecko), Some(Engine::Webkit)];
                let oses = [None, Some(Os::Windows), Some(Os::MacOs), Some(Os::Linux), Some(Os::Android), Some(Os::Ios), Some(Os::ChromeOs)];
                let own_ua = report.main.ua.clone();
                let user_agent = [Some(CHROME_UA), Some(own_ua.as_str()), None][body.len() % 3];
                let table = if body.len() / 3 % 2 == 0 { truth() } else { variant() };
                let claimed = Claimed {
                    user_agent,
                    engine: engines[usize::from(pick >> 1) % engines.len()],
                    os: oses[usize::from(pick >> 3) % oses.len()],
                    mobile: pick & 0x80 != 0,
                };
                let found = analyze(&report, &claimed, table);
                sane(&found);
                assert_eq!(analyze(&report, &claimed, table), found, "same report, different detections");
                if user_agent == Some(own_ua.as_str()) {
                    assert!(!found.iter().any(|d| d.id == "http_ua_mismatch"), "the report's own UA is a mismatch");
                }
            }
        }
    } else {
        match veritell_behavior::parse_summary(body) {
            Err(e) => assert!(!e.to_string().is_empty(), "empty error message"),
            Ok(summary) => {
                let params = veritell_behavior::Params::default();
                let found = veritell_behavior::analyze(&summary, &params);
                sane(&found);
                assert_eq!(veritell_behavior::analyze(&summary, &params), found, "same summary, different detections");
            }
        }
    }
});
