#![no_main]
// What a browser POSTs back: the probe report and the behaviour summary,
// parsed and then analysed as the gateway does. The first byte picks which,
// and what the request's User-Agent claimed.
//
// Properties checked, beyond "does not panic": every detection has an id, a
// penalty of at most 99 and an explanation; analysis is deterministic; a
// parsed probe report, written out again, parses to the same report.
use std::sync::OnceLock;
use veritell_core::Detection;
use veritell_probe::{analyze, parse_report, parse_truth, Claimed, Engine, EngineTruth, Os};

fn truth() -> &'static EngineTruth {
    static T: OnceLock<EngineTruth> = OnceLock::new();
    T.get_or_init(|| parse_truth(include_str!("../../crates/veritell-probe/data/engine_v1.json")).unwrap())
}

fn sane(found: &[Detection]) {
    for d in found {
        assert!(!d.id.is_empty() && !d.detail.is_empty(), "detection without id or detail: {d:?}");
        assert!(d.penalty <= 99, "penalty {} over 99 for {}", d.penalty, d.id);
    }
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some((&pick, body)) = data.split_first() else { return };
    if pick & 1 == 0 {
        if let Ok(report) = parse_report(body) {
            let again = serde_json::to_vec(&report).expect("report does not serialise");
            assert_eq!(parse_report(&again).as_ref().ok(), Some(&report), "report does not survive a round trip");
            let engines = [None, Some(Engine::Blink), Some(Engine::Gecko), Some(Engine::Webkit)];
            let oses = [None, Some(Os::Windows), Some(Os::MacOs), Some(Os::Linux), Some(Os::Android), Some(Os::Ios), Some(Os::ChromeOs)];
            let claimed = Claimed {
                user_agent: Some("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"),
                engine: engines[usize::from(pick >> 1) % engines.len()],
                os: oses[usize::from(pick >> 3) % oses.len()],
                mobile: pick & 0x80 != 0,
            };
            let found = analyze(&report, &claimed, truth());
            sane(&found);
            assert_eq!(analyze(&report, &claimed, truth()), found, "same report, different detections");
        }
    } else if let Ok(summary) = veritell_behavior::parse_summary(body) {
        let params = veritell_behavior::Params::default();
        let found = veritell_behavior::analyze(&summary, &params);
        sane(&found);
        assert_eq!(veritell_behavior::analyze(&summary, &params), found, "same summary, different detections");
    }
});
