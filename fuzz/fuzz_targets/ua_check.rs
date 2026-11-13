#![no_main]
// The User-Agent table: a request's User-Agent, JA4, HTTP/2 fingerprint and
// header names, checked against each other. Fields are separated by 0xFF;
// header names by newlines.
//
// Properties checked, beyond "does not panic": every detection has an id, a
// penalty of at most 99 and an explanation; the same request gives the same
// detections; surrounding spaces on the User-Agent change nothing.
use std::sync::OnceLock;
use veritell_ua::{parse_user_agent, Observed, TruthTable};

fn table() -> &'static TruthTable {
    static T: OnceLock<TruthTable> = OnceLock::new();
    T.get_or_init(TruthTable::builtin)
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let f: Vec<&str> = data.split(|&b| b == 0xFF).map(|b| std::str::from_utf8(b).unwrap_or("")).collect();
    let get = |i: usize| f.get(i).copied();
    let headers: Vec<String> = get(3).unwrap_or("").split('\n').filter(|h| !h.is_empty()).map(str::to_owned).collect();
    let claim = parse_user_agent(get(0));
    let padded = get(0).map(|u| format!("  {u} "));
    assert_eq!(parse_user_agent(padded.as_deref()), claim, "spaces around the User-Agent change the claim");
    let obs = Observed { user_agent: get(0), ja4: get(1), h2_akamai: get(2), header_names: &headers };
    let found = table().check(&obs);
    for d in &found {
        assert!(!d.id.is_empty() && !d.detail.is_empty(), "detection without id or detail: {d:?}");
        assert!(d.penalty <= 99, "penalty {} over 99 for {}", d.penalty, d.id);
    }
    assert_eq!(table().check(&obs), found, "same request, different detections");
});
