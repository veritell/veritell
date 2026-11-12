//! Acceptance tests written by the project lead. DO NOT EDIT.

use veritell_behavior::*;
use veritell_core::{Class, Layer};
use serde_json::{json, Value};

/// A person filling in a short form. Hand-written from the schema; the
/// sessions in lab/recordings/human.jsonl cover more kinds of input.
fn human() -> Value {
    json!({
        "v": 1, "nonce": "n-123", "trigger": "submit", "dur_ms": 18250, "hidden_ms": 0,
        "moves": 412, "strokes": 9, "straight": 0, "steady": 0,
        "clicks": 3, "sized": 2, "centered": 0, "teleport": 0, "touches": 0,
        "keys": 24, "key_gap_cv": 612, "pastes": 0, "scrolls": 2, "submits": 1, "untrusted": 0,
        "actions": 8, "gap_cv": 840, "gap_med_ms": 1450
    })
}

fn with(changes: Value) -> Value {
    let mut base = human();
    for (k, v) in changes.as_object().unwrap() {
        base[k] = v.clone();
    }
    base
}

fn parse(v: &Value) -> Result<Summary, ParseError> {
    parse_summary(v.to_string().as_bytes())
}

fn ids(v: &Value) -> Vec<String> {
    analyze(&parse(v).unwrap(), &Params::default())
        .into_iter()
        .map(|d| d.id)
        .collect()
}

fn zeroed() -> Value {
    with(json!({
        "moves": 0, "strokes": 0, "straight": 0, "steady": 0, "clicks": 0, "sized": 0,
        "centered": 0, "teleport": 0, "touches": 0, "keys": 0, "key_gap_cv": null,
        "pastes": 0, "scrolls": 0, "submits": 0, "actions": 0, "gap_cv": null, "gap_med_ms": null
    }))
}

// ---- parsing ----

#[test]
fn human_summary_parses() {
    let s = parse(&human()).unwrap();
    assert_eq!(s.trigger, Trigger::Submit);
    assert_eq!((s.moves, s.keys, s.key_gap_cv, s.gap_med_ms), (412, 24, Some(612), Some(1450)));
    assert!(s.has_input());
}

#[test]
fn the_documented_example_parses() {
    let doc = include_str!("../../../probe/BEHAVIOR.md");
    let start = doc.rfind("```json").unwrap() + 7;
    let end = start + doc[start..].find("```").unwrap();
    assert!(parse_summary(doc[start..end].trim().as_bytes()).is_ok());
}

#[test]
fn nulls_are_accepted_only_where_allowed() {
    assert!(parse(&with(json!({"key_gap_cv": null, "gap_cv": null, "gap_med_ms": null}))).is_ok());
    for field in ["moves", "v", "nonce", "trigger", "dur_ms", "submits"] {
        assert_eq!(parse(&with(json!({ field: null }))), Err(ParseError::Malformed), "{field}");
    }
}

#[test]
fn oversized_body_is_refused_before_parsing() {
    let mut body = human().to_string().into_bytes();
    body.resize(MAX_SUMMARY_BYTES + 1, b' ');
    assert_eq!(parse_summary(&body), Err(ParseError::TooLarge));
    // Exactly at the limit, padded with whitespace, is fine.
    body.truncate(MAX_SUMMARY_BYTES);
    assert!(parse_summary(&body).is_ok());
    assert_eq!(parse_summary(&vec![b'{'; 100_000]), Err(ParseError::TooLarge));
}

#[test]
fn malformed_bodies_are_refused() {
    for body in [
        &b""[..], b"null", b"[]", b"{}", b"\"x\"", b"{\"v\":1}", b"\xff\xfe", b"{\"v\":1,",
        b"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[",
    ] {
        assert_eq!(parse_summary(body), Err(ParseError::Malformed), "{body:?}");
    }
    let mut missing = human();
    missing.as_object_mut().unwrap().remove("teleport");
    assert_eq!(parse(&missing), Err(ParseError::Malformed));
    // Nothing beyond the schema: no place to smuggle a coordinate or text.
    assert_eq!(parse(&with(json!({"x": 10}))), Err(ParseError::Malformed));
    assert_eq!(parse(&with(json!({"path": [[1, 2], [3, 4]]}))), Err(ParseError::Malformed));
    for bad in [json!(-1), json!(1.5), json!("3"), json!(true), json!([1]), json!(1e30), json!(4294967296u64)] {
        assert_eq!(parse(&with(json!({"moves": bad}))), Err(ParseError::Malformed), "{bad}");
    }
    assert_eq!(parse(&with(json!({"trigger": "click"}))), Err(ParseError::Malformed));
    assert_eq!(parse(&with(json!({"nonce": 5}))), Err(ParseError::Malformed));
}

#[test]
fn version_is_checked() {
    assert_eq!(parse(&with(json!({"v": 2}))), Err(ParseError::Version));
    assert_eq!(parse(&with(json!({"v": 0}))), Err(ParseError::Version));
}

#[test]
fn limits_are_checked() {
    for field in ["moves", "strokes", "clicks", "touches", "keys", "pastes", "scrolls", "submits", "untrusted", "actions"] {
        assert_eq!(parse(&with(json!({ field: MAX_COUNT + 1 }))), Err(ParseError::Range), "{field}");
    }
    assert!(parse(&with(json!({"moves": MAX_COUNT, "keys": MAX_COUNT}))).is_ok());
    assert_eq!(parse(&with(json!({"dur_ms": MAX_MS + 1}))), Err(ParseError::Range));
    assert_eq!(parse(&with(json!({"gap_med_ms": MAX_MS + 1}))), Err(ParseError::Range));
    assert_eq!(parse(&with(json!({"gap_cv": MAX_CV + 1}))), Err(ParseError::Range));
    assert_eq!(parse(&with(json!({"key_gap_cv": MAX_CV + 1}))), Err(ParseError::Range));
    assert!(parse(&with(json!({"gap_cv": MAX_CV, "dur_ms": MAX_MS}))).is_ok());
    assert_eq!(parse(&with(json!({"nonce": ""}))), Err(ParseError::Range));
    assert_eq!(parse(&with(json!({"nonce": "a".repeat(MAX_NONCE_BYTES + 1)}))), Err(ParseError::Range));
    assert!(parse(&with(json!({"nonce": "a".repeat(MAX_NONCE_BYTES)}))).is_ok());
    // Version is reported before range.
    assert_eq!(parse(&with(json!({"v": 3, "moves": MAX_COUNT + 1}))), Err(ParseError::Version));
}

#[test]
fn parts_cannot_exceed_their_whole() {
    for change in [
        json!({"strokes": 3, "straight": 4}),
        json!({"strokes": 3, "steady": 4}),
        json!({"clicks": 2, "sized": 3, "centered": 0}),
        json!({"clicks": 5, "sized": 2, "centered": 3}),
        json!({"clicks": 2, "sized": 0, "centered": 0, "teleport": 3}),
        json!({"dur_ms": 100, "hidden_ms": 101}),
    ] {
        assert_eq!(parse(&with(change.clone())), Err(ParseError::Inconsistent), "{change}");
    }
    // Range is reported before consistency.
    assert_eq!(
        parse(&with(json!({"strokes": 3, "straight": MAX_COUNT + 1}))),
        Err(ParseError::Range)
    );
}

#[test]
fn hostile_input_never_panics() {
    let base = human().to_string().into_bytes();
    // Every truncation and a byte flip at every position.
    for cut in 0..base.len() {
        let _ = parse_summary(&base[..cut]);
        let mut flipped = base.clone();
        flipped[cut] ^= 0x5a;
        if let Ok(s) = parse_summary(&flipped) {
            let _ = analyze(&s, &Params::default());
        }
    }
    // Extreme but valid values with extreme parameters.
    let max = with(json!({
        "moves": MAX_COUNT, "strokes": MAX_COUNT, "straight": MAX_COUNT, "steady": MAX_COUNT,
        "clicks": MAX_COUNT, "sized": MAX_COUNT, "centered": MAX_COUNT, "teleport": MAX_COUNT,
        "actions": MAX_COUNT, "gap_cv": 0, "gap_med_ms": MAX_MS
    }));
    let s = parse(&max).unwrap();
    let wild = Params {
        min_strokes: u32::MAX, straight_pct: u32::MAX, steady_pct: u32::MAX,
        min_sized_clicks: u32::MAX, min_jumped_clicks: u32::MAX, jumped_pct: u32::MAX,
        min_keys: u32::MAX, key_cv_max: u32::MAX, min_actions: u32::MAX, cadence_cv_max: u32::MAX,
        agent_min_actions: u32::MAX, agent_think_ms: u32::MAX, agent_moves_per_click: u32::MAX,
    };
    let _ = analyze(&s, &wild);
    let zero = Params {
        min_strokes: 0, straight_pct: 0, steady_pct: 0, min_sized_clicks: 0, min_jumped_clicks: 0,
        jumped_pct: 0, min_keys: 0, key_cv_max: 0, min_actions: 0,
        cadence_cv_max: 0, agent_min_actions: 0, agent_think_ms: 0, agent_moves_per_click: 0,
    };
    let _ = analyze(&s, &zero);
    let _ = analyze(&parse(&zeroed()).unwrap(), &zero);
}

// ---- rules ----

#[test]
fn a_person_yields_nothing() {
    assert!(ids(&human()).is_empty());
    // Nor does a page that was opened and closed without interaction.
    assert!(ids(&with(json!({"trigger": "hide"}))).is_empty());
    assert!(ids(&zeroed()).is_empty());
    // A touch user: no mouse at all.
    let touch = with(json!({
        "moves": 0, "strokes": 0, "clicks": 0, "sized": 0, "centered": 0, "touches": 7,
        "keys": 0, "key_gap_cv": null
    }));
    assert!(ids(&touch).is_empty());
    // A keyboard-only user who tabs through the form.
    let keyboard = with(json!({
        "moves": 0, "strokes": 0, "clicks": 0, "sized": 0, "centered": 0, "keys": 60,
        "actions": 9, "gap_cv": 700, "gap_med_ms": 2600
    }));
    assert!(ids(&keyboard).is_empty());
}

#[test]
fn submit_with_no_input_fires() {
    let mut v = zeroed();
    v["submits"] = json!(1);
    assert_eq!(ids(&v), [NO_INPUT]);
    let d = &analyze(&parse(&v).unwrap(), &Params::default())[0];
    assert_eq!((d.layer, d.penalty, d.class_hint), (Layer::Behavior, 40, Some(Class::Automated)));
    assert!(!d.detail.is_empty());
    // Any one kind of input is enough to stay quiet.
    for field in ["moves", "touches", "keys", "pastes", "scrolls"] {
        let mut w = v.clone();
        w[field] = json!(1);
        assert!(ids(&w).is_empty(), "{field}");
    }
    // No submit, no rule.
    assert!(ids(&zeroed()).is_empty());
}

#[test]
fn straight_or_constant_speed_pointer_fires() {
    assert_eq!(ids(&with(json!({"strokes": 10, "straight": 9}))), [POINTER_SCRIPTED]);
    assert_eq!(ids(&with(json!({"strokes": 10, "steady": 10}))), [POINTER_SCRIPTED]);
    // One detection even when both hold.
    assert_eq!(ids(&with(json!({"strokes": 8, "straight": 8, "steady": 8}))), [POINTER_SCRIPTED]);
    // Below the share, or with too few strokes, it does not.
    assert!(ids(&with(json!({"strokes": 10, "straight": 8, "steady": 8}))).is_empty());
    assert!(ids(&with(json!({"strokes": 7, "straight": 7, "steady": 7}))).is_empty());
    let d = &analyze(&parse(&with(json!({"strokes": 10, "straight": 9}))).unwrap(), &Params::default())[0];
    assert_eq!((d.layer, d.penalty, d.class_hint), (Layer::Behavior, 35, Some(Class::Automated)));
}

#[test]
fn clicks_on_exact_centres_fire() {
    assert_eq!(ids(&with(json!({"clicks": 3, "sized": 2, "centered": 2}))), [CLICK_CENTERED]);
    assert!(ids(&with(json!({"clicks": 3, "sized": 3, "centered": 2}))).is_empty());
    // One centred click can be luck.
    assert!(ids(&with(json!({"clicks": 1, "sized": 1, "centered": 1}))).is_empty());
    let d = &analyze(&parse(&with(json!({"clicks": 2, "sized": 2, "centered": 2}))).unwrap(), &Params::default())[0];
    assert_eq!((d.layer, d.penalty, d.class_hint), (Layer::Behavior, 35, Some(Class::Automated)));
}

#[test]
fn fixed_cadence_fires() {
    assert_eq!(ids(&with(json!({"actions": 5, "gap_cv": 50, "gap_med_ms": 500}))), [CADENCE_FIXED]);
    assert_eq!(ids(&with(json!({"actions": 12, "gap_cv": 0, "gap_med_ms": 1000}))), [CADENCE_FIXED]);
    assert!(ids(&with(json!({"actions": 5, "gap_cv": 51}))).is_empty());
    assert!(ids(&with(json!({"actions": 4, "gap_cv": 0}))).is_empty());
    assert!(ids(&with(json!({"actions": 9, "gap_cv": null, "gap_med_ms": null}))).is_empty());
    let d = &analyze(&parse(&with(json!({"actions": 5, "gap_cv": 10}))).unwrap(), &Params::default())[0];
    assert_eq!((d.layer, d.penalty, d.class_hint), (Layer::Behavior, 30, Some(Class::Automated)));
}

fn agent() -> Value {
    with(json!({
        "moves": 5, "strokes": 0, "clicks": 5, "sized": 0, "centered": 0, "teleport": 5,
        "keys": 0, "key_gap_cv": null, "actions": 6, "gap_cv": 400, "gap_med_ms": 4200
    }))
}

#[test]
fn think_act_rhythm_is_an_agent_not_a_script() {
    // Every click of this agent jumps, so the jump rule fires beside it.
    assert_eq!(ids(&agent()), [CLICK_JUMPED, AGENT_RHYTHM]);
    let d = &analyze(&parse(&agent()).unwrap(), &Params::default())[1];
    assert_eq!((d.layer, d.penalty, d.class_hint), (Layer::Behavior, 30, Some(Class::UnverifiedAgent)));
    // Each condition is needed.
    for change in [
        json!({"actions": 3}),
        json!({"gap_med_ms": 1999}),
        json!({"gap_med_ms": null, "gap_cv": null}),
        json!({"teleport": 4}),
        json!({"moves": 11}),
        json!({"clicks": 0, "teleport": 0, "moves": 0}),
    ] {
        let mut v = agent();
        for (k, val) in change.as_object().unwrap() {
            v[k] = val.clone();
        }
        assert!(!ids(&v).contains(&AGENT_RHYTHM.to_string()), "{change}");
    }
    // At the boundaries it still fires.
    let mut edge = agent();
    edge["actions"] = json!(4);
    edge["gap_med_ms"] = json!(2000);
    edge["moves"] = json!(10);
    assert_eq!(ids(&edge), [CLICK_JUMPED, AGENT_RHYTHM]);
}

#[test]
fn rules_fire_together_in_the_documented_order() {
    let all = with(json!({
        "moves": 6, "strokes": 8, "straight": 8, "steady": 0,
        "clicks": 3, "sized": 3, "centered": 3, "teleport": 3,
        "keys": 0, "key_gap_cv": null, "scrolls": 0,
        "actions": 6, "gap_cv": 20, "gap_med_ms": 3000
    }));
    assert_eq!(ids(&all), [POINTER_SCRIPTED, CLICK_CENTERED, CLICK_JUMPED, CADENCE_FIXED, AGENT_RHYTHM]);
    let mut typed = all.clone();
    typed["keys"] = json!(20);
    typed["key_gap_cv"] = json!(9);
    assert_eq!(
        ids(&typed),
        [POINTER_SCRIPTED, CLICK_CENTERED, CLICK_JUMPED, KEYS_METRONOMIC, CADENCE_FIXED, AGENT_RHYTHM]
    );
}

#[test]
fn thresholds_come_from_params() {
    let s = parse(&with(json!({"strokes": 2, "straight": 1}))).unwrap();
    assert!(analyze(&s, &Params::default()).is_empty());
    let loose = Params { min_strokes: 2, straight_pct: 50, ..Params::default() };
    assert_eq!(analyze(&s, &loose)[0].id, POINTER_SCRIPTED);

    let s = parse(&agent()).unwrap();
    let strict = Params { agent_think_ms: 5000, min_jumped_clicks: 6, ..Params::default() };
    assert!(analyze(&s, &strict).is_empty());
    let s = parse(&with(json!({"clicks": 1, "sized": 1, "centered": 1}))).unwrap();
    let one = Params { min_sized_clicks: 1, ..Params::default() };
    assert_eq!(analyze(&s, &one)[0].id, CLICK_CENTERED);
    let s = parse(&with(json!({"actions": 5, "gap_cv": 200}))).unwrap();
    let wide = Params { cadence_cv_max: 200, ..Params::default() };
    assert_eq!(analyze(&s, &wide)[0].id, CADENCE_FIXED);
}

// ---- added after the first lab recordings ----

#[test]
fn clicks_where_the_pointer_jumped_fire() {
    assert_eq!(ids(&with(json!({"clicks": 3, "teleport": 2}))), [CLICK_JUMPED]);
    assert_eq!(ids(&with(json!({"clicks": 4, "teleport": 2}))), [CLICK_JUMPED]);
    // One jump can be a window regaining focus; fewer than half is not a pattern.
    assert!(ids(&with(json!({"clicks": 3, "teleport": 1}))).is_empty());
    assert!(ids(&with(json!({"clicks": 5, "teleport": 2}))).is_empty());
    let d = &analyze(&parse(&with(json!({"clicks": 3, "teleport": 3}))).unwrap(), &Params::default())[0];
    // No class of its own: an agent's clicks jump too, and it must stay an agent.
    assert_eq!((d.layer, d.penalty, d.class_hint), (Layer::Behavior, 30, None));
    let agent_found = analyze(&parse(&agent()).unwrap(), &Params::default());
    let verdict = veritell_core::score(agent_found, None);
    assert_eq!(verdict.class, Class::UnverifiedAgent);
    assert!(!d.detail.is_empty());
    let s = parse(&with(json!({"clicks": 3, "teleport": 1}))).unwrap();
    let loose = Params { min_jumped_clicks: 1, jumped_pct: 30, ..Params::default() };
    assert_eq!(analyze(&s, &loose)[0].id, CLICK_JUMPED);
}

#[test]
fn keys_at_even_intervals_fire() {
    assert_eq!(ids(&with(json!({"keys": 8, "key_gap_cv": 50}))), [KEYS_METRONOMIC]);
    assert_eq!(ids(&with(json!({"keys": 400, "key_gap_cv": 0}))), [KEYS_METRONOMIC]);
    assert!(ids(&with(json!({"keys": 8, "key_gap_cv": 51}))).is_empty());
    assert!(ids(&with(json!({"keys": 7, "key_gap_cv": 0}))).is_empty());
    assert!(ids(&with(json!({"keys": 30, "key_gap_cv": null}))).is_empty());
    let d = &analyze(&parse(&with(json!({"keys": 11, "key_gap_cv": 4}))).unwrap(), &Params::default())[0];
    assert_eq!((d.layer, d.penalty, d.class_hint), (Layer::Behavior, 30, Some(Class::Automated)));
    assert!(!d.detail.is_empty());
    let s = parse(&with(json!({"keys": 11, "key_gap_cv": 150}))).unwrap();
    let wide = Params { key_cv_max: 150, ..Params::default() };
    assert_eq!(analyze(&s, &wide)[0].id, KEYS_METRONOMIC);
}

/// Parses one line written by `lab/record.mjs`.
fn recorded(line: &str) -> Summary {
    let mut row: Value = serde_json::from_str(line).unwrap();
    let mut summary = row["summary"].take();
    summary["nonce"] = json!("recording");
    parse(&summary).unwrap()
}

#[test]
fn recorded_people_yield_nothing() {
    let file = include_str!("../../../lab/recordings/human.jsonl");
    let mut with_input = 0;
    for line in file.lines().filter(|l| !l.trim().is_empty()) {
        let s = recorded(line);
        let found = analyze(&s, &Params::default());
        assert!(found.is_empty(), "{line}: {:?}", found.iter().map(|d| &d.id).collect::<Vec<_>>());
        with_input += u32::from(s.has_input());
    }
    assert!(with_input >= 1, "no recorded session with input");
}

#[test]
fn a_recorded_script_that_randomises_its_clicks_is_still_caught() {
    let file = include_str!("../../../lab/recordings/patchright-jitter.jsonl");
    let mut seen = 0;
    for line in file.lines().filter(|l| !l.trim().is_empty()) {
        let found: Vec<String> = analyze(&recorded(line), &Params::default()).into_iter().map(|d| d.id).collect();
        assert!(found.contains(&KEYS_METRONOMIC.to_string()), "{line}: {found:?}");
        assert!(found.contains(&CLICK_JUMPED.to_string()), "{line}: {found:?}");
        assert!(!found.contains(&CLICK_CENTERED.to_string()), "{line}: {found:?}");
        seen += 1;
    }
    assert!(seen >= 2);
}

// ---- added after the second recordings: a phone, a trackpad, keyboard only, autofill ----

#[test]
fn taps_on_a_touch_screen_are_not_jumps() {
    // What Safari on iOS sent before the script was corrected: taps counted as mouse clicks.
    let phone = with(json!({
        "moves": 0, "strokes": 0, "clicks": 9, "sized": 6, "centered": 0, "teleport": 9, "touches": 15,
        "keys": 31, "key_gap_cv": 1267, "scrolls": 7, "actions": 38, "gap_cv": 934, "gap_med_ms": 454
    }));
    assert!(ids(&phone).is_empty());
    // A slow phone user must not look like an agent either.
    let mut slow = phone.clone();
    slow["gap_med_ms"] = json!(3500);
    assert!(ids(&slow).is_empty());
    // Without any touch the same numbers are a script.
    let mut no_touch = slow.clone();
    no_touch["touches"] = json!(0);
    assert_eq!(ids(&no_touch), [CLICK_JUMPED, AGENT_RHYTHM]);
}

#[test]
fn a_few_straight_strokes_are_not_enough() {
    // Seen from a person on a trackpad: 2 of 4, 5 of 11. Four out of four can happen.
    assert!(ids(&with(json!({"strokes": 4, "straight": 4}))).is_empty());
    assert!(ids(&with(json!({"strokes": 11, "straight": 5}))).is_empty());
    assert_eq!(Params::default().min_strokes, 8);
}

// ---- added in Phase 3 wave 0: nodriver on a form ----

#[test]
fn a_form_submitted_only_by_script_made_events_fires() {
    // What nodriver sent in the lab: two untrusted clicks, one stray pointer move, no keys.
    let line = include_str!("../../../lab/recordings/nodriver-form.jsonl").lines().next().unwrap();
    let found = analyze(&recorded(line), &Params::default());
    assert_eq!(found.iter().map(|d| d.id.as_str()).collect::<Vec<_>>(), [UNTRUSTED_SUBMIT]);
    let d = &found[0];
    assert_eq!((d.layer, d.penalty, d.class_hint), (Layer::Behavior, 40, Some(Class::Automated)));
    assert!(!d.detail.is_empty());

    let base = json!({
        "moves": 1, "strokes": 0, "straight": 0, "steady": 0, "clicks": 0, "sized": 0, "centered": 0,
        "teleport": 0, "touches": 0, "keys": 0, "key_gap_cv": null, "pastes": 0, "scrolls": 0,
        "submits": 1, "untrusted": 2, "actions": 0, "gap_cv": null, "gap_med_ms": null
    });
    assert_eq!(ids(&with(base.clone())), [UNTRUSTED_SUBMIT]);
    // A page whose own code calls click() after a person's click, tap, key or paste is ordinary.
    for (field, extra) in [("clicks", json!({})), ("touches", json!({})), ("keys", json!({})), ("pastes", json!({}))] {
        let mut v = with(base.clone());
        v[field] = json!(1);
        for (k, val) in extra.as_object().unwrap() {
            v[k] = val.clone();
        }
        assert!(ids(&v).is_empty(), "{field}");
    }
    // No untrusted event, or no submit: not this rule.
    let mut trusted = with(base.clone());
    trusted["untrusted"] = json!(0);
    assert!(ids(&trusted).is_empty());
    let mut unsent = with(base.clone());
    unsent["submits"] = json!(0);
    assert!(ids(&unsent).is_empty());
    // With no input of any kind it is reported after the no-input rule.
    let mut nothing = with(base);
    nothing["moves"] = json!(0);
    assert_eq!(ids(&nothing), [NO_INPUT, UNTRUSTED_SUBMIT]);
}
