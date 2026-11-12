use veritell_behavior::*;
use serde_json::{json, Value};

fn full() -> Value {
    json!({
        "v": 1, "nonce": "n-123", "trigger": "submit", "dur_ms": 18250, "hidden_ms": 0,
        "moves": 412, "strokes": 9, "straight": 0, "steady": 0,
        "clicks": 3, "sized": 2, "centered": 0, "teleport": 0, "touches": 0,
        "keys": 24, "key_gap_cv": 612, "pastes": 0, "scrolls": 2, "submits": 1, "untrusted": 0,
        "actions": 8, "gap_cv": 840, "gap_med_ms": 1450
    })
}

const NULLABLE: [&str; 3] = ["key_gap_cv", "gap_cv", "gap_med_ms"];

#[test]
fn missing_nullable_key_is_refused() {
    for k in NULLABLE {
        let mut v = full();
        v.as_object_mut().unwrap().remove(k);
        assert_eq!(parse_summary(v.to_string().as_bytes()), Err(ParseError::Malformed), "{k}");
    }
}

#[test]
fn explicit_null_is_accepted() {
    for k in NULLABLE {
        let mut v = full();
        v[k] = Value::Null;
        let s = parse_summary(v.to_string().as_bytes()).unwrap();
        assert!(match k {
            "key_gap_cv" => s.key_gap_cv.is_none(),
            "gap_cv" => s.gap_cv.is_none(),
            _ => s.gap_med_ms.is_none(),
        });
    }
    let mut v = full();
    for k in NULLABLE {
        v[k] = Value::Null;
    }
    assert!(parse_summary(v.to_string().as_bytes()).is_ok());
}
