//! The words logged when a probe report or the engine truth is refused.

use veritell_probe::*;

#[test]
fn report_errors_say_what_was_wrong() {
    assert_eq!(ReportError::TooLarge.to_string(), "report too large");
    assert_eq!(
        ReportError::Json("eof".into()).to_string(),
        "invalid report: eof"
    );
    assert_eq!(
        ReportError::Version(9).to_string(),
        "unsupported report version 9"
    );
    assert_eq!(
        ReportError::Limit("fonts").to_string(),
        "report field over limit: fonts"
    );
}

#[test]
fn a_refused_report_carries_its_reason() {
    let e = parse_report(b"{").unwrap_err();
    assert!(e.to_string().starts_with("invalid report: "), "{e}");
    let boxed: Box<dyn std::error::Error> = Box::new(e);
    assert!(!boxed.to_string().is_empty());
}

#[test]
fn truth_errors_say_what_was_wrong() {
    assert_eq!(
        TruthError::Json("eof".into()).to_string(),
        "invalid engine truth: eof"
    );
    for (engine, name) in [
        (Engine::Blink, "blink"),
        (Engine::Gecko, "gecko"),
        (Engine::Webkit, "webkit"),
    ] {
        assert_eq!(
            TruthError::Duplicate(engine).to_string(),
            format!("duplicate profile for {name}")
        );
    }
}

#[test]
fn truth_that_is_not_json_is_refused_with_a_message() {
    let e = parse_truth("[").unwrap_err();
    assert!(e.to_string().starts_with("invalid engine truth: "), "{e}");
}
