//! The words an operator reads when quotas are misconfigured or a snapshot
//! is refused.

use veritell_quota::*;

#[test]
fn config_errors_say_what_was_wrong() {
    assert_eq!(
        ConfigError::Zero.to_string(),
        "slot_secs, window_slots, day_secs and max_identities must not be zero"
    );
    assert_eq!(ConfigError::TooLarge.to_string(), "slot_secs, window_slots or max_identities too large");
}

#[test]
fn a_zero_setting_is_refused_with_a_message() {
    let e = Quotas::new(Config { slot_secs: 0, ..Config::default() }).err().expect("refused");
    assert_eq!(e, ConfigError::Zero);
    let boxed: Box<dyn std::error::Error> = Box::new(e);
    assert!(boxed.to_string().contains("must not be zero"));
}

#[test]
fn snapshot_errors_say_what_was_wrong() {
    assert_eq!(SnapshotError::Malformed.to_string(), "quota snapshot is malformed");
    assert_eq!(SnapshotError::Mismatch.to_string(), "quota snapshot was made with another day length");
    assert_eq!(SnapshotError::NotEmpty.to_string(), "quota snapshot can only be loaded before any use");
    let boxed: Box<dyn std::error::Error> = Box::new(SnapshotError::Malformed);
    assert!(!boxed.to_string().is_empty());
}
