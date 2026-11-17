//! The words an operator reads when sharing is misconfigured or a bundle is
//! refused.

use veritell_share::*;

#[test]
fn config_errors_name_the_limits() {
    assert_eq!(
        ConfigError::TooSmall.to_string(),
        format!("min_networks below {MIN_NETWORKS_FLOOR}, or max_fingerprints or ttl_secs zero")
    );
    assert_eq!(
        ConfigError::TooLarge.to_string(),
        format!("min_networks above 1000 or max_fingerprints above {MAX_ENTRIES}")
    );
}

#[test]
fn a_ledger_with_a_bad_config_is_refused_with_a_message() {
    let key = ShareKey::new(b"0123456789abcdef0123456789abcdef").unwrap();
    let e = Ledger::new(
        key.clone(),
        Config {
            min_networks: 1,
            ..Config::default()
        },
    )
    .err()
    .expect("refused");
    assert_eq!(e, ConfigError::TooSmall);
    let e = Ledger::new(
        key,
        Config {
            min_networks: 1001,
            ..Config::default()
        },
    )
    .err()
    .expect("refused");
    assert_eq!(e, ConfigError::TooLarge);
    let boxed: Box<dyn std::error::Error> = Box::new(e);
    assert!(!boxed.to_string().is_empty());
}

#[test]
fn bundle_errors_say_what_was_wrong() {
    assert_eq!(
        ShareError::Files.to_string(),
        format!("bundle does not hold exactly {FILE_NAME}")
    );
    assert_eq!(
        ShareError::Format("not an array").to_string(),
        format!("{FILE_NAME}: not an array")
    );
    assert_eq!(
        ShareError::TooMany.to_string(),
        format!("more than {MAX_ENTRIES} entries")
    );
    let feed = ShareError::Bundle(veritell_feed::FeedError::Expired);
    assert_eq!(
        feed.to_string(),
        veritell_feed::FeedError::Expired.to_string(),
        "the feed's own words"
    );
}

#[test]
fn a_bundle_that_does_not_verify_is_reported_through_the_feed() {
    let e = open_bundle(b"not json", &[], 0, 0).unwrap_err();
    assert!(matches!(e, ShareError::Bundle(_)), "{e:?}");
    assert_eq!(e.to_string(), "bundle is malformed");
}
