//! The words an operator reads when a token or an issuer key is refused.

use veritell_privacypass::*;

#[test]
fn every_refusal_says_what_went_wrong() {
    let cases = [
        (PassError::Name, "not a server name"),
        (PassError::Key("too short"), "issuer key refused: too short"),
        (PassError::Malformed, "malformed token"),
        (PassError::UnknownType(0x0001), "token type 0x0001 is not supported"),
        (PassError::UnknownKey, "token from an issuer key that is not trusted"),
        (PassError::WrongChallenge, "token for another challenge"),
        (PassError::BadAuthenticator, "token signature does not verify"),
    ];
    for (error, text) in cases {
        assert_eq!(error.to_string(), text);
    }
}

#[test]
fn a_refused_key_reaches_the_operator_with_its_reason() {
    let e = IssuerKey::new("issuer.test", b"not a key").unwrap_err();
    assert!(e.to_string().starts_with("issuer key refused: "), "{e}");
    let e = IssuerKey::new("[::1]", b"not a key").unwrap_err();
    assert_eq!(e.to_string(), "not a server name", "the name is checked first");
}
