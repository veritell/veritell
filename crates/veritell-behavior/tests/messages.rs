//! The words logged when a behaviour summary is refused.

use veritell_behavior::*;

#[test]
fn every_refusal_has_its_own_words() {
    let cases = [
        (ParseError::TooLarge, "summary too large"),
        (ParseError::Malformed, "summary malformed"),
        (ParseError::Version, "unsupported summary version"),
        (ParseError::Range, "summary value out of range"),
        (ParseError::Inconsistent, "summary inconsistent"),
    ];
    for (error, text) in cases {
        assert_eq!(error.to_string(), text);
        let boxed: Box<dyn std::error::Error> = Box::new(error);
        assert_eq!(boxed.to_string(), text);
    }
}
