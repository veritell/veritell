//! The words an operator reads when a model file is refused, and the score
//! a model gives at its edges.

use veritell_model::*;

#[test]
fn every_refusal_has_its_own_words() {
    let cases = [
        (ModelError::TooLarge, "model file too large"),
        (ModelError::Malformed, "model file malformed"),
        (ModelError::Version, "unsupported model version"),
        (ModelError::Limits, "model exceeds a size or depth limit"),
        (ModelError::Structure, "model structure invalid"),
    ];
    for (error, text) in cases {
        assert_eq!(error.to_string(), text);
        let boxed: Box<dyn std::error::Error> = Box::new(error);
        assert_eq!(boxed.to_string(), text);
    }
}

#[test]
fn a_score_without_a_probability_is_undecided() {
    let e = Evaluation {
        raw: f64::NAN,
        probability: f64::NAN,
        bias: 0.0,
        contributions: Vec::new(),
    };
    assert_eq!(e.score(), 50);
}
