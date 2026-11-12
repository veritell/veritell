//! Parsing and limit checks for a behaviour summary.

use crate::types::{ParseError, Summary};
use crate::{MAX_COUNT, MAX_CV, MAX_MS, MAX_NONCE_BYTES, MAX_SUMMARY_BYTES};

const REQUIRED_NULLABLE: [&str; 3] = ["key_gap_cv", "gap_cv", "gap_med_ms"];

/// Parses a summary body and checks every limit in `probe/BEHAVIOR.md`.
///
/// Checks are made in this order and the first failure is returned:
/// `TooLarge`, `Malformed`, `Version`, `Range`, `Inconsistent`.
pub fn parse_summary(body: &[u8]) -> Result<Summary, ParseError> {
    if body.len() > MAX_SUMMARY_BYTES {
        return Err(ParseError::TooLarge);
    }
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| ParseError::Malformed)?;
    // Every field is required. serde treats a missing `Option` as `None`, so
    // the three nullable fields are checked here: the key must be present,
    // its value may be null.
    let obj = value.as_object().ok_or(ParseError::Malformed)?;
    if REQUIRED_NULLABLE.iter().any(|k| !obj.contains_key(*k)) {
        return Err(ParseError::Malformed);
    }
    let s: Summary = serde_json::from_value(value).map_err(|_| ParseError::Malformed)?;
    if s.v != 1 {
        return Err(ParseError::Version);
    }
    check_range(&s)?;
    check_consistent(&s)?;
    Ok(s)
}

fn check_range(s: &Summary) -> Result<(), ParseError> {
    let counts = [
        s.moves, s.strokes, s.straight, s.steady, s.clicks, s.sized, s.centered, s.teleport,
        s.touches, s.keys, s.pastes, s.scrolls, s.submits, s.untrusted, s.actions,
    ];
    let durations = [Some(s.dur_ms), Some(s.hidden_ms), s.gap_med_ms];
    let cvs = [s.key_gap_cv, s.gap_cv];
    let bad = counts.iter().any(|&c| c > MAX_COUNT)
        || durations.iter().flatten().any(|&d| d > MAX_MS)
        || cvs.iter().flatten().any(|&c| c > MAX_CV)
        || s.nonce.is_empty()
        || s.nonce.len() > MAX_NONCE_BYTES;
    if bad {
        Err(ParseError::Range)
    } else {
        Ok(())
    }
}

fn check_consistent(s: &Summary) -> Result<(), ParseError> {
    let bad = s.straight > s.strokes
        || s.steady > s.strokes
        || s.sized > s.clicks
        || s.teleport > s.clicks
        || s.centered > s.sized
        || s.hidden_ms > s.dur_ms;
    if bad {
        Err(ParseError::Inconsistent)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_garbage_are_malformed() {
        assert_eq!(parse_summary(b""), Err(ParseError::Malformed));
        assert_eq!(parse_summary(&[0xff; 10]), Err(ParseError::Malformed));
    }

    #[test]
    fn too_large_wins() {
        assert_eq!(parse_summary(&[b' '; MAX_SUMMARY_BYTES + 1]), Err(ParseError::TooLarge));
    }
}
