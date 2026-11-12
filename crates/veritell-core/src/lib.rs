//! Types shared by every Veritell crate.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// What kind of client this request most likely comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    Human,
    VerifiedBot,
    SignedAgent,
    UnverifiedAgent,
    Automated,
    Malicious,
}

impl Class {
    pub fn as_str(&self) -> &'static str {
        match self {
            Class::Human => "human",
            Class::VerifiedBot => "verified_bot",
            Class::SignedAgent => "signed_agent",
            Class::UnverifiedAgent => "unverified_agent",
            Class::Automated => "automated",
            Class::Malicious => "malicious",
        }
    }

    /// Higher means more hostile. Used to pick between competing hints.
    fn severity(&self) -> u8 {
        match self {
            Class::Human | Class::VerifiedBot | Class::SignedAgent => 0,
            Class::UnverifiedAgent => 1,
            Class::Automated => 2,
            Class::Malicious => 3,
        }
    }
}

impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which detection layer produced a signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Layer {
    Identity,
    Network,
    Client,
    Behavior,
    Population,
}

/// One named reason that lowers the score.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Detection {
    /// Stable identifier, for example `tls_ua_mismatch`. Policies match on it.
    pub id: String,
    pub layer: Layer,
    /// Points subtracted from the score (0 to 99).
    pub penalty: u8,
    /// Class this detection argues for, if any.
    pub class_hint: Option<Class>,
    /// Human-readable explanation for logs and the dashboard.
    pub detail: String,
}

impl Detection {
    pub fn new(id: &str, layer: Layer, penalty: u8, detail: impl Into<String>) -> Self {
        Detection {
            id: id.to_string(),
            layer,
            penalty,
            class_hint: None,
            detail: detail.into(),
        }
    }

    pub fn with_class(mut self, class: Class) -> Self {
        self.class_hint = Some(class);
        self
    }
}

/// The scorer's output for one request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verdict {
    /// 1 (certainly automated) to 99 (no evidence of automation).
    pub score: u8,
    pub class: Class,
    pub detections: Vec<Detection>,
}

pub const SCORE_MAX: u8 = 99;
pub const SCORE_MIN: u8 = 1;
/// Below this score a request with no class hint is still called automated.
pub const AUTOMATED_BELOW: u8 = 30;

/// An identity that was positively proven. It overrides every class hint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proven {
    /// A declared crawler confirmed by the identity layer.
    VerifiedBot,
    /// A request signed by a trusted agent key (Web Bot Auth).
    SignedAgent,
}

/// Rule-based scorer, version 1: start at 99 and subtract penalties.
///
/// `verified_bot` is set when the identity layer has positively verified a
/// declared crawler; that overrides every hint.
pub fn score(detections: Vec<Detection>, verified_bot: Option<&str>) -> Verdict {
    score_proven(detections, verified_bot.map(|_| Proven::VerifiedBot))
}

/// Like [`score`], for any proven identity. The score still reflects the
/// detections, so a policy can treat a misbehaving known agent differently.
pub fn score_proven(detections: Vec<Detection>, proven: Option<Proven>) -> Verdict {
    let total: u32 = detections.iter().map(|d| d.penalty as u32).sum();
    let score = (SCORE_MAX as u32)
        .saturating_sub(total)
        .max(SCORE_MIN as u32) as u8;

    let class = match proven {
        Some(Proven::VerifiedBot) => Class::VerifiedBot,
        Some(Proven::SignedAgent) => Class::SignedAgent,
        None => {
            let hinted = detections
                .iter()
                .filter_map(|d| d.class_hint)
                .max_by_key(Class::severity);
            match hinted {
                Some(c) if c.severity() > 0 => c,
                _ if score < AUTOMATED_BELOW => Class::Automated,
                _ => Class::Human,
            }
        }
    };

    Verdict {
        score,
        class,
        detections,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    /// The lightest challenge: the gateway serves its challenge page at the
    /// lowest proof-of-work difficulty, which also runs the probe. (A
    /// challenge with no visible page at all is not built.)
    Silent,
    /// Proof-of-work page.
    Pow,
    /// Visible challenge. Not built: a policy that asks for it is refused
    /// when it loads. Parsed here so that the refusal can name it.
    Interactive,
}

/// What the gateway does with a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Pass,
    Throttle { per_minute: u32 },
    Challenge(ChallengeKind),
    Tarpit,
    Decoy,
    Block,
    /// Answer 402 with an offer. Which offer is the policy's business: the
    /// policy file writes `charge(<offer>)` and resolves the name itself.
    Charge,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionParseError(pub String);

impl fmt::Display for ActionParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid action: {}", self.0)
    }
}

impl std::error::Error for ActionParseError {}

/// Parses the action syntax used in policy files:
/// `pass`, `block`, `tarpit`, `decoy`, `throttle(30/min)`,
/// `challenge(silent)`, `challenge(pow)`, `challenge(interactive)`, `charge`.
impl FromStr for Action {
    type Err = ActionParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let err = || ActionParseError(s.to_string());
        let (name, arg) = match s.split_once('(') {
            Some((name, rest)) => {
                let arg = rest.strip_suffix(')').ok_or_else(err)?;
                (name.trim(), Some(arg.trim()))
            }
            None => (s, None),
        };
        match (name, arg) {
            ("pass", None) => Ok(Action::Pass),
            ("block", None) => Ok(Action::Block),
            ("tarpit", None) => Ok(Action::Tarpit),
            ("decoy", None) => Ok(Action::Decoy),
            ("charge", None) => Ok(Action::Charge),
            ("throttle", Some(arg)) => {
                let n = arg.strip_suffix("/min").ok_or_else(err)?;
                let per_minute: u32 = n.trim().parse().map_err(|_| err())?;
                if per_minute == 0 {
                    return Err(err());
                }
                Ok(Action::Throttle { per_minute })
            }
            ("challenge", Some("silent")) => Ok(Action::Challenge(ChallengeKind::Silent)),
            ("challenge", Some("pow")) => Ok(Action::Challenge(ChallengeKind::Pow)),
            ("challenge", Some("interactive")) => {
                Ok(Action::Challenge(ChallengeKind::Interactive))
            }
            _ => Err(err()),
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Action::Pass => f.write_str("pass"),
            Action::Block => f.write_str("block"),
            Action::Tarpit => f.write_str("tarpit"),
            Action::Decoy => f.write_str("decoy"),
            Action::Charge => f.write_str("charge"),
            Action::Throttle { per_minute } => write!(f, "throttle({per_minute}/min)"),
            Action::Challenge(ChallengeKind::Silent) => f.write_str("challenge(silent)"),
            Action::Challenge(ChallengeKind::Pow) => f.write_str("challenge(pow)"),
            Action::Challenge(ChallengeKind::Interactive) => {
                f.write_str("challenge(interactive)")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det(penalty: u8, hint: Option<Class>) -> Detection {
        let d = Detection::new("x", Layer::Network, penalty, "");
        match hint {
            Some(c) => d.with_class(c),
            None => d,
        }
    }

    #[test]
    fn clean_request_is_human_99() {
        let v = score(vec![], None);
        assert_eq!((v.score, v.class), (99, Class::Human));
    }

    #[test]
    fn penalties_subtract_and_clamp() {
        assert_eq!(score(vec![det(40, None)], None).score, 59);
        assert_eq!(score(vec![det(90, None), det(90, None)], None).score, 1);
    }

    #[test]
    fn strongest_hint_wins() {
        let v = score(
            vec![det(10, Some(Class::Automated)), det(10, Some(Class::Malicious))],
            None,
        );
        assert_eq!(v.class, Class::Malicious);
    }

    #[test]
    fn low_score_without_hint_is_automated() {
        assert_eq!(score(vec![det(80, None)], None).class, Class::Automated);
    }

    #[test]
    fn verified_bot_overrides_hints() {
        let v = score(vec![det(60, Some(Class::Automated))], Some("Googlebot"));
        assert_eq!(v.class, Class::VerifiedBot);
    }

    #[test]
    fn signed_agent_overrides_hints_and_keeps_the_score() {
        let v = score_proven(vec![det(60, Some(Class::Malicious))], Some(Proven::SignedAgent));
        assert_eq!((v.class, v.score), (Class::SignedAgent, 39));
        assert_eq!(score_proven(vec![], None).class, Class::Human);
    }

    #[test]
    fn action_round_trip() {
        for s in [
            "pass",
            "block",
            "tarpit",
            "decoy",
            "charge",
            "throttle(30/min)",
            "challenge(silent)",
            "challenge(pow)",
            "challenge(interactive)",
        ] {
            let a: Action = s.parse().unwrap();
            assert_eq!(a.to_string(), s);
        }
        assert_eq!(
            " throttle( 5 /min ) ".parse::<Action>().unwrap(),
            Action::Throttle { per_minute: 5 }
        );
    }

    #[test]
    fn bad_actions_rejected() {
        for s in ["", "allow", "throttle", "throttle(0/min)", "throttle(5)", "challenge(x)", "pass()", "charge(x)", "charge()"] {
            assert!(s.parse::<Action>().is_err(), "{s} should fail");
        }
    }
}
