//! The behaviour summary and the rule parameters.
//!
//! FIXED BY THE PROJECT LEAD: DO NOT EDIT. Field meanings are in
//! `probe/BEHAVIOR.md`.

use std::fmt;

use serde::Deserialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Trigger {
    Submit,
    Hide,
    Idle,
}

/// One summary, already checked against every limit by `parse_summary`.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Summary {
    pub v: u32,
    pub nonce: String,
    pub trigger: Trigger,
    pub dur_ms: u32,
    pub hidden_ms: u32,
    pub moves: u32,
    pub strokes: u32,
    pub straight: u32,
    pub steady: u32,
    pub clicks: u32,
    pub sized: u32,
    pub centered: u32,
    pub teleport: u32,
    pub touches: u32,
    pub keys: u32,
    pub key_gap_cv: Option<u32>,
    pub pastes: u32,
    pub scrolls: u32,
    pub submits: u32,
    pub untrusted: u32,
    pub actions: u32,
    pub gap_cv: Option<u32>,
    pub gap_med_ms: Option<u32>,
}

impl Summary {
    /// True when the page saw any pointer, touch, key, paste or scroll input.
    pub fn has_input(&self) -> bool {
        self.moves > 0
            || self.clicks > 0
            || self.touches > 0
            || self.keys > 0
            || self.pastes > 0
            || self.scrolls > 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// Body longer than `MAX_SUMMARY_BYTES`.
    TooLarge,
    /// Not JSON, not the schema, a missing or unknown field, a wrong type,
    /// a negative or fractional number.
    Malformed,
    /// `v` is not 1.
    Version,
    /// A value above its limit, or a nonce that is empty or too long.
    Range,
    /// A part larger than its whole: `straight` or `steady` above `strokes`,
    /// `sized` or `teleport` above `clicks`, `centered` above `sized`,
    /// `hidden_ms` above `dur_ms`.
    Inconsistent,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ParseError::TooLarge => "summary too large",
            ParseError::Malformed => "summary malformed",
            ParseError::Version => "unsupported summary version",
            ParseError::Range => "summary value out of range",
            ParseError::Inconsistent => "summary inconsistent",
        })
    }
}

impl std::error::Error for ParseError {}

/// Rule thresholds. The defaults are set against the lab's scripted clients
/// and leave a wide margin for people; they are provisional, to be tuned on
/// each site's own traffic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Params {
    /// `behavior_pointer_scripted` needs at least this many strokes.
    pub min_strokes: u32,
    /// ... and at least this percentage of them straight,
    pub straight_pct: u32,
    /// ... or at least this percentage of them at constant speed.
    pub steady_pct: u32,
    /// `behavior_click_centered` needs at least this many sized clicks, all
    /// of them centred.
    pub min_sized_clicks: u32,
    /// `behavior_click_jumped` needs at least this many clicks where the
    /// pointer jumped,
    pub min_jumped_clicks: u32,
    /// ... and at least this percentage of all mouse clicks jumping.
    pub jumped_pct: u32,
    /// `behavior_keys_metronomic` needs at least this many keys,
    pub min_keys: u32,
    /// ... and a key-gap coefficient of variation (times 1000) at most this.
    /// A script typing with a fixed delay stays in single digits; people
    /// type far less evenly.
    pub key_cv_max: u32,
    /// `behavior_cadence_fixed` needs at least this many actions,
    pub min_actions: u32,
    /// ... and a gap coefficient of variation (times 1000) at most this.
    pub cadence_cv_max: u32,
    /// `behavior_agent_rhythm` needs at least this many actions,
    pub agent_min_actions: u32,
    /// ... a median gap of at least this many milliseconds,
    pub agent_think_ms: u32,
    /// ... at least one mouse click, every mouse click a teleport, and at
    /// most this many pointer moves per click.
    pub agent_moves_per_click: u32,
}

impl Default for Params {
    fn default() -> Self {
        Params {
            // People draw straight strokes often, on a trackpad especially,
            // so a few in a row prove little: the rule waits for eight.
            min_strokes: 8,
            straight_pct: 90,
            steady_pct: 90,
            min_sized_clicks: 2,
            min_jumped_clicks: 2,
            jumped_pct: 50,
            min_keys: 8,
            key_cv_max: 50,
            min_actions: 5,
            cadence_cv_max: 50,
            agent_min_actions: 4,
            agent_think_ms: 2000,
            agent_moves_per_click: 2,
        }
    }
}
