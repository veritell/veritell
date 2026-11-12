//! Event schema and traits. FIXED BY THE PROJECT LEAD: DO NOT EDIT.

use std::collections::BTreeMap;

use veritell_core::{Class, Detection};
use serde::{Deserialize, Serialize};

/// What happened to produce an event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// A proxied (or refused) request.
    Request,
    /// A probe report was received.
    Probe,
    /// A challenge solution was checked.
    Challenge,
}

impl EventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            EventKind::Request => "request",
            EventKind::Probe => "probe",
            EventKind::Challenge => "challenge",
        }
    }
}

/// One decision, with everything needed to explain it.
///
/// Text fields come from the client and may contain anything. They are
/// already length-limited by the gateway. Consumers must treat them as data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Unix time in milliseconds.
    pub ts_ms: u64,
    pub kind: EventKind,
    pub ip: String,
    pub method: String,
    pub host: String,
    pub path: String,
    pub user_agent: String,
    pub ja4: String,
    pub h2: String,
    pub score: u8,
    pub class: Class,
    /// The reasons: every detection that contributed, with its explanation.
    pub detections: Vec<Detection>,
    /// Name of the verified crawler or signed agent, or "".
    pub identity: String,
    pub asn: u32,
    pub net_class: String,
    /// Session token state: "none", "valid", "expired", ...
    pub token: String,
    /// What the policy asked for, for example "challenge(pow)".
    pub action: String,
    pub enforced: bool,
    pub route: String,
    pub rule: String,
    /// What the gateway did: "passed", "challenged", "blocked", ...
    pub outcome: String,
    /// A known-person label set by the operator's enrolment link, or "".
    /// For measuring false positives only; it never affects a decision.
    #[serde(default)]
    pub known: String,
    /// For a behaviour report, its counts as a JSON object (see
    /// probe/BEHAVIOR.md: counts and timings only, nothing typed); else "".
    #[serde(default)]
    pub summary: String,
    /// The client's TCP SYN signature (p0f layout, see veritell-fp's
    /// `syn`), or "" where it was not measured. Never scored.
    #[serde(default)]
    pub tcp: String,
    /// The SYN's TTL or hop limit as it arrived, or 0 with `tcp` "".
    #[serde(default)]
    pub tcp_ttl: u8,
}

/// Receives events on the request path.
pub trait EventSink: Send + Sync {
    /// Must not block on I/O and must not panic.
    fn record(&self, event: &Event);
}

/// Selects events. Every set field must match; an unset field matches all.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Filter {
    pub class: Option<Class>,
    /// An event matches when it has a detection with this id.
    pub detection: Option<String>,
    /// An event matches when `score <= max_score`.
    pub max_score: Option<u8>,
    /// Exact match on the address text.
    pub ip: Option<String>,
    pub kind: Option<EventKind>,
    pub outcome: Option<String>,
    /// The site: matches `Event::host`, ASCII case ignored. One gateway can
    /// serve several sites (`--upstream-host`).
    pub host: Option<String>,
}

/// Counts over a time window.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    pub total: u64,
    /// Keyed by `Class::as_str()`.
    pub by_class: BTreeMap<String, u64>,
    pub by_outcome: BTreeMap<String, u64>,
    /// Detection id and count, most frequent first, ties by id ascending,
    /// at most 20 entries.
    pub top_detections: Vec<(String, u64)>,
    /// Ten buckets of score: index `min(score / 10, 9)`.
    pub score_histogram: [u64; 10],
    /// Events the store has discarded to stay within its capacity since it
    /// was created (not limited to the window).
    pub evicted: u64,
    /// Requests per site (`Event::host`, lower case) in the window, most
    /// first, ties by name, at most 20. Never narrowed by a site filter, so
    /// it always lists every site the gateway served.
    #[serde(default)]
    pub by_host: Vec<(String, u64)>,
}

/// Read access for the dashboard.
pub trait EventQuery: Send + Sync {
    /// Newest first, at most `limit` events.
    fn recent(&self, limit: usize, filter: &Filter) -> Vec<Event>;
    /// Counts over events with `ts_ms >= since_ms`. Only `Request` events
    /// are counted in `by_class`, `by_outcome`, `top_detections` and
    /// `score_histogram`; `total` counts those same events.
    fn summary(&self, since_ms: u64) -> Summary;
    /// The same counts for one site only (`host`, ASCII case ignored), or for
    /// all when `None`. `by_host` and `evicted` are never narrowed. A store
    /// that cannot filter by site answers for all sites.
    fn summary_for(&self, since_ms: u64, host: Option<&str>) -> Summary {
        let _ = host;
        self.summary(since_ms)
    }
}
