//! Load shedding: a cap on requests in flight to the origin, and who is
//! turned away first when the origin is that busy.
//!
//! The flood guard protects the gateway before a request is scored; this
//! protects the origin after it is, so it can use everything the gateway
//! knows. Past `soft` (three quarters of the cap) the least trusted are
//! refused: an automated, malicious or unverified-agent class, a hosting
//! network, or a score under 60. Past the cap, everyone without a reason to
//! be trusted is. Never refused: a valid session token, a known-person
//! mark, a verified crawler or signed agent.
//!
//! It has its own switch, `--shed off|log|enforce` (default `log`), apart
//! from the policy mode: `log` lets everything through and writes one
//! `shed` line a second with what `enforce` would have refused.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use crate::flood::GuardMode;

/// How much a request is trusted, for shedding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Trust {
    /// Turned away first, past the soft limit.
    Low,
    /// Turned away past the cap.
    Plain,
    /// Never turned away.
    Kept,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShedVerdict {
    Admit,
    /// Enforced: answer 503.
    Shed,
    /// `log` mode: let it through, but `enforce` would have refused it.
    WouldShed,
}

pub struct Shedder {
    pub mode: GuardMode,
    pub cap: u32,
    in_flight: Arc<AtomicU32>,
    /// (second, refused or would-be-refused in it, peak in flight in it)
    second: Mutex<(u64, u32, u32)>,
}

/// Held while a request is with the origin; gives its place back when
/// dropped (with the request's context).
pub struct InFlight(Arc<AtomicU32>);

impl Drop for InFlight {
    fn drop(&mut self) {
        let _ = self.0.try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            Some(n.saturating_sub(1))
        });
    }
}

impl Shedder {
    pub const DEFAULT_CAP: u32 = 256;

    pub fn new(mode: GuardMode, cap: u32) -> Self {
        Shedder {
            mode,
            cap: cap.max(1),
            in_flight: Arc::new(AtomicU32::new(0)),
            second: Mutex::new((0, 0, 0)),
        }
    }

    fn soft(&self) -> u32 {
        (self.cap / 4 * 3).max(1)
    }

    /// Whether a request of this trust may go to the origin now. An admitted
    /// request (also a `WouldShed` one) gets its place with [`Shedder::enter`].
    /// The second return is a `shed` line to write, at most one a second.
    pub fn check(&self, trust: Trust, now: u64) -> (ShedVerdict, Option<serde_json::Value>) {
        if self.mode == GuardMode::Off {
            return (ShedVerdict::Admit, None);
        }
        let busy = self.in_flight.load(Ordering::Acquire);
        let over = match trust {
            Trust::Kept => false,
            Trust::Plain => busy >= self.cap,
            Trust::Low => busy >= self.soft(),
        };
        let line = self.note(now, over, busy);
        let verdict = match (over, self.mode) {
            (false, _) => ShedVerdict::Admit,
            (true, GuardMode::Enforce) => ShedVerdict::Shed,
            (true, _) => ShedVerdict::WouldShed,
        };
        (verdict, line)
    }

    /// Takes a place in flight.
    pub fn enter(&self) -> InFlight {
        self.in_flight.fetch_add(1, Ordering::AcqRel);
        InFlight(Arc::clone(&self.in_flight))
    }

    #[cfg(test)]
    pub fn in_flight(&self) -> u32 {
        self.in_flight.load(Ordering::Acquire)
    }

    /// Counts this second; returns the last second's line when a new
    /// second starts and the last one refused anything.
    fn note(&self, now: u64, over: bool, busy: u32) -> Option<serde_json::Value> {
        let mut s = self.second.lock().unwrap_or_else(|e| e.into_inner());
        let mut line = None;
        if now > s.0 {
            if s.1 > 0 {
                line = Some(serde_json::json!({
                    "ts": s.0,
                    "kind": "shed",
                    "mode": self.mode.as_str(),
                    "refused": s.1,
                    "peak_in_flight": s.2,
                    "cap": self.cap,
                }));
            }
            *s = (now, 0, 0);
        }
        if over {
            s.1 = s.1.saturating_add(1);
        }
        s.2 = s.2.max(busy);
        line
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn low_trust_goes_first_and_kept_never() {
        let s = Shedder::new(GuardMode::Enforce, 4);
        let mut held = Vec::new();
        for _ in 0..3 {
            held.push(s.enter());
        }
        // 3 in flight: the soft limit (3) is reached, the cap (4) is not.
        assert_eq!(s.check(Trust::Low, 10).0, ShedVerdict::Shed);
        assert_eq!(s.check(Trust::Plain, 10).0, ShedVerdict::Admit);
        held.push(s.enter());
        assert_eq!(s.check(Trust::Plain, 10).0, ShedVerdict::Shed);
        assert_eq!(s.check(Trust::Kept, 10).0, ShedVerdict::Admit);
        held.clear();
        assert_eq!(s.in_flight(), 0, "places are given back");
        assert_eq!(s.check(Trust::Low, 10).0, ShedVerdict::Admit);
    }

    #[test]
    fn log_mode_lets_through_and_reports_once_a_second() {
        let s = Shedder::new(GuardMode::Log, 1);
        let _a = s.enter();
        let (v, line) = s.check(Trust::Plain, 20);
        assert_eq!(v, ShedVerdict::WouldShed);
        assert!(line.is_none());
        s.check(Trust::Plain, 20);
        let (_, line) = s.check(Trust::Kept, 21);
        let line = line.expect("the next second reports the last");
        assert_eq!(
            (line["refused"].as_u64(), line["peak_in_flight"].as_u64()),
            (Some(2), Some(1))
        );
        // A second with nothing refused writes nothing.
        assert!(s.check(Trust::Kept, 23).1.is_none());
    }

    #[test]
    fn off_admits_everything() {
        let s = Shedder::new(GuardMode::Off, 1);
        let _a = s.enter();
        let _b = s.enter();
        assert_eq!(s.check(Trust::Low, 1), (ShedVerdict::Admit, None));
    }
}
