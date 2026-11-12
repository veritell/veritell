//! What is kept between fetches, and when to fetch again.

use crate::{Ed25519Key, Fetched, MAX_STALE_SECS, RETRY_SECS};

/// What is known about one agent's directory, and when to ask again.
/// No clock and no network: the caller passes the time and the results.
///
/// - Before the first result, [`Cache::due`] is true and there are no keys.
/// - A success replaces the keys entirely (a key the new directory no longer
///   lists is gone at once), and the next fetch is due `ttl_secs` later.
/// - A failure changes no key. The next fetch is due `RETRY_SECS` later.
/// - Keys are usable from the success that brought them through
///   `ttl_secs + MAX_STALE_SECS` seconds after it (that second included);
///   later than that, with no success since, there are none.
/// - A `now` earlier than the time of the last result is treated as that
///   time. All sums saturate.
#[derive(Clone, Debug, Default)]
pub struct Cache {
    keys: Vec<Ed25519Key>,
    /// Time of the last success and the lifetime it gave.
    success: Option<(u64, u64)>,
    /// Time of the last result of either kind.
    last_result: u64,
    /// When the next fetch is due; `None` before the first result.
    next_due: Option<u64>,
}

impl Cache {
    pub fn new() -> Cache {
        Cache::default()
    }

    /// Whether a fetch should be made now.
    pub fn due(&self, now: u64) -> bool {
        match self.next_due {
            None => true,
            Some(due) => self.effective(now) >= due,
        }
    }

    fn effective(&self, now: u64) -> u64 {
        now.max(self.last_result)
    }

    pub fn on_success(&mut self, fetched: Fetched, now: u64) {
        let at = self.effective(now);
        self.keys = fetched.keys;
        self.success = Some((at, fetched.ttl_secs));
        self.last_result = at;
        self.next_due = Some(at.saturating_add(fetched.ttl_secs));
    }

    pub fn on_failure(&mut self, now: u64) {
        let at = self.effective(now);
        self.last_result = at;
        self.next_due = Some(at.saturating_add(RETRY_SECS));
    }

    /// The keys to trust at `now`; empty when there are none.
    pub fn keys(&self, now: u64) -> &[Ed25519Key] {
        let Some((at, ttl)) = self.success else {
            return &[];
        };
        let end = at.saturating_add(ttl).saturating_add(MAX_STALE_SECS);
        if self.effective(now) <= end {
            &self.keys
        } else {
            &[]
        }
    }
}
