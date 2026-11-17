//! Request volume: counts per key over a sliding window, in bounded memory,
//! and the flood guard built on them.
//!
//! The flood guard is a ceiling on requests per client network (the address
//! for IPv4, the /64 for IPv6), checked before a request is scored. It has
//! its own switch, apart from the policy mode, because its ceiling sits far
//! above what a person can send: `off`, `log` (count and report, let
//! everything through) or `enforce` (answer 429).
//!
//! The same windows count pages served per network and per client, which
//! the gateway turns into the `rate_net_high` and `rate_client_high`
//! detections. A page is what the origin answered with HTML, counted when
//! the response goes out: never what the client says it asked for, since
//! `sec-fetch-mode` and the like are the client's to write.

use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::Mutex;

/// Counts per key over the last `slots` slots of `slot_secs` each.
///
/// Memory is at most `max_keys` entries of `slots` 32-bit counters. When the
/// table is full, keys not seen within the window are dropped (at most once
/// per slot, so a full table under a flood does not sweep on every call); if
/// it is still full, a new key is not counted and [`Window::hit`] returns
/// `None`.
pub struct Window<K> {
    slot_secs: u64,
    slots: u32,
    max_keys: usize,
    inner: Mutex<Inner<K>>,
}

struct Inner<K> {
    map: HashMap<K, Entry>,
    /// The latest slot seen: time never goes back.
    latest_slot: u64,
    swept_slot: Option<u64>,
}

struct Entry {
    counts: Box<[u32]>,
    /// The slot of the last count.
    last_slot: u64,
    /// The slot this key last crossed the caller's limit in, for reporting
    /// once per window.
    reported_slot: Option<u64>,
}

/// What one call counted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hit {
    /// Requests from this key in the window, this one included.
    pub total: u32,
}

impl<K: Hash + Eq + Clone> Window<K> {
    pub fn new(slot_secs: u64, slots: u32, max_keys: usize) -> Self {
        Window {
            slot_secs: slot_secs.max(1),
            slots: slots.max(1),
            max_keys: max_keys.max(1),
            inner: Mutex::new(Inner {
                map: HashMap::new(),
                latest_slot: 0,
                swept_slot: None,
            }),
        }
    }

    /// The window's length in seconds.
    pub fn span_secs(&self) -> u64 {
        self.slot_secs.saturating_mul(u64::from(self.slots))
    }

    /// Counts one request from `key` at `now` (Unix seconds). `None` when
    /// the table is full and `key` is new.
    pub fn hit(&self, key: &K, now: u64) -> Option<Hit> {
        self.hit_reporting(key, now, u32::MAX).map(|(h, _)| h)
    }

    /// As [`Window::hit`], and also whether this is the first time within a
    /// window that `key` went past `limit`: true at most once per window
    /// length for each key, for as long as it stays past.
    pub fn hit_reporting(&self, key: &K, now: u64, limit: u32) -> Option<(Hit, bool)> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let slot = (now / self.slot_secs).max(inner.latest_slot);
        inner.latest_slot = slot;
        let slots = u64::from(self.slots);

        if !inner.map.contains_key(key) && inner.map.len() >= self.max_keys {
            if inner.swept_slot != Some(slot) {
                inner.swept_slot = Some(slot);
                inner
                    .map
                    .retain(|_, e| slot.saturating_sub(e.last_slot) < slots);
            }
            if inner.map.len() >= self.max_keys {
                return None;
            }
        }

        let n = self.slots as usize;
        let entry = inner.map.entry(key.clone()).or_insert_with(|| Entry {
            counts: vec![0; n].into_boxed_slice(),
            last_slot: slot,
            reported_slot: None,
        });
        // Clear the slots between the last count and this one.
        let gap = slot.saturating_sub(entry.last_slot);
        if gap >= slots {
            entry.counts.iter_mut().for_each(|c| *c = 0);
        } else {
            for s in entry.last_slot + 1..=slot {
                entry.counts[(s % slots) as usize] = 0;
            }
        }
        entry.last_slot = slot;
        let i = (slot % slots) as usize;
        entry.counts[i] = entry.counts[i].saturating_add(1);
        let total = entry.counts.iter().fold(0u32, |a, c| a.saturating_add(*c));

        let mut first = false;
        if total > limit {
            let due = entry
                .reported_slot
                .is_none_or(|r| slot.saturating_sub(r) >= slots);
            if due {
                entry.reported_slot = Some(slot);
                first = true;
            }
        }
        Some((Hit { total }, first))
    }

    /// Requests from `key` in the window at `now`, without counting one.
    pub fn peek(&self, key: &K, now: u64) -> u32 {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let slot = (now / self.slot_secs).max(inner.latest_slot);
        inner.latest_slot = slot;
        let slots = u64::from(self.slots);
        let Some(e) = inner.map.get(key) else {
            return 0;
        };
        let start = slot.saturating_sub(slots - 1);
        if e.last_slot < start {
            return 0;
        }
        (start..=e.last_slot).fold(0u32, |a, s| {
            a.saturating_add(e.counts[(s % slots) as usize])
        })
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().unwrap().map.len()
    }
}

/// `--flood-guard`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuardMode {
    Off,
    Log,
    Enforce,
}

impl GuardMode {
    pub fn parse(s: &str) -> Option<GuardMode> {
        match s {
            "off" => Some(GuardMode::Off),
            "log" => Some(GuardMode::Log),
            "enforce" => Some(GuardMode::Enforce),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            GuardMode::Off => "off",
            GuardMode::Log => "log",
            GuardMode::Enforce => "enforce",
        }
    }
}

/// What the guard says about one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuardVerdict {
    /// Under the ceiling, or the guard is off.
    Pass,
    /// Past the ceiling. `report` is true once per window per network.
    Over { total: u32, report: bool },
    /// The table is full and this network is new: it could not be counted.
    /// `enforce` refuses it, so a flood from many networks cannot push the
    /// counts out and slip through.
    Full,
}

/// Requests per client network over a sliding window, with a ceiling.
pub struct FloodGuard {
    pub mode: GuardMode,
    /// Requests per network allowed within the window.
    pub limit: u32,
    window: Window<IpAddr>,
}

impl FloodGuard {
    /// Default ceiling: 1000 requests per network in 10 s. A page with its
    /// assets is tens of requests; a crowd behind one address is many
    /// people. This is a backstop for floods, not a rate for scrapers.
    pub const DEFAULT_LIMIT: u32 = 1000;
    pub const SLOT_SECS: u64 = 1;
    pub const SLOTS: u32 = 10;

    pub fn new(mode: GuardMode, limit: u32, max_networks: usize) -> Self {
        FloodGuard {
            mode,
            limit,
            window: Window::new(Self::SLOT_SECS, Self::SLOTS, max_networks),
        }
    }

    /// Seconds a refused client should wait.
    pub fn retry_after(&self) -> u64 {
        self.window.span_secs()
    }

    pub fn check(&self, ip: IpAddr, now: u64) -> GuardVerdict {
        if self.mode == GuardMode::Off {
            return GuardVerdict::Pass;
        }
        let network = crate::conn::ConnLimiter::network(ip);
        match self.window.hit_reporting(&network, now, self.limit) {
            None => GuardVerdict::Full,
            Some((hit, _)) if hit.total <= self.limit => GuardVerdict::Pass,
            Some((hit, report)) => GuardVerdict::Over {
                total: hit.total,
                report,
            },
        }
    }
}

/// Pages served per network and per client over one minute, for the
/// `rate_net_high` and `rate_client_high` detections.
pub struct PageRates {
    pub net_limit: u32,
    pub client_limit: u32,
    /// Pages in ten minutes past which a client that never sent a probe
    /// report gets `pages_no_probe` (when the probe is injected).
    pub no_probe_pages: u32,
    nets: Window<IpAddr>,
    clients: Window<[u8; 16]>,
    /// Pages per client over ten minutes.
    clients_long: Window<[u8; 16]>,
}

impl PageRates {
    /// Defaults: past 120 pages a minute to one network, or 60 to one
    /// client (its handshake, User-Agent and address prefix). A person
    /// reading pages loads a few a minute.
    pub const DEFAULT_NET_LIMIT: u32 = 120;
    pub const DEFAULT_CLIENT_LIMIT: u32 = 60;
    /// A browser runs the injected probe on its first page; twenty pages
    /// in ten minutes with no report at all is not a browser.
    pub const DEFAULT_NO_PROBE_PAGES: u32 = 20;

    pub fn new(net_limit: u32, client_limit: u32, no_probe_pages: u32, max_keys: usize) -> Self {
        PageRates {
            net_limit,
            client_limit,
            no_probe_pages,
            nets: Window::new(10, 6, max_keys),
            clients: Window::new(10, 6, max_keys),
            clients_long: Window::new(60, 10, max_keys),
        }
    }

    /// Pages served to this client in the last ten minutes.
    pub fn pages_10m(&self, client: [u8; 16], now: u64) -> u32 {
        self.clients_long.peek(&client, now)
    }

    /// `pages_no_probe`, for a client that has not reported (the caller
    /// knows whether it has, and whether the probe is injected at all).
    pub fn no_probe(&self, client: [u8; 16], now: u64) -> Option<veritell_core::Detection> {
        use veritell_core::{Class, Detection, Layer};
        let pages = self.pages_10m(client, now);
        (pages >= self.no_probe_pages).then(|| {
            Detection::new(
                "pages_no_probe",
                Layer::Client,
                30,
                format!(
                    "{pages} pages in ten minutes, every one with the probe, and no probe report"
                ),
            )
            .with_class(Class::Automated)
        })
    }

    /// Counts one page served to this client.
    pub fn record(&self, ip: IpAddr, client: [u8; 16], now: u64) {
        self.nets.hit(&crate::conn::ConnLimiter::network(ip), now);
        self.clients.hit(&client, now);
        self.clients_long.hit(&client, now);
    }

    /// The detections this client's pages in the last minute earn.
    pub fn detections(
        &self,
        ip: IpAddr,
        client: [u8; 16],
        now: u64,
    ) -> Vec<veritell_core::Detection> {
        use veritell_core::{Class, Detection, Layer};
        let mut found = Vec::new();
        let net = self.nets.peek(&crate::conn::ConnLimiter::network(ip), now);
        if net > self.net_limit {
            found.push(
                Detection::new(
                    "rate_net_high",
                    Layer::Network,
                    20,
                    format!("{net} pages in a minute to this network"),
                )
                .with_class(Class::Automated),
            );
        }
        let own = self.clients.peek(&client, now);
        if own > self.client_limit {
            found.push(
                Detection::new(
                    "rate_client_high",
                    Layer::Behavior,
                    30,
                    format!("{own} pages in a minute to this client"),
                )
                .with_class(Class::Automated),
            );
        }
        found
    }
}

/// Pages per fingerprint (handshake, HTTP/2 settings and User-Agent),
/// across every network, for `fp_page_surge`: one fingerprint's pages in
/// the last minute at least `min_pages` and at least `growth` times its
/// average minute over the ten before. A campaign starting from many
/// addresses with one tool jumps from nothing; a fingerprint many people
/// share grows with the day, not fourfold in a minute.
///
/// Not before `WARMUP_SECS` after the first page counted: until then there
/// is no ten minutes to compare with.
pub struct FpSurge {
    pub min_pages: u32,
    pub growth: u32,
    started: std::sync::atomic::AtomicU64,
    minute: Window<u64>,
    eleven: Window<u64>,
    hasher: std::collections::hash_map::RandomState,
}

impl FpSurge {
    pub const DEFAULT_MIN_PAGES: u32 = 120;
    pub const DEFAULT_GROWTH: u32 = 4;
    pub const WARMUP_SECS: u64 = 660;
    /// Fingerprints longer than this are cut before hashing.
    const MAX_KEY_BYTES: usize = 512;

    pub fn new(min_pages: u32, growth: u32, max_keys: usize) -> Self {
        FpSurge {
            min_pages,
            growth: growth.max(1),
            started: std::sync::atomic::AtomicU64::new(0),
            minute: Window::new(10, 6, max_keys),
            eleven: Window::new(60, 11, max_keys),
            hasher: std::collections::hash_map::RandomState::new(),
        }
    }

    /// The counter key of a fingerprint (a keyed hash, drawn per process).
    pub fn key(&self, fingerprint: &str) -> u64 {
        use std::hash::BuildHasher;
        let bytes = fingerprint.as_bytes();
        self.hasher
            .hash_one(&bytes[..bytes.len().min(Self::MAX_KEY_BYTES)])
    }

    /// Counts one page served to this fingerprint.
    pub fn record(&self, key: u64, now: u64) {
        use std::sync::atomic::Ordering;
        let _ = self
            .started
            .compare_exchange(0, now.max(1), Ordering::AcqRel, Ordering::Acquire);
        self.minute.hit(&key, now);
        self.eleven.hit(&key, now);
    }

    pub fn detection(&self, key: u64, now: u64) -> Option<veritell_core::Detection> {
        use std::sync::atomic::Ordering;
        use veritell_core::{Class, Detection, Layer};
        let started = self.started.load(Ordering::Acquire);
        if started == 0 || now.saturating_sub(started) < Self::WARMUP_SECS {
            return None;
        }
        let current = self.minute.peek(&key, now);
        if current < self.min_pages {
            return None;
        }
        let before = self.eleven.peek(&key, now).saturating_sub(current) / 10;
        (u64::from(current) >= u64::from(self.growth) * u64::from(before.max(1))).then(|| {
            Detection::new(
                "fp_page_surge",
                Layer::Population,
                20,
                format!("{current} pages in a minute to this fingerprint, against {before} a minute before"),
            )
            .with_class(Class::Automated)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn counts_within_the_window_and_forgets_after_it() {
        let w: Window<u32> = Window::new(1, 10, 100);
        for _ in 0..5 {
            w.hit(&1, 100);
        }
        assert_eq!(w.hit(&1, 105).unwrap().total, 6);
        // At 110 the slot of 100 has left the window; 105 is still in it.
        assert_eq!(w.hit(&1, 110).unwrap().total, 2);
        // Long after: a fresh count.
        assert_eq!(w.hit(&1, 1_000).unwrap().total, 1);
    }

    #[test]
    fn a_clock_going_back_hands_nothing_back() {
        let w: Window<u32> = Window::new(1, 10, 100);
        for _ in 0..5 {
            w.hit(&1, 200);
        }
        assert_eq!(w.hit(&1, 50).unwrap().total, 6);
    }

    #[test]
    fn a_full_table_stays_at_its_bound() {
        let w: Window<u32> = Window::new(1, 10, 3);
        for k in 0..3 {
            assert!(w.hit(&k, 100).is_some());
        }
        assert!(w.hit(&99, 100).is_none());
        assert_eq!(w.len(), 3);
        // Keys known before still count.
        assert_eq!(w.hit(&0, 101).unwrap().total, 2);
        // Once the old keys leave the window, room comes back.
        assert!(w.hit(&99, 200).is_some());
        assert!(w.len() <= 3);
    }

    #[test]
    fn reports_once_per_window_while_over() {
        let w: Window<u32> = Window::new(1, 10, 10);
        let mut reports = 0;
        for t in 0..30u64 {
            for _ in 0..5 {
                let (_, first) = w.hit_reporting(&1, 1_000 + t, 3).unwrap();
                reports += u32::from(first);
            }
        }
        assert_eq!(reports, 3);
    }

    #[test]
    fn guard_passes_under_the_limit_and_flags_over_it() {
        let g = FloodGuard::new(GuardMode::Enforce, 3, 100);
        for _ in 0..3 {
            assert_eq!(g.check(ip("192.0.2.1"), 10), GuardVerdict::Pass);
        }
        assert_eq!(
            g.check(ip("192.0.2.1"), 10),
            GuardVerdict::Over {
                total: 4,
                report: true
            }
        );
        assert_eq!(
            g.check(ip("192.0.2.1"), 10),
            GuardVerdict::Over {
                total: 5,
                report: false
            }
        );
        // Another address has its own count.
        assert_eq!(g.check(ip("192.0.2.2"), 10), GuardVerdict::Pass);
        // After the window, the first address is under again.
        assert_eq!(g.check(ip("192.0.2.1"), 30), GuardVerdict::Pass);
    }

    #[test]
    fn guard_counts_an_ipv6_64_as_one_network() {
        let g = FloodGuard::new(GuardMode::Log, 2, 100);
        assert_eq!(g.check(ip("2001:db8::1"), 10), GuardVerdict::Pass);
        assert_eq!(g.check(ip("2001:db8::2"), 10), GuardVerdict::Pass);
        assert!(matches!(
            g.check(ip("2001:db8::ffff"), 10),
            GuardVerdict::Over { .. }
        ));
        assert_eq!(g.check(ip("2001:db8:0:1::1"), 10), GuardVerdict::Pass);
    }

    #[test]
    fn guard_off_counts_nothing() {
        let g = FloodGuard::new(GuardMode::Off, 0, 1);
        for _ in 0..10 {
            assert_eq!(g.check(ip("192.0.2.1"), 10), GuardVerdict::Pass);
        }
    }

    #[test]
    fn guard_full_table_is_reported() {
        let g = FloodGuard::new(GuardMode::Enforce, 10, 1);
        assert_eq!(g.check(ip("192.0.2.1"), 10), GuardVerdict::Pass);
        assert_eq!(g.check(ip("192.0.2.2"), 10), GuardVerdict::Full);
    }

    #[test]
    fn no_probe_fires_at_its_page_count_over_ten_minutes() {
        let r = PageRates::new(1000, 1000, 3, 100);
        let c = [9u8; 16];
        // One page a minute: under the minute rates, counted over ten.
        r.record(ip("192.0.2.1"), c, 1_000);
        r.record(ip("192.0.2.1"), c, 1_060);
        assert!(r.no_probe(c, 1_060).is_none());
        r.record(ip("192.0.2.1"), c, 1_120);
        assert_eq!(
            r.no_probe(c, 1_120).map(|d| d.id),
            Some("pages_no_probe".to_string())
        );
        // Ten minutes after the first, it has left the window.
        assert!(r.no_probe(c, 1_000 + 600).is_none());
    }

    #[test]
    fn fp_surge_waits_for_its_warmup_then_fires_on_a_jump() {
        let s = FpSurge::new(10, 4, 100);
        let k = s.key("t13d_x|h2|tool/1.0");
        let t0 = 10_000;
        s.record(s.key("other"), t0);
        // A burst before the warmup ends is not a surge yet.
        for _ in 0..50 {
            s.record(k, t0 + 60);
        }
        assert!(s.detection(k, t0 + 60).is_none(), "warming up");
        // Quiet for the next ten minutes, then a jump.
        let t = t0 + 60 + 700;
        for _ in 0..12 {
            s.record(k, t);
        }
        assert_eq!(
            s.detection(k, t).map(|d| d.id),
            Some("fp_page_surge".to_string())
        );
    }

    #[test]
    fn fp_surge_ignores_a_steady_popular_fingerprint() {
        let s = FpSurge::new(10, 4, 100);
        let k = s.key("t13d_safari|h2|iPhone");
        let t0 = 20_000;
        // 30 pages a minute, every minute, for 20 minutes.
        for m in 0..20u64 {
            for i in 0..30u64 {
                s.record(k, t0 + m * 60 + i * 2);
            }
        }
        let now = t0 + 19 * 60 + 58;
        assert!(s.detection(k, now).is_none(), "steady: no jump");
        assert!(s.detection(s.key("never seen"), now).is_none());
    }

    #[test]
    fn peek_counts_nothing_and_slides_with_the_window() {
        let w: Window<u32> = Window::new(1, 10, 10);
        assert_eq!(w.peek(&1, 100), 0);
        w.hit(&1, 100);
        w.hit(&1, 105);
        assert_eq!(w.peek(&1, 105), 2);
        assert_eq!(w.peek(&1, 105), 2, "peeking counts nothing");
        assert_eq!(w.peek(&1, 110), 1, "the slot of 100 has left");
        assert_eq!(w.peek(&1, 200), 0);
    }

    #[test]
    fn page_rates_fire_past_their_limits() {
        let r = PageRates::new(3, 2, 20, 100);
        let a = [7u8; 16];
        for _ in 0..2 {
            r.record(ip("192.0.2.1"), a, 100);
        }
        assert!(
            r.detections(ip("192.0.2.1"), a, 100).is_empty(),
            "two pages: at the limit"
        );
        r.record(ip("192.0.2.1"), a, 100);
        let ids =
            |d: Vec<veritell_core::Detection>| d.into_iter().map(|d| d.id).collect::<Vec<_>>();
        assert_eq!(
            ids(r.detections(ip("192.0.2.1"), a, 100)),
            ["rate_client_high"]
        );
        // Another client on the same network: only the network's count is past.
        r.record(ip("192.0.2.1"), [8u8; 16], 100);
        assert_eq!(
            ids(r.detections(ip("192.0.2.1"), [8u8; 16], 100)),
            ["rate_net_high"]
        );
        // A minute later, both are under again.
        assert!(r.detections(ip("192.0.2.1"), a, 200).is_empty());
    }
}
