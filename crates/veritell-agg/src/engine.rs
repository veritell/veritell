//! The windowed counters, the rules and the reputation entries.
//!
//! Layout: four bounded tables (fingerprints, networks, clients, routes), each
//! keyed by a keyed 64-bit hash of the attacker-controlled value, plus one
//! ring for all networks together. Fingerprints and networks hold a ring of
//! `2 * window_slots` cells, each with an exact request count and a lazily
//! allocated 256-register HyperLogLog (of networks for a fingerprint, of
//! fingerprints for a network). Clients hold strike counts, routes request
//! counts. See `sketch.rs` for the ring and `table.rs` for eviction.
//!
//! Rule inputs are cached per entry and refreshed when the window moves or a
//! new element could change the current union, so `observe` does a constant
//! amount of work.

mod sketch;
mod table;

use std::hash::Hasher;
use std::sync::{Mutex, MutexGuard};

use veritell_core::{Class, Detection, Layer};
use siphasher::sip::SipHasher13;

use self::sketch::{count_ring_bytes, sketch_ring_bytes, CountRing, SketchRing};
use self::table::{Table, Tracked};
use crate::{network_of, Config, ConfigError, Observation, CLIENT_REJECTIONS, FP_SPREAD, MAX_KEY_BYTES, NET_FANOUT, ROUTE_SURGE};

const TAG_FP: u8 = 1;
const TAG_NET: u8 = 2;
const TAG_CLIENT: u8 = 3;
const TAG_ROUTE: u8 = 4;
/// Allocator bookkeeping assumed per allocation, for the memory bound.
const ALLOC_OVERHEAD: usize = 16;

struct SketchEntry {
    ring: SketchRing,
    last_slot: u64,
    rep_until: u64,
}

struct CountEntry {
    ring: CountRing,
    last_slot: u64,
    rep_until: u64,
}

impl Tracked for SketchEntry {
    fn last_slot(&self) -> u64 {
        self.last_slot
    }
    fn rep_until(&self) -> u64 {
        self.rep_until
    }
}

impl Tracked for CountEntry {
    fn last_slot(&self) -> u64 {
        self.last_slot
    }
    fn rep_until(&self) -> u64 {
        self.rep_until
    }
}

struct Inner {
    fps: Table<SketchEntry>,
    nets: Table<SketchEntry>,
    clients: Table<CountEntry>,
    routes: Table<CountEntry>,
    /// Distinct networks seen for any fingerprint.
    total: SketchRing,
    latest: u64,
    first: Option<u64>,
}

/// Thread-safe. Every method takes `&self` and holds its lock only for a
/// bounded amount of work that does not depend on how many keys are tracked.
pub struct Aggregates {
    cfg: Config,
    key: [u8; 16],
    /// `window_slots` as u64.
    w: u64,
    bound: usize,
    inner: Mutex<Inner>,
}

fn random_key() -> [u8; 16] {
    let mut key = [0u8; 16];
    if getrandom::fill(&mut key).is_err() {
        // The OS source failed: fall back to the standard library's own
        // randomly keyed hasher, which draws from the same source.
        use std::hash::BuildHasher;
        let state = std::collections::hash_map::RandomState::new();
        for (i, chunk) in key.as_chunks_mut::<8>().0.iter_mut().enumerate() {
            let mut h = state.build_hasher();
            h.write_usize(i);
            chunk.copy_from_slice(&h.finish().to_le_bytes());
        }
    }
    key
}

/// Heap bytes of a table of up to `max_keys` entries of `entry_heap` bytes
/// each (beyond the `size_of` of the entry itself). The hash map is
/// preallocated; it could in the worst case still grow once (old and new
/// table alive together), so three times its size is counted.
fn table_bytes<E>(max_keys: usize, entry_heap: usize) -> usize {
    let buckets = match max_keys {
        0..=3 => 4,
        4..=7 => 8,
        n => n.saturating_mul(8).saturating_div(7).saturating_add(1).next_power_of_two(),
    };
    let slot = std::mem::size_of::<(u64, E)>().saturating_add(1);
    let map = buckets.saturating_mul(slot).saturating_add(64).saturating_mul(3);
    let order = max_keys.saturating_mul(2).saturating_mul(8);
    let entries = max_keys.saturating_mul(entry_heap.saturating_add(ALLOC_OVERHEAD));
    map.saturating_add(order).saturating_add(entries)
}

impl Aggregates {
    pub fn new(config: Config) -> Result<Self, ConfigError> {
        if config.slot_secs == 0 || config.window_slots == 0 || config.max_keys == 0 {
            return Err(ConfigError::Zero);
        }
        if config.slot_secs > 3600 || config.window_slots > 60 || config.max_keys > 1_000_000 {
            return Err(ConfigError::TooLarge);
        }
        let key = config.hash_seed.unwrap_or_else(random_key);
        let w = u64::from(config.window_slots);
        let wn = config.window_slots as usize;
        let k = config.max_keys;
        let bound = table_bytes::<SketchEntry>(k, sketch_ring_bytes(wn))
            .saturating_add(table_bytes::<SketchEntry>(k, sketch_ring_bytes(wn)))
            .saturating_add(table_bytes::<CountEntry>(k, count_ring_bytes(wn)))
            .saturating_add(table_bytes::<CountEntry>(k, count_ring_bytes(wn)))
            .saturating_add(sketch_ring_bytes(wn))
            .saturating_add(std::mem::size_of::<Self>());
        let inner = Inner {
            fps: Table::new(k),
            nets: Table::new(k),
            clients: Table::new(k),
            routes: Table::new(k),
            total: SketchRing::new(w),
            latest: 0,
            first: None,
        };
        Ok(Aggregates { cfg: config, key, w, bound, inner: Mutex::new(inner) })
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn hash(&self, tag: u8, data: &[u8]) -> u64 {
        let mut h = SipHasher13::new_with_key(&self.key);
        h.write_u8(tag);
        h.write(data);
        h.finish()
    }

    fn hash_text(&self, tag: u8, text: &str) -> u64 {
        let bytes = text.as_bytes();
        self.hash(tag, bytes.get(..MAX_KEY_BYTES).unwrap_or(bytes))
    }

    /// Records the request, evaluates the rules, and returns every detection
    /// that applies to it: rules that hold now, and live reputation entries
    /// for its fingerprint, network or client. At most one detection per id.
    pub fn observe(&self, observation: &Observation<'_>, now: u64) -> Vec<Detection> {
        let h_fp = self.hash_text(TAG_FP, observation.fingerprint);
        let h_route = self.hash_text(TAG_ROUTE, observation.route);
        let h_net = self.hash(TAG_NET, &network_of(observation.ip));
        let h_client = self.hash(TAG_CLIENT, &observation.client);

        let c = &self.cfg;
        let w = self.w;
        let w2 = w.saturating_mul(2);
        let mut guard = self.lock();
        let g = &mut *guard;
        let now = now.max(g.latest);
        g.latest = now;
        let first = *g.first.get_or_insert(now);
        let warm = now.saturating_sub(first) >= c.warmup_secs;
        let s = now / c.slot_secs;
        let until = now.saturating_add(c.reputation_ttl_secs);
        let mut out = Vec::new();

        g.total.record(s, w, h_net);
        let (total_cur, total_prev) = (g.total.est_cur(), g.total.est_prev());

        // One fingerprint over many networks.
        let e = g.fps.get_or_insert_with(h_fp, now, s, w2, || SketchEntry { ring: SketchRing::new(w), last_slot: s, rep_until: 0 });
        e.ring.record(s, w, h_net);
        e.last_slot = s;
        let (cur, prev) = (e.ring.est_cur(), e.ring.est_prev());
        let holds = warm
            && cur >= c.spread_min_networks
            && u128::from(cur) * u128::from(total_prev) >= u128::from(c.spread_growth) * u128::from(prev) * u128::from(total_cur);
        if holds {
            e.rep_until = until;
        }
        if holds || e.rep_until > now {
            out.push(
                Detection::new(
                    FP_SPREAD,
                    Layer::Population,
                    25,
                    format!("fingerprint seen from about {cur} networks in the window (about {prev} before), {total_cur} networks overall"),
                )
                .with_class(Class::Automated),
            );
        }

        // One network producing many fingerprints.
        let e = g.nets.get_or_insert_with(h_net, now, s, w2, || SketchEntry { ring: SketchRing::new(w), last_slot: s, rep_until: 0 });
        e.ring.record(s, w, h_fp);
        e.last_slot = s;
        let fps = e.ring.est_cur();
        let requests = e.ring.requests(s, w);
        let holds = warm && fps >= c.fanout_min_fingerprints && u128::from(fps) * 100 >= u128::from(requests) * u128::from(c.fanout_ratio_pct);
        if holds {
            e.rep_until = until;
        }
        if holds || e.rep_until > now {
            out.push(
                Detection::new(
                    NET_FANOUT,
                    Layer::Population,
                    25,
                    format!("network produced about {fps} fingerprints in {requests} requests in the window"),
                )
                .with_class(Class::Automated),
            );
        }

        // A client that keeps being rejected. Clients are only tracked once
        // they have a strike.
        if let Some(e) = g.clients.get_mut(h_client) {
            let strikes = e.ring.cur(s, w);
            let holds = strikes >= u64::from(c.strikes_max);
            if holds {
                e.rep_until = until;
            }
            if holds || e.rep_until > now {
                out.push(
                    Detection::new(CLIENT_REJECTIONS, Layer::Population, 40, format!("client rejected {strikes} times in the window"))
                        .with_class(Class::Automated),
                );
            }
        }

        // A route that suddenly gets much busier. No reputation entry.
        let e = g.routes.get_or_insert_with(h_route, now, s, w2, || CountEntry { ring: CountRing::new(w), last_slot: s, rep_until: 0 });
        e.ring.add(s, w);
        e.last_slot = s;
        let (cur, prev) = (e.ring.cur(s, w), e.ring.prev(s, w));
        if warm && cur >= u64::from(c.route_min_requests) && u128::from(cur) >= u128::from(c.route_growth) * u128::from(prev.max(1)) {
            out.push(Detection::new(
                ROUTE_SURGE,
                Layer::Population,
                5,
                format!("route got {cur} requests in the window against {prev} before"),
            ));
        }
        out
    }

    /// Records that something this client sent was rejected (a forged probe
    /// report, for example).
    pub fn strike(&self, client: &[u8; 16], now: u64) {
        let h = self.hash(TAG_CLIENT, client);
        let c = &self.cfg;
        let w = self.w;
        let mut guard = self.lock();
        let g = &mut *guard;
        let now = now.max(g.latest);
        g.latest = now;
        let s = now / c.slot_secs;
        let e = g.clients.get_or_insert_with(h, now, s, w.saturating_mul(2), || CountEntry {
            ring: CountRing::new(w),
            last_slot: s,
            rep_until: 0,
        });
        e.ring.add(s, w);
        e.last_slot = s;
        if e.ring.cur(s, w) >= u64::from(c.strikes_max) {
            e.rep_until = now.saturating_add(c.reputation_ttl_secs);
        }
    }

    /// Estimated distinct networks seen for this fingerprint in the current
    /// window. Within 30% of the true count or within 3, whichever is
    /// larger, up to 20,000. The estimate of a network's distinct
    /// fingerprints, used by `cluster_net_fanout`, has the same accuracy.
    pub fn networks(&self, fingerprint: &str, now: u64) -> u64 {
        let h = self.hash_text(TAG_FP, fingerprint);
        let g = self.lock();
        let s = now.max(g.latest) / self.cfg.slot_secs;
        g.fps.get(h).map_or(0, |e| u64::from(e.ring.union_est(s, self.w, false)))
    }

    /// Exact requests seen for this fingerprint in the current window.
    pub fn requests(&self, fingerprint: &str, now: u64) -> u64 {
        let h = self.hash_text(TAG_FP, fingerprint);
        let g = self.lock();
        let s = now.max(g.latest) / self.cfg.slot_secs;
        g.fps.get(h).map_or(0, |e| e.ring.requests(s, self.w))
    }

    /// Fingerprints, networks, clients and routes currently tracked, summed.
    /// Never above `4 * max_keys`.
    pub fn tracked(&self) -> usize {
        let g = self.lock();
        g.fps.len().saturating_add(g.nets.len()).saturating_add(g.clients.len()).saturating_add(g.routes.len())
    }

    /// The most heap memory this instance can ever use, in bytes, computed
    /// from the configuration (not measured). The implementation must make
    /// this true: every table is allocated or capped to fit it. Under 160 MiB
    /// for the default configuration.
    pub fn memory_bound_bytes(&self) -> usize {
        self.bound
    }
}
