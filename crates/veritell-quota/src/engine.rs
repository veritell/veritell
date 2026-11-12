//! Per-identity sliding-window rate and per-day quota in bounded memory.
//!
//! Data structure: one `Mutex` around a table made of a slab of nodes, a
//! `HashMap` from the 128-bit keyed identity hash to a slab index, and an
//! intrusive doubly linked list (by slab index) ordering nodes by last use.
//! Lookup, touch, insertion and eviction are all O(1): the least recently
//! used node is the list tail, so there is no scan, not even when evicting.
//!
//! Memory per identity: `window_slots` 32-bit counters, plus one node of a
//! few words (key, day, day use, head slot, two links) and one map entry.

use std::collections::HashMap;
use std::hash::Hasher;
use std::sync::Mutex;

use siphasher::sip128::{Hasher128, SipHasher13};

use crate::{Config, ConfigError};

/// Rate and day counters for many identities. Safe to share across threads:
/// every method takes `&self`.
pub struct Quotas {
    slot_secs: u64,
    window_slots: u32,
    day_secs: u64,
    max_identities: usize,
    inner: Mutex<Table>,
}

/// One tracked identity.
struct Node {
    key: u128,
    /// Counters of the rate window, indexed by `slot % window_slots`.
    ring: Vec<u32>,
    /// Newest slot the ring has been advanced to.
    head_slot: u64,
    /// Day number `day_used` belongs to.
    day: u64,
    day_used: u32,
    prev: Option<usize>,
    next: Option<usize>,
}

struct Table {
    /// Identity hash key; replaced together with the entries on import.
    key: [u8; 16],
    /// Latest `now` seen by any call.
    latest: u64,
    map: HashMap<u128, usize>,
    nodes: Vec<Node>,
    /// Most recently used.
    front: Option<usize>,
    /// Least recently used.
    back: Option<usize>,
}

impl Table {
    fn advance_time(&mut self, now: u64) -> u64 {
        if now > self.latest {
            self.latest = now;
        }
        self.latest
    }

    fn unlink(&mut self, idx: usize) {
        let (prev, next) = match self.nodes.get(idx) {
            Some(n) => (n.prev, n.next),
            None => return,
        };
        match prev {
            Some(p) => {
                if let Some(n) = self.nodes.get_mut(p) {
                    n.next = next;
                }
            }
            None => self.front = next,
        }
        match next {
            Some(x) => {
                if let Some(n) = self.nodes.get_mut(x) {
                    n.prev = prev;
                }
            }
            None => self.back = prev,
        }
        if let Some(n) = self.nodes.get_mut(idx) {
            n.prev = None;
            n.next = None;
        }
    }

    fn push_front(&mut self, idx: usize) {
        let old = self.front;
        if let Some(n) = self.nodes.get_mut(idx) {
            n.prev = None;
            n.next = old;
        }
        if let Some(o) = old {
            if let Some(n) = self.nodes.get_mut(o) {
                n.prev = Some(idx);
            }
        }
        self.front = Some(idx);
        if self.back.is_none() {
            self.back = Some(idx);
        }
    }

    fn touch(&mut self, idx: usize) {
        if self.front != Some(idx) {
            self.unlink(idx);
            self.push_front(idx);
        }
    }

    /// Finds the identity or starts tracking it (evicting the least recently
    /// used one if the table is full, O(1)), and marks it most recently used.
    fn find_or_insert(&mut self, key: u128, cap: usize, slots: usize, slot: u64, day: u64) -> Option<usize> {
        if let Some(&idx) = self.map.get(&key) {
            self.touch(idx);
            return Some(idx);
        }
        let fresh = |key: u128| Node {
            key,
            ring: vec![0; slots],
            head_slot: slot,
            day,
            day_used: 0,
            prev: None,
            next: None,
        };
        let idx = if self.nodes.len() < cap {
            self.nodes.push(fresh(key));
            self.nodes.len().saturating_sub(1)
        } else {
            let victim = self.back?;
            self.unlink(victim);
            let old = self.nodes.get_mut(victim)?;
            let old_key = old.key;
            *old = fresh(key);
            self.map.remove(&old_key);
            victim
        };
        self.map.insert(key, idx);
        self.push_front(idx);
        Some(idx)
    }
}

fn hash_with(key: &[u8; 16], bytes: &[u8]) -> u128 {
    let mut h = SipHasher13::new_with_key(key);
    h.write(bytes);
    h.finish128().as_u128()
}

/// Day use of a node as seen on `day` (a node only ever holds an earlier or
/// equal day, because time never goes backwards here).
fn day_used_on(node: &Node, day: u64) -> u32 {
    if node.day == day {
        node.day_used
    } else {
        0
    }
}

impl Quotas {
    /// Checks the configuration (see [`ConfigError`]; `Zero` is reported
    /// before `TooLarge`) and starts with nothing tracked.
    pub fn new(config: Config) -> Result<Quotas, ConfigError> {
        if config.slot_secs == 0 || config.window_slots == 0 || config.day_secs == 0 || config.max_identities == 0 {
            return Err(ConfigError::Zero);
        }
        if config.slot_secs > 3600 || config.window_slots > 60 || config.max_identities > 1_000_000 {
            return Err(ConfigError::TooLarge);
        }
        let key = match config.hash_seed {
            Some(k) => k,
            None => random_key(),
        };
        Ok(Quotas {
            slot_secs: config.slot_secs,
            window_slots: config.window_slots,
            day_secs: config.day_secs,
            max_identities: config.max_identities,
            inner: Mutex::new(Table {
                key,
                latest: 0,
                map: HashMap::new(),
                nodes: Vec::new(),
                front: None,
                back: None,
            }),
        })
    }

    #[cfg(test)]
    fn hash(&self, identity: &str) -> u128 {
        let key = self.lock().key;
        hash_with(&key, identity.as_bytes())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Table> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// One request against the identity's rate.
    ///
    /// Returns true, and counts the request in the current slot, if fewer
    /// than `limit` requests were counted for this identity in the window at
    /// `now`. Otherwise returns false and counts nothing: a refused request
    /// does not extend the wait. A `limit` of 0 always refuses.
    pub fn allow_rate(&self, identity: &str, limit: u32, now: u64) -> bool {
        let mut t = self.lock();
        let key = hash_with(&t.key, identity.as_bytes());
        let now = t.advance_time(now);
        let slot = now / self.slot_secs;
        let day = now / self.day_secs;
        let window = u64::from(self.window_slots);
        let idx = match t.find_or_insert(key, self.max_identities, self.window_slots as usize, slot, day) {
            Some(i) => i,
            None => return false,
        };
        let node = match t.nodes.get_mut(idx) {
            Some(n) => n,
            None => return false,
        };
        // Bring the ring up to the current slot, clearing slots that left.
        if slot > node.head_slot {
            let delta = slot - node.head_slot;
            if delta >= window {
                node.ring.iter_mut().for_each(|c| *c = 0);
            } else {
                for s in node.head_slot.saturating_add(1)..=slot {
                    // s <= slot, delta < window <= 60: no overflow possible
                    // in the range itself; the index is reduced mod window.
                    if let Some(c) = node.ring.get_mut((s % window) as usize) {
                        *c = 0;
                    }
                }
            }
            node.head_slot = slot;
        }
        let count: u64 = node.ring.iter().map(|&c| u64::from(c)).sum();
        if count >= u64::from(limit) {
            return false;
        }
        if let Some(c) = node.ring.get_mut((slot % window) as usize) {
            *c = c.saturating_add(1);
        }
        true
    }

    /// One request against the identity's quota for the day at `now`.
    ///
    /// Returns what was left **before** this request: `per_day` minus what
    /// this identity has taken today, saturating at 0. If that is more than 0
    /// one unit is taken; at 0 nothing changes. So with `per_day` 3 the
    /// answers over one day are 3, 2, 1, 0, 0, ...
    pub fn take(&self, identity: &str, per_day: u32, now: u64) -> u32 {
        let mut t = self.lock();
        let key = hash_with(&t.key, identity.as_bytes());
        let now = t.advance_time(now);
        let slot = now / self.slot_secs;
        let day = now / self.day_secs;
        let idx = match t.find_or_insert(key, self.max_identities, self.window_slots as usize, slot, day) {
            Some(i) => i,
            None => return 0,
        };
        let node = match t.nodes.get_mut(idx) {
            Some(n) => n,
            None => return 0,
        };
        if node.day != day {
            node.day = day;
            node.day_used = 0;
        }
        let left = per_day.saturating_sub(node.day_used);
        if left > 0 {
            node.day_used = node.day_used.saturating_add(1);
        }
        left
    }

    /// What [`Quotas::take`] would return, without taking anything, without
    /// tracking an identity that is not tracked yet, and without counting as
    /// a use for the least-recently-used rule. It does advance the latest
    /// time seen.
    pub fn left(&self, identity: &str, per_day: u32, now: u64) -> u32 {
        let mut t = self.lock();
        let key = hash_with(&t.key, identity.as_bytes());
        let now = t.advance_time(now);
        let day = now / self.day_secs;
        let used = t
            .map
            .get(&key)
            .and_then(|&i| t.nodes.get(i))
            .map_or(0, |n| day_used_on(n, day));
        per_day.saturating_sub(used)
    }

    /// The day's use in the format of the crate documentation. The day is
    /// the one at the latest time seen (`now` included, as everywhere).
    pub fn export(&self, now: u64) -> Vec<u8> {
        let mut t = self.lock();
        let now = t.advance_time(now);
        let day = now / self.day_secs;
        let mut entries: Vec<(u128, u32)> = Vec::new();
        let mut cur = t.back;
        while let Some(i) = cur {
            let Some(n) = t.nodes.get(i) else { break };
            if n.day == day && n.day_used > 0 {
                entries.push((n.key, n.day_used));
            }
            cur = n.prev;
        }
        let mut out = Vec::with_capacity(37 + entries.len().saturating_mul(20));
        out.push(1u8);
        out.extend_from_slice(&t.key);
        out.extend_from_slice(&self.day_secs.to_be_bytes());
        out.extend_from_slice(&day.to_be_bytes());
        out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        for (k, used) in entries {
            out.extend_from_slice(&k.to_be_bytes());
            out.extend_from_slice(&used.to_be_bytes());
        }
        out
    }

    /// Loads a snapshot made by [`Quotas::export`], before any other use.
    ///
    /// `NotEmpty` if an identity is already tracked; `Malformed` and
    /// `Mismatch` as their documentation says. All three leave this value
    /// unchanged. Otherwise the snapshot's key replaces this value's key,
    /// whatever `hash_seed` was configured, and if the snapshot's day is the
    /// day at `now` its entries are tracked with their use for that day and
    /// empty rate windows, in the snapshot's order of use. If there are more
    /// than `max_identities`, the most recently used are kept. A snapshot of
    /// an earlier day loads the key and no entries; one of a later day than
    /// `now` is `Malformed`. Returns how many identities are now tracked.
    pub fn import(&self, bytes: &[u8], now: u64) -> Result<usize, crate::SnapshotError> {
        use crate::SnapshotError::{Malformed, Mismatch, NotEmpty};
        let be64 = |o: usize| -> Option<u64> { Some(u64::from_be_bytes(bytes.get(o..o.checked_add(8)?)?.try_into().ok()?)) };
        let be32 = |o: usize| -> Option<u32> { Some(u32::from_be_bytes(bytes.get(o..o.checked_add(4)?)?.try_into().ok()?)) };
        if bytes.first() != Some(&1) {
            return Err(Malformed);
        }
        let mut key = [0u8; 16];
        key.copy_from_slice(bytes.get(1..17).ok_or(Malformed)?);
        let day_secs = be64(17).ok_or(Malformed)?;
        let snap_day = be64(25).ok_or(Malformed)?;
        let count = be32(33).ok_or(Malformed)? as usize;
        let expected = count.checked_mul(20).and_then(|n| n.checked_add(37)).ok_or(Malformed)?;
        if bytes.len() != expected {
            return Err(Malformed);
        }
        let mut entries: Vec<(u128, u32)> = Vec::with_capacity(count);
        let mut seen = std::collections::HashSet::with_capacity(count);
        for chunk in bytes.get(37..).ok_or(Malformed)?.as_chunks::<20>().0 {
            let (h, u) = chunk.split_at(16);
            let h = u128::from_be_bytes(h.try_into().map_err(|_| Malformed)?);
            let u = u32::from_be_bytes(u.try_into().map_err(|_| Malformed)?);
            if u == 0 || !seen.insert(h) {
                return Err(Malformed);
            }
            entries.push((h, u));
        }
        if day_secs != self.day_secs {
            return Err(Mismatch);
        }
        let mut t = self.lock();
        let eff = t.latest.max(now);
        let day = eff / self.day_secs;
        if snap_day > day {
            return Err(Malformed);
        }
        if !t.map.is_empty() {
            return Err(NotEmpty);
        }
        t.key = key;
        t.advance_time(now);
        if snap_day == day {
            let slot = eff / self.slot_secs;
            let skip = entries.len().saturating_sub(self.max_identities);
            for &(h, used) in entries.iter().skip(skip) {
                if let Some(idx) = t.find_or_insert(h, self.max_identities, self.window_slots as usize, slot, day) {
                    if let Some(n) = t.nodes.get_mut(idx) {
                        n.day = day;
                        n.day_used = used;
                    }
                }
            }
        }
        Ok(t.map.len())
    }

    /// Number of identities tracked right now. Never above `max_identities`.
    pub fn tracked(&self) -> usize {
        self.lock().map.len()
    }
}

/// A random per-process key; if the OS source fails, fall back to a key from
/// the clock, process id and a stack address (weaker, but never panics).
fn random_key() -> [u8; 16] {
    let mut k = [0u8; 16];
    if getrandom::fill(&mut k).is_ok() {
        return k;
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let mix = nanos ^ (u128::from(std::process::id()) << 64) ^ (&k as *const _ as usize as u128);
    mix.to_le_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q(max: usize) -> Quotas {
        Quotas::new(Config { max_identities: max, hash_seed: Some([1; 16]), ..Config::default() }).unwrap()
    }

    /// Checks the list, map and slab agree.
    fn check(q: &Quotas) {
        let t = q.lock();
        assert_eq!(t.map.len(), t.nodes.len().min(q.max_identities));
        let mut seen = 0;
        let mut cur = t.front;
        let mut prev = None;
        while let Some(i) = cur {
            let n = t.nodes.get(i).unwrap();
            assert_eq!(n.prev, prev);
            assert_eq!(t.map.get(&n.key), Some(&i));
            prev = Some(i);
            cur = n.next;
            seen += 1;
            assert!(seen <= t.nodes.len());
        }
        assert_eq!(prev, t.back);
        assert_eq!(seen, t.map.len());
    }

    #[test]
    fn list_stays_consistent_under_churn() {
        let q = q(5);
        for n in 0..200u64 {
            let id = format!("id{}", n * 7 % 13);
            if n % 2 == 0 {
                q.take(&id, 3, 1000 + n);
            } else {
                q.allow_rate(&id, 2, 1000 + n);
            }
            q.left(&format!("id{}", n % 5), 3, 1000 + n);
            check(&q);
        }
        assert_eq!(q.tracked(), 5);
    }

    #[test]
    fn hash_covers_whole_string_and_depends_on_key() {
        let a = q(2);
        let long = "z".repeat(5000);
        assert_ne!(a.hash(&long), a.hash(&format!("{long}!")));
        let b = Quotas::new(Config { hash_seed: Some([2; 16]), ..Config::default() }).unwrap();
        assert_ne!(a.hash("x"), b.hash("x"));
    }

    #[test]
    fn ring_clears_only_slots_that_left() {
        let q = q(2);
        assert!(q.allow_rate("a", 2, 0));
        assert!(q.allow_rate("a", 2, 55));
        assert!(!q.allow_rate("a", 2, 55));
        // Slot 6 drops slot 0 only.
        assert!(q.allow_rate("a", 2, 60));
        assert!(!q.allow_rate("a", 2, 60));
    }

    #[test]
    fn poisoned_mutex_is_recovered() {
        let q = std::sync::Arc::new(q(2));
        let q2 = std::sync::Arc::clone(&q);
        let _ = std::thread::spawn(move || {
            let _g = q2.inner.lock().unwrap();
            panic!("poison");
        })
        .join();
        assert_eq!(q.take("a", 1, 0), 1);
    }
}
