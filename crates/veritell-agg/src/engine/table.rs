//! A bounded key table with cheap, amortised O(1) eviction.

use std::collections::{HashMap, VecDeque};
use std::hash::{BuildHasherDefault, Hasher};

/// The keys are already keyed 64-bit hashes; use them as they are.
#[derive(Default)]
pub(crate) struct IdHasher(u64);

impl Hasher for IdHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = self.0.rotate_left(8) ^ u64::from(b);
        }
    }
    fn write_u64(&mut self, v: u64) {
        self.0 = v;
    }
}

pub(crate) trait Tracked {
    /// Slot of the last request that touched the entry.
    fn last_slot(&self) -> u64;
    /// The entry carries a reputation entry until this time.
    fn rep_until(&self) -> u64;
}

/// How many candidates one eviction looks at.
const CANDIDATES: usize = 8;

pub(crate) struct Table<E> {
    map: HashMap<u64, E, BuildHasherDefault<IdHasher>>,
    /// Keys in insertion order (second-chance queue for eviction).
    order: VecDeque<u64>,
    cap: usize,
}

impl<E: Tracked> Table<E> {
    pub(crate) fn new(cap: usize) -> Self {
        Table {
            map: HashMap::with_capacity_and_hasher(cap, BuildHasherDefault::default()),
            order: VecDeque::with_capacity(cap),
            cap,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }

    pub(crate) fn get(&self, key: u64) -> Option<&E> {
        self.map.get(&key)
    }

    pub(crate) fn get_mut(&mut self, key: u64) -> Option<&mut E> {
        self.map.get_mut(&key)
    }

    /// The entry for `key`, created with `make` (after evicting if the table
    /// is full). `s` is the current slot, `w2` the length of the whole
    /// window in slots; an entry untouched for `w2` slots is idle.
    pub(crate) fn get_or_insert_with(&mut self, key: u64, now: u64, s: u64, w2: u64, make: impl FnOnce() -> E) -> &mut E {
        if !self.map.contains_key(&key) {
            if self.map.len() >= self.cap {
                self.evict(now, s, w2);
            }
            self.order.push_back(key);
        }
        self.map.entry(key).or_insert_with(make)
    }

    /// Removes one entry, looking at no more than `CANDIDATES`: an idle
    /// entry without a live reputation entry at once, otherwise the one
    /// without a live entry that was touched longest ago (an entry with a
    /// live reputation entry only if every candidate has one).
    fn evict(&mut self, now: u64, s: u64, w2: u64) {
        let mut best: Option<(u64, (bool, u64))> = None;
        for _ in 0..CANDIDATES {
            let Some(key) = self.order.pop_front() else { break };
            let Some(e) = self.map.get(&key) else { continue };
            let live = e.rep_until() > now;
            let last = e.last_slot();
            if !live && s.saturating_sub(last) >= w2 {
                self.map.remove(&key);
                if let Some((k, _)) = best {
                    self.order.push_back(k);
                }
                return;
            }
            let score = (live, last);
            match best {
                Some((_, b)) if score >= b => self.order.push_back(key),
                Some((k, _)) => {
                    self.order.push_back(k);
                    best = Some((key, score));
                }
                None => best = Some((key, score)),
            }
        }
        if let Some((k, _)) = best {
            self.map.remove(&k);
        }
    }
}
