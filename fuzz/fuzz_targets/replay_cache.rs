#![no_main]
// Web Bot Auth replay cache: a sequence of operations on one `ReplayCache`,
// checked against a reference model with the same policy, and against a
// property that does not depend on the policy.
//
// Input: the first byte is the capacity (1 to 8, small so eviction happens
// often). Then each operation is a tag byte and its argument bytes:
//
//   0 id d   first_use of signature `id` (16 of them), expiring `d` away
//   1 d      time moves forward by d * 7 seconds (crosses CLOCK_SKEW_SECS)
//   2 id d   restore of `id`, refused until `d` away
//   3        restart: entries() saved and restored into a new cache
//
// `d` picks `expires` or `until` relative to now: below 0x80 after now,
// from 0x80 before now, 0xFF the largest u64 (the saturating edge).
//
// Properties checked after every operation:
// - every return value and the held set equal the model's;
// - len() never exceeds the capacity, is_empty() agrees with len();
// - a signature accepted once is refused until its expires plus
//   CLOCK_SKEW_SECS, unless the capacity dropped it to make room (the
//   documented flood case), whatever the model says;
// - a restart keeps exactly the entries still held.
use std::collections::HashMap;
use veritell_wba::{ReplayCache, SignatureInfo, CLOCK_SKEW_SECS};

const START: u64 = 1_735_689_600;

/// The policy `ReplayCache` documents, written plainly: entries sorted by
/// (until, id), the first one dropped first.
struct Model {
    capacity: usize,
    held: Vec<(u64, [u8; 32])>,
}

impl Model {
    fn evict_one(&mut self) -> Option<[u8; 32]> {
        let i = (0..self.held.len()).min_by_key(|&i| self.held[i])?;
        Some(self.held.remove(i).1)
    }

    fn contains(&self, id: &[u8; 32]) -> bool {
        self.held.iter().any(|(_, h)| h == id)
    }

    /// Returns whether it was a first use, and the ids dropped for room.
    fn first_use(&mut self, id: [u8; 32], expires: u64, now: u64) -> (bool, Vec<[u8; 32]>) {
        self.held.retain(|&(until, _)| until >= now);
        if self.contains(&id) {
            return (false, Vec::new());
        }
        let mut dropped = Vec::new();
        while self.held.len() >= self.capacity {
            dropped.extend(self.evict_one());
        }
        self.held.push((expires.saturating_add(CLOCK_SKEW_SECS), id));
        (true, dropped)
    }

    fn restore(&mut self, id: [u8; 32], until: u64, now: u64) -> Vec<[u8; 32]> {
        if until < now || self.contains(&id) {
            return Vec::new();
        }
        let first = self.held.iter().min().copied();
        if self.held.len() >= self.capacity && first.is_some_and(|(f, _)| until <= f) {
            return Vec::new();
        }
        let mut dropped = Vec::new();
        while self.held.len() >= self.capacity {
            dropped.extend(self.evict_one());
        }
        self.held.push((until, id));
        dropped
    }

    fn entries(&self, now: u64) -> Vec<([u8; 32], u64)> {
        let mut e: Vec<_> = self.held.iter().filter(|(until, _)| *until >= now).copied().collect();
        e.sort();
        e.into_iter().map(|(until, id)| (id, until)).collect()
    }
}

fn info(id: [u8; 32], expires: u64) -> SignatureInfo {
    SignatureInfo {
        replay_id: id,
        expires,
        components: vec!["@authority".into()],
    }
}

fn rel(now: u64, d: u8) -> u64 {
    match d {
        0xFF => u64::MAX,
        0x80..=0xFE => now.saturating_sub(u64::from(d - 0x80) * 13),
        _ => now.saturating_add(u64::from(d) * 13),
    }
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some((&cap, mut ops)) = data.split_first() else { return };
    let capacity = 1 + usize::from(cap % 8);
    let mut cache = ReplayCache::new(capacity);
    let mut model = Model {
        capacity,
        held: Vec::new(),
    };
    let mut now = START;
    // Accepted signatures the capacity has not dropped: id -> refused until.
    let mut guarded: HashMap<[u8; 32], u64> = HashMap::new();

    while let Some((&tag, rest)) = ops.split_first() {
        ops = rest;
        let mut arg = || {
            let (&b, rest) = ops.split_first().unwrap_or((&0, &[]));
            ops = rest;
            b
        };
        match tag % 4 {
            0 => {
                let id = [arg() % 16; 32];
                let expires = rel(now, arg());
                let got = cache.first_use(&info(id, expires), now);
                let (want, dropped) = model.first_use(id, expires, now);
                assert_eq!(got, want, "first_use differs from the model");
                for d in dropped {
                    guarded.remove(&d);
                }
                if let Some(&until) = guarded.get(&id) {
                    if until >= now {
                        assert!(!got, "replay accepted: refused until {until}, now {now}");
                    }
                }
                if got {
                    guarded.insert(id, expires.saturating_add(CLOCK_SKEW_SECS));
                }
            }
            1 => now = now.saturating_add(u64::from(arg()) * 7),
            2 => {
                let id = [arg() % 16; 32];
                let until = rel(now, arg());
                cache.restore(id, until, now);
                for d in model.restore(id, until, now) {
                    guarded.remove(&d);
                }
            }
            _ => {
                let saved = cache.entries(now);
                let mut fresh = ReplayCache::new(capacity);
                for &(id, until) in &saved {
                    fresh.restore(id, until, now);
                }
                assert_eq!(fresh.entries(now), saved, "a restart lost or changed entries");
                cache = fresh;
                model.held.retain(|&(until, _)| until >= now);
            }
        }
        assert!(cache.len() <= capacity, "{} entries over capacity {capacity}", cache.len());
        assert_eq!(cache.is_empty(), cache.len() == 0);
        assert_eq!(cache.entries(now), model.entries(now), "held set differs from the model");
    }
});
