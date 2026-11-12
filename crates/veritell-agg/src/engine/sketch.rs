//! Mergeable distinct-count sketch (HyperLogLog, 256 registers of 4 bits)
//! and the per-key rings of slot cells that make up a sliding window.
//!
//! A ring has `2 * window_slots` cells. The cell for slot `s` lives at
//! `s % (2 * window_slots)`, so a time jump of any size costs nothing: stale
//! cells are recognised by their slot number and reset when next written.
//! The estimates for the current and the previous window are cached and are
//! only recomputed when the window moves or a new element could change the
//! current union, so the common request costs a few comparisons.

/// Registers per sketch.
pub(crate) const M: usize = 256;
const BYTES: usize = M / 2;
/// Registers hold ranks up to 15 (enough for far more than 20,000 elements
/// over 256 registers).
const MAX_RANK: u32 = 15;
/// Approximate heap size of one dense sketch, for the memory bound.
pub(crate) const DENSE_BYTES: usize = std::mem::size_of::<Dense>();

/// Register index and rank of a 64-bit keyed hash.
pub(crate) fn split(h: u64) -> (usize, u8) {
    let idx = (h >> 56) as usize; // 0..=255
    let rank = ((h << 8).leading_zeros() + 1).min(MAX_RANK) as u8; // 1..=15
    (idx, rank)
}

/// One slot's sketch: 256 four-bit registers.
pub(crate) struct Dense {
    regs: [u8; BYTES],
}

impl Dense {
    fn new() -> Self {
        Dense { regs: [0; BYTES] }
    }

    fn get(&self, idx: usize) -> u8 {
        match self.regs.get(idx >> 1) {
            Some(b) if idx & 1 == 0 => b & 15,
            Some(b) => b >> 4,
            None => 0,
        }
    }

    fn raise(&mut self, idx: usize, rank: u8) {
        if let Some(b) = self.regs.get_mut(idx >> 1) {
            let shift = ((idx & 1) * 4) as u32;
            if rank > (*b >> shift) & 15 {
                *b = (*b & !(15u8 << shift)) | (rank << shift);
            }
        }
    }

    fn clear(&mut self) {
        self.regs = [0; BYTES];
    }
}

/// Union of several sketches, one byte per register.
pub(crate) struct Acc([u8; M]);

impl Acc {
    pub(crate) fn new() -> Self {
        Acc([0; M])
    }

    pub(crate) fn merge(&mut self, d: &Dense) {
        for ([lo, hi], &b) in self.0.as_chunks_mut::<2>().0.iter_mut().zip(d.regs.iter()) {
            *lo = (*lo).max(b & 15);
            *hi = (*hi).max(b >> 4);
        }
    }

    /// HyperLogLog estimate with the linear-counting correction for small
    /// ranges.
    pub(crate) fn estimate(&self) -> u32 {
        let m = M as f64;
        let mut zeros = 0u32;
        let mut sum = 0.0f64;
        for &r in &self.0 {
            if r == 0 {
                zeros += 1;
            }
            // 2^-r, exact.
            sum += f64::from_bits((1023 - u64::from(r & 15)) << 52);
        }
        let alpha = 0.7213 / (1.0 + 1.079 / m);
        let raw = alpha * m * m / sum;
        let est = if raw <= 2.5 * m && zeros > 0 { m * (m / f64::from(zeros)).ln() } else { raw };
        (est + 0.5) as u32 // saturating cast
    }
}

/// `Some(age)` of a cell's slot relative to slot `s`, if it is not in the future.
fn age(s: u64, slot: u64) -> Option<u64> {
    s.checked_sub(slot)
}

fn pos(s: u64, w: u64) -> usize {
    usize::try_from(s % w.saturating_mul(2).max(1)).unwrap_or(0)
}

pub(crate) struct SketchCell {
    slot: u64,
    n: u64,
    sk: Option<Box<Dense>>,
}

/// Per-key ring of requests counts and distinct-element sketches.
pub(crate) struct SketchRing {
    cells: Box<[SketchCell]>,
    est_slot: Option<u64>,
    est_cur: u32,
    est_prev: u32,
}

impl SketchRing {
    pub(crate) fn new(w: u64) -> Self {
        let n = usize::try_from(w.saturating_mul(2)).unwrap_or(2).max(1);
        let cells: Vec<SketchCell> = (0..n).map(|_| SketchCell { slot: 0, n: 0, sk: None }).collect();
        SketchRing { cells: cells.into_boxed_slice(), est_slot: None, est_cur: 0, est_prev: 0 }
    }

    /// Counts one request in slot `s` and adds `elem` (a keyed hash) to the
    /// slot's sketch. Afterwards `est_cur`/`est_prev` are valid for `s`.
    pub(crate) fn record(&mut self, s: u64, w: u64, elem: u64) {
        let (idx, rank) = split(elem);
        let dominated = self.cells.iter().any(|c| {
            age(s, c.slot).is_some_and(|a| a < w) && c.sk.as_ref().is_some_and(|d| d.get(idx) >= rank)
        });
        if let Some(c) = self.cells.get_mut(pos(s, w)) {
            if c.slot != s {
                c.slot = s;
                c.n = 0;
                if let Some(d) = c.sk.as_mut() {
                    d.clear();
                }
            }
            c.n = c.n.saturating_add(1);
            c.sk.get_or_insert_with(|| Box::new(Dense::new())).raise(idx, rank);
        }
        if self.est_slot != Some(s) {
            self.est_slot = Some(s);
            self.est_cur = self.union_est(s, w, false);
            self.est_prev = self.union_est(s, w, true);
        } else if !dominated {
            self.est_cur = self.union_est(s, w, false);
        }
    }

    pub(crate) fn est_cur(&self) -> u32 {
        self.est_cur
    }

    pub(crate) fn est_prev(&self) -> u32 {
        self.est_prev
    }

    /// Requests counted in the current window.
    pub(crate) fn requests(&self, s: u64, w: u64) -> u64 {
        self.cells
            .iter()
            .filter(|c| age(s, c.slot).is_some_and(|a| a < w))
            .fold(0u64, |t, c| t.saturating_add(c.n))
    }

    /// Estimated distinct elements in the current (`prev == false`) or
    /// previous window, computed from the cells.
    pub(crate) fn union_est(&self, s: u64, w: u64, prev: bool) -> u32 {
        let mut acc = Acc::new();
        for c in self.cells.iter() {
            let in_window = age(s, c.slot).is_some_and(|a| if prev { a >= w && a < w.saturating_mul(2) } else { a < w });
            if in_window {
                if let Some(d) = c.sk.as_ref() {
                    acc.merge(d);
                }
            }
        }
        acc.estimate()
    }
}

#[derive(Clone, Copy)]
struct CountCell {
    slot: u64,
    n: u64,
}

/// Per-key ring of exact counts.
pub(crate) struct CountRing {
    cells: Box<[CountCell]>,
}

impl CountRing {
    pub(crate) fn new(w: u64) -> Self {
        let n = usize::try_from(w.saturating_mul(2)).unwrap_or(2).max(1);
        CountRing { cells: vec![CountCell { slot: 0, n: 0 }; n].into_boxed_slice() }
    }

    pub(crate) fn add(&mut self, s: u64, w: u64) {
        if let Some(c) = self.cells.get_mut(pos(s, w)) {
            if c.slot != s {
                c.slot = s;
                c.n = 0;
            }
            c.n = c.n.saturating_add(1);
        }
    }

    pub(crate) fn cur(&self, s: u64, w: u64) -> u64 {
        self.sum(s, |a| a < w)
    }

    pub(crate) fn prev(&self, s: u64, w: u64) -> u64 {
        self.sum(s, |a| a >= w && a < w.saturating_mul(2))
    }

    fn sum(&self, s: u64, f: impl Fn(u64) -> bool) -> u64 {
        self.cells
            .iter()
            .filter(|c| age(s, c.slot).is_some_and(&f))
            .fold(0u64, |t, c| t.saturating_add(c.n))
    }
}

/// Heap bytes of one `SketchRing` with `w` window slots, every cell dense.
pub(crate) fn sketch_ring_bytes(w: usize) -> usize {
    let c = w.saturating_mul(2);
    c.saturating_mul(std::mem::size_of::<SketchCell>() + DENSE_BYTES + 16).saturating_add(16)
}

/// Heap bytes of one `CountRing`.
pub(crate) fn count_ring_bytes(w: usize) -> usize {
    w.saturating_mul(2).saturating_mul(std::mem::size_of::<CountCell>()).saturating_add(16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::hash::Hasher;

    fn h(key: u64, i: u64) -> u64 {
        let mut s = siphasher::sip::SipHasher13::new_with_keys(key, key ^ 0x9e37_79b9);
        s.write_u64(i);
        s.finish()
    }

    #[test]
    fn registers_pack_and_raise() {
        let mut d = Dense::new();
        d.raise(0, 3);
        d.raise(1, 9);
        d.raise(255, 15);
        d.raise(1, 4);
        assert_eq!((d.get(0), d.get(1), d.get(2), d.get(255)), (3, 9, 0, 15));
    }

    #[test]
    fn estimate_error_is_well_inside_the_contract() {
        for n in [1u64, 5, 100, 1_000, 5_000, 20_000] {
            let mut worst = 0.0f64;
            for key in 0..60u64 {
                let mut a = Acc::new();
                let mut d = Dense::new();
                for i in 0..n {
                    let (idx, r) = split(h(key * 7 + 1, i));
                    d.raise(idx, r);
                }
                a.merge(&d);
                let e = f64::from(a.estimate());
                worst = worst.max((e - n as f64).abs() / n as f64);
            }
            assert!(worst < 0.25 || n < 10, "n {n} worst {worst}");
        }
    }

    #[test]
    fn jumps_do_not_loop_and_old_cells_drop() {
        let mut r = SketchRing::new(6);
        r.record(5, 6, 123);
        r.record(u64::MAX, 6, 456);
        assert_eq!(r.requests(u64::MAX, 6), 1);
        assert_eq!(r.union_est(u64::MAX, 6, true), 0);
    }
}
