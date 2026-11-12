//! Saving and loading a [`MemoryBudgetStore`], so that a token, a solved
//! challenge or a nonce already used stays used across a restart.
//!
//! FIXED BY THE PROJECT LEAD: the public items and their documentation are
//! the contract. Implement the bodies; do not change a signature. Nothing may
//! panic for any input.
//!
//! # Format (version 1)
//!
//! ```text
//! version   u8 = 1
//! count     u32 big-endian
//! entries   count times: id [u8; 16], used u32 BE, expires_at u64 BE
//! ```
//!
//! Entries are in ascending order of `id`, with no id twice, and nothing
//! follows the last one.

use std::fmt;

use crate::MemoryBudgetStore;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotError {
    /// Not version 1, the wrong length for its count, ids out of order or
    /// repeated, or a `used` of 0.
    Malformed,
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("budget store snapshot is malformed")
    }
}

impl std::error::Error for SnapshotError {}

impl MemoryBudgetStore {
    /// Every entry that has not expired at `now` (`expires_at > now`), in the
    /// format above.
    pub fn export(&self, now: u64) -> Vec<u8> {
        let mut entries: Vec<Entry> = {
            let map = self.map.lock().unwrap_or_else(|e| e.into_inner());
            map.iter()
                .filter(|(_, v)| v.1 > now)
                .map(|(id, v)| (*id, v.0, v.1))
                .collect()
        };
        entries.sort_unstable_by_key(|e| e.0);
        entries.truncate(usize::try_from(u32::MAX).unwrap_or(usize::MAX));
        let count = u32::try_from(entries.len()).unwrap_or(u32::MAX);
        let mut out =
            Vec::with_capacity(HEADER_LEN.saturating_add(entries.len().saturating_mul(ENTRY_LEN)));
        out.push(VERSION);
        out.extend_from_slice(&count.to_be_bytes());
        for (id, used, expires_at) in entries {
            out.extend_from_slice(&id);
            out.extend_from_slice(&used.to_be_bytes());
            out.extend_from_slice(&expires_at.to_be_bytes());
        }
        out
    }

    /// Loads a snapshot made by [`MemoryBudgetStore::export`].
    ///
    /// The whole input is checked before anything changes: if it is
    /// malformed the store is left exactly as it was. Entries expired at
    /// `now` are skipped. An id already in the store keeps the larger `used`
    /// and the later `expires_at` of the two. New ids are added while the
    /// store has room (its `max_entries`); the rest are skipped. Returns how
    /// many entries were added or merged.
    pub fn import(&self, bytes: &[u8], now: u64) -> Result<usize, SnapshotError> {
        let entries = parse(bytes)?;
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        let mut applied = 0usize;
        for (id, used, expires_at) in entries {
            if expires_at <= now {
                continue;
            }
            if let Some(slot) = map.get_mut(&id) {
                slot.0 = slot.0.max(used);
                slot.1 = slot.1.max(expires_at);
                applied += 1;
            } else if map.len() < self.max_entries {
                map.insert(id, (used, expires_at));
                applied += 1;
            }
        }
        Ok(applied)
    }
}

/// One snapshot entry: id, used, expires_at.
type Entry = ([u8; 16], u32, u64);

const VERSION: u8 = 1;
const HEADER_LEN: usize = 5;
const ENTRY_LEN: usize = 28;

/// Validates the whole snapshot before anything is applied. Checks the
/// version, the exact length for the count (computed with checked arithmetic
/// before anything is allocated), strictly ascending ids and `used > 0`.
fn parse(bytes: &[u8]) -> Result<Vec<Entry>, SnapshotError> {
    if bytes.first() != Some(&VERSION) {
        return Err(SnapshotError::Malformed);
    }
    let count_bytes: [u8; 4] = bytes
        .get(1..HEADER_LEN)
        .and_then(|b| b.try_into().ok())
        .ok_or(SnapshotError::Malformed)?;
    let count = usize::try_from(u32::from_be_bytes(count_bytes))
        .map_err(|_| SnapshotError::Malformed)?;
    let expected_len = count
        .checked_mul(ENTRY_LEN)
        .and_then(|n| n.checked_add(HEADER_LEN));
    if expected_len != Some(bytes.len()) {
        return Err(SnapshotError::Malformed);
    }
    let body = bytes.get(HEADER_LEN..).ok_or(SnapshotError::Malformed)?;
    let mut entries = Vec::with_capacity(count);
    let mut prev: Option<[u8; 16]> = None;
    for chunk in body.as_chunks::<ENTRY_LEN>().0 {
        let (id, used, expires_at) = read_entry(chunk).ok_or(SnapshotError::Malformed)?;
        if used == 0 || prev.is_some_and(|p| id <= p) {
            return Err(SnapshotError::Malformed);
        }
        prev = Some(id);
        entries.push((id, used, expires_at));
    }
    Ok(entries)
}

fn read_entry(chunk: &[u8]) -> Option<Entry> {
    let id: [u8; 16] = chunk.get(0..16)?.try_into().ok()?;
    let used = u32::from_be_bytes(chunk.get(16..20)?.try_into().ok()?);
    let expires_at = u64::from_be_bytes(chunk.get(20..28)?.try_into().ok()?);
    Some((id, used, expires_at))
}
