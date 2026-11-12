//! Acceptance tests for MemoryBudgetStore snapshots. FIXED BY THE PROJECT LEAD: DO NOT EDIT.

use veritell_token::{BudgetStore, MemoryBudgetStore, SnapshotError};

const NOW: u64 = 1_800_000_000;

fn id(n: u8) -> [u8; 16] {
    [n; 16]
}

fn entry(out: &mut Vec<u8>, id: [u8; 16], used: u32, exp: u64) {
    out.extend_from_slice(&id);
    out.extend_from_slice(&used.to_be_bytes());
    out.extend_from_slice(&exp.to_be_bytes());
}

fn snapshot(entries: &[([u8; 16], u32, u64)]) -> Vec<u8> {
    let mut out = vec![1];
    out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for (i, u, e) in entries {
        entry(&mut out, *i, *u, *e);
    }
    out
}

#[test]
fn export_is_the_documented_format_in_id_order() {
    let s = MemoryBudgetStore::new(10);
    assert!(s.consume(&id(9), 3, NOW + 100, NOW));
    assert!(s.consume(&id(2), 1, NOW + 50, NOW));
    assert!(s.consume(&id(9), 3, NOW + 100, NOW));
    assert_eq!(s.export(NOW), snapshot(&[(id(2), 1, NOW + 50), (id(9), 2, NOW + 100)]));
}

#[test]
fn an_empty_store_exports_a_count_of_zero() {
    assert_eq!(MemoryBudgetStore::new(10).export(NOW), vec![1, 0, 0, 0, 0]);
}

#[test]
fn expired_entries_are_not_exported() {
    let s = MemoryBudgetStore::new(10);
    assert!(s.consume(&id(1), 1, NOW + 10, NOW));
    assert!(s.consume(&id(2), 1, NOW + 20, NOW));
    assert_eq!(s.export(NOW + 10), snapshot(&[(id(2), 1, NOW + 20)]));
}

#[test]
fn a_spent_id_stays_spent_after_a_round_trip() {
    let a = MemoryBudgetStore::new(10);
    assert!(a.consume(&id(1), 1, NOW + 600, NOW)); // a redeemed token
    assert!(a.consume(&id(2), 3, NOW + 600, NOW)); // a session with budget 3, one used
    let b = MemoryBudgetStore::new(10);
    assert_eq!(b.import(&a.export(NOW), NOW + 1), Ok(2));
    assert!(!b.consume(&id(1), 1, NOW + 600, NOW + 1), "the token was taken again");
    assert!(b.consume(&id(2), 3, NOW + 600, NOW + 1));
    assert!(b.consume(&id(2), 3, NOW + 600, NOW + 1));
    assert!(!b.consume(&id(2), 3, NOW + 600, NOW + 1), "the budget grew back");
    assert_eq!(b.len(), 2);
}

#[test]
fn import_skips_what_has_expired_since() {
    let b = MemoryBudgetStore::new(10);
    let snap = snapshot(&[(id(1), 1, NOW + 5), (id(2), 1, NOW + 50)]);
    assert_eq!(b.import(&snap, NOW + 5), Ok(1));
    assert_eq!(b.len(), 1);
    assert!(!b.consume(&id(2), 1, NOW + 50, NOW + 6));
}

#[test]
fn import_merges_with_what_is_there() {
    let b = MemoryBudgetStore::new(10);
    assert!(b.consume(&id(1), 5, NOW + 10, NOW));
    let snap = snapshot(&[(id(1), 3, NOW + 100)]);
    assert_eq!(b.import(&snap, NOW), Ok(1));
    // used is max(1, 3) = 3: two more of five.
    assert!(b.consume(&id(1), 5, NOW + 10, NOW));
    assert!(b.consume(&id(1), 5, NOW + 10, NOW));
    assert!(!b.consume(&id(1), 5, NOW + 10, NOW));
    // expires_at is the later one: still exported after the first had expired.
    assert_eq!(b.export(NOW + 50), snapshot(&[(id(1), 5, NOW + 100)]));
    // A smaller used does not lower it.
    assert_eq!(b.import(&snapshot(&[(id(1), 1, NOW + 100)]), NOW), Ok(1));
    assert!(!b.consume(&id(1), 5, NOW + 10, NOW));
}

#[test]
fn import_respects_capacity() {
    let b = MemoryBudgetStore::new(2);
    assert!(b.consume(&id(1), 1, NOW + 100, NOW));
    let snap = snapshot(&[(id(1), 1, NOW + 100), (id(2), 1, NOW + 100), (id(3), 1, NOW + 100)]);
    assert_eq!(b.import(&snap, NOW), Ok(2));
    assert_eq!(b.len(), 2);
}

#[test]
fn malformed_input_changes_nothing() {
    let b = MemoryBudgetStore::new(10);
    assert!(b.consume(&id(5), 2, NOW + 100, NOW));
    let before = b.export(NOW);
    let good = snapshot(&[(id(1), 1, NOW + 100), (id(2), 1, NOW + 100)]);
    let mut cases: Vec<Vec<u8>> = Vec::new();
    for n in 0..good.len() {
        cases.push(good[..n].to_vec());
    }
    let mut trailing = good.clone();
    trailing.push(0);
    cases.push(trailing);
    let mut v2 = good.clone();
    v2[0] = 2;
    cases.push(v2);
    let mut v0 = good.clone();
    v0[0] = 0;
    cases.push(v0);
    cases.push(snapshot(&[(id(2), 1, NOW + 100), (id(1), 1, NOW + 100)])); // out of order
    cases.push(snapshot(&[(id(1), 1, NOW + 100), (id(1), 1, NOW + 100)])); // repeated
    cases.push(snapshot(&[(id(1), 0, NOW + 100)])); // used 0
    let mut huge = vec![1];
    huge.extend_from_slice(&u32::MAX.to_be_bytes());
    cases.push(huge);
    for (i, c) in cases.iter().enumerate() {
        assert_eq!(b.import(c, NOW), Err(SnapshotError::Malformed), "case {i}");
        assert_eq!(b.export(NOW), before, "case {i} changed the store");
    }
}
