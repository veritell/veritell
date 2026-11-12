//! Acceptance tests for quota snapshots. FIXED BY THE PROJECT LEAD: DO NOT EDIT.

use veritell_quota::*;

/// The start of a day: 19676 * 86400.
const T0: u64 = 1_700_006_400;
const DAY: u64 = 86_400;

fn seeded(seed: u8, max: usize) -> Quotas {
    Quotas::new(Config { hash_seed: Some([seed; 16]), max_identities: max, ..Config::default() }).unwrap()
}

fn random() -> Quotas {
    Quotas::new(Config::default()).unwrap()
}

#[test]
fn the_days_use_survives_a_restart_with_another_key() {
    let a = random();
    for _ in 0..4 {
        a.take("agent-a", 10, T0 + 100);
    }
    a.take("agent-b", 10, T0 + 100);
    let b = random();
    assert_eq!(b.import(&a.export(T0 + 200), T0 + 300), Ok(2));
    assert_eq!(b.left("agent-a", 10, T0 + 300), 6);
    assert_eq!(b.left("agent-b", 10, T0 + 300), 9);
    assert_eq!(b.left("agent-c", 10, T0 + 300), 10);
    assert_eq!(b.take("agent-a", 10, T0 + 300), 6);
    assert_eq!(b.left("agent-a", 10, T0 + 300), 5);
}

#[test]
fn the_format_is_as_documented() {
    let a = seeded(9, 100);
    a.take("x", 10, T0 + 5);
    let snap = a.export(T0 + 5);
    assert_eq!(snap[0], 1);
    assert_eq!(&snap[1..17], &[9u8; 16]);
    assert_eq!(&snap[17..25], &DAY.to_be_bytes());
    assert_eq!(&snap[25..33], &(T0 / DAY).to_be_bytes());
    assert_eq!(&snap[33..37], &1u32.to_be_bytes());
    assert_eq!(snap.len(), 37 + 16 + 4);
    assert_eq!(&snap[53..57], &1u32.to_be_bytes());
}

#[test]
fn rate_windows_are_not_carried() {
    let a = seeded(1, 100);
    assert!(a.allow_rate("x", 1, T0));
    assert!(!a.allow_rate("x", 1, T0));
    a.take("x", 10, T0);
    let b = seeded(2, 100);
    b.import(&a.export(T0), T0).unwrap();
    assert!(b.allow_rate("x", 1, T0));
}

#[test]
fn identities_with_nothing_taken_today_are_left_out() {
    let a = seeded(1, 100);
    // In time order: an earlier `now` would count as the latest one seen.
    a.take("yesterday", 10, T0 - 10);
    a.allow_rate("only-rate", 5, T0);
    a.take("today", 10, T0 + 10);
    let b = seeded(2, 100);
    assert_eq!(b.import(&a.export(T0 + 10), T0 + 10), Ok(1));
    assert_eq!(b.left("today", 10, T0 + 10), 9);
}

#[test]
fn a_snapshot_from_an_earlier_day_loads_no_entries() {
    let a = seeded(1, 100);
    a.take("x", 10, T0 + 10);
    let snap = a.export(T0 + 10);
    let b = seeded(2, 100);
    assert_eq!(b.import(&snap, T0 + DAY + 10), Ok(0));
    assert_eq!(b.left("x", 10, T0 + DAY + 10), 10);
    assert_eq!(b.tracked(), 0);
}

#[test]
fn the_most_recently_used_are_kept_when_there_is_less_room() {
    let a = seeded(1, 100);
    for name in ["first", "second", "third"] {
        a.take(name, 10, T0 + 1);
    }
    a.take("first", 10, T0 + 2); // now the most recently used
    let b = seeded(2, 2);
    assert_eq!(b.import(&a.export(T0 + 2), T0 + 3), Ok(2));
    assert_eq!(b.left("first", 10, T0 + 3), 8);
    assert_eq!(b.left("third", 10, T0 + 3), 9);
    assert_eq!(b.left("second", 10, T0 + 3), 10, "the least recently used was kept");
}

#[test]
fn load_only_into_an_unused_value() {
    let a = seeded(1, 100);
    a.take("x", 10, T0);
    let b = seeded(2, 100);
    b.take("y", 10, T0);
    assert_eq!(b.import(&a.export(T0), T0), Err(SnapshotError::NotEmpty));
    assert_eq!(b.left("x", 10, T0), 10);
    assert_eq!(b.left("y", 10, T0), 9);
}

#[test]
fn another_day_length_is_refused() {
    let a = seeded(1, 100);
    a.take("x", 10, T0);
    let b = Quotas::new(Config { day_secs: 3600, hash_seed: Some([2; 16]), ..Config::default() }).unwrap();
    assert_eq!(b.import(&a.export(T0), T0), Err(SnapshotError::Mismatch));
    assert_eq!(b.tracked(), 0);
}

#[test]
fn malformed_input_changes_nothing() {
    let a = seeded(1, 100);
    a.take("x", 10, T0);
    a.take("y", 10, T0);
    let good = a.export(T0);
    let mut cases: Vec<Vec<u8>> = (0..good.len()).map(|n| good[..n].to_vec()).collect();
    let mut trailing = good.clone();
    trailing.push(0);
    cases.push(trailing);
    let mut v2 = good.clone();
    v2[0] = 2;
    cases.push(v2);
    let mut twice = good[..37].to_vec();
    twice[33..37].copy_from_slice(&2u32.to_be_bytes());
    twice.extend_from_slice(&good[37..57]);
    twice.extend_from_slice(&good[37..57]);
    cases.push(twice);
    let mut zero = good.clone();
    zero[53..57].copy_from_slice(&0u32.to_be_bytes());
    cases.push(zero);
    let mut later = good.clone();
    later[25..33].copy_from_slice(&(T0 / DAY + 1).to_be_bytes());
    cases.push(later);
    let mut huge = good[..33].to_vec();
    huge.extend_from_slice(&u32::MAX.to_be_bytes());
    cases.push(huge);
    for (i, c) in cases.iter().enumerate() {
        let b = seeded(2, 100);
        assert_eq!(b.import(c, T0), Err(SnapshotError::Malformed), "case {i}");
        assert_eq!(b.tracked(), 0, "case {i}");
        // The key was not replaced: a fresh value with seed 2 agrees with it.
        b.take("z", 10, T0);
        let c2 = seeded(2, 100);
        c2.take("z", 10, T0);
        assert_eq!(b.export(T0), c2.export(T0), "case {i} replaced the key");
    }
}
