//! Audit tests: the minimum-network rule counts networks within the window.

use veritell_core::Class;
use veritell_share::*;

const T: u64 = 1_800_000_000;
const TTL: u64 = 1000;

fn ledger() -> Ledger {
    let key = ShareKey::new(b"0123456789abcdef0123456789abcdef").unwrap();
    Ledger::new(key, Config { min_networks: 5, max_fingerprints: 100, ttl_secs: TTL }).unwrap()
}

fn net(n: u32) -> [u8; 8] {
    let b = n.to_be_bytes();
    [4, 10, b[1], b[2], b[3], 0, 0, 0]
}

#[test]
fn networks_spread_over_many_windows_are_not_exported() {
    let l = ledger();
    // One network every 0.9 ttl: the entry stays alive, no window holds 5.
    for n in 0..20u32 {
        let now = T + u64::from(n) * (TTL * 9 / 10);
        l.record("fp", net(n), Class::Automated, now);
        assert!(l.export(now).is_empty(), "exported after {} networks", n + 1);
    }
}

#[test]
fn networks_inside_one_window_are_exported() {
    let l = ledger();
    for n in 0..5u32 {
        l.record("fp", net(n), Class::Automated, T + u64::from(n) * (TTL / 5));
    }
    assert_eq!(l.export(T + TTL).len(), 1);
}

#[test]
fn records_past_the_window_stop_counting() {
    let l = ledger();
    for n in 0..4u32 {
        l.record("fp", net(n), Class::Automated, T);
    }
    // Fifth network arrives late enough that the first four are stale at
    // export time, but the entry itself is still fresh.
    l.record("fp", net(4), Class::Automated, T + TTL);
    assert_eq!(l.export(T + TTL).len(), 1);
    l.record("fp", net(4), Class::Automated, T + TTL + 1);
    assert!(l.export(T + TTL + 1).is_empty());
    // Five fresh networks later count again.
    for n in 0..5u32 {
        l.record("fp", net(n), Class::Automated, T + TTL + 2);
    }
    assert_eq!(l.export(T + TTL + 2).len(), 1);
}

#[test]
fn a_renoted_network_refreshes_its_own_time() {
    let l = ledger();
    for n in 0..5u32 {
        l.record("fp", net(n), Class::Automated, T);
    }
    for n in 0..5u32 {
        l.record("fp", net(n), Class::Automated, T + 900);
    }
    assert_eq!(l.export(T + 1800).len(), 1);
}

#[test]
fn memory_stays_bounded_with_many_networks() {
    let l = ledger();
    for n in 0..10_000u32 {
        l.record("fp", net(n), Class::Malicious, T + u64::from(n % 50));
    }
    assert_eq!(l.tracked(), 1);
    assert_eq!(l.export(T + 60).len(), 1);
    // A lone network long after: the old records are past the window.
    l.record("fp", net(99_999), Class::Malicious, T + 3 * TTL);
    assert!(l.export(T + 3 * TTL).is_empty());
}
