//! Acceptance tests for `addr`. FIXED BY THE PROJECT LEAD: DO NOT EDIT.

use std::net::IpAddr;
use std::sync::Arc;

use hmac::{Hmac, Mac};
use veritell_events::addr::{AddrMode, AddrRedactor};
use sha2::Sha256;

const DAY: u64 = 86_400;
const T0: u64 = 1_793_000_000; // 2026-10-26 07:33 UTC

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn day_keys() -> Box<dyn Fn(u64) -> [u8; 32] + Send + Sync> {
    Box::new(|day| {
        let mut k = [0u8; 32];
        k[..8].copy_from_slice(&day.to_be_bytes());
        k
    })
}

fn expected_keyed(key: [u8; 32], octets: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
    mac.update(octets);
    let out = mac.finalize().into_bytes();
    let hex: String = out[..16].iter().map(|b| format!("{b:02x}")).collect();
    format!("k:{hex}")
}

#[test]
fn parse_modes() {
    assert_eq!(AddrMode::parse("full"), Some(AddrMode::Full));
    assert_eq!(AddrMode::parse("truncated"), Some(AddrMode::Truncated));
    assert_eq!(AddrMode::parse("keyed"), Some(AddrMode::Keyed));
    assert_eq!(AddrMode::parse("Keyed"), None);
    assert_eq!(AddrMode::parse(""), None);
    assert_eq!(AddrMode::parse("keyed "), None);
}

#[test]
fn full_writes_the_address() {
    let r = AddrRedactor::with_keys(AddrMode::Full, day_keys());
    assert_eq!(r.mode(), AddrMode::Full);
    assert_eq!(r.stored(ip("203.0.113.9"), T0), "203.0.113.9");
    assert_eq!(r.stored(ip("::ffff:203.0.113.9"), T0), "203.0.113.9");
    assert_eq!(r.stored(ip("2001:db8::1"), T0), "2001:db8::1");
}

#[test]
fn truncated_keeps_the_network() {
    let r = AddrRedactor::with_keys(AddrMode::Truncated, day_keys());
    assert_eq!(r.stored(ip("203.0.113.9"), T0), "203.0.113.0/24");
    assert_eq!(r.stored(ip("203.0.113.255"), T0), "203.0.113.0/24");
    assert_eq!(r.stored(ip("::ffff:198.51.100.7"), T0), "198.51.100.0/24");
    assert_eq!(r.stored(ip("2001:db8:abcd:12::1"), T0), "2001:db8:abcd::/48");
    assert_eq!(r.stored(ip("2001:db8:abcd:ffff:ffff:ffff:ffff:ffff"), T0), "2001:db8:abcd::/48");
    assert_eq!(r.stored(ip("::1"), T0), "::/48");
}

#[test]
fn keyed_is_hmac_of_the_octets_under_the_days_key() {
    let r = AddrRedactor::with_keys(AddrMode::Keyed, day_keys());
    let day = T0 / DAY;
    let key = (day_keys())(day);
    assert_eq!(r.stored(ip("203.0.113.9"), T0), expected_keyed(key, &[203, 0, 113, 9]));
    assert_eq!(r.stored(ip("::ffff:203.0.113.9"), T0), expected_keyed(key, &[203, 0, 113, 9]));
    let v6 = ip("2001:db8::1");
    let IpAddr::V6(a) = v6 else { unreachable!() };
    assert_eq!(r.stored(v6, T0), expected_keyed(key, &a.octets()));
}

#[test]
fn keyed_links_within_a_day_and_not_across() {
    let r = AddrRedactor::with_keys(AddrMode::Keyed, day_keys());
    let start = T0 - T0 % DAY;
    let a = r.stored(ip("203.0.113.9"), start);
    assert_eq!(a, r.stored(ip("203.0.113.9"), start + DAY - 1));
    assert_ne!(a, r.stored(ip("203.0.113.9"), start + DAY));
    assert_ne!(a, r.stored(ip("203.0.113.10"), start));
    let shape = |s: &str| {
        s.len() == 34 && s.starts_with("k:") && s[2..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    assert!(shape(&a), "{a}");
    assert!(!a.contains("203.0.113"));
}

#[test]
fn keyed_goes_back_to_an_earlier_day_without_panicking() {
    // Clocks step backwards; the value must still be well formed.
    let r = AddrRedactor::with_keys(AddrMode::Keyed, day_keys());
    let late = r.stored(ip("203.0.113.9"), T0 + DAY);
    let early = r.stored(ip("203.0.113.9"), T0);
    assert_ne!(late, early);
    assert_eq!(early, expected_keyed((day_keys())(T0 / DAY), &[203, 0, 113, 9]));
}

#[test]
fn random_keys_differ_between_redactors() {
    let a = AddrRedactor::new(AddrMode::Keyed);
    let b = AddrRedactor::new(AddrMode::Keyed);
    let x = a.stored(ip("203.0.113.9"), T0);
    assert_eq!(x, a.stored(ip("203.0.113.9"), T0 + 60));
    assert_ne!(x, b.stored(ip("203.0.113.9"), T0));
}

#[test]
fn shared_between_threads() {
    let r = Arc::new(AddrRedactor::new(AddrMode::Keyed));
    let first = r.stored(ip("192.0.2.1"), T0);
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let r = Arc::clone(&r);
            std::thread::spawn(move || r.stored(ip("192.0.2.1"), T0))
        })
        .collect();
    for h in handles {
        assert_eq!(h.join().unwrap(), first);
    }
}
