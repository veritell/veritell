//! What may be stored for a client address.
//!
//! FIXED BY THE PROJECT LEAD: the public items and their documentation are the
//! contract. Implement the bodies; do not change a signature.
//!
//! Scoring always sees the real address. This module only decides what text is
//! written outside the process: log lines, events, the dashboard.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;

use hmac::{Hmac, Mac};
use sha2::Sha256;

const SECS_PER_DAY: u64 = 86_400;

/// How an address is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddrMode {
    /// The address as text. IPv4-mapped IPv6 is written as the IPv4 address.
    Full,
    /// IPv4 kept to its /24 (`203.0.113.0/24`), IPv6 to its /48
    /// (`2001:db8:abcd::/48`). IPv4-mapped IPv6 is treated as IPv4.
    Truncated,
    /// `k:` followed by 32 lowercase hex characters: the first 16 bytes of
    /// HMAC-SHA256 under the day's key, over the address's octets (4 bytes
    /// for IPv4, including IPv4-mapped IPv6; 16 for IPv6). The day is
    /// `now_secs / 86400`. Each day has its own key.
    Keyed,
}

impl AddrMode {
    /// `"full"`, `"truncated"` or `"keyed"`, exactly; anything else is `None`.
    pub fn parse(s: &str) -> Option<AddrMode> {
        match s {
            "full" => Some(AddrMode::Full),
            "truncated" => Some(AddrMode::Truncated),
            "keyed" => Some(AddrMode::Keyed),
            _ => None,
        }
    }
}

type KeyFn = Box<dyn Fn(u64) -> [u8; 32] + Send + Sync>;

/// The key currently held, and the day it belongs to. `key` is `None` when the
/// operating system's random source failed; the next call tries again.
#[derive(Default)]
struct Slot {
    day: Option<u64>,
    key: Option<[u8; 32]>,
}

/// Turns an address into the text that may be stored.
///
/// `Send + Sync`; `stored` never panics and never blocks on I/O.
pub struct AddrRedactor {
    mode: AddrMode,
    /// `None` means keys come from the operating system's random source.
    key_for_day: Option<KeyFn>,
    slot: Mutex<Slot>,
}

impl AddrRedactor {
    /// Keys come from the operating system's random source, one per day, and
    /// exist only in this process's memory. When the day changes the old key
    /// is dropped, so values from different days cannot be linked, and a
    /// restart starts a new key.
    pub fn new(mode: AddrMode) -> AddrRedactor {
        AddrRedactor {
            mode,
            key_for_day: None,
            slot: Mutex::new(Slot::default()),
        }
    }

    /// Keys come from `key_for_day(day)`. For tests.
    pub fn with_keys(
        mode: AddrMode,
        key_for_day: Box<dyn Fn(u64) -> [u8; 32] + Send + Sync>,
    ) -> AddrRedactor {
        AddrRedactor {
            mode,
            key_for_day: Some(key_for_day),
            slot: Mutex::new(Slot::default()),
        }
    }

    pub fn mode(&self) -> AddrMode {
        self.mode
    }

    /// The text to store for `ip` at `now_secs` (Unix seconds).
    pub fn stored(&self, ip: IpAddr, now_secs: u64) -> String {
        match self.mode {
            AddrMode::Full => full(ip),
            AddrMode::Truncated => truncated(ip),
            AddrMode::Keyed => self.keyed(ip, now_secs / SECS_PER_DAY),
        }
    }

    fn keyed(&self, ip: IpAddr, day: u64) -> String {
        let key = {
            let mut slot = match self.slot.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            // A random key only moves forward: a caller whose clock reads
            // the day before (a thread either side of midnight, a clock
            // stepped back) gets the current key, not a fresh one that would
            // give the same address two values in a day. Keys derived per
            // day give each day its own key either way.
            let day = match (&self.key_for_day, slot.day) {
                (None, Some(d)) => d.max(day),
                _ => day,
            };
            if slot.day != Some(day) || slot.key.is_none() {
                let key = match &self.key_for_day {
                    Some(f) => Some(f(day)),
                    None => {
                        let mut k = [0u8; 32];
                        if getrandom::fill(&mut k).is_ok() {
                            Some(k)
                        } else {
                            None
                        }
                    }
                };
                *slot = Slot { day: Some(day), key };
            }
            slot.key
        };
        match key {
            Some(key) => keyed_text(&key, ip),
            None => format!("k:{}", "0".repeat(32)),
        }
    }
}

/// The IPv4 address behind an IPv4-mapped IPv6 address, if it is one.
fn as_v4(ip: IpAddr) -> Option<Ipv4Addr> {
    match ip {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(v6) => v6.to_ipv4_mapped(),
    }
}

fn full(ip: IpAddr) -> String {
    match as_v4(ip) {
        Some(v4) => v4.to_string(),
        None => ip.to_string(),
    }
}

fn truncated(ip: IpAddr) -> String {
    match as_v4(ip) {
        Some(v4) => {
            let [a, b, c, _] = v4.octets();
            format!("{}/24", Ipv4Addr::new(a, b, c, 0))
        }
        None => match ip {
            IpAddr::V6(v6) => {
                let mut kept = [0u8; 16];
                for (dst, src) in kept.iter_mut().zip(v6.octets().iter()).take(6) {
                    *dst = *src;
                }
                format!("{}/48", Ipv6Addr::from(kept))
            }
            IpAddr::V4(v4) => format!("{v4}"),
        },
    }
}

fn keyed_text(key: &[u8; 32], ip: IpAddr) -> String {
    let mut mac = match Hmac::<Sha256>::new_from_slice(key) {
        Ok(mac) => mac,
        Err(_) => return format!("k:{}", "0".repeat(32)),
    };
    match as_v4(ip) {
        Some(v4) => mac.update(&v4.octets()),
        None => match ip {
            IpAddr::V6(v6) => mac.update(&v6.octets()),
            IpAddr::V4(v4) => mac.update(&v4.octets()),
        },
    }
    let out = mac.finalize().into_bytes();
    let hex: String = out
        .iter()
        .take(16)
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("k:{hex}")
}

#[cfg(test)]
mod forward_tests {
    use super::*;

    #[test]
    fn a_random_key_is_not_redrawn_for_an_earlier_day() {
        let r = AddrRedactor::new(AddrMode::Keyed);
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let day = 20_000 * SECS_PER_DAY;
        let today = r.stored(ip, day + 10);
        assert_eq!(r.stored(ip, day - 10), today, "a late caller from yesterday");
        assert_eq!(r.stored(ip, day + 20), today, "and today again: no flip");
        assert_ne!(r.stored(ip, day + SECS_PER_DAY), today, "tomorrow moves on");
    }
}
