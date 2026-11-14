//! Small helpers: form decoding, cookie lookup, throttling, system DNS.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use veritell_identity::Resolver;

/// Decodes `application/x-www-form-urlencoded`. Invalid escapes are kept
/// literally; invalid UTF-8 is replaced. Later duplicates are ignored.
pub fn parse_form(body: &[u8]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for pair in body.split(|b| *b == b'&') {
        if pair.is_empty() {
            continue;
        }
        let mut it = pair.splitn(2, |b| *b == b'=');
        let key = percent_decode(it.next().unwrap_or_default());
        let value = percent_decode(it.next().unwrap_or_default());
        out.entry(key).or_insert(value);
    }
    out
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn percent_decode(input: &[u8]) -> String {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while let Some(&b) = input.get(i) {
        match b {
            b'+' => out.push(b' '),
            b'%' => {
                let hi = input.get(i + 1).copied().and_then(hex_val);
                let lo = input.get(i + 2).copied().and_then(hex_val);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push(hi << 4 | lo);
                    i += 2;
                } else {
                    out.push(b'%');
                }
            }
            _ => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Finds one cookie value in a `Cookie` header.
pub fn cookie_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.split(';').find_map(|part| {
        let (k, v) = part.trim().split_once('=')?;
        (k == name).then_some(v)
    })
}

/// Fixed-window request counter per network: an IPv4 address, or an IPv6
/// /64 (one host usually holds a whole /64, so counting addresses would give
/// it 2^64 allowances). Bounded: when full, counters of past minutes are
/// dropped; if it is still full of this minute's counters, a network not yet
/// counted is refused until the next minute. Letting it through uncounted
/// would let anyone who fills the table turn throttling off, and clearing
/// the table would reset the counters of whoever filled it.
pub struct Throttle {
    windows: Mutex<HashMap<IpAddr, (u64, u32)>>,
    max_entries: usize,
}

impl Throttle {
    pub fn new(max_entries: usize) -> Self {
        Throttle {
            windows: Mutex::new(HashMap::new()),
            max_entries,
        }
    }

    /// Returns true if this request is within `per_minute`.
    pub fn allow(&self, ip: IpAddr, per_minute: u32, now: u64) -> bool {
        let minute = now / 60;
        let key = crate::conn::ConnLimiter::network(ip);
        let mut map = self.windows.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= self.max_entries && !map.contains_key(&key) {
            map.retain(|_, (m, _)| *m == minute);
            if map.len() >= self.max_entries {
                return false;
            }
        }
        let entry = map.entry(key).or_insert((minute, 0));
        if entry.0 != minute {
            *entry = (minute, 0);
        }
        entry.1 = entry.1.saturating_add(1);
        entry.1 <= per_minute
    }
}

/// DNS through the operating system resolver, off the async threads and
/// with a deadline so a slow resolver cannot stall request handling.
///
/// A lookup past its deadline keeps running on a blocking thread, so the
/// number of lookups in flight is capped: past `max_in_flight`, a lookup is
/// not started and the name counts as not resolved.
pub struct SystemResolver {
    timeout: Duration,
    slots: Slots,
}

impl SystemResolver {
    pub fn new(timeout: Duration, max_in_flight: usize) -> Self {
        SystemResolver { timeout, slots: Slots::new(max_in_flight) }
    }

    async fn run<T: Send + 'static>(&self, lookup: impl FnOnce() -> T + Send + 'static) -> Option<T> {
        let slot = self.slots.take()?;
        let task = tokio::task::spawn_blocking(move || {
            let _slot = slot;
            lookup()
        });
        tokio::time::timeout(self.timeout, task).await.ok()?.ok()
    }
}

/// A counter of lookups in flight. A slot is given back when the lookup
/// ends, not when its caller stops waiting.
struct Slots {
    used: Arc<AtomicUsize>,
    max: usize,
}

struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Slots {
    fn new(max: usize) -> Self {
        Slots { used: Arc::new(AtomicUsize::new(0)), max }
    }

    fn take(&self) -> Option<Slot> {
        self.used
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| (n < self.max).then_some(n + 1))
            .ok()
            .map(|_| Slot(Arc::clone(&self.used)))
    }
}

#[async_trait]
impl Resolver for SystemResolver {
    async fn reverse(&self, ip: IpAddr) -> Vec<String> {
        match self.run(move || dns_lookup::lookup_addr(&ip).ok()).await {
            Some(Some(name)) if name.parse::<IpAddr>().is_err() => vec![name],
            _ => Vec::new(),
        }
    }

    async fn forward(&self, host: &str) -> Vec<IpAddr> {
        let host = host.to_string();
        self.run(move || {
            dns_lookup::lookup_host(&host)
                .map(|it| it.collect::<Vec<_>>())
                .unwrap_or_default()
        })
        .await
        .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_throttle_counts_per_minute_and_per_network() {
        let t = Throttle::new(100);
        let a: IpAddr = "203.0.113.9".parse().unwrap();
        assert!(t.allow(a, 2, 60));
        assert!(t.allow(a, 2, 61));
        assert!(!t.allow(a, 2, 62), "third in the minute");
        assert!(t.allow(a, 2, 120), "a new minute");
        // An IPv6 /64 is one network, whatever the rest of the address.
        let b: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let c: IpAddr = "2001:db8:1:2:ffff::7".parse().unwrap();
        assert!(t.allow(b, 2, 60));
        assert!(t.allow(c, 2, 60));
        assert!(!t.allow(b, 2, 60), "the same /64");
        assert!(t.allow("2001:db8:1:3::1".parse().unwrap(), 2, 60), "another /64");
    }

    #[test]
    fn a_full_throttle_keeps_this_minutes_counters() {
        let t = Throttle::new(2);
        let a: IpAddr = "203.0.113.1".parse().unwrap();
        assert!(t.allow(a, 1, 60));
        assert!(t.allow("203.0.113.2".parse().unwrap(), 1, 60));
        // Full: a third network is refused, not let through uncounted...
        assert!(!t.allow("203.0.113.3".parse().unwrap(), 1, 60));
        // ...and the first is still over its allowance (the table was not
        // cleared).
        assert!(!t.allow(a, 1, 61));
        // Next minute, old counters make room.
        assert!(t.allow("203.0.113.3".parse().unwrap(), 1, 125));
    }

    #[test]
    fn lookups_in_flight_are_capped() {
        let slots = Slots::new(2);
        let a = slots.take().unwrap();
        let _b = slots.take().unwrap();
        assert!(slots.take().is_none(), "over the cap");
        drop(a);
        assert!(slots.take().is_some(), "a finished lookup gives its slot back");
    }

    #[test]
    fn form_decoding() {
        let f = parse_form(b"challenge=abc.def&counter=42&return_to=%2Fa%3Fb%3D1%26c%3D2+x");
        assert_eq!(f["challenge"], "abc.def");
        assert_eq!(f["counter"], "42");
        assert_eq!(f["return_to"], "/a?b=1&c=2 x");
    }

    #[test]
    fn form_decoding_survives_garbage() {
        let f = parse_form(b"a=%&b=%zz&c=%4&&=x&d&a=second&\xff=\xfe");
        assert_eq!(f["a"], "%");
        assert_eq!(f["b"], "%zz");
        assert_eq!(f["c"], "%4");
        assert_eq!(f["d"], "");
        assert!(parse_form(b"").is_empty());
    }

    #[test]
    fn cookie_lookup() {
        let h = "a=1; __Host-veritell=tok.en; b=2";
        assert_eq!(cookie_value(h, "__Host-veritell"), Some("tok.en"));
        assert_eq!(cookie_value(h, "veritell"), None);
        assert_eq!(cookie_value("", "__Host-veritell"), None);
        assert_eq!(
            cookie_value("x__Host-veritell=evil; __Host-veritell=good", "__Host-veritell"),
            Some("good")
        );
        // The known-person mark shares the prefix but is another cookie.
        let both = "__Host-veritell-known=p01.ab; __Host-veritell=tok";
        assert_eq!(cookie_value(both, "__Host-veritell"), Some("tok"));
        assert_eq!(cookie_value("__Host-veritell-known=p01.ab", "__Host-veritell"), None);
    }

    #[test]
    fn throttle_window() {
        let t = Throttle::new(10);
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        assert!(t.allow(ip, 2, 120));
        assert!(t.allow(ip, 2, 130));
        assert!(!t.allow(ip, 2, 140));
        // Next minute resets.
        assert!(t.allow(ip, 2, 180));
    }
}
