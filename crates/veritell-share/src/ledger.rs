//! Keyed fingerprint hashing and the ledger that counts, per fingerprint, the networks seen within the last `ttl_secs`.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use hmac::{Hmac, Mac};
use veritell_core::Class;
use sha2::Sha256;

use crate::{Config, ConfigError, Entry, HASH_BYTES, MAX_ENTRIES, MIN_NETWORKS_FLOOR, MIN_SECRET_BYTES};

const DOMAIN: &[u8] = b"veritell share fingerprint v1\0";

/// The secret the sharing parties agreed. It never leaves the process and
/// its `Debug` output must not reveal it.
#[derive(Clone)]
pub struct ShareKey {
    mac: Hmac<Sha256>,
}

impl std::fmt::Debug for ShareKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ShareKey(..)")
    }
}

impl ShareKey {
    /// `None` if `secret` is shorter than `MIN_SECRET_BYTES`.
    pub fn new(secret: &[u8]) -> Option<ShareKey> {
        if secret.len() < MIN_SECRET_BYTES {
            return None;
        }
        Hmac::<Sha256>::new_from_slice(secret).ok().map(|mac| ShareKey { mac })
    }

    /// The hash of a fingerprint as defined in the crate documentation.
    /// The whole text is hashed, whatever its length.
    pub fn hash(&self, fingerprint: &str) -> [u8; HASH_BYTES] {
        let mut mac = self.mac.clone();
        mac.update(DOMAIN);
        mac.update(fingerprint.as_bytes());
        let digest = mac.finalize().into_bytes();
        let mut out = [0u8; HASH_BYTES];
        for (o, d) in out.iter_mut().zip(digest.iter()) {
            *o = *d;
        }
        out
    }
}

/// What this install has judged, per fingerprint, and from how many
/// networks. Safe to share across threads: every method takes `&self`.
///
/// Memory: at most `max_fingerprints` entries, each holding the
/// fingerprint's hash (never its text) and at most `min_networks` network
/// identifiers, each with the time it was last seen; a network counts only
/// while seen within `ttl_secs`. Counting stops at `min_networks`: nothing more is needed to
/// decide.
///
/// Time is Unix seconds from the caller. A `now` earlier than the latest
/// seen is treated as the latest seen.
pub struct Ledger {
    key: ShareKey,
    config: Config,
    state: Mutex<State>,
}

struct Slot {
    class: Class,
    last: u64,
    /// At most `min_networks` identifiers, each with the time it was last
    /// seen. Only those seen within `ttl_secs` count.
    networks: Vec<([u8; 8], u64)>,
}

#[derive(Default)]
struct State {
    latest: u64,
    purged_at: Option<u64>,
    slots: HashMap<[u8; HASH_BYTES], Slot>,
}

fn severity(class: Class) -> u8 {
    match class {
        Class::Malicious => 2,
        Class::Automated => 1,
        _ => 0,
    }
}

impl Ledger {
    /// Checks the configuration (see [`ConfigError`]; `TooSmall` is reported
    /// before `TooLarge`).
    pub fn new(key: ShareKey, config: Config) -> Result<Ledger, ConfigError> {
        if config.min_networks < MIN_NETWORKS_FLOOR || config.max_fingerprints == 0 || config.ttl_secs == 0 {
            return Err(ConfigError::TooSmall);
        }
        if config.min_networks > 1000 || config.max_fingerprints > MAX_ENTRIES {
            return Err(ConfigError::TooLarge);
        }
        Ok(Ledger { key, config, state: Mutex::new(State::default()) })
    }

    /// Notes that a request with this fingerprint, from this network, was
    /// judged `class`.
    ///
    /// Only `Class::Automated` and `Class::Malicious` are noted; any other
    /// class changes nothing at all (it does not refresh, add a network or
    /// start an entry). An entry keeps the more severe class it has been
    /// given (`Malicious` over `Automated`) and the time it was last noted.
    ///
    /// When a new fingerprint arrives and the ledger is full, entries not
    /// noted for more than `ttl_secs` are dropped; if it is still full the
    /// new fingerprint is not noted.
    pub fn record(&self, fingerprint: &str, network: [u8; 8], class: Class, now: u64) {
        if severity(class) == 0 {
            return;
        }
        let hash = self.key.hash(fingerprint);
        let mut st = self.lock();
        let now = st.advance(now);
        let ttl = self.config.ttl_secs;
        let min = self.config.min_networks as usize;
        if let Some(slot) = st.slots.get_mut(&hash) {
            if now.saturating_sub(slot.last) > ttl {
                // Forgotten by now: start again.
                slot.networks.clear();
                slot.class = class;
            } else if severity(class) > severity(slot.class) {
                slot.class = class;
            }
            slot.last = now;
            // Records past the window no longer count; drop them.
            slot.networks.retain(|(_, t)| now.saturating_sub(*t) <= ttl);
            if let Some(n) = slot.networks.iter_mut().find(|(n, _)| *n == network) {
                n.1 = now;
            } else if slot.networks.len() < min {
                slot.networks.push((network, now));
            } else if let Some(oldest) = slot.networks.iter_mut().min_by_key(|(_, t)| *t) {
                // Full: the least recently seen network makes room.
                *oldest = (network, now);
            }
            return;
        }
        if st.slots.len() >= self.config.max_fingerprints {
            // At most one sweep per second, so a flood of new fingerprints
            // cannot make every call linear.
            if st.purged_at != Some(now) {
                st.purged_at = Some(now);
                st.slots.retain(|_, s| now.saturating_sub(s.last) <= ttl);
            }
            if st.slots.len() >= self.config.max_fingerprints {
                return;
            }
        }
        st.slots.insert(hash, Slot { class, last: now, networks: vec![(network, now)] });
    }

    /// The entries to share at `now`: every fingerprint noted from at least
    /// `min_networks` different networks, each seen within the last `ttl_secs`,
    /// and last noted no more than `ttl_secs` ago, sorted by hash. Never more than `MAX_ENTRIES`.
    pub fn export(&self, now: u64) -> Vec<Entry> {
        let mut st = self.lock();
        let now = st.advance(now);
        let ttl = self.config.ttl_secs;
        let min = self.config.min_networks as usize;
        let mut out: Vec<Entry> = st
            .slots
            .iter()
            .filter(|(_, s)| {
                now.saturating_sub(s.last) <= ttl
                    && s.networks.iter().filter(|(_, t)| now.saturating_sub(*t) <= ttl).count() >= min
            })
            .map(|(h, s)| Entry { hash: *h, class: s.class })
            .collect();
        out.sort_by_key(|a| a.hash);
        out.truncate(MAX_ENTRIES);
        out
    }

    /// Number of fingerprints remembered right now.
    pub fn tracked(&self) -> usize {
        self.lock().slots.len()
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl State {
    /// Moves the clock forward, never back; returns the time to use.
    fn advance(&mut self, now: u64) -> u64 {
        if now > self.latest {
            self.latest = now;
        }
        self.latest
    }
}
