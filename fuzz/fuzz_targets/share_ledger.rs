#![no_main]
// Opt-in sharing, the sender's side: a sequence of operations on one
// `veritell_share::Ledger`, checked against a reference model of the
// documented policy and against the privacy rule from a plain log; then
// what it exports goes through the file format, a signed bundle and the
// receiver's `Imported` lookup.
//
// Input: the first byte is the configuration: `min_networks` 5 + (bits 0
// and 1), `max_fingerprints` 1 + (bits 2 to 4). The second byte is
// `ttl_secs` minus one. When the top three bits of the first byte are all
// set, the rest is a raw configuration instead (u16 min_networks, u32
// max_fingerprints, u8 ttl_secs) and only `Ledger::new` is checked. Then
// each operation is a tag byte and its argument bytes:
//
//   0 f n c d  record fingerprint f (8 of them) from network n (16 of
//              them) as class c (all six), at the clock moved by d
//   1 d        export at the clock moved by d
//   2          tracked()
//   3 d        the clock moves by d
//
// `d` below 0x80 moves the clock forward by d seconds; from 0x80 it moves
// it back by d - 0x80 (a caller's clock may go back; the ledger keeps the
// latest).
//
// Properties checked, beyond "does not panic":
// - `Ledger::new` refuses exactly the documented configurations
//   (`TooSmall` before `TooLarge`), and every error has a message;
// - every export and tracked() equal the model's; tracked() never exceeds
//   `max_fingerprints`; a record with a class other than automated or
//   malicious changes nothing;
// - privacy, from the log alone: an exported fingerprint was recorded from
//   at least `min_networks` different networks within `ttl_secs` of the
//   export, and exported as malicious only if it was recorded so; exports
//   are sorted by hash and hold only those two classes;
// - the last export survives `encode`/`decode` and `seal_bundle`/`open_bundle`;
//   `Imported` built from it detects exactly the exported fingerprints,
//   with the documented id, layer, penalty, no class hint and the class
//   in its detail, and never names the hash; another secret detects none of them.
use std::collections::HashMap;
use veritell_core::{Class, Layer};
use veritell_share::{
    decode, encode, open_bundle, seal_bundle, Config, ConfigError, Entry, Imported, Ledger, ShareKey, DETECTION_ID,
    HASH_BYTES, MAX_ENTRIES, MIN_NETWORKS_FLOOR, MIN_SECRET_BYTES, PENALTY,
};

const START: u64 = 1_800_000_000;
const SECRET: &[u8; 32] = b"fuzz share secret, 32 bytes long";
const SEED: [u8; 32] = [0x5a; 32];
const CLASSES: [Class; 6] =
    [Class::Human, Class::VerifiedBot, Class::SignedAgent, Class::UnverifiedAgent, Class::Automated, Class::Malicious];

fn severity(c: Class) -> u8 {
    match c {
        Class::Malicious => 2,
        Class::Automated => 1,
        _ => 0,
    }
}

fn fingerprint(i: usize) -> String {
    format!("t13d1516h2_8daaf6152771_{i}")
}

struct Slot {
    class: Class,
    last: u64,
    networks: Vec<([u8; 8], u64)>,
}

/// The policy `Ledger` documents, written plainly.
struct Model {
    min: usize,
    max: usize,
    ttl: u64,
    latest: u64,
    purged_at: Option<u64>,
    slots: HashMap<[u8; HASH_BYTES], Slot>,
}

impl Model {
    fn advance(&mut self, now: u64) -> u64 {
        self.latest = self.latest.max(now);
        self.latest
    }

    fn record(&mut self, hash: [u8; HASH_BYTES], network: [u8; 8], class: Class, now: u64) {
        if severity(class) == 0 {
            return;
        }
        let now = self.advance(now);
        let (ttl, min) = (self.ttl, self.min);
        if let Some(s) = self.slots.get_mut(&hash) {
            if now - s.last > ttl {
                s.networks.clear();
                s.class = class;
            } else if severity(class) > severity(s.class) {
                s.class = class;
            }
            s.last = now;
            s.networks.retain(|&(_, t)| now - t <= ttl);
            if let Some(n) = s.networks.iter_mut().find(|(n, _)| *n == network) {
                n.1 = now;
            } else if s.networks.len() < min {
                s.networks.push((network, now));
            } else if let Some(oldest) = s.networks.iter_mut().min_by_key(|(_, t)| *t) {
                *oldest = (network, now);
            }
            return;
        }
        if self.slots.len() >= self.max {
            if self.purged_at != Some(now) {
                self.purged_at = Some(now);
                self.slots.retain(|_, s| now - s.last <= ttl);
            }
            if self.slots.len() >= self.max {
                return;
            }
        }
        self.slots.insert(hash, Slot { class, last: now, networks: vec![(network, now)] });
    }

    fn export(&mut self, now: u64) -> Vec<Entry> {
        let now = self.advance(now);
        let mut out: Vec<Entry> = self
            .slots
            .iter()
            .filter(|(_, s)| {
                now - s.last <= self.ttl && s.networks.iter().filter(|&&(_, t)| now - t <= self.ttl).count() >= self.min
            })
            .map(|(h, s)| Entry { hash: *h, class: s.class })
            .collect();
        out.sort_by_key(|e| e.hash);
        out
    }
}

fn expected_config(c: &Config) -> Result<(), ConfigError> {
    if c.min_networks < MIN_NETWORKS_FLOOR || c.max_fingerprints == 0 || c.ttl_secs == 0 {
        Err(ConfigError::TooSmall)
    } else if c.min_networks > 1000 || c.max_fingerprints > MAX_ENTRIES {
        Err(ConfigError::TooLarge)
    } else {
        Ok(())
    }
}

fn key() -> ShareKey {
    ShareKey::new(SECRET).expect("a 32-byte secret")
}

/// What the receiver does with an export.
fn receive(entries: &[Entry], hashes: &[[u8; HASH_BYTES]], now: u64) {
    let file = encode(entries);
    assert_eq!(decode(&file).as_deref(), Ok(entries), "an export does not survive the file format");
    let bundle = seal_bundle(entries, 7, now - 10, now + 10, &SEED).expect("an export does not seal");
    let opened = open_bundle(&bundle, &[veritell_feed::public_key(&SEED)], now, 7);
    assert_eq!(opened.as_ref().map(|(v, e)| (*v, e.as_slice())), Ok((7, entries)), "an export does not open");

    let imported = Imported::new(entries);
    assert_eq!((imported.len(), imported.is_empty()), (entries.len(), entries.is_empty()));
    let other = ShareKey::new(&[7u8; 40]).expect("a 40-byte secret");
    for (i, hash) in hashes.iter().enumerate() {
        let fp = fingerprint(i);
        let listed = entries.iter().find(|e| e.hash == *hash);
        let found = imported.detection(&key(), &fp);
        assert_eq!(found.is_some(), listed.is_some(), "{fp}: detected {found:?}, listed {listed:?}");
        if let (Some(d), Some(e)) = (found, listed) {
            assert_eq!((d.id.as_str(), d.layer, d.penalty, d.class_hint), (DETECTION_ID, Layer::Population, PENALTY, None));
            assert!(d.detail.contains(e.class.as_str()), "detail {:?} does not name {:?}", d.detail, e.class);
            let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
            assert!(!d.detail.contains(&hex) && !d.detail.contains(&fp), "detail names the fingerprint");
        }
        assert!(imported.detection(&other, &fp).is_none(), "{fp} detected under another secret");
    }
    assert!(Imported::empty().detection(&key(), &fingerprint(0)).is_none());
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    assert!(ShareKey::new(&SECRET[..MIN_SECRET_BYTES - 1]).is_none(), "a short secret makes a key");
    assert_eq!(format!("{:?}", key()), "ShareKey(..)");
    let [c, t, ops @ ..] = data else { return };

    if c & 0xE0 == 0xE0 {
        let [a, b, m0, m1, m2, m3, ttl, ..] = ops else { return };
        let config = Config {
            min_networks: u32::from(u16::from_be_bytes([*a, *b])),
            max_fingerprints: u32::from_be_bytes([*m0, *m1, *m2, *m3]) as usize,
            ttl_secs: u64::from(*ttl),
        };
        let got = Ledger::new(key(), config.clone()).err();
        assert_eq!(got, expected_config(&config).err(), "{config:?}");
        if let Some(e) = got {
            assert!(!e.to_string().is_empty(), "empty error message");
        }
        return;
    }
    let config = Config {
        min_networks: MIN_NETWORKS_FLOOR + u32::from(c & 3),
        max_fingerprints: 1 + usize::from(c >> 2 & 7),
        ttl_secs: 1 + u64::from(*t),
    };
    let ledger = Ledger::new(key(), config.clone()).expect("a valid configuration is refused");
    let mut model = Model {
        min: config.min_networks as usize,
        max: config.max_fingerprints,
        ttl: config.ttl_secs,
        latest: 0,
        purged_at: None,
        slots: HashMap::new(),
    };
    let hashes: Vec<[u8; HASH_BYTES]> = (0..8).map(|i| key().hash(&fingerprint(i))).collect();
    // (fingerprint, network, time used, class) of every automated or
    // malicious record.
    let mut log: Vec<(usize, [u8; 8], u64, Class)> = Vec::new();
    let mut now = START;
    let step = |now: u64, d: u8| if d < 0x80 { now + u64::from(d) } else { now - u64::from(d - 0x80) };

    let mut last = None;
    let mut rest = ops;
    while let Some((&tag, args)) = rest.split_first() {
        rest = args;
        match tag % 4 {
            0 => {
                let [f, n, k, d, tail @ ..] = rest else { break };
                rest = tail;
                now = step(now, *d);
                let (f, network, class) = (usize::from(*f % 8), [*n % 16; 8], CLASSES[usize::from(*k) % 6]);
                let before = (ledger.tracked(), ledger.export(0));
                ledger.record(&fingerprint(f), network, class, now);
                model.record(hashes[f], network, class, now);
                if severity(class) == 0 {
                    assert_eq!((ledger.tracked(), ledger.export(0)), before, "a {class:?} record changed the ledger");
                } else {
                    log.push((f, network, model.latest, class));
                }
            }
            1 => {
                let [d, tail @ ..] = rest else { break };
                rest = tail;
                now = step(now, *d);
                let got = ledger.export(now);
                assert_eq!(got, model.export(now), "export differs from the model");
                assert!(got.windows(2).all(|w| w[0].hash < w[1].hash), "export not sorted by hash");
                let at = model.latest;
                for e in &got {
                    assert!(severity(e.class) > 0, "exported class {:?}", e.class);
                    let f = hashes.iter().position(|h| *h == e.hash).expect("exported an unknown hash");
                    let mut networks: Vec<[u8; 8]> =
                        log.iter().filter(|r| r.0 == f && at - r.2 <= config.ttl_secs).map(|r| r.1).collect();
                    networks.sort();
                    networks.dedup();
                    assert!(
                        networks.len() >= config.min_networks as usize,
                        "fingerprint {f} exported after {} networks",
                        networks.len()
                    );
                    if e.class == Class::Malicious {
                        assert!(log.iter().any(|r| r.0 == f && r.3 == Class::Malicious), "{f} exported as malicious");
                    }
                }
                last = Some((got, at));
            }
            2 => {}
            _ => {
                let [d, tail @ ..] = rest else { break };
                rest = tail;
                now = step(now, *d);
            }
        }
        let tracked = ledger.tracked();
        assert_eq!(tracked, model.slots.len(), "tracked() differs from the model");
        assert!(tracked <= config.max_fingerprints, "{tracked} tracked over {}", config.max_fingerprints);
    }
    if let Some((entries, at)) = last {
        receive(&entries, &hashes, at);
    }
});
