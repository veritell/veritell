//! Probe plumbing: where analysed reports are kept, and how the request's
//! User-Agent is turned into the claim the report is checked against.

use std::collections::HashMap;
use std::sync::Mutex;

use veritell_core::{Class, Detection, Layer};
use veritell_probe::{Claimed, Engine, Os};
use veritell_ua::{parse_user_agent, UaKind};

/// Script and report endpoints.
pub const SCRIPT_PATH: &str = "/__veritell/probe.js";
pub const REPORT_PATH: &str = "/__veritell/probe";
/// Most client detections remembered for one client.
const MAX_DETECTIONS: usize = 16;

/// The probe template that builds are generated from.
pub const TEMPLATE: &str = include_str!("../../../probe/probe.js");

/// A built probe script with its per-request configuration filled in.
/// `nonce` must already be safe to embed (the probe crate issues only
/// `[A-Za-z0-9_-]`).
pub fn script_with(built: &str, nonce: &str) -> String {
    let config = serde_json::json!({ "nonce": nonce, "endpoint": REPORT_PATH }).to_string();
    built.replacen(veritell_probe_build::CONFIG_TOKEN, &config, 1)
}

/// What the HTTP User-Agent implies about the browser that should have
/// produced a report.
pub fn claimed(user_agent: Option<&str>) -> Claimed<'_> {
    let claim = parse_user_agent(user_agent);
    let engine = match claim.kind {
        UaKind::Browser { engine, .. } => Some(match engine {
            veritell_ua::Engine::Chromium => Engine::Blink,
            veritell_ua::Engine::Gecko => Engine::Gecko,
            veritell_ua::Engine::WebKit => Engine::Webkit,
        }),
        UaKind::Headless => Some(Engine::Blink),
        _ => None,
    };
    let os = match claim.os {
        veritell_ua::Os::Windows => Some(Os::Windows),
        veritell_ua::Os::MacOs => Some(Os::MacOs),
        veritell_ua::Os::Linux => Some(Os::Linux),
        veritell_ua::Os::Android => Some(Os::Android),
        veritell_ua::Os::Ios => Some(Os::Ios),
        veritell_ua::Os::ChromeOs => Some(Os::ChromeOs),
        veritell_ua::Os::Unknown => None,
    };
    Claimed {
        user_agent,
        engine,
        os,
        mobile: claim.mobile,
    }
}

/// Detection id for a report that no copy of the probe script sends.
pub const FORGED: &str = "probe_forged";

/// Why a probe report was refused. Each is recorded as the event's
/// outcome ([`Refusal::as_str`]); what follows for the client depends on the
/// kind, never on the text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    TooLarge,
    BuildUnknown,
    BuildExpired,
    SealInvalid,
    Malformed,
    BuildOrder,
    NonceExpired,
    NonceOtherClient,
    NonceInvalid,
    NonceReused,
    StoreFull,
}

impl Refusal {
    #[cfg(test)]
    pub const ALL: [Refusal; 11] = [
        Refusal::TooLarge, Refusal::BuildUnknown, Refusal::BuildExpired, Refusal::SealInvalid,
        Refusal::Malformed, Refusal::BuildOrder, Refusal::NonceExpired, Refusal::NonceOtherClient,
        Refusal::NonceInvalid, Refusal::NonceReused, Refusal::StoreFull,
    ];

    /// The event outcome.
    pub fn as_str(self) -> &'static str {
        match self {
            Refusal::TooLarge => "probe_too_large",
            Refusal::BuildUnknown => "probe_build_unknown",
            Refusal::BuildExpired => "probe_build_expired",
            Refusal::SealInvalid => "probe_seal_invalid",
            Refusal::Malformed => "probe_malformed",
            Refusal::BuildOrder => "probe_build_order",
            Refusal::NonceExpired => "probe_nonce_expired",
            Refusal::NonceOtherClient => "probe_nonce_other_client",
            Refusal::NonceInvalid => "probe_nonce_invalid",
            Refusal::NonceReused => "probe_nonce_reused",
            Refusal::StoreFull => "probe_store_full",
        }
    }

    /// Refusals that the gateway's own script cannot cause, so the report was
    /// made some other way. Expired nonces and builds, a nonce from another
    /// connection or sent twice, and an unknown build or nonce key (a restart
    /// with a new secret) all happen to real browsers and are not on the list.
    pub fn is_forgery(self) -> bool {
        matches!(self, Refusal::Malformed | Refusal::SealInvalid | Refusal::BuildOrder)
    }

    /// Whether the refusal counts as a strike against the client. A page
    /// left open past its nonce or its build sends an expired one, and a full
    /// store is not the client's doing.
    pub fn strikes(self) -> bool {
        !matches!(self, Refusal::NonceExpired | Refusal::BuildExpired | Refusal::StoreFull | Refusal::TooLarge)
    }
}

/// The nonce named on the outside of a sealed report (`"n"`, see
/// probe/SEALING.md), read without opening it. A report that fails to open
/// still names one: whether it was issued to the sender decides whether the
/// failure counts as evidence about the sender.
pub fn outer_nonce(body: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let nonce = value.get("n")?.as_str()?;
    (nonce.len() <= veritell_probe_build::MAX_NONCE_BYTES).then(|| nonce.to_string())
}

/// The evidence a forged report leaves on the client that sent it.
pub fn forged(why: Refusal) -> Detection {
    Detection::new(
        FORGED,
        Layer::Client,
        50,
        format!("sent a probe report that the probe script did not make ({})", why.as_str()),
    )
    .with_class(Class::Automated)
}

/// Whether the report's `page` object has its keys in the order this build
/// writes them (`Builder::key_order`). A real run of the build cannot do
/// otherwise; a report written without running it, even one sealed
/// correctly, almost always does. `orders` is the build's list; a report
/// that cannot be read here passes (the version 1 parser has its say).
pub fn in_build_order(orders: &[Vec<String>], report_json: &[u8]) -> bool {
    let Some(page) = page_keys(report_json) else { return true };
    orders.iter().all(|order| {
        let written: Vec<&String> = page.iter().filter(|k| order.contains(k)).collect();
        let expected: Vec<&String> = order.iter().filter(|k| page.contains(k)).collect();
        written == expected
    })
}

/// The keys of the report's top-level `page` object, in the order written.
fn page_keys(report_json: &[u8]) -> Option<Vec<String>> {
    use serde::de::{Deserializer, IgnoredAny, MapAccess, Visitor};

    struct Keys(Vec<String>);
    impl<'de> serde::Deserialize<'de> for Keys {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = Keys;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("an object")
                }
                fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Keys, A::Error> {
                    let mut keys = Vec::new();
                    while let Some((key, IgnoredAny)) = map.next_entry::<String, IgnoredAny>()? {
                        keys.push(key);
                    }
                    Ok(Keys(keys))
                }
            }
            d.deserialize_map(V)
        }
    }

    struct Top(Option<Vec<String>>);
    impl<'de> serde::Deserialize<'de> for Top {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = Top;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("an object")
                }
                fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Top, A::Error> {
                    let mut page = None;
                    while let Some(key) = map.next_key::<String>()? {
                        if key == "page" && page.is_none() {
                            page = Some(map.next_value::<Keys>()?.0);
                        } else {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                    Ok(Top(page))
                }
            }
            d.deserialize_map(V)
        }
    }

    serde_json::from_slice::<Top>(report_json).ok()?.0
}

struct Record {
    detections: Vec<Detection>,
    expires_at: u64,
}

/// Analysed probe results per client binding. Bounded and in process memory.
///
/// Evidence accumulates: a later clean report does not erase what an earlier
/// one showed, so a client cannot wash a bad result by sending a forged one.
pub struct ProbeStore {
    records: Mutex<HashMap<[u8; 16], Record>>,
    max_entries: usize,
}

impl ProbeStore {
    pub fn new(max_entries: usize) -> Self {
        ProbeStore {
            records: Mutex::new(HashMap::new()),
            max_entries: max_entries.max(1),
        }
    }

    /// Detections on record for this client, or `None` if it has not reported.
    pub fn get(&self, binding: &[u8; 16], now: u64) -> Option<Vec<Detection>> {
        let map = self.records.lock().unwrap_or_else(|e| e.into_inner());
        map.get(binding)
            .filter(|r| r.expires_at >= now)
            .map(|r| r.detections.clone())
    }

    /// Merges a new result into the record and returns what is now on record.
    pub fn put(
        &self,
        binding: [u8; 16],
        detections: Vec<Detection>,
        expires_at: u64,
        now: u64,
    ) -> Vec<Detection> {
        let mut map = self.records.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= self.max_entries && !map.contains_key(&binding) {
            map.retain(|_, r| r.expires_at >= now);
            if map.len() >= self.max_entries {
                // Still full of live records: forget the one nearest its
                // end rather than grow (an arbitrary one could be a client
                // that reported a second ago, which would then be marked
                // probe_missing for the rest of its token's life).
                if let Some(key) = map.iter().min_by_key(|(_, r)| r.expires_at).map(|(k, _)| *k) {
                    map.remove(&key);
                }
            }
        }
        let record = map.entry(binding).or_insert(Record {
            detections: Vec::new(),
            expires_at,
        });
        if record.expires_at < now {
            record.detections.clear();
        }
        record.expires_at = expires_at;
        for d in detections {
            let known = record.detections.iter().any(|k| k.id == d.id);
            if !known && record.detections.len() < MAX_DETECTIONS {
                record.detections.push(d);
            }
        }
        record.detections.clone()
    }

    /// The live records as JSON, for `--state-dir`: without them a restart
    /// would mark every client holding a token `probe_missing` until its
    /// token expired, although it did run the probe.
    pub fn export(&self, now: u64) -> Vec<u8> {
        let map = self.records.lock().unwrap_or_else(|e| e.into_inner());
        let rows: Vec<serde_json::Value> = map
            .iter()
            .filter(|(_, r)| r.expires_at >= now)
            .map(|(b, r)| {
                serde_json::json!({
                    "b": b.iter().map(|x| format!("{x:02x}")).collect::<String>(),
                    "e": r.expires_at,
                    "d": r.detections,
                })
            })
            .collect();
        serde_json::to_vec(&rows).unwrap_or_default()
    }

    /// Loads what [`ProbeStore::export`] wrote. The whole input is checked
    /// first; expired records are skipped; new records are added while there
    /// is room. Returns how many were loaded.
    pub fn import(&self, bytes: &[u8], now: u64) -> Result<usize, String> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Row {
            b: String,
            e: u64,
            d: Vec<Detection>,
        }
        let rows: Vec<Row> = serde_json::from_slice(bytes).map_err(|e| format!("probe records: {e}"))?;
        let mut parsed = Vec::with_capacity(rows.len());
        for row in rows {
            let b = row.b.as_bytes();
            if b.len() != 32 || row.d.len() > MAX_DETECTIONS {
                return Err("probe records: bad binding or too many detections".into());
            }
            let mut binding = [0u8; 16];
            for (i, slot) in binding.iter_mut().enumerate() {
                let hex = std::str::from_utf8(&b[i * 2..i * 2 + 2]).map_err(|_| "probe records: bad binding")?;
                *slot = u8::from_str_radix(hex, 16).map_err(|_| "probe records: bad binding")?;
            }
            parsed.push((binding, row.e, row.d));
        }
        let mut map = self.records.lock().unwrap_or_else(|e| e.into_inner());
        let mut loaded = 0;
        for (binding, expires_at, detections) in parsed {
            if expires_at < now || (map.len() >= self.max_entries && !map.contains_key(&binding)) {
                continue;
            }
            map.insert(binding, Record { detections, expires_at });
            loaded += 1;
        }
        Ok(loaded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det(id: &str) -> Detection {
        Detection::new(id, Layer::Client, 10, "")
    }

    #[test]
    fn records_survive_an_export_and_import() {
        let a = ProbeStore::new(10);
        a.put([1; 16], vec![det("x")], 1000, 10);
        a.put([2; 16], Vec::new(), 1000, 10);
        a.put([3; 16], vec![det("old")], 20, 10);
        let b = ProbeStore::new(10);
        assert_eq!(b.import(&a.export(10), 30), Ok(2), "the expired one is skipped");
        assert_eq!(b.get(&[1; 16], 30).unwrap().len(), 1);
        assert_eq!(b.get(&[2; 16], 30), Some(Vec::new()), "a clean record is a record");
        assert_eq!(b.get(&[3; 16], 30), None);
        assert!(b.import(b"[{\"b\":\"zz\",\"e\":1,\"d\":[]}]", 0).is_err());
        assert!(b.import(b"not json", 0).is_err());
    }

    #[test]
    fn a_full_store_forgets_the_record_nearest_its_end() {
        let s = ProbeStore::new(2);
        s.put([1; 16], Vec::new(), 500, 10);
        s.put([2; 16], Vec::new(), 100, 10);
        s.put([3; 16], Vec::new(), 900, 10);
        assert!(s.get(&[2; 16], 10).is_none(), "the one ending soonest went");
        assert!(s.get(&[1; 16], 10).is_some());
        assert!(s.get(&[3; 16], 10).is_some());
    }

    #[test]
    fn evidence_accumulates_and_expires() {
        let s = ProbeStore::new(10);
        let b = [1u8; 16];
        assert!(s.get(&b, 0).is_none());
        s.put(b, vec![det("a")], 100, 0);
        assert_eq!(s.get(&b, 50).map(|d| d.len()), Some(1));
        // A clean report afterwards does not erase it.
        let now = s.put(b, vec![], 200, 60);
        assert_eq!(now.len(), 1);
        s.put(b, vec![det("a"), det("b")], 200, 60);
        assert_eq!(s.get(&b, 200).map(|d| d.len()), Some(2));
        assert!(s.get(&b, 201).is_none());
        // After expiry a new report starts a fresh record.
        assert_eq!(s.put(b, vec![], 400, 300).len(), 0);
    }

    #[test]
    fn store_is_bounded() {
        let s = ProbeStore::new(3);
        for i in 0..50u8 {
            s.put([i; 16], vec![], 100, 0);
        }
        assert!(s.records.lock().unwrap().len() <= 3);
        let many: Vec<Detection> = (0..100).map(|i| det(&format!("d{i}"))).collect();
        assert_eq!(s.put([9; 16], many, 100, 0).len(), MAX_DETECTIONS);
    }

    #[test]
    fn page_order_is_checked_against_the_build() {
        let orders = vec![vec!["tz".to_string(), "plugins".into(), "screen".into()], vec!["x".into(), "y".into()]];
        let ok = br#"{"v":1,"page":{"tz":"","window":[0],"plugins":1,"screen":[0],"globals":[]},"main":{"y":1,"x":2}}"#;
        assert!(in_build_order(&orders, ok), "only the page is checked; other keys do not matter");
        let bad = br#"{"v":1,"page":{"plugins":1,"tz":"","screen":[0]}}"#;
        assert!(!in_build_order(&orders, bad));
        // Only the keys present are compared.
        assert!(in_build_order(&orders, br#"{"page":{"tz":"","screen":[0]}}"#));
        assert!(!in_build_order(&orders, br#"{"page":{"screen":[0],"tz":""}}"#));
        // Nothing to compare against, or nothing readable: the check passes.
        assert!(in_build_order(&[], bad));
        assert!(in_build_order(&orders, b"not json"));
        assert!(in_build_order(&orders, br#"{"v":1}"#));
        assert!(in_build_order(&orders, br#"{"page":[1,2]}"#));
        assert_eq!(page_keys(br#"{"a":{"page":{"z":1}},"page":{"b":[{"c":1}],"a":null}}"#), Some(vec!["b".into(), "a".into()]));
    }

    #[test]
    fn only_reports_no_script_makes_are_forgeries() {
        let forgeries: Vec<&str> = Refusal::ALL.iter().filter(|r| r.is_forgery()).map(|r| r.as_str()).collect();
        assert_eq!(forgeries, ["probe_seal_invalid", "probe_malformed", "probe_build_order"]);
        let d = forged(Refusal::Malformed);
        assert_eq!((d.id.as_str(), d.layer), (FORGED, Layer::Client));
        assert!(d.detail.contains("probe_malformed"));
    }

    #[test]
    fn refusals_keep_their_outcome_names_and_strike_rules() {
        let names: Vec<&str> = Refusal::ALL.iter().map(|r| r.as_str()).collect();
        let mut unique = names.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), names.len(), "one name each");
        assert!(names.iter().all(|n| n.starts_with("probe_")));
        let no_strike: Vec<&str> = Refusal::ALL.iter().filter(|r| !r.strikes()).map(|r| r.as_str()).collect();
        assert_eq!(no_strike, ["probe_too_large", "probe_build_expired", "probe_nonce_expired", "probe_store_full"]);
    }

    #[test]
    fn user_agent_claims() {
        let c = claimed(Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"));
        assert_eq!((c.engine, c.os, c.mobile), (Some(Engine::Blink), Some(Os::Windows), false));
        let c = claimed(Some("curl/8.7.1"));
        assert_eq!((c.engine, c.os), (None, None));
        assert_eq!(claimed(None).engine, None);
    }
}
