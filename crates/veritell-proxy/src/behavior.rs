//! Behaviour plumbing: the script and report endpoints, and what each
//! client's summaries have shown so far.

use std::collections::HashMap;
use std::sync::Mutex;

use veritell_core::Detection;

pub const SCRIPT_PATH: &str = "/__veritell/behavior.js";
pub const REPORT_PATH: &str = "/__veritell/behavior";
/// Token the gateway replaces with the per-request configuration.
pub const CONFIG_TOKEN: &str = "\"__VERITELL_BEHAVIOR__\"";
/// Summaries accepted per nonce: the script sends at most this many per page.
pub const SUMMARIES_PER_NONCE: u32 = 3;
/// Most behaviour detections remembered for one client.
const MAX_DETECTIONS: usize = 8;

pub const SCRIPT: &str = include_str!("../../../probe/behavior.js");

/// The script with its configuration filled in. `nonce` must already be safe
/// to embed (the probe crate issues only `[A-Za-z0-9_-]`).
pub fn script_with(nonce: &str) -> String {
    let config = serde_json::json!({ "nonce": nonce, "endpoint": REPORT_PATH }).to_string();
    SCRIPT.replacen(CONFIG_TOKEN, &config, 1)
}

/// A behaviour nonce is a probe nonce issued for a different binding, so
/// that neither can be spent at the other's endpoint.
pub fn nonce_binding(binding: &[u8; 16]) -> [u8; 16] {
    let mut out = *binding;
    for byte in out.iter_mut() {
        *byte ^= 0xb5;
    }
    out
}

/// What a client's summaries have shown.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Seen {
    pub detections: Vec<Detection>,
    /// True once any summary showed pointer, touch, key, paste or scroll input.
    pub any_input: bool,
}

struct Record {
    seen: Seen,
    expires_at: u64,
}

/// Behaviour results per client binding. Bounded and in process memory.
/// Evidence accumulates, as in the probe store: a later clean summary does
/// not erase an earlier detection.
pub struct BehaviorStore {
    records: Mutex<HashMap<[u8; 16], Record>>,
    max_entries: usize,
}

impl BehaviorStore {
    pub fn new(max_entries: usize) -> Self {
        BehaviorStore {
            records: Mutex::new(HashMap::new()),
            max_entries: max_entries.max(1),
        }
    }

    /// `None` when this client has sent no summary.
    pub fn get(&self, binding: &[u8; 16], now: u64) -> Option<Seen> {
        let map = self.records.lock().unwrap_or_else(|e| e.into_inner());
        map.get(binding)
            .filter(|r| r.expires_at >= now)
            .map(|r| r.seen.clone())
    }

    pub fn put(
        &self,
        binding: [u8; 16],
        detections: Vec<Detection>,
        has_input: bool,
        expires_at: u64,
        now: u64,
    ) {
        let mut map = self.records.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= self.max_entries && !map.contains_key(&binding) {
            map.retain(|_, r| r.expires_at >= now);
            if map.len() >= self.max_entries {
                // Still full of live records: forget one rather than grow.
                if let Some(key) = map.keys().next().copied() {
                    map.remove(&key);
                }
            }
        }
        let record = map.entry(binding).or_insert(Record {
            seen: Seen::default(),
            expires_at,
        });
        if record.expires_at < now {
            record.seen = Seen::default();
        }
        record.expires_at = expires_at;
        record.seen.any_input |= has_input;
        for d in detections {
            let known = record.seen.detections.iter().any(|k| k.id == d.id);
            if !known && record.seen.detections.len() < MAX_DETECTIONS {
                record.seen.detections.push(d);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veritell_core::Layer;

    fn det(id: &str) -> Detection {
        Detection::new(id, Layer::Behavior, 10, "")
    }

    #[test]
    fn evidence_and_input_accumulate_and_expire() {
        let s = BehaviorStore::new(10);
        let b = [1u8; 16];
        assert!(s.get(&b, 0).is_none());
        s.put(b, vec![], false, 100, 0);
        assert_eq!(s.get(&b, 50), Some(Seen::default()));
        s.put(b, vec![det("a")], true, 100, 10);
        s.put(b, vec![det("a")], false, 100, 20);
        let seen = s.get(&b, 100).unwrap();
        assert_eq!((seen.detections.len(), seen.any_input), (1, true));
        assert!(s.get(&b, 101).is_none());
        s.put(b, vec![], false, 400, 300);
        assert_eq!(s.get(&b, 300), Some(Seen::default()));
    }

    #[test]
    fn store_is_bounded() {
        let s = BehaviorStore::new(3);
        for i in 0..50u8 {
            s.put([i; 16], vec![], false, 100, 0);
        }
        assert!(s.records.lock().unwrap().len() <= 3);
        let many: Vec<Detection> = (0..100).map(|i| det(&format!("d{i}"))).collect();
        s.put([9; 16], many, false, 100, 0);
        assert_eq!(s.get(&[9; 16], 0).unwrap().detections.len(), MAX_DETECTIONS);
    }

    #[test]
    fn behaviour_nonces_use_their_own_binding() {
        let b = [7u8; 16];
        assert_ne!(nonce_binding(&b), b);
        assert_eq!(nonce_binding(&nonce_binding(&b)), b);
    }
}
