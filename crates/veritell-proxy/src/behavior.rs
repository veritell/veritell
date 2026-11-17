//! Behaviour plumbing: the script and report endpoints, and what each
//! client's summaries have shown so far.

use veritell_core::Detection;

use crate::probe::{add_detections, BindingStore};

pub const SCRIPT_PATH: &str = "/__veritell/behavior.js";
pub const REPORT_PATH: &str = "/__veritell/behavior";
/// Token the gateway replaces with the per-request configuration.
pub const CONFIG_TOKEN: &str = "\"__VERITELL_BEHAVIOR__\"";
/// Summaries accepted per nonce: the script sends at most this many per page.
pub const SUMMARIES_PER_NONCE: u32 = 3;

/// Why a behaviour summary was refused; [`Refusal::as_str`] is the event
/// outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    TooLarge,
    Malformed,
    NonceExpired,
    NonceOtherClient,
    NonceInvalid,
    NonceSpent,
    StoreFull,
}

impl Refusal {
    #[cfg(test)]
    pub const ALL: [Refusal; 7] = [
        Refusal::TooLarge,
        Refusal::Malformed,
        Refusal::NonceExpired,
        Refusal::NonceOtherClient,
        Refusal::NonceInvalid,
        Refusal::NonceSpent,
        Refusal::StoreFull,
    ];

    /// The event outcome.
    pub fn as_str(self) -> &'static str {
        match self {
            Refusal::TooLarge => "behavior_too_large",
            Refusal::Malformed => "behavior_malformed",
            Refusal::NonceExpired => "behavior_nonce_expired",
            Refusal::NonceOtherClient => "behavior_nonce_other_client",
            Refusal::NonceInvalid => "behavior_nonce_invalid",
            Refusal::NonceSpent => "behavior_nonce_spent",
            Refusal::StoreFull => "behavior_store_full",
        }
    }

    /// Whether it counts as a strike against the client: an expired nonce is
    /// what a page left open overnight sends, and a full store is not the
    /// client's doing.
    pub fn strikes(self) -> bool {
        !matches!(
            self,
            Refusal::NonceExpired | Refusal::StoreFull | Refusal::TooLarge
        )
    }
}
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

/// Behaviour results per client binding, kept by the same rules as the
/// probe results.
pub type BehaviorStore = BindingStore<Seen>;

impl BehaviorStore {
    pub fn put(
        &self,
        binding: [u8; 16],
        detections: Vec<Detection>,
        has_input: bool,
        expires_at: u64,
        now: u64,
    ) {
        self.update(binding, expires_at, now, |seen| {
            seen.any_input |= has_input;
            add_detections(&mut seen.detections, detections, MAX_DETECTIONS);
        });
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn refusals_keep_their_outcome_names_and_strike_rules() {
        let names: Vec<&str> = Refusal::ALL.iter().map(|r| r.as_str()).collect();
        let mut unique = names.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), names.len(), "one name each");
        assert!(names.iter().all(|n| n.starts_with("behavior_")));
        let no_strike: Vec<&str> = Refusal::ALL
            .iter()
            .filter(|r| !r.strikes())
            .map(|r| r.as_str())
            .collect();
        assert_eq!(
            no_strike,
            [
                "behavior_too_large",
                "behavior_nonce_expired",
                "behavior_store_full"
            ]
        );
    }

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
        assert!(s.len() <= 3);
        let many: Vec<Detection> = (0..100).map(|i| det(&format!("d{i}"))).collect();
        s.put([9; 16], many, false, 100, 0);
        assert_eq!(s.get(&[9; 16], 0).unwrap().detections.len(), MAX_DETECTIONS);
    }

    #[test]
    fn a_full_store_forgets_the_record_nearest_its_end() {
        let s = BehaviorStore::new(2);
        s.put([1; 16], vec![det("a")], true, 500, 10);
        s.put([2; 16], vec![], false, 100, 10);
        s.put([3; 16], vec![], false, 900, 10);
        assert!(s.get(&[2; 16], 10).is_none(), "the one ending soonest went");
        let kept = s.get(&[1; 16], 10).unwrap();
        assert_eq!(
            (kept.detections.len(), kept.any_input),
            (1, true),
            "the others are untouched"
        );
        assert!(s.get(&[3; 16], 10).is_some());
    }

    #[test]
    fn a_shorter_result_does_not_cut_the_record_short() {
        let s = BehaviorStore::new(10);
        let b = [1u8; 16];
        s.put(b, vec![det("a")], false, 500, 0);
        s.put(b, vec![], true, 100, 10);
        let seen = s
            .get(&b, 400)
            .expect("still on record past the shorter expiry");
        assert_eq!((seen.detections.len(), seen.any_input), (1, true));
        assert!(s.get(&b, 501).is_none());
    }

    #[test]
    fn behaviour_nonces_use_their_own_binding() {
        let b = [7u8; 16];
        assert_ne!(nonce_binding(&b), b);
        assert_eq!(nonce_binding(&nonce_binding(&b)), b);
    }
}
