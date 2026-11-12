//! The model's feature list against the detections the code can raise
//! (audit P2-2). `features_v1.json` is fixed with the model format; rules
//! added since are not in it, and the model cannot see them except through
//! the per-layer counts. This test names that gap exactly: a detection that
//! is neither a feature nor listed below fails it, so the next rule added
//! cannot fall out of the model unnoticed. Closing the gap means a v2
//! feature list and a retrained model (Phase 4, unit 12).

use std::collections::BTreeSet;
use std::path::Path;

/// Detections the code raises that features_v1.json does not list.
const NOT_IN_FEATURES_V1: &[&str] = &[
    "behavior_click_jumped",
    "behavior_keys_metronomic",
    "behavior_untrusted_submit",
    "crawler_unresolved",
    "shared_fp_reported",
    "wba_bad_signature",
    "wba_expired",
    "wba_malformed",
    "wba_replay",
    "wba_unknown_key",
    "wba_write_unbound",
];

fn ids_in(dir: &Path, out: &mut BTreeSet<String>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            ids_in(&path, out);
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        // Code only: unit tests make up ids of their own.
        let code = text.split("#[cfg(test)]").next().unwrap_or("");
        for (marker, quote_after) in [("Detection::new(", true), (": &str = \"", false)] {
            for piece in code.split(marker).skip(1) {
                let rest = if quote_after { piece.trim_start().strip_prefix('"') } else { Some(piece) };
                let Some(rest) = rest else { continue };
                let id: String = rest.chars().take_while(|c| *c != '"').collect();
                let looks_like_an_id = id.len() > 3
                    && id.contains('_')
                    && id.starts_with(|c: char| c.is_ascii_lowercase())
                    && id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
                if looks_like_an_id {
                    out.insert(id);
                }
            }
        }
    }
}

#[test]
fn every_detection_is_a_feature_or_a_known_gap() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut raised = BTreeSet::new();
    for entry in std::fs::read_dir(crates).unwrap() {
        let src = entry.unwrap().path().join("src");
        if src.is_dir() {
            ids_in(&src, &mut raised);
        }
    }
    let spec: serde_json::Value =
        serde_json::from_str(include_str!("../data/features_v1.json")).unwrap();
    let features: BTreeSet<String> =
        spec["ids"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    let known: BTreeSet<String> = NOT_IN_FEATURES_V1.iter().map(|s| s.to_string()).collect();
    // Strings that look like ids but are not detections (event outcomes,
    // policy actions, file kinds) are not features either: keep only what
    // is a feature, a known gap, or carries a detection's layer prefix.
    let detection_prefixes = ["ua_", "tls_", "h2_", "missing_", "probe_", "behavior_", "wba_", "crawler_", "net_", "agg_", "shared_", "bot_", "engine_", "native_", "realm_", "spatial_", "client_", "headless_", "webdriver_", "automation_", "model_"];
    let unexplained: Vec<&String> = raised
        .iter()
        .filter(|id| !features.contains(*id) && !known.contains(*id))
        .filter(|id| detection_prefixes.iter().any(|p| id.starts_with(p)))
        .collect();
    let stale: Vec<&String> = known.iter().filter(|id| features.contains(*id)).collect();
    assert!(unexplained.is_empty(), "detections in no feature list and not listed as a known gap: {unexplained:?}");
    assert!(stale.is_empty(), "listed as a gap but now a feature: {stale:?}");
}
