//! The feature vector: what the model is told about a request.
//!
//! FIXED BY THE PROJECT LEAD: DO NOT EDIT. `tools/train/train.py` builds the
//! same vector from the same file, `data/features_v1.json`.
//!
//! For each layer in `layers`, in order: `n_<layer>` (how many detections)
//! and `pen_<layer>` (the sum of their penalties). Then for each id in
//! `ids`, in order: `has_<id>` (1 when a detection with that id is present,
//! else 0). A detection whose id is not listed still counts in its layer.

use veritell_core::{Detection, Layer};
use serde::Deserialize;

pub const BUILTIN_FEATURES: &str = include_str!("../data/features_v1.json");

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureSpec {
    v: u32,
    layers: Vec<String>,
    ids: Vec<String>,
}

fn layer_name(layer: Layer) -> &'static str {
    match layer {
        Layer::Identity => "identity",
        Layer::Network => "network",
        Layer::Client => "client",
        Layer::Behavior => "behavior",
        Layer::Population => "population",
    }
}

impl FeatureSpec {
    /// `None` when the text is not a version 1 feature file.
    pub fn from_json(text: &str) -> Option<FeatureSpec> {
        let spec: FeatureSpec = serde_json::from_str(text).ok()?;
        (spec.v == 1 && spec.layers.len() <= 16 && spec.ids.len() <= 200).then_some(spec)
    }

    /// The feature file compiled into this crate.
    pub fn builtin() -> Option<FeatureSpec> {
        FeatureSpec::from_json(BUILTIN_FEATURES)
    }

    /// Feature names, in vector order.
    pub fn names(&self) -> Vec<String> {
        let mut out = Vec::with_capacity(self.layers.len() * 2 + self.ids.len());
        for layer in &self.layers {
            out.push(format!("n_{layer}"));
            out.push(format!("pen_{layer}"));
        }
        out.extend(self.ids.iter().map(|id| format!("has_{id}")));
        out
    }

    /// The feature vector for one request's detections.
    pub fn vector(&self, detections: &[Detection]) -> Vec<f32> {
        let mut out = Vec::with_capacity(self.layers.len() * 2 + self.ids.len());
        for layer in &self.layers {
            let mine = detections.iter().filter(|d| layer_name(d.layer) == layer);
            let (count, penalty) = mine.fold((0u32, 0u32), |(n, p), d| {
                (n.saturating_add(1), p.saturating_add(u32::from(d.penalty)))
            });
            out.push(count as f32);
            out.push(penalty as f32);
        }
        for id in &self.ids {
            let present = detections.iter().any(|d| &d.id == id);
            out.push(if present { 1.0 } else { 0.0 });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_spec_loads_and_names_are_unique() {
        let spec = FeatureSpec::builtin().unwrap();
        let names = spec.names();
        assert_eq!(names.len(), 5 * 2 + 28);
        assert_eq!(&names[..3], ["n_identity", "pen_identity", "n_network"]);
        let mut sorted = names.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len());
        assert!(names.len() <= crate::MAX_FEATURES);
    }

    #[test]
    fn vector_counts_layers_and_flags_ids() {
        let spec = FeatureSpec::builtin().unwrap();
        let names = spec.names();
        let at = |name: &str| names.iter().position(|n| n == name).unwrap();
        let dets = vec![
            Detection::new("webdriver_true", Layer::Client, 70, ""),
            Detection::new("something_new", Layer::Client, 10, ""),
            Detection::new("behavior_click_centered", Layer::Behavior, 35, ""),
        ];
        let x = spec.vector(&dets);
        assert_eq!(x.len(), names.len());
        assert_eq!((x[at("n_client")], x[at("pen_client")]), (2.0, 80.0));
        assert_eq!((x[at("n_behavior")], x[at("pen_behavior")]), (1.0, 35.0));
        assert_eq!(x[at("has_webdriver_true")], 1.0);
        assert_eq!(x[at("has_behavior_click_centered")], 1.0);
        assert_eq!(x[at("has_ua_headless")], 0.0);
        assert_eq!(x.iter().sum::<f32>(), 2.0 + 80.0 + 1.0 + 35.0 + 2.0);
        assert!(spec.vector(&[]).iter().all(|v| *v == 0.0));
    }

    #[test]
    fn bad_spec_is_refused() {
        assert!(FeatureSpec::from_json("{}").is_none());
        assert!(FeatureSpec::from_json(r#"{"v":2,"layers":[],"ids":[]}"#).is_none());
        assert!(FeatureSpec::from_json(r#"{"v":1,"layers":[],"ids":[],"x":1}"#).is_none());
        assert!(FeatureSpec::from_json(r#"{"v":1,"layers":[],"ids":[]}"#).is_some());
    }
}
