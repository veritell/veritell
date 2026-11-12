//! Loading, validating and evaluating a model. See the crate documentation
//! for the file format and for what must be refused.

use std::collections::HashSet;

use serde::Deserialize;

use crate::{
    Evaluation, ModelError, MAX_DEPTH, MAX_FEATURES, MAX_MODEL_BYTES, MAX_NAME_BYTES, MAX_NODES,
    MAX_TREES,
};

/// The file as written: shape only, nothing checked beyond types.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawModel {
    v: serde_json::Number,
    features: Vec<String>,
    base: f64,
    trees: Vec<Vec<RawNode>>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawNode {
    Split(RawSplit),
    Leaf(RawLeaf),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSplit {
    f: u64,
    t: f64,
    l: u64,
    r: u64,
    v: f64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLeaf {
    v: f64,
}

/// Marks a leaf in `Node::feature`.
const LEAF: u32 = u32::MAX;

/// One node of the flattened ensemble. Child indices are absolute positions
/// in `Model::nodes`.
#[derive(Clone, Copy, Debug)]
struct Node {
    feature: u32,
    left: u32,
    right: u32,
    threshold: f64,
    value: f64,
}

/// A validated model. Evaluation cannot fail for structural reasons and
/// takes at most `MAX_TREES * MAX_DEPTH` steps.
///
/// All trees live in one flat array; `roots` holds the position of each
/// tree's root in it.
#[derive(Clone, Debug)]
pub struct Model {
    features: Vec<String>,
    base: f64,
    roots: Vec<u32>,
    nodes: Vec<Node>,
}

fn index(raw: u64, len: usize) -> Option<usize> {
    usize::try_from(raw).ok().filter(|i| *i < len)
}

impl Model {
    pub fn from_json(bytes: &[u8]) -> Result<Model, ModelError> {
        if bytes.len() > MAX_MODEL_BYTES {
            return Err(ModelError::TooLarge);
        }
        let raw: RawModel = serde_json::from_slice(bytes).map_err(|_| ModelError::Malformed)?;
        if raw.v.as_u64() != Some(1) {
            return Err(ModelError::Version);
        }

        // Limits.
        if raw.features.len() > MAX_FEATURES || raw.trees.len() > MAX_TREES {
            return Err(ModelError::Limits);
        }
        if raw.features.iter().any(|n| n.is_empty() || n.len() > MAX_NAME_BYTES) {
            return Err(ModelError::Limits);
        }
        for tree in &raw.trees {
            if tree.len() > MAX_NODES {
                return Err(ModelError::Limits);
            }
            if leaf_too_deep(tree) {
                return Err(ModelError::Limits);
            }
        }

        // Structure.
        let mut seen = HashSet::new();
        if !raw.features.iter().all(|n| seen.insert(n.as_str())) {
            return Err(ModelError::Structure);
        }
        let mut roots = Vec::with_capacity(raw.trees.len());
        let mut nodes: Vec<Node> = Vec::new();
        for tree in &raw.trees {
            if tree.is_empty() {
                return Err(ModelError::Structure);
            }
            let start = nodes.len();
            roots.push(u32::try_from(start).map_err(|_| ModelError::Limits)?);
            for (i, node) in tree.iter().enumerate() {
                nodes.push(match node {
                    RawNode::Leaf(leaf) => Node {
                        feature: LEAF,
                        left: 0,
                        right: 0,
                        threshold: 0.0,
                        value: leaf.v,
                    },
                    RawNode::Split(s) => {
                        let child = |c: u64| {
                            index(c, tree.len())
                                .filter(|c| *c > i)
                                .and_then(|c| u32::try_from(start.checked_add(c)?).ok())
                        };
                        let feature = index(s.f, raw.features.len())
                            .and_then(|f| u32::try_from(f).ok())
                            .ok_or(ModelError::Structure)?;
                        Node {
                            feature,
                            left: child(s.l).ok_or(ModelError::Structure)?,
                            right: child(s.r).ok_or(ModelError::Structure)?,
                            threshold: s.t,
                            value: s.v,
                        }
                    }
                });
            }
        }
        Ok(Model { features: raw.features, base: raw.base, roots, nodes })
    }

    /// Feature names, in the order `evaluate` expects values.
    pub fn features(&self) -> &[String] {
        &self.features
    }

    pub fn trees(&self) -> usize {
        self.roots.len()
    }

    /// `None` when `x` does not have exactly one value per feature.
    pub fn evaluate(&self, x: &[f32]) -> Option<Evaluation> {
        if x.len() != self.features.len() {
            return None;
        }
        let mut raw = self.base;
        let mut bias = self.base;
        let mut contributions = vec![0.0f64; self.features.len()];
        for root in &self.roots {
            let mut at = usize::try_from(*root).ok()?;
            let mut node = *self.nodes.get(at)?;
            bias += node.value;
            let mut done = false;
            for _ in 0..=MAX_DEPTH {
                if node.feature == LEAF {
                    raw += node.value;
                    done = true;
                    break;
                }
                let f = usize::try_from(node.feature).ok()?;
                let value = f64::from(*x.get(f)?);
                let next = if value.is_nan() || value < node.threshold { node.left } else { node.right };
                at = usize::try_from(next).ok()?;
                let child = *self.nodes.get(at)?;
                *contributions.get_mut(f)? += child.value - node.value;
                node = child;
            }
            if !done {
                return None;
            }
        }
        let p = 1.0 / (1.0 + (-raw).exp());
        let probability = if p.is_nan() { 0.5 } else { p.clamp(0.0, 1.0) };
        Some(Evaluation { raw, probability, bias, contributions })
    }
}

/// True when a node reachable from the root through valid child links is a
/// leaf deeper than `MAX_DEPTH`. Links that are not strictly forward or are
/// out of range are ignored here (they are `Structure` errors, checked
/// later), and nodes no parent reaches are not considered.
fn leaf_too_deep(tree: &[RawNode]) -> bool {
    let mut depth: Vec<Option<usize>> = vec![None; tree.len()];
    if let Some(d) = depth.first_mut() {
        *d = Some(0);
    }
    for (i, node) in tree.iter().enumerate() {
        let Some(d) = depth.get(i).copied().flatten() else { continue };
        match node {
            RawNode::Leaf(_) => {
                if d > MAX_DEPTH {
                    return true;
                }
            }
            RawNode::Split(s) => {
                for c in [s.l, s.r] {
                    let Some(c) = index(c, tree.len()).filter(|c| *c > i) else { continue };
                    if let Some(slot) = depth.get_mut(c) {
                        let next = d.saturating_add(1);
                        if slot.is_none_or(|old| next > old) {
                            *slot = Some(next);
                        }
                    }
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unreachable_nodes_are_harmless() {
        let m = Model::from_json(
            br#"{"v":1,"features":["a"],"base":0,"trees":[[{"v":1},{"f":0,"t":0,"l":2,"r":2,"v":0},{"v":3}]]}"#,
        )
        .unwrap();
        assert_eq!(m.evaluate(&[0.0]).unwrap().raw, 1.0);
    }
}
