//! Acceptance tests written by the project lead. DO NOT EDIT.

use veritell_model::*;
use serde_json::{json, Value};

// ---- a reference evaluator, written to be obviously right ----

struct Reference {
    raw: f64,
    bias: f64,
    contributions: Vec<f64>,
}

fn reference(model: &Value, x: &[f32]) -> Reference {
    let n = model["features"].as_array().unwrap().len();
    let base = model["base"].as_f64().unwrap();
    let mut out = Reference { raw: base, bias: base, contributions: vec![0.0; n] };
    for tree in model["trees"].as_array().unwrap() {
        let nodes = tree.as_array().unwrap();
        out.bias += nodes[0]["v"].as_f64().unwrap();
        let mut i = 0usize;
        loop {
            let node = &nodes[i];
            let v = node["v"].as_f64().unwrap();
            let Some(f) = node.get("f") else {
                out.raw += v;
                break;
            };
            let f = f.as_u64().unwrap() as usize;
            let t = node["t"].as_f64().unwrap();
            let value = f64::from(x[f]);
            let next = if value.is_nan() || value < t { &node["l"] } else { &node["r"] };
            let next = next.as_u64().unwrap() as usize;
            out.contributions[f] += nodes[next]["v"].as_f64().unwrap() - v;
            i = next;
        }
    }
    out
}

/// Small deterministic generator, so that the models below are fixed.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn unit(&mut self) -> f64 {
        (self.next() % 2_000_001) as f64 / 1_000_000.0 - 1.0
    }
}

/// A random tree of at most `depth` levels below the root, as a node array
/// in which children always come after their parent.
fn random_tree(rng: &mut Lcg, features: usize, depth: usize) -> Value {
    let mut nodes: Vec<Value> = vec![Value::Null];
    let mut open = vec![(0usize, 0usize)]; // (index, depth)
    while let Some((i, d)) = open.pop() {
        let v = rng.unit();
        if d >= depth || nodes.len() > 900 || rng.next().is_multiple_of(4) {
            nodes[i] = json!({ "v": v });
            continue;
        }
        let (l, r) = (nodes.len(), nodes.len() + 1);
        nodes.push(Value::Null);
        nodes.push(Value::Null);
        nodes[i] = json!({ "f": rng.next() as usize % features, "t": rng.unit() * 3.0, "l": l, "r": r, "v": v });
        open.push((l, d + 1));
        open.push((r, d + 1));
    }
    Value::Array(nodes)
}

fn random_model(seed: u64, features: usize, trees: usize, depth: usize) -> Value {
    let mut rng = Lcg(seed);
    let names: Vec<String> = (0..features).map(|i| format!("f{i}")).collect();
    let trees: Vec<Value> = (0..trees).map(|_| random_tree(&mut rng, features, depth)).collect();
    json!({ "v": 1, "features": names, "base": rng.unit(), "trees": trees })
}

fn load(model: &Value) -> Result<Model, ModelError> {
    Model::from_json(model.to_string().as_bytes())
}

fn tiny() -> Value {
    json!({
        "v": 1, "features": ["a", "b"], "base": -0.25,
        "trees": [
            [ {"f": 0, "t": 0.5, "l": 1, "r": 2, "v": 0.1}, {"v": -0.4}, {"f": 1, "t": 2.0, "l": 3, "r": 4, "v": 0.6}, {"v": 0.2}, {"v": 1.0} ],
            [ {"v": 0.05} ]
        ]
    })
}

/// A tree that is one long right-hand chain: its last leaf is at `depth`.
fn chain(depth: usize) -> Value {
    let mut nodes = Vec::new();
    for d in 0..depth {
        nodes.push(json!({ "f": 0, "t": d as f64, "l": 2 * d + 1, "r": 2 * d + 2, "v": 0.0 }));
        nodes.push(json!({ "v": d as f64 }));
    }
    nodes.push(json!({ "v": 100.0 }));
    Value::Array(nodes)
}

fn close(a: f64, b: f64, eps: f64) -> bool {
    (a - b).abs() <= eps
}

// ---- evaluation ----

#[test]
fn a_small_model_by_hand() {
    let m = load(&tiny()).unwrap();
    assert_eq!(m.features(), ["a", "b"]);
    assert_eq!(m.trees(), 2);

    // a < 0.5: left leaf.
    let e = m.evaluate(&[0.0, 9.0]).unwrap();
    assert!(close(e.raw, -0.25 - 0.4 + 0.05, 1e-12));
    assert!(close(e.bias, -0.25 + 0.1 + 0.05, 1e-12));
    assert!(close(e.contributions[0], -0.5, 1e-12) && e.contributions[1] == 0.0);
    assert!(close(e.probability, 1.0 / (1.0 + (0.6f64).exp()), 1e-12));

    // a >= 0.5 and b >= 2: right, then right.
    let e = m.evaluate(&[0.5, 2.0]).unwrap();
    assert!(close(e.raw, -0.25 + 1.0 + 0.05, 1e-12));
    assert!(close(e.contributions[0], 0.5, 1e-12));
    assert!(close(e.contributions[1], 0.4, 1e-12));
    assert_eq!(e.top(5).iter().map(|t| t.0).collect::<Vec<_>>(), [0, 1]);
    assert_eq!(e.top(1).len(), 1);

    // a >= 0.5 and b < 2.
    let e = m.evaluate(&[7.0, 1.999]).unwrap();
    assert!(close(e.raw, -0.25 + 0.2 + 0.05, 1e-12));
    assert!(close(e.contributions[1], -0.4, 1e-12));
}

#[test]
fn nan_goes_left_and_equal_goes_right() {
    let m = load(&tiny()).unwrap();
    let nan = m.evaluate(&[f32::NAN, f32::NAN]).unwrap();
    assert!(close(nan.raw, -0.25 - 0.4 + 0.05, 1e-12));
    let nan_b = m.evaluate(&[1.0, f32::NAN]).unwrap();
    assert!(close(nan_b.raw, -0.25 + 0.2 + 0.05, 1e-12));
    let inf = m.evaluate(&[f32::INFINITY, f32::NEG_INFINITY]).unwrap();
    assert!(close(inf.raw, -0.25 + 0.2 + 0.05, 1e-12));
}

#[test]
fn matches_the_reference_on_fixed_models_and_inputs() {
    let mut checked = 0;
    for seed in 1..=40u64 {
        let features = 1 + (seed as usize * 7) % 40;
        let model = random_model(seed, features, 1 + (seed as usize * 13) % 60, 1 + seed as usize % MAX_DEPTH);
        let loaded = load(&model).unwrap();
        let mut rng = Lcg(seed ^ 0xabcdef);
        for case in 0..25 {
            let x: Vec<f32> = (0..features)
                .map(|i| if (case + i) % 17 == 0 { f32::NAN } else { (rng.unit() * 4.0) as f32 })
                .collect();
            let want = reference(&model, &x);
            let got = loaded.evaluate(&x).unwrap();
            assert!(close(got.raw, want.raw, 1e-6), "seed {seed} case {case}: {} against {}", got.raw, want.raw);
            assert!(close(got.bias, want.bias, 1e-6));
            assert_eq!(got.contributions.len(), features);
            for (g, w) in got.contributions.iter().zip(&want.contributions) {
                assert!(close(*g, *w, 1e-6));
            }
            // Attributions account for the whole result.
            let total: f64 = got.bias + got.contributions.iter().sum::<f64>();
            assert!(close(total, got.raw, 1e-9), "seed {seed}: {total} against {}", got.raw);
            assert!(close(got.probability, 1.0 / (1.0 + (-want.raw).exp()), 1e-9));
            assert!((0.0..=1.0).contains(&got.probability));
            checked += 1;
        }
    }
    assert_eq!(checked, 1000);
}

#[test]
fn score_is_on_the_gateway_scale() {
    let with_base = |base: f64| {
        let m = load(&json!({ "v": 1, "features": ["a"], "base": base, "trees": [] })).unwrap();
        assert_eq!(m.trees(), 0);
        m.evaluate(&[0.0]).unwrap()
    };
    assert_eq!(with_base(0.0).score(), 50);
    assert_eq!(with_base(-50.0).score(), 99);
    assert_eq!(with_base(50.0).score(), 1);
    assert_eq!(with_base(1e300).score(), 1);
    assert_eq!(with_base(-1e300).score(), 99);
    assert!(with_base(0.0).top(3).is_empty());
    let e = with_base(1.0);
    assert!(close(e.raw, 1.0, 0.0) && close(e.bias, 1.0, 0.0));
}

#[test]
fn top_orders_by_size_then_index() {
    let m = load(&json!({
        "v": 1, "features": ["a", "b", "c", "d"], "base": 0.0,
        "trees": [
            [ {"f": 1, "t": 0.5, "l": 1, "r": 2, "v": 0.0}, {"v": -0.3}, {"v": 0.3} ],
            [ {"f": 3, "t": 0.5, "l": 1, "r": 2, "v": 0.0}, {"v": -0.3}, {"v": 0.3} ],
            [ {"f": 2, "t": 0.5, "l": 1, "r": 2, "v": 0.0}, {"v": -0.9}, {"v": 0.9} ]
        ]
    }))
    .unwrap();
    let e = m.evaluate(&[0.0, 1.0, 0.0, 0.0]).unwrap();
    let top = e.top(10);
    assert_eq!(top.iter().map(|t| t.0).collect::<Vec<_>>(), [2, 1, 3]);
    assert!(close(top[0].1, -0.9, 1e-12) && close(top[1].1, 0.3, 1e-12) && close(top[2].1, -0.3, 1e-12));
    assert_eq!(e.top(2).len(), 2);
    assert!(e.top(0).is_empty());
}

#[test]
fn wrong_vector_length_is_refused() {
    let m = load(&tiny()).unwrap();
    assert!(m.evaluate(&[]).is_none());
    assert!(m.evaluate(&[1.0]).is_none());
    assert!(m.evaluate(&[1.0, 2.0, 3.0]).is_none());
}

#[test]
fn the_builtin_feature_names_make_a_valid_model() {
    let names = FeatureSpec::builtin().unwrap().names();
    let m = load(&json!({ "v": 1, "features": names, "base": 0.0, "trees": [[{"v": 0.5}]] })).unwrap();
    assert_eq!(m.features(), names.as_slice());
    let x = FeatureSpec::builtin().unwrap().vector(&[]);
    assert!(close(m.evaluate(&x).unwrap().raw, 0.5, 1e-12));
}

// ---- limits ----

#[test]
fn models_at_the_limits_load() {
    let m = load(&json!({ "v": 1, "features": ["a"], "base": 0.0, "trees": [chain(MAX_DEPTH)] })).unwrap();
    assert!(close(m.evaluate(&[1e9]).unwrap().raw, 100.0, 1e-12));
    assert!(close(m.evaluate(&[3.5]).unwrap().raw, 4.0, 1e-12));

    let many: Vec<Value> = (0..MAX_TREES).map(|_| json!([{"v": 0.001}])).collect();
    let m = load(&json!({ "v": 1, "features": ["a"], "base": 0.0, "trees": many })).unwrap();
    assert!(close(m.evaluate(&[0.0]).unwrap().raw, 0.512, 1e-9));

    let names: Vec<String> = (0..MAX_FEATURES).map(|i| format!("f{i}")).collect();
    assert!(load(&json!({ "v": 1, "features": names, "base": 0.0, "trees": [] })).is_ok());
    let long = "n".repeat(MAX_NAME_BYTES);
    assert!(load(&json!({ "v": 1, "features": [long], "base": 0.0, "trees": [] })).is_ok());

    // MAX_NODES nodes in one tree: a full binary tree of depth 9.
    let mut rng = Lcg(5);
    let mut nodes: Vec<Value> = Vec::new();
    for i in 0..MAX_NODES {
        if 2 * i + 2 < MAX_NODES {
            nodes.push(json!({ "f": 0, "t": rng.unit(), "l": 2 * i + 1, "r": 2 * i + 2, "v": rng.unit() }));
        } else {
            nodes.push(json!({ "v": rng.unit() }));
        }
    }
    assert!(load(&json!({ "v": 1, "features": ["a"], "base": 0.0, "trees": [nodes] })).is_ok());
}

#[test]
fn models_over_the_limits_are_refused() {
    let over = |m: Value| assert_eq!(load(&m).err(), Some(ModelError::Limits), "{}", &m.to_string()[..60.min(m.to_string().len())]);
    over(json!({ "v": 1, "features": ["a"], "base": 0.0, "trees": [chain(MAX_DEPTH + 1)] }));
    let many: Vec<Value> = (0..=MAX_TREES).map(|_| json!([{"v": 0.0}])).collect();
    over(json!({ "v": 1, "features": ["a"], "base": 0.0, "trees": many }));
    let names: Vec<String> = (0..=MAX_FEATURES).map(|i| format!("f{i}")).collect();
    over(json!({ "v": 1, "features": names, "base": 0.0, "trees": [] }));
    over(json!({ "v": 1, "features": ["n".repeat(MAX_NAME_BYTES + 1)], "base": 0.0, "trees": [] }));
    over(json!({ "v": 1, "features": [""], "base": 0.0, "trees": [] }));
    let nodes: Vec<Value> = (0..=MAX_NODES).map(|_| json!({"v": 0.0})).collect();
    over(json!({ "v": 1, "features": ["a"], "base": 0.0, "trees": [nodes] }));
}

#[test]
fn oversized_file_is_refused_before_parsing() {
    let mut body = tiny().to_string().into_bytes();
    body.resize(MAX_MODEL_BYTES + 1, b' ');
    assert_eq!(Model::from_json(&body).err(), Some(ModelError::TooLarge));
    body.truncate(MAX_MODEL_BYTES);
    assert!(Model::from_json(&body).is_ok());
}

// ---- structure ----

#[test]
fn cycles_and_bad_indices_are_refused() {
    let bad = |trees: Value| {
        let m = json!({ "v": 1, "features": ["a", "b"], "base": 0.0, "trees": trees });
        assert_eq!(load(&m).err(), Some(ModelError::Structure), "{trees}");
    };
    // A node that is its own child, and a two-node loop.
    bad(json!([[ {"f": 0, "t": 0.0, "l": 0, "r": 1, "v": 0.0}, {"v": 0.0} ]]));
    bad(json!([[ {"f": 0, "t": 0.0, "l": 1, "r": 2, "v": 0.0}, {"f": 0, "t": 0.0, "l": 0, "r": 2, "v": 0.0}, {"v": 0.0} ]]));
    // A child that points backwards without making a loop is refused too.
    bad(json!([[ {"f": 0, "t": 0.0, "l": 1, "r": 2, "v": 0.0}, {"v": 0.0}, {"f": 0, "t": 0.0, "l": 1, "r": 3, "v": 0.0}, {"v": 0.0} ]]));
    // Past the end.
    bad(json!([[ {"f": 0, "t": 0.0, "l": 1, "r": 2, "v": 0.0}, {"v": 0.0} ]]));
    bad(json!([[ {"f": 0, "t": 0.0, "l": 1, "r": 4000000000u64, "v": 0.0}, {"v": 0.0} ]]));
    // Feature index past the end.
    bad(json!([[ {"f": 2, "t": 0.0, "l": 1, "r": 2, "v": 0.0}, {"v": 0.0}, {"v": 0.0} ]]));
    // A tree with no nodes.
    bad(json!([[]]));
    bad(json!([[{"v": 1.0}], []]));
    // A feature name used twice.
    let twice = json!({ "v": 1, "features": ["a", "a"], "base": 0.0, "trees": [] });
    assert_eq!(load(&twice).err(), Some(ModelError::Structure));
}

#[test]
fn malformed_files_are_refused() {
    for body in [&b""[..], b"null", b"[]", b"{}", b"\xff", b"{\"v\":1", b"{\"v\":1,\"features\":[],\"base\":0}"] {
        assert_eq!(Model::from_json(body).err(), Some(ModelError::Malformed), "{body:?}");
    }
    let bad = |change: fn(&mut Value)| {
        let mut m = tiny();
        change(&mut m);
        assert_eq!(load(&m).err(), Some(ModelError::Malformed), "{m}");
    };
    bad(|m| m["extra"] = json!(1));
    bad(|m| m["base"] = json!("0"));
    bad(|m| m["base"] = Value::Null);
    bad(|m| m["features"] = json!([1, 2]));
    bad(|m| m["trees"] = json!({}));
    bad(|m| m["trees"][0][1] = json!({}));
    bad(|m| m["trees"][0][1] = json!({"v": 0.1, "f": 0}));
    bad(|m| m["trees"][0][1] = json!({"v": 0.1, "x": 0}));
    bad(|m| m["trees"][0][0] = json!({"f": 0, "t": 0.5, "l": 1, "r": 2}));
    bad(|m| m["trees"][0][0] = json!({"f": 0, "t": 0.5, "l": 1, "r": 2, "v": 0.1, "w": 1}));
    bad(|m| m["trees"][0][0]["l"] = json!(-1));
    bad(|m| m["trees"][0][0]["l"] = json!(1.5));
    bad(|m| m["trees"][0][0]["f"] = json!(-1));
    bad(|m| m["trees"][0][0]["t"] = json!("x"));
    bad(|m| m["trees"][0][1]["v"] = Value::Null);
    // Numbers that overflow a double are not finite.
    let huge = tiny().to_string().replace("-0.25", "1e999");
    assert_eq!(Model::from_json(huge.as_bytes()).err(), Some(ModelError::Malformed));
    let huge = tiny().to_string().replace("0.6", "-1e999");
    assert_eq!(Model::from_json(huge.as_bytes()).err(), Some(ModelError::Malformed));
}

#[test]
fn version_is_checked_before_limits_and_structure() {
    let mut m = tiny();
    m["v"] = json!(2);
    assert_eq!(load(&m).err(), Some(ModelError::Version));
    m["trees"] = json!([[]]);
    assert_eq!(load(&m).err(), Some(ModelError::Version));
    // Limits before structure.
    let both = json!({ "v": 1, "features": ["a", "a"], "base": 0.0, "trees": [chain(MAX_DEPTH + 1)] });
    assert_eq!(load(&both).err(), Some(ModelError::Limits));
}

// ---- hostile input and cost ----

#[test]
fn hostile_files_never_panic() {
    let base = random_model(7, 5, 6, 4).to_string().into_bytes();
    for cut in (0..base.len()).step_by(3) {
        let _ = Model::from_json(&base[..cut]);
    }
    let mut rng = Lcg(11);
    for _ in 0..3000 {
        let mut flipped = base.clone();
        let at = rng.next() as usize % flipped.len();
        flipped[at] = b"0123456789{}[],:\"-.e"[rng.next() as usize % 20];
        if let Ok(m) = Model::from_json(&flipped) {
            // Whatever loaded must evaluate without trouble.
            let x = vec![0.5f32; m.features().len()];
            let e = m.evaluate(&x).unwrap();
            let _ = (e.score(), e.top(3));
        }
    }
    // Deep nesting must not overflow the stack.
    let deep = format!("{}{}", "[".repeat(200_000), "]".repeat(200_000));
    assert!(Model::from_json(deep.as_bytes()).is_err());
    let deep = format!("{{\"v\":1,\"features\":[],\"base\":0,\"trees\":{}{}}}", "[".repeat(100_000), "]".repeat(100_000));
    assert!(Model::from_json(deep.as_bytes()).is_err());
}

#[test]
fn the_largest_model_evaluates_quickly() {
    // MAX_TREES trees, each a chain of MAX_DEPTH: the most steps an evaluation can take.
    let trees: Vec<Value> = (0..MAX_TREES).map(|_| chain(MAX_DEPTH)).collect();
    let m = load(&json!({ "v": 1, "features": ["a"], "base": 0.0, "trees": trees })).unwrap();
    let start = std::time::Instant::now();
    let mut sum = 0.0;
    for i in 0..2_000 {
        sum += m.evaluate(&[1e9 + i as f32]).unwrap().raw;
    }
    let per_call = start.elapsed() / 2_000;
    assert!(close(sum, 2_000.0 * 100.0 * MAX_TREES as f64, 1e-3));
    // About 5,000 steps. Generous enough for a debug build on a busy machine.
    assert!(per_call < std::time::Duration::from_millis(2), "{per_call:?} per evaluation");
}
