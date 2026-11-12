//! Evaluates a model on feature vectors, for comparing with the trainer.
//!
//!   eval <model.json> < vectors.jsonl
//!
//! Each input line is a JSON array of numbers. Each output line is the raw
//! result and the probability, with 9 decimals, separated by a space.
//! FIXED BY THE PROJECT LEAD: DO NOT EDIT.

use std::io::{BufRead, Write};

fn main() {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: eval <model.json> < vectors.jsonl");
        std::process::exit(2);
    };
    let bytes = std::fs::read(&path).unwrap_or_else(|e| {
        eprintln!("{path}: {e}");
        std::process::exit(2);
    });
    let model = veritell_model::Model::from_json(&bytes).unwrap_or_else(|e| {
        eprintln!("{path}: {e}");
        std::process::exit(1);
    });
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let x: Vec<f32> = serde_json::from_str(&line).unwrap_or_else(|e| {
            eprintln!("bad vector: {e}");
            std::process::exit(1);
        });
        let Some(result) = model.evaluate(&x) else {
            eprintln!("vector has {} values, the model wants {}", x.len(), model.features().len());
            std::process::exit(1);
        };
        let _ = writeln!(out, "{:.9} {:.9}", result.raw, result.probability);
    }
}
