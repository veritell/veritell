//! Runs the shipped analysis over a captured report and prints the findings.
//!
//!   cargo run -q -p veritell-probe --example check_report -- report.json blink|gecko|webkit|none

use veritell_probe::{analyze, parse_report, parse_truth, Claimed, Engine};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(path) = args.first() else {
        eprintln!("usage: check_report <report.json> [blink|gecko|webkit|none]");
        std::process::exit(2);
    };
    let engine = match args.get(1).map(String::as_str) {
        Some("blink") => Some(Engine::Blink),
        Some("gecko") => Some(Engine::Gecko),
        Some("webkit") => Some(Engine::Webkit),
        _ => None,
    };
    let body = std::fs::read(path).unwrap_or_default();
    let report = match parse_report(&body) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    let truth = match parse_truth(include_str!("../data/engine_v1.json")) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    let claimed = Claimed {
        user_agent: None,
        engine,
        os: None,
        mobile: false,
    };
    let found = analyze(&report, &claimed, &truth);
    if found.is_empty() {
        println!("clean");
    }
    for d in found {
        println!("{} ({}): {}", d.id, d.penalty, d.detail);
    }
}
