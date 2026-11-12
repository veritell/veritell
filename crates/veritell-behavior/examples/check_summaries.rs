//! Runs the behaviour rules over recorded summaries.
//!
//!   check_summaries < lab/recordings/human.jsonl
//!
//! Each input line is either a summary or an object with a `summary` field
//! (what `lab/record.mjs` writes; a missing nonce is filled in). Prints the
//! numbers each rule looks at and the rules that fired, and exits 1 if any
//! did.

use std::io::BufRead;

use veritell_behavior::{analyze, parse_summary, Params};

fn main() {
    let params = Params::default();
    let (mut total, mut flagged) = (0u32, 0u32);
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let Ok(mut value) = serde_json::from_str::<serde_json::Value>(&line) else {
            println!("line is not JSON");
            flagged += 1;
            continue;
        };
        let text = |key: &str| value.get(key).and_then(|b| b.as_str()).unwrap_or("-").to_string();
        let label = format!("{}/{}", text("browser"), text("device"));
        if let Some(inner) = value.get_mut("summary") {
            value = inner.take();
        }
        if let Some(object) = value.as_object_mut() {
            object.entry("nonce").or_insert_with(|| "recording".into());
        }
        let summary = match parse_summary(value.to_string().as_bytes()) {
            Ok(s) => s,
            Err(e) => {
                println!("refused: {e}");
                flagged += 1;
                continue;
            }
        };
        total += 1;
        let found = analyze(&summary, &params);
        let s = &summary;
        println!(
            "{label:18} {:6?} {:>6} ms  moves {:>5}  strokes {:>3} (straight {}, steady {})  clicks {} (sized {}, centred {}, jumped {})  keys {:>3} (cv {:?})  scrolls {}  actions {} (cv {:?}, median {:?} ms)  ->  {}",
            s.trigger, s.dur_ms, s.moves, s.strokes, s.straight, s.steady, s.clicks, s.sized, s.centered, s.teleport,
            s.keys, s.key_gap_cv, s.scrolls, s.actions, s.gap_cv, s.gap_med_ms,
            if found.is_empty() { "clean".to_string() } else { found.iter().map(|d| d.id.as_str()).collect::<Vec<_>>().join(", ") }
        );
        if !found.is_empty() {
            flagged += 1;
        }
    }
    println!("{total} summaries, {flagged} flagged or refused");
    if flagged > 0 {
        std::process::exit(1);
    }
}
