//! The summary window reaches back as far as the gateway keeps events.

use std::sync::Mutex;

use veritell_dash::*;
use veritell_events::{Event, EventQuery, Filter, Summary};

const NOW: u64 = 40 * 86_400 * 1000;

#[derive(Default)]
struct Fake {
    since: Mutex<Vec<u64>>,
}

impl EventQuery for Fake {
    fn recent(&self, _limit: usize, _filter: &Filter) -> Vec<Event> {
        Vec::new()
    }
    fn summary(&self, since_ms: u64) -> Summary {
        self.since.lock().unwrap().push(since_ms);
        Summary::default()
    }
    fn summary_for(&self, since_ms: u64, _host: Option<&str>) -> Summary {
        self.since.lock().unwrap().push(since_ms);
        Summary::default()
    }
}

fn since_for(query: &str) -> u64 {
    let f = Fake::default();
    assert_eq!(handle("GET", &format!("/api/summary{query}"), &f, NOW).status, 200);
    let since = *f.since.lock().unwrap().last().unwrap();
    since
}

#[test]
fn thirty_days_is_the_longest_window() {
    assert_eq!(MAX_WINDOW_SECS, 30 * 86_400);
    assert_eq!(since_for("?window_secs=604800"), NOW - 7 * 86_400 * 1000);
    assert_eq!(since_for("?window_secs=2592000"), NOW - 30 * 86_400 * 1000);
    assert_eq!(since_for("?window_secs=2592001"), NOW - 30 * 86_400 * 1000);
}

#[test]
fn the_page_offers_seven_days_all_and_custom() {
    let html = String::from_utf8(handle("GET", "/", &Fake::default(), NOW).body).unwrap();
    for needle in [
        r#"value="604800"><span>7d</span>"#,
        r#"value="2592000""#,
        r#"<span>All</span>"#,
        r#"id="window-custom""#,
        r#"id="window-n""#,
        r#"id="window-unit""#,
    ] {
        assert!(html.contains(needle), "missing {needle}");
    }
}
