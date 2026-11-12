//! The page shows the gateway's version in the top bar.

use veritell_dash::*;
use veritell_events::{Event, EventQuery, Filter, Summary};

struct Empty;

impl EventQuery for Empty {
    fn recent(&self, _limit: usize, _filter: &Filter) -> Vec<Event> {
        Vec::new()
    }
    fn summary(&self, _since_ms: u64) -> Summary {
        Summary::default()
    }
    fn summary_for(&self, _since_ms: u64, _host: Option<&str>) -> Summary {
        Summary::default()
    }
}

#[test]
fn page_shows_the_version() {
    let r = handle("GET", "/", &Empty, 0);
    assert_eq!(r.status, 200);
    let html = String::from_utf8(r.body).unwrap();
    let expected = format!(">v{}</span>", env!("CARGO_PKG_VERSION"));
    assert!(html.contains(&expected), "version missing from the page");
    assert!(!html.contains("{{"), "a placeholder was left in the page");
}
