//! The dashboard's site filter: `host` on /api/events and /api/summary.

use std::sync::Mutex;

use veritell_dash::*;
use veritell_events::{Event, EventQuery, Filter, Summary};

#[derive(Default)]
struct Fake {
    asked_recent: Mutex<Vec<Filter>>,
    asked_summary: Mutex<Vec<(u64, Option<String>)>>,
}

impl EventQuery for Fake {
    fn recent(&self, _limit: usize, filter: &Filter) -> Vec<Event> {
        self.asked_recent.lock().unwrap().push(filter.clone());
        Vec::new()
    }
    fn summary(&self, since_ms: u64) -> Summary {
        self.asked_summary.lock().unwrap().push((since_ms, None));
        Summary::default()
    }
    fn summary_for(&self, since_ms: u64, host: Option<&str>) -> Summary {
        self.asked_summary.lock().unwrap().push((since_ms, host.map(str::to_string)));
        Summary { total: 7, by_host: vec![("shop.example".into(), 7)], ..Summary::default() }
    }
}

#[test]
fn events_take_a_host() {
    let f = Fake::default();
    assert_eq!(handle("GET", "/api/events?host=shop.example", &f, 0).status, 200);
    assert_eq!(handle("GET", "/api/events?host=", &f, 0).status, 200);
    assert_eq!(handle("GET", "/api/events", &f, 0).status, 200);
    let asked = f.asked_recent.lock().unwrap();
    assert_eq!(asked[0].host.as_deref(), Some("shop.example"));
    assert_eq!(asked[1].host, None, "empty is every site");
    assert_eq!(asked[2].host, None);
}

#[test]
fn the_summary_takes_a_host_and_reports_sites() {
    let f = Fake::default();
    let r = handle("GET", "/api/summary?window_secs=60&host=shop%2Eexample", &f, 100_000);
    assert_eq!(r.status, 200);
    let body: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(body["total"], 7);
    assert_eq!(body["by_host"], serde_json::json!([["shop.example", 7]]));
    handle("GET", "/api/summary?window_secs=60", &f, 100_000);
    let asked = f.asked_summary.lock().unwrap();
    assert_eq!(asked[0], (40_000, Some("shop.example".to_string())));
    assert_eq!(asked[1], (40_000, None));
}
