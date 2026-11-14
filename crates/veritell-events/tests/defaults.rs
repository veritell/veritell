//! What the trait gives a store that does not do the work itself, and the
//! names event kinds are written under.

use veritell_events::*;

/// A store that counts but cannot filter by site.
struct Unfiltered;

impl EventQuery for Unfiltered {
    fn recent(&self, _limit: usize, _filter: &Filter) -> Vec<Event> {
        Vec::new()
    }
    fn summary(&self, since_ms: u64) -> Summary {
        Summary { total: since_ms, ..Summary::default() }
    }
}

#[test]
fn a_store_that_cannot_filter_by_site_answers_for_all_sites() {
    let store = Unfiltered;
    assert_eq!(store.summary_for(7, Some("shop.test")), store.summary(7));
    assert_eq!(store.summary_for(7, None), store.summary(7));
    assert!(store.recent(10, &Filter::default()).is_empty());
}

#[test]
fn event_kinds_are_written_under_their_names() {
    assert_eq!(EventKind::Request.as_str(), "request");
    assert_eq!(EventKind::Probe.as_str(), "probe");
    assert_eq!(EventKind::Challenge.as_str(), "challenge");
}
