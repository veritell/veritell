//! In-memory store and fan-out.

use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::types::{Event, EventKind, EventQuery, EventSink, Filter, Summary};

const TOP_DETECTIONS: usize = 20;
const TOP_HOSTS: usize = 20;

struct Inner {
    /// Shared, so readers can copy pointers under the lock and do their
    /// work after releasing it.
    events: VecDeque<Arc<Event>>,
    capacity: usize,
    evicted: u64,
}

/// Keeps the most recent `capacity` events. Thread-safe. When full, the
/// oldest event is discarded and counted in `Summary::evicted`.
pub struct MemoryRing {
    inner: Mutex<Inner>,
}

impl MemoryRing {
    /// `capacity` of 0 is treated as 1.
    pub fn new(capacity: usize) -> MemoryRing {
        let capacity = capacity.max(1);
        MemoryRing {
            inner: Mutex::new(Inner {
                // Do not pre-allocate a huge buffer for a huge capacity.
                events: VecDeque::with_capacity(capacity.min(4096)),
                capacity,
                evicted: 0,
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn len(&self) -> usize {
        self.lock().events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Every stored event, oldest first.
    pub fn events(&self) -> Vec<Event> {
        let events: Vec<Arc<Event>> = self.lock().events.iter().cloned().collect();
        events.iter().map(|e| Event::clone(e)).collect()
    }

    /// Adds events, oldest first, as `record` would (used to put a saved
    /// ring back after a restart).
    pub fn restore(&self, events: Vec<Event>) {
        for event in &events {
            self.record(event);
        }
    }
}

fn bump(n: &mut u64) {
    *n = n.saturating_add(1);
}

/// Most first, ties by key ascending, at most `n`.
fn top_n(mut v: Vec<(String, u64)>, n: usize) -> Vec<(String, u64)> {
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v.truncate(n);
    v
}

fn matches(event: &Event, filter: &Filter) -> bool {
    filter.class.is_none_or(|c| c == event.class)
        && filter
            .detection
            .as_ref()
            .is_none_or(|id| event.detections.iter().any(|d| &d.id == id))
        && filter.max_score.is_none_or(|m| event.score <= m)
        && filter.ip.as_ref().is_none_or(|ip| ip == &event.ip)
        && filter.kind.is_none_or(|k| k == event.kind)
        && filter.outcome.as_ref().is_none_or(|o| o == &event.outcome)
        && filter.host.as_ref().is_none_or(|h| h.eq_ignore_ascii_case(&event.host))
}

impl EventSink for MemoryRing {
    fn record(&self, event: &Event) {
        let event = Arc::new(event.clone());
        let mut inner = self.lock();
        while inner.events.len() >= inner.capacity {
            if inner.events.pop_front().is_none() {
                break;
            }
            inner.evicted = inner.evicted.saturating_add(1);
        }
        inner.events.push_back(event);
    }
}

impl EventQuery for MemoryRing {
    fn recent(&self, limit: usize, filter: &Filter) -> Vec<Event> {
        if limit == 0 {
            return Vec::new();
        }
        let found: Vec<Arc<Event>> = self
            .lock()
            .events
            .iter()
            .rev()
            .filter(|e| matches(e, filter))
            .take(limit)
            .cloned()
            .collect();
        found.iter().map(|e| Event::clone(e)).collect()
    }

    fn summary(&self, since_ms: u64) -> Summary {
        self.summary_for(since_ms, None)
    }

    fn summary_for(&self, since_ms: u64, host: Option<&str>) -> Summary {
        // `record` takes the same lock on every request, so under it this
        // only copies pointers to the events in the window; the counting
        // happens after the lock is released.
        let (window, evicted) = {
            let inner = self.lock();
            let window: Vec<Arc<Event>> = inner
                .events
                .iter()
                .filter(|e| e.kind == EventKind::Request && e.ts_ms >= since_ms)
                .cloned()
                .collect();
            (window, inner.evicted)
        };
        let mut s = Summary { evicted, ..Summary::default() };
        // Every site in the window, whatever the site filter.
        let mut hosts: HashMap<Cow<'_, str>, u64> = HashMap::new();
        let mut detections: HashMap<&str, u64> = HashMap::new();
        let mut by_class: HashMap<&'static str, u64> = HashMap::new();
        let mut by_outcome: HashMap<&str, u64> = HashMap::new();
        for e in &window {
            let key = if e.host.bytes().any(|b| b.is_ascii_uppercase()) {
                Cow::Owned(e.host.to_ascii_lowercase())
            } else {
                Cow::Borrowed(e.host.as_str())
            };
            bump(hosts.entry(key).or_insert(0));
            if !host.is_none_or(|h| h.eq_ignore_ascii_case(&e.host)) {
                continue;
            }
            s.total = s.total.saturating_add(1);
            bump(by_class.entry(e.class.as_str()).or_insert(0));
            bump(by_outcome.entry(e.outcome.as_str()).or_insert(0));
            // Each event counts once per distinct detection id. An event
            // has a handful at most, so a look back beats sorting a copy.
            for (i, d) in e.detections.iter().enumerate() {
                if e.detections[..i].iter().all(|p| p.id != d.id) {
                    bump(detections.entry(d.id.as_str()).or_insert(0));
                }
            }
            if let Some(b) = s.score_histogram.get_mut(usize::from(e.score / 10).min(9)) {
                bump(b);
            }
        }
        s.by_host = top_n(hosts.into_iter().map(|(k, v)| (k.into_owned(), v)).collect(), TOP_HOSTS);
        s.top_detections =
            top_n(detections.into_iter().map(|(k, v)| (k.to_string(), v)).collect(), TOP_DETECTIONS);
        s.by_class = by_class.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
        s.by_outcome = by_outcome.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
        s
    }
}

/// Sends each event to several sinks, in order.
pub struct Fanout {
    sinks: Vec<Arc<dyn EventSink>>,
}

impl Fanout {
    pub fn new(sinks: Vec<Arc<dyn EventSink>>) -> Fanout {
        Fanout { sinks }
    }
}

impl EventSink for Fanout {
    fn record(&self, event: &Event) {
        for sink in &self.sinks {
            sink.record(event);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veritell_core::{Class, Detection, Layer};

    fn ev(ts: u64, score: u8, dets: &[&str]) -> Event {
        Event {
            ts_ms: ts,
            kind: EventKind::Request,
            ip: "1.2.3.4".into(),
            method: "GET".into(),
            host: "h".into(),
            path: "/".into(),
            user_agent: "ua".into(),
            ja4: String::new(),
            h2: String::new(),
            score,
            class: Class::Human,
            detections: dets.iter().map(|d| Detection::new(d, Layer::Network, 1, "x")).collect(),
            identity: String::new(),
            asn: 0,
            net_class: String::new(),
            token: "none".into(),
            action: String::new(),
            enforced: false,
            route: String::new(),
            rule: String::new(),
            outcome: "passed".into(),
            known: String::new(),
            summary: String::new(),
            tcp: String::new(),
            tcp_ttl: 0,
        }
    }

    #[test]
    fn poisoned_mutex_does_not_panic() {
        let ring = Arc::new(MemoryRing::new(4));
        let r = Arc::clone(&ring);
        let _ = std::thread::spawn(move || {
            let _guard = r.inner.lock();
            panic!("poison");
        })
        .join();
        ring.record(&ev(1, 50, &[]));
        assert_eq!(ring.len(), 1);
        assert_eq!(ring.recent(5, &Filter::default()).len(), 1);
        assert_eq!(ring.summary(0).total, 1);
    }

    #[test]
    fn histogram_edges_and_duplicate_detections() {
        let ring = MemoryRing::new(10);
        ring.record(&ev(1, 0, &["a", "a"]));
        ring.record(&ev(2, 9, &[]));
        ring.record(&ev(3, 10, &[]));
        ring.record(&ev(4, 100, &[]));
        ring.record(&ev(5, 255, &[]));
        let s = ring.summary(0);
        assert_eq!(s.score_histogram, [2, 1, 0, 0, 0, 0, 0, 0, 0, 2]);
        assert_eq!(s.top_detections, [("a".to_string(), 1)]);
    }

    #[test]
    fn evicted_counts_even_outside_window() {
        let ring = MemoryRing::new(1);
        ring.record(&ev(1, 50, &[]));
        ring.record(&ev(2, 50, &[]));
        let s = ring.summary(2);
        assert_eq!((s.total, s.evicted), (1, 1));
    }
}
