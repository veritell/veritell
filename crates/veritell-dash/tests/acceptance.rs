//! Acceptance tests written by the project lead. DO NOT EDIT.

use std::sync::Mutex;

use veritell_core::{Class, Detection, Layer};
use veritell_dash::*;
use veritell_events::{Event, EventKind, EventQuery, Filter, Summary};

/// Records what it was asked and returns canned data.
#[derive(Default)]
struct Fake {
    events: Vec<Event>,
    asked_recent: Mutex<Vec<(usize, Filter)>>,
    asked_summary: Mutex<Vec<u64>>,
}

impl EventQuery for Fake {
    fn recent(&self, limit: usize, filter: &Filter) -> Vec<Event> {
        self.asked_recent.lock().unwrap().push((limit, filter.clone()));
        self.events.iter().take(limit).cloned().collect()
    }

    fn summary(&self, since_ms: u64) -> Summary {
        self.asked_summary.lock().unwrap().push(since_ms);
        Summary {
            total: 42,
            ..Summary::default()
        }
    }
}

fn event() -> Event {
    Event {
        ts_ms: 1_700_000_000_000,
        kind: EventKind::Request,
        ip: "203.0.113.9".into(),
        method: "GET".into(),
        host: "example.com".into(),
        path: "/<script>alert(1)</script>".into(),
        user_agent: "\"><img src=x onerror=alert(1)>".into(),
        ja4: "t13d".into(),
        h2: "1:2".into(),
        score: 39,
        class: Class::Automated,
        detections: vec![Detection::new("ua_declared_tool", Layer::Network, 60, "says it is curl")],
        identity: String::new(),
        asn: 0,
        net_class: "unknown".into(),
        token: "none".into(),
        action: "pass".into(),
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

fn fake() -> Fake {
    Fake {
        events: vec![event()],
        ..Fake::default()
    }
}

const NOW: u64 = 1_700_000_100_000;

fn get(f: &Fake, target: &str) -> Response {
    handle("GET", target, f, NOW)
}

fn header<'a>(r: &'a Response, name: &str) -> Option<&'a str> {
    r.headers.iter().find(|(k, _)| *k == name).map(|(_, v)| v.as_str())
}

fn last_filter(f: &Fake) -> (usize, Filter) {
    f.asked_recent.lock().unwrap().last().cloned().unwrap()
}

#[test]
fn static_assets() {
    let f = fake();
    for (path, content_type) in [
        ("/", "text/html; charset=utf-8"),
        ("/app.js", "text/javascript; charset=utf-8"),
        ("/app.css", "text/css; charset=utf-8"),
    ] {
        let r = get(&f, path);
        assert_eq!((r.status, r.content_type), (200, content_type), "{path}");
        assert!(r.body.len() > 100, "{path} is nearly empty");
    }
    let html = String::from_utf8(get(&f, "/").body).unwrap();
    assert!(html.contains("app.js") && html.contains("app.css"));
    // A query string on a static path is fine.
    assert_eq!(get(&f, "/?x=1").status, 200);
}

#[test]
fn security_headers_are_on_every_response() {
    let f = fake();
    for (method, target) in [
        ("GET", "/"),
        ("GET", "/app.js"),
        ("GET", "/api/events"),
        ("GET", "/api/summary"),
        ("GET", "/nope"),
        ("POST", "/"),
        ("GET", "/api/events?class=bogus"),
    ] {
        let r = handle(method, target, &f, NOW);
        assert_eq!(header(&r, "content-security-policy"), Some(CSP), "{method} {target}");
        assert_eq!(header(&r, "x-content-type-options"), Some("nosniff"), "{method} {target}");
        assert_eq!(header(&r, "cache-control"), Some("no-store"), "{method} {target}");
        assert_eq!(header(&r, "referrer-policy"), Some("no-referrer"), "{method} {target}");
    }
    assert!(!CSP.contains("unsafe"));
}

#[test]
fn the_page_never_builds_html_from_data() {
    let f = fake();
    for path in ["/", "/app.js"] {
        let text = String::from_utf8(get(&f, path).body).unwrap();
        for banned in [
            "innerHTML",
            "outerHTML",
            "insertAdjacentHTML",
            "document.write",
            "eval(",
            "new Function",
            "setAttribute(\"on",
            "setAttribute('on",
            "javascript:",
            "srcdoc",
        ] {
            assert!(!text.contains(banned), "{path} contains {banned}");
        }
    }
    let html = String::from_utf8(get(&f, "/").body).unwrap();
    let lower = html.to_ascii_lowercase();
    // Inline script or style would be blocked by the policy, and external
    // resources are not allowed at all.
    assert!(!lower.contains("<style"), "inline style");
    assert!(!lower.contains(" style="), "inline style attribute");
    assert!(!lower.contains("http://") && !lower.contains("https://"), "external reference");
    assert!(!lower.contains(" onclick=") && !lower.contains(" onload="), "inline handler");
    for part in lower.split("<script").skip(1) {
        let tag = part.split('>').next().unwrap_or("");
        assert!(tag.contains("src="), "inline script");
    }
    let js = String::from_utf8(get(&f, "/app.js").body).unwrap();
    assert!(js.contains("textContent"));
    assert!(js.contains("/api/events") && js.contains("/api/summary"));
    assert!(!js.contains("http://") && !js.contains("https://"));
}

#[test]
fn only_get() {
    let f = fake();
    for method in ["POST", "PUT", "DELETE", "HEAD", "OPTIONS", "get", ""] {
        let r = handle(method, "/api/events", &f, NOW);
        assert_eq!(r.status, 405, "{method}");
        assert_eq!(r.content_type, "text/plain; charset=utf-8");
    }
    assert!(f.asked_recent.lock().unwrap().is_empty());
}

#[test]
fn unknown_paths() {
    let f = fake();
    for target in [
        "/api",
        "/api/events/",
        "/api/events/1",
        "//",
        "/index.html",
        "/../etc/passwd",
        "/app.js/..",
        "/%61pp.js",
        "",
        "api/events",
        "/API/EVENTS",
    ] {
        let r = get(&f, target);
        assert_eq!(r.status, 404, "{target:?}");
        assert_eq!(r.content_type, "text/plain; charset=utf-8");
    }
    // The body of an error never repeats the request.
    let r = get(&f, "/<script>alert(1)</script>");
    assert_eq!(r.status, 404);
    assert!(!String::from_utf8_lossy(&r.body).contains("script"));
}

#[test]
fn events_api_returns_events_as_json() {
    let f = fake();
    let r = get(&f, "/api/events");
    assert_eq!((r.status, r.content_type), (200, "application/json"));
    let got: Vec<Event> = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(got, vec![event()]);
    assert_eq!(last_filter(&f), (DEFAULT_LIMIT, Filter::default()));
}

#[test]
fn events_api_parameters() {
    let f = fake();
    let r = get(
        &f,
        "/api/events?limit=7&class=verified_bot&detection=tls_ua_mismatch&max_score=40&ip=2001%3Adb8%3A%3A1&kind=probe&outcome=passed&unknown=1",
    );
    assert_eq!(r.status, 200);
    assert_eq!(
        last_filter(&f),
        (
            7,
            Filter {
                class: Some(Class::VerifiedBot),
                detection: Some("tls_ua_mismatch".into()),
                max_score: Some(40),
                ip: Some("2001:db8::1".into()),
                kind: Some(EventKind::Probe),
                outcome: Some("passed".into()),
                host: None,
            }
        )
    );

    for (query, limit) in [
        ("limit=0", 0),
        ("limit=500", 500),
        ("limit=501", MAX_LIMIT),
        ("limit=99999999999999999999999", DEFAULT_LIMIT),
        ("limit=abc", DEFAULT_LIMIT),
        ("limit=-1", DEFAULT_LIMIT),
        ("limit=", DEFAULT_LIMIT),
        ("limit=3&limit=9", 3),
    ] {
        assert_eq!(get(&f, &format!("/api/events?{query}")).status, 200, "{query}");
        assert_eq!(last_filter(&f).0, limit, "{query}");
    }

    get(&f, "/api/events?outcome=a+b%20c&detection=%zz%4");
    let (_, filter) = last_filter(&f);
    assert_eq!(filter.outcome.as_deref(), Some("a b c"));
    assert!(filter.detection.is_some());

    for class in ["human", "verified_bot", "signed_agent", "unverified_agent", "automated", "malicious"] {
        assert_eq!(get(&f, &format!("/api/events?class={class}")).status, 200);
        assert_eq!(last_filter(&f).1.class.map(|c| c.as_str()), Some(class));
    }
}

#[test]
fn events_api_rejects_bad_values() {
    let f = fake();
    let before = f.asked_recent.lock().unwrap().len();
    for query in ["class=bogus", "class=", "kind=nope", "max_score=300", "max_score=x", "max_score=-1"] {
        let r = get(&f, &format!("/api/events?{query}"));
        assert_eq!(r.status, 400, "{query}");
        assert_eq!(r.content_type, "text/plain; charset=utf-8");
        assert!(!String::from_utf8_lossy(&r.body).contains("bogus"));
    }
    assert_eq!(f.asked_recent.lock().unwrap().len(), before);
}

#[test]
fn long_queries_are_refused() {
    let f = fake();
    let ok = format!("/api/events?ip={}", "a".repeat(MAX_QUERY_BYTES - 3));
    assert_eq!(get(&f, &ok).status, 200);
    let long = format!("/api/events?ip={}", "a".repeat(MAX_QUERY_BYTES - 2));
    assert_eq!(get(&f, &long).status, 414);
    let long_static = format!("/?{}", "a".repeat(MAX_QUERY_BYTES + 1));
    assert_eq!(get(&f, &long_static).status, 414);
    // The method check still comes first.
    assert_eq!(handle("POST", &long, &f, NOW).status, 405);
}

#[test]
fn summary_api() {
    let f = fake();
    let r = get(&f, "/api/summary");
    assert_eq!((r.status, r.content_type), (200, "application/json"));
    let s: Summary = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(s.total, 42);

    for (query, since) in [
        ("", NOW - DEFAULT_WINDOW_SECS * 1000),
        ("?window_secs=60", NOW - 60_000),
        ("?window_secs=abc", NOW - DEFAULT_WINDOW_SECS * 1000),
        ("?window_secs=0", NOW),
        ("?window_secs=99999999", NOW - MAX_WINDOW_SECS * 1000),
        ("?window_secs=18446744073709551615", NOW - MAX_WINDOW_SECS * 1000),
    ] {
        assert_eq!(get(&f, &format!("/api/summary{query}")).status, 200);
        assert_eq!(f.asked_summary.lock().unwrap().last().copied(), Some(since), "{query}");
    }
    // A small clock value must not underflow.
    assert_eq!(handle("GET", "/api/summary", &f, 5).status, 200);
    assert_eq!(f.asked_summary.lock().unwrap().last().copied(), Some(0));
}

#[test]
fn hostile_targets_do_not_panic() {
    let f = fake();
    for target in [
        "?",
        "/?",
        "/api/events?",
        "/api/events?&&&=&=&",
        "/api/events?=x",
        "/api/events?limit",
        "/api/events?%",
        "/api/events?%f",
        "/api/events?ip=%ff%fe",
        "/api/events?ip=\u{0}\u{202e}é",
        "/api/events#frag?limit=1",
        "/api/summary?window_secs=-0",
        "/api/events??limit=2",
    ] {
        let r = get(&f, target);
        assert!([200, 400, 404].contains(&r.status), "{target:?} gave {}", r.status);
    }
}
