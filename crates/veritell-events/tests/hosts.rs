//! Several sites behind one gateway: the site filter, the per-site summary
//! and the list of sites.

use veritell_core::Class;
use veritell_events::*;

fn event(ts_ms: u64, host: &str, class: Class, kind: EventKind) -> Event {
    Event {
        ts_ms,
        kind,
        ip: "203.0.113.9".into(),
        method: "GET".into(),
        host: host.into(),
        path: "/".into(),
        user_agent: "curl/8.7.1".into(),
        ja4: String::new(),
        h2: String::new(),
        score: if class == Class::Human { 90 } else { 10 },
        class,
        detections: Vec::new(),
        identity: String::new(),
        asn: 0,
        net_class: String::new(),
        token: String::new(),
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

fn ring() -> MemoryRing {
    let ring = MemoryRing::new(100);
    ring.record(&event(100, "shop.example", Class::Human, EventKind::Request));
    ring.record(&event(200, "shop.example", Class::Automated, EventKind::Request));
    ring.record(&event(300, "Shop.Example", Class::Automated, EventKind::Request));
    ring.record(&event(400, "blog.example", Class::Human, EventKind::Request));
    ring.record(&event(500, "blog.example", Class::Human, EventKind::Probe));
    ring.record(&event(50, "old.example", Class::Human, EventKind::Request));
    ring
}

#[test]
fn the_host_filter_matches_one_site_ignoring_case() {
    let r = ring();
    let ts = |host: &str| -> Vec<u64> {
        r.recent(100, &Filter { host: Some(host.into()), ..Filter::default() })
            .iter()
            .map(|e| e.ts_ms)
            .collect()
    };
    assert_eq!(ts("shop.example"), [300, 200, 100]);
    assert_eq!(ts("SHOP.EXAMPLE"), [300, 200, 100]);
    assert_eq!(ts("blog.example"), [500, 400]);
    assert_eq!(ts("nowhere.example"), Vec::<u64>::new());
    let both = Filter { host: Some("shop.example".into()), class: Some(Class::Human), ..Filter::default() };
    assert_eq!(r.recent(100, &both).iter().map(|e| e.ts_ms).collect::<Vec<_>>(), [100]);
}

#[test]
fn the_summary_for_one_site_counts_only_it_but_lists_every_site() {
    let r = ring();
    let all = r.summary(100);
    assert_eq!(all.total, 4, "requests at or after 100; the probe is not counted");
    assert_eq!(all.by_host, vec![("shop.example".to_string(), 3), ("blog.example".to_string(), 1)]);
    assert_eq!(r.summary_for(100, None), all);

    let shop = r.summary_for(100, Some("shop.example"));
    assert_eq!(shop.total, 3);
    assert_eq!(shop.by_class.get("automated"), Some(&2));
    assert_eq!(shop.by_class.get("human"), Some(&1));
    assert_eq!(shop.by_host, all.by_host, "the site list is never narrowed");

    let blog = r.summary_for(100, Some("BLOG.example"));
    assert_eq!(blog.total, 1);
    assert_eq!(r.summary_for(100, Some("nowhere.example")).total, 0);
}

#[test]
fn the_site_list_is_capped_and_ordered() {
    let r = MemoryRing::new(1000);
    for i in 0..25u64 {
        for _ in 0..=i {
            r.record(&event(1000, &format!("s{i:02}.example"), Class::Human, EventKind::Request));
        }
    }
    let s = r.summary(0);
    assert_eq!(s.by_host.len(), 20);
    assert_eq!(s.by_host[0], ("s24.example".to_string(), 25));
    assert!(s.by_host.windows(2).all(|w| w[0].1 >= w[1].1));
}

#[test]
fn an_old_summary_without_sites_still_reads() {
    let s: Summary = serde_json::from_str(
        r#"{"total":1,"by_class":{},"by_outcome":{},"top_detections":[],"score_histogram":[0,0,0,0,0,0,0,0,0,0],"evicted":0}"#,
    )
    .unwrap();
    assert!(s.by_host.is_empty());
}
