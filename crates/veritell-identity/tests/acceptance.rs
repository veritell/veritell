//! Acceptance tests written by the project lead. DO NOT EDIT.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use veritell_core::{Class, Layer};
use veritell_identity::*;

const GOOGLEBOT_UA: &str = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
const BINGBOT_UA: &str = "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)";
const CHROME_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36";

#[derive(Default, Clone)]
struct MockDns {
    ptr: HashMap<IpAddr, Vec<String>>,
    fwd: HashMap<String, Vec<IpAddr>>,
    reverse_calls: Arc<AtomicUsize>,
    forward_calls: Arc<AtomicUsize>,
}

impl MockDns {
    fn with(mut self, ip: &str, name: &str, forward_to: &[&str]) -> Self {
        self.ptr.insert(ip.parse().unwrap(), vec![name.to_string()]);
        self.fwd.insert(
            name.trim_end_matches('.').to_ascii_lowercase(),
            forward_to.iter().map(|s| s.parse().unwrap()).collect(),
        );
        self
    }
}

#[async_trait]
impl Resolver for MockDns {
    async fn reverse(&self, ip: IpAddr) -> Vec<String> {
        self.reverse_calls.fetch_add(1, Ordering::SeqCst);
        self.ptr.get(&ip).cloned().unwrap_or_default()
    }
    async fn forward(&self, host: &str) -> Vec<IpAddr> {
        self.forward_calls.fetch_add(1, Ordering::SeqCst);
        self.fwd
            .get(&host.trim_end_matches('.').to_ascii_lowercase())
            .cloned()
            .unwrap_or_default()
    }
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[tokio::test]
async fn real_googlebot_is_verified() {
    let dns = MockDns::default().with(
        "66.249.66.1",
        "crawl-66-249-66-1.googlebot.com.",
        &["66.249.66.1"],
    );
    let v = CrawlerVerifier::new(dns);
    assert_eq!(
        v.verify(Some(GOOGLEBOT_UA), ip("66.249.66.1")).await,
        CrawlerVerdict::Verified { name: "Googlebot".into() }
    );
}

#[tokio::test]
async fn bingbot_and_ipv6_are_supported() {
    let dns = MockDns::default()
        .with("157.55.39.1", "msnbot-157-55-39-1.search.msn.com", &["157.55.39.1"])
        .with(
            "2001:4860:4801:10::1",
            "crawl-2001-4860.googlebot.com",
            &["2001:4860:4801:10::1"],
        );
    let v = CrawlerVerifier::new(dns);
    assert_eq!(
        v.verify(Some(BINGBOT_UA), ip("157.55.39.1")).await,
        CrawlerVerdict::Verified { name: "Bingbot".into() }
    );
    assert_eq!(
        v.verify(Some(GOOGLEBOT_UA), ip("2001:4860:4801:10::1")).await,
        CrawlerVerdict::Verified { name: "Googlebot".into() }
    );
}

#[tokio::test]
async fn ordinary_browser_makes_no_claim_and_costs_no_dns() {
    let dns = MockDns::default();
    let calls = dns.reverse_calls.clone();
    let v = CrawlerVerifier::new(dns);
    assert_eq!(v.verify(Some(CHROME_UA), ip("203.0.113.9")).await, CrawlerVerdict::NoClaim);
    assert_eq!(v.verify(None, ip("203.0.113.9")).await, CrawlerVerdict::NoClaim);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn wrong_domain_is_spoofed() {
    let dns = MockDns::default().with("203.0.113.9", "host9.example.net", &["203.0.113.9"]);
    let v = CrawlerVerifier::new(dns);
    assert_eq!(
        v.verify(Some(GOOGLEBOT_UA), ip("203.0.113.9")).await,
        CrawlerVerdict::Spoofed { claimed: "Googlebot".into() }
    );
}

#[tokio::test]
async fn suffix_tricks_are_spoofed() {
    for name in [
        "googlebot.com.evil.net",
        "fakegooglebot.com",
        "crawl.googlebot.com.evil.net.",
        "googlebot.comx",
    ] {
        let dns = MockDns::default().with("203.0.113.9", name, &["203.0.113.9"]);
        let v = CrawlerVerifier::new(dns);
        assert_eq!(
            v.verify(Some(GOOGLEBOT_UA), ip("203.0.113.9")).await,
            CrawlerVerdict::Spoofed { claimed: "Googlebot".into() },
            "{name}"
        );
    }
}

#[tokio::test]
async fn forward_lookup_must_confirm() {
    // PTR is attacker-controlled for attacker-owned IP space; the forward
    // lookup of the real domain will not point back.
    let dns = MockDns::default().with(
        "203.0.113.9",
        "crawl-66-249-66-1.googlebot.com",
        &["66.249.66.1"],
    );
    let v = CrawlerVerifier::new(dns);
    assert_eq!(
        v.verify(Some(GOOGLEBOT_UA), ip("203.0.113.9")).await,
        CrawlerVerdict::Spoofed { claimed: "Googlebot".into() }
    );
}

#[tokio::test]
async fn dns_failure_is_unresolved_not_spoofed() {
    // No PTR at all.
    let v = CrawlerVerifier::new(MockDns::default());
    assert_eq!(
        v.verify(Some(GOOGLEBOT_UA), ip("66.249.66.1")).await,
        CrawlerVerdict::Unresolved { claimed: "Googlebot".into() }
    );
}

#[tokio::test]
async fn an_operator_ptr_that_resolves_to_nothing_is_spoofed_and_not_cached() {
    // Anyone can set a PTR under googlebot.com for their own address; the
    // name then resolves to nothing. Changed 2026-11-12 (was Unresolved).
    let dns = MockDns::default().with("66.249.66.1", "crawl-66-249-66-1.googlebot.com", &[]);
    let calls = dns.reverse_calls.clone();
    let v = CrawlerVerifier::new(dns);
    for _ in 0..2 {
        assert_eq!(
            v.verify(Some(GOOGLEBOT_UA), ip("66.249.66.1")).await,
            CrawlerVerdict::Spoofed { claimed: "Googlebot".into() }
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2, "judged again each time, in case DNS failed");
    assert_eq!(v.cache_len(), 0);
}

#[tokio::test]
async fn results_are_cached_but_failures_are_not() {
    let dns = MockDns::default().with(
        "66.249.66.1",
        "crawl-66-249-66-1.googlebot.com",
        &["66.249.66.1"],
    );
    let calls = dns.reverse_calls.clone();
    let v = CrawlerVerifier::new(dns);
    for _ in 0..3 {
        v.verify(Some(GOOGLEBOT_UA), ip("66.249.66.1")).await;
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(v.cache_len(), 1);

    // Unresolved must be retried.
    for _ in 0..2 {
        v.verify(Some(GOOGLEBOT_UA), ip("66.249.66.2")).await;
    }
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert_eq!(v.cache_len(), 1);
}

#[tokio::test]
async fn cache_is_bounded() {
    let mut dns = MockDns::default();
    for i in 1..=20u8 {
        dns = dns.with(&format!("203.0.113.{i}"), "host.example.net", &[]);
    }
    let v = CrawlerVerifier::with_specs(dns, builtin_specs(), 5);
    for i in 1..=20u8 {
        v.verify(Some(GOOGLEBOT_UA), ip(&format!("203.0.113.{i}"))).await;
    }
    assert!(v.cache_len() <= 5, "cache grew to {}", v.cache_len());
}

#[tokio::test]
async fn custom_specs_and_case_insensitive_token() {
    let spec = CrawlerSpec {
        name: "ExampleBot".into(),
        ua_token: "examplebot".into(),
        rdns_suffixes: vec!["crawler.example.org".into()],
    };
    let dns = MockDns::default().with("198.51.100.7", "N7.Crawler.Example.ORG.", &["198.51.100.7"]);
    let v = CrawlerVerifier::with_specs(dns, vec![spec], 100);
    assert_eq!(
        v.verify(Some("EXAMPLEBOT/1.0"), ip("198.51.100.7")).await,
        CrawlerVerdict::Verified { name: "ExampleBot".into() }
    );
    // Googlebot is not in this verifier's specs.
    assert_eq!(v.verify(Some(GOOGLEBOT_UA), ip("198.51.100.7")).await, CrawlerVerdict::NoClaim);
}

#[test]
fn builtin_specs_cover_the_major_crawlers() {
    let specs = builtin_specs();
    for name in ["Googlebot", "Bingbot", "Applebot", "YandexBot", "Baiduspider"] {
        let s = specs
            .iter()
            .find(|s| s.name == name)
            .unwrap_or_else(|| panic!("missing spec for {name}"));
        assert!(!s.rdns_suffixes.is_empty());
        assert!(s.rdns_suffixes.iter().all(|x| !x.starts_with('.') && !x.ends_with('.')));
    }
}

#[test]
fn verdict_detections() {
    let d = CrawlerVerdict::Spoofed { claimed: "Googlebot".into() }.detection().unwrap();
    assert_eq!(d.id, "crawler_spoofed");
    assert_eq!((d.penalty, d.class_hint, d.layer), (90, Some(Class::Malicious), Layer::Identity));
    let d = CrawlerVerdict::Unresolved { claimed: "Googlebot".into() }.detection().unwrap();
    assert_eq!(d.id, "crawler_unresolved");
    assert_eq!((d.penalty, d.class_hint), (10, None));
    assert!(CrawlerVerdict::NoClaim.detection().is_none());
    assert!(CrawlerVerdict::Verified { name: "Googlebot".into() }.detection().is_none());
}

const TSV: &str = "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n\
1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n\
3.0.0.0\t3.1.255.255\t16509\tUS\tAMAZON-02\n\
24.0.0.0\t24.15.255.255\t7922\tUS\tCOMCAST-7922\n\
2600:1f00::\t2600:1fff:ffff:ffff:ffff:ffff:ffff:ffff\t16509\tUS\tAMAZON-02\n\
2601::\t2601:ffff:ffff:ffff:ffff:ffff:ffff:ffff\t7922\tUS\tCOMCAST-7922\n";

#[test]
fn asn_lookup_v4_and_v6() {
    let db = AsnDb::from_iptoasn_tsv(TSV).unwrap();
    // The unrouted (AS 0) row is skipped.
    assert_eq!(db.len(), 5);

    let aws = db.lookup(ip("3.1.2.3")).unwrap();
    assert_eq!((aws.asn, aws.org.as_str(), aws.class), (16509, "AMAZON-02", NetClass::Hosting));
    assert_eq!(db.lookup(ip("3.0.0.0")).unwrap().asn, 16509);
    assert_eq!(db.lookup(ip("3.1.255.255")).unwrap().asn, 16509);
    assert!(db.lookup(ip("3.2.0.0")).is_none());
    assert!(db.lookup(ip("1.0.2.1")).is_none());
    assert!(db.lookup(ip("0.0.0.1")).is_none());
    assert!(db.lookup(ip("255.255.255.255")).is_none());

    let comcast = db.lookup(ip("24.1.2.3")).unwrap();
    assert_eq!((comcast.asn, comcast.class), (7922, NetClass::Other));

    assert_eq!(db.lookup(ip("2600:1f18::1")).unwrap().asn, 16509);
    assert_eq!(db.lookup(ip("2601:1::1")).unwrap().class, NetClass::Other);
    assert!(db.lookup(ip("2a00::1")).is_none());
}

#[test]
fn asn_detection_and_edge_cases() {
    let db = AsnDb::from_iptoasn_tsv(TSV).unwrap();
    let d = db.lookup(ip("3.1.2.3")).unwrap().detection().unwrap();
    assert_eq!(d.id, "net_hosting");
    assert_eq!((d.penalty, d.class_hint, d.layer), (20, None, Layer::Identity));
    assert!(db.lookup(ip("24.1.2.3")).unwrap().detection().is_none());

    let empty = AsnDb::empty();
    assert!(empty.is_empty());
    assert!(empty.lookup(ip("3.1.2.3")).is_none());

    // Blank lines are ignored; malformed lines report their line number.
    assert_eq!(AsnDb::from_iptoasn_tsv("\n\n").unwrap().len(), 0);
    match AsnDb::from_iptoasn_tsv("3.0.0.0\t3.1.255.255\t16509\tUS\tAMAZON-02\nnot-an-ip\tx\ty\tz\tw\n") {
        Err(AsnError::BadLine(2, _)) => {}
        other => panic!("expected BadLine(2, _), got {:?}", other.map(|d| d.len())),
    }
}
