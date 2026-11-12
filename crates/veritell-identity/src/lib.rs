//! Identity layer: is a self-declared crawler really who it says it is, and
//! what kind of network does the request come from?
//!
//! PUBLIC API IS FIXED. Implement the bodies; do not change signatures.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use veritell_core::{Class, Detection, Layer};

/// DNS lookups, abstracted so tests can run without a network.
#[async_trait]
pub trait Resolver: Send + Sync {
    /// PTR lookup. Returns host names, possibly with a trailing dot.
    /// An empty list means the lookup failed or there is no record.
    async fn reverse(&self, ip: IpAddr) -> Vec<String>;
    /// A/AAAA lookup. An empty list means failure or no record.
    async fn forward(&self, host: &str) -> Vec<IpAddr>;
}

/// How to recognise and verify one crawler.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrawlerSpec {
    /// Display name, e.g. "Googlebot".
    pub name: String,
    /// Substring of the User-Agent that makes the claim (matched case-insensitively).
    pub ua_token: String,
    /// Reverse-DNS names must equal one of these or end with `.` + one of these.
    pub rdns_suffixes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CrawlerVerdict {
    /// The User-Agent does not claim to be a crawler we have a spec for.
    NoClaim,
    /// Forward-confirmed reverse DNS succeeded.
    Verified { name: String },
    /// DNS answered, and the answer proves the claim false; or the address's
    /// reverse name is the operator's but resolves to nothing, which a real
    /// crawler's never does (anyone can write any PTR for their own address).
    Spoofed { claimed: String },
    /// DNS did not answer; the claim is neither proven nor disproven.
    Unresolved { claimed: String },
}

impl CrawlerVerdict {
    /// `Spoofed` -> `crawler_spoofed` (penalty 90, class Malicious, layer Identity).
    /// `Unresolved` -> `crawler_unresolved` (penalty 10, no class, layer Identity).
    /// Others -> `None`.
    pub fn detection(&self) -> Option<Detection> {
        match self {
            CrawlerVerdict::Spoofed { claimed } => Some(
                Detection::new(
                    "crawler_spoofed",
                    Layer::Identity,
                    90,
                    format!("claims to be {claimed} but its IP does not belong to that operator"),
                )
                .with_class(Class::Malicious),
            ),
            CrawlerVerdict::Unresolved { claimed } => Some(Detection::new(
                "crawler_unresolved",
                Layer::Identity,
                10,
                format!("claims to be {claimed}; reverse DNS could not confirm it"),
            )),
            CrawlerVerdict::NoClaim | CrawlerVerdict::Verified { .. } => None,
        }
    }
}

type CacheKey = (String, IpAddr);

/// How long a confirmed crawler address stays trusted without a new lookup.
const VERIFIED_TTL: Duration = Duration::from_secs(24 * 3600);
/// How long a disproved claim is remembered. Shorter: addresses change
/// hands, and anyone can make a claim from as many addresses as they hold.
const SPOOFED_TTL: Duration = Duration::from_secs(3600);

struct Entry {
    verdict: CrawlerVerdict,
    expires: Instant,
    /// Matches the queue item that inserted it, so a key left behind in a
    /// queue (after expiry or an update) never evicts a newer entry.
    seq: u64,
}

/// Bounded result cache with two FIFO queues, oldest first. When full,
/// disproved claims are evicted before confirmed crawlers, so a flood of
/// fake claims from many addresses can't push the real crawlers out.
#[derive(Default)]
struct Cache {
    entries: HashMap<CacheKey, Entry>,
    verified: VecDeque<(CacheKey, u64)>,
    other: VecDeque<(CacheKey, u64)>,
    seq: u64,
}

impl Cache {
    /// Removes the oldest live entry, disproved claims first. False when
    /// both queues are empty.
    fn evict_one(&mut self) -> bool {
        loop {
            let item = match self.other.pop_front() {
                Some(item) => item,
                None => match self.verified.pop_front() {
                    Some(item) => item,
                    None => return false,
                },
            };
            if self.entries.get(&item.0).is_some_and(|e| e.seq == item.1) {
                self.entries.remove(&item.0);
                return true;
            }
        }
    }

    /// Drops queue items whose entry is gone or newer, once the queues hold
    /// more than twice what the map does.
    fn compact(&mut self) {
        if self.verified.len() + self.other.len() <= 2 * self.entries.len().max(16) {
            return;
        }
        let entries = &self.entries;
        let live = |item: &(CacheKey, u64)| entries.get(&item.0).is_some_and(|e| e.seq == item.1);
        self.verified.retain(live);
        self.other.retain(live);
    }
}

/// Verifies crawler claims, with a bounded in-memory cache.
pub struct CrawlerVerifier<R: Resolver> {
    resolver: R,
    specs: Vec<CrawlerSpec>,
    cache: Mutex<Cache>,
    cache_capacity: usize,
}

impl<R: Resolver> CrawlerVerifier<R> {
    /// Uses `builtin_specs()` and a cache of at most 10_000 entries.
    pub fn new(resolver: R) -> Self {
        Self::with_specs(resolver, builtin_specs(), 10_000)
    }

    pub fn with_specs(resolver: R, specs: Vec<CrawlerSpec>, cache_capacity: usize) -> Self {
        CrawlerVerifier {
            resolver,
            specs,
            cache: Mutex::new(Cache::default()),
            cache_capacity,
        }
    }

    pub async fn verify(&self, user_agent: Option<&str>, ip: IpAddr) -> CrawlerVerdict {
        let Some(ua) = user_agent else {
            return CrawlerVerdict::NoClaim;
        };
        let Some(spec) = self.match_spec(ua) else {
            return CrawlerVerdict::NoClaim;
        };

        let claimed = spec.name.clone();
        let key: CacheKey = (claimed.clone(), ip);
        if let Some(hit) = self.cache_get(&key) {
            return hit;
        }

        let names = self.resolver.reverse(ip).await;
        if names.is_empty() {
            return CrawlerVerdict::Unresolved { claimed };
        }

        let suffixes: Vec<String> = spec
            .rdns_suffixes
            .iter()
            .map(|s| normalise_host(s))
            .filter(|s| !s.is_empty())
            .collect();
        let matching: Vec<String> = names
            .iter()
            .map(|n| normalise_host(n))
            .filter(|h| !h.is_empty() && suffixes.iter().any(|s| host_matches(h, s)))
            .collect();

        if matching.is_empty() {
            let verdict = CrawlerVerdict::Spoofed { claimed };
            self.cache_put(key, verdict.clone());
            return verdict;
        }

        let mut any_answer = false;
        for host in &matching {
            let addrs = self.resolver.forward(host).await;
            if addrs.is_empty() {
                continue;
            }
            any_answer = true;
            if addrs.contains(&ip) {
                let verdict = CrawlerVerdict::Verified { name: claimed };
                self.cache_put(key, verdict.clone());
                return verdict;
            }
        }

        if !any_answer {
            // The reverse name claims the operator but nothing answers for
            // it. Not cached: the resolver can't tell "no such name" from a
            // lookup that failed, so a real crawler caught by a passing DNS
            // failure is judged again on its next request.
            return CrawlerVerdict::Spoofed { claimed };
        }
        let verdict = CrawlerVerdict::Spoofed { claimed };
        self.cache_put(key, verdict.clone());
        verdict
    }

    /// Number of cached results (for tests and metrics).
    pub fn cache_len(&self) -> usize {
        self.lock_cache().entries.len()
    }

    /// First spec, in list order, whose token occurs in the User-Agent.
    fn match_spec(&self, ua: &str) -> Option<&CrawlerSpec> {
        let ua_lower = ua.to_ascii_lowercase();
        self.specs.iter().find(|s| {
            !s.ua_token.is_empty() && ua_lower.contains(&s.ua_token.to_ascii_lowercase())
        })
    }

    fn lock_cache(&self) -> MutexGuard<'_, Cache> {
        self.cache.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn cache_get(&self, key: &CacheKey) -> Option<CrawlerVerdict> {
        self.cache_get_at(key, Instant::now())
    }

    fn cache_get_at(&self, key: &CacheKey, now: Instant) -> Option<CrawlerVerdict> {
        let mut cache = self.lock_cache();
        match cache.entries.get(key) {
            Some(e) if e.expires > now => Some(e.verdict.clone()),
            Some(_) => {
                cache.entries.remove(key);
                cache.compact();
                None
            }
            None => None,
        }
    }

    fn cache_put(&self, key: CacheKey, verdict: CrawlerVerdict) {
        self.cache_put_at(key, verdict, Instant::now())
    }

    fn cache_put_at(&self, key: CacheKey, verdict: CrawlerVerdict, now: Instant) {
        if self.cache_capacity == 0 {
            return;
        }
        let verified = matches!(verdict, CrawlerVerdict::Verified { .. });
        let expires = now + if verified { VERIFIED_TTL } else { SPOOFED_TTL };
        let mut cache = self.lock_cache();
        // A replaced entry is queued again under its new kind and lifetime;
        // its old queue item no longer matches and is skipped.
        if cache.entries.remove(&key).is_none() {
            while cache.entries.len() >= self.cache_capacity && cache.evict_one() {}
        }
        cache.seq += 1;
        let seq = cache.seq;
        if verified {
            cache.verified.push_back((key.clone(), seq));
        } else {
            cache.other.push_back((key.clone(), seq));
        }
        cache.entries.insert(key, Entry { verdict, expires, seq });
        cache.compact();
    }
}

/// Trim, strip one trailing dot, lowercase.
fn normalise_host(name: &str) -> String {
    let trimmed = name.trim();
    trimmed.strip_suffix('.').unwrap_or(trimmed).to_ascii_lowercase()
}

/// `host` equals `suffix`, or ends with `.` + `suffix` (with a non-empty label before it).
/// Both arguments must already be normalised.
fn host_matches(host: &str, suffix: &str) -> bool {
    if host == suffix {
        return true;
    }
    host.strip_suffix(suffix)
        .and_then(|rest| rest.strip_suffix('.'))
        .is_some_and(|label| !label.is_empty())
}

/// The crawlers Veritell can verify out of the box.
pub fn builtin_specs() -> Vec<CrawlerSpec> {
    fn spec(name: &str, ua_token: &str, suffixes: &[&str]) -> CrawlerSpec {
        CrawlerSpec {
            name: name.to_string(),
            ua_token: ua_token.to_string(),
            rdns_suffixes: suffixes.iter().map(|s| s.to_string()).collect(),
        }
    }
    vec![
        spec(
            "Googlebot",
            "googlebot",
            // Not googleusercontent.com: Google Cloud customers' VMs have
            // reverse names under it (*.bc.googleusercontent.com) that
            // forward-confirm, so anyone with a VM could pass as Googlebot.
            &["googlebot.com", "google.com"],
        ),
        spec("Bingbot", "bingbot", &["search.msn.com"]),
        spec("Applebot", "applebot", &["applebot.apple.com"]),
        // "yandexbot", not "yandex": Yandex's own browser and apps carry
        // "Yandex" in their User-Agent and must not be treated as crawler claims.
        spec("YandexBot", "yandexbot", &["yandex.ru", "yandex.net", "yandex.com"]),
        spec("Baiduspider", "baiduspider", &["baidu.com", "baidu.jp"]),
    ]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetClass {
    /// Cloud or hosting provider: unusual for a person browsing.
    Hosting,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AsnInfo {
    pub asn: u32,
    pub org: String,
    pub class: NetClass,
}

impl AsnInfo {
    /// `Hosting` -> `net_hosting` (penalty 20, no class, layer Identity). `Other` -> `None`.
    pub fn detection(&self) -> Option<Detection> {
        match self.class {
            NetClass::Hosting => Some(Detection::new(
                "net_hosting",
                Layer::Identity,
                20,
                format!("AS{} ({}) is a hosting or cloud provider", self.asn, self.org),
            )),
            NetClass::Other => None,
        }
    }
}

#[derive(Debug)]
pub enum AsnError {
    /// 1-based line number and a description.
    BadLine(usize, String),
}

impl std::fmt::Display for AsnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AsnError::BadLine(n, why) => write!(f, "line {n}: {why}"),
        }
    }
}

impl std::error::Error for AsnError {}

/// Autonomous systems that are cloud or hosting providers.
const HOSTING_ASNS: &[u32] = &[
    16509, 14618, 396982, 8075, 14061, 16276, 24940, 63949, 20473, 51167, 12876, 31898, 45102,
    132203, 45090, 13335,
];

/// One inclusive address range owned by one autonomous system.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Span<T> {
    start: T,
    end: T,
    asn: u32,
    org: String,
}

/// IP-range to autonomous-system lookup.
pub struct AsnDb {
    /// Sorted by `start`.
    v4: Vec<Span<u32>>,
    /// Sorted by `start`.
    v6: Vec<Span<u128>>,
}

/// One accepted TSV row, already split by address family.
enum Parsed {
    V4(Span<u32>),
    V6(Span<u128>),
}

/// Maps an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) to its IPv4 form.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

/// Parses one TSV row. `Ok(None)` means the row is valid but unrouted (AS 0).
fn parse_row(line: &str) -> Result<Option<Parsed>, String> {
    let fields: Vec<&str> = line.splitn(5, '\t').collect();
    let [start_s, end_s, asn_s, _country, org] = fields.as_slice() else {
        return Err(format!("expected 5 tab-separated fields, found {}", fields.len()));
    };

    let start = canonical(
        start_s
            .trim()
            .parse::<IpAddr>()
            .map_err(|_| format!("bad range start address {:?}", start_s.trim()))?,
    );
    let end = canonical(
        end_s
            .trim()
            .parse::<IpAddr>()
            .map_err(|_| format!("bad range end address {:?}", end_s.trim()))?,
    );
    let asn: u32 = asn_s
        .trim()
        .parse()
        .map_err(|_| format!("bad AS number {:?}", asn_s.trim()))?;
    let org = org.trim().to_string();

    let parsed = match (start, end) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let (a, b) = (u32::from(a), u32::from(b));
            if a > b {
                return Err("range start is after range end".to_string());
            }
            Parsed::V4(Span { start: a, end: b, asn, org })
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let (a, b) = (u128::from(a), u128::from(b));
            if a > b {
                return Err("range start is after range end".to_string());
            }
            Parsed::V6(Span { start: a, end: b, asn, org })
        }
        _ => return Err("range start and end are different address families".to_string()),
    };

    if asn == 0 {
        Ok(None)
    } else {
        Ok(Some(parsed))
    }
}

/// Finds the span containing `ip` in a `start`-sorted slice.
fn find<T: Ord + Copy>(spans: &[Span<T>], ip: T) -> Option<&Span<T>> {
    let idx = spans.partition_point(|s| s.start <= ip);
    let span = spans.get(idx.checked_sub(1)?)?;
    (ip <= span.end).then_some(span)
}

impl AsnDb {
    pub fn empty() -> AsnDb {
        AsnDb { v4: Vec::new(), v6: Vec::new() }
    }

    /// Loads the iptoasn.com combined TSV format:
    /// `range_start \t range_end \t AS_number \t country_code \t AS_description`.
    pub fn from_iptoasn_tsv(tsv: &str) -> Result<AsnDb, AsnError> {
        let mut db = AsnDb::empty();
        for (idx, line) in tsv.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let line_no = idx + 1;
            match parse_row(line).map_err(|why| AsnError::BadLine(line_no, why))? {
                Some(Parsed::V4(span)) => db.v4.push(span),
                Some(Parsed::V6(span)) => db.v6.push(span),
                None => {}
            }
        }
        db.v4.sort_by_key(|s| s.start);
        db.v6.sort_by_key(|s| s.start);
        Ok(db)
    }

    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<AsnInfo> {
        let (asn, org) = match canonical(ip) {
            IpAddr::V4(a) => find(&self.v4, u32::from(a)).map(|s| (s.asn, s.org.as_str()))?,
            IpAddr::V6(a) => find(&self.v6, u128::from(a)).map(|s| (s.asn, s.org.as_str()))?,
        };
        let class = if HOSTING_ASNS.contains(&asn) {
            NetClass::Hosting
        } else {
            NetClass::Other
        };
        Some(AsnInfo { asn, org: org.to_string(), class })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Resolver whose PTR answer is fixed and whose forward answers come from a table.
    struct FixedDns {
        names: Vec<String>,
        forward: Vec<(String, IpAddr)>,
        forward_calls: AtomicUsize,
    }

    #[async_trait]
    impl Resolver for FixedDns {
        async fn reverse(&self, _ip: IpAddr) -> Vec<String> {
            self.names.clone()
        }
        async fn forward(&self, host: &str) -> Vec<IpAddr> {
            self.forward_calls.fetch_add(1, Ordering::SeqCst);
            self.forward
                .iter()
                .filter(|(h, _)| h.as_str() == host)
                .map(|(_, ip)| *ip)
                .collect()
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn no_dns() -> FixedDns {
        FixedDns { names: Vec::new(), forward: Vec::new(), forward_calls: AtomicUsize::new(0) }
    }

    fn key(n: u32) -> CacheKey {
        ("Googlebot".to_string(), IpAddr::from(std::net::Ipv6Addr::from(0x2001_0db8_u128 << 96 | u128::from(n))))
    }

    fn good() -> CrawlerVerdict {
        CrawlerVerdict::Verified { name: "Googlebot".into() }
    }

    fn fake() -> CrawlerVerdict {
        CrawlerVerdict::Spoofed { claimed: "Googlebot".into() }
    }

    #[test]
    fn a_flood_of_fake_claims_does_not_evict_real_crawlers() {
        let v = CrawlerVerifier::with_specs(no_dns(), builtin_specs(), 10);
        let t = Instant::now();
        for n in 0..3 {
            v.cache_put_at(key(n), good(), t);
        }
        for n in 100..10_100 {
            v.cache_put_at(key(n), fake(), t);
        }
        assert_eq!(v.cache_len(), 10);
        for n in 0..3 {
            assert_eq!(v.cache_get_at(&key(n), t), Some(good()), "verified entry {n} was evicted");
        }
        // The newest fake claims are the ones kept.
        assert_eq!(v.cache_get_at(&key(10_099), t), Some(fake()));
        assert_eq!(v.cache_get_at(&key(100), t), None);
    }

    #[test]
    fn verified_entries_go_when_nothing_else_is_left() {
        let v = CrawlerVerifier::with_specs(no_dns(), builtin_specs(), 3);
        let t = Instant::now();
        for n in 0..5 {
            v.cache_put_at(key(n), good(), t);
        }
        assert_eq!(v.cache_len(), 3);
        assert_eq!(v.cache_get_at(&key(0), t), None);
        assert_eq!(v.cache_get_at(&key(4), t), Some(good()));
    }

    #[test]
    fn entries_expire_by_kind() {
        let v = CrawlerVerifier::with_specs(no_dns(), builtin_specs(), 10);
        let t = Instant::now();
        v.cache_put_at(key(1), good(), t);
        v.cache_put_at(key(2), fake(), t);
        let after_spoofed = t + SPOOFED_TTL + Duration::from_secs(1);
        assert_eq!(v.cache_get_at(&key(1), after_spoofed), Some(good()));
        assert_eq!(v.cache_get_at(&key(2), after_spoofed), None);
        assert_eq!(v.cache_len(), 1, "an expired entry is removed when found");
        assert_eq!(v.cache_get_at(&key(1), t + VERIFIED_TTL), None);
        assert_eq!(v.cache_len(), 0);
    }

    #[test]
    fn a_replaced_entry_is_not_evicted_by_its_old_queue_item() {
        let v = CrawlerVerifier::with_specs(no_dns(), builtin_specs(), 2);
        let t = Instant::now();
        v.cache_put_at(key(1), fake(), t);
        v.cache_put_at(key(2), fake(), t);
        // key 1 becomes verified: its old item in the fake queue is stale.
        v.cache_put_at(key(1), good(), t);
        v.cache_put_at(key(3), fake(), t);
        assert_eq!(v.cache_get_at(&key(1), t), Some(good()));
        assert_eq!(v.cache_get_at(&key(2), t), None);
        assert_eq!(v.cache_get_at(&key(3), t), Some(fake()));
    }

    #[test]
    fn queues_stay_bounded_under_churn() {
        let v = CrawlerVerifier::with_specs(no_dns(), builtin_specs(), 50);
        let mut t = Instant::now();
        for round in 0..200u32 {
            for n in 0..50 {
                v.cache_put_at(key(n), if (n + round) % 2 == 0 { good() } else { fake() }, t);
            }
            t += SPOOFED_TTL + Duration::from_secs(1);
            for n in 0..50 {
                let _ = v.cache_get_at(&key(n), t);
            }
        }
        let c = v.lock_cache();
        assert!(c.entries.len() <= 50);
        assert!(c.verified.len() + c.other.len() <= 2 * 50, "queues hold {}", c.verified.len() + c.other.len());
    }

    #[tokio::test]
    async fn ptr_with_several_names_matches_on_the_second() {
        let target = ip("66.249.66.1");
        let dns = FixedDns {
            names: vec![
                "host.example.net".to_string(),
                "crawl-66-249-66-1.googlebot.com.".to_string(),
            ],
            forward: vec![("crawl-66-249-66-1.googlebot.com".to_string(), target)],
            forward_calls: AtomicUsize::new(0),
        };
        let v = CrawlerVerifier::new(dns);
        assert_eq!(
            v.verify(Some("Googlebot/2.1"), target).await,
            CrawlerVerdict::Verified { name: "Googlebot".into() }
        );
    }

    #[tokio::test]
    async fn a_cloud_vm_named_under_googleusercontent_is_not_googlebot() {
        // A Google Cloud VM's own reverse name forward-confirms; it must not
        // make a User-Agent saying Googlebot verified.
        let target = ip("34.120.1.2");
        let name = "2.1.120.34.bc.googleusercontent.com";
        let dns = FixedDns {
            names: vec![name.to_string()],
            forward: vec![(name.to_string(), target)],
            forward_calls: AtomicUsize::new(0),
        };
        let v = CrawlerVerifier::new(dns);
        assert_ne!(
            v.verify(Some("Mozilla/5.0 (compatible; Googlebot/2.1)"), target).await,
            CrawlerVerdict::Verified { name: "Googlebot".into() }
        );
    }

    #[tokio::test]
    async fn zero_capacity_cache_stores_nothing() {
        let target = ip("66.249.66.1");
        let dns = FixedDns {
            names: vec!["crawl.googlebot.com".to_string()],
            forward: vec![("crawl.googlebot.com".to_string(), target)],
            forward_calls: AtomicUsize::new(0),
        };
        let v = CrawlerVerifier::with_specs(dns, builtin_specs(), 0);
        assert_eq!(
            v.verify(Some("Googlebot/2.1"), target).await,
            CrawlerVerdict::Verified { name: "Googlebot".into() }
        );
        assert_eq!(v.cache_len(), 0);
    }

    #[test]
    fn mapped_ipv4_is_looked_up_as_ipv4() {
        let db = AsnDb::from_iptoasn_tsv("3.0.0.0\t3.1.255.255\t16509\tUS\tAMAZON-02\n").unwrap();
        let info = db.lookup(ip("::ffff:3.1.2.3")).unwrap();
        assert_eq!((info.asn, info.class), (16509, NetClass::Hosting));
        assert!(db.lookup(ip("::ffff:3.2.0.0")).is_none());
    }

    #[test]
    fn start_after_end_is_a_line_error() {
        match AsnDb::from_iptoasn_tsv("3.0.0.0\t3.1.255.255\t16509\tUS\tAMAZON-02\n3.1.0.0\t3.0.0.0\t16509\tUS\tX\n") {
            Err(AsnError::BadLine(2, why)) => assert!(why.contains("after")),
            other => panic!("expected BadLine(2, _), got {:?}", other.map(|d| d.len())),
        }
    }

    #[test]
    fn short_row_reports_its_line() {
        assert!(matches!(
            AsnDb::from_iptoasn_tsv("3.0.0.0\t3.1.255.255\t16509\n"),
            Err(AsnError::BadLine(1, _))
        ));
    }

    #[test]
    fn host_suffix_matching_is_label_aware() {
        assert!(host_matches("googlebot.com", "googlebot.com"));
        assert!(host_matches("a.b.googlebot.com", "googlebot.com"));
        assert!(!host_matches("fakegooglebot.com", "googlebot.com"));
        assert!(!host_matches("googlebot.com.evil.net", "googlebot.com"));
        assert!(!host_matches(".googlebot.com", "googlebot.com"));
    }
}
