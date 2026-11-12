//! Acceptance tests written by the project lead. DO NOT EDIT.
//!
//! The directory bodies are the examples of
//! draft-ietf-webbotauth-httpsig-protocol-01 (section 5.5.1 and appendix
//! E.2.3); the key is the Ed25519 test key of RFC 9421 B.1.4.

use std::cell::RefCell;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use veritell_directory::*;

const RFC_KEY_X: &str = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs";
const DRAFT_KEYID: &str = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";
/// Appendix E.2.3.
const E23_BODY: &str = r#"{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs","use":"sig"}]}"#;
/// Section 5.5.1, whose `kid` is not this key's thumbprint.
const S551_BODY: &str = r#"{
  "keys": [{
    "kty": "OKP",
    "crv": "Ed25519",
    "kid": "NFcWBst6DXG-N35nHdzMrioWntdzNZghQSkjHNMMSjw",
    "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
    "use": "sig",
    "nbf": 1712793600,
    "exp": 1715385600
  }]
}"#;
const RSA_ENTRY: &str = r#"{"kty":"RSA","n":"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw","e":"AQAB"}"#;

fn ed_entry(seed: u8) -> String {
    format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{}"}}"#, URL_SAFE_NO_PAD.encode([seed; 32]))
}

fn keys_of(entries: &[String]) -> String {
    format!(r#"{{"keys":[{}]}}"#, entries.join(","))
}

fn url(text: &str) -> DirectoryUrl {
    parse_url(text).unwrap_or_else(|e| panic!("{text:?} should parse: {e}"))
}

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

// ---------- URL ----------

#[test]
fn urls_that_are_accepted() {
    let u = url("https://agent.example/jwks.json");
    assert_eq!((u.host.as_str(), u.port, u.path_and_query.as_str()), ("agent.example", 443, "/jwks.json"));
    assert_eq!(u.as_string(), "https://agent.example/jwks.json");

    let u = url("HTTPS://Agent.Example:8443/a/B?c=D");
    assert_eq!((u.host.as_str(), u.port, u.path_and_query.as_str()), ("agent.example", 8443, "/a/B?c=D"));
    assert_eq!(u.as_string(), "https://agent.example:8443/a/B?c=D");

    assert_eq!(url("https://agent.example").path_and_query, "/");
    assert_eq!(url("https://agent.example?x=1").path_and_query, "/?x=1");
    assert_eq!(url("https://agent.example:443/").as_string(), "https://agent.example/");
    assert_eq!(url("https://signature-agent.test/.well-known/http-message-signatures-directory").host, "signature-agent.test");

    let u = url("https://[2001:db8::1]:444/k");
    assert_eq!((u.host.as_str(), u.port), ("2001:db8::1", 444));
    assert_eq!(u.as_string(), "https://[2001:db8::1]:444/k");
    assert_eq!(url("https://[::1]").host, "::1");
    assert_eq!(url("https://192.0.2.7/k").host, "192.0.2.7");

    // An "@" after the path has begun is not user information.
    assert_eq!(url("https://a.example/x@y").path_and_query, "/x@y");
    assert_eq!(url("https://a.example?u=@").path_and_query, "/?u=@");
    assert_eq!(url("https://a.example:65535/").port, 65535);
    assert_eq!(url("https://a.example:1/").port, 1);

    let longest_host = format!("{}.{}.{}.{}", "a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(61));
    assert_eq!(longest_host.len(), 253);
    assert!(parse_url(&format!("https://{longest_host}/")).is_ok());
}

#[test]
fn urls_that_are_refused() {
    let too_long = format!("https://agent.example/{}", "a".repeat(MAX_URL_BYTES));
    let host_254 = format!("https://{}.{}.{}.{}/", "a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(62));
    let bad = [
        "",
        "agent.example/jwks.json",
        "http://agent.example/",
        "ftp://agent.example/",
        "data:application/json,{}",
        "file:///etc/passwd",
        "https:",
        "https://",
        "https:///path",
        "https:/agent.example/",
        "https://user@agent.example/",
        "https://user:pw@agent.example/",
        "https://agent.example@evil.example/",
        "https://agent.example/#frag",
        "https://agent.example/a#b",
        "https://agent.example#b",
        "https://agent.example:/",
        "https://agent.example:0/",
        "https://agent.example:65536/",
        "https://agent.example:80a/",
        "https://agent.example:+80/",
        "https://agent.example:99999999999999999999/",
        "https://agent..example/",
        "https://.agent.example/",
        "https://agent.example./",
        "https://agent_example/",
        "https://ex%61mple.com/",
        "https://exa mple/",
        "https://agent.example/a b",
        "https://agent.example/a\tb",
        "https://agent.example/a\nb",
        "https://agent.example/caf\u{e9}",
        "https://agent.example/a\\b",
        "https://agent.example\\@evil.example/",
        "https://[::1/",
        "https://[not-an-address]/",
        "https://[::1]x/",
        "https://[::1]:x/",
        "https://[127.0.0.1]/",
        " https://agent.example/",
        "https://agent.example/ ",
        too_long.as_str(),
        host_254.as_str(),
    ];
    for text in bad {
        match parse_url(text) {
            Err(FetchError::Url(_)) => {}
            other => panic!("{text:?} should be refused as a URL, got {other:?}"),
        }
    }
}

// ---------- addresses ----------

#[test]
fn addresses_that_are_refused() {
    for text in [
        "0.0.0.0", "0.255.255.255", "10.0.0.1", "10.255.255.255", "100.64.0.0", "100.127.255.255",
        "127.0.0.1", "127.255.255.254", "169.254.0.1", "169.254.169.254", "172.16.0.1",
        "172.31.255.255", "192.0.0.1", "192.0.2.1", "192.168.0.0", "192.168.255.255", "198.18.0.1",
        "198.19.255.255", "198.51.100.1", "203.0.113.1", "224.0.0.1", "239.255.255.255", "240.0.0.1",
        "255.255.255.255",
        "::", "::1", "fc00::1", "fdff::1", "fd00:ec2::254", "fe80::1", "febf::1", "ff02::1",
        "2001:db8::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254",
        "::127.0.0.1", "64:ff9b::7f00:1", "64:ff9b::a00:1",
    ] {
        assert!(!address_allowed(ip(text)), "{text} must be refused");
    }
}

#[test]
fn addresses_that_are_allowed() {
    for text in [
        "1.1.1.1", "8.8.8.8", "9.255.255.255", "11.0.0.0", "100.63.255.255", "100.128.0.0",
        "126.255.255.255", "128.0.0.1", "169.253.255.255", "169.255.0.0", "172.15.255.255",
        "172.32.0.0", "192.0.1.0", "192.0.3.0", "192.167.255.255", "192.169.0.0", "198.17.255.255",
        "198.20.0.0", "198.51.99.255", "198.51.101.0", "203.0.112.255", "203.0.114.0",
        "223.255.255.255",
        "2606:4700:4700::1111", "2001:4860:4860::8888", "2001:db7::1", "2001:db9::1",
        "::ffff:8.8.8.8", "64:ff9b::808:808",
    ] {
        assert!(address_allowed(ip(text)), "{text} must be allowed");
    }
}

// ---------- lifetime ----------

#[test]
fn lifetime_from_cache_control() {
    let cases: [(Option<&str>, u64); 21] = [
        (None, DEFAULT_TTL_SECS),
        (Some(""), DEFAULT_TTL_SECS),
        (Some("public"), DEFAULT_TTL_SECS),
        (Some("s-maxage=900"), DEFAULT_TTL_SECS),
        (Some("max-age=86400"), 86_400),
        (Some("max-age=600"), 600),
        (Some("max-age=300"), 300),
        (Some("max-age=10"), MIN_TTL_SECS),
        (Some("max-age=0"), MIN_TTL_SECS),
        (Some("max-age=999999"), MAX_TTL_SECS),
        (Some("max-age=99999999999999999999999999"), MAX_TTL_SECS),
        (Some("public, max-age=1200"), 1200),
        (Some(" max-age=1200 , public"), 1200),
        (Some("MAX-AGE=1200"), 1200),
        (Some("max-age=700, max-age=800"), 700),
        (Some("no-store"), MIN_TTL_SECS),
        (Some("max-age=5000, no-cache"), MIN_TTL_SECS),
        (Some("No-Cache, max-age=5000"), MIN_TTL_SECS),
        (Some("max-age=abc"), DEFAULT_TTL_SECS),
        (Some("max-age="), DEFAULT_TTL_SECS),
        (Some("max-age=-5"), DEFAULT_TTL_SECS),
    ];
    for (value, expected) in cases {
        assert_eq!(ttl_from_cache_control(value), expected, "{value:?}");
    }
}

// ---------- directory body ----------

#[test]
fn the_drafts_directories_parse() {
    let keys = parse_keys(E23_BODY.as_bytes()).unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].keyid, DRAFT_KEYID);
    assert_eq!(keys[0].public.to_vec(), URL_SAFE_NO_PAD.decode(RFC_KEY_X).unwrap());
    assert_eq!((keys[0].not_before, keys[0].not_after), (None, None));

    // `kid` is never believed: the key id is the computed thumbprint.
    let keys = parse_keys(S551_BODY.as_bytes()).unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].keyid, DRAFT_KEYID);
    assert_eq!((keys[0].not_before, keys[0].not_after), (Some(1_712_793_600), Some(1_715_385_600)));
}

#[test]
fn keys_of_other_types_are_skipped() {
    let body = keys_of(&[RSA_ENTRY.to_string(), ed_entry(1), r#"{"kty":"EC","crv":"P-256","x":"a","y":"b"}"#.to_string(), r#"{"kty":"OKP","crv":"X25519","x":"a"}"#.to_string(), ed_entry(2)]);
    let keys = parse_keys(body.as_bytes()).unwrap();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0].public, [1; 32]);
    assert_eq!(keys[1].public, [2; 32]);
}

#[test]
fn directories_that_are_refused_whole() {
    let mut many: Vec<String> = vec![RSA_ENTRY.to_string(); 64];
    many.push(ed_entry(1));
    let bad: Vec<String> = vec![
        String::new(),
        "not json".to_string(),
        "[]".to_string(),
        "{}".to_string(),
        r#"{"keys":{}}"#.to_string(),
        r#"{"keys":[]}"#.to_string(),
        // Nothing this gateway can use.
        keys_of(&[RSA_ENTRY.to_string()]),
        keys_of(&[r#"{"kty":"OKP","crv":"X25519","x":"a"}"#.to_string()]),
        // One malformed entry beside a good one.
        keys_of(&[ed_entry(1), "7".to_string()]),
        keys_of(&[ed_entry(1), "{}".to_string()]),
        keys_of(&[ed_entry(1), r#"{"kty":7}"#.to_string()]),
        keys_of(&[ed_entry(1), r#"{"kty":"OKP","crv":"Ed25519"}"#.to_string()]),
        keys_of(&[ed_entry(1), r#"{"kty":"OKP","crv":"Ed25519","x":"AAAA"}"#.to_string()]),
        keys_of(&[ed_entry(1), r#"{"kty":"OKP","crv":"Ed25519","x":"not base64 !"}"#.to_string()]),
        keys_of(&[ed_entry(1), format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{}","nbf":"soon"}}"#, URL_SAFE_NO_PAD.encode([2u8; 32]))]),
        // The same key twice.
        keys_of(&[ed_entry(1), ed_entry(1)]),
        // 65 entries.
        keys_of(&many),
    ];
    for body in &bad {
        match parse_keys(body.as_bytes()) {
            Err(FetchError::Directory(_)) => {}
            other => panic!("{body:.80} should be refused, got {other:?}"),
        }
    }
    assert!(matches!(parse_keys(&[0xff, 0xfe, b'{', b'}']), Err(FetchError::Directory(_))));

    // 64 entries is the limit, not past it.
    let mut most: Vec<String> = vec![RSA_ENTRY.to_string(); 63];
    most.push(ed_entry(1));
    assert_eq!(parse_keys(keys_of(&most).as_bytes()).unwrap().len(), 1);
}

// ---------- fetch ----------

struct Fake {
    addrs: Result<Vec<IpAddr>, String>,
    response: Result<Response, String>,
    resolved: RefCell<Vec<(String, u16)>>,
    gets: RefCell<Vec<(SocketAddr, String, usize, Duration)>>,
}

impl Fake {
    fn new(addrs: &[&str], status: u16, body: &[u8]) -> Fake {
        Fake {
            addrs: Ok(addrs.iter().map(|a| ip(a)).collect()),
            response: Ok(Response { status, cache_control: None, body: body.to_vec() }),
            resolved: RefCell::new(Vec::new()),
            gets: RefCell::new(Vec::new()),
        }
    }

    fn good(addrs: &[&str]) -> Fake {
        Fake::new(addrs, 200, E23_BODY.as_bytes())
    }
}

impl Transport for Fake {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, String> {
        self.resolved.borrow_mut().push((host.to_string(), port));
        self.addrs.clone()
    }

    fn get(&self, addr: SocketAddr, url: &DirectoryUrl, max_bytes: usize, timeout: Duration) -> Result<Response, String> {
        self.gets.borrow_mut().push((addr, url.as_string(), max_bytes, timeout));
        self.response.clone()
    }
}

const URL: &str = "https://agent.example/jwks.json";

fn fetch(fake: &Fake) -> Result<Fetched, FetchError> {
    fetch_with(fake, &url(URL), &FetchConfig::default())
}

#[test]
fn a_good_directory_is_fetched_once_from_a_checked_address() {
    let mut fake = Fake::good(&["93.184.216.34"]);
    if let Ok(r) = &mut fake.response {
        r.cache_control = Some("max-age=7200".to_string());
    }
    let fetched = fetch(&fake).unwrap();
    assert_eq!(fetched.keys.len(), 1);
    assert_eq!(fetched.keys[0].keyid, DRAFT_KEYID);
    assert_eq!(fetched.ttl_secs, 7200);
    assert_eq!(*fake.resolved.borrow(), vec![("agent.example".to_string(), 443)]);
    assert_eq!(
        *fake.gets.borrow(),
        vec![("93.184.216.34:443".parse().unwrap(), URL.to_string(), MAX_BODY_BYTES, FetchConfig::DEFAULT_TIMEOUT)]
    );

    // No Cache-Control: the default lifetime.
    assert_eq!(fetch(&Fake::good(&["93.184.216.34"])).unwrap().ttl_secs, DEFAULT_TTL_SECS);
}

#[test]
fn the_urls_port_and_the_configured_timeout_are_used() {
    let fake = Fake::good(&["2606:4700:4700::1111", "1.1.1.1"]);
    let config = FetchConfig { allow: Vec::new(), timeout: Duration::from_secs(2) };
    fetch_with(&fake, &url("https://agent.example:8443/k"), &config).unwrap();
    let gets = fake.gets.borrow();
    assert_eq!(gets.len(), 1);
    // The first resolved address, with the URL's port.
    assert_eq!(gets[0].0, "[2606:4700:4700::1111]:8443".parse().unwrap());
    assert_eq!(gets[0].3, Duration::from_secs(2));
    assert_eq!(*fake.resolved.borrow(), vec![("agent.example".to_string(), 8443)]);
}

#[test]
fn a_name_that_does_not_resolve() {
    let mut fake = Fake::good(&[]);
    assert!(matches!(fetch(&fake), Err(FetchError::Resolve(_))));
    fake.addrs = Err("no such host".to_string());
    assert!(matches!(fetch(&fake), Err(FetchError::Resolve(_))));
    assert!(fake.gets.borrow().is_empty());
}

#[test]
fn refused_addresses_are_never_connected_to() {
    for (addrs, refused) in [
        (vec!["127.0.0.1"], "127.0.0.1"),
        (vec!["10.0.0.5"], "10.0.0.5"),
        (vec!["192.168.1.1"], "192.168.1.1"),
        (vec!["169.254.169.254"], "169.254.169.254"),
        (vec!["::1"], "::1"),
        (vec!["fe80::1"], "fe80::1"),
        (vec!["::ffff:10.0.0.1"], "::ffff:10.0.0.1"),
        // One bad address among good ones refuses the fetch, wherever it is.
        (vec!["93.184.216.34", "127.0.0.1"], "127.0.0.1"),
        (vec!["93.184.216.34", "1.1.1.1", "10.1.1.1", "8.8.8.8"], "10.1.1.1"),
        // The first one that is refused is the one reported.
        (vec!["10.0.0.5", "127.0.0.1"], "10.0.0.5"),
    ] {
        let fake = Fake::good(&addrs);
        assert_eq!(fetch(&fake), Err(FetchError::AddressRefused(ip(refused))), "{addrs:?}");
        assert!(fake.gets.borrow().is_empty(), "{addrs:?}");
    }
}

#[test]
fn an_address_literal_is_checked_like_a_resolved_one() {
    let fake = Fake::good(&["127.0.0.1"]);
    let r = fetch_with(&fake, &url("https://127.0.0.1/k"), &FetchConfig::default());
    assert_eq!(r, Err(FetchError::AddressRefused(ip("127.0.0.1"))));
    assert_eq!(*fake.resolved.borrow(), vec![("127.0.0.1".to_string(), 443)]);
    assert!(fake.gets.borrow().is_empty());
}

#[test]
fn the_operator_can_allow_one_exact_address_and_port() {
    let allow = FetchConfig { allow: vec!["127.0.0.1:8443".parse().unwrap()], timeout: Duration::ZERO };

    let fake = Fake::good(&["127.0.0.1"]);
    assert!(fetch_with(&fake, &url("https://agent.test:8443/k"), &allow).is_ok());
    assert_eq!(fake.gets.borrow()[0].0, "127.0.0.1:8443".parse().unwrap());

    // Another port on the same address is not covered.
    let fake = Fake::good(&["127.0.0.1"]);
    assert_eq!(
        fetch_with(&fake, &url("https://agent.test:9000/k"), &allow),
        Err(FetchError::AddressRefused(ip("127.0.0.1")))
    );
    // Nor is another address on the same port.
    let fake = Fake::good(&["127.0.0.2"]);
    assert_eq!(
        fetch_with(&fake, &url("https://agent.test:8443/k"), &allow),
        Err(FetchError::AddressRefused(ip("127.0.0.2")))
    );
    // Nor does it excuse a second, different private address.
    let fake = Fake::good(&["127.0.0.1", "10.0.0.1"]);
    assert_eq!(
        fetch_with(&fake, &url("https://agent.test:8443/k"), &allow),
        Err(FetchError::AddressRefused(ip("10.0.0.1")))
    );
    assert!(fake.gets.borrow().is_empty());
}

#[test]
fn a_transport_failure_is_reported() {
    let mut fake = Fake::good(&["93.184.216.34"]);
    fake.response = Err("certificate not valid for agent.example".to_string());
    assert_eq!(fetch(&fake), Err(FetchError::Transport("certificate not valid for agent.example".to_string())));
    assert_eq!(fake.gets.borrow().len(), 1);
}

#[test]
fn only_status_200_is_a_directory() {
    // The body is a perfectly good directory each time: it must not matter.
    for status in [100u16, 201, 204, 206, 301, 302, 303, 307, 308, 304, 400, 401, 404, 429, 500, 503] {
        let fake = Fake::new(&["93.184.216.34"], status, E23_BODY.as_bytes());
        assert_eq!(fetch(&fake), Err(FetchError::Status(status)));
        // One request: nothing was followed or retried.
        assert_eq!(fake.gets.borrow().len(), 1);
    }
}

#[test]
fn the_body_is_capped() {
    // Valid JSON padded with spaces to exactly the limit is accepted.
    let mut body = E23_BODY.as_bytes().to_vec();
    body.resize(MAX_BODY_BYTES, b' ');
    assert!(fetch(&Fake::new(&["93.184.216.34"], 200, &body)).is_ok());
    // One byte more is refused before it is parsed.
    body.push(b' ');
    assert_eq!(fetch(&Fake::new(&["93.184.216.34"], 200, &body)), Err(FetchError::TooLarge));
}

#[test]
fn a_body_that_is_not_a_directory() {
    for body in ["<html>moved</html>", "", r#"{"keys":[]}"#] {
        let fake = Fake::new(&["93.184.216.34"], 200, body.as_bytes());
        assert!(matches!(fetch(&fake), Err(FetchError::Directory(_))), "{body:?}");
    }
}

// ---------- cache ----------

const T: u64 = 1_800_000_000;

fn fetched(seed: u8, ttl_secs: u64) -> Fetched {
    Fetched { keys: vec![Ed25519Key::from_public([seed; 32])], ttl_secs }
}

fn seeds(cache: &Cache, now: u64) -> Vec<u8> {
    cache.keys(now).iter().map(|k| k.public[0]).collect()
}

#[test]
fn a_new_cache_wants_a_fetch_and_has_no_keys() {
    let c = Cache::new();
    assert!(c.due(0));
    assert!(c.due(T));
    assert!(c.keys(T).is_empty());
}

#[test]
fn a_success_is_used_until_its_lifetime_ends() {
    let mut c = Cache::new();
    c.on_success(fetched(1, 3600), T);
    assert!(!c.due(T));
    assert!(!c.due(T + 3599));
    assert!(c.due(T + 3600));
    assert_eq!(seeds(&c, T), [1]);
    assert_eq!(seeds(&c, T + 3600), [1]);
}

#[test]
fn a_failure_keeps_the_keys_and_waits_before_trying_again() {
    let mut c = Cache::new();
    c.on_success(fetched(1, 3600), T);
    c.on_failure(T + 3600);
    assert!(!c.due(T + 3600));
    assert!(!c.due(T + 3600 + RETRY_SECS - 1));
    assert!(c.due(T + 3600 + RETRY_SECS));
    assert_eq!(seeds(&c, T + 3600 + RETRY_SECS), [1]);
}

#[test]
fn failures_do_not_keep_keys_alive_for_ever() {
    let mut c = Cache::new();
    c.on_success(fetched(1, 3600), T);
    let end = T + 3600 + MAX_STALE_SECS;
    let mut now = T + 3600;
    while now < end {
        c.on_failure(now);
        assert_eq!(seeds(&c, now), [1], "at {now}");
        now += 6 * 3600;
    }
    assert_eq!(seeds(&c, end - 1), [1]);
    assert!(c.keys(end + 1).is_empty());
    c.on_failure(end + 1);
    assert!(c.keys(end + 2).is_empty());
    // A success brings keys back.
    c.on_success(fetched(2, 600), end + 400);
    assert_eq!(seeds(&c, end + 400), [2]);
    assert!(!c.due(end + 999));
    assert!(c.due(end + 1000));
}

#[test]
fn a_success_replaces_every_key() {
    let mut c = Cache::new();
    c.on_success(Fetched { keys: vec![Ed25519Key::from_public([1; 32]), Ed25519Key::from_public([2; 32])], ttl_secs: 3600 }, T);
    assert_eq!(seeds(&c, T), [1, 2]);
    c.on_success(fetched(3, 900), T + 4000);
    assert_eq!(seeds(&c, T + 4000), [3]);
    assert!(!c.due(T + 4899));
    assert!(c.due(T + 4900));
}

#[test]
fn a_failure_before_any_success() {
    let mut c = Cache::new();
    c.on_failure(T);
    assert!(!c.due(T + RETRY_SECS - 1));
    assert!(c.due(T + RETRY_SECS));
    assert!(c.keys(T + RETRY_SECS).is_empty());
}

#[test]
fn a_clock_that_steps_back_and_the_end_of_time() {
    let mut c = Cache::new();
    c.on_success(fetched(1, 3600), T);
    assert!(!c.due(T - 1000));
    assert!(!c.due(0));
    assert_eq!(seeds(&c, 0), [1]);

    let mut c = Cache::new();
    c.on_success(fetched(1, MAX_TTL_SECS), u64::MAX - 10);
    let _ = c.due(u64::MAX);
    assert_eq!(seeds(&c, u64::MAX), [1]);
    c.on_failure(u64::MAX);
    let _ = c.due(u64::MAX);
    let _ = c.keys(u64::MAX);
}
