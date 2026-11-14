//! The router, `request_filter`, driven with real HTTP/1.1 requests over an
//! in-memory stream, so these paths have unit tests and not only
//! `scripts/e2e.sh`. A stream that reports a TLS digest takes the gateway's
//! own path; one without takes the sidecar's, as the plain listener does.

use super::*;
use async_trait::async_trait;
use pingora::protocols::l4::socket::SocketAddr as PingoraAddr;
use pingora::protocols::raw_connect::ProxyDigest;
use pingora::protocols::tls::SslDigest;
use pingora::protocols::{
    GetProxyDigest, GetSocketDigest, GetTimingDigest, Peek, Shutdown, SocketDigest, Ssl, TimingDigest, UniqueID,
    UniqueIDType,
};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use veritell_events::MemoryRing;

const SECRET: &[u8] = b"router-test-secret-router-test-secret!!";
const KNOWN_KEY: &[u8] = b"router-known-key-router-known-key-0123";

/// The gateway's end of an in-memory connection: TLS or plain, from 203.0.113.9.
#[derive(Debug)]
struct Conn {
    io: DuplexStream,
    tls: bool,
}

impl AsyncRead for Conn {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for Conn {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

#[async_trait]
impl Shutdown for Conn {
    async fn shutdown(&mut self) {}
}
impl UniqueID for Conn {
    fn id(&self) -> UniqueIDType {
        1
    }
}
impl Ssl for Conn {
    fn get_ssl_digest(&self) -> Option<Arc<SslDigest>> {
        self.tls.then(|| Arc::new(SslDigest::new("TLS_AES_128_GCM_SHA256", "TLSv1.3", None, None, Vec::new())))
    }
}
impl GetTimingDigest for Conn {
    fn get_timing_digest(&self) -> Vec<Option<TimingDigest>> {
        Vec::new()
    }
}
impl GetProxyDigest for Conn {
    fn get_proxy_digest(&self) -> Option<Arc<ProxyDigest>> {
        None
    }
}
impl GetSocketDigest for Conn {
    fn get_socket_digest(&self) -> Option<Arc<SocketDigest>> {
        let d = SocketDigest::from_raw_fd(0);
        let _ = d.peer_addr.set(Some(PingoraAddr::Inet("203.0.113.9:40000".parse().unwrap())));
        Some(Arc::new(d))
    }
}
impl Peek for Conn {}

/// A gateway as main builds it, with test keys, the default shadow policy
/// unless one is given, no upstream (a passed request gets the score report),
/// and its events in a ring the test can read.
fn gateway(policy: Policy, trusted_proxies: Vec<IpAddr>) -> (Gateway, Arc<MemoryRing>) {
    let ring = Arc::new(MemoryRing::new(1000));
    let builder = veritell_probe_build::Builder::new(probe::TEMPLATE, SECRET).unwrap();
    let engine_truth = veritell_probe::parse_truth(crate::BUILTIN_ENGINE_TRUTH).unwrap();
    let g = Gateway {
        upstream: None,
        host_upstreams: Default::default(),
        upstream_tls: false,
        upstream_sni: None,
        upstream_ca: None,
        forwarded_replace: false,
        policy,
        data: Arc::new(LiveData {
            truth: veritell_feed::Live::new(veritell_ua::TruthTable::builtin()),
            engine_truth: veritell_feed::Live::new(engine_truth),
        }),
        probe_builds: Arc::new(ProbeBuilds::new(builder, Duration::from_secs(60), 300)),
        crawlers: CrawlerVerifier::new(SystemResolver::new(Duration::from_millis(100), 4)),
        asn: AsnDb::empty(),
        keys: Keys::from_secret(SECRET).unwrap(),
        token_budgets: Arc::new(MemoryBudgetStore::new(1000)),
        used_challenges: Arc::new(MemoryBudgetStore::new(1000)),
        throttle: Throttle::new(1000),
        token_budget: 500,
        probe_key: ProbeKey::from_secret(SECRET).unwrap(),
        probes: Arc::new(ProbeStore::new(1000)),
        used_nonces: Arc::new(MemoryBudgetStore::new(1000)),
        agents: Arc::new(veritell_feed::Live::new(TrustedAgents::new())),
        wba_replays: Arc::new(std::sync::Mutex::new(ReplayCache::new(100))),
        quotas: Arc::new(veritell_quota::Quotas::new(veritell_quota::Config::default()).unwrap()),
        events: ring.clone(),
        behaviors: BehaviorStore::new(1000),
        behavior_params: veritell_behavior::Params::default(),
        used_behavior_nonces: Arc::new(MemoryBudgetStore::new(1000)),
        agg: Aggregates::new(veritell_agg::Config::default()).unwrap(),
        trusted_proxies,
        model: None,
        share: None,
        pass: None,
        addr: veritell_events::addr::AddrRedactor::new(veritell_events::addr::AddrMode::Full),
        known_key: Some(crate::known::KnownKey::new(KNOWN_KEY)),
        inject_probe: false,
        log_requests: false,
        body_timeout: Duration::from_secs(2),
        write_timeout: Duration::from_secs(2),
        source_link: String::new(),
    };
    (g, ring)
}

/// Sends `request` (raw HTTP/1.1) and returns the status, the response head
/// in lowercase, the body, and whether the router handled it itself.
async fn send(g: &Gateway, request: &str, tls: bool) -> (u16, String, String, bool) {
    let (mut client, server) = tokio::io::duplex(1 << 20);
    client.write_all(request.as_bytes()).await.unwrap();
    let mut session = Session::new_h1(Box::new(Conn { io: server, tls }));
    assert!(session.read_request().await.unwrap(), "the request is read");
    let mut ctx = g.new_ctx();
    let handled = g.request_filter(&mut session, &mut ctx).await.unwrap();
    let _ = session.finish_body().await;
    drop(session);
    let mut raw = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut raw)).await;
    let text = String::from_utf8_lossy(&raw).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    (status, head.to_ascii_lowercase(), body.to_string(), handled)
}

fn get(path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: shop.test\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15\r\nConnection: close\r\n\r\n")
}

fn post(path: &str, body: &str) -> String {
    format!(
        "POST {path} HTTP/1.1\r\nHost: shop.test\r\nUser-Agent: curl/8.7.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn outcomes(ring: &MemoryRing) -> Vec<String> {
    ring.events().into_iter().map(|e| e.outcome).collect()
}

#[tokio::test]
async fn a_page_passes_in_shadow_mode_and_is_logged() {
    let (g, ring) = gateway(Policy::default_shadow(), Vec::new());
    let (status, head, body, handled) = send(&g, &get("/catalog?page=2"), true).await;
    assert!(handled, "no upstream: the router answers itself");
    assert_eq!(status, 200, "{head}");
    assert!(body.contains("\"class\""), "the score report: {body}");
    assert_eq!(outcomes(&ring), ["passed"]);
    let e = &ring.events()[0];
    assert_eq!((e.path.as_str(), e.method.as_str()), ("/catalog", "GET"));
    assert_eq!(e.token, "none");
}

#[tokio::test]
async fn the_gateway_paths_answer_only_their_method() {
    let (g, ring) = gateway(Policy::default_shadow(), Vec::new());
    for (request, want) in [
        (post(CHALLENGE_PATH, ""), 405),
        (get(VERIFY_PATH), 405),
        (post(probe::SCRIPT_PATH, ""), 405),
        (get(probe::REPORT_PATH), 405),
        (post(behavior::SCRIPT_PATH, ""), 405),
        (get(behavior::REPORT_PATH), 405),
    ] {
        let (status, head, _, handled) = send(&g, &request, true).await;
        assert!(handled);
        assert_eq!(status, want, "{}: {head}", request.lines().next().unwrap());
    }
    assert!(ring.events().is_empty(), "a wrong method is not an assessed request");
}

#[tokio::test]
async fn the_scripts_are_served_with_a_fresh_nonce() {
    let (g, _) = gateway(Policy::default_shadow(), Vec::new());
    for path in [probe::SCRIPT_PATH, behavior::SCRIPT_PATH] {
        let (status, head, body, _) = send(&g, &get(path), true).await;
        assert_eq!(status, 200, "{path}");
        assert!(head.contains("content-type: text/javascript"), "{path}: {head}");
        assert!(!body.is_empty());
    }
    let (_, _, a, _) = send(&g, &get(behavior::SCRIPT_PATH), true).await;
    let (_, _, b, _) = send(&g, &get(behavior::SCRIPT_PATH), true).await;
    assert_ne!(a, b, "each script carries its own nonce");
}

#[tokio::test]
async fn junk_reports_are_refused_with_their_reason() {
    let (g, ring) = gateway(Policy::default_shadow(), Vec::new());
    let (status, _, _, _) = send(&g, &post(probe::REPORT_PATH, "not a sealed report"), true).await;
    assert_eq!(status, 403);
    let (status, _, _, _) = send(&g, &post(behavior::REPORT_PATH, "{}"), true).await;
    assert_eq!(status, 403);
    assert_eq!(outcomes(&ring), ["probe_malformed", "behavior_malformed"]);
    // The forged probe report leaves evidence on the client (Refusal::is_forgery).
    assert_eq!(ring.events()[0].detections.iter().map(|d| d.id.as_str()).collect::<Vec<_>>(), [probe::FORGED]);
}

#[tokio::test]
async fn a_known_person_link_sets_the_mark_and_a_forged_one_does_not() {
    use hmac::{Hmac, Mac};
    let (g, _) = gateway(Policy::default_shadow(), Vec::new());
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(KNOWN_KEY).unwrap();
    mac.update(b"veritell-known\0p07-test");
    let hex: String = mac.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect();
    let (status, head, body, handled) = send(&g, &get(&format!("/__veritell/known/p07-test/{}", &hex[..32])), true).await;
    assert!(handled);
    assert_eq!(status, 200);
    assert!(head.contains("set-cookie: __host-veritell-known=p07-test."), "{head}");
    assert!(body.contains("p07-test"));
    let (_, head, _, _) = send(&g, &get(&format!("/__veritell/known/p07-test/{}", "0".repeat(32))), true).await;
    assert!(!head.contains("set-cookie: __host-veritell-known"), "a forged link marks nothing");
}

#[tokio::test]
async fn an_enforcing_policy_challenges_and_its_open_route_passes() {
    let policy = Policy::from_yaml(
        "mode: enforce\nroutes:\n  - name: open\n    match: path.startsWith(\"/open\")\n    rules: []\n  - name: rest\n    rules:\n      - when: score < 101\n        action: challenge(pow)\n",
    )
    .unwrap();
    let (g, ring) = gateway(policy, Vec::new());
    let (status, head, body, handled) = send(&g, &get("/cart"), true).await;
    assert!(handled);
    assert_eq!(status, 403, "{head}");
    assert!(body.contains(CHALLENGE_PATH) || body.contains("challenge"), "the challenge page");
    let (status, _, _, _) = send(&g, &get("/open/page"), true).await;
    assert_eq!(status, 200, "the open route passes");
    assert_eq!(outcomes(&ring), ["challenged", "passed"]);
}

#[tokio::test]
async fn the_plain_listener_serves_only_the_sidecar_endpoint() {
    let (g, _) = gateway(Policy::default_shadow(), Vec::new());
    let (status, _, _, handled) = send(&g, &get("/catalog"), false).await;
    assert!(handled);
    assert_eq!(status, 404, "only the authorization endpoint is served without TLS");
    let (status, _, _, _) = send(&g, &get(AUTHZ_PATH), false).await;
    assert_eq!(status, 403, "a peer that is not a trusted proxy is refused");

    let trusted = vec!["203.0.113.9".parse().unwrap()];
    let (g, _) = gateway(Policy::default_shadow(), trusted);
    let (status, _, body, _) = send(&g, &get(AUTHZ_PATH), false).await;
    assert_eq!(status, 400, "a trusted peer that names no original request: {body}");
    let request = format!(
        "GET {AUTHZ_PATH} HTTP/1.1\r\nHost: shop.test\r\nX-Original-URI: /cart\r\nX-Original-Method: GET\r\nX-Forwarded-For: 198.51.100.4\r\nUser-Agent: curl/8.7.1\r\nConnection: close\r\n\r\n"
    );
    let (status, head, _, _) = send(&g, &request, false).await;
    assert_eq!(status, 200, "shadow mode allows: {head}");
}
