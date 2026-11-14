//! The request path: gather facts, score, apply policy, act, log.

use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::prelude::*;

use std::sync::Arc;

use veritell_core::{score_proven, Action, ChallengeKind, Class, Detection, Layer, Proven, Verdict};
use veritell_events::{Event, EventKind, EventSink};
use veritell_identity::{AsnDb, CrawlerVerdict, CrawlerVerifier, NetClass};
use veritell_probe::{NonceError, ProbeKey};
use veritell_probe_build::OpenError;
use veritell_policy::{Decision, Policy, PolicyInput, NO_QUOTA};
use veritell_token::pow::{self, VERIFY_PATH};
use veritell_token::{Binding, Consumed, Keys, MemoryBudgetStore};
use veritell_ua::Observed;
use veritell_wba::{ReplayCache, RequestParts, SignatureInfo, TrustedAgents, WbaVerdict};

use veritell_agg::{Aggregates, Observation};

use crate::behavior::{self, BehaviorStore};
use crate::conn::conn_info;
use crate::maintenance::{LiveData, ProbeBuilds};
use crate::pass::{PrivacyPass, Redemption};
use crate::probe::{self, ProbeStore};
use crate::util::{cookie_value, parse_form, SystemResolver, Throttle};

/// `__Host-`: browsers keep it only when Secure, on Path=/ and without Domain.
pub const COOKIE_NAME: &str = "__Host-veritell";
const TOKEN_TTL_SECS: u64 = 1800;
const TOKEN_BUDGET: u32 = 500;
const CHALLENGE_TTL_SECS: u64 = 120;
const MAX_FORM_BYTES: usize = 8 * 1024;
const TARPIT_DELAY: Duration = Duration::from_secs(5);
const HEADER_PREFIX: &str = "x-veritell-";
/// How long a challenge page waits for a browser to come back with a
/// Privacy Pass token. Safari took about 0.3 s on an iPhone (Phase 3, L20).
const TOKEN_WAIT_MS: u32 = 1500;

/// Whether a client may answer a `PrivateToken` challenge: Safari, or another
/// browser on Apple's WebKit. Only used to decide whether a challenge page
/// waits for it; nothing is trusted on it.
fn may_hold_token(user_agent: Option<&str>) -> bool {
    user_agent.is_some_and(|ua| {
        ua.contains("AppleWebKit/") && !ua.contains("Chrome/") && !ua.contains("Android")
    })
}
pub(crate) const PROBE_NONCE_TTL_SECS: u64 = 120;
/// A probe result outlives the token issued alongside it.
const PROBE_RESULT_TTL_SECS: u64 = TOKEN_TTL_SECS + CHALLENGE_TTL_SECS;
/// A behaviour nonce must outlive a long stay on one page.
const BEHAVIOR_NONCE_TTL_SECS: u64 = TOKEN_TTL_SECS;
const BEHAVIOR_RESULT_TTL_SECS: u64 = TOKEN_TTL_SECS + CHALLENGE_TTL_SECS;
/// Longest client-chosen text copied into an event.
const MAX_EVENT_TEXT: usize = 512;

pub struct Gateway {
    pub upstream: Option<(String, u16)>,
    /// Plain-HTTP upstreams by request host name (`--upstream-host
    /// name=host:port`), lower case. A request for any other name goes to
    /// `upstream`.
    pub host_upstreams: std::collections::HashMap<String, (String, u16)>,
    /// Speak TLS to the upstream (`--upstream-tls on`). The certificate and
    /// its name are always checked.
    pub upstream_tls: bool,
    /// SNI for a request with no usable host name (`--upstream-sni`).
    pub upstream_sni: Option<String>,
    /// Roots to check the upstream with (`--upstream-ca`), parsed once at
    /// start; `None` means the system roots.
    pub upstream_ca: Option<Arc<Box<[boring::x509::X509]>>>,
    /// `--forwarded-for replace`: the origin gets only the address the
    /// gateway saw in `x-forwarded-for`, and whatever the client wrote there
    /// (and in `forwarded` and `x-forwarded-host`) is dropped. `x-real-ip` is
    /// the gateway's view of the client in both modes. For a gateway that
    /// is the first hop: an origin that reads `x-forwarded-for` from the left
    /// (Caddy before 2.8, by default) then cannot be given a made-up address.
    pub forwarded_replace: bool,
    pub policy: Policy,
    /// Truth tables, replaceable by a feed while running.
    pub data: Arc<LiveData>,
    pub probe_builds: Arc<ProbeBuilds>,
    pub crawlers: CrawlerVerifier<SystemResolver>,
    pub asn: AsnDb,
    pub keys: Keys,
    pub token_budgets: Arc<MemoryBudgetStore>,
    pub used_challenges: Arc<MemoryBudgetStore>,
    pub throttle: Throttle,
    /// Token budget per issued token (overridable for tests).
    pub token_budget: u32,
    pub probe_key: ProbeKey,
    pub probes: Arc<ProbeStore>,
    pub used_nonces: Arc<MemoryBudgetStore>,
    /// Agents whose signatures are believed. Replaced as a whole when a
    /// fetched key directory changes.
    pub agents: Arc<veritell_feed::Live<TrustedAgents>>,
    /// Signatures of verified agents already seen, so that a captured
    /// signed request cannot be sent again as that agent.
    /// Shared with the state saver, so a restart keeps it.
    pub wba_replays: Arc<std::sync::Mutex<ReplayCache>>,
    /// Rate and daily quota per proven identity.
    pub quotas: Arc<veritell_quota::Quotas>,
    pub events: Arc<dyn EventSink>,
    pub behaviors: BehaviorStore,
    pub behavior_params: veritell_behavior::Params,
    pub used_behavior_nonces: Arc<MemoryBudgetStore>,
    /// Population counters and reputation entries.
    pub agg: Aggregates,
    /// Peers whose `x-forwarded-for` is believed. Empty by default.
    pub trusted_proxies: Vec<IpAddr>,
    /// A model evaluated beside the rules. It changes no action.
    pub model: Option<ShadowModel>,
    /// Sharing with other installs, when configured.
    pub share: Option<Arc<crate::share::Sharing>>,
    /// Privacy Pass issuers whose tokens waive the proof of work, if any.
    pub pass: Option<PrivacyPass>,
    /// What is written for a client address in logs and events. Scoring and
    /// policy always see the real address.
    pub addr: veritell_events::addr::AddrRedactor,
    /// Signs known-person marks; `None` turns them off.
    pub known_key: Option<crate::known::KnownKey>,
    /// Adds the probe and behaviour scripts to the origin's pages.
    pub inject_probe: bool,
    /// `--log-requests off`: no line per request, probe or behaviour report
    /// on standard output. The event store has them all, and deletes them
    /// after its retention; a container log is only rotated by size, so on
    /// a quiet site it would keep them for longer. Operational messages
    /// still go out.
    pub log_requests: bool,
    /// `--body-timeout`: the time a request body has to arrive in full.
    pub body_timeout: Duration,
    /// `--write-timeout`: the longest one write to a client may wait.
    pub write_timeout: Duration,
    /// What goes before `</body>` on the gateway's own pages: a link to the
    /// source (`--source-url`), then `</body>`. Just `</body>` with `off`.
    pub source_link: String,
}

/// A loaded model with the feature definition it was trained on.
pub struct ShadowModel {
    pub model: veritell_model::Model,
    pub features: veritell_model::FeatureSpec,
}

/// What the model said about one request.
struct ModelOpinion {
    score: u8,
    probability: f64,
    /// The features that moved the result most, with how far.
    top: Vec<(String, f64)>,
}

impl ModelOpinion {
    fn to_json(&self) -> serde_json::Value {
        let top: Vec<serde_json::Value> = self
            .top
            .iter()
            .map(|(name, by)| serde_json::json!({ "feature": name, "by": (by * 1000.0).round() / 1000.0 }))
            .collect();
        serde_json::json!({
            "score": self.score,
            "probability": (self.probability * 1000.0).round() / 1000.0,
            "top": top,
        })
    }
}

pub const AUTHZ_PATH: &str = "/__veritell/authz";
pub const CHALLENGE_PATH: &str = "/__veritell/challenge";
/// Headers a proxy adds for the authorization endpoint. They are not the
/// client's and are left out of what is scored.
const SIDECAR_HEADERS: [&str; 7] = [
    "x-original-uri",
    "x-original-method",
    "x-original-host",
    "x-forwarded-uri",
    "x-forwarded-method",
    "x-forwarded-host",
    "x-forwarded-for",
];

/// The client's request as a sidecar proxy describes it.
#[derive(Debug, PartialEq, Eq)]
struct Original {
    uri: String,
    method: String,
    host: String,
}

#[derive(Debug, PartialEq, Eq)]
enum SidecarError {
    /// No original URI, or one that is not a path.
    Missing,
    /// `X-Original-*` and `X-Forwarded-*` both given, with different values.
    Conflict,
}

/// Reads the original request from a sidecar call. `get` reads one request
/// header; `suffix` is the path and query after the endpoint path, if the
/// proxy put it there (Envoy), and `own_method` the call's method.
///
/// Caddy and Traefik set `X-Forwarded-*` and pass the client's other headers
/// through, so a client can add its own `X-Original-*`; nginx sets
/// `X-Original-*` and passes a client's `X-Forwarded-*`. A value is taken
/// from either, but when both are present they must agree: otherwise one of
/// them is the client's, and the call is refused.
fn original_request(
    get: impl Fn(&str) -> Option<String>,
    suffix: Option<String>,
    own_method: &str,
) -> std::result::Result<Original, SidecarError> {
    let pick = |name: &str, same: fn(&str, &str) -> bool| {
        let (a, b) = (get(&format!("x-original-{name}")), get(&format!("x-forwarded-{name}")));
        match (a, b) {
            (Some(a), Some(b)) if !same(&a, &b) => Err(SidecarError::Conflict),
            (a, b) => Ok(b.or(a)),
        }
    };
    let exact = |a: &str, b: &str| a == b;
    let same_host = |a: &str, b: &str| {
        let name = |h: &str| host_name(h).map(|n| n.trim_end_matches('.').to_ascii_lowercase());
        name(a) == name(b)
    };
    // With the path in the call itself, the call's method is the client's.
    let (uri, method) = match suffix {
        Some(uri) => (Some(uri), Some(own_method.to_string())),
        None => (pick("uri", exact)?, pick("method", exact)?),
    };
    let uri = uri.filter(|u| u.starts_with('/')).ok_or(SidecarError::Missing)?;
    let host = pick("host", same_host)?.or_else(|| get("host")).unwrap_or_default();
    Ok(Original { uri, method: method.unwrap_or_else(|| "GET".to_string()), host })
}

impl Gateway {
    pub fn default_token_budget() -> u32 {
        TOKEN_BUDGET
    }
}

/// Carried from the request filter to the upstream filter.
#[derive(Default)]
pub struct Ctx {
    upstream_headers: Vec<(&'static str, String)>,
    /// The address of the connection's peer, appended to `x-forwarded-for`
    /// for the origin, as nginx's `$proxy_add_x_forwarded_for` does.
    peer_ip: Option<IpAddr>,
    /// The client's address as the gateway decided it: the peer, or what a
    /// trusted proxy reported. Sent to the origin as `x-real-ip`.
    client_ip: Option<IpAddr>,
    /// The peer is a trusted proxy, so the forwarding headers are its own.
    behind_proxy: bool,
    /// Passive probe injection: see the state machine in `inject.rs`.
    injection: crate::inject::Injection,
    /// When the request's headers were in: its body must follow within
    /// `--body-timeout`.
    request_started: Option<std::time::Instant>,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// The part of a JA4 fingerprint that is the same on every connection from
/// one client: protocol, TLS version and SNI flag, and the cipher hash.
///
/// The rest changes when a browser resumes a TLS session: a resumed
/// handshake carries a pre-shared-key extension, which alters the extension
/// count and the extension hash. Binding to the full string made a token or
/// a probe nonce fail when the browser used a second connection.
fn stable_ja4(ja4: &str) -> String {
    let mut parts = ja4.split('_');
    let head: String = parts.next().unwrap_or("").chars().take(4).collect();
    let ciphers = parts.next().unwrap_or("");
    format!("{head}_{ciphers}")
}

/// Cuts client-chosen text to a bounded length on a character boundary.
fn bounded(text: &str) -> String {
    text.chars().take(MAX_EVENT_TEXT).collect()
}

/// Whether a single-use id may be used now. A full store refuses: anyone can
/// fill it, and letting the use through would turn single use off.
/// A request body of at most `max` bytes, read within `limit` of now (the
/// request's headers are in). `Ok(None)` when it is larger; an error when it
/// is too slow, which closes the connection.
async fn read_body(session: &mut Session, max: usize, limit: Duration) -> Result<Option<Vec<u8>>> {
    let until = tokio::time::Instant::now() + limit;
    let mut body: Vec<u8> = Vec::new();
    loop {
        let chunk = match tokio::time::timeout_at(until, session.read_request_body()).await {
            Ok(chunk) => chunk?,
            Err(_) => return Err(Error::explain(ErrorType::ReadTimedout, "request body not complete in time")),
        };
        let Some(chunk) = chunk else { return Ok(Some(body)) };
        if body.len().saturating_add(chunk.len()) > max {
            return Ok(None);
        }
        body.extend_from_slice(&chunk);
    }
}

/// The User-Agent with the crawler name a `ua_declared_bot` detection names
/// (its detail ends ": <name>") swapped for a made-up one, so the table runs
/// the checks it runs for a crawler it doesn't know. `None` when the name
/// isn't found in the User-Agent as written.
fn without_bot_claim(user_agent: &str, detail: &str) -> Option<String> {
    let name = detail.rsplit_once(": ")?.1;
    if name.is_empty() || !user_agent.contains(name) {
        return None;
    }
    Some(user_agent.replacen(name, "Unverifiedbot", 1))
}

/// The closing `</body>` of a page the gateway serves, after a footer: who
/// made it ("Powered by Veritell") and a link to its source. `None` for a URL that isn't plain http(s) without spaces or
/// quotes; the caller refuses it.
pub fn source_link(url: &str) -> Option<String> {
    let ok = (url.starts_with("https://") || url.starts_with("http://"))
        && url.len() <= 512
        && !url.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, '"' | '<' | '>' | '\'' | '`'));
    ok.then(|| {
        let url = url.replace('&', "&amp;");
        format!(
            "<p class=\"source\">Powered by <a href=\"https://veritell.io\">Veritell</a> · \
             <a href=\"{url}\">Source code</a> (AGPL-3.0)</p>\n</body>"
        )
    })
}

/// What is actually done with a decision: nothing in shadow mode; a
/// challenge is waived for a valid token; a throttle applies only when
/// `allow` (asked with the rate) says the client is over it; a charge is
/// waived when the request claims a receipt.
fn effective_action(
    d: &Decision,
    has_token: bool,
    receipt_claimed: bool,
    allow: impl FnOnce(u32) -> bool,
) -> Action {
    match d.action {
        _ if !d.enforced => Action::Pass,
        Action::Challenge(_) if has_token => Action::Pass,
        Action::Throttle { per_minute } => {
            if allow(per_minute) { Action::Pass } else { d.action }
        }
        Action::Charge if receipt_claimed => Action::Pass,
        other => other,
    }
}

/// The challenge a verify form solves, when the solution is right for this
/// client and the challenge has not been used. Single use: the same
/// solution cannot mint a second token. A full store cannot tell a replay,
/// so it refuses.
fn check_solution(
    keys: &Keys,
    used: &MemoryBudgetStore,
    form: &std::collections::HashMap<String, String>,
    binding: &Binding,
    now: u64,
) -> Option<pow::Solved> {
    form.get("challenge")
        .zip(form.get("counter").and_then(|c| c.parse::<u64>().ok()))
        .and_then(|(challenge, counter)| pow::verify_solution(keys, challenge, counter, binding, now).ok())
        .filter(|s| admitted(used.try_consume(&s.id, 1, s.expires_at, now), "solved challenges"))
}

/// The level the authorization endpoint set for a challenge link: the
/// difficulty of the challenge it signed and the proxy passed on as `c`.
/// `None` without one, or for a string that isn't ours.
fn link_difficulty(keys: &Keys, query: &std::collections::HashMap<String, String>) -> Option<u8> {
    query.get("c").and_then(|c| pow::issued_difficulty(keys, c))
}

/// The difficulty for a fresh challenge after a failed one: the failed
/// one's own level. A string that is not one of ours gets the hardest.
fn retry_difficulty(keys: &Keys, form: &std::collections::HashMap<String, String>) -> u8 {
    form.get("challenge")
        .and_then(|c| pow::issued_difficulty(keys, c))
        .unwrap_or_else(|| pow::difficulty_for_score(1))
}

fn admitted(consumed: Consumed, store: &str) -> bool {
    if consumed == Consumed::Full {
        note_full(store);
    }
    consumed == Consumed::Used
}

/// Says on standard error that a store is full, at most once a minute.
fn note_full(store: &str) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static LAST_MINUTE: AtomicU64 = AtomicU64::new(0);
    let minute = now_secs() / 60;
    if LAST_MINUTE.swap(minute, Ordering::Relaxed) != minute {
        eprintln!("veritell: the {store} store is full; new uses are refused until entries expire");
    }
}

fn header<'a>(req: &'a RequestHeader, name: &str) -> Option<&'a str> {
    req.headers.get(name).and_then(|v| v.to_str().ok())
}

/// The host name of a `Host` / `:authority` value: no port, no brackets of an
/// IPv6 literal. `None` when nothing is left.
fn host_name(authority: &str) -> Option<&str> {
    let a = authority.trim();
    let host = match a.strip_prefix('[') {
        Some(rest) => rest.split(']').next()?,
        // More than one colon without brackets is a bare IPv6 address.
        None if a.matches(':').count() > 1 => a,
        None => a.rsplit_once(':').map_or(a, |(h, _)| h),
    };
    (!host.is_empty()).then_some(host)
}

/// The SNI (and the name the certificate is checked against) for the
/// upstream: the request's host name; if that is missing or an IP address,
/// `--upstream-sni`; if there is none, the upstream's own host.
fn upstream_sni(authority: Option<&str>, configured: Option<&str>, upstream_host: &str) -> String {
    authority
        .and_then(host_name)
        .filter(|h| h.parse::<IpAddr>().is_err())
        .or(configured)
        .unwrap_or(upstream_host)
        .to_string()
}

/// Every `cookie` field, joined with `"; "`. Over HTTP/2 a client may send
/// its cookies as several fields (RFC 9113, section 8.2.3), and the server
/// must read them as one; taking the first field would lose the rest.
fn cookies(req: &RequestHeader) -> Option<String> {
    join_cookie_fields(req.headers.get_all("cookie").iter().filter_map(|v| v.to_str().ok()))
}

fn join_cookie_fields<'a>(fields: impl Iterator<Item = &'a str>) -> Option<String> {
    let parts: Vec<&str> = fields.map(str::trim).filter(|f| !f.is_empty()).collect();
    (!parts.is_empty()).then(|| parts.join("; "))
}

struct Facts {
    ip: IpAddr,
    method: String,
    host: String,
    path: String,
    path_and_query: String,
    user_agent: Option<String>,
    ja4: Option<String>,
    h2: Option<String>,
    header_names: Vec<String>,
    cookie: Option<String>,
    authority: String,
    query: Option<String>,
    /// Every header, collected only when the request carries a signature.
    signed_headers: Vec<(String, String)>,
    authorization: Option<String>,
    /// `sec-fetch-mode`, as the browser sent it.
    fetch_mode: Option<String>,
    /// A known-person label from a valid mark, or "". Written to logs and
    /// events only: nothing that scores or decides reads it.
    known: String,
    /// The client's TCP SYN, where it was measured. Logged and stored only:
    /// nothing that scores or decides reads it.
    syn: Option<crate::syn::SynSeen>,
}

impl Facts {
    /// Whether the request loads a page. Without `sec-fetch-mode` it is
    /// taken to: an older browser gets the page, as before.
    fn is_navigation(&self) -> bool {
        self.fetch_mode.as_deref().is_none_or(|m| m.eq_ignore_ascii_case("navigate"))
    }
}

/// The client address a trusted proxy reports: the last entry of
/// `x-forwarded-for`, which is the one that proxy appended itself.
fn forwarded_ip(value: &str) -> Option<IpAddr> {
    value.rsplit(',').next()?.trim().parse().ok().map(canonical)
}

/// The last entry over every `x-forwarded-for` line, read in order. A proxy
/// may add its own line instead of extending the client's (HAProxy does),
/// so the first line can be wholly the client's. A line that is not text
/// makes the whole header unusable.
fn last_forwarded<'a>(lines: impl Iterator<Item = Option<&'a str>>) -> Option<IpAddr> {
    let lines: Vec<&str> = lines.collect::<Option<_>>()?;
    let joined: Vec<&str> = lines.into_iter().map(str::trim).filter(|l| !l.is_empty()).collect();
    forwarded_ip(&joined.join(", "))
}

/// The client address in a request from a trusted proxy.
fn forwarded_for(req: &RequestHeader) -> Option<IpAddr> {
    last_forwarded(req.headers.get_all("x-forwarded-for").iter().map(|v| v.to_str().ok()))
}

/// An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`, what a dual-stack listener
/// reports for an IPv4 client) as the IPv4 address it is. Every address the
/// gateway compares, counts or looks up goes through this once, where it
/// enters: otherwise `--trusted-proxy 10.0.0.1` would not match the peer
/// `::ffff:10.0.0.1`, and a real crawler's address would not be found among
/// the IPv4 addresses its name resolves to.
pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

fn gather(session: &Session, trusted_proxies: &[IpAddr]) -> Facts {
    let req = session.req_header();
    let info = conn_info(session);
    let peer = session
        .client_addr()
        .and_then(|a| a.as_inet())
        .map(|a| canonical(a.ip()))
        .unwrap_or(IpAddr::from([0, 0, 0, 0]));
    // A forwarded address is believed only from a configured peer. Behind
    // such a peer the TLS and HTTP/2 fingerprints are the proxy's, not the
    // client's, so they are left out.
    let behind_proxy = trusted_proxies.contains(&peer);
    let ip = if behind_proxy {
        forwarded_for(req).unwrap_or(peer)
    } else {
        peer
    };
    let info = if behind_proxy { None } else { info };
    let host = req
        .uri
        .host()
        .or_else(|| header(req, "host"))
        .unwrap_or("")
        .to_string();
    Facts {
        ip,
        method: req.method.as_str().to_string(),
        host,
        path: req.uri.path().to_string(),
        path_and_query: req
            .uri
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| req.uri.path().to_string()),
        user_agent: header(req, "user-agent").map(str::to_owned),
        ja4: info.map(|i| i.tls.ja4.clone()),
        h2: info
            .and_then(|i| i.h2.fingerprint())
            .map(|h| h.akamai.clone()),
        syn: info.and_then(|i| i.syn.get().cloned()),
        header_names: req.headers.keys().map(|k| k.as_str().to_string()).collect(),
        cookie: cookies(req),
        authority: req
            .uri
            .authority()
            .map(|a| a.as_str())
            .or_else(|| header(req, "host"))
            .unwrap_or("")
            .to_string(),
        query: req.uri.query().map(str::to_owned),
        authorization: header(req, "authorization").map(str::to_owned),
        fetch_mode: header(req, "sec-fetch-mode").map(str::to_owned),
        known: String::new(),
        signed_headers: if req.headers.contains_key("signature-input") {
            req.headers
                .iter()
                .filter_map(|(k, v)| Some((k.as_str().to_string(), v.to_str().ok()?.to_string())))
                .collect()
        } else {
            Vec::new()
        },
    }
}

/// The agent a Web Bot Auth verdict proves, and the detection to record.
/// Only a verified signature seen for the first time proves an agent; an
/// unknown key or a bad signature never does. A verified signature seen
/// before is a replay: no agent, and a `wba_replay` detection.
/// Whether a method changes something at the origin. Anything but GET, HEAD
/// and OPTIONS counts.
fn is_write(method: &str) -> bool {
    !matches!(method, "GET" | "HEAD" | "OPTIONS")
}

/// Whether a signature binds the request's method and target: `@method`,
/// the path (`@path`, `@request-target` or `@target-uri`) and, when the
/// request has a query, the query too (`@query`, or one of the two that
/// carry it). Web Bot Auth only requires `@authority`, so a captured
/// signature could otherwise be sent with another method, path or query
/// until it expires. The body is not bound: see SECURITY.md.
fn binds_target(info: &SignatureInfo, has_query: bool) -> bool {
    let whole = info.covers("@request-target") || info.covers("@target-uri");
    info.covers("@method")
        && (whole || info.covers("@path"))
        && (!has_query || whole || info.covers("@query"))
}

/// The agent a request proves, if any, and what to note. A trusted agent's
/// signature counts once (the replay cache), and on a write request only when
/// it binds the method and target (`binds_target`): otherwise the request is
/// treated as unsigned, and noted at no cost.
fn signed_agent_of(
    verdict: WbaVerdict,
    info: Option<&SignatureInfo>,
    write: bool,
    has_query: bool,
    replays: &mut ReplayCache,
    now: u64,
) -> (Option<String>, Option<Detection>) {
    match verdict {
        WbaVerdict::Verified { agent, .. } => match info {
            Some(info) if write && !binds_target(info, has_query) => (
                None,
                Some(Detection::new(
                    "wba_write_unbound",
                    Layer::Identity,
                    0,
                    format!("{agent} signed this write request without covering its method, path and query: treated as unsigned"),
                )),
            ),
            Some(info) if replays.first_use(info, now) => (Some(agent), None),
            _ => (
                None,
                Some(
                    Detection::new(
                        "wba_replay",
                        Layer::Identity,
                        30,
                        "a trusted agent's signature that was already used, or unreadable",
                    )
                    .with_class(Class::UnverifiedAgent),
                ),
            ),
        },
        other => (None, other.detection()),
    }
}

/// HTTP/2 settings and pseudo-header order of Apple's system HTTP client
/// (CFNetwork / URLSession), as opposed to WebKit's own: same TLS, other
/// settings order and window, `:path` before `:authority`.
const APPLE_SYSTEM_H2_SETTINGS: &str = "2:0;4:2097152;3:100;9:1";
const APPLE_SYSTEM_H2_ORDER: &str = "m,s,p,a";
/// What an iOS app's own icon fetch trips when it borrows the browser's
/// User-Agent: the engine check sees Apple's system client, not WebKit.
const IOS_APP_ICON_IDS: [&str; 3] = ["h2_settings_mismatch", "h2_pseudo_order_mismatch", "missing_sec_fetch"];

/// A site icon, as browsers and apps fetch them from the site's root.
fn is_icon_path(path: &str) -> bool {
    matches!(path, "/favicon.ico" | "/favicon.png" | "/favicon.svg")
        || (path.starts_with("/apple-touch-icon") && path.ends_with(".png") && !path[1..].contains('/'))
}

/// iOS browsers built on WebKit (DuckDuckGo, for one) fetch a site's icons
/// with the app's own HTTP client: Apple's system client, over the same TLS
/// as Safari, without `sec-fetch-*`, but with the browser's User-Agent. The
/// engine check then reads a WebKit browser with the wrong HTTP/2 and no
/// Fetch Metadata, which is what a bot pretending to be Safari looks like.
/// For that request alone (a GET or HEAD of a site icon, an iOS
/// User-Agent, Apple's system HTTP/2 exactly, TLS that matched), those three
/// findings are dropped; anything else that fired stays. An icon is worth
/// nothing to a scraper, and the TLS must still be Apple's.
fn drop_ios_app_icon_fetch(detections: &mut Vec<Detection>, method: &str, path: &str, ua: Option<&str>, h2: Option<&str>) {
    let ios = ua.is_some_and(|u| ["iPhone", "iPad", "iPod"].iter().any(|d| u.contains(d)));
    let apple_h2 = h2.is_some_and(|h| {
        let parts: Vec<&str> = h.split('|').collect();
        parts.len() == 4 && parts[0] == APPLE_SYSTEM_H2_SETTINGS && parts[3] == APPLE_SYSTEM_H2_ORDER
    });
    if !(ios && apple_h2 && matches!(method, "GET" | "HEAD") && is_icon_path(path)) {
        return;
    }
    if detections.iter().any(|d| d.id == "tls_ua_mismatch") {
        return;
    }
    detections.retain(|d| !IOS_APP_ICON_IDS.contains(&d.id.as_str()));
}

/// A User-Agent that is no browser, tool or crawler we know (`ua_unknown`,
/// penalty 20) left the request at 79, which the score reads as a person.
/// Nothing in it says person: it is an agent of some kind. The finding now
/// argues for that class; the score and the penalty are unchanged.
fn unknown_agent_is_not_a_person(detections: &mut [Detection]) {
    for d in detections.iter_mut() {
        if d.id == "ua_unknown" && d.class_hint.is_none() {
            d.class_hint = Some(Class::UnverifiedAgent);
        }
    }
}

/// The networks a crawler's operator crawls from. A claim whose address has
/// no reverse DNS stays unresolved (a DNS failure must never brand the real
/// crawler), but when the address is in a routed range of another network
/// the claim is false either way.
const CRAWLER_NETWORKS: [(&str, &[u32]); 4] = [
    ("Googlebot", &[15169]),
    ("Bingbot", &[8075]),
    ("Applebot", &[714, 6185]),
    ("YandexBot", &[13238]),
];

/// An unresolved crawler claim from a known address outside the operator's
/// networks is spoofed: `crawler_unresolved` gives way to `crawler_spoofed`.
/// No AS number (no database, or an unrouted address) changes nothing.
fn crawler_from_another_network(detections: &mut Vec<Detection>, claimed: &str, asn: u32) {
    let Some((_, networks)) = CRAWLER_NETWORKS.iter().find(|(name, _)| *name == claimed) else {
        return;
    };
    if asn == 0 || networks.contains(&asn) {
        return;
    }
    detections.retain(|d| d.id != "crawler_unresolved");
    let mut d = CrawlerVerdict::Spoofed { claimed: claimed.to_string() }
        .detection()
        .expect("a spoofed claim always has a detection");
    d.detail = format!("claims to be {claimed}, from AS{asn}, which is not that operator's network (no reverse DNS)");
    detections.push(d);
}

/// The visitor's network: AS number, class as stored (`hosting`, `other`, or
/// `unknown` when the address is in no routed range or there is no database),
/// and the network detection a request gets for it, if any.
fn network_of(db: &AsnDb, ip: IpAddr) -> (u32, &'static str, Option<Detection>) {
    match db.lookup(ip) {
        Some(info) => {
            let class = match info.class {
                NetClass::Hosting => "hosting",
                NetClass::Other => "other",
            };
            (info.asn, class, info.detection())
        }
        None => (0, "unknown", None),
    }
}

/// What the session token in a request's cookie turned out to be. Only
/// `Valid` counts as holding a token; the rest say why not, in the events.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TokenState {
    None,
    Valid,
    BudgetSpent,
    StoreFull,
    Expired,
    BindingMismatch,
    Invalid,
}

impl TokenState {
    fn is_valid(self) -> bool {
        self == TokenState::Valid
    }

    /// The `token` field of events.
    fn as_str(self) -> &'static str {
        match self {
            TokenState::None => "none",
            TokenState::Valid => "valid",
            TokenState::BudgetSpent => "budget_spent",
            TokenState::StoreFull => "store_full",
            TokenState::Expired => "expired",
            TokenState::BindingMismatch => "binding_mismatch",
            TokenState::Invalid => "invalid",
        }
    }
}

struct Assessment {
    model: Option<ModelOpinion>,
    verdict: Verdict,
    verified_bot: Option<String>,
    /// Name of the verified crawler or signed agent.
    identity: Option<String>,
    asn: u32,
    net_class: &'static str,
    token: TokenState,
    /// Counter key for the proven identity. The kind is part of it, so a
    /// signed agent that names itself after a crawler does not share that
    /// crawler's counters.
    identity_key: Option<String>,
    /// What the identity had left of its day before this request, when it
    /// has a daily quota.
    quota_left: Option<u32>,
}

impl Gateway {
    fn binding(&self, f: &Facts) -> Binding {
        let stable = f.ja4.as_deref().map(stable_ja4);
        Binding::derive(stable.as_deref(), f.ip, f.user_agent.as_deref())
    }

    async fn assess(&self, f: &Facts, now: u64) -> Assessment {
        let mut detections: Vec<Detection> = self.data.truth.load().check(&Observed {
            user_agent: f.user_agent.as_deref(),
            ja4: f.ja4.as_deref(),
            h2_akamai: f.h2.as_deref(),
            header_names: &f.header_names,
        });
        drop_ios_app_icon_fetch(&mut detections, &f.method, &f.path, f.user_agent.as_deref(), f.h2.as_deref());
        unknown_agent_is_not_a_person(&mut detections);

        let crawler = self.crawlers.verify(f.user_agent.as_deref(), f.ip).await;
        detections.extend(crawler.detection());
        let unresolved_claim = match &crawler {
            CrawlerVerdict::Unresolved { claimed } => Some(claimed.clone()),
            _ => None,
        };
        let verified_bot = match crawler {
            CrawlerVerdict::Verified { name } => Some(name),
            _ => None,
        };
        // Web Bot Auth: a signature from a trusted key proves who the agent is.
        let mut signed_agent: Option<String> = None;
        if !f.signed_headers.is_empty() {
            let headers: Vec<(&str, &str)> = f
                .signed_headers
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            let parts = RequestParts {
                method: &f.method,
                authority: &f.authority,
                path: &f.path,
                query: f.query.as_deref(),
                headers: &headers,
            };
            let verdict = veritell_wba::verify(&parts, &self.agents.load(), now);
            // Read only for a verified signature, so only trusted keys fill
            // the replay cache.
            let info = matches!(verdict, WbaVerdict::Verified { .. })
                .then(|| veritell_wba::signature_info(&parts))
                .flatten();
            let mut replays = self.wba_replays.lock().unwrap_or_else(|e| e.into_inner());
            let (agent, found) =
                signed_agent_of(verdict, info.as_ref(), is_write(&f.method), f.query.is_some(), &mut replays, now);
            drop(replays);
            detections.extend(found);
            signed_agent = agent;
        }

        // A crawler claim we could not confirm is an unverified agent, not a
        // person. Without this, claiming to be a bot from an address with no
        // reverse DNS would score almost clean.
        if verified_bot.is_none()
            && signed_agent.is_none()
            && detections.iter().any(|d| d.id == "ua_declared_bot")
        {
            // The User-Agent table skips its TLS and HTTP/2 checks for a
            // crawler name it knows, trusting the gateway to verify it. Not
            // verified: check the request again as if the name were made up.
            let neutral = detections
                .iter()
                .find(|d| d.id == "ua_declared_bot")
                .and_then(|d| without_bot_claim(f.user_agent.as_deref()?, &d.detail));
            if let Some(ua) = neutral {
                let more = self.data.truth.load().check(&Observed {
                    user_agent: Some(&ua),
                    ja4: f.ja4.as_deref(),
                    h2_akamai: f.h2.as_deref(),
                    header_names: &f.header_names,
                });
                for d in more {
                    if !detections.iter().any(|seen| seen.id == d.id) {
                        detections.push(d);
                    }
                }
            }
            detections.push(
                Detection::new(
                    "bot_unverified",
                    Layer::Identity,
                    30,
                    "User-Agent claims to be a bot, and the claim is not verified",
                )
                .with_class(Class::UnverifiedAgent),
            );
        }

        let (asn, net_class, net_detection) = network_of(&self.asn, f.ip);
        detections.extend(net_detection);
        if let Some(claimed) = unresolved_claim {
            crawler_from_another_network(&mut detections, &claimed, asn);
        }

        let token = match f
            .cookie
            .as_deref()
            .and_then(|c| cookie_value(c, COOKIE_NAME))
        {
            None => TokenState::None,
            Some(token) => match veritell_token::verify(&self.keys, token, &self.binding(f), now) {
                Ok(claims) => match self
                    .token_budgets
                    .try_consume(&claims.id, claims.budget, claims.expires_at, now)
                {
                    Consumed::Used => TokenState::Valid,
                    Consumed::Spent => TokenState::BudgetSpent,
                    // A full store cannot count this token's uses, so the
                    // token does not count: the budget would be off.
                    Consumed::Full => {
                        note_full("token budgets");
                        TokenState::StoreFull
                    }
                },
                Err(veritell_token::TokenError::Expired) => TokenState::Expired,
                Err(veritell_token::TokenError::BindingMismatch) => TokenState::BindingMismatch,
                Err(_) => TokenState::Invalid,
            },
        };

        // What this client's browser reported about itself, if it has.
        match self.probes.get(&self.binding(f).0, now) {
            Some(found) => detections.extend(found),
            // Every challenge page runs the probe, so a client that holds a
            // token and never reported skipped or blocked the script.
            None if token.is_valid() => detections.push(
                Detection::new(
                    "probe_missing",
                    Layer::Client,
                    40,
                    "holds a session token but never sent a probe report",
                )
                .with_class(Class::Automated),
            ),
            None => {}
        }

        // How this client has used the pages it loaded, if it has reported.
        if let Some(seen) = self.behaviors.get(&self.binding(f).0, now) {
            let writes = matches!(f.method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE");
            let known = seen.detections.iter().any(|d| d.id == veritell_behavior::NO_INPUT);
            detections.extend(seen.detections);
            // A form posted without a `submit` event (a script calling
            // `form.submit()`, or a client posting directly) shows up here.
            if writes && !seen.any_input && !known {
                detections.push(
                    Detection::new(
                        veritell_behavior::NO_INPUT,
                        Layer::Behavior,
                        40,
                        "a write request from a client whose pages saw no input at all",
                    )
                    .with_class(Class::Automated),
                );
            }
        }

        // What the population is doing. A proven identity is left out: a
        // crawler is one fingerprint on many networks by design.
        let mut shared: Option<(String, bool)> = None;
        if verified_bot.is_none() && signed_agent.is_none() {
            let fingerprint = format!(
                "{}|{}|{}",
                f.ja4.as_deref().unwrap_or(""),
                f.h2.as_deref().unwrap_or(""),
                f.user_agent.as_deref().unwrap_or("")
            );
            // What another install reported about this fingerprint: a hint.
            // Only with a handshake of the client's own: behind a trusted
            // proxy the fingerprint is the User-Agent alone, which every
            // person on that browser version shares.
            if let (Some(share), Some(_)) = (&self.share, &f.ja4) {
                let reported = share.reported(&fingerprint);
                shared = Some((fingerprint.clone(), reported.is_some()));
                detections.extend(reported);
            }
            detections.extend(self.agg.observe(
                &Observation {
                    fingerprint: &fingerprint,
                    ip: f.ip,
                    client: self.binding(f).0,
                    route: &f.path,
                },
                now,
            ));
        }

        let proven = if verified_bot.is_some() {
            Some(Proven::VerifiedBot)
        } else if signed_agent.is_some() {
            Some(Proven::SignedAgent)
        } else {
            None
        };
        let identity = verified_bot.clone().or(signed_agent);
        let identity_key = match (proven, &identity) {
            (Some(Proven::VerifiedBot), Some(name)) => Some(format!("bot\n{name}")),
            (Some(Proven::SignedAgent), Some(name)) => Some(format!("agent\n{name}")),
            _ => None,
        };
        // Every request by a proven identity counts against its day,
        // whatever is decided afterwards.
        let quota_left = match (&identity_key, &identity) {
            (Some(key), Some(name)) => self.policy.quota_for(name).map(|per_day| self.quotas.take(key, per_day, now)),
            _ => None,
        };

        let model = self.model.as_ref().and_then(|m| {
            let result = m.model.evaluate(&m.features.vector(&detections))?;
            let names = m.model.features();
            let top = result
                .top(3)
                .into_iter()
                .filter_map(|(i, by)| Some((names.get(i)?.clone(), by)))
                .collect();
            Some(ModelOpinion { score: result.score(), probability: result.probability, top })
        });

        let verdict = score_proven(detections, proven);
        if let (Some(share), Some((fingerprint, leaned))) = (&self.share, &shared) {
            share.note(fingerprint, veritell_agg::network_of(f.ip), verdict.class, *leaned, now);
        }
        Assessment {
            model,
            verdict,
            verified_bot,
            identity,
            asn,
            net_class,
            token,
            identity_key,
            quota_left,
        }
    }

    fn decide(&self, f: &Facts, a: &Assessment) -> Decision {
        let ids: Vec<String> = a.verdict.detections.iter().map(|d| d.id.clone()).collect();
        let ip = f.ip.to_string();
        self.policy.evaluate(&PolicyInput {
            path: &f.path,
            method: &f.method,
            host: &f.host,
            score: a.verdict.score,
            class: a.verdict.class,
            detections: &ids,
            ja4: f.ja4.as_deref().unwrap_or(""),
            user_agent: f.user_agent.as_deref().unwrap_or(""),
            ip: &ip,
            asn: a.asn,
            net_class: a.net_class,
            verified_bot: a.verified_bot.as_deref().unwrap_or(""),
            has_token: a.token.is_valid(),
            identity: a.identity.as_deref().unwrap_or(""),
            quota_left: a.quota_left.unwrap_or(NO_QUOTA),
        })
    }

    /// What the origin is told about a request it is given.
    fn origin_headers(f: &Facts, a: &Assessment, d: &Decision) -> Vec<(&'static str, String)> {
        let ids: Vec<&str> = a.verdict.detections.iter().map(|d| d.id.as_str()).collect();
        vec![
            ("x-veritell-score", a.verdict.score.to_string()),
            ("x-veritell-class", a.verdict.class.as_str().to_string()),
            ("x-veritell-detections", ids.join(",")),
            ("x-veritell-action", d.action.to_string()),
            ("x-veritell-ja4", f.ja4.clone().unwrap_or_default()),
            ("x-veritell-h2", f.h2.clone().unwrap_or_default()),
        ]
    }

    /// The address as it may be written outside the process (`--ip-mode`).
    fn stored_ip(&self, ip: IpAddr) -> String {
        self.addr.stored(ip, now_secs())
    }

    fn log(&self, f: &Facts, a: &Assessment, d: &Decision, outcome: &str, now: u64) {
        let line = serde_json::json!({
            "ts": now,
            "ip": self.stored_ip(f.ip),
            "method": f.method,
            "host": f.host,
            "path": f.path,
            "user_agent": f.user_agent,
            "ja4": f.ja4,
            "h2": f.h2,
            "score": a.verdict.score,
            "class": a.verdict.class.as_str(),
            "detections": a.verdict.detections.iter().map(|d| d.id.as_str()).collect::<Vec<_>>(),
            "verified_bot": a.verified_bot,
            "identity": a.identity.as_deref().unwrap_or(""),
            "asn": a.asn,
            "net_class": a.net_class,
            "token": a.token.as_str(),
            "action": d.action.to_string(),
            "enforced": d.enforced,
            "route": d.route,
            "rule": d.rule,
            "policy_error": d.error,
            "quota_left": a.quota_left,
            "offer": d.offer.as_ref().map(|o| o.name.as_str()),
            "outcome": outcome,
            "model": a.model.as_ref().map(ModelOpinion::to_json),
            "known": f.known,
            "tcp": f.syn.as_ref().map(|s| s.signature.as_str()),
            "tcp_ttl": f.syn.as_ref().map(|s| s.ttl),
        });
        if self.log_requests {
            println!("{line}");
        }
        self.events.record(&Event {
            ts_ms: now_millis(),
            kind: EventKind::Request,
            ip: self.stored_ip(f.ip),
            method: bounded(&f.method),
            host: bounded(&f.host),
            path: bounded(&f.path),
            user_agent: bounded(f.user_agent.as_deref().unwrap_or("")),
            ja4: f.ja4.clone().unwrap_or_default(),
            h2: f.h2.clone().unwrap_or_default(),
            score: a.verdict.score,
            class: a.verdict.class,
            detections: a.verdict.detections.clone(),
            identity: a.identity.clone().unwrap_or_default(),
            asn: a.asn,
            net_class: a.net_class.to_string(),
            token: a.token.as_str().to_string(),
            action: d.action.to_string(),
            enforced: d.enforced,
            route: d.route.clone().unwrap_or_default(),
            rule: d.rule.map(|r| r.to_string()).unwrap_or_default(),
            outcome: outcome.to_string(),
            known: f.known.clone(),
            summary: String::new(),
            tcp: f.syn.as_ref().map(|s| s.signature.clone()).unwrap_or_default(),
            tcp_ttl: f.syn.as_ref().map_or(0, |s| s.ttl),
        });
    }

    /// Records something other than a proxied request: a probe report or a
    /// challenge attempt.
    fn side_event(&self, kind: EventKind, f: &Facts, detections: Vec<Detection>, outcome: &str) {
        self.side_event_with(kind, f, detections, outcome, String::new());
    }

    /// A side event that also carries a behaviour report's counts. It records
    /// the visitor's network like a request does, but adds no network
    /// detection: a side event's detections are those of the report itself.
    fn side_event_with(&self, kind: EventKind, f: &Facts, detections: Vec<Detection>, outcome: &str, summary: String) {
        let (asn, net_class, _) = network_of(&self.asn, f.ip);
        let ids: Vec<&str> = detections.iter().map(|d| d.id.as_str()).collect();
        if self.log_requests {
            println!(
                "{}",
                serde_json::json!({
                    "ts": now_secs(), "kind": kind.as_str(), "ip": self.stored_ip(f.ip), "path": bounded(&f.path),
                    "ja4": f.ja4, "user_agent": f.user_agent.as_deref().map(bounded), "detections": ids, "outcome": outcome, "known": f.known,
                })
            );
        }
        let verdict = score_proven(detections, None);
        self.events.record(&Event {
            ts_ms: now_millis(),
            kind,
            ip: self.stored_ip(f.ip),
            method: bounded(&f.method),
            host: bounded(&f.host),
            path: bounded(&f.path),
            user_agent: bounded(f.user_agent.as_deref().unwrap_or("")),
            ja4: f.ja4.clone().unwrap_or_default(),
            h2: f.h2.clone().unwrap_or_default(),
            score: verdict.score,
            class: verdict.class,
            detections: verdict.detections,
            identity: String::new(),
            asn,
            net_class: net_class.to_string(),
            token: String::new(),
            action: String::new(),
            enforced: false,
            route: String::new(),
            rule: String::new(),
            outcome: outcome.to_string(),
            known: f.known.clone(),
            summary,
            tcp: f.syn.as_ref().map(|s| s.signature.clone()).unwrap_or_default(),
            tcp_ttl: f.syn.as_ref().map_or(0, |s| s.ttl),
        });
    }

    async fn respond(
        &self,
        session: &mut Session,
        status: u16,
        content_type: &str,
        body: Vec<u8>,
        extra: &[(&'static str, String)],
    ) -> Result<()> {
        let mut resp = ResponseHeader::build(status, Some(4 + extra.len()))?;
        resp.insert_header("content-type", content_type)?;
        resp.insert_header("content-length", body.len().to_string())?;
        resp.insert_header("cache-control", "no-store")?;
        for (name, value) in extra {
            resp.insert_header(*name, value.as_str())?;
        }
        session.write_response_header(Box::new(resp), false).await?;
        session
            .write_response_body(Some(Bytes::from(body)), true)
            .await?;
        Ok(())
    }

    async fn serve_challenge(
        &self,
        session: &mut Session,
        f: &Facts,
        difficulty: u8,
        return_to: &str,
        now: u64,
        // Status and extra headers: 403 and none, unless a token challenge
        // goes out with the page.
        (status, extra): (u16, &[(&'static str, String)]),
    ) -> Result<()> {
        let challenge = pow::issue_challenge(
            &self.keys,
            &self.binding(f),
            now,
            CHALLENGE_TTL_SECS,
            difficulty,
        );
        // Every challenge page also runs the probe. The page waits for it
        // when the root element carries `data-probe`. The slots filled by
        // `challenge_page` are HTML-escaped, so neither marker can occur in them.
        // With a token challenge on a page load in a browser that may hold
        // a token, the page waits before leaving, so that the browser's
        // reload with the token is not cut short (Phase 3, L20).
        let root = if status == 401 && f.is_navigation() && may_hold_token(f.user_agent.as_deref()) {
            format!("<html lang=\"en\" data-probe data-wait=\"{TOKEN_WAIT_MS}\">")
        } else {
            "<html lang=\"en\" data-probe>".to_string()
        };
        let page = pow::challenge_page(&challenge, return_to)
            .replacen("<html lang=\"en\">", &root, 1)
            .replacen(
                "</body>",
                "<script src=\"/__veritell/probe.js\" async></script>\n</body>",
                1,
            )
            // The AGPL's offer of source to the people who use the program
            // over the network (section 13): a link on the pages the gateway
            // itself serves.
            .replacen("</body>", &self.source_link, 1);
        self.respond(
            session,
            status,
            "text/html; charset=utf-8",
            page.into_bytes(),
            extra,
        )
        .await
    }

    /// POST /__veritell/verify: check a proof-of-work solution and issue a token.
    async fn handle_verify(&self, session: &mut Session, f: &Facts, now: u64) -> Result<()> {
        let Some(body) = read_body(session, MAX_FORM_BYTES, self.body_timeout).await? else {
            return self
                .respond(session, 413, "text/plain", b"too large".to_vec(), &[])
                .await;
        };
        let form = parse_form(&body);
        let return_to = pow::sanitize_return_to(form.get("return_to").map_or("/", String::as_str));
        let binding = self.binding(f);

        let solved = check_solution(&self.keys, &self.used_challenges, &form, &binding, now);

        let outcome = if solved.is_some() {
            "challenge_passed"
        } else {
            "challenge_failed"
        };
        self.side_event(EventKind::Challenge, f, Vec::new(), outcome);

        if solved.is_none() {
            // Start over with a fresh challenge at the level of the one that
            // failed. A failure is mostly a page left open past the
            // challenge's two minutes, a phone that changed network while
            // solving, or a double submit: going straight to the hardest
            // level (20 bits) could leave a slow phone unable to ever finish.
            let difficulty = retry_difficulty(&self.keys, &form);
            return self
                .serve_challenge(session, f, difficulty, return_to, now, (403, &[]))
                .await;
        }

        let token = veritell_token::issue(
            &self.keys,
            &binding,
            now,
            TOKEN_TTL_SECS,
            self.token_budget,
        );
        let cookie = format!(
            "{COOKIE_NAME}={token}; Path=/; Max-Age={TOKEN_TTL_SECS}; HttpOnly; Secure; SameSite=Lax"
        );
        self.respond(
            session,
            303,
            "text/plain",
            Vec::new(),
            &[("location", return_to.to_string()), ("set-cookie", cookie)],
        )
        .await
    }

    /// GET /__veritell/probe.js: the probe script with a nonce for this client.
    async fn serve_probe_script(&self, session: &mut Session, f: &Facts, now: u64) -> Result<()> {
        let nonce = veritell_probe::issue_nonce(
            &self.probe_key,
            &self.binding(f).0,
            now,
            PROBE_NONCE_TTL_SECS,
        );
        self.respond(
            session,
            200,
            "text/javascript; charset=utf-8",
            probe::script_with(&self.probe_builds.current.load().script, &nonce).into_bytes(),
            &[],
        )
        .await
    }

    /// POST /__veritell/probe: check and analyse a probe report. A rejected
    /// report is logged; only one that the script cannot have made (see
    /// `probe::Refusal::is_forgery`) leaves state behind, a `probe_forged` detection
    /// on the client.
    async fn handle_probe_report(&self, session: &mut Session, f: &Facts, now: u64) -> Result<()> {
        let Some(body) = read_body(session, veritell_probe_build::MAX_SEALED_BYTES, self.body_timeout).await? else {
            self.side_event(EventKind::Probe, f, Vec::new(), probe::Refusal::TooLarge.as_str());
            return self
                .respond(session, 413, "text/plain", b"too large".to_vec(), &[])
                .await;
        };
        let binding = self.binding(f);
        // Reports arrive sealed for one build and one nonce. A plain report
        // is not accepted: it fails here as malformed.
        let checked = self
            .probe_builds
            .builder
            .open(&body, now)
            .map_err(|e| match e {
                OpenError::UnknownBuild => probe::Refusal::BuildUnknown,
                OpenError::ExpiredBuild => probe::Refusal::BuildExpired,
                OpenError::Decrypt => probe::Refusal::SealInvalid,
                OpenError::TooLarge | OpenError::Malformed | OpenError::Keys => probe::Refusal::Malformed,
            })
            .and_then(|opened| {
                let report = veritell_probe::parse_report(&opened.report_json)
                    .map_err(|_| probe::Refusal::Malformed)?;
                // The outer nonce is the authenticated one; the copy inside
                // the report must agree with it.
                if report.nonce != opened.nonce {
                    return Err(probe::Refusal::Malformed);
                }
                // Sealing proves the sender read this build's script, not
                // that it ran it: the build key is in the script. The order
                // in which the build writes the page's keys differs from
                // build to build and only a run of it produces that order.
                let orders = self.probe_builds.builder.key_order(&opened.build_id).unwrap_or_default();
                if !probe::in_build_order(&orders, &opened.report_json) {
                    return Err(probe::Refusal::BuildOrder);
                }
                Ok(report)
            })
            .and_then(|report| {
                let info =
                    veritell_probe::verify_nonce(&self.probe_key, &report.nonce, &binding.0, now)
                        .map_err(|e| match e {
                            NonceError::Expired => probe::Refusal::NonceExpired,
                            NonceError::BindingMismatch => probe::Refusal::NonceOtherClient,
                            NonceError::Malformed | NonceError::BadMac => probe::Refusal::NonceInvalid,
                        })?;
                // Single use: a captured report cannot be sent again. A full
                // store cannot tell a replay, so the report is refused.
                match self.used_nonces.try_consume(&info.id, 1, info.expires_at, now) {
                    Consumed::Used => {}
                    Consumed::Spent => return Err(probe::Refusal::NonceReused),
                    Consumed::Full => {
                        note_full("probe nonces");
                        return Err(probe::Refusal::StoreFull);
                    }
                }
                Ok(report)
            });
        let report = match checked {
            Ok(report) => report,
            Err(why) => {
                // Not every refusal counts against the client (Refusal::strikes).
                if why.strikes() {
                    self.agg.strike(&binding.0, now);
                }
                // A report that no copy of the script makes is evidence about
                // the client that sent it: without this, sending one would
                // leave the client exactly where it was.
                let found = if why.is_forgery() {
                    let found = vec![probe::forged(why)];
                    self.probes.put(binding.0, found.clone(), now.saturating_add(PROBE_RESULT_TTL_SECS), now);
                    found
                } else {
                    Vec::new()
                };
                self.side_event(EventKind::Probe, f, found, why.as_str());
                return self
                    .respond(session, 403, "text/plain", b"rejected".to_vec(), &[])
                    .await;
            }
        };
        let found = veritell_probe::analyze(
            &report,
            &probe::claimed(f.user_agent.as_deref()),
            &self.data.engine_truth.load(),
        );
        let outcome = if found.is_empty() { "probe_clean" } else { "probe_flagged" };
        self.side_event(EventKind::Probe, f, found.clone(), outcome);
        self.probes.put(
            binding.0,
            found,
            now.saturating_add(PROBE_RESULT_TTL_SECS),
            now,
        );
        self.respond(session, 204, "text/plain", Vec::new(), &[]).await
    }

    /// GET /__veritell/behavior.js: the behaviour script with a nonce.
    async fn serve_behavior_script(&self, session: &mut Session, f: &Facts, now: u64) -> Result<()> {
        let nonce = veritell_probe::issue_nonce(
            &self.probe_key,
            &behavior::nonce_binding(&self.binding(f).0),
            now,
            BEHAVIOR_NONCE_TTL_SECS,
        );
        self.respond(
            session,
            200,
            "text/javascript; charset=utf-8",
            behavior::script_with(&nonce).into_bytes(),
            &[],
        )
        .await
    }

    /// POST /__veritell/behavior: check and analyse a behaviour summary. A
    /// rejected summary is logged and counts as a strike against the client.
    async fn handle_behavior_report(&self, session: &mut Session, f: &Facts, now: u64) -> Result<()> {
        let Some(body) = read_body(session, veritell_behavior::MAX_SUMMARY_BYTES, self.body_timeout).await? else {
            self.side_event(EventKind::Probe, f, Vec::new(), behavior::Refusal::TooLarge.as_str());
            return self
                .respond(session, 413, "text/plain", b"too large".to_vec(), &[])
                .await;
        };
        let binding = self.binding(f);
        let checked = veritell_behavior::parse_summary(&body)
            .map_err(|_| behavior::Refusal::Malformed)
            .and_then(|summary| {
                let info = veritell_probe::verify_nonce(
                    &self.probe_key,
                    &summary.nonce,
                    &behavior::nonce_binding(&binding.0),
                    now,
                )
                .map_err(|e| match e {
                    NonceError::Expired => behavior::Refusal::NonceExpired,
                    NonceError::BindingMismatch => behavior::Refusal::NonceOtherClient,
                    NonceError::Malformed | NonceError::BadMac => behavior::Refusal::NonceInvalid,
                })?;
                match self.used_behavior_nonces.try_consume(
                    &info.id,
                    behavior::SUMMARIES_PER_NONCE,
                    info.expires_at,
                    now,
                ) {
                    Consumed::Used => {}
                    Consumed::Spent => return Err(behavior::Refusal::NonceSpent),
                    Consumed::Full => {
                        note_full("behaviour nonces");
                        return Err(behavior::Refusal::StoreFull);
                    }
                }
                Ok(summary)
            });
        let summary = match checked {
            Ok(summary) => summary,
            Err(why) => {
                if why.strikes() {
                    self.agg.strike(&binding.0, now);
                }
                self.side_event(EventKind::Probe, f, Vec::new(), why.as_str());
                return self
                    .respond(session, 403, "text/plain", b"rejected".to_vec(), &[])
                    .await;
            }
        };
        let found = veritell_behavior::analyze(&summary, &self.behavior_params);
        let outcome = if found.is_empty() { "behavior_clean" } else { "behavior_flagged" };
        // The counts themselves, so that thresholds can be set from what
        // real traffic sends. They are counts only; see probe/BEHAVIOR.md.
        let s = &summary;
        let counts = serde_json::json!({
            "dur_ms": s.dur_ms,
            "moves": s.moves, "strokes": s.strokes, "straight": s.straight, "steady": s.steady,
            "clicks": s.clicks, "sized": s.sized, "centered": s.centered, "teleport": s.teleport,
            "touches": s.touches, "keys": s.keys, "key_gap_cv": s.key_gap_cv, "pastes": s.pastes,
            "scrolls": s.scrolls, "submits": s.submits, "untrusted": s.untrusted,
            "actions": s.actions, "gap_cv": s.gap_cv, "gap_med_ms": s.gap_med_ms,
        });
        let mut line = counts.clone();
        if let Some(obj) = line.as_object_mut() {
            obj.insert("ts".into(), now.into());
            obj.insert("kind".into(), "behavior_summary".into());
            obj.insert("ip".into(), self.stored_ip(f.ip).into());
            obj.insert("known".into(), f.known.clone().into());
        }
        if self.log_requests {
            println!("{line}");
        }
        // The same counts go into the event, so that the event store holds
        // them for as long as it keeps events, whatever happens to the log.
        self.side_event_with(EventKind::Probe, f, found.clone(), outcome, counts.to_string());
        self.behaviors.put(
            binding.0,
            found,
            summary.has_input(),
            now.saturating_add(BEHAVIOR_RESULT_TTL_SECS),
            now,
        );
        self.respond(session, 204, "text/plain", Vec::new(), &[]).await
    }

    /// What is actually done: nothing in shadow mode, and a challenge or a
    /// throttle only when a token or the rate allowance does not cover it.
    fn effective(&self, f: &Facts, a: &Assessment, d: &Decision, now: u64) -> Action {
        effective_action(d, a.token.is_valid(), Self::claims_receipt(f, d), |per_minute| {
            // A proven identity is limited as itself, wherever it comes
            // from; everyone else by address.
            match &a.identity_key {
                Some(key) => self.quotas.allow_rate(key, per_minute, now),
                None => self.throttle.allow(f.ip, per_minute, now),
            }
        })
    }

    /// Whether the request carries the header the offer names as a claim of
    /// payment. The gateway does not check the claim: the request goes to
    /// the origin marked as unverified, and the origin decides.
    fn claims_receipt(f: &Facts, d: &Decision) -> bool {
        d.enforced
            && d.action == Action::Charge
            && d.offer
                .as_ref()
                .and_then(|o| o.receipt_header.as_deref())
                .is_some_and(|name| f.header_names.iter().any(|h| h == name))
    }

    /// The 402 answer: the offer in one header and as the JSON body. It is
    /// the same for every client the rule applies to and says nothing about
    /// what was detected.
    fn offer_answer(d: &Decision) -> (Vec<u8>, Vec<(&'static str, String)>) {
        match &d.offer {
            Some(o) => (o.body_json().into_bytes(), vec![("veritell-offer", o.header_value())]),
            None => (b"{}".to_vec(), Vec::new()),
        }
    }

    /// GET /__veritell/challenge?return_to=/path&c=...: the challenge page on
    /// request. A proxy in sidecar mode sends a client here when the
    /// authorization endpoint asks for a challenge, with the endpoint's
    /// `x-veritell-challenge` as `c`.
    async fn serve_challenge_on_request(&self, session: &mut Session, f: &Facts, now: u64) -> Result<()> {
        let query = parse_form(f.query.as_deref().unwrap_or("").as_bytes());
        let return_to = pow::sanitize_return_to(query.get("return_to").map_or("/", String::as_str));
        let difficulty = match link_difficulty(&self.keys, &query) {
            Some(d) => d,
            // A link without `c` (a proxy set up before it existed): score
            // the request here, which also spends token budget and counts it
            // in the population, as the authorization call already did.
            None => pow::difficulty_for_score(self.assess(f, now).await.verdict.score),
        };
        self.serve_challenge(session, f, difficulty, return_to, now, (403, &[])).await
    }

    /// The authorization endpoint for a proxy that asks before it serves
    /// (see `sidecar/README.md`). Only reachable on the plain listener.
    async fn handle_sidecar(&self, session: &mut Session, now: u64) -> Result<()> {
        let req = session.req_header();
        let peer = session
            .client_addr()
            .and_then(|a| a.as_inet())
            .map(|a| canonical(a.ip()))
            .unwrap_or(IpAddr::from([0, 0, 0, 0]));
        let path = req.uri.path();
        let suffix = match path.strip_prefix(AUTHZ_PATH) {
            Some("") => None,
            Some(rest) if rest.starts_with('/') => Some(
                req.uri
                    .path_and_query()
                    .and_then(|pq| pq.as_str().strip_prefix(AUTHZ_PATH))
                    .unwrap_or(rest)
                    .to_string(),
            ),
            _ => {
                return self
                    .respond(session, 404, "text/plain", b"not found".to_vec(), &[])
                    .await
            }
        };
        // Nothing a stranger sends here is believed, and a stranger is not
        // told what score an address would get.
        if !self.trusted_proxies.contains(&peer) {
            if self.log_requests {
                println!(
                    "{}",
                    serde_json::json!({ "ts": now, "kind": "sidecar", "ip": self.stored_ip(peer), "outcome": "sidecar_untrusted_peer" })
                );
            }
            return self
                .respond(session, 403, "text/plain", b"forbidden".to_vec(), &[])
                .await;
        }
        let original = original_request(
            |name| header(req, name).map(str::to_owned),
            suffix,
            req.method.as_str(),
        );
        let (original, ip) = match (original, forwarded_for(req)) {
            (Ok(original), Some(ip)) => (original, ip),
            (result, _) => {
                let outcome = match result {
                    Err(SidecarError::Conflict) => "sidecar_conflict",
                    _ => "sidecar_missing",
                };
                if self.log_requests {
                    println!(
                        "{}",
                        serde_json::json!({ "ts": now, "kind": "sidecar", "ip": self.stored_ip(peer), "outcome": outcome })
                    );
                }
                let body: &[u8] = match outcome {
                    "sidecar_conflict" => b"original request given twice, differently",
                    _ => b"original request missing",
                };
                return self.respond(session, 400, "text/plain", body.to_vec(), &[]).await;
            }
        };
        let Original { uri, method, host } = original;
        let (path, query) = match uri.split_once('?') {
            Some((p, q)) => (p.to_string(), Some(q.to_string())),
            None => (uri.clone(), None),
        };
        let client_header = |name: &str| !SIDECAR_HEADERS.contains(&name);
        let f = Facts {
            ip,
            method: bounded(&method),
            host: host.clone(),
            path,
            path_and_query: uri,
            user_agent: header(req, "user-agent").map(str::to_owned),
            ja4: None,
            h2: None,
            syn: None,
            header_names: req
                .headers
                .keys()
                .map(|k| k.as_str().to_string())
                .filter(|k| client_header(k))
                .collect(),
            cookie: cookies(req),
            authority: host,
            query,
            authorization: None,
            fetch_mode: None,
            known: String::new(),
            signed_headers: if req.headers.contains_key("signature-input") {
                req.headers
                    .iter()
                    .filter(|(k, _)| client_header(k.as_str()))
                    .filter_map(|(k, v)| Some((k.as_str().to_string(), v.to_str().ok()?.to_string())))
                    .collect()
            } else {
                Vec::new()
            },
        };

        let a = self.assess(&f, now).await;
        let d = self.decide(&f, &a);
        let ids: Vec<&str> = a.verdict.detections.iter().map(|d| d.id.as_str()).collect();
        let answer = [
            ("x-veritell-score", a.verdict.score.to_string()),
            ("x-veritell-class", a.verdict.class.as_str().to_string()),
            ("x-veritell-detections", ids.join(",")),
            ("x-veritell-action", d.action.to_string()),
        ];
        let mut answer = answer.to_vec();
        let (status, outcome) = match self.effective(&f, &a, &d, now) {
            Action::Pass if Self::claims_receipt(&f, &d) => {
                answer.push(("x-veritell-receipt", "unverified".to_string()));
                (200, "charge_receipt")
            }
            Action::Pass => (200, "passed"),
            // 403, not 402: nginx's auth_request turns any status but 2xx,
            // 401 and 403 into a 500. The offer goes in the headers, and
            // `x-veritell-action: charge` tells it from a block.
            Action::Charge => {
                answer.extend(Self::offer_answer(&d).1);
                (403, "charged")
            }
            Action::Challenge(_) => {
                // A signed challenge at this client's level, for the proxy to
                // pass on as `c=` in the /__veritell/challenge link: the page
                // then needs no second assessment.
                let c = pow::issue_challenge(
                    &self.keys,
                    &self.binding(&f),
                    now,
                    CHALLENGE_TTL_SECS,
                    pow::difficulty_for_score(a.verdict.score),
                );
                answer.push(("x-veritell-challenge", c));
                (403, "challenged")
            }
            Action::Throttle { .. } => (429, "throttled"),
            // A proxy waiting on this answer is not made to wait longer.
            Action::Tarpit => (429, "tarpitted"),
            Action::Decoy => (403, "decoyed"),
            Action::Block => (403, "blocked"),
        };
        self.log(&f, &a, &d, outcome, now);
        self.respond(session, status, "text/plain", Vec::new(), &answer).await
    }

    /// With no upstream configured the gateway answers itself, which is
    /// enough to test detection end to end.
    async fn serve_report(&self, session: &mut Session, f: &Facts, a: &Assessment) -> Result<()> {
        let body = serde_json::json!({
            "ja4": f.ja4,
            "h2": f.h2,
            "score": a.verdict.score,
            "class": a.verdict.class.as_str(),
            "detections": a.verdict.detections,
            "verified_bot": a.verified_bot,
            "identity": a.identity.as_deref().unwrap_or(""),
            "token": a.token.as_str(),
            "model": a.model.as_ref().map(ModelOpinion::to_json),
        });
        self.respond(
            session,
            200,
            "application/json",
            serde_json::to_vec_pretty(&body).unwrap_or_default(),
            &[],
        )
        .await
    }
}

/// The origin is told who connected, as any reverse proxy does: the peer's
/// address is appended to `x-forwarded-for`, so the last entry is always the
/// one the gateway saw, and an origin that trusts only the gateway takes that
/// one. Earlier entries are whatever the client (or a proxy in front) wrote.
/// `x-real-ip` is always the gateway's own view of the client. `forwarded`
/// and `x-forwarded-host` are dropped unless a trusted proxy is the peer,
/// which wrote them; with `replace` they and `x-forwarded-for` always go.
/// The connection is always TLS here.
fn set_forwarding(req: &mut RequestHeader, ctx: &Ctx, replace: bool) -> Result<()> {
    req.remove_header("x-real-ip");
    if replace || !ctx.behind_proxy {
        req.remove_header("forwarded");
        req.remove_header("x-forwarded-host");
    }
    if replace {
        req.remove_header("x-forwarded-for");
    }
    if let Some(ip) = ctx.client_ip.or(ctx.peer_ip) {
        req.insert_header("x-real-ip", ip.to_string())?;
    }
    if let Some(ip) = ctx.peer_ip {
        let forwarded = match req
            .headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect::<Vec<_>>()
            .join(", ")
        {
            prior if prior.trim().is_empty() => ip.to_string(),
            prior => format!("{prior}, {ip}"),
        };
        req.insert_header("x-forwarded-for", forwarded)?;
        req.insert_header("x-forwarded-proto", "https")?;
    }
    Ok(())
}

#[async_trait]
impl ProxyHttp for Gateway {
    type CTX = Ctx;
    fn new_ctx(&self) -> Self::CTX {
        Ctx::default()
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let now = now_secs();
        // Slow clients. A write that waits longer ends the request (an
        // HTTP/2 client that never opens its receive window); so does one
        // HTTP/1 body read. The body's total time is checked as it comes.
        session.set_write_timeout(Some(self.write_timeout));
        session.set_read_timeout(Some(self.body_timeout));
        ctx.request_started = Some(std::time::Instant::now());
        // The plain listener exists only for the authorization endpoint.
        if session.digest().is_none_or(|d| d.ssl_digest.is_none()) {
            self.handle_sidecar(session, now).await?;
            return Ok(true);
        }
        let mut f = gather(session, &self.trusted_proxies);
        ctx.peer_ip = session.client_addr().and_then(|a| a.as_inet()).map(|a| canonical(a.ip()));
        ctx.client_ip = Some(f.ip);
        ctx.behind_proxy = ctx.peer_ip.is_some_and(|p| self.trusted_proxies.contains(&p));
        ctx.injection = crate::inject::Injection::for_request(
            self.inject_probe,
            &f.method,
            header(session.req_header(), "sec-fetch-dest"),
        );
        if let Some(key) = &self.known_key {
            if let Some(label) = f.cookie.as_deref().and_then(|c| key.label_from_cookie(c)) {
                f.known = label.to_string();
            }
            if f.method == "GET" {
                if let Some(label) = key.label_from_path(&f.path) {
                    println!("{}", serde_json::json!({ "ts": now, "kind": "known_enrolled", "known": label }));
                    // The page goes on to the site's home page after a few
                    // seconds, so the person can start browsing straight away.
                    // The label is [a-z0-9-] only (label_from_path), so it is
                    // safe in the page as it is.
                    let body = format!(
                        "<!doctype html><meta charset=utf-8><meta http-equiv=refresh content=\"3; url=/\"><title>Marked</title>\
                         <p>This browser is now marked <b>{label}</b> \
                         for measuring this site's bot detection. Nothing else changes. To undo it, clear this site's cookies.</p>\
                         <p><a href=\"/\">Continue to the site</a></p>"
                    );
                    let cookie = key.set_cookie(label);
                    self.respond(session, 200, "text/html; charset=utf-8", body.into_bytes(), &[("set-cookie", cookie)])
                        .await?;
                    return Ok(true);
                }
            }
        }

        if f.path == CHALLENGE_PATH {
            if f.method == "GET" {
                self.serve_challenge_on_request(session, &f, now).await?;
            } else {
                self.respond(session, 405, "text/plain", b"method not allowed".to_vec(), &[])
                    .await?;
            }
            return Ok(true);
        }

        if f.path == VERIFY_PATH {
            if f.method == "POST" {
                self.handle_verify(session, &f, now).await?;
            } else {
                self.respond(session, 405, "text/plain", b"method not allowed".to_vec(), &[])
                    .await?;
            }
            return Ok(true);
        }
        if f.path == probe::SCRIPT_PATH {
            if f.method == "GET" {
                self.serve_probe_script(session, &f, now).await?;
            } else {
                self.respond(session, 405, "text/plain", b"method not allowed".to_vec(), &[])
                    .await?;
            }
            return Ok(true);
        }
        if f.path == probe::REPORT_PATH {
            if f.method == "POST" {
                self.handle_probe_report(session, &f, now).await?;
            } else {
                self.respond(session, 405, "text/plain", b"method not allowed".to_vec(), &[])
                    .await?;
            }
            return Ok(true);
        }

        if f.path == behavior::SCRIPT_PATH {
            if f.method == "GET" {
                self.serve_behavior_script(session, &f, now).await?;
            } else {
                self.respond(session, 405, "text/plain", b"method not allowed".to_vec(), &[])
                    .await?;
            }
            return Ok(true);
        }
        if f.path == behavior::REPORT_PATH {
            if f.method == "POST" {
                self.handle_behavior_report(session, &f, now).await?;
            } else {
                self.respond(session, 405, "text/plain", b"method not allowed".to_vec(), &[])
                    .await?;
            }
            return Ok(true);
        }

        let a = self.assess(&f, now).await;
        let d = self.decide(&f, &a);

        // A challenge is satisfied by a valid token.
        let effective = self.effective(&f, &a, &d, now);

        match effective {
            Action::Pass => {
                let receipt = Self::claims_receipt(&f, &d);
                self.log(&f, &a, &d, if receipt { "charge_receipt" } else { "passed" }, now);
                if self.upstream.is_none() {
                    self.serve_report(session, &f, &a).await?;
                    return Ok(true);
                }
                ctx.upstream_headers = Self::origin_headers(&f, &a, &d);
                if receipt {
                    ctx.upstream_headers.push(("x-veritell-receipt", "unverified".to_string()));
                }
                Ok(false)
            }
            Action::Challenge(kind) => {
                // A silent challenge costs almost nothing to solve: its
                // purpose is to make the browser run the probe.
                let mut difficulty = match kind {
                    ChallengeKind::Silent => pow::MIN_DIFFICULTY,
                    // A policy cannot ask for `interactive` (it is refused at
                    // load); were it here, it would be a proof of work.
                    ChallengeKind::Pow | ChallengeKind::Interactive => {
                        pow::difficulty_for_score(a.verdict.score)
                    }
                };
                // On a proof-of-work or interactive challenge a Privacy Pass
                // token stands in for the work, whatever the score: a person
                // on an iPhone scores 99 and would otherwise never be asked
                // (Phase 3, L20). A page load is still served the page, at
                // its lightest, so the probe runs; a script's request goes to
                // the origin. The token changes no score. A silent
                // challenge has no work to waive and is left alone.
                let (mut status, mut extra, mut outcome) = (403, Vec::new(), "challenged");
                if let Some(pass) = self.pass.as_ref().filter(|_| kind != ChallengeKind::Silent) {
                    let origin = f.authority.to_ascii_lowercase();
                    match pass.redeem(f.authorization.as_deref(), &origin, now) {
                        // A script's request goes to the origin: it cannot
                        // show the page, and the token is spent on it. A
                        // page load gets the page at its lightest, so the
                        // probe runs.
                        Redemption::Redeemed if !f.is_navigation() => {
                            self.log(&f, &a, &d, "token_passed", now);
                            if self.upstream.is_none() {
                                self.serve_report(session, &f, &a).await?;
                                return Ok(true);
                            }
                            ctx.upstream_headers = Self::origin_headers(&f, &a, &d);
                            ctx.upstream_headers.push(("x-veritell-token", "privacy-pass".to_string()));
                            return Ok(false);
                        }
                        Redemption::Redeemed => {
                            difficulty = pow::MIN_DIFFICULTY;
                            outcome = "token_redeemed";
                        }
                        refused => {
                            if let Redemption::Refused(why) = refused {
                                outcome = why;
                            }
                            // Ask (again): a client that can fetch a token
                            // does, and every other client shows the page.
                            if let Some(offer) = pass.offer(&origin, now) {
                                status = 401;
                                extra.push(("www-authenticate", offer));
                            }
                        }
                    }
                }
                self.log(&f, &a, &d, outcome, now);
                // Only a GET can be replayed by a redirect; others go home.
                let return_to = if f.method == "GET" {
                    f.path_and_query.as_str()
                } else {
                    "/"
                };
                self.serve_challenge(session, &f, difficulty, return_to, now, (status, &extra))
                    .await?;
                Ok(true)
            }
            Action::Throttle { .. } => {
                self.log(&f, &a, &d, "throttled", now);
                self.respond(
                    session,
                    429,
                    "text/plain",
                    b"too many requests".to_vec(),
                    &[("retry-after", "60".to_string())],
                )
                .await?;
                Ok(true)
            }
            Action::Tarpit => {
                self.log(&f, &a, &d, "tarpitted", now);
                tokio::time::sleep(TARPIT_DELAY).await;
                self.respond(session, 429, "text/plain", b"too many requests".to_vec(), &[])
                    .await?;
                Ok(true)
            }
            // Phase 0 placeholder: a generic not-found instead of real decoy content.
            Action::Decoy => {
                self.log(&f, &a, &d, "decoyed", now);
                self.respond(session, 404, "text/plain", b"not found".to_vec(), &[])
                    .await?;
                Ok(true)
            }
            Action::Charge => {
                self.log(&f, &a, &d, "charged", now);
                let (body, extra) = Self::offer_answer(&d);
                self.respond(session, 402, "application/json", body, &extra).await?;
                Ok(true)
            }
            Action::Block => {
                self.log(&f, &a, &d, "blocked", now);
                self.respond(session, 403, "text/plain", b"forbidden".to_vec(), &[])
                    .await?;
                Ok(true)
            }
        }
    }

    /// A proxied request's body: all of it within `--body-timeout` of the
    /// headers. Each chunk is checked as it comes; one that never comes is
    /// the per-read timeout's (HTTP/1) or the frame deadline's (HTTP/2).
    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        if body.is_some() && ctx.request_started.is_some_and(|t| t.elapsed() > self.body_timeout) {
            return Err(Error::explain(ErrorType::ReadTimedout, "request body not complete in time"));
        }
        Ok(())
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        if !self.host_upstreams.is_empty() {
            let req = session.req_header();
            let authority = req.uri.authority().map(|a| a.as_str()).or_else(|| header(req, "host"));
            let name = authority.and_then(host_name).map(|h| h.trim_end_matches('.').to_ascii_lowercase());
            if let Some((host, port)) = name.and_then(|n| self.host_upstreams.get(&n)) {
                return Ok(Box::new(HttpPeer::new((host.as_str(), *port), false, host.clone())));
            }
        }
        let (host, port) = self
            .upstream
            .clone()
            .ok_or_else(|| Error::explain(ErrorType::InternalError, "no upstream configured"))?;
        if !self.upstream_tls {
            return Ok(Box::new(HttpPeer::new((host.as_str(), port), false, host.clone())));
        }
        let req = session.req_header();
        let authority = req.uri.authority().map(|a| a.as_str()).or_else(|| header(req, "host"));
        let sni = upstream_sni(authority, self.upstream_sni.as_deref(), &host);
        let mut peer = HttpPeer::new((host.as_str(), port), true, sni);
        // HttpPeer::new leaves both checks on; stated so a change is seen.
        peer.options.verify_cert = true;
        peer.options.verify_hostname = true;
        if let Some(ca) = &self.upstream_ca {
            peer.options.ca = Some(Arc::clone(ca));
        }
        Ok(Box::new(peer))
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        let value = |name: &str| upstream_response.headers.get(name).and_then(|v| v.to_str().ok());
        let (status, content_type, encoding) =
            (upstream_response.status.as_u16(), value("content-type"), value("content-encoding"));
        let etag = value("etag").map(crate::inject::weaken_etag);
        if ctx.injection.on_response(status, content_type, encoding) {
            // The body changes: its length goes, and a strong validator
            // would now be false. Over HTTP/1.1 it is sent chunked, said in
            // the header: without a length or that, the body ends when the
            // connection closes, and every page costs the client a new
            // connection. HTTP/2 frames the body itself and drops the
            // header; HTTP/1.0 has no chunks and keeps the close.
            upstream_response.remove_header("content-length");
            if session.req_header().version == http::Version::HTTP_11
                && !upstream_response.headers.contains_key("transfer-encoding")
            {
                upstream_response.insert_header("transfer-encoding", "chunked")?;
            }
            if let Some(etag) = etag {
                upstream_response.insert_header("etag", etag)?;
            }
        }
        Ok(())
    }

    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<std::time::Duration>> {
        if ctx.injection != crate::inject::Injection::Pass {
            let chunk = body.take().map(|b| b.to_vec());
            *body = ctx.injection.on_body(chunk, end_of_stream).map(Bytes::from);
        }
        Ok(None)
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // Drop anything the client sent under our prefix, then add our own.
        let spoofed: Vec<String> = upstream_request
            .headers
            .keys()
            .map(|k| k.as_str().to_string())
            .filter(|k| k.starts_with(HEADER_PREFIX))
            .collect();
        for name in spoofed {
            upstream_request.remove_header(name.as_str());
        }
        crate::inject::drop_accept_encoding(&ctx.injection, upstream_request);
        crate::inject::drop_stale_validators(&ctx.injection, upstream_request);
        for (name, value) in std::mem::take(&mut ctx.upstream_headers) {
            upstream_request.insert_header(name, value)?;
        }
        set_forwarding(upstream_request, ctx, self.forwarded_replace)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    mod rules_2026_11 {
        use super::super::{crawler_from_another_network, unknown_agent_is_not_a_person};
        use veritell_core::{Class, Detection, Layer};

        fn det(id: &str) -> Detection {
            Detection::new(id, Layer::Identity, 10, "test")
        }
        fn ids(d: &[Detection]) -> Vec<&str> {
            d.iter().map(|d| d.id.as_str()).collect()
        }

        #[test]
        fn an_unknown_agent_is_not_a_person() {
            let mut d = vec![det("ua_unknown"), det("missing_sec_fetch")];
            unknown_agent_is_not_a_person(&mut d);
            assert_eq!(d[0].class_hint, Some(Class::UnverifiedAgent));
            assert_eq!(d[0].penalty, 10);
            assert_eq!(d[1].class_hint, None);
        }

        #[test]
        fn a_stronger_hint_is_kept() {
            let mut d = vec![det("ua_unknown").with_class(Class::Malicious)];
            unknown_agent_is_not_a_person(&mut d);
            assert_eq!(d[0].class_hint, Some(Class::Malicious));
        }

        #[test]
        fn googlebot_from_another_network_is_spoofed() {
            let mut d = vec![det("crawler_unresolved"), det("bot_unverified")];
            crawler_from_another_network(&mut d, "Googlebot", 212238);
            assert_eq!(ids(&d), ["bot_unverified", "crawler_spoofed"]);
            assert_eq!(d[1].class_hint, Some(Class::Malicious));
            assert!(d[1].detail.contains("AS212238"));
        }

        #[test]
        fn the_operators_own_network_stays_unresolved() {
            for (name, asn) in [("Googlebot", 15169), ("Bingbot", 8075), ("Applebot", 714), ("Applebot", 6185)] {
                let mut d = vec![det("crawler_unresolved")];
                crawler_from_another_network(&mut d, name, asn);
                assert_eq!(ids(&d), ["crawler_unresolved"], "{name} {asn}");
            }
        }

        #[test]
        fn no_network_known_or_another_crawler_changes_nothing() {
            let mut d = vec![det("crawler_unresolved")];
            crawler_from_another_network(&mut d, "Googlebot", 0);
            assert_eq!(ids(&d), ["crawler_unresolved"]);
            crawler_from_another_network(&mut d, "Baiduspider", 212238);
            assert_eq!(ids(&d), ["crawler_unresolved"]);
        }
    }

    mod ios_app_icon {
        use super::super::drop_ios_app_icon_fetch;
        use veritell_core::{Detection, Layer};

        const DDG: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.3 Mobile/15E148 Safari/604.1 Ddg/27.3";
        const APPLE: &str = "2:0;4:2097152;3:100;9:1|10485760|0|m,s,p,a";
        const WEBKIT: &str = "2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p";

        fn fired(ids: &[&str]) -> Vec<Detection> {
            ids.iter().map(|i| Detection::new(i, Layer::Network, 10, "test")).collect()
        }
        fn after(method: &str, path: &str, ua: &str, h2: &str, ids: &[&str]) -> Vec<String> {
            let mut d = fired(ids);
            drop_ios_app_icon_fetch(&mut d, method, path, Some(ua), Some(h2));
            d.into_iter().map(|d| d.id.to_string()).collect()
        }
        const SEEN: [&str; 3] = ["h2_settings_mismatch", "h2_pseudo_order_mismatch", "missing_sec_fetch"];

        #[test]
        fn an_ios_apps_icon_fetch_is_clean() {
            for path in ["/favicon.ico", "/apple-touch-icon.png", "/apple-touch-icon-240x240-precomposed.png", "/favicon.svg"] {
                assert!(after("GET", path, DDG, APPLE, &SEEN).is_empty(), "{path}");
            }
            assert!(after("HEAD", "/favicon.ico", DDG, APPLE, &SEEN).is_empty());
        }

        #[test]
        fn other_findings_stay() {
            assert_eq!(after("GET", "/favicon.ico", DDG, APPLE, &["h2_settings_mismatch", "net_hosting"]), ["net_hosting"]);
        }

        #[test]
        fn only_icons() {
            for path in ["/", "/missions", "/item/1", "/favicon.ico.php", "/img/apple-touch-icon.png", "/apple-touch-icon.png/x"] {
                assert_eq!(after("GET", path, DDG, APPLE, &SEEN).len(), 3, "{path}");
            }
            assert_eq!(after("POST", "/favicon.ico", DDG, APPLE, &SEEN).len(), 3);
        }

        #[test]
        fn only_apples_system_client_on_ios() {
            let mac = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.3 Safari/605.1.15";
            assert_eq!(after("GET", "/favicon.ico", mac, APPLE, &SEEN).len(), 3);
            assert_eq!(after("GET", "/favicon.ico", DDG, WEBKIT, &SEEN).len(), 3);
            assert_eq!(after("GET", "/favicon.ico", DDG, "1:65536;2:0;4:6291456|15663105|0|m,a,s,p", &SEEN).len(), 3);
        }

        #[test]
        fn not_with_another_tls_stack() {
            let ids = ["tls_ua_mismatch", "h2_settings_mismatch", "h2_pseudo_order_mismatch", "missing_sec_fetch"];
            assert_eq!(after("GET", "/favicon.ico", DDG, APPLE, &ids).len(), 4);
        }
    }

    #[test]
    fn network_of_looks_up_both_families() {
        use super::{network_of, AsnDb};
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        let db = AsnDb::from_iptoasn_tsv(
            "203.0.113.0\t203.0.113.255\t64500\tZZ\tEXAMPLE-HOSTING\n\
             2001:db8::\t2001:db8:ffff:ffff:ffff:ffff:ffff:ffff\t64501\tZZ\tEXAMPLE-ISP\n",
        )
        .unwrap();
        let v4 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let mapped = IpAddr::V6(Ipv4Addr::new(203, 0, 113, 7).to_ipv6_mapped());
        let v6: IpAddr = "2001:db8::42".parse().unwrap();
        let none = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let (asn, _, _) = network_of(&db, v4);
        assert_eq!(asn, 64500);
        // A dual-stack listener sees IPv4 visitors as ::ffff:a.b.c.d.
        assert_eq!(network_of(&db, mapped).0, 64500);
        assert_eq!(network_of(&db, v6).0, 64501);
        let (asn, class, det) = network_of(&db, none);
        assert_eq!((asn, class, det.is_none()), (0, "unknown", true));
        let (asn, class, det) = network_of(&AsnDb::empty(), v4);
        assert_eq!((asn, class, det.is_none()), (0, "unknown", true));
    }

    use super::{forwarded_ip, stable_ja4, upstream_sni};
    use super::{admitted, signed_agent_of, last_forwarded, original_request, set_forwarding, Ctx, Original, SidecarError};
    use super::{check_solution, effective_action, link_difficulty, retry_difficulty, source_link, without_bot_claim};

    #[test]
    fn the_source_link_takes_plain_urls_only() {
        assert_eq!(
            source_link("https://github.com/veritell/veritell").as_deref(),
            Some(
                "<p class=\"source\">Powered by <a href=\"https://veritell.io\">Veritell</a> · \
                 <a href=\"https://github.com/veritell/veritell\">Source code</a> (AGPL-3.0)</p>\n</body>"
            )
        );
        assert!(source_link("https://example.test/src?a=1&b=2").unwrap().contains("?a=1&amp;b=2"));
        for bad in ["javascript:alert(1)", "ftp://x.test/", "https://x.test/\"onclick=\"x", "https://x.test/<b>", "https://x.test/ a", ""] {
            assert_eq!(source_link(bad), None, "{bad}");
        }
    }

    /// Web Bot Auth through the gateway's own steps (verify, signature_info,
    /// signed_agent_of) with requests signed here, as an agent would.
    mod wba_flow {
        use super::super::{is_write, signed_agent_of};
        use base64::Engine as _;
        use ed25519_dalek::{Signer, SigningKey};
        use veritell_wba::{signature_base, signature_info, verify, Ed25519Key, ReplayCache, RequestParts, TrustedAgents};

        const NOW: u64 = 1_800_000_000;

        fn key(seed: u8) -> SigningKey {
            SigningKey::from_bytes(&[seed; 32])
        }

        fn trusting(k: &SigningKey) -> TrustedAgents {
            let mut t = TrustedAgents::new();
            t.add("agent.test", None, vec![Ed25519Key::from_public(k.verifying_key().to_bytes())]).unwrap();
            t
        }

        struct Signed {
            input: String,
            signature: String,
        }

        /// `/a?b` as its path and query.
        fn split(target: &str) -> (&str, Option<&str>) {
            match target.split_once('?') {
                Some((p, q)) => (p, Some(q)),
                None => (target, None),
            }
        }

        /// Signs `method target` on shop.test, covering `components`.
        fn sign(k: &SigningKey, method: &str, target: &str, components: &[&str], nonce: &str) -> Signed {
            let (path, query) = split(target);
            let keyid = Ed25519Key::from_public(k.verifying_key().to_bytes()).keyid;
            let list = components.iter().map(|c| format!("\"{c}\"")).collect::<Vec<_>>().join(" ");
            let member = format!(
                "({list});created={};expires={};keyid=\"{keyid}\";nonce=\"{nonce}\";tag=\"web-bot-auth\"",
                NOW - 10,
                NOW + 300
            );
            let parts = RequestParts { method, authority: "shop.test", path, query, headers: &[] };
            let base = signature_base(&parts, &member).unwrap();
            let sig = base64::engine::general_purpose::STANDARD.encode(k.sign(base.as_bytes()).to_bytes());
            Signed { input: format!("sig1={member}"), signature: format!("sig1=:{sig}:") }
        }

        /// What the gateway concludes for `method target` carrying `s`.
        fn judge(trusted: &TrustedAgents, cache: &mut ReplayCache, method: &str, target: &str, s: &Signed) -> (Option<String>, Option<String>) {
            let (path, query) = split(target);
            let headers = [("signature-input", s.input.as_str()), ("signature", s.signature.as_str())];
            let parts = RequestParts { method, authority: "shop.test", path, query, headers: &headers };
            let verdict = verify(&parts, trusted, NOW);
            let info = signature_info(&parts);
            let (agent, found) = signed_agent_of(verdict, info.as_ref(), is_write(method), query.is_some(), cache, NOW);
            (agent, found.map(|d| d.id))
        }

        #[test]
        fn a_read_signed_over_the_authority_alone_proves_the_agent() {
            let k = key(1);
            let s = sign(&k, "GET", "/catalog", &["@authority"], "n1");
            let got = judge(&trusting(&k), &mut ReplayCache::new(64), "GET", "/catalog", &s);
            assert_eq!(got, (Some("agent.test".into()), None));
        }

        #[test]
        fn a_write_must_bind_its_method_and_path() {
            let (k, mut cache) = (key(1), ReplayCache::new(64));
            let t = trusting(&k);
            for (method, covered) in [
                ("POST", &["@authority"][..]),
                ("POST", &["@authority", "@method"][..]),
                ("POST", &["@authority", "@path"][..]),
                ("DELETE", &["@authority"][..]),
                ("PUT", &["@authority", "@query"][..]),
            ] {
                let s = sign(&k, method, "/cart", covered, &format!("{method}{}", covered.len()));
                assert_eq!(
                    judge(&t, &mut cache, method, "/cart", &s),
                    (None, Some("wba_write_unbound".into())),
                    "{method} covering {covered:?}"
                );
            }
            let s = sign(&k, "POST", "/cart", &["@authority", "@method", "@path"], "bound");
            assert_eq!(judge(&t, &mut cache, "POST", "/cart", &s), (Some("agent.test".into()), None));
        }

        #[test]
        fn a_write_with_a_query_must_bind_the_query_too() {
            let (k, mut cache) = (key(1), ReplayCache::new(64));
            let t = trusting(&k);
            // Method and path alone leave the query free: unbound.
            let s = sign(&k, "POST", "/cart?id=4", &["@authority", "@method", "@path"], "q1");
            assert_eq!(judge(&t, &mut cache, "POST", "/cart?id=4", &s), (None, Some("wba_write_unbound".into())));
            for (n, covered) in [
                &["@authority", "@method", "@path", "@query"][..],
                &["@authority", "@method", "@request-target"][..],
                &["@authority", "@method", "@target-uri"][..],
            ]
            .into_iter()
            .enumerate()
            {
                let s = sign(&k, "POST", "/cart?id=4", covered, &format!("q2-{n}"));
                assert_eq!(judge(&t, &mut cache, "POST", "/cart?id=4", &s), (Some("agent.test".into()), None), "{covered:?}");
            }
            // The whole target binds the path without @path.
            let s = sign(&k, "POST", "/cart", &["@authority", "@method", "@request-target"], "q3");
            assert_eq!(judge(&t, &mut cache, "POST", "/cart", &s), (Some("agent.test".into()), None));
            // And a query signed with the target cannot be swapped.
            let s = sign(&k, "POST", "/cart?id=4", &["@authority", "@method", "@target-uri"], "q4");
            assert_eq!(judge(&t, &mut cache, "POST", "/cart?id=5", &s).1.as_deref(), Some("wba_bad_signature"));
        }

        #[test]
        fn a_bound_signature_does_not_carry_over_to_another_method_or_path() {
            let (k, mut cache) = (key(1), ReplayCache::new(64));
            let t = trusting(&k);
            let s = sign(&k, "POST", "/cart", &["@authority", "@method", "@path"], "n2");
            let (agent, found) = judge(&t, &mut cache, "POST", "/account/delete", &s);
            assert_eq!((agent, found.as_deref()), (None, Some("wba_bad_signature")));
            let (agent, found) = judge(&t, &mut cache, "DELETE", "/cart", &s);
            assert_eq!((agent, found.as_deref()), (None, Some("wba_bad_signature")));
        }

        #[test]
        fn an_unbound_signature_on_a_read_cannot_be_reused_for_a_write() {
            // Captured from a GET, sent again as a POST: same signature over
            // the authority only. Not an agent either way the second time.
            let (k, mut cache) = (key(1), ReplayCache::new(64));
            let t = trusting(&k);
            let s = sign(&k, "GET", "/", &["@authority"], "n3");
            assert_eq!(judge(&t, &mut cache, "GET", "/", &s).0.as_deref(), Some("agent.test"));
            assert_eq!(judge(&t, &mut cache, "POST", "/cart", &s), (None, Some("wba_write_unbound".into())));
            assert_eq!(judge(&t, &mut cache, "GET", "/", &s), (None, Some("wba_replay".into())));
        }

        #[test]
        fn a_bound_write_is_still_single_use() {
            let (k, mut cache) = (key(1), ReplayCache::new(64));
            let t = trusting(&k);
            let s = sign(&k, "POST", "/cart", &["@authority", "@method", "@path"], "n4");
            assert_eq!(judge(&t, &mut cache, "POST", "/cart", &s).0.as_deref(), Some("agent.test"));
            assert_eq!(judge(&t, &mut cache, "POST", "/cart", &s), (None, Some("wba_replay".into())));
        }

        #[test]
        fn an_untrusted_key_proves_nothing_even_when_it_binds_everything() {
            let (signer, other) = (key(1), key(2));
            let s = sign(&signer, "POST", "/cart", &["@authority", "@method", "@path"], "n5");
            let got = judge(&trusting(&other), &mut ReplayCache::new(64), "POST", "/cart", &s);
            assert_eq!(got, (None, Some("wba_unknown_key".into())));
        }

        #[test]
        fn safe_methods_are_reads() {
            for m in ["GET", "HEAD", "OPTIONS"] {
                assert!(!is_write(m), "{m}");
            }
            for m in ["POST", "PUT", "PATCH", "DELETE", "CONNECT", "TRACE", "PROPFIND"] {
                assert!(is_write(m), "{m}");
            }
        }
    }

    #[test]
    fn a_challenge_link_carries_the_endpoints_level() {
        let (k, b) = (keys(), Binding([1; 16]));
        let c = pow::issue_challenge(&k, &b, 1_000, 120, 14);
        assert_eq!(link_difficulty(&k, &form(&[("c", &c), ("return_to", "/a")])), Some(14));
        assert_eq!(link_difficulty(&k, &form(&[("return_to", "/a")])), None, "no c: the page scores the request");
        assert_eq!(link_difficulty(&k, &form(&[("c", "made-up")])), None);
        let other = pow::issue_challenge(&Keys::from_secret(&[8u8; 32]).unwrap(), &b, 1_000, 120, 8);
        assert_eq!(link_difficulty(&k, &form(&[("c", &other)])), None, "another gateway's string");
    }

    #[test]
    fn an_unverified_crawler_is_checked_as_a_made_up_one() {
        let table = veritell_ua::TruthTable::builtin();
        let curl_ja4 = "t13d4907h2_0d8feac7bc37_7395dae3b2f3";
        let ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
        let check = |ua: &str| table.check(&veritell_ua::Observed { user_agent: Some(ua), ja4: Some(curl_ja4), ..Default::default() });
        let first = check(ua);
        let ids: Vec<&str> = first.iter().map(|d| d.id.as_str()).collect();
        assert_eq!(ids, ["ua_declared_bot"], "the table trusts a known name");
        let neutral = without_bot_claim(ua, &first[0].detail).expect("name found");
        assert!(neutral.contains("Unverifiedbot/2.1") && !neutral.contains("Googlebot"), "{neutral}");
        let again = check(&neutral);
        assert!(again.iter().any(|d| d.id != "ua_declared_bot" && d.penalty > 0),
            "curl's TLS stack behind a crawler claim must show: {:?}", again.iter().map(|d| &d.id).collect::<Vec<_>>());
        // A detail without a name found in the User-Agent changes nothing.
        assert_eq!(without_bot_claim(ua, "User-Agent claims to be a crawler: Nobot"), None);
        assert_eq!(without_bot_claim(ua, "no colon"), None);
    }
    use veritell_core::{Action, ChallengeKind};
    use veritell_policy::Decision;
    use veritell_token::{pow, Binding, Keys, MemoryBudgetStore};

    fn decision(action: Action, enforced: bool) -> Decision {
        Decision { action, enforced, route: None, rule: None, error: None, offer: None }
    }

    #[test]
    fn shadow_mode_never_acts() {
        for action in [
            Action::Block,
            Action::Tarpit,
            Action::Decoy,
            Action::Charge,
            Action::Challenge(ChallengeKind::Pow),
            Action::Throttle { per_minute: 1 },
        ] {
            let mut asked = false;
            let got = effective_action(&decision(action, false), false, false, |_| {
                asked = true;
                false
            });
            assert_eq!(got, Action::Pass, "{action:?}");
            assert!(!asked, "shadow mode must not count against a rate: {action:?}");
        }
    }

    #[test]
    fn enforced_actions_and_their_waivers() {
        let pow = Action::Challenge(ChallengeKind::Pow);
        assert_eq!(effective_action(&decision(pow, true), false, false, |_| true), pow);
        assert_eq!(effective_action(&decision(pow, true), true, false, |_| true), Action::Pass, "a token waives a challenge");
        // A token waives only a challenge.
        assert_eq!(effective_action(&decision(Action::Block, true), true, true, |_| true), Action::Block);
        assert_eq!(effective_action(&decision(Action::Charge, true), false, false, |_| true), Action::Charge);
        assert_eq!(effective_action(&decision(Action::Charge, true), false, true, |_| true), Action::Pass, "a receipt claim waives a charge");
        assert_eq!(effective_action(&decision(Action::Pass, true), false, false, |_| false), Action::Pass);
    }

    #[test]
    fn a_throttle_asks_with_its_rate_and_acts_only_when_over() {
        let throttle = Action::Throttle { per_minute: 30 };
        let mut rate = 0;
        let got = effective_action(&decision(throttle, true), false, false, |r| {
            rate = r;
            true
        });
        assert_eq!((got, rate), (Action::Pass, 30));
        assert_eq!(effective_action(&decision(throttle, true), true, true, |_| false), throttle);
    }

    fn keys() -> Keys {
        Keys::from_secret(&[7u8; 32]).unwrap()
    }

    fn form(fields: &[(&str, &str)]) -> HashMap<String, String> {
        fields.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    /// A challenge for `binding` at the lowest difficulty, and its answer.
    fn solved(keys: &Keys, binding: &Binding, now: u64) -> (String, String) {
        let c = pow::issue_challenge(keys, binding, now, 120, pow::MIN_DIFFICULTY);
        let counter = pow::solve(&c, 1 << 24).expect("solvable");
        (c, counter.to_string())
    }

    #[test]
    fn a_solution_mints_once() {
        let (k, b, used) = (keys(), Binding([1; 16]), MemoryBudgetStore::new(100));
        let (c, n) = solved(&k, &b, 1_000);
        let f = form(&[("challenge", &c), ("counter", &n)]);
        assert!(check_solution(&k, &used, &f, &b, 1_010).is_some());
        assert!(check_solution(&k, &used, &f, &b, 1_011).is_none(), "a replay must not mint a second token");
    }

    #[test]
    fn a_wrong_or_foreign_solution_is_refused() {
        let (k, b, used) = (keys(), Binding([1; 16]), MemoryBudgetStore::new(100));
        let (c, n) = solved(&k, &b, 1_000);
        let ok = form(&[("challenge", &c), ("counter", &n)]);
        // Another client (binding), too late, or signed with another key.
        assert!(check_solution(&k, &used, &ok, &Binding([2; 16]), 1_010).is_none());
        assert!(check_solution(&k, &used, &ok, &b, 1_000 + 121).is_none());
        let other = Keys::from_secret(&[8u8; 32]).unwrap();
        assert!(check_solution(&other, &used, &ok, &b, 1_010).is_none());
        // Missing or malformed fields.
        for f in [
            form(&[("challenge", &c)]),
            form(&[("counter", &n)]),
            form(&[("challenge", &c), ("counter", "x")]),
            form(&[("challenge", "garbage"), ("counter", &n)]),
        ] {
            assert!(check_solution(&k, &used, &f, &b, 1_010).is_none(), "{f:?}");
        }
        // None of that used the challenge up: the right answer still works.
        assert!(check_solution(&k, &used, &ok, &b, 1_010).is_some());
    }

    #[test]
    fn a_full_store_refuses_a_good_solution() {
        let (k, b) = (keys(), Binding([1; 16]));
        let used = MemoryBudgetStore::new(0);
        let (c, n) = solved(&k, &b, 1_000);
        assert!(check_solution(&k, &used, &form(&[("challenge", &c), ("counter", &n)]), &b, 1_010).is_none());
    }

    #[test]
    fn a_retry_keeps_the_failed_challenges_level() {
        let (k, b) = (keys(), Binding([1; 16]));
        let c = pow::issue_challenge(&k, &b, 1_000, 120, 14);
        assert_eq!(retry_difficulty(&k, &form(&[("challenge", &c)])), 14);
        let hardest = pow::difficulty_for_score(1);
        assert_eq!(retry_difficulty(&k, &form(&[("challenge", "not ours")])), hardest);
        assert_eq!(retry_difficulty(&k, &form(&[])), hardest);
        let foreign = pow::issue_challenge(&Keys::from_secret(&[8u8; 32]).unwrap(), &b, 1_000, 120, 8);
        assert_eq!(retry_difficulty(&k, &form(&[("challenge", &foreign)])), hardest);
    }
    use pingora::http::RequestHeader;
    use std::collections::HashMap;
    use veritell_token::Consumed;

    #[test]
    fn every_forwarded_line_is_read_and_the_last_entry_wins() {
        let last = |lines: &[&str]| last_forwarded(lines.iter().map(|l| Some(*l)));
        // The client's own line first, the proxy's line after it.
        assert_eq!(last(&["66.249.66.1", "198.51.100.7"]), "198.51.100.7".parse().ok());
        assert_eq!(last(&["1.1.1.1, 2.2.2.2", " 198.51.100.7 "]), "198.51.100.7".parse().ok());
        assert_eq!(last(&["198.51.100.7", ""]), "198.51.100.7".parse().ok());
        assert_eq!(last(&["198.51.100.7"]), "198.51.100.7".parse().ok());
        assert_eq!(last(&[]), None);
        assert_eq!(last(&["198.51.100.7", "garbage"]), None);
        // A line that is not text spoils the whole header.
        assert_eq!(last_forwarded([Some("66.249.66.1"), None].into_iter()), None);
    }

    fn original(headers: &[(&str, &str)], suffix: Option<&str>) -> Result<Original, SidecarError> {
        let map: HashMap<String, String> =
            headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        original_request(|n| map.get(n).cloned(), suffix.map(str::to_owned), "POST")
    }

    #[test]
    fn sidecar_reads_either_header_family() {
        let o = original(&[("x-original-uri", "/a?b=1"), ("x-original-method", "PUT"), ("x-original-host", "site.test")], None).unwrap();
        assert_eq!(o, Original { uri: "/a?b=1".into(), method: "PUT".into(), host: "site.test".into() });
        let o = original(&[("x-forwarded-uri", "/a"), ("host", "gw.test")], None).unwrap();
        assert_eq!(o, Original { uri: "/a".into(), method: "GET".into(), host: "gw.test".into() });
        // The same value in both is fine; hosts compare by name.
        let o = original(&[("x-original-uri", "/a"), ("x-forwarded-uri", "/a"), ("x-original-host", "Site.test"), ("x-forwarded-host", "site.test:443")], None).unwrap();
        assert_eq!((o.uri.as_str(), o.host.as_str()), ("/a", "site.test:443"));
    }

    #[test]
    fn a_spoofed_original_header_is_refused() {
        // Caddy or Traefik set x-forwarded-*; the client added x-original-*.
        for (name, fwd, spoof) in [("uri", "/admin", "/open/x"), ("method", "POST", "GET"), ("host", "admin.test", "open.test")] {
            let headers = [(format!("x-forwarded-{name}"), fwd), (format!("x-original-{name}"), spoof), ("x-forwarded-uri".to_string(), "/admin")];
            let headers: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (k.as_str(), *v)).collect();
            assert_eq!(original(&headers, None), Err(SidecarError::Conflict), "{name}");
        }
        assert_eq!(original(&[], None), Err(SidecarError::Missing));
        assert_eq!(original(&[("x-original-uri", "http://evil.test/")], None), Err(SidecarError::Missing));
    }

    #[test]
    fn sidecar_path_suffix_uses_the_calls_own_method() {
        let o = original(&[("x-original-uri", "/elsewhere"), ("x-original-method", "GET")], Some("/open/y?z=2")).unwrap();
        assert_eq!((o.uri.as_str(), o.method.as_str()), ("/open/y?z=2", "POST"));
    }

    #[test]
    fn a_replayed_signature_proves_no_agent() {
        use veritell_wba::{ReplayCache, SignatureInfo, WbaVerdict};
        let mut cache = ReplayCache::new(10);
        let info = SignatureInfo { replay_id: [7; 32], expires: 1_000, components: vec!["@authority".into()] };
        let verified = || WbaVerdict::Verified { agent: "agent.test".into(), keyid: "k".into() };
        let (agent, found) = signed_agent_of(verified(), Some(&info), false, false, &mut cache, 900);
        assert_eq!((agent.as_deref(), found.is_none()), (Some("agent.test"), true));
        // The same signature again is a replay.
        let (agent, found) = signed_agent_of(verified(), Some(&info), false, false, &mut cache, 901);
        assert_eq!((agent, found.map(|d| d.id)), (None, Some("wba_replay".to_string())));
        // A new signature from the same agent is fine.
        let other = SignatureInfo { replay_id: [8; 32], ..info.clone() };
        assert_eq!(signed_agent_of(verified(), Some(&other), false, false, &mut cache, 902).0.as_deref(), Some("agent.test"));
        // No replay facts: not believed.
        assert_eq!(signed_agent_of(verified(), None, false, false, &mut cache, 902).0, None);
    }

    #[test]
    fn an_unknown_key_proves_no_agent() {
        use veritell_wba::{ReplayCache, WbaVerdict};
        let mut cache = ReplayCache::new(10);
        let (agent, found) = signed_agent_of(WbaVerdict::UnknownKey { keyid: "k".into() }, None, false, false, &mut cache, 1);
        assert_eq!((agent, found.map(|d| d.id)), (None, Some("wba_unknown_key".to_string())));
        assert!(cache.is_empty(), "an unknown key fills nothing");
        let (agent, found) = signed_agent_of(WbaVerdict::Absent, None, false, false, &mut cache, 1);
        assert!(agent.is_none() && found.is_none());
    }

    #[test]
    fn a_full_store_refuses() {
        assert!(admitted(Consumed::Used, "test"));
        assert!(!admitted(Consumed::Spent, "test"));
        assert!(!admitted(Consumed::Full, "test"));
    }

    fn forwarded(ctx: &Ctx, replace: bool, client: &[(&str, &str)]) -> Vec<(String, String)> {
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        for (k, v) in client {
            req.append_header(k.to_string(), *v).unwrap();
        }
        set_forwarding(&mut req, ctx, replace).unwrap();
        let mut out: Vec<(String, String)> = req
            .headers
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap().to_string()))
            .collect();
        out.sort();
        out
    }

    #[test]
    fn the_origin_gets_the_gateways_view_of_the_client() {
        let spoofed = [
            ("x-real-ip", "66.249.66.1"),
            ("forwarded", "for=66.249.66.1"),
            ("x-forwarded-host", "admin.test"),
            ("x-forwarded-for", "66.249.66.1"),
        ];
        let peer = "198.51.100.7".parse().ok();
        let ctx = Ctx { peer_ip: peer, client_ip: peer, ..Ctx::default() };
        let pairs = |v: &[(&str, &str)]| -> Vec<(String, String)> {
            v.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
        };
        assert_eq!(
            forwarded(&ctx, false, &spoofed),
            pairs(&[
                ("x-forwarded-for", "66.249.66.1, 198.51.100.7"),
                ("x-forwarded-proto", "https"),
                ("x-real-ip", "198.51.100.7"),
            ])
        );
        assert_eq!(
            forwarded(&ctx, true, &spoofed),
            pairs(&[("x-forwarded-for", "198.51.100.7"), ("x-forwarded-proto", "https"), ("x-real-ip", "198.51.100.7")])
        );
        // Behind a trusted proxy, its forwarding headers stay, and the client
        // is the address it reported.
        let ctx = Ctx {
            peer_ip: "10.0.0.1".parse().ok(),
            client_ip: "203.0.113.5".parse().ok(),
            behind_proxy: true,
            ..Ctx::default()
        };
        let got = forwarded(&ctx, false, &[("x-forwarded-host", "site.test"), ("x-forwarded-for", "203.0.113.5")]);
        assert!(got.contains(&("x-forwarded-host".into(), "site.test".into())));
        assert!(got.contains(&("x-real-ip".into(), "203.0.113.5".into())));
        assert!(got.contains(&("x-forwarded-for".into(), "203.0.113.5, 10.0.0.1".into())));
    }

    #[test]
    fn upstream_sni_choice() {
        let sni = |a, c| upstream_sni(a, c, "10.0.0.1");
        assert_eq!(sni(Some("site.test"), None), "site.test");
        assert_eq!(sni(Some("site.test:8443"), Some("other.test")), "site.test");
        assert_eq!(sni(Some("127.0.0.1:8443"), Some("other.test")), "other.test");
        assert_eq!(sni(Some("[::1]:8443"), Some("other.test")), "other.test");
        assert_eq!(sni(Some("[::1]"), None), "10.0.0.1");
        assert_eq!(sni(Some("[2001:db8::1]:443"), None), "10.0.0.1");
        assert_eq!(sni(Some("::1"), Some("other.test")), "other.test");
        assert_eq!(sni(None, Some("other.test")), "other.test");
        assert_eq!(sni(None, None), "10.0.0.1");
        assert_eq!(sni(Some(""), Some("other.test")), "other.test");
        assert_eq!(sni(Some(":443"), None), "10.0.0.1");
        assert_eq!(sni(Some("[::1"), None), "10.0.0.1");
    }

    #[test]
    fn cookie_fields_are_joined() {
        use super::join_cookie_fields;
        assert_eq!(join_cookie_fields(["a=1", "b=2"].into_iter()), Some("a=1; b=2".into()));
        assert_eq!(join_cookie_fields(["a=1; b=2", " c=3 "].into_iter()), Some("a=1; b=2; c=3".into()));
        assert_eq!(join_cookie_fields(["", "  "].into_iter()), None);
        assert_eq!(join_cookie_fields(std::iter::empty()), None);
    }

    #[test]
    fn mapped_addresses_are_canonical() {
        use super::canonical;
        assert_eq!(canonical("::ffff:10.0.0.1".parse().unwrap()), "10.0.0.1".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(canonical("10.0.0.1".parse().unwrap()), "10.0.0.1".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(canonical("2001:db8::1".parse().unwrap()), "2001:db8::1".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(forwarded_ip("1.1.1.1, ::ffff:203.0.113.9"), "203.0.113.9".parse().ok());
    }

    #[test]
    fn forwarded_address_is_the_last_entry() {
        assert_eq!(forwarded_ip("203.0.113.9"), "203.0.113.9".parse().ok());
        // Earlier entries are whatever the client claimed.
        assert_eq!(forwarded_ip("1.1.1.1, 10.0.0.1 , 2001:db8::7"), "2001:db8::7".parse().ok());
        for bad in ["", ",", "unknown", "1.2.3.4:80", "1.2.3.4,"] {
            assert_eq!(forwarded_ip(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn binding_ignores_what_session_resumption_changes() {
        // Same client, first and resumed handshake: extension count and hash differ.
        let first = stable_ja4("t13d1516h2_8daaf6152771_806a8c22fdea");
        let resumed = stable_ja4("t13d1517h2_8daaf6152771_3cbfd9057e0d");
        assert_eq!(first, resumed);
        assert_eq!(first, "t13d_8daaf6152771");
        // A different cipher list is still a different client.
        assert_ne!(first, stable_ja4("t13d4907h2_0d8feac7bc37_7395dae3b2f3"));
        assert_eq!(stable_ja4(""), "_");
        assert_eq!(stable_ja4("é"), "é_");
    }
}
