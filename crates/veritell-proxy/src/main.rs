//! Veritell gateway binary.
//!
//! veritell --cert cert.pem --key key.pem [--listen 127.0.0.1:8443]
//!          [--upstream host:port] [--policy policy.yaml] [--asn-db ip2asn.tsv]
//!          [--token-budget N] [--wba-agents agents.json]
//!          [--engine-truth engine.json] [--admin 127.0.0.1:9090]
//!          [--clickhouse-url http://host:8123] [--clickhouse-database veritell]
//!          [--clickhouse-table events] [--clickhouse-user default]
//!          [--feed bundle.json --feed-key <base64url Ed25519 public key>]
//!          [--probe-build-rotate 60] [--probe-build-ttl 300]
//!          [--trusted-proxy ip[,ip]] [--agg-slot 10] [--agg-warmup 120] [--agg-reputation-ttl 600]
//!          [--agg-spread-min 50] [--agg-fanout-min 30] [--agg-strikes 3]
//!          [--model model.json] [--sidecar-listen 127.0.0.1:9191]
//!          [--wba-directory-allow ip:port[,ip:port]] [--wba-directory-ca roots.pem]
//!          [--privacy-pass-issuer name=key[,name=key]] [--ip-mode full|truncated|keyed]
//!          [--header-timeout 15] [--body-timeout 60] [--write-timeout 30]
//!          [--max-conns-per-network 256]
//!          [--state-dir dir] [--state-flush 10] [--inject-probe on|off] [--upstream-tls on|off] [--upstream-sni name] [--upstream-ca file.pem] [--forwarded-for append|replace] [--log-requests on|off] [--single-use-capacity 200000]
//!          [--share-export file] [--share-import file --share-import-key key[,key]] [--share-min-networks n] [--share-interval secs]
//!          [--sni-dir dir] [--upstream-host name=host:port[,name=host:port]]
//!
//! `--inject-probe on` adds the probe and behaviour scripts to the origin's
//! HTML pages, so that they report from every visitor's browser, not only
//! from a challenge page; see `inject.rs`. Off by default.
//!
//! `--state-dir` keeps the day's quota use and every single-use store
//! (redeemed tokens, solved challenges, token budgets, nonces) in files in
//! that directory, so a restart neither resets a quota nor lets a used token
//! be used again. They are saved every `--state-flush` seconds and on a
//! graceful shutdown (SIGTERM); see `state.rs`.
//!
//! `--header-timeout` is the time a request's headers have to arrive in full:
//! on HTTP/1, the first request's from the end of the TLS handshake and a
//! later one's from its first byte; on HTTP/2, every frame but DATA and every
//! header block from its first byte. `--body-timeout` is the time a request
//! body has to arrive in full (and one HTTP/2 DATA frame), counted from the
//! request's headers. `--write-timeout` is the longest one write to a client
//! may wait, as for an HTTP/2 client that never opens its receive window.
//! `--max-conns-per-network` caps the connections open at once from one
//! IPv4 address or one IPv6 /64; peers in `--trusted-proxy` are not capped.
//! Both are there for clients that hold connections open by sending slowly.
//!
//! `--source-url` is the link to the source code on the pages the gateway
//! serves itself (the challenge page), as AGPL-3.0 section 13 asks of a
//! program used over a network: by default this repository. It sits in a
//! footer, "Powered by Veritell · Source code". Someone running a changed
//! gateway must point it at their own changed source; `off` drops the whole
//! footer (for an unchanged gateway that offers the source elsewhere).
//!
//! `--ip-mode` sets what is written for a client address in log lines,
//! events and the dashboard: the address (`full`, the default), its /24 or
//! /48 (`truncated`), or a keyed hash under a random key that changes every
//! UTC day and is never written anywhere (`keyed`). Scoring, policy and the
//! in-memory counters always use the real address. With `--state-dir`, the
//! dashboard's events are saved there too (`events.state`, up to 30 days),
//! in the same form: with `full`, client addresses are on disk. The rollout
//! kit runs `keyed`.
//!
//! `--privacy-pass-issuer` lists Privacy Pass issuers whose tokens are
//! accepted in place of the proof of work: the issuer's name and its public
//! key in base64url, as the issuer publishes it (RFC 9578, token type 2).
//! None are trusted by default. With an issuer listed, every proof-of-work
//! challenge, whatever the score, is sent with status 401 and
//! a `WWW-Authenticate: PrivateToken` challenge beside the usual page. The
//! challenge is for the first key listed, so list the preferred issuer
//! first; tokens for any listed key are taken.
//!
//! An agent in the `--wba-agents` file that has `signature_agent` and no
//! `keys` gets its keys from that URL, fetched in the background and kept
//! current (see `directories.rs`). Only `https` URLs on public addresses are
//! fetched. `--wba-directory-allow` lists exact addresses that are fetched
//! although they are private or loopback, for an agent on the operator's own
//! network; `--wba-directory-ca` adds certificates to trust for these
//! fetches.
//!
//! `--model` loads a tree model (example: `scripts/fixtures/e2e_model.json`). It runs in shadow: its
//! score and the features that moved it most are written to each log line
//! beside the rule score, and no action depends on it.
//!
//! `--sidecar-listen` opens a plain-HTTP listener that answers only the
//! authorization endpoint, for a proxy that asks before it serves (see
//! `sidecar/README.md`). It answers only peers listed in `--trusted-proxy`.
//!
//! `--trusted-proxy` lists peers (a load balancer in front of the gateway)
//! whose `x-forwarded-for` header is believed (the last entry, over every
//! line of the header). From any other peer the header is ignored. Behind a
//! trusted peer the TLS and HTTP/2 fingerprints are the peer's, so they are
//! left out of scoring.
//!
//! The `--agg-*` options set the population rules: seconds per window slot
//! (a window is six slots), seconds after start in
//! which no cluster rule fires, seconds a reputation entry lasts, networks
//! one fingerprint must appear on, fingerprints one network must produce,
//! and rejected reports before a client is marked.
//!
//! `--feed` names a signed bundle file that is loaded at start and again
//! whenever it changes; a bundle that does not verify is refused and the
//! data in use stays in place. `--feed-key` may list several keys separated
//! by commas.
//!
//! `--admin` serves the dashboard over plain HTTP. It accepts a loopback
//! address, or any address when VERITELL_ADMIN_TOKEN is set (in a container,
//! `0.0.0.0:port` with the port published on the host's loopback only). The ClickHouse password is read from VERITELL_CLICKHOUSE_PASSWORD.
//!
//! Sharing with other installs is off unless `--share-export` or
//! `--share-import` is given. Both need VERITELL_SHARE_KEY, a secret of at
//! least 32 bytes that the sharing installs have agreed; only keyed hashes
//! of fingerprints seen from at least `--share-min-networks` networks
//! (default 20, never below 5) are written, with no address, User-Agent or
//! count. `--share-export` writes a signed bundle every `--share-interval`
//! seconds (default 300), signed with the Ed25519 seed in
//! VERITELL_SHARE_SEED (base64url, 32 bytes). `--share-import` reads a
//! bundle signed by one of `--share-import-key`; what it lists costs a
//! request 10 points and nothing more.
//!
//! VERITELL_ADMIN_TOKEN (at least 16 bytes), when set, is required on every
//! request to the `--admin` listener: `Authorization: Bearer <token>`, or
//! HTTP Basic with the token as the password.
//!
//! The signing secret is read from the VERITELL_SECRET environment variable
//! (at least 32 bytes). Without it a random secret is generated at start, so
//! tokens stop working when the process restarts.

mod admin;
mod admin_auth;
mod behavior;
mod conn;
mod directories;
mod gateway;
mod inject;
mod known;
mod maintenance;
mod pass;
mod probe;
mod share;
mod sni;
mod state;
mod syn;
mod tee;
mod util;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use pingora::listeners::tls::TlsSettings;
use pingora::prelude::*;
use pingora::proxy::http_proxy;
use pingora::services::listening::Service;
use pingora::tls::ssl::SslFiletype;

use veritell_events::clickhouse::{ClickHouseConfig, ClickHouseSink};
use veritell_events::{EventSink, Fanout, MemoryRing};
use veritell_feed::{FeedKey, Live};
use veritell_identity::{AsnDb, CrawlerVerifier};
use veritell_probe::ProbeKey;
use veritell_policy::{Mode, Policy};
use veritell_token::{Keys, MemoryBudgetStore};
use veritell_ua::TruthTable;

use conn::{install_client_hello_hook, FingerprintApp, TlsCallbacks};
use gateway::Gateway;
use util::{SystemResolver, Throttle};

const USAGE: &str = "usage: veritell --cert <pem> --key <pem> [--listen addr:port] \
[--upstream host:port] [--policy file.yaml] [--asn-db file.tsv] [--token-budget n] \
[--wba-agents file.json] [--engine-truth file.json] [--admin 127.0.0.1:port] \
[--clickhouse-url url] [--clickhouse-database name] [--clickhouse-table name] [--clickhouse-user name] \
[--feed bundle.json --feed-key key[,key]] [--probe-build-rotate secs] [--probe-build-ttl secs] \
[--trusted-proxy ip[,ip]] [--agg-slot secs] [--agg-warmup secs] [--agg-reputation-ttl secs] [--agg-spread-min n] \
[--agg-fanout-min n] [--agg-strikes n] [--model file.json] [--sidecar-listen addr:port] \
[--wba-directory-allow ip:port[,ip:port]] [--wba-directory-ca file.pem] \
[--privacy-pass-issuer name=key[,name=key]] [--share-export file] [--share-import file --share-import-key key[,key]] \
[--share-min-networks n] [--share-interval secs] [--ip-mode full|truncated|keyed] [--header-timeout secs] [--body-timeout secs] [--write-timeout secs] [--source-url url|off] [--max-conns-per-network n] [--state-dir dir] [--state-flush secs] [--inject-probe on|off] \
[--upstream-tls on|off] [--upstream-sni name] [--upstream-ca file.pem] [--forwarded-for append|replace] [--log-requests on|off] [--single-use-capacity n] \
[--sni-dir dir] [--upstream-host name=host:port[,name=host:port]]";

/// Events kept in memory for the dashboard.
const RING_CAPACITY: usize = 50_000;
const BUILTIN_ENGINE_TRUTH: &str = include_str!("../../veritell-probe/data/engine_v1.json");

fn fail(message: impl std::fmt::Display) -> ! {
    eprintln!("veritell: {message}");
    std::process::exit(2);
}

/// Fails unless `addr` (the value of `--flag`) names an address this process
/// can listen on. Pingora binds later, inside `run_forever`: a bad address
/// panics there, and an address in use is retried silently for 30 s and
/// then panics, after "listening on" was already printed. An address in use
/// is retried here the same way, saying so, and then fails cleanly.
fn check_bindable(flag: &str, addr: &str) {
    use std::net::{TcpListener, ToSocketAddrs};
    let Some(sock) = addr.to_socket_addrs().ok().and_then(|mut a| a.next()) else {
        fail(format!("--{flag} {addr:?} is not ip:port"));
    };
    for attempt in 0..30 {
        match TcpListener::bind(sock) {
            Ok(_) => return,
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                if attempt == 0 {
                    eprintln!("veritell: --{flag} {addr} is in use; trying again for 30 s");
                }
                std::thread::sleep(Duration::from_secs(1));
            }
            Err(e) => fail(format!("--{flag} {addr}: {e}")),
        }
    }
    fail(format!("--{flag} {addr} is still in use: is another gateway running?"));
}

/// Whether `--name` is one of the flags USAGE lists.
/// Where the gateway's pages say its source is (`--source-url`).
const DEFAULT_SOURCE_URL: &str = "https://github.com/veritell/veritell";

fn known_flag(name: &str) -> bool {
    !name.is_empty()
        && USAGE.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-')).any(|w| w.strip_prefix("--") == Some(name))
}

fn parse_args() -> HashMap<String, String> {
    let mut out = HashMap::new();
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let Some(name) = flag.strip_prefix("--") else {
            fail(format!("unexpected argument {flag:?}\n{USAGE}"));
        };
        // Only the flags in USAGE: a misspelt or retired one would otherwise
        // be ignored without a word, and the gateway run without it.
        if !known_flag(name) {
            fail(format!("unknown flag --{name}\n{USAGE}"));
        }
        let Some(value) = args.next() else {
            fail(format!("--{name} needs a value\n{USAGE}"));
        };
        out.insert(name.to_string(), value);
    }
    out
}

fn load_keys() -> (Keys, ProbeKey, Vec<u8>) {
    let secret = match std::env::var("VERITELL_SECRET") {
        Ok(s) => s.into_bytes(),
        Err(_) => {
            let mut random = [0u8; 32];
            if getrandom::fill(&mut random).is_err() {
                fail("no VERITELL_SECRET and the system random source failed");
            }
            eprintln!("veritell: VERITELL_SECRET not set; using a random secret for this run");
            random.to_vec()
        }
    };
    let keys = Keys::from_secret(&secret).unwrap_or_else(|e| fail(format!("VERITELL_SECRET: {e}")));
    let probe_key = ProbeKey::from_secret(&secret)
        .unwrap_or_else(|| fail("VERITELL_SECRET: must be at least 32 bytes"));
    (keys, probe_key, secret)
}

fn read_file(what: &str, path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| fail(format!("cannot read {what} {path}: {e}")))
}

fn main() {
    let args = parse_args();
    let (Some(cert), Some(key)) = (args.get("cert"), args.get("key")) else {
        fail(USAGE);
    };
    let listen = args.get("listen").map_or("127.0.0.1:8443", String::as_str);

    let upstream = args.get("upstream").map(|raw| {
        let parsed = raw
            .rsplit_once(':')
            .and_then(|(h, p)| Some((h.to_string(), p.parse::<u16>().ok()?)));
        parsed.unwrap_or_else(|| fail(format!("--upstream {raw:?} is not host:port")))
    });

    let policy = match args.get("policy") {
        None => Policy::default_shadow(),
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .unwrap_or_else(|e| fail(format!("cannot read policy {path}: {e}")));
            Policy::from_yaml(&text).unwrap_or_else(|e| fail(format!("{path}: {e}")))
        }
    };

    // An empty value is the same as none, so that a deployment file can
    // always pass the flag (the kit does, before its first download).
    let asn = match args.get("asn-db").filter(|p| !p.is_empty()) {
        None => AsnDb::empty(),
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .unwrap_or_else(|e| fail(format!("cannot read ASN database {path}: {e}")));
            let db = AsnDb::from_iptoasn_tsv(&text).unwrap_or_else(|e| fail(format!("{path}: {e}")));
            eprintln!("veritell: ASN database {path}: {} ranges", db.len());
            db
        }
    };

    let token_budget = match args.get("token-budget") {
        None => Gateway::default_token_budget(),
        Some(raw) => raw
            .parse::<u32>()
            .ok()
            .filter(|n| *n > 0)
            .unwrap_or_else(|| fail("--token-budget must be a positive integer")),
    };

    // Empty means none, as for --asn-db: the kit always passes the flag.
    let agents_config = match args.get("wba-agents").filter(|p| !p.is_empty()) {
        None => directories::AgentsConfig::default(),
        Some(path) => directories::parse_agents(&read_file("agents file", path))
            .unwrap_or_else(|e| fail(format!("{path}: {e}"))),
    };
    let directory_fetch = veritell_directory::FetchConfig {
        allow: match args.get("wba-directory-allow") {
            None => Vec::new(),
            Some(raw) => raw
                .split(',')
                .map(|a| {
                    a.trim().parse::<std::net::SocketAddr>().unwrap_or_else(|_| {
                        fail(format!("--wba-directory-allow: {a:?} is not ip:port"))
                    })
                })
                .collect(),
        },
        // Said outright rather than with zero, which the crate also reads as
        // the default.
        timeout: veritell_directory::FetchConfig::DEFAULT_TIMEOUT,
    };
    let directory_roots = args.get("wba-directory-ca").map(|path| {
        std::fs::read(path).unwrap_or_else(|e| fail(format!("cannot read {path}: {e}")))
    });
    let directory_transport = veritell_directory::HttpsTransport::new(directory_roots.as_deref())
        .unwrap_or_else(|e| fail(format!("--wba-directory-ca: {e}")))
        // Name lookups inside the same deadline as the fetch.
        .with_resolve_timeout(directory_fetch.timeout);
    let agents = Arc::new(Live::new(directories::build(&agents_config, &[], 0).0));
    let seconds = |name: &str, default: u64| match args.get(name) {
        None => default,
        Some(raw) => raw
            .parse::<u64>()
            .ok()
            .filter(|n| *n > 0)
            .unwrap_or_else(|| fail(format!("--{name} must be a positive number of seconds"))),
    };
    let build_rotate = seconds("probe-build-rotate", 60);
    let build_ttl = seconds("probe-build-ttl", 300);
    if build_ttl < build_rotate {
        fail("--probe-build-ttl must not be shorter than --probe-build-rotate");
    }
    // A script served just before a rotation must still be accepted when its
    // report arrives, up to the report nonce's lifetime later; otherwise
    // honest reports are refused as probe_build_expired. Allowed (the
    // end-to-end checks use tiny values to watch builds expire), but said.
    if build_ttl < build_rotate.saturating_add(gateway::PROBE_NONCE_TTL_SECS) {
        eprintln!(
            "veritell: warning: --probe-build-ttl {build_ttl} is under --probe-build-rotate {build_rotate} + {}: \
             reports from pages loaded just before a rotation can arrive after their build expired",
            gateway::PROBE_NONCE_TTL_SECS
        );
    }

    let trusted_proxies: Vec<std::net::IpAddr> = match args.get("trusted-proxy") {
        None => Vec::new(),
        Some(raw) => raw
            .split(',')
            .map(|ip| {
                ip.trim()
                    .parse()
                    .map(gateway::canonical)
                    .unwrap_or_else(|_| fail(format!("--trusted-proxy: {ip:?} is not an IP address")))
            })
            .collect(),
    };
    let number = |name: &str, default: u64, least: u64| match args.get(name) {
        None => default,
        Some(raw) => raw
            .parse::<u64>()
            .ok()
            .filter(|n| *n >= least)
            .unwrap_or_else(|| fail(format!("--{name} must be a whole number, at least {least}"))),
    };
    let small = |name: &str, default: u32| {
        u32::try_from(number(name, u64::from(default), 1))
            .unwrap_or_else(|_| fail(format!("--{name} is too large")))
    };
    let agg_defaults = veritell_agg::Config::default();
    let agg_config = veritell_agg::Config {
        slot_secs: number("agg-slot", agg_defaults.slot_secs, 1),
        warmup_secs: number("agg-warmup", agg_defaults.warmup_secs, 0),
        reputation_ttl_secs: number("agg-reputation-ttl", agg_defaults.reputation_ttl_secs, 1),
        spread_min_networks: small("agg-spread-min", agg_defaults.spread_min_networks),
        fanout_min_fingerprints: small("agg-fanout-min", agg_defaults.fanout_min_fingerprints),
        strikes_max: small("agg-strikes", agg_defaults.strikes_max),
        ..agg_defaults
    };
    let agg = veritell_agg::Aggregates::new(agg_config)
        .unwrap_or_else(|e| fail(format!("population settings: {e}")));

    let model = args.get("model").map(|path| {
        let bytes = std::fs::read(path).unwrap_or_else(|e| fail(format!("cannot read model {path}: {e}")));
        let model = veritell_model::Model::from_json(&bytes).unwrap_or_else(|e| fail(format!("{path}: {e}")));
        let features = veritell_model::FeatureSpec::builtin()
            .unwrap_or_else(|| fail("built-in feature definition is invalid"));
        // A model trained on other features would be fed the wrong numbers.
        if model.features() != features.names().as_slice() {
            fail(format!("{path}: the model's features are not the ones this gateway computes"));
        }
        eprintln!("veritell: model with {} trees loaded (shadow)", model.trees());
        gateway::ShadowModel { model, features }
    });
    let sidecar = args.get("sidecar-listen").map(|raw| {
        if raw.parse::<std::net::SocketAddr>().is_err() {
            fail(format!("--sidecar-listen {raw:?} is not ip:port"));
        }
        if trusted_proxies.is_empty() {
            fail("--sidecar-listen needs --trusted-proxy: the endpoint answers no one else");
        }
        raw.clone()
    });

    let feed = match (args.get("feed"), args.get("feed-key")) {
        (None, None) => None,
        (Some(path), Some(raw)) => {
            let keys: Vec<FeedKey> = raw
                .split(',')
                .map(|k| {
                    FeedKey::from_base64url(k.trim())
                        .unwrap_or_else(|| fail("--feed-key: not a base64url Ed25519 public key"))
                })
                .collect();
            Some(maintenance::FeedSource { path: path.into(), keys })
        }
        _ => fail("--feed and --feed-key must be given together"),
    };

    let engine_truth = match args.get("engine-truth") {
        None => veritell_probe::parse_truth(BUILTIN_ENGINE_TRUTH)
            .unwrap_or_else(|e| fail(format!("built-in engine truth: {e}"))),
        Some(path) => veritell_probe::parse_truth(&read_file("engine truth", path))
            .unwrap_or_else(|e| fail(format!("{path}: {e}"))),
    };

    // The admin listener speaks plain HTTP, so it binds loopback unless a
    // token is set (see `admin::check_bind`). The token's length is checked
    // below.
    let admin = args.get("admin").map(|raw| {
        match raw.parse::<std::net::SocketAddr>() {
            Ok(addr) => match admin::check_bind(addr, std::env::var_os("VERITELL_ADMIN_TOKEN").is_some()) {
                Ok(()) => raw.clone(),
                Err(message) => fail(message),
            },
            Err(_) => fail(format!("--admin {raw:?} is not ip:port")),
        }
    });

    let ring = Arc::new(MemoryRing::new(RING_CAPACITY));
    let mut sinks: Vec<Arc<dyn EventSink>> = vec![ring.clone() as Arc<dyn EventSink>];
    if let Some(url) = args.get("clickhouse-url") {
        let arg = |name: &str, default: &str| args.get(name).map_or(default, String::as_str).to_string();
        let sink = ClickHouseSink::start(ClickHouseConfig {
            url: url.clone(),
            database: arg("clickhouse-database", "veritell"),
            table: arg("clickhouse-table", "events"),
            user: arg("clickhouse-user", "default"),
            password: std::env::var("VERITELL_CLICKHOUSE_PASSWORD").unwrap_or_default(),
            batch_size: 500,
            flush_interval: Duration::from_secs(1),
            queue_capacity: 50_000,
            timeout: Duration::from_secs(5),
        })
        .unwrap_or_else(|e| fail(format!("--clickhouse-url: {e}")));
        sinks.push(Arc::new(sink));
    }

    let mode = policy.mode();
    let (keys, probe_key, secret) = load_keys();

    let data = Arc::new(maintenance::LiveData {
        truth: Live::new(TruthTable::builtin()),
        engine_truth: Live::new(engine_truth),
    });
    // A feed that is present at start must verify; one that is absent may
    // appear later.
    let mut feed_version = 0;
    if let Some(source) = &feed {
        if source.path.exists() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let loaded = std::fs::read(&source.path)
                .map_err(|e| maintenance::FeedProblem::Read(e.to_string()))
                .and_then(|bytes| maintenance::apply_feed(&bytes, &source.keys, &data, 0, now));
            match loaded {
                Ok(v) => {
                    feed_version = v;
                    eprintln!("veritell: feed version {v} loaded");
                }
                Err(e) => fail(format!("feed {}: {e}", source.path.display())),
            }
        }
    }
    let builder = veritell_probe_build::Builder::new(probe::TEMPLATE, &secret)
        .unwrap_or_else(|e| fail(format!("probe template: {e}")));
    let probe_builds = Arc::new(maintenance::ProbeBuilds::new(
        builder,
        Duration::from_secs(build_rotate),
        build_ttl,
    ));
    {
        let (builds, data) = (probe_builds.clone(), data.clone());
        let spawned = std::thread::Builder::new()
            .name("veritell-maintenance".to_string())
            .spawn(move || maintenance::run(builds, data, feed, feed_version));
        if spawned.is_err() {
            fail("could not start the maintenance thread");
        }
    }
    if !agents_config.fetched.is_empty() {
        eprintln!("veritell: fetching key directories for {} agents", agents_config.fetched.len());
        let live = agents.clone();
        let spawned = std::thread::Builder::new()
            .name("veritell-directories".to_string())
            .spawn(move || directories::run(agents_config, live, directory_transport, directory_fetch));
        if spawned.is_err() {
            fail("could not start the key directory thread");
        }
    }
    let admin_token = std::env::var("VERITELL_ADMIN_TOKEN").ok().map(|t| {
        if t.len() < admin_auth::MIN_TOKEN_BYTES {
            fail(format!("VERITELL_ADMIN_TOKEN must be at least {} bytes", admin_auth::MIN_TOKEN_BYTES));
        }
        t.into_bytes()
    });

    let share_export = args.get("share-export").map(|path| {
        let seed = std::env::var("VERITELL_SHARE_SEED")
            .ok()
            .and_then(|s| FeedKey::from_base64url(s.trim()))
            .unwrap_or_else(|| fail("--share-export needs VERITELL_SHARE_SEED: an Ed25519 seed, 32 bytes in base64url"));
        share::ExportTo { path: path.into(), seed: seed.0, every: Duration::from_secs(seconds("share-interval", 300)) }
    });
    let share_import = match (args.get("share-import"), args.get("share-import-key")) {
        (None, None) => None,
        (Some(path), Some(raw)) => Some(share::ImportFrom {
            path: path.into(),
            keys: raw
                .split(',')
                .map(|k| {
                    FeedKey::from_base64url(k.trim())
                        .unwrap_or_else(|| fail("--share-import-key: not a base64url Ed25519 public key"))
                })
                .collect(),
        }),
        _ => fail("--share-import and --share-import-key must be given together"),
    };
    let sharing = (share_export.is_some() || share_import.is_some()).then(|| {
        let key = std::env::var("VERITELL_SHARE_KEY")
            .ok()
            .and_then(|k| veritell_share::ShareKey::new(k.as_bytes()))
            .unwrap_or_else(|| fail("sharing needs VERITELL_SHARE_KEY: the secret agreed with the other installs, at least 32 bytes"));
        let ledger = share_export.as_ref().map(|_| {
            let defaults = veritell_share::Config::default();
            let config = veritell_share::Config { min_networks: small("share-min-networks", defaults.min_networks), ..defaults };
            veritell_share::Ledger::new(key.clone(), config).unwrap_or_else(|e| fail(format!("sharing: {e}")))
        });
        eprintln!(
            "veritell: sharing on (export: {}, import: {})",
            if share_export.is_some() { "yes" } else { "no" },
            if share_import.is_some() { "yes" } else { "no" }
        );
        Arc::new(share::Sharing {
            key,
            ledger,
            imported: Live::new(veritell_share::Imported::empty()),
            imported_until: std::sync::atomic::AtomicU64::new(0),
        })
    });
    if let Some(sharing) = &sharing {
        let sharing = sharing.clone();
        let spawned = std::thread::Builder::new()
            .name("veritell-share".to_string())
            .spawn(move || share::run(sharing, share_export, share_import));
        if spawned.is_err() {
            fail("could not start the sharing thread");
        }
    }

    // Entries in each single-use store (token budgets, solved challenges,
    // probe and behaviour nonces, redeemed Privacy Pass tokens). Small values
    // are for tests of what happens when one is full.
    let single_use_capacity: usize = match args.get("single-use-capacity") {
        None => 200_000,
        Some(raw) => raw.parse().ok().filter(|n| *n > 0)
            .unwrap_or_else(|| fail("--single-use-capacity must be a positive number")),
    };
    let pass = args.get("privacy-pass-issuer").map(|raw| {
        let keys = pass::parse_issuers(raw).unwrap_or_else(|e| fail(format!("--privacy-pass-issuer: {e}")));
        eprintln!("veritell: Privacy Pass tokens accepted from {} issuer keys", keys.len());
        let mut context_secret = b"privacy-pass ".to_vec();
        context_secret.extend_from_slice(&secret);
        pass::PrivacyPass { keys, secret: context_secret, used: Arc::new(MemoryBudgetStore::new(single_use_capacity)) }
    });
    let header_timeout = seconds("header-timeout", 15);
    let body_timeout = Duration::from_secs(seconds("body-timeout", 60));
    let write_timeout = Duration::from_secs(seconds("write-timeout", 30));
    // AGPL section 13: the gateway's own pages link to its source. A changed
    // gateway must point this at its own changed source.
    let source_link = match args.get("source-url").map(String::as_str) {
        Some("off") => "</body>".to_string(),
        raw => gateway::source_link(raw.unwrap_or(DEFAULT_SOURCE_URL))
            .unwrap_or_else(|| fail(format!("--source-url: {:?} is not a plain http(s) URL", raw.unwrap_or("")))),
    };
    let max_conns: u32 = match args.get("max-conns-per-network") {
        None => 256,
        Some(raw) => raw
            .parse()
            .ok()
            .filter(|n| *n > 0)
            .unwrap_or_else(|| fail("--max-conns-per-network must be a positive number")),
    };
    // Stores that survive a restart when `--state-dir` is given.
    let quotas = Arc::new(
        veritell_quota::Quotas::new(veritell_quota::Config::default())
            .unwrap_or_else(|e| fail(format!("quota settings: {e}"))),
    );
    let probes = Arc::new(probe::ProbeStore::new(200_000));
    let used_nonces = Arc::new(MemoryBudgetStore::new(single_use_capacity));
    let used_behavior_nonces = Arc::new(MemoryBudgetStore::new(single_use_capacity));
    let token_budgets = Arc::new(MemoryBudgetStore::new(single_use_capacity));
    let used_challenges = Arc::new(MemoryBudgetStore::new(single_use_capacity));
    let wba_replays = Arc::new(state::Replays::new(veritell_wba::ReplayCache::new(100_000)));
    let saver = args.get("state-dir").map(|dir| {
        let dir = std::path::PathBuf::from(dir);
        if !dir.is_dir() {
            fail(format!("--state-dir: {} is not a directory", dir.display()));
        }
        let mut stores: Vec<(&'static str, Arc<dyn state::Snapshot>)> = vec![
            ("used-probe-nonces", Arc::clone(&used_nonces) as Arc<dyn state::Snapshot>),
            ("used-behavior-nonces", Arc::clone(&used_behavior_nonces) as Arc<dyn state::Snapshot>),
            ("token-budgets", Arc::clone(&token_budgets) as Arc<dyn state::Snapshot>),
            ("used-challenges", Arc::clone(&used_challenges) as Arc<dyn state::Snapshot>),
            ("probe-results", Arc::clone(&probes) as Arc<dyn state::Snapshot>),
            ("events", Arc::new(state::Events::new(Arc::clone(&ring))) as Arc<dyn state::Snapshot>),
            ("wba-replays", Arc::clone(&wba_replays) as Arc<dyn state::Snapshot>),
        ];
        if let Some(p) = &pass {
            stores.push(("used-tokens", Arc::clone(&p.used) as Arc<dyn state::Snapshot>));
        }
        let state = Arc::new(state::State::new(dir, Arc::clone(&quotas), stores));
        state.load(state::now_secs());
        state::Saver { state, every: Duration::from_secs(seconds("state-flush", 10)) }
    });
    let addr_mode = match args.get("ip-mode") {
        None => veritell_events::addr::AddrMode::Full,
        Some(raw) => veritell_events::addr::AddrMode::parse(raw)
            .unwrap_or_else(|| fail(format!("--ip-mode: {raw:?} is not full, truncated or keyed"))),
    };
    let known_key = known::KnownKey::from_env().map(|k| k.unwrap_or_else(|e| fail(e)));
    if known_key.is_some() {
        eprintln!("veritell: known-person marks on (VERITELL_KNOWN_KEY)");
    }
    let inject_probe = match args.get("inject-probe").map(String::as_str) {
        None | Some("off") => false,
        Some("on") => true,
        Some(other) => fail(format!("--inject-probe: {other:?} is not on or off")),
    };
    let upstream_tls = match args.get("upstream-tls").map(String::as_str) {
        None | Some("off") => false,
        Some("on") => true,
        Some(other) => fail(format!("--upstream-tls: {other:?} is not on or off")),
    };
    let log_requests = match args.get("log-requests").map(String::as_str) {
        None | Some("on") => true,
        Some("off") => false,
        Some(other) => fail(format!("--log-requests: {other:?} is not on or off")),
    };
    let forwarded_replace = match args.get("forwarded-for").map(String::as_str) {
        None | Some("append") => false,
        Some("replace") => true,
        Some(other) => fail(format!("--forwarded-for: {other:?} is not append or replace")),
    };
    let upstream_sni = args.get("upstream-sni").cloned();
    // An empty value is the same as none: the system roots. (A deployment
    // file can always pass the flag that way.)
    let upstream_ca = args.get("upstream-ca").filter(|p| !p.is_empty()).map(|path| {
        let pem = std::fs::read(path).unwrap_or_else(|e| fail(format!("cannot read upstream CA {path}: {e}")));
        let certs = boring::x509::X509::stack_from_pem(&pem)
            .unwrap_or_else(|e| fail(format!("--upstream-ca {path}: not PEM certificates: {e}")));
        if certs.is_empty() {
            fail(format!("--upstream-ca {path}: no certificates in it"));
        }
        Arc::new(certs.into_boxed_slice())
    });
    // Other sites behind the same gateway, by host name, over plain HTTP.
    // An empty value is the same as none (a deployment file can pass it so).
    let mut host_upstreams = HashMap::new();
    for item in args.get("upstream-host").map_or("", String::as_str).split(',').filter(|s| !s.trim().is_empty()) {
        let parsed = item.trim().split_once('=').and_then(|(name, addr)| {
            let (h, p) = addr.rsplit_once(':')?;
            let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
            (!name.is_empty() && !h.is_empty()).then_some((name, (h.to_string(), p.parse::<u16>().ok()?)))
        });
        let Some((name, addr)) = parsed else {
            fail(format!("--upstream-host {item:?} is not name=host:port"));
        };
        if host_upstreams.insert(name.clone(), addr).is_some() {
            fail(format!("--upstream-host names {name} twice"));
        }
    }
    for (name, (h, p)) in &host_upstreams {
        eprintln!("veritell: requests for {name} go to http://{h}:{p}");
    }
    let gateway = Gateway {
        source_link,
        body_timeout,
        write_timeout,
        host_upstreams,
        upstream_tls,
        upstream_sni,
        upstream_ca,
        forwarded_replace,
        inject_probe,
        log_requests,
        known_key,
        addr: veritell_events::addr::AddrRedactor::new(addr_mode),
        upstream,
        policy,
        data,
        probe_builds,
        wba_replays: Arc::clone(&wba_replays),
        // At most 64 crawler lookups at once; tokio's blocking pool has 512
        // threads by default, shared with everything else.
        crawlers: CrawlerVerifier::new(SystemResolver::new(Duration::from_secs(2), 64)),
        asn,
        keys,
        probe_key,
        probes: Arc::clone(&probes),
        used_nonces: Arc::clone(&used_nonces),
        agents,
        quotas: Arc::clone(&quotas),
        events: Arc::new(Fanout::new(sinks)),
        behaviors: behavior::BehaviorStore::new(200_000),
        behavior_params: veritell_behavior::Params::default(),
        used_behavior_nonces: Arc::clone(&used_behavior_nonces),
        agg,
        trusted_proxies,
        model,
        share: sharing,
        pass,
        token_budgets: Arc::clone(&token_budgets),
        used_challenges: Arc::clone(&used_challenges),
        throttle: Throttle::new(100_000),
        token_budget,
    };

    // A graceful shutdown (SIGTERM, as `docker stop` sends) saves the state
    // when it is broadcast, then waits this long for requests in flight.
    // Pingora's default is five minutes, longer than any container stop
    // waits, so the port stayed held and empty until the process was killed:
    // ten seconds without HTTPS at each restart or swap.
    let conf = pingora::server::configuration::ServerConf {
        grace_period_seconds: Some(1),
        graceful_shutdown_timeout_seconds: Some(1),
        ..Default::default()
    };
    let mut server = Server::new_with_opt_and_conf(None, conf);
    server.bootstrap();

    let syn_store = Arc::new(syn::SynStore::default());
    let app = FingerprintApp {
        limiter: conn::ConnLimiter::new(max_conns),
        trusted_proxies: gateway.trusted_proxies.clone(),
        header_timeout: Duration::from_secs(header_timeout),
        body_timeout,
        inner: Arc::new(http_proxy(&server.configuration, gateway)),
        syn: Arc::clone(&syn_store),
    };
    let mut service = Service::new("veritell".to_string(), app);

    // More certificates by SNI; the --cert pair stays the default. An empty
    // value is the same as none.
    let sni = args.get("sni-dir").filter(|d| !d.is_empty()).map(|dir| {
        let certs = sni::SniCerts::load(std::path::Path::new(dir)).unwrap_or_else(|e| fail(format!("--sni-dir: {e}")));
        for (label, names) in &certs.loaded {
            eprintln!("veritell: certificate {label} served for {}", names.join(", "));
        }
        if certs.is_empty() {
            eprintln!("veritell: --sni-dir {dir} holds no certificates; the default is served to every name");
        }
        Arc::new(certs)
    });
    let mut tls =
        TlsSettings::with_callbacks(Box::new(TlsCallbacks { sni })).unwrap_or_else(|e| fail(e));
    tls.set_certificate_chain_file(cert)
        .unwrap_or_else(|e| fail(format!("certificate {cert}: {e}")));
    tls.set_private_key_file(key, SslFiletype::PEM)
        .unwrap_or_else(|e| fail(format!("private key {key}: {e}")));
    if !install_client_hello_hook(&mut tls) {
        fail("could not register the TLS fingerprint hook");
    }
    tls.enable_h2();
    check_bindable("listen", listen);
    service.add_tls_with_settings(listen, None, tls);
    // The client's TCP SYN, measured and never scored (Linux only).
    #[cfg(target_os = "linux")]
    match listen.rsplit(':').next().and_then(|p| p.parse::<u16>().ok()) {
        Some(port) => service
            .endpoints()
            .set_pre_tls_callback(Arc::new(syn::SynHook::new(Arc::clone(&syn_store), port))),
        None => eprintln!("veritell: no port in --listen {listen:?}; the TCP SYN is not measured"),
    }
    if let Some(addr) = &sidecar {
        check_bindable("sidecar-listen", addr);
        service.add_tcp(addr);
        eprintln!("veritell: authorization endpoint on http://{addr}{}", gateway::AUTHZ_PATH);
    }
    server.add_service(service);
    if let Some(saver) = saver {
        server.add_service(pingora::services::background::background_service("state", saver));
    }

    if let Some(addr) = &admin {
        let mut admin_service = Service::new(
            "veritell-admin".to_string(),
            admin::AdminApp {
                events: ring.clone(),
                token: admin_token.clone(),
                hosts: admin::allowed_hosts(addr.parse().unwrap_or_else(|_| fail(format!("--admin {addr:?} is not ip:port")))),
            },
        );
        check_bindable("admin", addr);
        admin_service.add_tcp(addr);
        server.add_service(admin_service);
        eprintln!(
            "veritell: dashboard on http://{addr}{}{}",
            if admin_token.is_some() { " (token required)" } else { "" },
            if addr.parse::<std::net::SocketAddr>().is_ok_and(|a| !a.ip().is_loopback()) {
                " (not loopback: publish the port on the host's loopback only)"
            } else {
                ""
            }
        );
    }

    eprintln!(
        "veritell: listening on https://{listen} ({} mode)",
        match mode {
            Mode::Shadow => "shadow",
            Mode::Enforce => "enforce",
        }
    );
    server.run_forever();
}
