//! The `veritell` binary itself: how it refuses a bad configuration, and a
//! whole start with most features on, a few requests over real TLS, and a
//! graceful stop.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

const BIN: &str = env!("CARGO_BIN_EXE_veritell");
const SECRET: &str = "startup-test-secret-0123456789abcdef";
const ADMIN_TOKEN: &str = "startup-admin-token";
const SHARE_KEY: &str = "startup-share-key-0123456789abcdef";
const FEED_SEED: [u8; 32] = [21; 32];
const SHARE_SEED: [u8; 32] = [22; 32];
const BROWSER: &str =
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15";

/// A fresh directory for one test.
fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("veritell-startup-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A port nothing listens on right now.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn write(dir: &Path, name: &str, content: impl AsRef<[u8]>) -> String {
    let path = dir.join(name);
    std::fs::write(&path, content).unwrap();
    path.to_string_lossy().into_owned()
}

/// A self-signed P-256 certificate for `localhost`: (cert path, key path).
fn certificate(dir: &Path) -> (String, String) {
    use boring::asn1::Asn1Time;
    use boring::ec::{EcGroup, EcKey};
    use boring::hash::MessageDigest;
    use boring::nid::Nid;
    use boring::pkey::PKey;
    use boring::x509::extension::SubjectAlternativeName;
    use boring::x509::{X509Builder, X509NameBuilder};

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "localhost").unwrap();
    let name = name.build();
    let mut b = X509Builder::new().unwrap();
    b.set_version(2).unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    b.set_not_after(&Asn1Time::days_from_now(2).unwrap()).unwrap();
    let san = SubjectAlternativeName::new().dns("localhost").build(&b.x509v3_context(None, None)).unwrap();
    b.append_extension(&san).unwrap();
    b.sign(&key, MessageDigest::sha256()).unwrap();
    let cert = b.build();
    (
        write(dir, "cert.pem", cert.to_pem().unwrap()),
        write(dir, "key.pem", key.private_key_to_pem_pkcs8().unwrap()),
    )
}

fn command(args: &[&str]) -> Command {
    let mut c = Command::new(BIN);
    c.args(args)
        .env_remove("VERITELL_ADMIN_TOKEN")
        .env_remove("VERITELL_SHARE_SEED")
        .env_remove("VERITELL_SHARE_KEY")
        .env_remove("VERITELL_KNOWN_KEY")
        .env("VERITELL_SECRET", SECRET);
    c
}

fn run(args: &[&str]) -> Output {
    command(args).stdin(Stdio::null()).output().unwrap()
}

/// Runs the gateway with `args` and expects it to refuse to start with a
/// message containing `says`.
fn refused(args: &[&str], says: &str) {
    let out = run(args);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{args:?} should be refused; stderr: {stderr}");
    assert!(stderr.contains(says), "{args:?}: expected {says:?} in: {stderr}");
}

#[test]
fn bad_configurations_are_refused_before_anything_starts() {
    let dir = temp_dir("refused");
    let (cert, key) = certificate(&dir);
    let missing = dir.join("missing").to_string_lossy().into_owned();
    let bad_yaml = write(&dir, "bad.yaml", "mode: [");
    let bad_json = write(&dir, "bad.json", "{");
    let bad_tsv = write(&dir, "bad.tsv", "not a range\n");
    let not_pem = write(&dir, "not.pem", "hello");
    let feed = write(&dir, "feed.json", "not a bundle");
    let feed_key = URL_SAFE_NO_PAD.encode([1u8; 32]);
    let base = ["--cert", cert.as_str(), "--key", key.as_str()];
    let with = |extra: &[&str]| -> Vec<String> {
        base.iter().chain(extra.iter()).map(|s| s.to_string()).collect()
    };
    let cases: Vec<(Vec<String>, &str)> = vec![
        (vec![], "usage: veritell"),
        (vec!["stray".into()], "unexpected argument \"stray\""),
        (vec!["--no-such-flag".into(), "x".into()], "unknown flag --no-such-flag"),
        (vec!["--cert".into()], "--cert needs a value"),
        (with(&["--upstream", "no-port"]), "is not host:port"),
        (with(&["--policy", &missing]), "cannot read policy"),
        (with(&["--policy", &bad_yaml]), "bad.yaml"),
        (with(&["--asn-db", &missing]), "cannot read ASN database"),
        (with(&["--asn-db", &bad_tsv]), "bad.tsv"),
        (with(&["--token-budget", "0"]), "--token-budget must be a positive integer"),
        (with(&["--wba-agents", &missing]), "cannot read agents file"),
        (with(&["--wba-agents", &bad_json]), "bad.json"),
        (with(&["--wba-directory-allow", "nowhere"]), "--wba-directory-allow: \"nowhere\" is not ip:port"),
        (with(&["--wba-directory-ca", &missing]), "cannot read"),
        (with(&["--wba-directory-ca", &not_pem]), "--wba-directory-ca"),
        (with(&["--probe-build-rotate", "0"]), "--probe-build-rotate must be a positive number of seconds"),
        (with(&["--probe-build-rotate", "60", "--probe-build-ttl", "30"]), "must not be shorter"),
        (with(&["--trusted-proxy", "nope"]), "--trusted-proxy: \"nope\" is not an IP address"),
        (with(&["--agg-slot", "0"]), "--agg-slot must be a whole number, at least 1"),
        (with(&["--agg-strikes", "99999999999"]), "--agg-strikes is too large"),
        (with(&["--model", &missing]), "cannot read model"),
        (with(&["--model", &bad_json]), "bad.json"),
        (with(&["--sidecar-listen", "nope"]), "--sidecar-listen \"nope\" is not ip:port"),
        (with(&["--sidecar-listen", "127.0.0.1:1"]), "--sidecar-listen needs --trusted-proxy"),
        (with(&["--feed", &feed]), "--feed and --feed-key must be given together"),
        (with(&["--feed", &feed, "--feed-key", "short"]), "--feed-key: not a base64url Ed25519 public key"),
        (with(&["--feed", &feed, "--feed-key", &feed_key]), "feed "),
        (with(&["--engine-truth", &missing]), "cannot read engine truth"),
        (with(&["--engine-truth", &bad_json]), "bad.json"),
        (with(&["--admin", "nope"]), "--admin \"nope\" is not ip:port"),
        (with(&["--admin", "0.0.0.0:1"]), "needs VERITELL_ADMIN_TOKEN"),
        (with(&["--clickhouse-url", "not a url"]), "--clickhouse-url"),
        (with(&["--share-export", &missing]), "--share-export needs VERITELL_SHARE_SEED"),
        (with(&["--share-import", &missing]), "--share-import and --share-import-key must be given together"),
        (with(&["--share-import", &missing, "--share-import-key", "short"]), "--share-import-key: not a base64url"),
        (with(&["--share-import", &missing, "--share-import-key", &feed_key]), "sharing needs VERITELL_SHARE_KEY"),
        (with(&["--single-use-capacity", "0"]), "--single-use-capacity must be a positive number"),
        (with(&["--privacy-pass-issuer", "nokey"]), "--privacy-pass-issuer:"),
        (with(&["--source-url", "javascript:alert(1)"]), "--source-url:"),
        (with(&["--max-conns-per-network", "0"]), "--max-conns-per-network must be a positive number"),
        (with(&["--flood-guard", "maybe"]), "--flood-guard: \"maybe\" is not off, log or enforce"),
        (with(&["--flood-limit", "0"]), "--flood-limit must be a positive number"),
        (with(&["--rate-net-limit", "x"]), "--rate-net-limit must be a positive number"),
        (with(&["--rate-client-limit", "0"]), "--rate-client-limit must be a positive number"),
        (with(&["--shed", "maybe"]), "--shed: \"maybe\" is not off, log or enforce"),
        (with(&["--max-in-flight", "0"]), "--max-in-flight must be a positive number"),
        (with(&["--fp-surge-min", "0"]), "--fp-surge-min must be a positive number"),
        (with(&["--state-dir", &missing]), "--state-dir:"),
        (with(&["--ip-mode", "partial"]), "--ip-mode: \"partial\" is not full, truncated or keyed"),
        (with(&["--inject-probe", "maybe"]), "--inject-probe: \"maybe\" is not on or off"),
        (with(&["--upstream-tls", "maybe"]), "--upstream-tls: \"maybe\" is not on or off"),
        (with(&["--log-requests", "maybe"]), "--log-requests: \"maybe\" is not on or off"),
        (with(&["--forwarded-for", "maybe"]), "--forwarded-for: \"maybe\" is not append or replace"),
        (with(&["--upstream-ca", &missing]), "cannot read upstream CA"),
        (with(&["--upstream-ca", &not_pem]), "--upstream-ca"),
        (with(&["--upstream-host", "nonsense"]), "--upstream-host \"nonsense\" is not name=host:port"),
        (with(&["--upstream-host", "a.test=h:1,A.test=h:2"]), "--upstream-host names a.test twice"),
        (with(&["--sni-dir", &missing]), "--sni-dir:"),
        (with(&["--listen", "nope"]), "--listen \"nope\" is not ip:port"),
        (vec!["--cert".into(), missing.clone(), "--key".into(), key.clone()], "certificate"),
        (vec!["--cert".into(), cert.clone(), "--key".into(), missing.clone()], "private key"),
    ];
    for (args, says) in &cases {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        refused(&args, says);
    }

    // Secrets read from the environment.
    let out = command(&base).env("VERITELL_SECRET", "short").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("VERITELL_SECRET"));
    let out = command(&with(&["--admin", "127.0.0.1:1"]).iter().map(String::as_str).collect::<Vec<_>>())
        .env("VERITELL_ADMIN_TOKEN", "short")
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stderr).contains("VERITELL_ADMIN_TOKEN must be at least"));
    let out = command(&with(&["--share-export", &missing]).iter().map(String::as_str).collect::<Vec<_>>())
        .env("VERITELL_SHARE_SEED", URL_SAFE_NO_PAD.encode(SHARE_SEED))
        .env("VERITELL_SHARE_KEY", SHARE_KEY)
        .args(["--share-min-networks", "1"])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stderr).contains("sharing: "), "min_networks below the floor");
    std::fs::remove_dir_all(dir).unwrap();
}

/// A running gateway, stopped gracefully when dropped.
struct Gateway {
    child: Child,
    stderr: mpsc::Receiver<String>,
    seen: Vec<String>,
}

impl Gateway {
    fn start(mut cmd: Command) -> Gateway {
        let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
        let (tx, rx) = mpsc::channel();
        let stderr = child.stderr.take().unwrap();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let mut g = Gateway { child, stderr: rx, seen: Vec::new() };
        g.wait_for("listening on https://");
        g
    }

    /// Waits until a line containing `text` has been written to stderr.
    fn wait_for(&mut self, text: &str) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while !self.seen.iter().any(|l| l.contains(text)) {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.stderr.recv_timeout(left) {
                Ok(line) => self.seen.push(line),
                Err(_) => panic!("no {text:?} on stderr; got: {:#?}", self.seen),
            }
        }
    }

    fn said(&self, text: &str) -> bool {
        self.seen.iter().any(|l| l.contains(text))
    }

    /// SIGTERM, as `docker stop` sends: a graceful stop that saves the
    /// state, and lets the process write its coverage profile.
    fn stop(mut self) -> std::process::ExitStatus {
        let pid = self.child.id().to_string();
        assert!(Command::new("kill").args(["-TERM", &pid]).status().unwrap().success());
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "the gateway did not stop");
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

/// One HTTP/1.1 request over TLS to `port`; returns the response, head and
/// body as text.
fn https(port: u16, request: &str) -> String {
    use boring::ssl::{SslConnector, SslMethod, SslVerifyMode};
    let mut b = SslConnector::builder(SslMethod::tls()).unwrap();
    b.set_verify(SslVerifyMode::NONE);
    b.set_alpn_protos(b"\x08http/1.1").unwrap();
    let tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut tls = b.build().connect("localhost", tcp).unwrap();
    tls.write_all(request.as_bytes()).unwrap();
    let mut out = Vec::new();
    let _ = tls.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

/// One plain HTTP/1.1 request to `port`.
fn http(port: u16, request: &str) -> String {
    let mut tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    tcp.write_all(request.as_bytes()).unwrap();
    let mut out = Vec::new();
    let _ = tcp.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

fn status(response: &str) -> u16 {
    response.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0)
}

#[test]
fn a_full_start_serves_and_stops_gracefully() {
    let dir = temp_dir("full");
    let (cert, key) = certificate(&dir);
    let state = dir.join("state");
    std::fs::create_dir_all(&state).unwrap();
    let sni = dir.join("sni");
    std::fs::create_dir_all(&sni).unwrap();
    let engine = write(&dir, "engine.json", include_str!("../../veritell-probe/data/engine_v1.json"));

    // A signed feed, present at start.
    let mut files = std::collections::BTreeMap::new();
    files.insert("engine_v1.json".to_string(), include_bytes!("../../veritell-probe/data/engine_v1.json").to_vec());
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let bundle = veritell_feed::seal(&files, 7, now, now + 3600, &FEED_SEED).unwrap();
    let feed = write(&dir, "feed.json", bundle);
    let feed_key = URL_SAFE_NO_PAD.encode(veritell_feed::public_key(&FEED_SEED).0);

    // Another install's share bundle, and this one's export path.
    let shared = veritell_share::seal_bundle(&[], now, now, now + 3600, &SHARE_SEED).unwrap();
    let share_import = write(&dir, "share-in.json", shared);
    let share_key = URL_SAFE_NO_PAD.encode(veritell_feed::public_key(&SHARE_SEED).0);
    let share_export = dir.join("share-out.json").to_string_lossy().into_owned();

    // An agent whose keys come from a directory (fetched in the background;
    // nothing answers, which is fine).
    let agents = write(
        &dir,
        "agents.json",
        r#"{"agents":[{"name":"crawler","signature_agent":"https://127.0.0.1:9/keys.json"}]}"#,
    );
    let issuer = format!("issuer.test={}", URL_SAFE_NO_PAD.encode(include_bytes!("../testdata/pass_issuer_spki.der")));

    let (listen, admin, sidecar) = (free_port(), free_port(), free_port());
    let listen_addr = format!("127.0.0.1:{listen}");
    let admin_addr = format!("127.0.0.1:{admin}");
    let sidecar_addr = format!("127.0.0.1:{sidecar}");
    let args = [
        "--cert", &cert, "--key", &key,
        "--listen", &listen_addr,
        "--admin", &admin_addr,
        "--sidecar-listen", &sidecar_addr,
        "--trusted-proxy", "127.0.0.1",
        "--policy", concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/policy.yaml"),
        "--asn-db", concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/fixtures/ip2asn.tsv"),
        "--engine-truth", &engine,
        "--feed", &feed, "--feed-key", &feed_key,
        "--share-export", &share_export, "--share-interval", "1",
        "--share-import", &share_import, "--share-import-key", &share_key,
        "--wba-agents", &agents, "--wba-directory-allow", "127.0.0.1:9",
        "--privacy-pass-issuer", &issuer,
        "--state-dir", state.to_str().unwrap(), "--state-flush", "1",
        "--sni-dir", sni.to_str().unwrap(),
        "--upstream-host", "other.test=127.0.0.1:9",
        "--probe-build-rotate", "1", "--probe-build-ttl", "2",
        "--token-budget", "50",
        "--ip-mode", "truncated",
        "--inject-probe", "on",
        "--log-requests", "off",
        "--forwarded-for", "replace",
        "--source-url", "https://example.test/src",
        "--single-use-capacity", "1000",
        "--max-conns-per-network", "64",
        "--header-timeout", "5", "--body-timeout", "5", "--write-timeout", "5",
    ];
    let mut cmd = command(&args);
    cmd.env("VERITELL_ADMIN_TOKEN", ADMIN_TOKEN)
        .env("VERITELL_SHARE_SEED", URL_SAFE_NO_PAD.encode(SHARE_SEED))
        .env("VERITELL_SHARE_KEY", SHARE_KEY);
    let mut g = Gateway::start(cmd);
    for said in [
        "ASN database",
        "feed version 7 loaded",
        "fetching key directories for 1 agents",
        "sharing on (export: yes, import: yes)",
        "Privacy Pass tokens accepted from 1 issuer keys",
        "requests for other.test go to http://127.0.0.1:9",
        "holds no certificates",
        "authorization endpoint on http://",
        "dashboard on http://",
        "(token required)",
        "warning: --probe-build-ttl",
    ] {
        assert!(g.said(said), "expected {said:?} on stderr: {:#?}", g.seen);
    }

    // The main listener, over TLS: a page, the challenge page, a probe
    // report that does not verify, and a request for another site.
    let page = https(listen, &format!("GET /catalog HTTP/1.1\r\nHost: localhost\r\nUser-Agent: {BROWSER}\r\nAccept: text/html\r\nConnection: close\r\n\r\n"));
    assert!(status(&page) > 0, "{page}");
    let challenge = https(listen, &format!("GET /__veritell/challenge?return_to=/ HTTP/1.1\r\nHost: localhost\r\nUser-Agent: {BROWSER}\r\nConnection: close\r\n\r\n"));
    assert!(status(&challenge) > 0, "{challenge}");
    let probe = https(listen, "GET /__veritell/probe.js HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert!(status(&probe) > 0, "{probe}");
    let report = https(listen, "POST /__veritell/report HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
    assert!(status(&report) > 0, "{report}");
    let other = https(listen, "GET / HTTP/1.1\r\nHost: other.test\r\nUser-Agent: curl/8.7.1\r\nConnection: close\r\n\r\n");
    assert!(status(&other) > 0, "{other}");
    let pass = https(listen, &format!("GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: {BROWSER}\r\nAuthorization: PrivateToken token=\"AAAA\"\r\nConnection: close\r\n\r\n"));
    assert!(status(&pass) > 0, "{pass}");

    // The sidecar's authorization endpoint, from the trusted proxy.
    let authz = http(sidecar, &format!("GET /__veritell/authz HTTP/1.1\r\nHost: localhost\r\nX-Original-URI: /cart\r\nX-Forwarded-For: 198.51.100.7\r\nUser-Agent: {BROWSER}\r\nConnection: close\r\n\r\n"));
    assert!(matches!(status(&authz), 200 | 403), "{authz}");
    assert!(authz.to_ascii_lowercase().contains("x-veritell-score"), "{authz}");
    let no_uri = http(sidecar, "GET /__veritell/authz HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 198.51.100.7\r\nConnection: close\r\n\r\n");
    assert_eq!(status(&no_uri), 400, "{no_uri}");

    // The admin listener needs its token.
    let admin_get = |auth: &str| {
        http(admin, &format!("GET /api/summary HTTP/1.1\r\nHost: {admin_addr}\r\n{auth}Connection: close\r\n\r\n"))
    };
    assert_eq!(status(&admin_get("")), 401);
    let summary = admin_get(&format!("Authorization: Bearer {ADMIN_TOKEN}\r\n"));
    assert_eq!(status(&summary), 200, "{summary}");
    assert!(summary.contains("\"total\""), "{summary}");

    // Background work: an export written, a probe build rotated, state saved.
    g.wait_for("share export written");
    std::thread::sleep(Duration::from_millis(1500));
    let status = g.stop();
    assert!(status.success(), "a graceful stop exits cleanly: {status:?}");
    assert!(Path::new(&share_export).exists());
    assert!(std::fs::read_dir(&state).unwrap().next().is_some(), "the state was saved");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_minimal_start_needs_only_a_certificate() {
    let dir = temp_dir("minimal");
    let (cert, key) = certificate(&dir);
    let listen = format!("127.0.0.1:{}", free_port());
    let mut cmd = command(&["--cert", &cert, "--key", &key, "--listen", &listen, "--source-url", "off"]);
    cmd.env_remove("VERITELL_SECRET");
    let g = Gateway::start(cmd);
    assert!(g.said("VERITELL_SECRET not set; using a random secret"));
    assert!(g.said("(shadow mode)"));
    assert!(g.stop().success());
    std::fs::remove_dir_all(dir).unwrap();
}

/// Writes a secret file readable by its owner only.
fn private(dir: &Path, name: &str, content: &str) -> String {
    use std::os::unix::fs::PermissionsExt;
    let path = write(dir, name, content);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path
}

#[test]
fn a_settings_file_starts_the_gateway_and_flags_win_over_it() {
    let dir = temp_dir("config");
    certificate(&dir);
    let (from_file, from_flag, admin) = (free_port(), free_port(), free_port());
    private(&dir, "admin_token", &format!("{ADMIN_TOKEN}\n"));
    // Relative paths are the file's directory's; the ASN database is missing
    // on purpose, and an empty flag turns it off.
    let config = write(
        &dir,
        "veritell.toml",
        format!(
            "[server]\nlisten = \"127.0.0.1:{from_file}\"\nadmin = \"0.0.0.0:{admin}\"\n\
             [tls]\ncert = \"cert.pem\"\nkey = \"key.pem\"\n\
             [detection]\nasn_db = \"missing.tsv\"\nsource_url = \"off\"\n\
             [secrets]\nadmin_token_file = \"admin_token\"\n"
        ),
    );
    let listen = format!("127.0.0.1:{from_flag}");
    let g = Gateway::start(command(&["--config", &config, "--listen", &listen, "--asn-db", ""]));
    assert!(g.said(&format!("listening on https://{listen}")), "the flag's --listen: {:#?}", g.seen);
    assert!(TcpStream::connect(("127.0.0.1", from_file)).is_err(), "the file's listen was used");
    // The admin token came from the file: 0.0.0.0 is allowed, and it is asked for.
    let deadline = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect(("127.0.0.1", admin)).is_err() {
        assert!(Instant::now() < deadline, "the dashboard did not open");
        std::thread::sleep(Duration::from_millis(50));
    }
    let get = |auth: &str| http(admin, &format!("GET /api/summary HTTP/1.1\r\nHost: 127.0.0.1:{admin}\r\n{auth}Connection: close\r\n\r\n"));
    assert_eq!(status(&get("")), 401);
    assert_eq!(status(&get(&format!("Authorization: Bearer {ADMIN_TOKEN}\r\n"))), 200);
    assert!(g.stop().success());

    // The environment wins over the secret file.
    let out = command(&["check-config", "--config", &config]).env("VERITELL_ADMIN_TOKEN", "x").output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}");
    assert!(stdout.contains("secrets.admin_token_file: VERITELL_ADMIN_TOKEN environment"), "{stdout}");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn check_config_prints_settings_and_hides_secrets() {
    let dir = temp_dir("check");
    let token = private(&dir, "admin_token", ADMIN_TOKEN);
    let config = write(
        &dir,
        "veritell.toml",
        format!("[tls]\ncert = \"c.pem\"\nkey = \"/k.pem\"\n[server]\ntrusted_proxies = [\"10.0.0.1\", \"10.0.0.2\"]\n[secrets]\nadmin_token_file = \"{token}\"\n"),
    );
    let out = command(&["check-config", "--config", &config, "--listen", "127.0.0.1:1"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", String::from_utf8_lossy(&out.stderr));
    let cert = dir.join("c.pem");
    for line in [
        "server.listen = \"127.0.0.1:1\"".to_string(),
        "server.trusted_proxies = \"10.0.0.1,10.0.0.2\"".to_string(),
        format!("tls.cert = {:?}", cert.to_string_lossy()),
        "tls.key = \"/k.pem\"".to_string(),
        format!("secrets.admin_token_file: VERITELL_ADMIN_TOKEN file {token}"),
        "secrets.secret_file: VERITELL_SECRET environment".to_string(),
        "secrets.share_key_file: VERITELL_SHARE_KEY unset".to_string(),
    ] {
        assert!(stdout.lines().any(|l| l == line), "no {line:?} in:\n{stdout}");
    }
    assert!(!stdout.contains(ADMIN_TOKEN) && !stdout.contains(SECRET), "a secret was printed:\n{stdout}");

    // The example in the deploy kit is a valid file.
    let example = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/veritell.example.toml");
    let out = command(&["check-config", "--config", example]).output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn bad_settings_files_are_refused() {
    let dir = temp_dir("bad-config");
    let (cert, key) = certificate(&dir);
    let file = |name: &str, text: &str| write(&dir, name, text);
    let typo = file("typo.toml", "[server]\nlisen = \"127.0.0.1:1\"\n");
    let wrong = file("wrong.toml", "[server]\nheader_timeout_secs = \"15\"\n");
    let value = file("value.toml", "[flood]\nlimit = 0\n");
    let open_secret = file("open.toml", "[secrets]\nsecret_file = \"secret\"\n");
    write(&dir, "secret", SECRET);
    let missing = dir.join("missing.toml").to_string_lossy().into_owned();
    let base = |config: &str| vec!["--cert".to_string(), cert.clone(), "--key".into(), key.clone(), "--config".into(), config.to_string()];
    let cases: Vec<(Vec<String>, &str)> = vec![
        (base(&typo), "unknown setting server.lisen"),
        (base(&wrong), "server.header_timeout_secs must be a whole number"),
        // A value the flag would refuse is refused with the flag's message.
        (base(&value), "--flood-limit must be a positive number"),
        (base(&missing), "cannot read --config"),
        (vec!["--config".into(), typo.clone(), "--config".into(), typo.clone()], "--config is given twice"),
    ];
    for (args, says) in &cases {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        refused(&args, says);
    }
    // A secret file others can read, once the environment does not set it.
    std::fs::set_permissions(dir.join("secret"), std::os::unix::fs::PermissionsExt::from_mode(0o644)).unwrap();
    let args = base(&open_secret);
    let out = command(&args.iter().map(String::as_str).collect::<Vec<_>>()).env_remove("VERITELL_SECRET").output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("VERITELL_SECRET from") && stderr.contains("make it 600"), "{stderr}");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn help_lists_the_flags_and_exits_cleanly() {
    for args in [&["--help"][..], &["-h"], &["check-config", "--cert", "x", "-h"]] {
        let out = run(args);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(out.status.code(), Some(0), "{args:?}");
        assert!(stdout.starts_with("veritell: a gateway"), "{args:?}: {stdout}");
        assert!(stdout.contains("--listen addr:port") && stdout.contains("VERITELL_SECRET"), "{stdout}");
    }
    // A wrong command line points to it.
    refused(&[], "veritell --help says what each flag does");
}
