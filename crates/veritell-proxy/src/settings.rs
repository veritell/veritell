//! The settings file (`--config`): TOML, with a section per area and a key
//! per flag (see `deploy/veritell.example.toml`).
//!
//! The file is turned into the same flag name → value map the command line
//! gives, and the command line is laid over it, so every default, check and
//! error message stays where the flags are read, in `main`. [`KEYS`] is the
//! only place the mapping is written.
//!
//! Rules: an unknown section or key is an error, and so is a value of the
//! wrong type. On/off settings are `true` or `false`; numbers are whole and
//! not negative; a flag that takes `a,b` is a list of strings, and one that
//! takes `name=value,...` is a table of strings. A relative path is relative
//! to the file's directory. An empty list or table sets nothing.
//!
//! Secrets are never values in the file: `[secrets]` names files to read
//! them from, and the environment variable wins over the file (see
//! [`Secrets`]).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// How a key's value becomes a flag value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A string, as the flag takes it.
    Text,
    /// A string naming a file or directory; relative to the file's directory.
    Path,
    /// A whole number, at least 0.
    Number,
    /// `true` or `false`, for a flag that takes `on` or `off`.
    Bool,
    /// A list of strings, for a flag that takes `a,b`.
    List,
    /// A table of strings, for a flag that takes `name=value,...`.
    Map,
    /// A file to read a secret from (`[secrets]`); the flag column names the
    /// environment variable instead.
    Secret,
}

/// One setting: its path in the file, the flag it sets (for a secret, the
/// environment variable), its kind, and what `--help` says of it.
#[derive(Clone, Copy, Debug)]
pub struct Key {
    pub path: &'static str,
    pub flag: &'static str,
    pub kind: Kind,
    /// The value's form in `--help`, as `addr:port`.
    pub arg: &'static str,
    /// The default in `--help`; empty when there is none.
    pub default: &'static str,
    pub help: &'static str,
    /// The heading `--help` starts with this key, if any.
    pub section: Option<&'static str>,
}

const fn key(path: &'static str, flag: &'static str, kind: Kind, arg: &'static str, default: &'static str, help: &'static str) -> Key {
    Key { path, flag, kind, arg, default, help, section: None }
}

const fn first(section: &'static str, k: Key) -> Key {
    Key { section: Some(section), ..k }
}

/// Every key, in the order `--help` lists them.
pub const KEYS: &[Key] = &[
    first("Server", key("server.listen", "listen", Kind::Text, "addr:port", "127.0.0.1:8443", "address to serve HTTPS on")),
    key("server.admin", "admin", Kind::Text, "addr:port", "", "dashboard over plain HTTP; loopback unless VERITELL_ADMIN_TOKEN is set"),
    key("server.sidecar_listen", "sidecar-listen", Kind::Text, "addr:port", "", "authorization endpoint for a proxy in front (plain HTTP)"),
    key("server.header_timeout_secs", "header-timeout", Kind::Number, "secs", "15", "time for a request's headers to arrive"),
    key("server.body_timeout_secs", "body-timeout", Kind::Number, "secs", "60", "time for a request body to arrive"),
    key("server.write_timeout_secs", "write-timeout", Kind::Number, "secs", "30", "longest one write to a client may wait"),
    key("server.max_conns_per_network", "max-conns-per-network", Kind::Number, "n", "256", "connections open at once per IPv4 address or IPv6 /64"),
    key("server.max_in_flight", "max-in-flight", Kind::Number, "n", "256", "requests in flight to the origin before load shedding"),
    key("server.shed", "shed", Kind::Text, "off|log|enforce", "log", "load shedding past --max-in-flight; enforce answers 503"),
    key("server.trusted_proxies", "trusted-proxy", Kind::List, "ip[,ip]", "", "peers whose X-Forwarded-For is believed (a load balancer)"),
    key("server.forwarded_for", "forwarded-for", Kind::Text, "append|replace", "append", "how the client address is passed to the origin"),
    key("server.log_requests", "log-requests", Kind::Bool, "on|off", "on", "a log line per request"),
    first("TLS", key("tls.cert", "cert", Kind::Path, "pem", "", "certificate the gateway presents (required)")),
    key("tls.key", "key", Kind::Path, "pem", "", "its private key (required)"),
    key("tls.sni_dir", "sni-dir", Kind::Path, "dir", "", "a certificate per server name"),
    first("Upstream (the site)", key("upstream.address", "upstream", Kind::Text, "host:port", "", "the origin; without it the gateway answers alone")),
    key("upstream.tls", "upstream-tls", Kind::Bool, "on|off", "off", "TLS to the origin"),
    key("upstream.sni", "upstream-sni", Kind::Text, "name", "", "server name sent to the origin"),
    key("upstream.ca", "upstream-ca", Kind::Path, "pem", "", "CA that signs the origin's certificate (else the system roots)"),
    key("upstream.hosts", "upstream-host", Kind::Map, "name=host:port[,...]", "", "an origin per server name"),
    first("Detection", key("detection.policy", "policy", Kind::Path, "file.yaml", "", "rules: mode, thresholds, actions (else the built-in shadow policy)")),
    key("detection.asn_db", "asn-db", Kind::Path, "file.tsv", "", "IP-to-network table (ip2asn TSV)"),
    key("detection.engine_truth", "engine-truth", Kind::Path, "file.json", "", "browser engine table for probe reports (else the built-in one)"),
    key("detection.model", "model", Kind::Path, "file.json", "", "tree model, run in shadow: logged, never acted on"),
    key("detection.inject_probe", "inject-probe", Kind::Bool, "on|off", "off", "add the probe scripts to the origin's HTML pages"),
    key("detection.source_url", "source-url", Kind::Text, "url|off", "this repository", "source link on the gateway's own pages, as the AGPL asks"),
    first("Probe", key("probe.build_rotate_secs", "probe-build-rotate", Kind::Number, "secs", "60", "seconds between new probe builds")),
    key("probe.build_ttl_secs", "probe-build-ttl", Kind::Number, "secs", "300", "seconds a probe build is accepted"),
    first("Tokens", key("tokens.budget", "token-budget", Kind::Number, "n", "500", "requests one session token is good for")),
    key("tokens.single_use_capacity", "single-use-capacity", Kind::Number, "n", "200000", "entries per single-use store (used tokens, nonces)"),
    first("Web Bot Auth", key("web_bot_auth.agents", "wba-agents", Kind::Path, "file.json", "", "signed agents to trust")),
    key("web_bot_auth.directory_allow", "wba-directory-allow", Kind::List, "ip:port[,...]", "", "private addresses key directories may be fetched from"),
    key("web_bot_auth.directory_ca", "wba-directory-ca", Kind::Path, "pem", "", "extra CA for key directory fetches"),
    first("Privacy Pass", key("privacy_pass.issuers", "privacy-pass-issuer", Kind::Map, "name=key[,...]", "", "issuers whose tokens replace the proof of work")),
    first("Aggregation (population rules)", key("aggregation.slot_secs", "agg-slot", Kind::Number, "secs", "10", "window slot; a window is six")),
    key("aggregation.warmup_secs", "agg-warmup", Kind::Number, "secs", "120", "seconds after start before cluster rules fire"),
    key("aggregation.reputation_ttl_secs", "agg-reputation-ttl", Kind::Number, "secs", "600", "how long a reputation entry lasts"),
    key("aggregation.spread_min_networks", "agg-spread-min", Kind::Number, "n", "50", "networks one fingerprint must appear on"),
    key("aggregation.fanout_min_fingerprints", "agg-fanout-min", Kind::Number, "n", "30", "fingerprints one network must produce"),
    key("aggregation.strikes", "agg-strikes", Kind::Number, "n", "3", "rejected reports before a client is marked"),
    first("Floods and scraping", key("flood.mode", "flood-guard", Kind::Text, "off|log|enforce", "log", "ceiling on requests per network; enforce answers 429")),
    key("flood.limit", "flood-limit", Kind::Number, "n", "1000", "requests per network in 10 s"),
    key("flood.rate_net_limit", "rate-net-limit", Kind::Number, "n", "120", "pages a minute per network before rate_net_high"),
    key("flood.rate_client_limit", "rate-client-limit", Kind::Number, "n", "60", "pages a minute per client before rate_client_high"),
    key("flood.no_probe_pages", "no-probe-pages", Kind::Number, "n", "20", "pages in 10 min without a probe report: pages_no_probe"),
    key("flood.fp_surge_min", "fp-surge-min", Kind::Number, "n", "120", "pages a minute one fingerprint needs for fp_page_surge"),
    key("flood.fp_surge_growth", "fp-surge-growth", Kind::Number, "n", "4", "times its usual minute for fp_page_surge"),
    first("Data feed", key("feed.path", "feed", Kind::Path, "file", "", "signed data bundle, reloaded when it changes")),
    key("feed.keys", "feed-key", Kind::List, "key[,key]", "", "Ed25519 keys the feed may be signed with"),
    first("Sharing with other installs", key("share.export", "share-export", Kind::Path, "file", "", "write a share bundle (needs the share key and seed below)")),
    key("share.import", "share-import", Kind::Path, "file", "", "read another install's share bundle"),
    key("share.import_keys", "share-import-key", Kind::List, "key[,key]", "", "keys that bundle may be signed with"),
    key("share.min_networks", "share-min-networks", Kind::Number, "n", "20", "networks a fingerprint is seen from before it is shared"),
    key("share.interval_secs", "share-interval", Kind::Number, "secs", "300", "seconds between exports"),
    first("Events", key("events.ip_mode", "ip-mode", Kind::Text, "full|truncated|keyed", "full", "client addresses in logs, events and the dashboard")),
    key("events.clickhouse.url", "clickhouse-url", Kind::Text, "url", "", "ClickHouse to send events to"),
    key("events.clickhouse.database", "clickhouse-database", Kind::Text, "name", "veritell", "its database"),
    key("events.clickhouse.table", "clickhouse-table", Kind::Text, "name", "events", "its table"),
    key("events.clickhouse.user", "clickhouse-user", Kind::Text, "name", "default", "its user"),
    first("State", key("state.dir", "state-dir", Kind::Path, "dir", "", "keep quotas and single-use stores across restarts")),
    key("state.flush_secs", "state-flush", Kind::Number, "secs", "10", "seconds between saves"),
    first("Secrets: environment variables, or a file each named in", key("secrets.secret_file", "VERITELL_SECRET", Kind::Secret, "", "", "signing secret, at least 32 bytes; random per run if unset")),
    key("secrets.admin_token_file", "VERITELL_ADMIN_TOKEN", Kind::Secret, "", "", "dashboard token, at least 16 bytes"),
    key("secrets.clickhouse_password_file", "VERITELL_CLICKHOUSE_PASSWORD", Kind::Secret, "", "", "ClickHouse password"),
    key("secrets.share_seed_file", "VERITELL_SHARE_SEED", Kind::Secret, "", "", "Ed25519 seed that signs the share export (base64url)"),
    key("secrets.share_key_file", "VERITELL_SHARE_KEY", Kind::Secret, "", "", "secret agreed with the sharing installs, at least 32 bytes"),
    key("secrets.known_key_file", "VERITELL_KNOWN_KEY", Kind::Secret, "", "", "key for known-person links, at least 32 bytes"),
];

/// The text of `veritell --help`: every flag with its value, default and
/// what it does, grouped as in the settings file, then the secrets.
pub fn help() -> String {
    let flag_col = |k: &Key| if k.kind == Kind::Secret { k.flag.to_string() } else { format!("--{} {}", k.flag, k.arg) };
    let width = KEYS.iter().map(|k| flag_col(k).len()).max().unwrap_or(0) + 2;
    let mut out = String::from(
        "veritell: a gateway in front of an HTTPS site that scores each request for\n\
         bots; in shadow mode (the default policy) it only logs what it would do.\n\
         \n\
         usage: veritell [check-config] [--config file.toml] --cert pem --key pem [--flag value ...]\n\
         \x20      veritell -h | --help\n\
         \n\
         Every flag takes one value. A flag wins over the settings file, where each\n\
         flag is a key in the [section] shown (deploy/veritell.example.toml).\n\
         \n",
    );
    for (left, text) in [
        ("--config file.toml", "settings file (TOML)"),
        ("check-config", "print what the file and flags set, then stop"),
        ("-h, --help", "this help"),
    ] {
        out.push_str(&format!("  {left:width$}{text}\n"));
    }
    for k in KEYS {
        if let Some(title) = k.section {
            let table = k.path.split('.').next().unwrap_or("");
            out.push_str(&format!("\n{title}  [{table}]\n"));
        }
        let default = if k.default.is_empty() { String::new() } else { format!(" (default {})", k.default) };
        out.push_str(&format!("  {:width$}{}{default}\n", flag_col(k), k.help));
    }
    out
}

/// Largest settings file read.
pub const MAX_FILE_BYTES: u64 = 1024 * 1024;
/// Largest secret file read.
pub const MAX_SECRET_BYTES: u64 = 64 * 1024;

/// What a settings file says.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Loaded {
    /// Flag name → value, as the command line would give them.
    pub flags: HashMap<String, String>,
    /// Environment variable → the file to read it from when it is not set.
    pub secret_files: HashMap<String, PathBuf>,
}

/// Reads and converts the file at `path`.
pub fn load(path: &Path) -> Result<Loaded, String> {
    let shown = path.display();
    let meta = std::fs::metadata(path).map_err(|e| format!("cannot read --config {shown}: {e}"))?;
    if meta.len() > MAX_FILE_BYTES {
        return Err(format!("--config {shown}: larger than {MAX_FILE_BYTES} bytes"));
    }
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read --config {shown}: {e}"))?;
    let base = path.parent().unwrap_or(Path::new("."));
    parse(&text, base).map_err(|e| format!("--config {shown}: {e}"))
}

/// Converts settings text; relative paths are taken against `base`.
pub fn parse(text: &str, base: &Path) -> Result<Loaded, String> {
    let table: toml::Table = text.parse().map_err(|e: toml::de::Error| e.message().to_string())?;
    let mut out = Loaded::default();
    walk("", &table, base, &mut out)?;
    Ok(out)
}

fn key_at(path: &str) -> Option<(&'static str, Kind)> {
    KEYS.iter().find(|k| k.path == path).map(|k| (k.flag, k.kind))
}

fn is_section(path: &str) -> bool {
    KEYS.iter().any(|k| k.path.strip_prefix(path).is_some_and(|rest| rest.starts_with('.')))
}

fn walk(prefix: &str, table: &toml::Table, base: &Path, out: &mut Loaded) -> Result<(), String> {
    for (name, value) in table {
        let path = if prefix.is_empty() { name.clone() } else { format!("{prefix}.{name}") };
        match (key_at(&path), value) {
            (Some((flag, kind)), value) => set(&path, flag, kind, value, base, out)?,
            (None, toml::Value::Table(inner)) if is_section(&path) => walk(&path, inner, base, out)?,
            (None, _) if is_section(&path) => return Err(format!("{path} must be a section")),
            (None, _) => return Err(format!("unknown setting {path}")),
        }
    }
    Ok(())
}

fn one_item(path: &str, s: &str) -> Result<(), String> {
    if s.contains(',') {
        Err(format!("{path}: {s:?} holds a comma; give each item separately"))
    } else {
        Ok(())
    }
}

fn resolve(base: &Path, s: &str) -> String {
    if s.is_empty() || Path::new(s).is_absolute() {
        s.to_string()
    } else {
        base.join(s).to_string_lossy().into_owned()
    }
}

fn set(path: &str, flag: &str, kind: Kind, value: &toml::Value, base: &Path, out: &mut Loaded) -> Result<(), String> {
    use toml::Value as V;
    let text = match (kind, value) {
        (Kind::Text, V::String(s)) => s.clone(),
        (Kind::Path, V::String(s)) => resolve(base, s),
        (Kind::Number, V::Integer(n)) if *n >= 0 => n.to_string(),
        (Kind::Number, V::Integer(_)) => return Err(format!("{path} must not be negative")),
        (Kind::Bool, V::Boolean(b)) => if *b { "on" } else { "off" }.to_string(),
        (Kind::List, V::Array(items)) => {
            let mut parts = Vec::with_capacity(items.len());
            for item in items {
                let V::String(s) = item else {
                    return Err(format!("{path} must be a list of strings"));
                };
                one_item(path, s)?;
                parts.push(s.as_str());
            }
            parts.join(",")
        }
        (Kind::Map, V::Table(entries)) => {
            let mut parts = Vec::with_capacity(entries.len());
            for (name, v) in entries {
                let V::String(s) = v else {
                    return Err(format!("{path}.{name} must be a string"));
                };
                if name.is_empty() || name.contains('=') {
                    return Err(format!("{path}: {name:?} is not a usable name"));
                }
                one_item(path, name)?;
                one_item(path, s)?;
                parts.push(format!("{name}={s}"));
            }
            parts.join(",")
        }
        (Kind::Secret, V::String(s)) if !s.is_empty() => {
            out.secret_files.insert(flag.to_string(), PathBuf::from(resolve(base, s)));
            return Ok(());
        }
        _ => {
            let want = match kind {
                Kind::Text | Kind::Path => "a string",
                Kind::Number => "a whole number",
                Kind::Bool => "true or false",
                Kind::List => "a list of strings",
                Kind::Map => "a table of strings",
                Kind::Secret => "a file name",
            };
            return Err(format!("{path} must be {want}"));
        }
    };
    if !(text.is_empty() && matches!(kind, Kind::List | Kind::Map)) {
        out.flags.insert(flag.to_string(), text);
    }
    Ok(())
}

/// Where each secret comes from: its environment variable when set, else
/// the file `[secrets]` names for it.
#[derive(Debug, Default)]
pub struct Secrets {
    files: HashMap<String, PathBuf>,
}

/// Where a secret was found.
#[derive(Debug, PartialEq, Eq)]
pub enum Source {
    Environment,
    File(PathBuf),
    Unset,
}

impl Secrets {
    pub fn new(files: HashMap<String, PathBuf>) -> Secrets {
        Secrets { files }
    }

    /// Where `env` would be read from.
    pub fn source(&self, env: &str) -> Source {
        if std::env::var_os(env).is_some() {
            Source::Environment
        } else if let Some(path) = self.files.get(env) {
            Source::File(path.clone())
        } else {
            Source::Unset
        }
    }

    /// The secret `env`: the environment variable if set (and valid UTF-8,
    /// as before), else the content of its file without one trailing
    /// newline. A file that cannot be read, is not a regular file, is
    /// readable by group or others, or is not UTF-8 is an error.
    pub fn get(&self, env: &str) -> Result<Option<String>, String> {
        match self.source(env) {
            Source::Environment => Ok(std::env::var(env).ok()),
            Source::Unset => Ok(None),
            Source::File(path) => read_secret_file(&path).map(Some).map_err(|e| format!("{env} from {}: {e}", path.display())),
        }
    }
}

fn read_secret_file(path: &Path) -> Result<String, String> {
    let meta = std::fs::metadata(path).map_err(|e| e.to_string())?;
    if !meta.is_file() {
        return Err("not a regular file".to_string());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!("readable by others (mode {mode:o}); make it 600"));
        }
    }
    if meta.len() > MAX_SECRET_BYTES {
        return Err(format!("larger than {MAX_SECRET_BYTES} bytes"));
    }
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    let mut text = String::from_utf8(bytes).map_err(|_| "not UTF-8".to_string())?;
    if text.ends_with('\n') {
        text.pop();
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flags(text: &str) -> HashMap<String, String> {
        parse(text, Path::new("/etc/veritell")).expect("parses").flags
    }

    fn refused(text: &str, says: &str) {
        let e = parse(text, Path::new("/etc/veritell")).expect_err("refused");
        assert!(e.contains(says), "{e:?} does not say {says:?}");
    }

    /// The flags `main` accepts, from its usage text.
    fn usage_flags() -> Vec<&'static str> {
        let mut v: Vec<&str> = crate::USAGE
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
            .filter_map(|w| w.strip_prefix("--"))
            .filter(|w| !w.is_empty())
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    #[test]
    fn every_flag_has_one_key_and_every_key_a_flag() {
        let usage = usage_flags();
        for flag in &usage {
            if *flag == "config" || *flag == "help" {
                continue;
            }
            let n = KEYS.iter().filter(|k| k.flag == *flag && k.kind != Kind::Secret).count();
            assert_eq!(n, 1, "--{flag} has {n} keys");
        }
        for Key { path, flag, kind, .. } in KEYS {
            if *kind == Kind::Secret {
                assert!(flag.starts_with("VERITELL_") && path.ends_with("_file"), "{path}");
            } else {
                assert!(usage.contains(flag), "{path} names --{flag}, which is not a flag");
            }
        }
    }

    #[test]
    fn the_example_names_every_key_and_loads() {
        let text = include_str!("../../../deploy/veritell.example.toml");
        let loaded = parse(text, Path::new("/etc/veritell")).expect("the example loads");
        // A key is named uncommented (and so loaded) or as `# key =` in its section.
        let mut section = String::new();
        let mut named = std::collections::BTreeSet::new();
        for line in text.lines() {
            let line = line.trim();
            if let Some(s) = line.strip_prefix('[').and_then(|l| l.split(']').next()) {
                section = s.to_string();
            } else if let Some((key, _)) = line.trim_start_matches("# ").split_once(" = ") {
                if !key.contains(' ') {
                    named.insert(format!("{section}.{}", key.trim()));
                }
            }
        }
        for Key { path, kind, .. } in KEYS {
            let section = *kind == Kind::Map && text.contains(&format!("[{path}]"));
            assert!(named.contains(*path) || section, "the example does not name {path}");
        }
        assert!(loaded.secret_files.is_empty(), "the example sets a secret file");
        assert!(!loaded.flags.contains_key("upstream"), "the example sets an upstream");
    }

    #[test]
    fn help_lists_every_flag_and_secret_once() {
        let text = help();
        for flag in usage_flags() {
            if flag == "help" {
                continue;
            }
            let lines = text.lines().filter(|l| l.trim_start().starts_with(&format!("--{flag} "))).count();
            assert_eq!(lines, 1, "--{flag} is on {lines} lines of the help");
        }
        for k in KEYS.iter().filter(|k| k.kind == Kind::Secret) {
            assert!(text.lines().any(|l| l.trim_start().starts_with(k.flag)), "{} is not in the help", k.flag);
        }
        for k in KEYS {
            assert!(!k.help.is_empty() && !k.arg.is_empty() || k.kind == Kind::Secret, "{} has no help", k.path);
        }
        assert!(KEYS.first().is_some_and(|k| k.section.is_some()), "the help starts without a heading");
    }

    #[test]
    fn kinds_convert() {
        let f = flags(
            r#"
            [server]
            listen = "0.0.0.0:443"
            header_timeout_secs = 20
            log_requests = false
            trusted_proxies = ["10.0.0.1", "10.0.0.2"]
            [tls]
            cert = "cert.pem"
            key = "/abs/key.pem"
            [upstream]
            tls = true
            [upstream.hosts]
            "a.example" = "127.0.0.1:8081"
            "b.example" = "127.0.0.1:8082"
            [detection]
            asn_db = ""
            "#,
        );
        assert_eq!(f["listen"], "0.0.0.0:443");
        assert_eq!(f["header-timeout"], "20");
        assert_eq!(f["log-requests"], "off");
        assert_eq!(f["upstream-tls"], "on");
        assert_eq!(f["trusted-proxy"], "10.0.0.1,10.0.0.2");
        assert_eq!(f["cert"], "/etc/veritell/cert.pem");
        assert_eq!(f["key"], "/abs/key.pem");
        assert_eq!(f["upstream-host"], "a.example=127.0.0.1:8081,b.example=127.0.0.1:8082");
        assert_eq!(f["asn-db"], "", "an empty path stays empty: none");
    }

    #[test]
    fn empty_lists_and_tables_set_nothing() {
        let f = flags("[server]\ntrusted_proxies = []\n[upstream.hosts]\n[privacy_pass.issuers]\n");
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn secrets_are_files_not_values() {
        let loaded = parse("[secrets]\nsecret_file = \"s\"\n", Path::new("/run")).unwrap();
        assert!(loaded.flags.is_empty());
        assert_eq!(loaded.secret_files["VERITELL_SECRET"], PathBuf::from("/run/s"));
        refused("[secrets]\nsecret = \"hunter2\"\n", "unknown setting secrets.secret");
    }

    #[test]
    fn mistakes_are_refused() {
        refused("[server]\nlisen = \"x\"\n", "unknown setting server.lisen");
        refused("[sever]\nlisten = \"x\"\n", "unknown setting sever");
        refused("listen = \"x\"\n", "unknown setting listen");
        refused("server = 1\n", "server must be a section");
        refused("[server]\nlisten = 8443\n", "server.listen must be a string");
        refused("[server]\nheader_timeout_secs = \"15\"\n", "must be a whole number");
        refused("[server]\nheader_timeout_secs = -1\n", "must not be negative");
        refused("[server]\nheader_timeout_secs = 1.5\n", "must be a whole number");
        refused("[server]\nlog_requests = \"on\"\n", "must be true or false");
        refused("[server]\ntrusted_proxies = \"10.0.0.1\"\n", "must be a list of strings");
        refused("[server]\ntrusted_proxies = [1]\n", "must be a list of strings");
        refused("[server]\ntrusted_proxies = [\"a,b\"]\n", "holds a comma");
        refused("[upstream.hosts]\n\"a=b\" = \"x\"\n", "not a usable name");
        refused("[upstream.hosts]\na = 1\n", "upstream.hosts.a must be a string");
        refused("[upstream]\nhosts = \"a=b\"\n", "must be a table of strings");
        refused("[secrets]\nsecret_file = 1\n", "must be a file name");
        refused("[server]\nlisten = \"a\"\nlisten = \"b\"\n", "duplicate");
        refused("[server", "");
    }

    #[cfg(unix)]
    #[test]
    fn secret_files_must_be_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("veritell-settings-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("s");
        std::fs::write(&file, "a secret of at least thirty-two bytes\n").unwrap();
        let env = "VERITELL_SETTINGS_TEST_UNSET";
        let secrets = Secrets::new(HashMap::from([(env.to_string(), file.clone())]));

        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let e = secrets.get(env).expect_err("a 0644 secret file is refused");
        assert!(e.contains("make it 600"), "{e}");

        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(secrets.get(env).unwrap().as_deref(), Some("a secret of at least thirty-two bytes"));
        assert_eq!(secrets.source(env), Source::File(file.clone()));
        assert_eq!(Secrets::default().get(env), Ok(None));

        let e = Secrets::new(HashMap::from([(env.to_string(), dir.clone())])).get(env).expect_err("a directory");
        assert!(e.contains("not a regular file"), "{e}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
