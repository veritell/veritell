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

/// Every key: its path in the file, the flag it sets, and its kind.
pub const KEYS: &[(&str, &str, Kind)] = &[
    ("server.listen", "listen", Kind::Text),
    ("server.admin", "admin", Kind::Text),
    ("server.sidecar_listen", "sidecar-listen", Kind::Text),
    ("server.header_timeout_secs", "header-timeout", Kind::Number),
    ("server.body_timeout_secs", "body-timeout", Kind::Number),
    ("server.write_timeout_secs", "write-timeout", Kind::Number),
    ("server.max_conns_per_network", "max-conns-per-network", Kind::Number),
    ("server.max_in_flight", "max-in-flight", Kind::Number),
    ("server.shed", "shed", Kind::Text),
    ("server.trusted_proxies", "trusted-proxy", Kind::List),
    ("server.forwarded_for", "forwarded-for", Kind::Text),
    ("server.log_requests", "log-requests", Kind::Bool),
    ("tls.cert", "cert", Kind::Path),
    ("tls.key", "key", Kind::Path),
    ("tls.sni_dir", "sni-dir", Kind::Path),
    ("upstream.address", "upstream", Kind::Text),
    ("upstream.tls", "upstream-tls", Kind::Bool),
    ("upstream.sni", "upstream-sni", Kind::Text),
    ("upstream.ca", "upstream-ca", Kind::Path),
    ("upstream.hosts", "upstream-host", Kind::Map),
    ("detection.policy", "policy", Kind::Path),
    ("detection.asn_db", "asn-db", Kind::Path),
    ("detection.engine_truth", "engine-truth", Kind::Path),
    ("detection.model", "model", Kind::Path),
    ("detection.inject_probe", "inject-probe", Kind::Bool),
    ("detection.source_url", "source-url", Kind::Text),
    ("probe.build_rotate_secs", "probe-build-rotate", Kind::Number),
    ("probe.build_ttl_secs", "probe-build-ttl", Kind::Number),
    ("tokens.budget", "token-budget", Kind::Number),
    ("tokens.single_use_capacity", "single-use-capacity", Kind::Number),
    ("web_bot_auth.agents", "wba-agents", Kind::Path),
    ("web_bot_auth.directory_allow", "wba-directory-allow", Kind::List),
    ("web_bot_auth.directory_ca", "wba-directory-ca", Kind::Path),
    ("privacy_pass.issuers", "privacy-pass-issuer", Kind::Map),
    ("aggregation.slot_secs", "agg-slot", Kind::Number),
    ("aggregation.warmup_secs", "agg-warmup", Kind::Number),
    ("aggregation.reputation_ttl_secs", "agg-reputation-ttl", Kind::Number),
    ("aggregation.spread_min_networks", "agg-spread-min", Kind::Number),
    ("aggregation.fanout_min_fingerprints", "agg-fanout-min", Kind::Number),
    ("aggregation.strikes", "agg-strikes", Kind::Number),
    ("flood.mode", "flood-guard", Kind::Text),
    ("flood.limit", "flood-limit", Kind::Number),
    ("flood.rate_net_limit", "rate-net-limit", Kind::Number),
    ("flood.rate_client_limit", "rate-client-limit", Kind::Number),
    ("flood.no_probe_pages", "no-probe-pages", Kind::Number),
    ("flood.fp_surge_min", "fp-surge-min", Kind::Number),
    ("flood.fp_surge_growth", "fp-surge-growth", Kind::Number),
    ("feed.path", "feed", Kind::Path),
    ("feed.keys", "feed-key", Kind::List),
    ("share.export", "share-export", Kind::Path),
    ("share.import", "share-import", Kind::Path),
    ("share.import_keys", "share-import-key", Kind::List),
    ("share.min_networks", "share-min-networks", Kind::Number),
    ("share.interval_secs", "share-interval", Kind::Number),
    ("events.ip_mode", "ip-mode", Kind::Text),
    ("events.clickhouse.url", "clickhouse-url", Kind::Text),
    ("events.clickhouse.database", "clickhouse-database", Kind::Text),
    ("events.clickhouse.table", "clickhouse-table", Kind::Text),
    ("events.clickhouse.user", "clickhouse-user", Kind::Text),
    ("state.dir", "state-dir", Kind::Path),
    ("state.flush_secs", "state-flush", Kind::Number),
    ("secrets.secret_file", "VERITELL_SECRET", Kind::Secret),
    ("secrets.admin_token_file", "VERITELL_ADMIN_TOKEN", Kind::Secret),
    ("secrets.clickhouse_password_file", "VERITELL_CLICKHOUSE_PASSWORD", Kind::Secret),
    ("secrets.share_seed_file", "VERITELL_SHARE_SEED", Kind::Secret),
    ("secrets.share_key_file", "VERITELL_SHARE_KEY", Kind::Secret),
    ("secrets.known_key_file", "VERITELL_KNOWN_KEY", Kind::Secret),
];

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
    KEYS.iter().find(|(p, _, _)| *p == path).map(|&(_, flag, kind)| (flag, kind))
}

fn is_section(path: &str) -> bool {
    KEYS.iter().any(|(p, _, _)| p.strip_prefix(path).is_some_and(|rest| rest.starts_with('.')))
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
            if *flag == "config" {
                continue;
            }
            let n = KEYS.iter().filter(|(_, f, k)| f == flag && *k != Kind::Secret).count();
            assert_eq!(n, 1, "--{flag} has {n} keys");
        }
        for (path, flag, kind) in KEYS {
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
        for (path, _, kind) in KEYS {
            let section = *kind == Kind::Map && text.contains(&format!("[{path}]"));
            assert!(named.contains(*path) || section, "the example does not name {path}");
        }
        assert!(loaded.secret_files.is_empty(), "the example sets a secret file");
        assert!(!loaded.flags.contains_key("upstream"), "the example sets an upstream");
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
