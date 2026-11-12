//! User-Agent parsing and cross-layer consistency checks.
//!
//! The question this crate answers: does the network stack we observed match
//! what the User-Agent header claims to be?
//!
//! PUBLIC API IS FIXED. Implement the bodies; do not change signatures.

use std::sync::OnceLock;

use veritell_core::{Class, Detection, Layer};
use serde::Deserialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Engine {
    Chromium,
    Gecko,
    WebKit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Os {
    Windows,
    MacOs,
    Linux,
    Android,
    Ios,
    ChromeOs,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UaKind {
    /// No User-Agent header, or an empty one.
    Missing,
    /// A browser. `name` is lowercase: "chrome", "edge", "opera", "firefox",
    /// "safari", "samsung". `major` is the browser's own major version.
    Browser {
        engine: Engine,
        name: String,
        major: u32,
    },
    /// Chrome running headless and saying so ("HeadlessChrome").
    Headless,
    /// An HTTP library or CLI that identifies itself (curl, python-requests, ...).
    /// `name` is the lowercase product token, for example "curl".
    DeclaredTool { name: String },
    /// Claims to be a crawler or AI agent (Googlebot, bingbot, GPTBot, ...).
    /// `name` is the matched token in its original case.
    DeclaredBot { name: String },
    /// Anything else.
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UaClaim {
    pub kind: UaKind,
    pub os: Os,
    pub mobile: bool,
}

/// Known crawler / AI agent names (matched case-insensitively as whole tokens).
const KNOWN_BOTS: &[&str] = &[
    "Googlebot",
    "bingbot",
    "Applebot",
    "DuckDuckBot",
    "YandexBot",
    "Baiduspider",
    "facebookexternalhit",
    "GPTBot",
    "ChatGPT-User",
    "OAI-SearchBot",
    "ClaudeBot",
    "Claude-User",
    "PerplexityBot",
    "Perplexity-User",
    "Bytespider",
    "Amazonbot",
    "CCBot",
];

/// Product tokens of HTTP libraries and CLIs that identify themselves.
const KNOWN_TOOLS: &[&str] = &[
    "curl",
    "wget",
    "python-requests",
    "python-httpx",
    "python-urllib",
    "aiohttp",
    "go-http-client",
    "okhttp",
    "java",
    "libwww-perl",
    "scrapy",
    "axios",
    "node-fetch",
    "node",
    "undici",
    "got",
    "httpie",
    "postmanruntime",
    "insomnia",
    "apache-httpclient",
    "ruby",
    "php",
    "guzzlehttp",
    "restsharp",
    "dart",
    "reqwest",
    "hyper",
];

fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

/// One maximal run of `[A-Za-z0-9_-]`.
struct Token<'a> {
    text: &'a str,
    /// Byte offset just after the token.
    end: usize,
}

fn tokens(ua: &str) -> Vec<Token<'_>> {
    let bytes = ua.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes.get(i).copied().is_some_and(is_token_byte) {
            let start = i;
            while bytes.get(i).copied().is_some_and(is_token_byte) {
                i = i.saturating_add(1);
            }
            if let Some(text) = ua.get(start..i) {
                out.push(Token { text, end: i });
            }
        } else {
            i = i.saturating_add(1);
        }
    }
    out
}

fn followed_by_slash(ua: &str, tok: &Token<'_>) -> bool {
    ua.as_bytes().get(tok.end) == Some(&b'/')
}

fn ends_with_ci(s: &str, suffix: &str) -> bool {
    let (s, suf) = (s.as_bytes(), suffix.as_bytes());
    match s.len().checked_sub(suf.len()) {
        Some(start) => s.get(start..).is_some_and(|t| t.eq_ignore_ascii_case(suf)),
        None => false,
    }
}

/// A known crawler's name, or that name with a suffix after a hyphen
/// (`Googlebot-Image`, `Googlebot-News`, `Baiduspider-image`): the same
/// crawler family, and the same claim to verify.
/// iOS's own HTTP client for site icons:
/// `NetworkingExtension/<v> Network/<v> iOS/<v>`, those three products and
/// nothing else.
fn is_ios_system_fetcher(ua: &str) -> bool {
    let parts: Vec<&str> = ua.split(' ').collect();
    let product = |p: &str, name: &str| {
        p.strip_prefix(name)
            .and_then(|v| v.strip_prefix('/'))
            .is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit() || b == b'.'))
    };
    parts.len() == 3
        && product(parts[0], "NetworkingExtension")
        && product(parts[1], "Network")
        && product(parts[2], "iOS")
}

fn is_known_bot(name: &str) -> bool {
    KNOWN_BOTS.iter().any(|k| {
        name.eq_ignore_ascii_case(k)
            || (name.len() > k.len() + 1
                && name.get(..k.len()).is_some_and(|p| p.eq_ignore_ascii_case(k))
                && name.as_bytes().get(k.len()) == Some(&b'-'))
    })
}

fn find_bot(ua: &str, toks: &[Token<'_>]) -> Option<String> {
    for tok in toks {
        let known = is_known_bot(tok.text);
        let generic = followed_by_slash(ua, tok)
            && ["bot", "crawler", "spider"]
                .iter()
                .any(|s| ends_with_ci(tok.text, s));
        if known || generic {
            return Some(tok.text.to_string());
        }
    }
    None
}

fn find_tool(ua: &str) -> Option<String> {
    let first = tokens(ua).into_iter().next()?;
    if ua.get(..first.text.len()) != Some(first.text) {
        return None; // the UA does not start with the token
    }
    match ua.as_bytes().get(first.end) {
        None | Some(b'/') | Some(b' ') => {}
        Some(_) => return None,
    }
    KNOWN_TOOLS
        .iter()
        .find(|t| first.text.eq_ignore_ascii_case(t))
        .map(|t| (*t).to_string())
}

/// Version following the first `name/` product token.
/// Outer `None`: no such token. Inner `None`: version missing or unparsable.
fn product_major(ua: &str, toks: &[Token<'_>], name: &str) -> Option<Option<u32>> {
    let tok = toks
        .iter()
        .find(|t| t.text == name && followed_by_slash(ua, t))?;
    let rest = ua.get(tok.end.saturating_add(1)..).unwrap_or("");
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    Some(digits.parse::<u32>().ok())
}

fn has_product(ua: &str, toks: &[Token<'_>], name: &str) -> bool {
    toks.iter().any(|t| t.text == name && followed_by_slash(ua, t))
}

fn browser_kind(ua: &str, toks: &[Token<'_>], is_ios: bool) -> Option<UaKind> {
    let mk = |engine, name: &str, major: Option<u32>| {
        major.map(|major| UaKind::Browser {
            engine,
            name: name.to_string(),
            major,
        })
    };
    if is_ios {
        for (tok, name) in [("CriOS", "chrome"), ("FxiOS", "firefox"), ("EdgiOS", "edge")] {
            if let Some(v) = product_major(ua, toks, tok) {
                return mk(Engine::WebKit, name, v);
            }
        }
        if has_product(ua, toks, "Safari") {
            if let Some(v) = product_major(ua, toks, "Version") {
                return mk(Engine::WebKit, "safari", v);
            }
        }
        return None;
    }
    for (tok, name) in [("Edg", "edge"), ("EdgA", "edge"), ("OPR", "opera"), ("SamsungBrowser", "samsung")] {
        if let Some(v) = product_major(ua, toks, tok) {
            return mk(Engine::Chromium, name, v);
        }
    }
    if let Some(v) = product_major(ua, toks, "Firefox") {
        if has_product(ua, toks, "Gecko") {
            return mk(Engine::Gecko, "firefox", v);
        }
    }
    for tok in ["Chrome", "Chromium"] {
        if let Some(v) = product_major(ua, toks, tok) {
            return mk(Engine::Chromium, "chrome", v);
        }
    }
    if has_product(ua, toks, "Safari")
        && has_product(ua, toks, "AppleWebKit")
        && !has_product(ua, toks, "Chrome")
    {
        if let Some(v) = product_major(ua, toks, "Version") {
            return mk(Engine::WebKit, "safari", v);
        }
    }
    None
}

/// Parses a User-Agent header value. Never panics, whatever the input.
pub fn parse_user_agent(ua: Option<&str>) -> UaClaim {
    let ua = ua.map(str::trim).unwrap_or("");
    if ua.is_empty() {
        return UaClaim {
            kind: UaKind::Missing,
            os: Os::Unknown,
            mobile: false,
        };
    }
    let is_ios = ["iPhone", "iPad", "iPod"].iter().any(|s| ua.contains(s));
    let os = if is_ios {
        Os::Ios
    } else if ua.contains("Android") {
        Os::Android
    } else if ua.contains("Windows") {
        Os::Windows
    } else if ua.contains("CrOS") {
        Os::ChromeOs
    } else if ua.contains("Mac OS X") || ua.contains("Macintosh") {
        Os::MacOs
    } else if ua.contains("Linux") || ua.contains("X11") {
        Os::Linux
    } else {
        Os::Unknown
    };
    let mobile = os == Os::Ios || ua.contains("Mobile") || ua.contains("Android");

    let toks = tokens(ua);
    let kind = if let Some(name) = find_bot(ua, &toks) {
        UaKind::DeclaredBot { name }
    } else if ua.contains("HeadlessChrome") {
        UaKind::Headless
    } else if let Some(name) = find_tool(ua) {
        UaKind::DeclaredTool { name }
    } else {
        browser_kind(ua, &toks, is_ios).unwrap_or(UaKind::Unknown)
    };
    UaClaim { kind, os, mobile }
}

/// What the gateway observed for one request.
#[derive(Clone, Debug, Default)]
pub struct Observed<'a> {
    pub user_agent: Option<&'a str>,
    /// Full JA4 string, e.g. `t13d1516h2_8daaf6152771_806a8c22fdea`.
    pub ja4: Option<&'a str>,
    /// HTTP/2 fingerprint `settings|window_update|priorities|pseudo_order`,
    /// or `None` for HTTP/1.x.
    pub h2_akamai: Option<&'a str>,
    /// Request header names, lowercase, in the order received.
    pub header_names: &'a [String],
}

#[derive(Debug)]
pub enum TruthError {
    Json(String),
    UnsupportedVersion(u64),
}

impl std::fmt::Display for TruthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TruthError::Json(e) => write!(f, "truth table is not valid JSON: {e}"),
            TruthError::UnsupportedVersion(v) => write!(f, "unsupported truth table version {v}"),
        }
    }
}

impl std::error::Error for TruthError {}

#[derive(Clone, Debug, Default, Deserialize)]
struct Dimension {
    #[serde(default)]
    verified: bool,
    #[serde(default)]
    values: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct EngineTruth {
    #[serde(default)]
    ja4_cipher_hash: Dimension,
    #[serde(default)]
    h2_settings: Dimension,
    #[serde(default)]
    h2_pseudo_order: Dimension,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct Engines {
    #[serde(default)]
    chromium: EngineTruth,
    #[serde(default)]
    gecko: EngineTruth,
    #[serde(default)]
    webkit: EngineTruth,
}

#[derive(Clone, Debug, Deserialize)]
struct Tool {
    name: String,
    ja4_cipher_hash: String,
}

#[derive(Deserialize)]
struct RawTable {
    #[serde(default)]
    engines: Engines,
    #[serde(default)]
    tools: Vec<Tool>,
}

/// Known-good fingerprints per browser engine, plus known tool fingerprints.
#[derive(Clone, Debug, Default)]
pub struct TruthTable {
    engines: Engines,
    tools: Vec<Tool>,
}

/// Cipher hash: section 2 of exactly 3 `_`-separated sections.
fn ja4_cipher_hash(ja4: &str) -> Option<&str> {
    let mut it = ja4.split('_');
    let (_, b, _) = (it.next()?, it.next()?, it.next()?);
    if it.next().is_some() || b.is_empty() {
        return None;
    }
    Some(b)
}

/// (settings, pseudo order) of exactly 4 `|`-separated sections.
fn h2_parts(h2: &str) -> Option<(&str, &str)> {
    let mut it = h2.split('|');
    let settings = it.next()?;
    let (_, _) = (it.next()?, it.next()?);
    let order = it.next()?;
    if it.next().is_some() {
        return None;
    }
    Some((settings, order))
}

fn dimension_mismatch(
    dim: &Dimension,
    observed: &str,
    id: &str,
    what: &str,
    strong: u8,
    weak: u8,
) -> Option<Detection> {
    if dim.values.is_empty() || dim.values.iter().any(|v| v == observed) {
        return None;
    }
    let detail = format!(
        "{what} {observed:?} does not match the User-Agent's engine (expected one of: {})",
        dim.values.join(", ")
    );
    Some(if dim.verified {
        Detection::new(id, Layer::Network, strong, detail).with_class(Class::Automated)
    } else {
        Detection::new(id, Layer::Network, weak, detail)
    })
}

impl TruthTable {
    /// The table compiled into the binary from `data/truth_v1.json`.
    pub fn builtin() -> TruthTable {
        static TABLE: OnceLock<TruthTable> = OnceLock::new();
        TABLE
            .get_or_init(|| {
                TruthTable::from_json(include_str!("../data/truth_v1.json")).unwrap_or_default()
            })
            .clone()
    }

    /// Loads a table in the `data/truth_v1.json` format.
    pub fn from_json(json: &str) -> Result<TruthTable, TruthError> {
        let value: serde_json::Value =
            serde_json::from_str(json).map_err(|e| TruthError::Json(e.to_string()))?;
        let version = value
            .get("version")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| TruthError::Json("missing or invalid \"version\"".to_string()))?;
        if version != 1 {
            return Err(TruthError::UnsupportedVersion(version));
        }
        let raw: RawTable =
            serde_json::from_value(value).map_err(|e| TruthError::Json(e.to_string()))?;
        Ok(TruthTable {
            engines: raw.engines,
            tools: raw.tools,
        })
    }

    /// Whether the TLS cipher hash, HTTP/2 settings and pseudo-header order
    /// are all present and all among WebKit's known values.
    fn is_webkit_stack(&self, obs: &Observed<'_>) -> bool {
        let truth = &self.engines.webkit;
        let known = |dim: &Dimension, v: &str| !dim.values.is_empty() && dim.values.iter().any(|x| x == v);
        let (Some(hash), Some((settings, order))) =
            (obs.ja4.and_then(ja4_cipher_hash), obs.h2_akamai.and_then(h2_parts))
        else {
            return false;
        };
        known(&truth.ja4_cipher_hash, hash)
            && known(&truth.h2_settings, settings)
            && known(&truth.h2_pseudo_order, order)
    }

    fn engine(&self, engine: Engine) -> &EngineTruth {
        match engine {
            Engine::Chromium => &self.engines.chromium,
            Engine::Gecko => &self.engines.gecko,
            Engine::WebKit => &self.engines.webkit,
        }
    }

    /// Runs every consistency rule and returns the detections that fired.
    pub fn check(&self, obs: &Observed<'_>) -> Vec<Detection> {
        let net = Layer::Network;
        let claim = parse_user_agent(obs.user_agent);
        let (engine, name, major) = match claim.kind {
            UaKind::Missing => {
                return vec![Detection::new(
                    "ua_missing",
                    net,
                    40,
                    "request has no User-Agent header",
                )
                .with_class(Class::Automated)];
            }
            UaKind::Headless => {
                return vec![Detection::new(
                    "ua_headless",
                    net,
                    70,
                    "User-Agent declares HeadlessChrome",
                )
                .with_class(Class::Automated)];
            }
            UaKind::DeclaredTool { name } => {
                return vec![Detection::new(
                    "ua_declared_tool",
                    net,
                    60,
                    format!("User-Agent declares an HTTP tool: {name}"),
                )
                .with_class(Class::Automated)];
            }
            UaKind::DeclaredBot { name } => {
                let bot = Detection::new(
                    "ua_declared_bot",
                    net,
                    0,
                    format!("User-Agent claims to be a crawler: {name}"),
                );
                if is_known_bot(&name) {
                    // Checked by the gateway against the crawler's published
                    // addresses or signature.
                    return vec![bot];
                }
                // Any name ending in "bot/" counts as a crawler claim, so it
                // must not hide what the rest of the request shows.
                let mut out = vec![bot];
                out.extend(self.made_up_bot_checks(obs));
                return out;
            }
            UaKind::Unknown => {
                // iOS fetches a site's icons itself (tabs, bookmarks, the
                // share sheet) as "NetworkingExtension/… iOS/…", over the
                // same network stack as Safari. It passes only when TLS and
                // HTTP/2 are both WebKit's: the User-Agent alone earns nothing.
                if obs.user_agent.is_some_and(is_ios_system_fetcher) && self.is_webkit_stack(obs) {
                    return Vec::new();
                }
                return vec![Detection::new(
                    "ua_unknown",
                    net,
                    20,
                    "User-Agent is not a recognised browser, tool or bot",
                )];
            }
            UaKind::Browser {
                engine,
                name,
                major,
            } => (engine, name, major),
        };

        self.browser_checks(obs, engine, &name, major)
    }

    /// Checks for a crawler name we don't know: whatever else the
    /// User-Agent claims, and an HTTP tool's TLS stack.
    fn made_up_bot_checks(&self, obs: &Observed<'_>) -> Vec<Detection> {
        let net = Layer::Network;
        let ua = obs.user_agent.map(str::trim).unwrap_or("");
        let toks = tokens(ua);
        let is_ios = ["iPhone", "iPad", "iPod"].iter().any(|s| ua.contains(s));
        if ua.contains("HeadlessChrome") {
            return vec![Detection::new(
                "ua_headless",
                net,
                70,
                "User-Agent declares HeadlessChrome",
            )
            .with_class(Class::Automated)];
        }
        if let Some(name) = find_tool(ua) {
            return vec![Detection::new(
                "ua_declared_tool",
                net,
                60,
                format!("User-Agent declares an HTTP tool: {name}"),
            )
            .with_class(Class::Automated)];
        }
        if let Some(UaKind::Browser {
            engine,
            name,
            major,
        }) = browser_kind(ua, &toks, is_ios)
        {
            return self.browser_checks(obs, engine, &name, major);
        }
        let mut out = Vec::new();
        if let Some(h) = obs.ja4.and_then(ja4_cipher_hash) {
            if let Some(tool) = self.tools.iter().find(|t| t.ja4_cipher_hash == h) {
                out.push(
                    Detection::new(
                        "tls_known_tool",
                        net,
                        60,
                        format!(
                            "TLS cipher hash {h} belongs to {}, but the User-Agent claims an unknown crawler",
                            tool.name
                        ),
                    )
                    .with_class(Class::Automated),
                );
            }
        }
        out
    }

    /// The TLS, HTTP/2 and header checks for a browser claim.
    fn browser_checks(
        &self,
        obs: &Observed<'_>,
        engine: Engine,
        name: &str,
        major: u32,
    ) -> Vec<Detection> {
        let net = Layer::Network;
        let truth = self.engine(engine);
        let mut out = Vec::new();

        if let Some(h) = obs.ja4.and_then(ja4_cipher_hash) {
            if let Some(tool) = self.tools.iter().find(|t| t.ja4_cipher_hash == h) {
                out.push(
                    Detection::new(
                        "tls_known_tool",
                        net,
                        60,
                        format!(
                            "TLS cipher hash {h} belongs to {}, but the User-Agent claims {name}",
                            tool.name
                        ),
                    )
                    .with_class(Class::Automated),
                );
            } else if let Some(d) = dimension_mismatch(
                &truth.ja4_cipher_hash,
                h,
                "tls_ua_mismatch",
                "TLS cipher hash",
                45,
                15,
            ) {
                out.push(d);
            }
        }

        if let Some((settings, order)) = obs.h2_akamai.and_then(h2_parts) {
            out.extend(dimension_mismatch(
                &truth.h2_settings,
                settings,
                "h2_settings_mismatch",
                "HTTP/2 settings",
                35,
                10,
            ));
            out.extend(dimension_mismatch(
                &truth.h2_pseudo_order,
                order,
                "h2_pseudo_order_mismatch",
                "HTTP/2 pseudo-header order",
                35,
                10,
            ));
        }

        let has = |h: &str| obs.header_names.iter().any(|n| n == h);
        if engine == Engine::Chromium && major >= 90 && !has("sec-ch-ua") {
            out.push(Detection::new(
                "missing_client_hints",
                net,
                25,
                format!("Chromium {major} always sends sec-ch-ua, but it is absent"),
            ));
        }
        let expects_fetch_metadata = match engine {
            Engine::Chromium => major >= 80,
            Engine::Gecko => major >= 90,
            Engine::WebKit => name == "safari" && major >= 17,
        };
        if expects_fetch_metadata && !has("sec-fetch-site") {
            out.push(Detection::new(
                "missing_sec_fetch",
                net,
                20,
                format!("{name} {major} always sends sec-fetch-site, but it is absent"),
            ));
        }
        if !has("accept-language") {
            out.push(Detection::new(
                "missing_accept_language",
                net,
                15,
                "browser request has no accept-language header",
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn browser(ua: &str) -> (Engine, String, u32) {
        match parse_user_agent(Some(ua)).kind {
            UaKind::Browser { engine, name, major } => (engine, name, major),
            other => panic!("expected browser, got {other:?}"),
        }
    }

    #[test]
    fn opera() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 OPR/120.0.0.0";
        assert_eq!(browser(ua), (Engine::Chromium, "opera".into(), 120));
    }

    #[test]
    fn samsung() {
        let ua = "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/27.0 Chrome/125.0.0.0 Mobile Safari/537.36";
        assert_eq!(browser(ua), (Engine::Chromium, "samsung".into(), 27));
    }

    #[test]
    fn edge_android() {
        let ua = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36 EdgA/142.0.0.0";
        assert_eq!(browser(ua), (Engine::Chromium, "edge".into(), 142));
        let c = parse_user_agent(Some(ua));
        assert_eq!((c.os, c.mobile), (Os::Android, true));
    }

    #[test]
    fn ipad_safari() {
        let ua = "Mozilla/5.0 (iPad; CPU OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1";
        assert_eq!(browser(ua), (Engine::WebKit, "safari".into(), 18));
        let c = parse_user_agent(Some(ua));
        assert_eq!((c.os, c.mobile), (Os::Ios, true));
    }

    #[test]
    fn cubot_is_not_a_bot() {
        let ua = "Mozilla/5.0 (Linux; Android 10; CUBOT X30) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36";
        assert_eq!(browser(ua), (Engine::Chromium, "chrome".into(), 120));
    }

    #[test]
    fn a_known_crawlers_hyphenated_variants_are_crawler_claims() {
        for (ua, name) in [
            ("Googlebot-Image/1.0", "Googlebot-Image"),
            ("Mozilla/5.0 (compatible; Googlebot-News)", "Googlebot-News"),
            ("Baiduspider-image+(+http://www.baidu.com/search/spider.htm)", "Baiduspider-image"),
        ] {
            assert_eq!(parse_user_agent(Some(ua)).kind, UaKind::DeclaredBot { name: name.into() }, "{ua}");
        }
        // Not a variant: no hyphen, or nothing after it.
        assert_eq!(parse_user_agent(Some("Googlebotx")).kind, UaKind::Unknown);
    }

    #[test]
    fn generic_bot_suffix_needs_slash() {
        assert_eq!(
            parse_user_agent(Some("MyCrawler/1.0")).kind,
            UaKind::DeclaredBot { name: "MyCrawler".into() }
        );
        assert_eq!(parse_user_agent(Some("MyCrawler")).kind, UaKind::Unknown);
    }

    #[test]
    fn overflowing_version_is_unknown() {
        let ua = "Mozilla/5.0 (Windows NT 10.0) Chrome/99999999999999999999.0 Safari/537.36";
        assert_eq!(parse_user_agent(Some(ua)).kind, UaKind::Unknown);
        assert_eq!(parse_user_agent(Some("Chrome/4294967296")).kind, UaKind::Unknown);
        assert_eq!(browser("Chrome/4294967295"), (Engine::Chromium, "chrome".into(), u32::MAX));
    }

    #[test]
    fn tool_requires_boundary() {
        assert_eq!(
            parse_user_agent(Some("curl")).kind,
            UaKind::DeclaredTool { name: "curl".into() }
        );
        assert_eq!(parse_user_agent(Some("curlify/1.0")).kind, UaKind::Unknown);
    }

    #[test]
    fn missing_engine_in_table_means_no_data() {
        let table = TruthTable::from_json(r#"{"version":1,"engines":{},"tools":[]}"#).unwrap();
        let headers: Vec<String> = ["sec-ch-ua", "sec-fetch-site", "accept-language"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let d = table.check(&Observed {
            user_agent: Some("Mozilla/5.0 (X11; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0"),
            ja4: Some("t13d1715h2_aaaaaaaaaaaa_bbbbbbbbbbbb"),
            h2_akamai: Some("1:1|0|0|m,a,s,p"),
            header_names: &headers,
        });
        assert!(d.is_empty(), "{d:?}");
    }

    #[test]
    fn table_with_note_and_missing_dimensions_loads() {
        let json = r#"{"version":1,"note":"x","engines":{"gecko":{}}}"#;
        assert!(TruthTable::from_json(json).is_ok());
        assert!(matches!(
            TruthTable::from_json(r#"{"engines":{}}"#),
            Err(TruthError::Json(_))
        ));
    }
}
