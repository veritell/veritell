//! Admin dashboard: request handling and the page itself.
//!
//! This crate does no networking. The gateway's admin listener calls
//! [`handle`] and writes the result to the socket.
//!
//! PUBLIC API IS FIXED. Implement the body; do not change signatures.
//!
//! Events contain text chosen by clients (paths, User-Agents). The JSON API
//! returns it as JSON strings; the page must only ever put it into the
//! document with `textContent`.

use veritell_events::{EventQuery, Filter};
use serde::de::DeserializeOwned;
use serde::Serialize;

const INDEX_HTML: &str = include_str!("../assets/index.html");
const APP_JS: &str = include_str!("../assets/app.js");
const APP_CSS: &str = include_str!("../assets/app.css");

/// Largest `limit` accepted by `/api/events`; larger values are clamped.
pub const MAX_LIMIT: usize = 500;
/// `limit` when the parameter is absent or not a number.
pub const DEFAULT_LIMIT: usize = 100;
/// Longest query string accepted; longer ones get 414.
pub const MAX_QUERY_BYTES: usize = 1024;
/// `window_secs` when the parameter is absent or not a number.
pub const DEFAULT_WINDOW_SECS: u64 = 3600;
/// Largest `window_secs`; larger values are clamped. 30 days: everything the
/// gateway keeps (it saves and loads no event older than that), so the
/// page's "All" asks for this.
pub const MAX_WINDOW_SECS: u64 = 30 * 24 * 3600;

/// Sent with every response.
pub const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    /// Extra headers. Always contains `content-security-policy` ([`CSP`]),
    /// `x-content-type-options: nosniff`, `cache-control: no-store` and
    /// `referrer-policy: no-referrer`.
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
}

/// Answers one admin request.
///
/// | Request | Response |
/// |---|---|
/// | `GET /` | 200 `text/html; charset=utf-8`, the page (`assets/index.html`) |
/// | `GET /app.js` | 200 `text/javascript; charset=utf-8` (`assets/app.js`) |
/// | `GET /app.css` | 200 `text/css; charset=utf-8` (`assets/app.css`) |
/// | `GET /api/events` | 200 `application/json`, a JSON array of events, newest first |
/// | `GET /api/summary` | 200 `application/json`, a `Summary` object |
/// | any other path | 404 `text/plain; charset=utf-8` |
/// | any method other than GET | 405 `text/plain; charset=utf-8` |
/// | query string longer than [`MAX_QUERY_BYTES`] | 414 `text/plain; charset=utf-8` |
///
/// The method check comes first, then the query length, then the path.
/// The path is matched exactly (no trailing slash, no normalisation).
///
/// `/api/events` parameters, all optional, percent-decoded (`+` is a space):
/// `limit` (clamped to [`MAX_LIMIT`]; [`DEFAULT_LIMIT`] when absent or not a
/// number), `class` (a `Class` name such as `automated`), `detection`,
/// `max_score` (0 to 255), `ip`, `kind` (`request`, `probe`, `challenge`),
/// `outcome`, `host` (the site, ASCII case ignored). A `class`, `kind` or `max_score` that does not parse is a
/// 400 `text/plain; charset=utf-8`. Unknown parameters are ignored; when a
/// parameter repeats, the first one counts.
///
/// `/api/summary` parameters: `window_secs` ([`DEFAULT_WINDOW_SECS`] when
/// absent or not a number, clamped to [`MAX_WINDOW_SECS`]) and `host` (one
/// site; empty or absent is every site). The summary
/// covers events with `ts_ms >= now_ms - window_secs * 1000` (saturating).
pub fn handle(method: &str, path_and_query: &str, events: &dyn EventQuery, now_ms: u64) -> Response {
    if method != "GET" {
        return text(405, "method not allowed");
    }
    let (path, query) = path_and_query.split_once('?').unwrap_or((path_and_query, ""));
    if query.len() > MAX_QUERY_BYTES {
        return text(414, "query string too long");
    }
    let params = parse_query(query);
    match path {
        "/" => respond(200, "text/html; charset=utf-8", index_html().into_bytes()),
        "/app.js" => respond(200, "text/javascript; charset=utf-8", APP_JS.as_bytes().to_vec()),
        "/app.css" => respond(200, "text/css; charset=utf-8", APP_CSS.as_bytes().to_vec()),
        "/api/events" => events_api(&params, events),
        "/api/summary" => summary_api(&params, events, now_ms),
        _ => text(404, "not found"),
    }
}

/// The page, with the gateway's version (the workspace version) in the top bar.
fn index_html() -> String {
    INDEX_HTML.replace("{{version}}", env!("CARGO_PKG_VERSION"))
}

type Params = Vec<(String, String)>;

fn respond(status: u16, content_type: &'static str, body: Vec<u8>) -> Response {
    Response {
        status,
        content_type,
        headers: vec![
            ("content-security-policy", CSP.to_string()),
            ("x-content-type-options", "nosniff".to_string()),
            ("cache-control", "no-store".to_string()),
            ("referrer-policy", "no-referrer".to_string()),
        ],
        body,
    }
}

/// Fixed short text bodies only; never repeats any part of the request.
fn text(status: u16, message: &'static str) -> Response {
    respond(status, "text/plain; charset=utf-8", message.as_bytes().to_vec())
}

fn json<T: Serialize>(value: &T) -> Response {
    let body = serde_json::to_vec(value).unwrap_or_else(|_| b"null".to_vec());
    respond(200, "application/json", body)
}

fn parse_query(query: &str) -> Params {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            (percent_decode(name), percent_decode(value))
        })
        .collect()
}

/// First occurrence of `name` wins.
fn param<'a>(params: &'a [(String, String)], name: &str) -> Option<&'a str> {
    params
        .iter()
        .find(|(key, _)| key.as_str() == name)
        .map(|(_, value)| value.as_str())
}

/// Empty values count as absent for free-text filters.
fn text_param(params: &[(String, String)], name: &str) -> Option<String> {
    param(params, name)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// Absent is `Ok(None)`; present but not a valid name is `Err`.
fn enum_param<T: DeserializeOwned>(params: &[(String, String)], name: &str) -> Result<Option<T>, ()> {
    param(params, name).map_or(Ok(None), |value| {
        serde_json::from_value(serde_json::Value::String(value.to_string()))
            .map(Some)
            .map_err(|_| ())
    })
}

fn parse_filter(params: &[(String, String)]) -> Result<Filter, ()> {
    Ok(Filter {
        class: enum_param(params, "class")?,
        detection: text_param(params, "detection"),
        max_score: param(params, "max_score")
            .map(|raw| raw.parse::<u8>().map_err(|_| ()))
            .transpose()?,
        ip: text_param(params, "ip"),
        kind: enum_param(params, "kind")?,
        outcome: text_param(params, "outcome"),
        host: text_param(params, "host"),
    })
}

fn events_api(params: &[(String, String)], events: &dyn EventQuery) -> Response {
    let limit = param(params, "limit")
        .and_then(|raw| raw.parse::<usize>().ok())
        .map_or(DEFAULT_LIMIT, |n| n.min(MAX_LIMIT));
    match parse_filter(params) {
        Ok(filter) => json(&events.recent(limit, &filter)),
        Err(()) => text(400, "bad request"),
    }
}

fn summary_api(params: &[(String, String)], events: &dyn EventQuery, now_ms: u64) -> Response {
    let window_secs = param(params, "window_secs")
        .and_then(|raw| raw.parse::<u64>().ok())
        .unwrap_or(DEFAULT_WINDOW_SECS)
        .min(MAX_WINDOW_SECS);
    let since_ms = now_ms.saturating_sub(window_secs.saturating_mul(1000));
    match text_param(params, "host") {
        Some(host) => json(&events.summary_for(since_ms, Some(&host))),
        None => json(&events.summary(since_ms)),
    }
}

/// Percent-decodes a query component: `+` is a space, `%XX` is a byte,
/// an invalid escape is kept literally. Never panics.
fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i: usize = 0;
    while let Some(&byte) = bytes.get(i) {
        if byte == b'+' {
            out.push(b' ');
            i = i.saturating_add(1);
        } else if byte == b'%' {
            let hi = bytes.get(i.saturating_add(1)).and_then(|&h| hex_value(h));
            let lo = bytes.get(i.saturating_add(2)).and_then(|&l| hex_value(l));
            match (hi, lo) {
                (Some(hi), Some(lo)) => {
                    out.push(hi.saturating_mul(16).saturating_add(lo));
                    i = i.saturating_add(3);
                }
                _ => {
                    out.push(b'%');
                    i = i.saturating_add(1);
                }
            }
        } else {
            out.push(byte);
            i = i.saturating_add(1);
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte.saturating_sub(b'0')),
        b'a'..=b'f' => Some(byte.saturating_sub(b'a').saturating_add(10)),
        b'A'..=b'F' => Some(byte.saturating_sub(b'A').saturating_add(10)),
        _ => None,
    }
}
