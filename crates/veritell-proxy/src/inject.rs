//! Passive probe injection (`--inject-probe on`).
//!
//! In shadow mode nobody is challenged, so the probe and behaviour scripts,
//! which otherwise only run on a challenge page, never run, and nothing is
//! learned about real browsers from the inside. With injection on, the
//! gateway adds the two scripts to the origin's HTML pages on the way out.
//! They report as on a challenge page; the page itself is not otherwise
//! changed, and nothing waits for them.
//!
//! Only a page load is touched: a GET whose `Sec-Fetch-Dest` is `document`
//! (or absent), answered 200 with `text/html` and no `Content-Encoding`. The
//! body is held until it ends, up to [`MAX_BUFFER`]; the scripts go before
//! the first `</head>`, else before the last `</body>`. A larger body, or one
//! with neither tag, is passed on unchanged.

/// The scripts, same origin, so a `script-src 'self'` policy allows them.
pub const SNIPPET: &str =
    "<script src=\"/__veritell/probe.js\" async></script><script src=\"/__veritell/behavior.js\" async></script>";

/// Largest body held for injection.
pub const MAX_BUFFER: usize = 512 * 1024;

/// Whether the request is a page load the scripts may be added to.
pub fn request_wants(method: &str, sec_fetch_dest: Option<&str>) -> bool {
    method == "GET" && sec_fetch_dest.is_none_or(|d| d.eq_ignore_ascii_case("document"))
}

/// Takes `Accept-Encoding` off the upstream request of a page load that is to
/// be injected: a server that compresses its pages would otherwise answer
/// with a body the gateway cannot read, and injection skips encoded
/// responses. Only an `Injection::Wanted` request that accepts `text/html` is
/// touched; the client then gets the page uncompressed. Everything else keeps
/// its header.
pub fn drop_accept_encoding(state: &Injection, upstream_request: &mut pingora::http::RequestHeader) {
    if *state != Injection::Wanted {
        return;
    }
    if accepts_html(upstream_request) {
        upstream_request.remove_header("accept-encoding");
    }
}

/// Takes the validators off the upstream request of a page load that is to
/// be injected, when they can only come from a copy without the scripts.
/// The gateway weakens the `ETag` of every page it changes, so a strong
/// entity tag in `If-None-Match` names a copy cached before the gateway was
/// in front (or while injection was off). A 304 would keep that copy, and
/// the visitor's browser would never run the probe. Without the validators
/// the origin sends the page in full. A weak tag is the gateway's own copy
/// (it has the scripts) and stays, as does every request that is not
/// `Injection::Wanted` with `text/html` in `Accept`. `If-Modified-Since`
/// alone cannot tell the two copies apart and is left alone.
pub fn drop_stale_validators(state: &Injection, upstream_request: &mut pingora::http::RequestHeader) {
    if *state != Injection::Wanted || !accepts_html(upstream_request) {
        return;
    }
    let strong = upstream_request
        .headers
        .get_all("if-none-match")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(has_strong_tag);
    if strong {
        upstream_request.remove_header("if-none-match");
        upstream_request.remove_header("if-modified-since");
    }
}

/// Whether an `If-None-Match` value lists a strong entity tag (`"x"`, not
/// `W/"x"`, and not `*`).
pub fn has_strong_tag(value: &str) -> bool {
    value
        .split(',')
        .map(str::trim)
        .any(|t| t.starts_with('"'))
}

fn accepts_html(req: &pingora::http::RequestHeader) -> bool {
    req.headers
        .get_all("accept")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.to_ascii_lowercase().contains("text/html"))
}

/// Whether the response is a whole HTML page that can be read as it is.
pub fn response_allows(status: u16, content_type: Option<&str>, content_encoding: Option<&str>) -> bool {
    status == 200
        && content_type.is_some_and(|t| {
            t.split(';').next().is_some_and(|m| m.trim().eq_ignore_ascii_case("text/html"))
        })
        && content_encoding.is_none_or(|e| e.trim().is_empty() || e.trim().eq_ignore_ascii_case("identity"))
}

fn find_ci(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w.eq_ignore_ascii_case(needle))
}

fn rfind_ci(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).rposition(|w| w.eq_ignore_ascii_case(needle))
}

/// What happens to one response's body. The only transitions are:
///
/// ```text
/// for_request:  Pass (off, or not a page load)   | Wanted
/// on_response:  Wanted -> Holding (an HTML page) | Wanted -> Pass
/// on_body:      Holding -> Holding (more to come, under the limit)
///               Holding -> Pass (end: scripts inserted if there is a place;
///                                over the limit: what is held goes out as it is)
/// ```
///
/// `Pass` lets every chunk through untouched, and nothing leaves it.
#[derive(Debug, Default, PartialEq, Eq)]
pub enum Injection {
    #[default]
    Pass,
    Wanted,
    Holding(Vec<u8>),
}

impl Injection {
    pub fn for_request(enabled: bool, method: &str, sec_fetch_dest: Option<&str>) -> Injection {
        if enabled && request_wants(method, sec_fetch_dest) { Injection::Wanted } else { Injection::Pass }
    }

    /// At the response headers. True when the body will be changed, so that
    /// the caller drops `Content-Length` and weakens a strong `ETag`.
    pub fn on_response(&mut self, status: u16, content_type: Option<&str>, content_encoding: Option<&str>) -> bool {
        *self = match std::mem::take(self) {
            Injection::Wanted if response_allows(status, content_type, content_encoding) => Injection::Holding(Vec::new()),
            _ => Injection::Pass,
        };
        matches!(self, Injection::Holding(_))
    }

    /// For each body chunk: what to send now. `None` while holding.
    pub fn on_body(&mut self, chunk: Option<Vec<u8>>, end_of_stream: bool) -> Option<Vec<u8>> {
        let Injection::Holding(held) = self else { return chunk };
        if let Some(chunk) = chunk {
            held.extend_from_slice(&chunk);
        }
        if held.len() > MAX_BUFFER {
            let out = std::mem::take(held);
            *self = Injection::Pass;
            return Some(out);
        }
        if end_of_stream {
            let out = std::mem::take(held);
            *self = Injection::Pass;
            return Some(insert(&out).unwrap_or(out));
        }
        None
    }
}

/// The `ETag` for a body the gateway changed: a strong validator promises
/// the exact bytes, which these no longer are, so it is made weak (RFC 9110,
/// section 8.8.1). A weak one stays as it is.
pub fn weaken_etag(etag: &str) -> String {
    let etag = etag.trim();
    if etag.starts_with("W/") { etag.to_string() } else { format!("W/{etag}") }
}

/// The page with the scripts added, or `None` when it has no place for them.
pub fn insert(html: &[u8]) -> Option<Vec<u8>> {
    let at = find_ci(html, b"</head>").or_else(|| rfind_ci(html, b"</body>"))?;
    let mut out = Vec::with_capacity(html.len() + SNIPPET.len());
    out.extend_from_slice(&html[..at]);
    out.extend_from_slice(SNIPPET.as_bytes());
    out.extend_from_slice(&html[at..]);
    Some(out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn strong_tags_are_found() {
        use super::has_strong_tag;
        assert!(has_strong_tag("\"v1\""));
        assert!(has_strong_tag("W/\"v0\", \"v1\""));
        assert!(has_strong_tag(" \"v1\" "));
        assert!(!has_strong_tag("W/\"v1\""));
        assert!(!has_strong_tag("W/\"a\",W/\"b\""));
        assert!(!has_strong_tag("*"));
        assert!(!has_strong_tag(""));
    }

    use super::*;

    #[test]
    fn before_the_first_head_close() {
        let page = b"<!doctype html><html><HEAD><title>x</title></Head><body>a</head></body></html>";
        let out = String::from_utf8(insert(page).unwrap()).unwrap();
        assert_eq!(out, format!("<!doctype html><html><HEAD><title>x</title>{SNIPPET}</Head><body>a</head></body></html>"));
    }

    #[test]
    fn else_before_the_last_body_close() {
        let out = String::from_utf8(insert(b"<p></body>x</BODY>").unwrap()).unwrap();
        assert_eq!(out, format!("<p></body>x{SNIPPET}</BODY>"));
    }

    #[test]
    fn nothing_without_a_place() {
        assert_eq!(insert(b"<p>no tags</p>"), None);
        assert_eq!(insert(b""), None);
        assert_eq!(insert(b"</hea"), None);
    }

    fn run(state: &mut Injection, chunks: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for (i, c) in chunks.iter().enumerate() {
            if let Some(sent) = state.on_body(Some(c.to_vec()), i + 1 == chunks.len()) {
                out.extend_from_slice(&sent);
            }
        }
        out
    }

    #[test]
    fn a_page_split_anywhere_gets_the_scripts_once() {
        let page = b"<html><head><title>t</title></head><body>b</body></html>";
        let want = String::from_utf8(insert(page).unwrap()).unwrap();
        for cut in 0..=page.len() {
            let mut st = Injection::Wanted;
            assert!(st.on_response(200, Some("text/html"), None));
            let out = run(&mut st, &[&page[..cut], &page[cut..]]);
            assert_eq!(String::from_utf8(out).unwrap(), want, "cut at {cut}");
            assert_eq!(st, Injection::Pass);
        }
    }

    #[test]
    fn nothing_is_sent_until_the_end() {
        let mut st = Injection::Wanted;
        st.on_response(200, Some("text/html"), None);
        assert_eq!(st.on_body(Some(b"<head>".to_vec()), false), None);
        assert_eq!(st.on_body(None, false), None);
        let out = st.on_body(None, true).unwrap();
        assert_eq!(out, b"<head>".to_vec(), "no </head> and no </body>: unchanged");
    }

    #[test]
    fn over_the_limit_the_held_part_goes_out_and_the_rest_passes() {
        let mut st = Injection::Wanted;
        st.on_response(200, Some("text/html"), None);
        let big = vec![b'x'; MAX_BUFFER];
        assert_eq!(st.on_body(Some(b"<head></head>".to_vec()), false), None);
        let first = st.on_body(Some(big.clone()), false).unwrap();
        assert_eq!(first.len(), 13 + MAX_BUFFER);
        assert_eq!(st, Injection::Pass);
        assert_eq!(st.on_body(Some(b"</body>".to_vec()), true), Some(b"</body>".to_vec()));
    }

    #[test]
    fn other_responses_and_requests_pass_untouched() {
        let mut st = Injection::Wanted;
        assert!(!st.on_response(200, Some("application/json"), None));
        assert_eq!(st.on_body(Some(b"{}".to_vec()), true), Some(b"{}".to_vec()));
        let mut off = Injection::for_request(false, "GET", None);
        assert_eq!(off, Injection::Pass);
        assert!(!off.on_response(200, Some("text/html"), None));
        assert_eq!(Injection::for_request(true, "GET", Some("script")), Injection::Pass);
        assert_eq!(Injection::for_request(true, "GET", Some("document")), Injection::Wanted);
        // A second response decision cannot restart holding.
        let mut st = Injection::Pass;
        assert!(!st.on_response(200, Some("text/html"), None));
    }

    #[test]
    fn an_empty_page_ends_cleanly() {
        let mut st = Injection::Wanted;
        st.on_response(200, Some("text/html"), None);
        assert_eq!(st.on_body(None, true), Some(Vec::new()));
        assert_eq!(st, Injection::Pass);
    }

    #[test]
    fn etags_are_made_weak() {
        assert_eq!(weaken_etag("\"abc\""), "W/\"abc\"");
        assert_eq!(weaken_etag("W/\"abc\""), "W/\"abc\"");
        assert_eq!(weaken_etag(" \"abc\" "), "W/\"abc\"");
    }

    #[test]
    fn which_requests() {
        assert!(request_wants("GET", None));
        assert!(request_wants("GET", Some("document")));
        assert!(request_wants("GET", Some("Document")));
        assert!(!request_wants("GET", Some("iframe")));
        assert!(!request_wants("GET", Some("empty")));
        assert!(!request_wants("HEAD", None));
        assert!(!request_wants("POST", Some("document")));
    }

    #[test]
    fn which_responses() {
        assert!(response_allows(200, Some("text/html"), None));
        assert!(response_allows(200, Some("text/html; charset=utf-8"), Some("identity")));
        assert!(response_allows(200, Some("Text/HTML"), Some("")));
        assert!(!response_allows(200, Some("text/html"), Some("gzip")));
        assert!(!response_allows(200, Some("application/json"), None));
        assert!(!response_allows(200, Some("text/htmlx"), None));
        assert!(!response_allows(200, None, None));
        assert!(!response_allows(304, Some("text/html"), None));
        assert!(!response_allows(206, Some("text/html"), None));
    }
}
