//! Admin listener: serves the dashboard from the in-memory event ring.
//! Plain HTTP. It binds loopback, or any address when a token is configured
//! ([`check_bind`], enforced at start-up in `main`): inside a container the
//! host can only reach it on the container's own address, and the deploy kit
//! publishes that port on the host's 127.0.0.1 only. With a token configured,
//! nothing is served without it (see `admin_auth`).
//!
//! Every request must name this listener in its `Host` header (its own
//! `ip:port`, or `localhost:port`; for an all-addresses bind, the loopback
//! names a tunnel gives). Loopback alone does not stop a web page
//! in the operator's browser: a name the page controls can be re-pointed at
//! 127.0.0.1 (DNS rebinding), and the browser then sends that name as `Host`.
//! Refusing any other `Host` closes that, with or without a token.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use http::Response;
use pingora::apps::http_app::ServeHttp;
use pingora::protocols::http::ServerSession;

use veritell_events::MemoryRing;

pub struct AdminApp {
    pub events: Arc<MemoryRing>,
    /// When set, every request must present it.
    pub token: Option<Vec<u8>>,
    /// The `Host` values this listener answers to.
    pub hosts: Vec<String>,
}

/// Whether the admin listener may bind `addr`. Loopback always; any other
/// address only with a token, since the listener speaks plain HTTP and
/// anything that can reach the port could otherwise read the events.
pub fn check_bind(addr: std::net::SocketAddr, has_token: bool) -> Result<(), String> {
    if addr.ip().is_loopback() || has_token {
        Ok(())
    } else {
        Err(format!(
            "--admin {addr}: a non-loopback address needs VERITELL_ADMIN_TOKEN"
        ))
    }
}

/// The `Host` values a listener on `addr` answers to: `ip:port` as written,
/// `[ip]:port` for IPv6, and `localhost:port`. For an unspecified address
/// (`0.0.0.0`, `[::]`) the loopback names instead (`127.0.0.1:port`,
/// `[::1]:port`), which is what a tunnel or a published port gives; the
/// unspecified address itself is not a name a browser should use.
pub fn allowed_hosts(addr: std::net::SocketAddr) -> Vec<String> {
    let port = addr.port();
    let mut hosts = vec![format!("localhost:{port}")];
    if addr.ip().is_unspecified() {
        hosts.push(format!("127.0.0.1:{port}"));
        hosts.push(format!("[::1]:{port}"));
    } else {
        hosts.push(addr.to_string());
    }
    hosts.sort();
    hosts.dedup();
    hosts
}

/// Whether a request's `Host` names this listener (ASCII case-insensitive).
pub fn host_allowed(host: Option<&str>, allowed: &[String]) -> bool {
    host.is_some_and(|h| allowed.iter().any(|a| a.eq_ignore_ascii_case(h.trim())))
}

fn misdirected() -> Response<Vec<u8>> {
    let body = b"wrong host".to_vec();
    Response::builder()
        .status(http::StatusCode::MISDIRECTED_REQUEST)
        .header("content-type", "text/plain")
        .header("content-length", body.len())
        .header("cache-control", "no-store")
        .body(body)
        .unwrap_or_else(|_| {
            let mut fallback = Response::new(b"wrong host".to_vec());
            *fallback.status_mut() = http::StatusCode::MISDIRECTED_REQUEST;
            fallback
        })
}

/// The answer to a request without the token. `Basic` is offered so that a
/// browser asks for it; the token is the password.
fn unauthorized() -> Response<Vec<u8>> {
    let body = b"unauthorized".to_vec();
    Response::builder()
        .status(http::StatusCode::UNAUTHORIZED)
        .header("content-type", "text/plain")
        .header("content-length", body.len())
        .header("cache-control", "no-store")
        .header(
            "www-authenticate",
            "Basic realm=\"veritell admin\", charset=\"UTF-8\"",
        )
        .body(body)
        .unwrap_or_else(|_| {
            let mut fallback = Response::new(b"unauthorized".to_vec());
            *fallback.status_mut() = http::StatusCode::UNAUTHORIZED;
            fallback
        })
}

#[async_trait]
impl ServeHttp for AdminApp {
    async fn response(&self, session: &mut ServerSession) -> Response<Vec<u8>> {
        let req = session.req_header();
        let host = req.headers.get("host").and_then(|v| v.to_str().ok());
        if !host_allowed(host, &self.hosts) {
            return misdirected();
        }
        if let Some(token) = &self.token {
            let presented = req
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok());
            if !crate::admin_auth::authorized(presented, token) {
                return unauthorized();
            }
        }
        let target = req
            .uri
            .path_and_query()
            .map_or_else(|| req.uri.path().to_string(), |p| p.as_str().to_string());
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        let out = veritell_dash::handle(req.method.as_str(), &target, self.events.as_ref(), now_ms);

        let mut builder = Response::builder()
            .status(out.status)
            .header("content-type", out.content_type)
            .header("content-length", out.body.len());
        for (name, value) in &out.headers {
            builder = builder.header(*name, value.as_str());
        }
        builder.body(out.body).unwrap_or_else(|_| {
            let mut fallback = Response::new(b"internal error".to_vec());
            *fallback.status_mut() = http::StatusCode::INTERNAL_SERVER_ERROR;
            fallback
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_this_listeners_names_are_answered() {
        let ok = allowed_hosts("127.0.0.1:9090".parse().unwrap());
        assert!(host_allowed(Some("127.0.0.1:9090"), &ok));
        assert!(host_allowed(Some("localhost:9090"), &ok));
        assert!(host_allowed(Some("LOCALHOST:9090"), &ok));
        assert!(
            !host_allowed(Some("attacker.example:9090"), &ok),
            "a rebinding page's name"
        );
        assert!(!host_allowed(Some("localhost:9091"), &ok));
        assert!(!host_allowed(Some("127.0.0.1"), &ok));
        assert!(!host_allowed(None, &ok));
        let v6 = allowed_hosts("[::1]:9090".parse().unwrap());
        assert!(host_allowed(Some("[::1]:9090"), &v6));
        assert!(host_allowed(Some("localhost:9090"), &v6));
    }

    #[test]
    fn all_addresses_answer_to_loopback_names_only() {
        for bind in ["0.0.0.0:9090", "[::]:9090"] {
            let ok = allowed_hosts(bind.parse().unwrap());
            assert!(host_allowed(Some("127.0.0.1:9090"), &ok), "{bind}");
            assert!(host_allowed(Some("[::1]:9090"), &ok), "{bind}");
            assert!(host_allowed(Some("localhost:9090"), &ok), "{bind}");
            assert!(
                !host_allowed(Some("0.0.0.0:9090"), &ok),
                "{bind}: not a name to browse to"
            );
            assert!(!host_allowed(Some("[::]:9090"), &ok), "{bind}");
            assert!(
                !host_allowed(Some("172.20.0.5:9090"), &ok),
                "{bind}: the container's address"
            );
            assert!(!host_allowed(Some("attacker.example:9090"), &ok), "{bind}");
        }
    }

    #[test]
    fn non_loopback_bind_needs_a_token() {
        let any: std::net::SocketAddr = "0.0.0.0:9090".parse().unwrap();
        assert!(check_bind(any, false).is_err());
        assert!(check_bind(any, true).is_ok());
        assert!(check_bind("192.0.2.1:9090".parse().unwrap(), false).is_err());
        assert!(check_bind("127.0.0.1:9090".parse().unwrap(), false).is_ok());
        assert!(check_bind("[::1]:9090".parse().unwrap(), false).is_ok());
    }

    // ---------- the listener's answers ----------

    use base64::Engine as _;
    use tokio::io::AsyncWriteExt;

    const TOKEN: &[u8] = b"admin-test-token";

    fn app(token: Option<&[u8]>) -> AdminApp {
        AdminApp {
            events: Arc::new(MemoryRing::new(16)),
            token: token.map(<[u8]>::to_vec),
            hosts: allowed_hosts("127.0.0.1:9090".parse().unwrap()),
        }
    }

    /// Sends `request` (raw HTTP/1.1) to `app` and returns its answer.
    async fn ask(app: &AdminApp, request: &str) -> Response<Vec<u8>> {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        client.write_all(request.as_bytes()).await.unwrap();
        let mut session = ServerSession::new_http1(Box::new(server));
        assert!(session.read_request().await.unwrap(), "the request is read");
        app.response(&mut session).await
    }

    fn get(path: &str, host: &str, authorization: Option<&str>) -> String {
        let auth = authorization
            .map(|a| format!("Authorization: {a}\r\n"))
            .unwrap_or_default();
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n{auth}\r\n")
    }

    fn header<'a>(r: &'a Response<Vec<u8>>, name: &str) -> &'a str {
        r.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
    }

    #[tokio::test]
    async fn another_host_is_misdirected_before_anything_else() {
        let r = ask(
            &app(Some(TOKEN)),
            &get("/api/summary", "attacker.example:9090", None),
        )
        .await;
        assert_eq!(r.status(), http::StatusCode::MISDIRECTED_REQUEST);
        assert_eq!(r.body(), b"wrong host");
        assert_eq!(header(&r, "cache-control"), "no-store");
        assert_eq!(header(&r, "content-length"), "10");
        assert!(
            r.headers().get("www-authenticate").is_none(),
            "no login offered to a rebinding page"
        );
    }

    #[tokio::test]
    async fn without_a_token_configured_the_dashboard_is_served() {
        let a = app(None);
        let r = ask(&a, &get("/", "localhost:9090", None)).await;
        assert_eq!(r.status(), http::StatusCode::OK);
        assert!(header(&r, "content-type").starts_with("text/html"));
        assert_eq!(header(&r, "content-length"), r.body().len().to_string());
        let r = ask(
            &a,
            &get("/api/summary?window_secs=60", "127.0.0.1:9090", None),
        )
        .await;
        assert_eq!(r.status(), http::StatusCode::OK);
        assert!(header(&r, "content-type").starts_with("application/json"));
        assert!(String::from_utf8_lossy(r.body()).contains("\"total\""));
    }

    #[tokio::test]
    async fn with_a_token_configured_nothing_is_served_without_it() {
        let a = app(Some(TOKEN));
        let r = ask(&a, &get("/api/events", "localhost:9090", None)).await;
        assert_eq!(r.status(), http::StatusCode::UNAUTHORIZED);
        assert_eq!(r.body(), b"unauthorized");
        assert!(header(&r, "www-authenticate").starts_with("Basic realm=\"veritell admin\""));
        assert_eq!(header(&r, "cache-control"), "no-store");
        let r = ask(
            &a,
            &get("/api/events", "localhost:9090", Some("Bearer wrong")),
        )
        .await;
        assert_eq!(r.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn the_token_is_taken_as_a_bearer_or_a_basic_password() {
        let a = app(Some(TOKEN));
        let bearer = format!("Bearer {}", std::str::from_utf8(TOKEN).unwrap());
        let r = ask(&a, &get("/api/events", "localhost:9090", Some(&bearer))).await;
        assert_eq!(r.status(), http::StatusCode::OK);
        let basic = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD
                .encode([b"admin:".as_slice(), TOKEN].concat())
        );
        let r = ask(
            &a,
            &get("/api/events?limit=5", "localhost:9090", Some(&basic)),
        )
        .await;
        assert_eq!(r.status(), http::StatusCode::OK);
        assert_eq!(r.body(), b"[]");
    }

    #[tokio::test]
    async fn the_dashboards_own_answers_and_headers_are_passed_on() {
        let a = app(None);
        let r = ask(
            &a,
            "POST /api/events HTTP/1.1\r\nHost: localhost:9090\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        assert_eq!(r.status(), http::StatusCode::METHOD_NOT_ALLOWED);
        let r = ask(&a, &get("/nothing-here", "localhost:9090", None)).await;
        assert_eq!(r.status(), http::StatusCode::NOT_FOUND);
    }
}
