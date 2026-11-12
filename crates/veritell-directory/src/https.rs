//! The real network transport.

use std::io::{self, Read};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;

use crate::{DirectoryUrl, FetchConfig, Response, Transport};

/// The real transport: system DNS, then HTTPS with certificate checking.
///
/// Built on `ureq` 2 (already used by `veritell-events`), which must be
/// configured so that: redirects are off; the connection goes to the `addr`
/// passed to `get` and nowhere else (ureq's resolver hook returns exactly
/// that address); the request URL keeps the host name, so the certificate
/// and SNI are checked against `url.host`; no proxy from the environment is
/// used; the timeout covers the whole exchange; reading stops at
/// `max_bytes + 1`.
pub struct HttpsTransport {
    tls: Arc<rustls::ClientConfig>,
    resolve_timeout: Duration,
}

/// Runs `lookup` on a helper thread and waits at most `timeout` for it. On
/// timeout the helper is left to finish by itself and its answer is dropped.
fn lookup_with_deadline<F>(timeout: Duration, lookup: F) -> Result<Vec<IpAddr>, String>
where
    F: FnOnce() -> Result<Vec<IpAddr>, String> + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("veritell-dns".to_string())
        .spawn(move || {
            // The receiver may be gone after a timeout; that is fine.
            let _ = tx.send(lookup());
        })
        .map_err(|e| format!("could not start the name lookup: {e}"))?;
    match rx.recv_timeout(timeout) {
        Ok(answer) => answer,
        Err(mpsc::RecvTimeoutError::Timeout) => Err("name lookup timed out".to_string()),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err("name lookup failed".to_string()),
    }
}

impl HttpsTransport {
    /// `extra_roots_pem`: PEM certificates trusted in addition to the
    /// built-in roots (an operator's private CA, or a test server's
    /// certificate). Fails with a description if the PEM holds no usable
    /// certificate.
    pub fn new(extra_roots_pem: Option<&[u8]>) -> Result<HttpsTransport, String> {
        let mut roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        if let Some(pem) = extra_roots_pem {
            let mut added = 0usize;
            for item in CertificateDer::pem_slice_iter(pem) {
                let der = item.map_err(|e| format!("extra root certificate PEM: {e}"))?;
                roots.add(der).map_err(|e| format!("extra root certificate refused: {e}"))?;
                added = added.saturating_add(1);
            }
            if added == 0 {
                return Err("no certificate found in the extra root PEM".to_string());
            }
        }
        let config = rustls::ClientConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
        .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
        .map_err(|e| format!("TLS configuration: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
        Ok(HttpsTransport { tls: Arc::new(config), resolve_timeout: FetchConfig::DEFAULT_TIMEOUT })
    }

    /// How long a name lookup may take before it is given up (default
    /// `FetchConfig::DEFAULT_TIMEOUT`; zero means the default). Set it to the
    /// fetch deadline so that DNS is inside it.
    pub fn with_resolve_timeout(mut self, timeout: Duration) -> HttpsTransport {
        self.resolve_timeout = if timeout.is_zero() { FetchConfig::DEFAULT_TIMEOUT } else { timeout };
        self
    }
}

impl Transport for HttpsTransport {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, String> {
        let bare = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
        if let Ok(ip) = bare.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let host = host.to_string();
        lookup_with_deadline(self.resolve_timeout, move || {
            let found = (host.as_str(), port).to_socket_addrs().map_err(|e| e.to_string())?;
            let mut out: Vec<IpAddr> = Vec::new();
            for sa in found {
                if !out.contains(&sa.ip()) {
                    out.push(sa.ip());
                }
            }
            Ok(out)
        })
    }

    fn get(
        &self,
        addr: SocketAddr,
        url: &DirectoryUrl,
        max_bytes: usize,
        timeout: Duration,
    ) -> Result<Response, String> {
        let timeout = if timeout.is_zero() { FetchConfig::DEFAULT_TIMEOUT } else { timeout };
        let agent = ureq::AgentBuilder::new()
            .redirects(0)
            .try_proxy_from_env(false)
            .https_only(true)
            .timeout(timeout)
            .tls_config(self.tls.clone())
            .resolver(move |_netloc: &str| -> io::Result<Vec<SocketAddr>> { Ok(vec![addr]) })
            .build();
        let response = match agent.get(&url.as_string()).call() {
            Ok(r) => r,
            Err(ureq::Error::Status(code, r)) => {
                return Ok(Response {
                    status: code,
                    cache_control: r.header("cache-control").map(str::to_string),
                    body: Vec::new(),
                });
            }
            Err(e) => return Err(e.to_string()),
        };
        let status = response.status();
        let cache_control = response.header("cache-control").map(str::to_string);
        let mut body = Vec::new();
        response
            .into_reader()
            .take((max_bytes as u64).saturating_add(1))
            .read_to_end(&mut body)
            .map_err(|e| format!("reading the body: {e}"))?;
        Ok(Response { status, cache_control, body })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_with_built_in_roots_only() {
        assert!(HttpsTransport::new(None).is_ok());
    }

    #[test]
    fn refuses_pem_without_a_certificate() {
        assert!(HttpsTransport::new(Some(b"garbage")).is_err());
        assert!(HttpsTransport::new(Some(b"")).is_err());
    }

    #[test]
    fn address_literals_resolve_to_themselves() {
        let t = HttpsTransport::new(None).unwrap();
        assert_eq!(t.resolve("127.0.0.1", 443).unwrap(), vec!["127.0.0.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(t.resolve("::1", 443).unwrap(), vec!["::1".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn a_slow_lookup_is_given_up_at_the_deadline() {
        let start = std::time::Instant::now();
        let r = lookup_with_deadline(Duration::from_millis(200), || {
            std::thread::sleep(Duration::from_secs(3));
            Ok(vec!["93.184.216.34".parse().unwrap()])
        });
        assert!(r.unwrap_err().contains("timed out"));
        assert!(start.elapsed() < Duration::from_secs(2), "{:?}", start.elapsed());
    }

    #[test]
    fn a_fast_lookup_is_returned() {
        let r = lookup_with_deadline(Duration::from_secs(2), || Ok(vec!["1.1.1.1".parse().unwrap()]));
        assert_eq!(r.unwrap(), vec!["1.1.1.1".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn the_transport_resolve_honours_its_deadline_setting() {
        let t = HttpsTransport::new(None).unwrap().with_resolve_timeout(Duration::from_secs(1));
        assert_eq!(t.resolve_timeout, Duration::from_secs(1));
        let t = t.with_resolve_timeout(Duration::ZERO);
        assert_eq!(t.resolve_timeout, FetchConfig::DEFAULT_TIMEOUT);
    }

    #[test]
    fn localhost_resolves_to_loopback() {
        let t = HttpsTransport::new(None).unwrap();
        let ips = t.resolve("localhost", 443).unwrap();
        assert!(!ips.is_empty());
        assert!(ips.iter().all(|ip| ip.is_loopback()));
        let mut seen = ips.clone();
        seen.dedup();
        assert_eq!(seen, ips);
    }
}
