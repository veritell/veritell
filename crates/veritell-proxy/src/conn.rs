//! Per-connection fingerprint capture: the TLS ClientHello callback and the
//! server-app wrapper that tees the HTTP/2 preamble.

use std::any::Any;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use boring::ex_data::Index;
use pingora::apps::ServerApp;
use pingora::listeners::tls::TlsSettings;
use pingora::listeners::TlsAccept;
use pingora::protocols::tls::TlsRef;
use pingora::protocols::{Stream, ALPN};
use pingora::proxy::{HttpProxy, ProxyHttp, Session};
use pingora::server::ShutdownWatch;
use pingora::tls::ssl::Ssl;

use veritell_fp::ja4::{self, TlsFp};

use crate::syn::{SynSeen, SynStore};
use crate::tee::{Guard, H1Guard, H2Capture, H2Guard, TeeStream};

/// Attached to the TLS digest so the HTTP layer can read it.
pub struct ConnInfo {
    pub tls: TlsFp,
    pub h2: Arc<H2Capture>,
    /// The client's TCP SYN, set once the connection reaches the HTTP layer
    /// (Linux only; see `syn.rs`). Logged, never scored.
    pub syn: OnceLock<SynSeen>,
}

fn tls_fp_index() -> Option<Index<Ssl, TlsFp>> {
    static IDX: OnceLock<Option<Index<Ssl, TlsFp>>> = OnceLock::new();
    *IDX.get_or_init(|| Ssl::new_ex_index().ok())
}

/// Registers the ClientHello callback on a listener's TLS settings.
/// Returns false if BoringSSL could not allocate the ex_data slot.
pub fn install_client_hello_hook(tls: &mut TlsSettings) -> bool {
    let Some(index) = tls_fp_index() else {
        return false;
    };
    tls.set_select_certificate_callback(move |mut hello| {
        if let Some(fp) = ja4::compute(hello.as_bytes(), false) {
            hello.ssl_mut().replace_ex_data(index, fp);
        }
        Ok(())
    });
    true
}

pub struct TlsCallbacks {
    /// Extra certificates by SNI (`--sni-dir`); `None` serves the default
    /// certificate on the context to every connection.
    pub sni: Option<Arc<crate::sni::SniCerts>>,
}

#[async_trait]
impl TlsAccept for TlsCallbacks {
    /// Switches the connection to the certificate for its SNI name, when one
    /// was loaded for it; otherwise the context's default stays.
    async fn certificate_callback(&self, ssl: &mut TlsRef) {
        let Some(sni) = &self.sni else { return };
        let Some(name) = ssl.servername(boring::ssl::NameType::HOST_NAME).map(str::to_owned) else {
            return;
        };
        if let Some(ctx) = sni.find(&name) {
            // On failure the default certificate is served, never none.
            let _ = ssl.set_ssl_context(ctx);
        }
    }

    async fn handshake_complete_callback(
        &self,
        ssl: &TlsRef,
    ) -> Option<Arc<dyn Any + Send + Sync>> {
        let tls = ssl.ex_data(tls_fp_index()?).cloned()?;
        Some(Arc::new(ConnInfo {
            tls,
            h2: Arc::new(H2Capture::default()),
            syn: OnceLock::new(),
        }))
    }
}

/// Open connections per client network: the address for IPv4, the /64 for
/// IPv6 (one host usually holds a whole /64). Memory is one entry per network
/// with a connection open, so it is bounded by the open connections.
pub struct ConnLimiter {
    max_per_network: u32,
    open: Mutex<HashMap<IpAddr, u32>>,
    stats: Mutex<ConnStats>,
}

/// What one hour of connections looked like, without any address: the most
/// any one network held open at once, how often a network reached each
/// level, and how many connections the cap refused. Written as a
/// `conn_peak` line when the first connection of the next hour arrives, so
/// a cap can be chosen from what real clients do.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConnStats {
    /// The hour (Unix seconds / 3600) these counts belong to.
    hour: u64,
    pub peak: u32,
    /// Times a network's open connections reached 16, 32, 64 and 128.
    pub reached: [u32; 4],
    pub refused: u32,
}

const LEVELS: [u32; 4] = [16, 32, 64, 128];

impl ConnStats {
    fn line(&self) -> serde_json::Value {
        serde_json::json!({
            "kind": "conn_peak",
            "hour_start": self.hour * 3600,
            "peak": self.peak,
            "reached_16": self.reached[0],
            "reached_32": self.reached[1],
            "reached_64": self.reached[2],
            "reached_128": self.reached[3],
            "refused": self.refused,
        })
    }
}

/// Held for the life of a connection; gives its place back when dropped.
pub struct ConnGuard {
    limiter: Arc<ConnLimiter>,
    network: IpAddr,
}

impl ConnLimiter {
    pub fn new(max_per_network: u32) -> Arc<ConnLimiter> {
        Arc::new(ConnLimiter {
            max_per_network,
            open: Mutex::new(HashMap::new()),
            stats: Mutex::new(ConnStats::default()),
        })
    }

    pub fn network(ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V4(_) => ip,
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => {
                    let s = v6.segments();
                    IpAddr::from([s[0], s[1], s[2], s[3], 0, 0, 0, 0])
                }
            },
        }
    }

    /// A place for one more connection from `ip`, or `None` when its network
    /// already has the maximum open.
    pub fn acquire(self: &Arc<Self>, ip: IpAddr) -> Option<ConnGuard> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let (guard, finished) = self.acquire_at(ip, now);
        if let Some(stats) = finished {
            println!("{}", stats.line());
        }
        guard
    }

    /// As [`ConnLimiter::acquire`] at `now`; also returns the last hour's
    /// counts when this is the first connection of a new hour.
    fn acquire_at(self: &Arc<Self>, ip: IpAddr, now: u64) -> (Option<ConnGuard>, Option<ConnStats>) {
        let network = Self::network(ip);
        let mut open = self.open.lock().unwrap_or_else(|e| e.into_inner());
        let count = open.entry(network).or_insert(0);
        let admitted = *count < self.max_per_network;
        if admitted {
            *count += 1;
        }
        let held = *count;
        drop(open);

        let mut stats = self.stats.lock().unwrap_or_else(|e| e.into_inner());
        let hour = now / 3600;
        let mut finished = None;
        if hour > stats.hour {
            let old = std::mem::take(&mut *stats);
            // Nothing to report for the first hour seen, or an empty one.
            if old.hour != 0 && old.peak != 0 {
                finished = Some(old);
            }
            stats.hour = hour;
        }
        if admitted {
            stats.peak = stats.peak.max(held);
            if let Some(i) = LEVELS.iter().position(|&l| l == held) {
                stats.reached[i] = stats.reached[i].saturating_add(1);
            }
        } else {
            stats.refused = stats.refused.saturating_add(1);
        }
        drop(stats);

        let guard = admitted.then(|| ConnGuard { limiter: Arc::clone(self), network });
        (guard, finished)
    }

    #[cfg(test)]
    fn open_for(&self, ip: IpAddr) -> u32 {
        let open = self.open.lock().unwrap_or_else(|e| e.into_inner());
        open.get(&Self::network(ip)).copied().unwrap_or(0)
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        let mut open = self.limiter.open.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = open.get_mut(&self.network) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                open.remove(&self.network);
            }
        }
    }
}

/// Wraps the stock HTTP proxy. Each new HTTP/2 connection is read through a
/// `TeeStream` that copies its preamble; each HTTP/1 connection through one
/// that puts deadlines on slow requests (see `tee.rs`). Connections over the
/// per-network cap are closed before any request is read.
pub struct FingerprintApp<SV: ProxyHttp> {
    pub inner: Arc<HttpProxy<SV>>,
    pub limiter: Arc<ConnLimiter>,
    /// Peers that are not capped: a proxy in front carries many clients.
    pub trusted_proxies: Vec<IpAddr>,
    pub header_timeout: Duration,
    /// The longest a request body (HTTP/1 or HTTP/2) or one HTTP/2 DATA
    /// frame may take to arrive (`--body-timeout`).
    pub body_timeout: Duration,
    /// SYNs read before the handshake, by socket cookie.
    pub syn: Arc<SynStore>,
}

#[async_trait]
impl<SV> ServerApp for FingerprintApp<SV>
where
    SV: ProxyHttp + Send + Sync + 'static,
    SV::CTX: Send + Sync,
{
    async fn process_new(
        self: &Arc<Self>,
        stream: Stream,
        shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        let peer = stream
            .get_socket_digest()
            .and_then(|d| d.peer_addr().and_then(|a| a.as_inet()).map(|a| crate::gateway::canonical(a.ip())));
        let _guard = match peer {
            Some(ip) if !self.trusted_proxies.contains(&ip) => match self.limiter.acquire(ip) {
                Some(guard) => Some(guard),
                None => {
                    // Counts only: the address is not written here.
                    println!("{}", serde_json::json!({ "kind": "conn_refused", "reason": "per_network_cap" }));
                    return None;
                }
            },
            _ => None,
        };
        // The SYN read before the handshake, matched by socket cookie (0
        // where the platform has none).
        if let (Some(digest), Some(cookie)) = (
            stream.get_ssl_digest(),
            stream.get_socket_digest().and_then(|d| d.socket_cookie().ok()).filter(|&c| c != 0),
        ) {
            if let Some(ci) = digest.extension.get::<ConnInfo>() {
                if let Some(seen) = self.syn.take(cookie) {
                    let _ = ci.syn.set(seen);
                }
            }
        }
        let h2 = matches!(stream.selected_alpn_proto(), Some(ALPN::H2));
        let capture = if h2 {
            stream
                .get_ssl_digest()
                .and_then(|d| d.extension.get::<ConnInfo>().map(|c| c.h2.clone()))
                .filter(|c| c.attach())
        } else {
            None
        };
        let guard = Some(if h2 {
            Guard::H2(H2Guard::new(self.header_timeout, self.body_timeout))
        } else {
            Guard::H1(H1Guard::new(self.header_timeout))
        });
        let stream: Stream = if capture.is_some() || guard.is_some() {
            Box::new(TeeStream::new(stream, capture, guard))
        } else {
            stream
        };
        // The guard is held until the connection is finished with: Pingora
        // 0.9's HTTP proxy serves keep-alive requests inside this call and
        // does not hand the stream back, so one guard covers the connection.
        ServerApp::process_new(&self.inner, stream, shutdown).await
    }

    async fn cleanup(&self) {
        ServerApp::cleanup(self.inner.as_ref()).await
    }
}

pub fn conn_info(session: &Session) -> Option<&ConnInfo> {
    session
        .digest()?
        .ssl_digest
        .as_ref()?
        .extension
        .get::<ConnInfo>()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn caps_per_network_and_gives_places_back() {
        let l = ConnLimiter::new(2);
        let a = l.acquire(ip("203.0.113.9")).unwrap();
        let b = l.acquire(ip("203.0.113.9")).unwrap();
        assert!(l.acquire(ip("203.0.113.9")).is_none());
        assert!(l.acquire(ip("203.0.113.10")).is_some(), "another address is another network");
        drop(a);
        assert!(l.acquire(ip("203.0.113.9")).is_some());
        drop(b);
        assert_eq!(l.open_for(ip("203.0.113.9")), 0);
        assert!(l.open.lock().unwrap().is_empty(), "no entry is left for a network with nothing open");
    }

    #[test]
    fn an_hour_of_connections_is_reported_without_addresses() {
        let l = ConnLimiter::new(17);
        let t = 3600 * 500_000;
        let mut held = Vec::new();
        for _ in 0..17 {
            held.push(l.acquire_at(ip("203.0.113.9"), t).0.unwrap());
        }
        let (refused, none) = l.acquire_at(ip("203.0.113.9"), t + 10);
        assert!(refused.is_none() && none.is_none(), "same hour: nothing reported yet");
        let (_, report) = l.acquire_at(ip("198.51.100.1"), t + 3600);
        let report = report.expect("the first connection of the next hour reports the last");
        assert_eq!((report.peak, report.reached, report.refused), (17, [1, 0, 0, 0], 1));
        let line = report.line().to_string();
        assert!(!line.contains("203.0.113"), "{line}");
        // The new hour starts from zero, and a quiet hour is not reported.
        let (_, again) = l.acquire_at(ip("198.51.100.1"), t + 3 * 3600);
        assert_eq!(again.map(|s| s.peak), Some(1), "the hour of t + 3600 held one");
        drop(held);
    }

    #[test]
    fn ipv6_is_counted_per_64_and_mapped_v4_as_v4() {
        let l = ConnLimiter::new(1);
        let _a = l.acquire(ip("2001:db8:1:2::1")).unwrap();
        assert!(l.acquire(ip("2001:db8:1:2:ffff::9")).is_none(), "same /64");
        assert!(l.acquire(ip("2001:db8:1:3::1")).is_some(), "another /64");
        let _v4 = l.acquire(ip("198.51.100.7")).unwrap();
        assert!(l.acquire(ip("::ffff:198.51.100.7")).is_none());
    }
}
