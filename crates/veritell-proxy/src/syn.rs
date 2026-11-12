//! The client's TCP SYN, measured and never scored.
//!
//! Linux keeps a copy of a connection's SYN when the listening socket has
//! `TCP_SAVE_SYN` set, and gives it back once through `TCP_SAVED_SYN`.
//! Pingora 0.9 has no way to set the option on its listener, but the kernel
//! reads it from the listener when each SYN arrives, so it can be set after
//! the socket is bound: the first connection finds the listener among the
//! process's descriptors and sets it there. That connection's own SYN was
//! not saved; every later one is.
//!
//! The SYN is read before the TLS handshake (Pingora's pre-TLS hook, which
//! sees the raw TCP stream), parsed, and kept by the connection's socket
//! cookie until the connection reaches the HTTP layer, which takes it. A
//! connection that never gets there (a failed handshake) leaves its entry
//! behind; entries older than a minute are swept when the store is full, and
//! a full store takes nothing more.
//!
//! Only the signature and the observed TTL are kept. The SYN's source address
//! is compared with the peer's and then dropped. A SYN from a peer that is
//! not a public address is a local proxy's (Docker's userland proxy carries
//! IPv6 to a container this way), not the client's, so it is not kept.

// Elsewhere only the taking side is used: nothing is ever put.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// What the HTTP layer gets: the signature and the TTL as it arrived.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SynSeen {
    pub signature: String,
    pub ttl: u8,
}

const CAPACITY: usize = 4096;
const MAX_AGE: Duration = Duration::from_secs(60);

/// Parsed SYNs waiting for their connection's first request.
pub struct SynStore {
    entries: Mutex<HashMap<u64, (Instant, SynSeen)>>,
}

impl Default for SynStore {
    fn default() -> Self {
        SynStore { entries: Mutex::new(HashMap::new()) }
    }
}

impl SynStore {
    pub fn put(&self, cookie: u64, seen: SynSeen) {
        self.put_at(cookie, seen, Instant::now());
    }

    fn put_at(&self, cookie: u64, seen: SynSeen, now: Instant) {
        let mut e = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        if e.len() >= CAPACITY {
            e.retain(|_, (at, _)| now.duration_since(*at) < MAX_AGE);
            if e.len() >= CAPACITY {
                return;
            }
        }
        e.insert(cookie, (now, seen));
    }

    pub fn take(&self, cookie: u64) -> Option<SynSeen> {
        let mut e = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        e.remove(&cookie).map(|(_, s)| s)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
}

/// Whether `ip` can be a client on the internet: not loopback, private,
/// link-local, shared (100.64/10) or unique-local.
pub fn is_public(ip: IpAddr) -> bool {
    match crate::gateway::canonical(ip) {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || (o[0] == 100 && (64..128).contains(&o[1])))
        }
        IpAddr::V6(v6) => {
            let s = v6.segments()[0];
            !(v6.is_loopback() || v6.is_unspecified() || (s & 0xfe00) == 0xfc00 || (s & 0xffc0) == 0xfe80)
        }
    }
}

/// What to keep of a parsed SYN, given the peer the socket reports.
pub fn accept(fp: veritell_fp::syn::SynFp, peer: IpAddr) -> Option<SynSeen> {
    let peer = crate::gateway::canonical(peer);
    if !is_public(peer) || crate::gateway::canonical(fp.src) != peer {
        return None;
    }
    Some(SynSeen { signature: fp.signature, ttl: fp.ttl })
}

#[cfg(target_os = "linux")]
pub use linux::SynHook;

#[cfg(target_os = "linux")]
mod linux {
    use std::os::fd::{AsRawFd, RawFd};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use async_trait::async_trait;
    use pingora::listeners::PreTlsProcess;
    use pingora::protocols::l4::stream::Stream as L4Stream;
    use pingora::protocols::GetSocketDigest;

    use super::{accept, SynStore};

    /// Pingora's pre-TLS hook: sets up the listener once, then reads each
    /// connection's saved SYN. Never fails a connection.
    pub struct SynHook {
        pub store: Arc<SynStore>,
        pub port: u16,
        configured: AtomicBool,
    }

    impl SynHook {
        pub fn new(store: Arc<SynStore>, port: u16) -> SynHook {
            SynHook { store, port, configured: AtomicBool::new(false) }
        }
    }

    #[async_trait]
    impl PreTlsProcess for SynHook {
        async fn process(&self, stream: &mut L4Stream) -> pingora::Result<()> {
            if !self.configured.swap(true, Ordering::AcqRel) {
                let n = save_syn_on_listeners(self.port);
                println!("{}", serde_json::json!({ "kind": "tcp_syn", "listeners": n }));
            }
            let fd = stream.as_raw_fd();
            let Some(bytes) = saved_syn(fd) else { return Ok(()) };
            let Some(fp) = veritell_fp::syn::parse(&bytes) else { return Ok(()) };
            let peer = stream
                .get_socket_digest()
                .and_then(|d| d.peer_addr().and_then(|a| a.as_inet()).map(|a| a.ip()));
            if let (Some(peer), Ok(cookie)) = (peer, socket_cookie(fd)) {
                if let Some(seen) = accept(fp, peer) {
                    self.store.put(cookie, seen);
                }
            }
            Ok(())
        }
    }

    fn getsockopt_int(fd: RawFd, level: libc::c_int, name: libc::c_int) -> Option<libc::c_int> {
        let mut v: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `v` and `len` are valid for writes of the sizes given.
        let r = unsafe { libc::getsockopt(fd, level, name, (&mut v as *mut libc::c_int).cast(), &mut len) };
        (r == 0).then_some(v)
    }

    fn socket_cookie(fd: RawFd) -> std::io::Result<u64> {
        let mut v: u64 = 0;
        let mut len = std::mem::size_of::<u64>() as libc::socklen_t;
        // SAFETY: `v` and `len` are valid for writes of the sizes given.
        let r = unsafe {
            libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_COOKIE, (&mut v as *mut u64).cast(), &mut len)
        };
        if r == 0 {
            Ok(v)
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    /// The saved SYN, once; `None` if none was saved.
    fn saved_syn(fd: RawFd) -> Option<Vec<u8>> {
        // An IPv6 header and the largest TCP header are 100 bytes; IPv4 with
        // options at most 120. 512 leaves room.
        let mut buf = vec![0u8; 512];
        let mut len = buf.len() as libc::socklen_t;
        // SAFETY: `buf` is valid for writes of `len` bytes.
        let r = unsafe {
            libc::getsockopt(fd, libc::IPPROTO_TCP, libc::TCP_SAVED_SYN, buf.as_mut_ptr().cast(), &mut len)
        };
        if r != 0 || len == 0 {
            return None;
        }
        buf.truncate(len as usize);
        Some(buf)
    }

    /// The local TCP port of `fd`, if it is an IPv4 or IPv6 socket.
    fn local_port(fd: RawFd) -> Option<u16> {
        // SAFETY: a zeroed sockaddr_storage is a valid value; getsockname
        // writes at most `len` bytes into it.
        let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        let r = unsafe { libc::getsockname(fd, (&mut ss as *mut libc::sockaddr_storage).cast(), &mut len) };
        if r != 0 {
            return None;
        }
        match libc::c_int::from(ss.ss_family) {
            libc::AF_INET => {
                // SAFETY: the family says the storage holds a sockaddr_in.
                let sin: &libc::sockaddr_in = unsafe { &*(&ss as *const libc::sockaddr_storage).cast() };
                Some(u16::from_be(sin.sin_port))
            }
            libc::AF_INET6 => {
                // SAFETY: the family says the storage holds a sockaddr_in6.
                let sin6: &libc::sockaddr_in6 = unsafe { &*(&ss as *const libc::sockaddr_storage).cast() };
                Some(u16::from_be(sin6.sin6_port))
            }
            _ => None,
        }
    }

    /// Sets `TCP_SAVE_SYN` on every listening TCP socket of this process
    /// bound to `port`. Returns how many it set.
    fn save_syn_on_listeners(port: u16) -> usize {
        let Ok(dir) = std::fs::read_dir("/proc/self/fd") else { return 0 };
        let mut n = 0;
        for entry in dir.flatten() {
            let Some(fd) = entry.file_name().to_str().and_then(|s| s.parse::<RawFd>().ok()) else {
                continue;
            };
            if getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_ACCEPTCONN) != Some(1)
                || getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_TYPE) != Some(libc::SOCK_STREAM)
                || local_port(fd) != Some(port)
            {
                continue;
            }
            let one: libc::c_int = 1;
            // SAFETY: `one` is a valid c_int for the size given.
            let r = unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_TCP,
                    libc::TCP_SAVE_SYN,
                    (&one as *const libc::c_int).cast(),
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            if r == 0 {
                n += 1;
            }
        }
        n
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};

        /// The whole path on a real socket: the option set after bind, a
        /// connection, its SYN read once and parsed.
        #[test]
        fn saves_and_reads_a_real_syn() {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = l.local_addr().unwrap().port();
            assert!(save_syn_on_listeners(port) >= 1);
            let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
            let (mut s, peer) = l.accept().unwrap();
            let bytes = saved_syn(s.as_raw_fd()).expect("a SYN was saved");
            let fp = veritell_fp::syn::parse(&bytes).expect("it parses");
            assert!(fp.signature.starts_with("4:64:0:"), "{}", fp.signature);
            assert_eq!(fp.ttl, 64, "loopback: no hop");
            assert_eq!(fp.src, peer.ip());
            assert!(saved_syn(s.as_raw_fd()).is_none(), "given back once only");
            assert!(accept(fp, peer.ip()).is_none(), "loopback is not a client's SYN");
            assert_ne!(socket_cookie(s.as_raw_fd()).unwrap(), 0);
            c.write_all(b"x").unwrap();
            let mut b = [0u8; 1];
            s.read_exact(&mut b).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veritell_fp::syn::SynFp;

    fn fp(src: &str) -> SynFp {
        SynFp { signature: "4:64:0:1460:64240,7:mss:df".into(), ttl: 52, src: src.parse().unwrap() }
    }

    #[test]
    fn keeps_only_a_public_peers_own_syn() {
        let kept = accept(fp("203.0.113.9"), "203.0.113.9".parse().unwrap()).unwrap();
        assert_eq!(kept, SynSeen { signature: "4:64:0:1460:64240,7:mss:df".into(), ttl: 52 });
        assert!(accept(fp("203.0.113.9"), "::ffff:203.0.113.9".parse().unwrap()).is_some(), "mapped peer");
        assert!(accept(fp("203.0.113.9"), "198.51.100.1".parse().unwrap()).is_none(), "not the peer's");
        for local in ["172.20.0.1", "10.1.2.3", "192.168.1.1", "127.0.0.1", "100.64.0.1", "fd00::1", "fe80::1", "::1"] {
            assert!(accept(fp(local), local.parse().unwrap()).is_none(), "{local}");
        }
        assert!(is_public("2a01:4f8::1".parse().unwrap()));
    }

    #[test]
    fn store_takes_once_and_stays_bounded() {
        let s = SynStore::default();
        let seen = SynSeen { signature: "x".into(), ttl: 1 };
        s.put(7, seen.clone());
        assert_eq!(s.take(7), Some(seen.clone()));
        assert_eq!(s.take(7), None);
        let old = Instant::now();
        for c in 0..CAPACITY as u64 {
            s.put_at(c, seen.clone(), old);
        }
        // Full of fresh entries: the new one is not taken.
        s.put_at(1_000_000, seen.clone(), old + Duration::from_secs(1));
        assert_eq!(s.len(), CAPACITY);
        assert!(s.take(1_000_000).is_none());
        // Once they are older than a minute they are swept.
        s.put_at(1_000_001, seen.clone(), old + MAX_AGE + Duration::from_secs(1));
        assert_eq!(s.len(), 1);
        assert!(s.take(1_000_001).is_some());
    }
}
