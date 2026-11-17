#![no_main]
// Fetching a key directory, with the network replaced: `fetch_with` over a
// transport whose DNS answers and responses come from the input, and the
// `Cache` that keeps what was fetched. The directory's owner controls both
// its DNS and its server, so both are hostile. The first byte picks the
// mode: even fetches, odd drives a cache.
//
// Fetch input, after the first byte: a flags byte (bit 0 the lookup fails,
// bits 1 to 3 the number of addresses, bit 4 a zero timeout, bit 5 port
// 8443 instead of 443, bit 6 a body one byte over `MAX_BODY_BYTES`), then
// per address a tag byte and 4 or 16 address bytes (tag bit 0 IPv6, bit 1
// on the allow list with the URL's port, bit 2 on it with another port,
// bit 3 the transport answers from it rather than failing), then the
// status (2 bytes), a byte whose bit 0 says a `Cache-Control` value
// follows up to the next 0xFF, and the body.
//
// Cache input, after the first byte: operations, a tag byte and its
// argument:
//
//   0 k t   a fetch succeeds with the first k % 4 keys and lifetime t
//           (t % 4 picks MIN_TTL_SECS, DEFAULT_TTL_SECS, MAX_TTL_SECS or
//           the largest u64, to reach the saturating sums)
//   1       a fetch fails
//   2 d     the clock moves: below 0x80 forward d hours, below 0xFF back
//           d - 0x80 minutes, 0xFF to the largest u64
//
// Properties checked, beyond "does not panic":
// - The address rule (gate G11), whatever the model says: the transport
//   is only ever asked to connect to an address `address_allowed` accepts
//   or the operator listed with that port, and never at all when any
//   resolved address is refused; every call carries the URL, the URL's
//   port, `MAX_BODY_BYTES` and the configured timeout (`DEFAULT_TIMEOUT`
//   for zero).
// - Every result, and the list of addresses tried, equals what the
//   documented order of rules in `fetch_with` gives; an accepted directory
//   is `parse_keys` of the body with `ttl_from_cache_control` of its header.
// - Every error has a message.
// - The cache's `due` and `keys` equal a model of its documented rules
//   after every operation, and keys are only ever ones a success brought.
use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use veritell_directory::{
    address_allowed, fetch_with, parse_keys, ttl_from_cache_control, Cache, DirectoryUrl,
    Ed25519Key, FetchConfig, FetchError, Fetched, Response, Transport, DEFAULT_TTL_SECS,
    MAX_BODY_BYTES, MAX_STALE_SECS, MAX_TTL_SECS, MIN_TTL_SECS, RETRY_SECS,
};

struct Fake {
    lookup: Result<Vec<IpAddr>, String>,
    /// Per resolved address, in order: whether it answers.
    answers: Vec<bool>,
    response: Response,
    calls: RefCell<Vec<(SocketAddr, DirectoryUrl, usize, Duration)>>,
}

impl Transport for Fake {
    fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>, String> {
        self.lookup.clone()
    }

    fn get(
        &self,
        addr: SocketAddr,
        url: &DirectoryUrl,
        max_bytes: usize,
        timeout: Duration,
    ) -> Result<Response, String> {
        self.calls
            .borrow_mut()
            .push((addr, url.clone(), max_bytes, timeout));
        let ips = self.lookup.as_deref().unwrap_or_default();
        // The first resolved address equal to this one decides.
        match ips.iter().position(|ip| *ip == addr.ip()) {
            Some(i) if self.answers[i] => Ok(self.response.clone()),
            Some(i) => Err(format!("connection to address {i} failed")),
            None => Err("not a resolved address".into()),
        }
    }
}

fn fetch(data: &[u8]) {
    let Some((&flags, mut rest)) = data.split_first() else {
        return;
    };
    let port = if flags & 0x20 != 0 { 8443 } else { 443 };
    let url = DirectoryUrl {
        host: "agent.example".into(),
        port,
        path_and_query: "/.well-known/http-message-signatures-directory".into(),
    };
    let mut config = FetchConfig {
        allow: Vec::new(),
        timeout: Duration::from_secs(2),
    };
    if flags & 0x10 != 0 {
        config.timeout = Duration::ZERO;
    }
    let (mut ips, mut answers) = (Vec::new(), Vec::new());
    for _ in 0..(flags >> 1 & 7) {
        let Some((&tag, tail)) = rest.split_first() else {
            return;
        };
        let n = if tag & 1 == 1 { 16 } else { 4 };
        if tail.len() < n {
            return;
        }
        let ip = match n {
            16 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&tail[..16]).unwrap())),
            _ => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&tail[..4]).unwrap())),
        };
        rest = &tail[n..];
        if tag & 2 != 0 {
            config.allow.push(SocketAddr::new(ip, port));
        }
        if tag & 4 != 0 {
            config.allow.push(SocketAddr::new(ip, port ^ 1));
        }
        ips.push(ip);
        answers.push(tag & 8 != 0);
    }
    let [s0, s1, cc_flag, rest @ ..] = rest else {
        return;
    };
    let (cache_control, mut body) = if cc_flag & 1 == 1 {
        let end = rest.iter().position(|&b| b == 0xFF).unwrap_or(rest.len());
        (
            Some(String::from_utf8_lossy(&rest[..end]).into_owned()),
            rest.get(end + 1..).unwrap_or_default().to_vec(),
        )
    } else {
        (None, rest.to_vec())
    };
    if flags & 0x40 != 0 {
        body.resize(MAX_BODY_BYTES + 1, b' ');
    }
    let response = Response {
        status: u16::from_be_bytes([*s0, *s1]),
        cache_control,
        body,
    };
    let lookup = if flags & 1 == 1 {
        Err("lookup failed".to_string())
    } else {
        Ok(ips.clone())
    };
    let fake = Fake {
        lookup,
        answers: answers.clone(),
        response: response.clone(),
        calls: RefCell::new(Vec::new()),
    };

    let got = fetch_with(&fake, &url, &config);
    let calls = fake.calls.into_inner();

    // The address rule, independent of the model.
    let permitted = |sa: &SocketAddr| address_allowed(sa.ip()) || config.allow.contains(sa);
    let timeout = if config.timeout.is_zero() {
        FetchConfig::DEFAULT_TIMEOUT
    } else {
        config.timeout
    };
    for (sa, u, max, t) in &calls {
        assert!(
            permitted(sa),
            "connected to {sa}, which is refused and not allowed"
        );
        assert_eq!(
            (u, sa.port(), *max, *t),
            (&url, port, MAX_BODY_BYTES, timeout),
            "call to {sa}"
        );
    }
    let refused = ips
        .iter()
        .copied()
        .find(|ip| !permitted(&SocketAddr::new(*ip, port)));
    if refused.is_some() {
        assert!(
            calls.is_empty(),
            "connected although {refused:?} was refused"
        );
    }

    // The documented order of rules.
    let mut tried = Vec::new();
    let want: Result<Fetched, FetchError> = (|| {
        if flags & 1 == 1 {
            return Err(FetchError::Resolve("lookup failed".into()));
        }
        if ips.is_empty() {
            return Err(FetchError::Resolve("no addresses".into()));
        }
        if let Some(ip) = refused {
            return Err(FetchError::AddressRefused(ip));
        }
        let mut answered = false;
        for ip in &ips {
            tried.push(SocketAddr::new(*ip, port));
            if answers[ips.iter().position(|x| x == ip).unwrap()] {
                answered = true;
                break;
            }
        }
        if !answered {
            let last = ips.iter().position(|x| x == ips.last().unwrap()).unwrap();
            return Err(FetchError::Transport(format!(
                "connection to address {last} failed"
            )));
        }
        if response.status != 200 {
            return Err(FetchError::Status(response.status));
        }
        if response.body.len() > MAX_BODY_BYTES {
            return Err(FetchError::TooLarge);
        }
        let keys = parse_keys(&response.body)?;
        Ok(Fetched {
            keys,
            ttl_secs: ttl_from_cache_control(response.cache_control.as_deref()),
        })
    })();
    match (&got, &want) {
        // The wording of a lookup failure is the implementation's.
        (Err(FetchError::Resolve(_)), Err(FetchError::Resolve(_))) => {}
        _ => assert_eq!(got, want, "fetch_with disagrees with its rules"),
    }
    let called: Vec<SocketAddr> = calls.iter().map(|c| c.0).collect();
    assert_eq!(called, tried, "addresses tried");
    if let Err(e) = got {
        assert!(!e.to_string().is_empty(), "empty error message");
    }
}

/// `Cache` as documented.
#[derive(Default)]
struct Model {
    keys: Vec<Ed25519Key>,
    success: Option<(u64, u64)>,
    last: u64,
    next: Option<u64>,
}

impl Model {
    fn due(&self, now: u64) -> bool {
        self.next.is_none_or(|n| now.max(self.last) >= n)
    }

    fn keys(&self, now: u64) -> &[Ed25519Key] {
        match self.success {
            Some((at, ttl))
                if now.max(self.last) <= at.saturating_add(ttl).saturating_add(MAX_STALE_SECS) =>
            {
                &self.keys
            }
            _ => &[],
        }
    }
}

fn cache(mut ops: &[u8]) {
    let all: Vec<Ed25519Key> = (1..=3u8)
        .map(|i| Ed25519Key::from_public([i; 32]))
        .collect();
    let (mut c, mut m) = (Cache::new(), Model::default());
    let mut now: u64 = 1_800_000_000;
    let mut brought: Vec<Vec<Ed25519Key>> = vec![Vec::new()];
    while let Some((&tag, tail)) = ops.split_first() {
        ops = tail;
        match tag % 3 {
            0 => {
                let [k, t, tail @ ..] = ops else { return };
                ops = tail;
                let keys = all[..usize::from(k % 4)].to_vec();
                let ttl =
                    [MIN_TTL_SECS, DEFAULT_TTL_SECS, MAX_TTL_SECS, u64::MAX][usize::from(t % 4)];
                c.on_success(
                    Fetched {
                        keys: keys.clone(),
                        ttl_secs: ttl,
                    },
                    now,
                );
                let at = now.max(m.last);
                m = Model {
                    keys: keys.clone(),
                    success: Some((at, ttl)),
                    last: at,
                    next: Some(at.saturating_add(ttl)),
                };
                brought.push(keys);
            }
            1 => {
                c.on_failure(now);
                m.last = now.max(m.last);
                m.next = Some(m.last.saturating_add(RETRY_SECS));
            }
            _ => {
                let [d, tail @ ..] = ops else { return };
                ops = tail;
                now = match *d {
                    0xFF => u64::MAX,
                    d if d < 0x80 => now.saturating_add(u64::from(d) * 3600),
                    d => now.saturating_sub(u64::from(d - 0x80) * 60),
                };
            }
        }
        for t in [now, now.saturating_sub(1), now.saturating_add(1)] {
            assert_eq!(
                c.due(t),
                m.due(t),
                "due({t}) differs from the documented rules"
            );
            assert_eq!(
                c.keys(t),
                m.keys(t),
                "keys({t}) differ from the documented rules"
            );
            assert!(
                brought.iter().any(|b| b.as_slice() == c.keys(t)),
                "keys no success brought"
            );
        }
    }
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some((&pick, rest)) = data.split_first() else {
        return;
    };
    if pick & 1 == 0 {
        fetch(rest);
    } else {
        cache(rest);
    }
});
