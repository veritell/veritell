//! The rules themselves: which URLs and addresses are acceptable, how a
//! directory body is read, and the fetch that applies them in order.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::{
    DirectoryUrl, Ed25519Key, FetchConfig, FetchError, Fetched, Transport, DEFAULT_TTL_SECS,
    MAX_BODY_BYTES, MAX_TTL_SECS, MAX_URL_BYTES, MIN_TTL_SECS,
};

fn url_err(msg: &str) -> FetchError {
    FetchError::Url(msg.to_string())
}

fn dir_err(msg: impl Into<String>) -> FetchError {
    FetchError::Directory(msg.into())
}

/// Parses and checks a directory URL. All failures are `FetchError::Url`.
///
/// Accepted: `https://host[:port][/path][?query]`, at most `MAX_URL_BYTES`
/// bytes, printable ASCII only (0x21..=0x7e: no spaces, no control
/// characters, nothing above 0x7e).
/// - The scheme is `https`, compared without regard to case. Nothing else.
/// - No user information (an `@` before the first `/`, `?` or `#`).
/// - No fragment (`#` anywhere).
/// - The host is not empty. It is lowercased. It is one of: a bracketed IPv6
///   literal (`[2001:db8::1]`, which must parse as an IPv6 address); or text
///   made only of ASCII letters, digits, `-` and `.`, at most 253 bytes, with
///   no empty label (no leading, trailing or doubled `.`). An IPv4 literal is
///   such text.
/// - The port, if given, is 1..=65535 in decimal digits only; `https://h:/`
///   is refused. Absent means 443.
/// - `path_and_query` is everything from the first `/` on; when the URL has
///   no path it is `/`, followed by the query if there is one
///   (`https://h?x=1` gives `/?x=1`).
/// - No backslash anywhere.
pub fn parse_url(text: &str) -> Result<DirectoryUrl, FetchError> {
    if text.len() > MAX_URL_BYTES {
        return Err(url_err("URL too long"));
    }
    if !text.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(url_err("URL has a space, control or non-ASCII character"));
    }
    if text.contains('\\') {
        return Err(url_err("URL has a backslash"));
    }
    if text.contains('#') {
        return Err(url_err("URL has a fragment"));
    }
    let rest = match text.split_at_checked(8) {
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case("https://") => rest,
        _ => return Err(url_err("scheme must be https")),
    };
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at_checked(end).unwrap_or((rest, ""));
    if authority.contains('@') {
        return Err(url_err("user information is not allowed"));
    }
    let path_and_query = if tail.is_empty() {
        "/".to_string()
    } else if tail.starts_with('/') {
        tail.to_string()
    } else {
        format!("/{tail}")
    };

    let (host, port_text): (String, Option<&str>) = if let Some(inner) = authority.strip_prefix('[') {
        let (addr, after) = inner.split_once(']').ok_or_else(|| url_err("unterminated IPv6 literal"))?;
        if addr.parse::<Ipv6Addr>().is_err() {
            return Err(url_err("bracketed host is not an IPv6 address"));
        }
        let port = if after.is_empty() {
            None
        } else {
            Some(after.strip_prefix(':').ok_or_else(|| url_err("unexpected text after IPv6 literal"))?)
        };
        (addr.to_ascii_lowercase(), port)
    } else {
        match authority.split_once(':') {
            Some((h, p)) => (h.to_ascii_lowercase(), Some(p)),
            None => (authority.to_ascii_lowercase(), None),
        }
    };
    if !host.contains(':') {
        if host.is_empty() {
            return Err(url_err("empty host"));
        }
        if host.len() > 253 {
            return Err(url_err("host too long"));
        }
        if !host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.') {
            return Err(url_err("host has a character that is not a letter, digit, '-' or '.'"));
        }
        if host.split('.').any(str::is_empty) {
            return Err(url_err("host has an empty label"));
        }
    }
    let port = match port_text {
        None => 443,
        Some(p) => {
            if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err(url_err("port is not decimal digits"));
            }
            match p.parse::<u16>() {
                Ok(n) if n != 0 => n,
                _ => return Err(url_err("port out of range")),
            }
        }
    };
    Ok(DirectoryUrl { host, port, path_and_query })
}

/// Whether a directory may be fetched from this address. False for anything
/// that is not ordinary public unicast space:
///
/// IPv4: `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`,
/// `169.254.0.0/16` (this covers the cloud metadata address
/// 169.254.169.254), `172.16.0.0/12`, `192.0.0.0/24`, `192.0.2.0/24`,
/// `192.168.0.0/16`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`,
/// `224.0.0.0/4` and `240.0.0.0/4` (which includes 255.255.255.255).
///
/// IPv6: `::`, `::1`, `fc00::/7`, `fe80::/10`, `ff00::/8`, `2001:db8::/32`;
/// an IPv4-mapped address (`::ffff:a.b.c.d`), an IPv4-compatible one
/// (`::a.b.c.d`) and a NAT64 one (`64:ff9b::/96`) are judged by the IPv4
/// address they carry; so is an IPv4-translated one (`::ffff:0:a.b.c.d`).
/// Also refused: 6to4 `2002::/16`, Teredo `2001::/32`, local-use NAT64
/// `64:ff9b:1::/48`, site-local `fec0::/10`, the discard prefix `100::/64`,
/// ORCHID `2001:10::/28` and ORCHIDv2 `2001:20::/28`, the documentation
/// prefix `3fff::/20`, and the IPv4 6to4 relay anycast `192.88.99.0/24`.
pub fn address_allowed(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4_allowed(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4_allowed(v4);
            }
            let [a, b, c, d, e, f, g, h] = v6.segments();
            // IPv4-compatible (::a.b.c.d; also covers :: and ::1).
            if [a, b, c, d, e, f] == [0; 6] {
                return v4_allowed(v4_from(g, h));
            }
            // IPv4-translated (SIIT) ::ffff:0:a.b.c.d.
            if [a, b, c, d] == [0; 4] && e == 0xffff && f == 0 {
                return v4_allowed(v4_from(g, h));
            }
            // NAT64 64:ff9b::/96.
            if a == 0x64 && b == 0xff9b && [c, d, e, f] == [0; 4] {
                return v4_allowed(v4_from(g, h));
            }
            !((a & 0xfe00) == 0xfc00
                || (a & 0xffc0) == 0xfe80
                || (a & 0xffc0) == 0xfec0 // site-local fec0::/10
                || (a & 0xff00) == 0xff00
                || (a == 0x2001 && b == 0x0db8)
                || (a == 0x2001 && b == 0) // Teredo 2001:0::/32
                || (a == 0x2001 && (b & 0xfff0) == 0x10) // ORCHID 2001:10::/28
                || (a == 0x2001 && (b & 0xfff0) == 0x20) // ORCHIDv2 2001:20::/28
                || (a == 0x3fff && (b & 0xf000) == 0) // documentation 3fff::/20
                || a == 0x2002 // 6to4 2002::/16
                || (a == 0x64 && b == 0xff9b && c == 1) // local-use NAT64 64:ff9b:1::/48
                || (a == 0x100 && [b, c, d] == [0; 3])) // discard 100::/64
        }
    }
}

fn v4_from(hi: u16, lo: u16) -> Ipv4Addr {
    let [a, b] = hi.to_be_bytes();
    let [c, d] = lo.to_be_bytes();
    Ipv4Addr::new(a, b, c, d)
}

fn v4_allowed(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || (a == 100 && (b & 0xc0) == 64)
        || a == 127
        || (a == 169 && b == 254)
        || (a == 172 && (b & 0xf0) == 16)
        || (a == 192 && b == 0 && (c == 0 || c == 2))
        || (a == 192 && b == 168)
        || (a == 192 && b == 88 && c == 99)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}

/// How long a response asks to be kept, from its `Cache-Control` value,
/// clamped to `MIN_TTL_SECS..=MAX_TTL_SECS`.
///
/// Directives are separated by commas, names compared without regard to
/// case, surrounding spaces ignored. `no-store` or `no-cache` anywhere gives
/// `MIN_TTL_SECS`. Otherwise the first `max-age=<digits>` decides (a value
/// too large for 64 bits counts as the maximum). No header, no `max-age`, or
/// one that is not all digits: `DEFAULT_TTL_SECS`.
pub fn ttl_from_cache_control(value: Option<&str>) -> u64 {
    let Some(value) = value else {
        return DEFAULT_TTL_SECS;
    };
    let mut max_age: Option<&str> = None;
    for directive in value.split(',') {
        let directive = directive.trim();
        let (name, arg) = match directive.split_once('=') {
            Some((n, a)) => (n.trim(), Some(a.trim())),
            None => (directive, None),
        };
        if name.eq_ignore_ascii_case("no-store") || name.eq_ignore_ascii_case("no-cache") {
            return MIN_TTL_SECS;
        }
        if max_age.is_none() && name.eq_ignore_ascii_case("max-age") {
            max_age = Some(arg.unwrap_or(""));
        }
    }
    match max_age {
        Some(digits) if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) => {
            digits.parse::<u64>().unwrap_or(u64::MAX).clamp(MIN_TTL_SECS, MAX_TTL_SECS)
        }
        _ => DEFAULT_TTL_SECS,
    }
}

/// Reads a directory body. All failures are `FetchError::Directory`.
///
/// The body must be UTF-8 JSON of the form `{"keys":[...]}` with at most
/// `veritell_wba::MAX_KEYS` entries, each an object with a string `kty`.
/// An entry with `"kty":"OKP"` and `"crv":"Ed25519"` is a key this gateway
/// can use and must be well-formed (as `veritell_wba::parse_directory`
/// requires); one bad entry refuses the whole directory. An entry of another
/// type (`RSA`, `EC`, another curve) is skipped: the draft's own examples
/// publish RSA keys beside Ed25519 ones. A directory is refused if it has no
/// usable key or the same key id twice.
pub fn parse_keys(body: &[u8]) -> Result<Vec<Ed25519Key>, FetchError> {
    let text = std::str::from_utf8(body).map_err(|_| dir_err("body is not UTF-8"))?;
    let root: serde_json::Value =
        serde_json::from_str(text).map_err(|e| dir_err(format!("body is not JSON: {e}")))?;
    let entries = root
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| dir_err("expected an object with a \"keys\" array"))?;
    if entries.len() > veritell_wba::MAX_KEYS {
        return Err(dir_err("too many keys"));
    }
    let mut usable: Vec<&serde_json::Value> = Vec::new();
    for entry in entries {
        let obj = entry.as_object().ok_or_else(|| dir_err("a key is not an object"))?;
        let text = |name: &str| obj.get(name).and_then(serde_json::Value::as_str);
        let kty = text("kty").ok_or_else(|| dir_err("a key has no string \"kty\""))?;
        if kty == "OKP" && text("crv") == Some("Ed25519") {
            usable.push(entry);
        }
    }
    if usable.is_empty() {
        return Err(dir_err("no Ed25519 key in the directory"));
    }
    let json = serde_json::to_string(&serde_json::json!({ "keys": usable }))
        .map_err(|e| dir_err(e.to_string()))?;
    let keys = veritell_wba::parse_directory(&json).map_err(|e| dir_err(e.to_string()))?;
    if keys.is_empty() {
        return Err(dir_err("no Ed25519 key in the directory"));
    }
    for (i, key) in keys.iter().enumerate() {
        if keys.iter().skip(i.saturating_add(1)).any(|other| other.keyid == key.keyid) {
            return Err(dir_err("the same key id appears twice"));
        }
    }
    Ok(keys)
}

/// Fetches one directory through `transport`, applying every rule in the
/// crate documentation. In order:
///
/// 1. `transport.resolve(host, port)`. An error or an empty answer is
///    `Resolve`.
/// 2. Every resolved address must satisfy [`address_allowed`] or appear,
///    with the URL's port, in `config.allow`. The first that does neither
///    is reported as `AddressRefused` and nothing is fetched. (For an IP
///    literal the transport returns that address and the same check runs.)
/// 3. `transport.get` is called with each resolved address in turn
///    (skipping any that fails the check), `MAX_BODY_BYTES` and the
///    configured timeout (`DEFAULT_TIMEOUT` when zero). A transport error
///    moves on to the next address; when all fail the last error is
///    `Transport`. Any response, whatever its status, ends the attempts.
/// 4. A status other than 200 is `Status`. The body is not looked at.
/// 5. A body longer than `MAX_BODY_BYTES` is `TooLarge`.
/// 6. [`parse_keys`], then [`ttl_from_cache_control`].
pub fn fetch_with(
    transport: &dyn Transport,
    url: &DirectoryUrl,
    config: &FetchConfig,
) -> Result<Fetched, FetchError> {
    let addrs = transport
        .resolve(&url.host, url.port)
        .map_err(FetchError::Resolve)?;
    if addrs.is_empty() {
        return Err(FetchError::Resolve("no addresses".to_string()));
    }
    for ip in &addrs {
        if !address_allowed(*ip) && !config.allow.contains(&SocketAddr::new(*ip, url.port)) {
            return Err(FetchError::AddressRefused(*ip));
        }
    }
    let timeout = if config.timeout.is_zero() { FetchConfig::DEFAULT_TIMEOUT } else { config.timeout };
    let mut last_error: Option<String> = None;
    let mut answer: Option<crate::Response> = None;
    for ip in &addrs {
        let sa = SocketAddr::new(*ip, url.port);
        // Defence in depth: never connect to an address that fails the check.
        if !address_allowed(*ip) && !config.allow.contains(&sa) {
            continue;
        }
        match transport.get(sa, url, MAX_BODY_BYTES, timeout) {
            Ok(r) => {
                answer = Some(r);
                break;
            }
            Err(e) => last_error = Some(e),
        }
    }
    let response = match answer {
        Some(r) => r,
        None => match last_error {
            Some(e) => return Err(FetchError::Transport(e)),
            None => {
                let ip = addrs.first().copied().ok_or_else(|| FetchError::Resolve("no addresses".to_string()))?;
                return Err(FetchError::AddressRefused(ip));
            }
        },
    };
    if response.status != 200 {
        return Err(FetchError::Status(response.status));
    }
    if response.body.len() > MAX_BODY_BYTES {
        return Err(FetchError::TooLarge);
    }
    let keys = parse_keys(&response.body)?;
    let ttl_secs = ttl_from_cache_control(response.cache_control.as_deref());
    Ok(Fetched { keys, ttl_secs })
}

#[cfg(test)]
mod audit_tests {
    use super::*;

    fn ok(s: &str) -> bool {
        address_allowed(s.parse().unwrap())
    }

    #[test]
    fn six_to_four_is_refused() {
        assert!(!ok("2002::1"));
        assert!(!ok("2002:0808:0808::1"));
        assert!(!ok("2002:7f00:1::1"));
        assert!(ok("2003::1"));
    }

    #[test]
    fn orchid_and_documentation_ranges_are_refused() {
        for a in ["2001:10::1", "2001:1f:ffff::1", "2001:20::1", "2001:2f::1", "3fff::1", "3fff:fff::1"] {
            assert!(!ok(a), "{a}");
        }
        for a in ["2001:30::1", "2001:4860::8888", "3ffe::1", "3fff:1000::1"] {
            assert!(ok(a), "{a}");
        }
    }

    #[test]
    fn teredo_is_refused() {
        assert!(!ok("2001:0:4136:e378:8000:63bf:3fff:fdd2"));
        assert!(ok("2001:1::1"));
    }

    #[test]
    fn ipv4_translated_is_judged_by_the_embedded_address() {
        assert!(!ok("::ffff:0:127.0.0.1"));
        assert!(!ok("::ffff:0:10.0.0.1"));
        assert!(ok("::ffff:0:93.184.216.34"));
    }

    #[test]
    fn local_use_nat64_is_refused() {
        assert!(!ok("64:ff9b:1::1"));
        assert!(!ok("64:ff9b:1:ffff::1"));
        assert!(ok("64:ff9b::5db8:d822"));
        assert!(ok("64:ff9a::1"));
    }

    #[test]
    fn site_local_is_refused() {
        assert!(!ok("fec0::1"));
        assert!(!ok("feff::1"));
        assert!(ok("2600::1"));
    }

    #[test]
    fn discard_prefix_is_refused() {
        assert!(!ok("100::1"));
        assert!(!ok("100::ffff:ffff:ffff:ffff"));
        assert!(ok("100:0:0:1::1"));
    }

    #[test]
    fn six_to_four_relay_anycast_is_refused() {
        assert!(!ok("192.88.99.1"));
        assert!(!ok("192.88.99.255"));
        assert!(!ok("::ffff:192.88.99.1"));
        assert!(ok("192.88.98.1"));
        assert!(ok("192.88.100.1"));
    }
}
