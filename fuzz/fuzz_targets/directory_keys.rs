#![no_main]
// What a remote key directory sends back, and the values the fetcher reads
// from it: the body (a JWKS), the URL it is listed under, Cache-Control,
// and the address it resolved to. The first byte picks which.
//
// Properties checked, beyond "does not panic":
// - Address: `address_allowed` agrees with a second implementation built
//   from the documented prefix list, and refuses everything the standard
//   library calls loopback, private, link-local, multicast, unspecified,
//   broadcast, documentation or unique-local.
// - URL: an accepted URL prints back to itself; a WHATWG parser reads the
//   same port and scheme; nothing that could change the request's target
//   (`@` in the host, `#`, `\`, whitespace) is in it.
// - Cache-Control: the TTL agrees with a second implementation.
// - Keys: every key's id is its thumbprint, ids are unique, there are 1 to
//   64; the Web Bot Auth directory parser reads the same keys.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use veritell_directory::{
    address_allowed, parse_keys, parse_url, ttl_from_cache_control, DEFAULT_TTL_SECS, MAX_TTL_SECS, MIN_TTL_SECS,
};

/// Refused IPv4 prefixes, as documented on `address_allowed`.
const V4_DENY: &[(u32, u32)] = &[
    (0x0000_0000, 8),  // 0.0.0.0/8
    (0x0a00_0000, 8),  // 10/8
    (0x6440_0000, 10), // 100.64/10
    (0x7f00_0000, 8),  // 127/8
    (0xa9fe_0000, 16), // 169.254/16
    (0xac10_0000, 12), // 172.16/12
    (0xc000_0000, 24), // 192.0.0/24
    (0xc000_0200, 24), // 192.0.2/24
    (0xc058_6300, 24), // 192.88.99/24
    (0xc0a8_0000, 16), // 192.168/16
    (0xc612_0000, 15), // 198.18/15
    (0xc633_6400, 24), // 198.51.100/24
    (0xcb00_7100, 24), // 203.0.113/24
    (0xe000_0000, 4),  // 224/4
    (0xf000_0000, 4),  // 240/4
];

/// Refused IPv6 prefixes, other than those that carry an IPv4 address.
const V6_DENY: &[(u128, u32)] = &[
    (0xfc00 << 112, 7),                          // unique local
    (0xfe80 << 112, 10),                         // link-local
    (0xfec0 << 112, 10),                         // site-local
    (0xff00 << 112, 8),                          // multicast
    (0x2001_0db8 << 96, 32),                     // documentation
    (0x2001_0000 << 96, 32),                     // Teredo
    (0x2001_0010 << 96, 28),                     // ORCHID
    (0x2001_0020 << 96, 28),                     // ORCHIDv2
    (0x3fff << 112, 20),                         // documentation
    (0x2002 << 112, 16),                         // 6to4
    ((0x0064_ff9b_0001u128) << 80, 48),          // local-use NAT64
    (0x0100 << 112, 64),                         // discard
];

/// IPv6 prefixes whose last 32 bits are an IPv4 address judged as such.
const V6_CARRIES_V4: &[(u128, u32)] = &[
    (0, 96),                          // IPv4-compatible, and :: and ::1
    (0xffff << 32, 96),               // IPv4-mapped
    (0xffff << 48, 96),               // IPv4-translated
    ((0x0064_ff9b_u128) << 96, 96),   // NAT64
];

fn in_prefix(addr: u128, net: u128, bits: u32, width: u32) -> bool {
    let shift = width - bits;
    (addr >> shift) == (net >> shift)
}

fn reference(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let a = u32::from(v4);
            !V4_DENY.iter().any(|&(n, b)| in_prefix(u128::from(a), u128::from(n), b, 32))
        }
        IpAddr::V6(v6) => {
            let a = u128::from(v6);
            if V6_CARRIES_V4.iter().any(|&(n, b)| in_prefix(a, n, b, 128)) {
                return reference(IpAddr::V4(Ipv4Addr::from(a as u32)));
            }
            !V6_DENY.iter().any(|&(n, b)| in_prefix(a, n, b, 128))
        }
    }
}

fn std_says_special(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            a.is_loopback()
                || a.is_private()
                || a.is_link_local()
                || a.is_multicast()
                || a.is_unspecified()
                || a.is_broadcast()
                || a.is_documentation()
        }
        IpAddr::V6(a) => {
            a.is_loopback()
                || a.is_multicast()
                || a.is_unspecified()
                || a.is_unique_local()
                || a.is_unicast_link_local()
                || a.to_ipv4_mapped().is_some_and(|v4| std_says_special(IpAddr::V4(v4)))
        }
    }
}

fn address(ip: IpAddr) {
    let got = address_allowed(ip);
    assert_eq!(got, reference(ip), "address_allowed({ip}) disagrees with the documented list");
    if std_says_special(ip) {
        assert!(!got, "address_allowed({ip}) allows an address the standard library calls special");
    }
}

fn url(text: &str) {
    let Ok(u) = parse_url(text) else { return };
    let again = parse_url(&u.as_string()).expect("printed URL does not parse");
    assert_eq!(again, u, "URL does not print back to itself");
    // `@` is fine in a path; in the host it would hide another host.
    assert!(!u.host.contains(['@', '#', '\\', '/', '?']), "accepted host {:?}", u.host);
    assert!(!u.path_and_query.contains(['#', '\\', ' ', '\t', '\r', '\n']), "accepted path {:?}", u.path_and_query);
    assert!(u.port != 0 && !u.host.is_empty() && u.path_and_query.starts_with('/'));
    if let Ok(w) = url::Url::parse(text) {
        assert_eq!(w.scheme(), "https");
        assert_eq!(w.port_or_known_default(), Some(u.port), "WHATWG reads another port in {text:?}");
        assert!(w.username().is_empty() && w.password().is_none(), "WHATWG sees user information in {text:?}");
    }
}

fn ttl_reference(value: &str) -> u64 {
    let mut max_age = None;
    for d in value.split(',') {
        let (name, arg) = match d.find('=') {
            Some(i) => (d[..i].trim(), Some(d[i + 1..].trim())),
            None => (d.trim(), None),
        };
        let name = name.to_ascii_lowercase();
        if name == "no-store" || name == "no-cache" {
            return MIN_TTL_SECS;
        }
        if name == "max-age" && max_age.is_none() {
            max_age = Some(arg.unwrap_or(""));
        }
    }
    match max_age {
        Some(v) if !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) => {
            let n = v.trim_start_matches('0');
            let secs = if n.len() > 20 { u64::MAX } else { n.parse::<u128>().unwrap_or(0).min(u128::from(u64::MAX)) as u64 };
            secs.clamp(MIN_TTL_SECS, MAX_TTL_SECS)
        }
        _ => DEFAULT_TTL_SECS,
    }
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some((&pick, rest)) = data.split_first() else { return };
    let text = std::str::from_utf8(rest).unwrap_or("");
    match pick % 4 {
        0 => {
            if let Ok(keys) = parse_keys(rest) {
                assert!((1..=64).contains(&keys.len()), "{} keys accepted", keys.len());
                for (i, k) in keys.iter().enumerate() {
                    assert_eq!(k.keyid, veritell_wba::jwk_thumbprint_ed25519(&k.public));
                    assert!(keys[..i].iter().all(|o| o.keyid != k.keyid), "duplicate key id accepted");
                }
                let wba = veritell_wba::parse_directory(text).expect("WBA parser refuses a directory the fetcher accepts");
                assert_eq!(wba, keys, "the two directory parsers read different keys");
            }
        }
        1 => url(text),
        2 => {
            assert_eq!(ttl_from_cache_control(Some(text)), ttl_reference(text), "TTL for {text:?}");
        }
        _ => {
            let ip: Option<IpAddr> = match rest.len() {
                4 => Some(IpAddr::from(<[u8; 4]>::try_from(rest).unwrap())),
                16 => Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(rest).unwrap()))),
                _ => text.parse().ok(),
            };
            if let Some(ip) = ip {
                address(ip);
            }
        }
    }
});
