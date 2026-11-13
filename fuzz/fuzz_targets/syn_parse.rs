#![no_main]
// The client's TCP SYN, as Linux saves it (TCP_SAVE_SYN): IP and TCP headers.
//
// Properties checked, beyond "does not panic": the signature has p0f's seven
// fields; its version, TTL and source address are the header's; and the
// timestamp option's clock value, which could identify a machine, never
// appears in it.
use std::net::IpAddr;

/// The TCP timestamp option's TSval, found by walking the options here
/// rather than with the parser under test.
fn tsval(data: &[u8]) -> Option<u32> {
    let ip_len = match data.first()? >> 4 {
        4 => usize::from(data[0] & 0x0f) * 4,
        _ => 40,
    };
    let tcp = data.get(ip_len..)?;
    let doff = usize::from(tcp.get(12)? >> 4) * 4;
    let opts = tcp.get(20..doff)?;
    let mut i = 0;
    while i < opts.len() {
        match opts[i] {
            0 => return None,
            1 => i += 1,
            kind => {
                let len = usize::from(*opts.get(i + 1)?);
                if len < 2 {
                    return None;
                }
                if kind == 8 && len == 10 {
                    return Some(u32::from_be_bytes(opts.get(i + 2..i + 6)?.try_into().ok()?));
                }
                i += len;
            }
        }
    }
    None
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some(fp) = veritell_fp::syn::parse(data) else { return };
    let fields: Vec<&str> = fp.signature.split(':').collect();
    assert_eq!(fields.len(), 7, "signature {:?} does not have 7 fields", fp.signature);
    let version = data[0] >> 4;
    assert_eq!(fields[0], version.to_string());
    assert_eq!(fields[1], veritell_fp::syn::initial_ttl(fp.ttl).to_string());
    let (ttl, src) = if version == 4 {
        (data[8], IpAddr::from(<[u8; 4]>::try_from(&data[12..16]).unwrap()))
    } else {
        (data[7], IpAddr::from(<[u8; 16]>::try_from(&data[8..24]).unwrap()))
    };
    assert_eq!((fp.ttl, fp.src), (ttl, src));
    assert!(fp.signature.bytes().all(|b| b.is_ascii_graphic()), "signature {:?} is not plain text", fp.signature);
    if let Some(ts) = tsval(data).filter(|&t| t >= 100_000) {
        assert!(!fp.signature.contains(&ts.to_string()), "timestamp clock {ts} kept in {:?}", fp.signature);
    }
});
