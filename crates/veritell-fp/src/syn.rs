//! The client's TCP SYN, as Linux saves it for a listener with
//! `TCP_SAVE_SYN` set: the IP header and the TCP header with its options, no
//! payload and no link layer. Measured only: the result is
//! logged and stored, and nothing scores on it.
//!
//! The signature follows p0f's layout, so values can be compared with its
//! database by eye:
//!
//! ```text
//! ver:ittl:olen:mss:wsize,scale:olayout:quirks
//! ```
//!
//! `ver` is 4 or 6; `ittl` the initial TTL the observed one most likely
//! started from (32, 64, 128 or 255); `olen` the length of IPv4 options (0
//! for IPv6); `mss` the MSS option or `*`; `wsize` the window as sent; `scale`
//! the window scale or `*`; `olayout` the TCP options in order; `quirks` the
//! oddities in the headers, and `data+` for a SYN that carries data (TCP
//! Fast Open). The observed TTL is kept apart, in [`SynFp::ttl`]:
//! it depends on the path, the signature should not.
//!
//! Option values that could identify a machine beyond its stack, such as the
//! timestamp clock, are reduced to quirks and never kept.

use std::net::IpAddr;

/// What one SYN shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SynFp {
    /// See the module documentation.
    pub signature: String,
    /// The TTL or hop limit as it arrived.
    pub ttl: u8,
    /// The SYN's source address, for checking it against the peer. Not to
    /// be stored: the caller drops it after the check.
    pub src: IpAddr,
}

/// The initial TTL that `ttl` most likely started from.
pub fn initial_ttl(ttl: u8) -> u8 {
    match ttl {
        0..=32 => 32,
        33..=64 => 64,
        65..=128 => 128,
        _ => 255,
    }
}

/// Parses a saved SYN. `None` when the bytes are not an IPv4 or IPv6 packet
/// carrying a TCP segment with SYN set and ACK clear, or are cut short. An
/// IPv6 packet with extension headers before TCP is also refused: clients do
/// not send them on a SYN, and following them is more parser than this is
/// worth.
pub fn parse(bytes: &[u8]) -> Option<SynFp> {
    let version = bytes.first()? >> 4;
    let mut quirks: Vec<&str> = Vec::new();
    let (ttl, src, olen, tcp) = match version {
        4 => {
            let ihl = usize::from(bytes[0] & 0x0f) * 4;
            if ihl < 20 || bytes.len() < ihl {
                return None;
            }
            if bytes[9] != 6 {
                return None;
            }
            let total = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
            if total < ihl {
                return None;
            }
            let flags = bytes[6] >> 5;
            let df = flags & 0b010 != 0;
            let id = u16::from_be_bytes([bytes[4], bytes[5]]);
            if df {
                quirks.push("df");
                if id != 0 {
                    quirks.push("id+");
                }
            } else if id == 0 {
                quirks.push("id-");
            }
            if flags & 0b100 != 0 {
                quirks.push("0+");
            }
            if bytes[1] & 0x03 != 0 {
                quirks.push("ecn");
            }
            let src = IpAddr::from([bytes[12], bytes[13], bytes[14], bytes[15]]);
            // A SYN with data (TCP Fast Open) is longer than what was saved:
            // only the headers are kept. Parse what is there.
            (bytes[8], src, ihl - 20, (&bytes[ihl..total.min(bytes.len())], total - ihl))
        }
        6 => {
            if bytes.len() < 40 || bytes[6] != 6 {
                return None;
            }
            let payload = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
            let flow = u32::from_be_bytes([0, bytes[1] & 0x0f, bytes[2], bytes[3]]);
            if flow != 0 {
                quirks.push("flow");
            }
            let traffic_class = (bytes[0] & 0x0f) << 4 | bytes[1] >> 4;
            if traffic_class & 0x03 != 0 {
                quirks.push("ecn");
            }
            let mut a = [0u8; 16];
            a.copy_from_slice(&bytes[8..24]);
            (bytes[7], IpAddr::from(a), 0, (&bytes[40..(40 + payload).min(bytes.len())], payload))
        }
        _ => return None,
    };
    let (tcp, segment) = tcp;
    let tcp_fields = tcp_signature(tcp, segment, &mut quirks)?;
    let quirk_text = quirks.join(",");
    Some(SynFp {
        signature: format!(
            "{version}:{}:{olen}:{}:{}",
            initial_ttl(ttl),
            tcp_fields,
            quirk_text
        ),
        ttl,
        src,
    })
}

/// `mss:wsize,scale:olayout`, adding the TCP quirks to `quirks`. `tcp` is
/// the header as saved; `segment` the TCP length the IP header declares,
/// header and data.
fn tcp_signature(tcp: &[u8], segment: usize, quirks: &mut Vec<&'static str>) -> Option<String> {
    if tcp.len() < 20 {
        return None;
    }
    let doff = usize::from(tcp[12] >> 4) * 4;
    if doff < 20 || doff > tcp.len() {
        return None;
    }
    let flags = tcp[13];
    let (fin, syn, rst, psh, ack, urg, ece, cwr) = (
        flags & 0x01 != 0,
        flags & 0x02 != 0,
        flags & 0x04 != 0,
        flags & 0x08 != 0,
        flags & 0x10 != 0,
        flags & 0x20 != 0,
        flags & 0x40 != 0,
        flags & 0x80 != 0,
    );
    if !syn || ack || rst || fin {
        return None;
    }
    // One `ecn` quirk, whether the IP header, the TCP flags or both show it.
    if (ece || cwr || tcp[12] & 0x01 != 0) && !quirks.contains(&"ecn") {
        quirks.push("ecn");
    }
    if segment > doff {
        quirks.push("data+");
    }
    if u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]) == 0 {
        quirks.push("seq-");
    }
    if u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]) != 0 {
        quirks.push("ack+");
    }
    if u16::from_be_bytes([tcp[18], tcp[19]]) != 0 && !urg {
        quirks.push("uptr+");
    }
    if urg {
        quirks.push("urgf+");
    }
    if psh {
        quirks.push("pushf+");
    }
    let window = u16::from_be_bytes([tcp[14], tcp[15]]);

    let opts = &tcp[20..doff];
    let mut layout: Vec<String> = Vec::new();
    let mut mss: Option<u16> = None;
    let mut scale: Option<u8> = None;
    let mut i = 0;
    while i < opts.len() {
        match opts[i] {
            0 => {
                // End of options: what follows is padding. p0f writes the
                // number of padding bytes, and notes any that are not zero.
                let rest = &opts[i + 1..];
                layout.push(format!("eol+{}", rest.len()));
                if rest.iter().any(|&b| b != 0) {
                    quirks.push("opt+");
                }
                break;
            }
            1 => {
                layout.push("nop".into());
                i += 1;
            }
            kind => {
                let Some(&len) = opts.get(i + 1) else {
                    quirks.push("bad");
                    break;
                };
                let len = usize::from(len);
                if len < 2 || i + len > opts.len() {
                    quirks.push("bad");
                    break;
                }
                let body = &opts[i + 2..i + len];
                match (kind, len) {
                    (2, 4) => {
                        mss = Some(u16::from_be_bytes([body[0], body[1]]));
                        layout.push("mss".into());
                    }
                    (3, 3) => {
                        scale = Some(body[0]);
                        if body[0] > 14 {
                            quirks.push("exws");
                        }
                        layout.push("ws".into());
                    }
                    (4, 2) => layout.push("sok".into()),
                    (5, _) => layout.push("sack".into()),
                    (8, 10) => {
                        if body[0..4] == [0, 0, 0, 0] {
                            quirks.push("ts1-");
                        }
                        if body[4..8] != [0, 0, 0, 0] {
                            quirks.push("ts2+");
                        }
                        layout.push("ts".into());
                    }
                    (2 | 3 | 4 | 8, _) => {
                        // A known option with the wrong length.
                        quirks.push("bad");
                        layout.push(format!("?{kind}"));
                    }
                    _ => layout.push(format!("?{kind}")),
                }
                i += len;
            }
        }
    }
    let mss = mss.map_or_else(|| "*".to_string(), |m| m.to_string());
    let scale = scale.map_or_else(|| "*".to_string(), |s| s.to_string());
    Some(format!("{mss}:{window},{scale}:{}", layout.join(",")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// IPv4 header (20 bytes, no options) followed by `tcp`.
    fn v4(ttl: u8, df: bool, id: u16, tcp: &[u8]) -> Vec<u8> {
        let total = (20 + tcp.len()) as u16;
        let mut p = vec![0x45, 0x00];
        p.extend_from_slice(&total.to_be_bytes());
        p.extend_from_slice(&id.to_be_bytes());
        p.extend_from_slice(&[if df { 0x40 } else { 0 }, 0, ttl, 6, 0, 0]);
        p.extend_from_slice(&[203, 0, 113, 9, 198, 51, 100, 1]);
        p.extend_from_slice(tcp);
        p
    }

    /// TCP header with SYN set, the given window and options (padded to 4).
    fn tcp(window: u16, opts: &[u8]) -> Vec<u8> {
        let mut o = opts.to_vec();
        while !o.len().is_multiple_of(4) {
            o.push(0);
        }
        let doff = ((20 + o.len()) / 4) as u8;
        let mut t = vec![0xc3, 0x50, 0x01, 0xbb, 0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0];
        t.push(doff << 4);
        t.push(0x02);
        t.extend_from_slice(&window.to_be_bytes());
        t.extend_from_slice(&[0, 0, 0, 0]);
        t.extend_from_slice(&o);
        t
    }

    // MSS 1460, SACK permitted, timestamps (own clock non-zero, echo zero),
    // NOP, window scale 7: what Linux sends.
    const LINUX_OPTS: [u8; 20] = [
        2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0, 1, 2, 3, 0, 0, 0, 0, 1, 3, 3, 7,
    ];

    #[test]
    fn linux_syn() {
        let p = v4(57, true, 0x1c46, &tcp(64240, &LINUX_OPTS));
        let fp = parse(&p).unwrap();
        assert_eq!(fp.signature, "4:64:0:1460:64240,7:mss,sok,ts,nop,ws:df,id+");
        assert_eq!(fp.ttl, 57);
        assert_eq!(fp.src, "203.0.113.9".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn windows_syn_with_eol_padding() {
        // MSS, NOP, WS 8, NOP, NOP, SOK; then padded with EOL to a multiple
        // of four.
        let opts = [2, 4, 0x05, 0xb4, 1, 3, 3, 8, 1, 1, 4, 2];
        let p = v4(113, true, 0x7a01, &tcp(64240, &opts));
        assert_eq!(
            parse(&p).unwrap().signature,
            "4:128:0:1460:64240,8:mss,nop,ws,nop,nop,sok:df,id+"
        );
        let opts = [2, 4, 0x05, 0xb4, 1, 3, 3, 8, 0];
        let p = v4(113, true, 1, &tcp(64240, &opts));
        assert_eq!(parse(&p).unwrap().signature, "4:128:0:1460:64240,8:mss,nop,ws,eol+3:df,id+");
    }

    #[test]
    fn ipv6_syn() {
        let t = tcp(65535, &[2, 4, 0x05, 0xa0, 1, 3, 3, 6, 1, 1, 8, 10, 0, 0, 0, 9, 0, 0, 0, 0, 4, 2, 0, 0]);
        let mut p = vec![0x60, 0x0a, 0xbc, 0xde];
        p.extend_from_slice(&(t.len() as u16).to_be_bytes());
        p.extend_from_slice(&[6, 64]);
        let src: std::net::Ipv6Addr = "2001:db8::7".parse().unwrap();
        p.extend_from_slice(&src.octets());
        p.extend_from_slice(&[0u8; 16]);
        p.extend_from_slice(&t);
        let fp = parse(&p).unwrap();
        assert_eq!(fp.signature, "6:64:0:1440:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:flow");
        assert_eq!(fp.ttl, 64);
        assert_eq!(fp.src, IpAddr::from(src));
    }

    #[test]
    fn quirks() {
        // No DF and a zero id; timestamp with a zero own clock and a
        // non-zero echo; window scale over 14.
        let opts = [8, 10, 0, 0, 0, 0, 0, 0, 0, 5, 3, 3, 15];
        let p = v4(250, false, 0, &tcp(1024, &opts));
        assert_eq!(parse(&p).unwrap().signature, "4:255:0:*:1024,15:ts,ws,eol+2:id-,ts1-,ts2+,exws");
    }

    #[test]
    fn refuses_what_is_not_a_syn() {
        let mut t = tcp(1024, &[]);
        t[13] = 0x12; // SYN+ACK
        assert!(parse(&v4(64, true, 1, &t)).is_none());
        t[13] = 0x10; // ACK
        assert!(parse(&v4(64, true, 1, &t)).is_none());
        let mut udp = v4(64, true, 1, &tcp(1024, &[]));
        udp[9] = 17;
        assert!(parse(&udp).is_none());
        assert!(parse(&[]).is_none());
        assert!(parse(&[0x45]).is_none());
        assert!(parse(&[0x70; 60]).is_none());
    }

    #[test]
    fn cut_or_malformed_input_is_refused_or_marked_never_panics() {
        let p = v4(64, true, 1, &tcp(64240, &LINUX_OPTS));
        for n in 0..p.len() {
            // Every prefix: the declared lengths no longer fit.
            assert!(parse(&p[..n]).is_none(), "prefix of {n} bytes");
        }
        // An option whose length runs past the header.
        let p = v4(64, true, 1, &tcp(1, &[2, 40, 0, 0]));
        assert_eq!(parse(&p).unwrap().signature, "4:64:0:*:1,*::df,id+,bad");
        // A zero length would loop forever if it were taken.
        let p = v4(64, true, 1, &tcp(1, &[9, 0, 0, 0]));
        assert!(parse(&p).unwrap().signature.ends_with(",bad"));
        // A known option with the wrong length.
        let p = v4(64, true, 1, &tcp(1, &[2, 3, 0, 1]));
        assert_eq!(parse(&p).unwrap().signature, "4:64:0:*:1,*:?2,nop:df,id+,bad");
        // Every byte value at every position: never a panic.
        let base = v4(64, true, 1, &tcp(64240, &LINUX_OPTS));
        for pos in 0..base.len() {
            for b in 0..=255u8 {
                let mut q = base.clone();
                q[pos] = b;
                let _ = parse(&q);
            }
        }
    }

    #[test]
    fn a_fast_open_syn_is_measured_from_its_saved_headers() {
        // Linux saves the headers only: the IP length counts 100 bytes of
        // data that aren't in the buffer.
        let mut p = v4(57, true, 0x1c46, &tcp(64240, &LINUX_OPTS));
        let total = (p.len() + 100) as u16;
        p[2..4].copy_from_slice(&total.to_be_bytes());
        assert_eq!(parse(&p).unwrap().signature, "4:64:0:1460:64240,7:mss,sok,ts,nop,ws:df,id+,data+");
        // The same with the data present.
        p.extend_from_slice(&[0xab; 100]);
        assert_eq!(parse(&p).unwrap().signature, "4:64:0:1460:64240,7:mss,sok,ts,nop,ws:df,id+,data+");
        // IPv6.
        let t = tcp(65535, &[2, 4, 0x05, 0xa0]);
        let mut p = vec![0x60, 0, 0, 0];
        p.extend_from_slice(&((t.len() + 50) as u16).to_be_bytes());
        p.extend_from_slice(&[6, 64]);
        p.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7]);
        p.extend_from_slice(&[0u8; 16]);
        p.extend_from_slice(&t);
        assert_eq!(parse(&p).unwrap().signature, "6:64:0:1440:65535,*:mss:data+");
    }

    #[test]
    fn ecn_is_one_quirk_whatever_shows_it() {
        let mut p = v4(64, true, 1, &tcp(1024, &[]));
        p[1] = 0x02; // ECT(0) in the IP header
        assert_eq!(parse(&p).unwrap().signature, "4:64:0:*:1024,*::df,id+,ecn");
        let ip_only = p.clone();
        p[20 + 13] |= 0xc0; // ECE and CWR as well
        assert_eq!(parse(&p).unwrap().signature, parse(&ip_only).unwrap().signature);
        let mut t = tcp(1024, &[]);
        t[13] |= 0xc0; // TCP flags only
        assert_eq!(parse(&v4(64, true, 1, &t)).unwrap().signature, "4:64:0:*:1024,*::df,id+,ecn");
    }

    #[test]
    fn initial_ttl_buckets() {
        assert_eq!(initial_ttl(1), 32);
        assert_eq!(initial_ttl(32), 32);
        assert_eq!(initial_ttl(33), 64);
        assert_eq!(initial_ttl(64), 64);
        assert_eq!(initial_ttl(100), 128);
        assert_eq!(initial_ttl(129), 255);
    }
}
