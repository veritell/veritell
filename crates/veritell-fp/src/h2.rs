//! HTTP/2 client fingerprint, parsed from the first bytes the client sends
//! after the TLS handshake (preface, SETTINGS, WINDOW_UPDATE, PRIORITY, first HEADERS).
//!
//! Output follows the widely used "Akamai" layout:
//! `settings|window_update|priority_frames|pseudo_header_order`

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const FRAME_HEADERS: u8 = 0x1;
const FRAME_PRIORITY: u8 = 0x2;
const FRAME_SETTINGS: u8 = 0x4;
const FRAME_WINDOW_UPDATE: u8 = 0x8;
const FRAME_CONTINUATION: u8 = 0x9;

const FLAG_ACK: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_PADDED: u8 = 0x8;
const FLAG_PRIORITY: u8 = 0x20;

#[derive(Clone, Debug, Default)]
pub struct Priority {
    pub stream: u32,
    pub exclusive: bool,
    pub depends_on: u32,
    /// Effective weight (wire value + 1).
    pub weight: u16,
}

#[derive(Clone, Debug, Default)]
pub struct H2Fp {
    pub settings: Vec<(u16, u32)>,
    pub window_update: u32,
    pub priorities: Vec<Priority>,
    /// Priority carried inside the first HEADERS frame, if any.
    pub headers_priority: Option<Priority>,
    pub pseudo_order: Vec<String>,
    /// Regular header names in the order sent on the first request.
    pub header_order: Vec<String>,
    pub akamai: String,
}

pub enum Parse {
    /// The first header block has not fully arrived yet.
    Incomplete,
    /// The bytes are not a valid HTTP/2 client preamble.
    Invalid,
    Done(H2Fp),
}

fn parse_priority(stream: u32, p: &[u8]) -> Option<Priority> {
    if p.len() < 5 {
        return None;
    }
    let dep = u32::from_be_bytes([p[0], p[1], p[2], p[3]]);
    Some(Priority {
        stream,
        exclusive: dep & 0x8000_0000 != 0,
        depends_on: dep & 0x7fff_ffff,
        weight: p[4] as u16 + 1,
    })
}

pub fn parse(buf: &[u8]) -> Parse {
    if buf.len() < PREFACE.len() {
        return if PREFACE.starts_with(buf) {
            Parse::Incomplete
        } else {
            Parse::Invalid
        };
    }
    if &buf[..PREFACE.len()] != PREFACE {
        return Parse::Invalid;
    }

    let mut fp = H2Fp::default();
    let mut rest = &buf[PREFACE.len()..];
    let mut block: Vec<u8> = Vec::new();
    let mut in_headers = false;
    let mut complete = false;

    while rest.len() >= 9 {
        let len = u32::from_be_bytes([0, rest[0], rest[1], rest[2]]) as usize;
        let ty = rest[3];
        let flags = rest[4];
        let stream = u32::from_be_bytes([rest[5], rest[6], rest[7], rest[8]]) & 0x7fff_ffff;
        if rest.len() < 9 + len {
            break;
        }
        let payload = &rest[9..9 + len];
        rest = &rest[9 + len..];

        if in_headers {
            // Only CONTINUATION may follow an unfinished header block.
            if ty != FRAME_CONTINUATION {
                return Parse::Invalid;
            }
            block.extend_from_slice(payload);
            if flags & FLAG_END_HEADERS != 0 {
                complete = true;
                break;
            }
            continue;
        }

        match ty {
            FRAME_SETTINGS if stream == 0 && flags & FLAG_ACK == 0 && fp.settings.is_empty() => {
                for c in payload.as_chunks::<6>().0 {
                    fp.settings.push((
                        u16::from_be_bytes([c[0], c[1]]),
                        u32::from_be_bytes([c[2], c[3], c[4], c[5]]),
                    ));
                }
            }
            FRAME_WINDOW_UPDATE if stream == 0 && fp.window_update == 0 && len == 4 => {
                fp.window_update =
                    u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])
                        & 0x7fff_ffff;
            }
            FRAME_PRIORITY => {
                if let Some(p) = parse_priority(stream, payload) {
                    fp.priorities.push(p);
                }
            }
            FRAME_HEADERS => {
                let mut p = payload;
                let mut pad = 0usize;
                if flags & FLAG_PADDED != 0 {
                    let Some((&n, tail)) = p.split_first() else {
                        return Parse::Invalid;
                    };
                    pad = n as usize;
                    p = tail;
                }
                if flags & FLAG_PRIORITY != 0 {
                    let Some(pr) = parse_priority(stream, p) else {
                        return Parse::Invalid;
                    };
                    fp.headers_priority = Some(pr);
                    p = &p[5..];
                }
                if pad > p.len() {
                    return Parse::Invalid;
                }
                block.extend_from_slice(&p[..p.len() - pad]);
                if flags & FLAG_END_HEADERS != 0 {
                    complete = true;
                    break;
                }
                in_headers = true;
            }
            _ => {}
        }
    }

    if !complete {
        return Parse::Incomplete;
    }

    // First header block on the connection, so a fresh HPACK decoder is correct.
    // The decoder runs on peer-controlled bytes; contain any panic it may have.
    // Under the fuzzer (`--cfg fuzzing`) the guard is left out, so that a
    // panic in the decoder is reported instead of hidden.
    #[cfg(not(fuzzing))]
    let decoded = std::panic::catch_unwind(|| decode_names(&block));
    #[cfg(fuzzing)]
    let decoded: Result<_, ()> = Ok(decode_names(&block));
    let Ok(Some(names)) = decoded else {
        return Parse::Invalid;
    };
    for name in names {
        if let Some(pseudo) = name.strip_prefix(':') {
            fp.pseudo_order.push(pseudo.to_string());
        } else {
            fp.header_order.push(name);
        }
    }

    fp.akamai = akamai_string(&fp);
    Parse::Done(fp)
}

/// Most header fields kept from the first block. Browsers send a few dozen.
const MAX_FIELDS: usize = 256;
/// Most decoded bytes (names and values) accepted from the first block.
/// HPACK lets a short block expand a lot: one large table entry can be
/// referenced once per byte, so a 16 KiB block could decode to tens of MB.
const MAX_DECODED: usize = 64 * 1024;

/// Most Huffman-coded strings accepted from the first block. loona-hpack
/// builds a new Huffman table for each one (about 10 µs), so a block of tiny
/// Huffman strings cost up to 70 ms of CPU for 16 KiB. Browsers send a few
/// dozen, a cookie split into crumbs included.
const MAX_HUFFMAN_STRINGS: usize = 128;

/// Walks a header block's representations without decoding any string, and
/// says whether it stays within `MAX_FIELDS` fields and `MAX_HUFFMAN_STRINGS`
/// Huffman strings. Cheap: integers and lengths only. A block cut short or
/// malformed passes here; loona-hpack refuses it.
fn within_decode_limits(block: &[u8]) -> bool {
    /// An HPACK integer with an `n`-bit prefix (RFC 7541, 5.1); `None` past
    /// the end, or larger than any length a 16 KiB block can carry.
    fn integer(b: &[u8], pos: &mut usize, n: u8) -> Option<usize> {
        let mask = (1usize << n) - 1;
        let mut v = usize::from(*b.get(*pos)?) & mask;
        *pos += 1;
        if v < mask {
            return Some(v);
        }
        let mut shift = 0u32;
        loop {
            let byte = *b.get(*pos)?;
            *pos += 1;
            v = v.checked_add(usize::from(byte & 0x7f).checked_shl(shift)?)?;
            if byte & 0x80 == 0 {
                return (v <= 1 << 24).then_some(v);
            }
            shift += 7;
            if shift > 28 {
                return None;
            }
        }
    }
    /// Skips a string literal; true when it was Huffman-coded.
    fn string(b: &[u8], pos: &mut usize) -> Option<bool> {
        let huffman = *b.get(*pos)? & 0x80 != 0;
        let len = integer(b, pos, 7)?;
        *pos = pos.checked_add(len)?;
        (*pos <= b.len()).then_some(huffman)
    }
    let (mut pos, mut fields, mut huffman) = (0usize, 0usize, 0usize);
    while pos < block.len() {
        let first = block[pos];
        let parsed = if first & 0x80 != 0 {
            // Indexed field.
            integer(block, &mut pos, 7).map(|_| 1)
        } else if first & 0xe0 == 0x20 {
            // Dynamic table size update: no field.
            integer(block, &mut pos, 5).map(|_| 0)
        } else {
            // A literal: with incremental indexing (6-bit index), or without
            // / never indexed (4-bit). Index 0: the name is a string too.
            let prefix = if first & 0x40 != 0 { 6 } else { 4 };
            (|| {
                if integer(block, &mut pos, prefix)? == 0 {
                    huffman += usize::from(string(block, &mut pos)?);
                }
                huffman += usize::from(string(block, &mut pos)?);
                Some(1)
            })()
        };
        let Some(n) = parsed else { return true };
        fields += n;
        if fields > MAX_FIELDS || huffman > MAX_HUFFMAN_STRINGS {
            return false;
        }
    }
    true
}

/// Decodes the header names of a block, without keeping the values.
/// `None` when the block is not valid HPACK or decodes past the limits above.
fn decode_names(block: &[u8]) -> Option<Vec<String>> {
    if !within_decode_limits(block) {
        return None;
    }
    let mut dec = loona_hpack::Decoder::new();
    let mut names = Vec::new();
    let mut total = 0usize;
    let mut fields = 0usize;
    let mut over = false;
    // The callback only borrows each field, so an indexed reference costs
    // no allocation; once over a limit, the rest is skipped.
    let res = dec.decode_with_cb(block, |name, value| {
        if over {
            return;
        }
        fields = fields.saturating_add(1);
        total = total.saturating_add(name.len()).saturating_add(value.len());
        if fields > MAX_FIELDS || total > MAX_DECODED {
            over = true;
            return;
        }
        names.push(String::from_utf8_lossy(&name).into_owned());
    });
    if res.is_err() || over {
        return None;
    }
    Some(names)
}

fn akamai_string(fp: &H2Fp) -> String {
    let settings = fp
        .settings
        .iter()
        .map(|(k, v)| format!("{k}:{v}"))
        .collect::<Vec<_>>()
        .join(";");
    let window = if fp.window_update == 0 {
        "00".to_string()
    } else {
        fp.window_update.to_string()
    };
    let priorities = if fp.priorities.is_empty() {
        "0".to_string()
    } else {
        fp.priorities
            .iter()
            .map(|p| {
                format!(
                    "{}:{}:{}:{}",
                    p.stream, p.exclusive as u8, p.depends_on, p.weight
                )
            })
            .collect::<Vec<_>>()
            .join(",")
    };
    // One letter per pseudo-header. The names are the peer's to write: any
    // first character other than a lowercase letter or digit becomes `?`, so
    // that a name such as `:|x` cannot add a separator to the fingerprint
    // (which would make `veritell-ua` skip its HTTP/2 checks) and still shows
    // up as an order no browser sends.
    let pseudo = fp
        .pseudo_order
        .iter()
        .map(|p| match p.chars().next() {
            Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() => c.to_string(),
            _ => "?".to_string(),
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("{settings}|{window}|{priorities}|{pseudo}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A literal without indexing, new name, both strings Huffman-coded and
    /// one byte long ("a" padded): five bytes, two Huffman strings.
    const TINY_HUFFMAN_FIELD: [u8; 5] = [0x00, 0x81, 0x1f, 0x81, 0x1f];

    #[test]
    fn a_flood_of_tiny_huffman_strings_is_refused_before_decoding() {
        let block: Vec<u8> = TINY_HUFFMAN_FIELD.repeat(16 * 1024 / 5);
        let t = std::time::Instant::now();
        assert_eq!(decode_names(&block), None);
        let took = t.elapsed();
        // Was about 70 ms in a release build; the walk alone is microseconds.
        assert!(took < std::time::Duration::from_millis(20), "took {took:?}");
    }

    #[test]
    fn huffman_strings_up_to_the_limit_still_decode() {
        let ok = TINY_HUFFMAN_FIELD.repeat(MAX_HUFFMAN_STRINGS / 2);
        assert_eq!(decode_names(&ok).map(|n| n.len()), Some(MAX_HUFFMAN_STRINGS / 2));
        let over = TINY_HUFFMAN_FIELD.repeat(MAX_HUFFMAN_STRINGS / 2 + 1);
        assert!(within_decode_limits(&ok) && !within_decode_limits(&over));
    }

    #[test]
    fn the_field_limit_is_checked_before_decoding() {
        // Indexed :method GET, cheap, one field each.
        assert!(within_decode_limits(&[0x82; MAX_FIELDS]));
        assert!(!within_decode_limits(&[0x82; MAX_FIELDS + 1]));
        // Table size updates are not fields.
        let mut b = vec![0x20; 500];
        b.extend_from_slice(&[0x82; 10]);
        assert!(within_decode_limits(&b));
    }

    #[test]
    fn the_walk_reads_integers_and_lengths_as_hpack_does() {
        // Literal with incremental indexing, indexed name 32 (cookie), raw
        // value of 200 bytes (7-bit prefix 127 + continuation 73).
        let mut b = vec![0x40 | 32, 0x7f, 73];
        b.extend_from_slice(&[b'x'; 200]);
        b.push(0x82);
        assert!(within_decode_limits(&b));
        assert_eq!(decode_names(&b).map(|n| n.len()), Some(2));
        // Cut short, or an integer that never ends: left to loona-hpack, which refuses it.
        assert!(within_decode_limits(&b[..50]));
        assert!(within_decode_limits(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]));
        assert_eq!(decode_names(&b[..50]), None);
    }

    #[test]
    fn the_walk_never_panics() {
        let mut x: u32 = 1;
        for len in 0..300usize {
            let b: Vec<u8> = (0..len)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 17;
                    x ^= x << 5;
                    x as u8
                })
                .collect();
            let _ = within_decode_limits(&b);
        }
    }

    fn frame(ty: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let len = payload.len() as u32;
        let mut f = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8, ty, flags];
        f.extend_from_slice(&stream.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    fn chrome_like() -> Vec<u8> {
        let mut b = PREFACE.to_vec();
        // SETTINGS 1:65536, 2:0, 4:6291456, 6:262144
        let mut s = Vec::new();
        for (k, v) in [(1u16, 65536u32), (2, 0), (4, 6291456), (6, 262144)] {
            s.extend_from_slice(&k.to_be_bytes());
            s.extend_from_slice(&v.to_be_bytes());
        }
        b.extend(frame(FRAME_SETTINGS, 0, 0, &s));
        b.extend(frame(FRAME_WINDOW_UPDATE, 0, 0, &15663105u32.to_be_bytes()));
        // HEADERS with priority (exclusive, dep 0, weight 256) and static-table
        // indexed fields: :method GET (2), :authority (1, empty), :scheme https (7), :path / (4)
        let mut h = vec![0x80, 0x00, 0x00, 0x00, 0xff];
        h.extend_from_slice(&[0x82, 0x41, 0x00, 0x87, 0x84]);
        b.extend(frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_PRIORITY | 0x1,
            1,
            &h,
        ));
        b
    }

    #[test]
    fn parses_chrome_like_preamble() {
        let Parse::Done(fp) = parse(&chrome_like()) else {
            panic!("expected a complete parse");
        };
        assert_eq!(
            fp.akamai,
            "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
        );
        let p = fp.headers_priority.unwrap();
        assert!(p.exclusive);
        assert_eq!(p.weight, 256);
    }

    #[test]
    fn partial_input_is_incomplete() {
        let full = chrome_like();
        for cut in [0, 10, 24, 40, full.len() - 1] {
            assert!(matches!(parse(&full[..cut]), Parse::Incomplete));
        }
    }

    #[test]
    fn garbage_is_invalid() {
        assert!(matches!(parse(b"GET / HTTP/1.1\r\n\r\n"), Parse::Invalid));
    }

    #[test]
    fn pseudo_header_names_cannot_add_separators() {
        // Found by the Phase 4 fuzzing unit: `:|x` and `:,y` used to be
        // copied into the fingerprint as `|` and `,`.
        let mut block = vec![0x00, 0x03];
        block.extend_from_slice(b":|x");
        block.push(0x00);
        block.extend_from_slice(&[0x00, 0x03]);
        block.extend_from_slice(b":,y");
        block.push(0x00);
        block.extend_from_slice(&[0x00, 0x01]);
        block.extend_from_slice(b":");
        block.push(0x00);
        let mut buf = PREFACE.to_vec();
        buf.extend(frame(FRAME_SETTINGS, 0, 0, &[]));
        buf.extend(frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, &block));
        let Parse::Done(fp) = parse(&buf) else { panic!("not parsed") };
        assert_eq!(fp.akamai.matches('|').count(), 3, "{}", fp.akamai);
        assert!(fp.akamai.ends_with("|?,?,?"), "{}", fp.akamai);
    }

    fn headers_only(block: &[u8]) -> Vec<u8> {
        let mut b = PREFACE.to_vec();
        b.extend(frame(FRAME_SETTINGS, 0, 0, &[]));
        b.extend(frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, block));
        b
    }

    #[test]
    fn expanding_block_is_rejected() {
        // One ~4 KB literal added to the dynamic table, then referenced
        // (index 62) thousands of times: a short block that would decode
        // to tens of MB.
        let mut block = vec![0x40, 0x01, b'x', 0x7f];
        // Value length 4000 as an HPACK integer with a 7-bit prefix.
        let mut n = 4000usize - 127;
        while n >= 128 {
            block.push((n % 128) as u8 | 0x80);
            n /= 128;
        }
        block.push(n as u8);
        block.extend(std::iter::repeat_n(b'a', 4000));
        block.extend(std::iter::repeat_n(0xbe, 12_000));
        assert!(matches!(parse(&headers_only(&block)), Parse::Invalid));
    }

    #[test]
    fn too_many_fields_is_rejected() {
        // :method GET (static index 2), repeated: small, but too many fields.
        let block = vec![0x82; MAX_FIELDS + 1];
        assert!(matches!(parse(&headers_only(&block)), Parse::Invalid));
        let block = vec![0x82; MAX_FIELDS];
        assert!(matches!(parse(&headers_only(&block)), Parse::Done(_)));
    }

    #[test]
    fn bad_hpack_is_invalid_not_panic() {
        let mut b = PREFACE.to_vec();
        b.extend(frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, &[0xff, 0xff, 0xff]));
        assert!(matches!(parse(&b), Parse::Invalid));
    }
}
