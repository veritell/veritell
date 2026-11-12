//! JA4 TLS client fingerprint, computed from the raw ClientHello body.
//!
//! Format: `{proto}{ver}{sni}{nciphers}{nexts}{alpn}_{sha256(ciphers)[:12]}_{sha256(exts_sigalgs)[:12]}`

use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Default)]
pub struct TlsFp {
    pub ja4: String,
    /// Unhashed form, useful for debugging and for building the truth table.
    pub ja4_r: String,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    /// Extension types in the order the client sent them (GREASE removed).
    pub ext_order: Vec<u16>,
}

/// Bounds-checked cursor. Every read returns `None` instead of panicking,
/// because this parses bytes controlled by the remote peer.
struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf }
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.buf.len() < n {
            return None;
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Some(head)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
    fn vec8(&mut self) -> Option<&'a [u8]> {
        let n = self.u8()? as usize;
        self.take(n)
    }
    fn vec16(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
    fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

fn is_grease(v: u16) -> bool {
    (v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0xff)
}

fn u16_list(bytes: &[u8]) -> Vec<u16> {
    bytes
        .as_chunks::<2>().0.iter()
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .filter(|v| !is_grease(*v))
        .collect()
}

fn hex_list(values: &[u16]) -> String {
    values
        .iter()
        .map(|v| format!("{v:04x}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn hash12(s: &str) -> String {
    if s.is_empty() {
        return "000000000000".to_string();
    }
    let digest = Sha256::digest(s.as_bytes());
    digest[..6].iter().map(|b| format!("{b:02x}")).collect()
}

fn version_code(v: u16) -> &'static str {
    match v {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        _ => "00",
    }
}

fn alpn_code(first: Option<&[u8]>) -> String {
    let Some(p) = first.filter(|p| !p.is_empty()) else {
        return "00".to_string();
    };
    let (a, b) = (p[0], p[p.len() - 1]);
    if a.is_ascii_alphanumeric() && b.is_ascii_alphanumeric() {
        format!("{}{}", a as char, b as char)
    } else {
        // Non-printable ALPN: first hex digit of the first byte, last of the last.
        let (ha, hb) = (format!("{a:02x}"), format!("{b:02x}"));
        format!("{}{}", &ha[..1], &hb[1..])
    }
}

/// The two hashed sections, split out so they can be tested against the
/// published JA4 examples.
pub fn cipher_hash(ciphers: &[u16]) -> String {
    let mut sorted = ciphers.to_vec();
    sorted.sort_unstable();
    hash12(&hex_list(&sorted))
}

pub fn extension_hash(exts: &[u16], sig_algs: &[u16]) -> String {
    hash12(&extension_raw(exts, sig_algs))
}

fn extension_raw(exts: &[u16], sig_algs: &[u16]) -> String {
    let mut sorted: Vec<u16> = exts
        .iter()
        .copied()
        .filter(|e| *e != 0x0000 && *e != 0x0010)
        .collect();
    sorted.sort_unstable();
    let mut s = hex_list(&sorted);
    if !sig_algs.is_empty() && !s.is_empty() {
        s.push('_');
        s.push_str(&hex_list(sig_algs));
    }
    s
}

/// `hello` is the ClientHello handshake body, starting at `legacy_version`.
/// A leading 4-byte handshake header is tolerated and skipped.
pub fn compute(hello: &[u8], quic: bool) -> Option<TlsFp> {
    let mut body = hello;
    if body.len() >= 4 && body[0] == 0x01 {
        let len = u32::from_be_bytes([0, body[1], body[2], body[3]]) as usize;
        if len == body.len() - 4 {
            body = &body[4..];
        }
    }

    let mut r = Reader::new(body);
    let legacy_version = r.u16()?;
    r.take(32)?; // random
    r.vec8()?; // session id
    let ciphers = u16_list(r.vec16()?);
    r.vec8()?; // compression methods

    let mut ext_order = Vec::new();
    let mut sig_algs = Vec::new();
    let mut alpn: Vec<Vec<u8>> = Vec::new();
    let mut sni = None;
    let mut has_sni = false;
    let mut version = legacy_version;

    if !r.is_empty() {
        let mut exts = Reader::new(r.vec16()?);
        while !exts.is_empty() {
            let ty = exts.u16()?;
            let data = exts.vec16()?;
            if is_grease(ty) {
                continue;
            }
            ext_order.push(ty);
            let mut d = Reader::new(data);
            match ty {
                0x0000 => {
                    has_sni = true;
                    if let Some(list) = d.vec16() {
                        let mut l = Reader::new(list);
                        if l.u8() == Some(0) {
                            sni = l
                                .vec16()
                                .and_then(|n| std::str::from_utf8(n).ok())
                                .map(str::to_owned);
                        }
                    }
                }
                0x0010 => {
                    if let Some(list) = d.vec16() {
                        let mut l = Reader::new(list);
                        while let Some(p) = l.vec8() {
                            alpn.push(p.to_vec());
                            if l.is_empty() {
                                break;
                            }
                        }
                    }
                }
                0x000d => {
                    if let Some(list) = d.vec16() {
                        sig_algs = u16_list(list);
                    }
                }
                0x002b => {
                    if let Some(list) = d.vec8() {
                        if let Some(max) = u16_list(list).into_iter().max() {
                            version = max;
                        }
                    }
                }
                _ => {}
            }
        }
    }

    let part_a = format!(
        "{}{}{}{:02}{:02}{}",
        if quic { 'q' } else { 't' },
        version_code(version),
        if has_sni { 'd' } else { 'i' },
        ciphers.len().min(99),
        ext_order.len().min(99),
        alpn_code(alpn.first().map(Vec::as_slice)),
    );

    let mut sorted_ciphers = ciphers.clone();
    sorted_ciphers.sort_unstable();

    Some(TlsFp {
        ja4: format!(
            "{part_a}_{}_{}",
            cipher_hash(&ciphers),
            extension_hash(&ext_order, &sig_algs)
        ),
        ja4_r: format!(
            "{part_a}_{}_{}",
            hex_list(&sorted_ciphers),
            extension_raw(&ext_order, &sig_algs)
        ),
        sni,
        alpn: alpn
            .iter()
            .map(|p| String::from_utf8_lossy(p).into_owned())
            .collect(),
        ext_order,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Example values from the JA4 specification (Chrome-style hello).
    #[test]
    fn spec_cipher_hash() {
        let ciphers = [
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
            0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
        ];
        assert_eq!(cipher_hash(&ciphers), "8daaf6152771");
    }

    #[test]
    fn spec_extension_hash() {
        let exts = [
            0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023,
            0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015,
        ];
        let sig = [
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ];
        assert_eq!(extension_hash(&exts, &sig), "e5627efa2ab1");
    }

    #[test]
    fn grease_detection() {
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0xfafa));
        assert!(!is_grease(0x1301));
        assert!(!is_grease(0x0a1a));
    }

    #[test]
    fn truncated_input_does_not_panic() {
        let hello = [0x03u8, 0x03, 0x00];
        assert!(compute(&hello, false).is_none());
        assert!(compute(&[], false).is_none());
    }

    #[test]
    fn minimal_hello() {
        let mut h = vec![0x03, 0x03];
        h.extend_from_slice(&[0u8; 32]);
        h.push(0); // session id
        h.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x0a, 0x0a]); // 1 cipher + GREASE
        h.extend_from_slice(&[0x01, 0x00]); // compression
        let fp = compute(&h, false).unwrap();
        assert_eq!(fp.ja4, "t12i010000_".to_string() + &cipher_hash(&[0x1301]) + "_000000000000");
    }
}
