#![no_main]
use veritell_fp::ja4;

fn is_hex12(s: &str) -> bool {
    s.len() == 12 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn check(data: &[u8], quic: bool) {
    let Some(fp) = ja4::compute(data, quic) else {
        return;
    };
    // `{proto}{ver}{sni}{nciphers}{nexts}{alpn}_{hash12}_{hash12}`
    let parts: Vec<&str> = fp.ja4.split('_').collect();
    assert_eq!(parts.len(), 3, "ja4 parts: {:?}", fp.ja4);
    let a = parts[0];
    assert!(a.len() == 10 && a.is_ascii(), "ja4 part a: {a:?}");
    assert_eq!(a.as_bytes()[0], if quic { b'q' } else { b't' });
    assert!(is_hex12(parts[1]), "ja4 cipher hash: {:?}", parts[1]);
    assert!(is_hex12(parts[2]), "ja4 ext hash: {:?}", parts[2]);
    // The unhashed form shares part a.
    assert!(fp.ja4_r.starts_with(a), "ja4_r: {:?}", fp.ja4_r);
    assert!(fp.ja4_r.split('_').count() >= 3);
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    check(data, false);
    check(data, true);
});
