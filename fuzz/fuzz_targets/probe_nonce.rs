#![no_main]
// Probe nonces: the value a client gets with the probe script and sends
// back with its report, so it can be replayed, edited or made up. The first
// byte picks the mode:
//
//   even  the rest is a nonce as sent
//   odd   a nonce issued here, then edited: binding (16 bytes), clock
//         offset (u32), ttl (u32, or the largest u64 when bit 1 of the
//         first byte is set), then (position, byte) edits
//
// Properties checked, beyond "does not panic", from the contract in
// `veritell_probe::nonce`:
// - Forgery: no nonce made without the key verifies. One with the wrong
//   shape is `Malformed` (a separate check of the 96-character base64url
//   alphabet), any other is `BadMac`.
// - An issued nonce is 96 characters of `[A-Za-z0-9_-]`, verifies with
//   its binding until `now + ttl` (saturating) and gives that expiry,
//   and two issued with the same arguments differ.
// - Order of checks: after expiry `Expired` with any binding; before,
//   another binding is `BindingMismatch`; under another key `BadMac`.
// - Any edit that changes an issued nonce is refused, and one that keeps
//   the shape is `BadMac`: the encoding is canonical and the MAC covers
//   id, expiry and binding tag.
use std::sync::OnceLock;
use veritell_probe::{issue_nonce, verify_nonce, NonceError, ProbeKey};

const NOW: u64 = 1_800_000_000;

fn key() -> &'static ProbeKey {
    static K: OnceLock<ProbeKey> = OnceLock::new();
    K.get_or_init(|| ProbeKey::from_secret(&[3u8; 32]).unwrap())
}

fn other_key() -> &'static ProbeKey {
    static K: OnceLock<ProbeKey> = OnceLock::new();
    K.get_or_init(|| ProbeKey::from_secret(&[4u8; 40]).unwrap())
}

fn well_shaped(s: &str) -> bool {
    s.len() == 96
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn apply(s: &str, edits: &[u8]) -> String {
    let mut b = s.as_bytes().to_vec();
    for e in edits.chunks_exact(2) {
        match e[0] {
            0xFF => b.truncate(usize::from(e[1])),
            0xFE => b.push(e[1]),
            p if !b.is_empty() => {
                let i = usize::from(p) % b.len();
                b[i] = e[1];
            }
            _ => {}
        }
    }
    String::from_utf8_lossy(&b).into_owned()
}

fn minted(pick: u8, d: &[u8]) {
    if d.len() < 24 {
        return;
    }
    let binding: [u8; 16] = d[..16].try_into().unwrap();
    let now = NOW + u64::from(u32::from_be_bytes(d[16..20].try_into().unwrap()));
    let ttl = if pick & 2 == 2 {
        u64::MAX
    } else {
        u64::from(u32::from_be_bytes(d[20..24].try_into().unwrap()))
    };
    let edits = &d[24..];
    let mut other = binding;
    other[0] ^= 1;

    let n = issue_nonce(key(), &binding, now, ttl);
    assert!(well_shaped(&n), "issued nonce {n:?}");
    assert_ne!(
        issue_nonce(key(), &binding, now, ttl),
        n,
        "two nonces alike"
    );
    let expires_at = now.saturating_add(ttl);
    let info = verify_nonce(key(), &n, &binding, now).expect("a fresh nonce is refused");
    assert_eq!(info.expires_at, expires_at);
    assert_eq!(
        verify_nonce(key(), &n, &binding, expires_at).map(|i| i.id),
        Ok(info.id),
        "refused at its expiry"
    );
    assert_eq!(
        verify_nonce(key(), &n, &other, now).err(),
        Some(NonceError::BindingMismatch),
        "another binding"
    );
    if let Some(late) = expires_at.checked_add(1) {
        assert_eq!(
            verify_nonce(key(), &n, &binding, late).err(),
            Some(NonceError::Expired),
            "verified after expiry"
        );
        assert_eq!(
            verify_nonce(key(), &n, &other, late).err(),
            Some(NonceError::Expired),
            "binding checked before expiry"
        );
    }
    assert_eq!(
        verify_nonce(other_key(), &n, &binding, now).err(),
        Some(NonceError::BadMac),
        "another key"
    );

    let edited = apply(&n, edits);
    if edited != n {
        let want = if well_shaped(&edited) {
            NonceError::BadMac
        } else {
            NonceError::Malformed
        };
        assert_eq!(
            verify_nonce(key(), &edited, &binding, now).err(),
            Some(want),
            "edited nonce {edited:?}"
        );
    }
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some((&pick, rest)) = data.split_first() else {
        return;
    };
    if pick & 1 == 1 {
        minted(pick, rest);
        return;
    }
    assert!(
        ProbeKey::from_secret(&rest[..rest.len().min(31)]).is_none(),
        "a short secret makes a key"
    );
    let text = std::str::from_utf8(rest).unwrap_or("");
    let binding = [pick; 16];
    let want = if well_shaped(text) {
        NonceError::BadMac
    } else {
        NonceError::Malformed
    };
    assert_eq!(
        verify_nonce(key(), text, &binding, NOW).err(),
        Some(want),
        "nonce {text:?}"
    );
});
