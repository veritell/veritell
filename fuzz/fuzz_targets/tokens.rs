#![no_main]
// What a client presents to be let through: the session cookie, a solved
// challenge (string and counter), the return path after a challenge, and a
// Privacy Pass token in an Authorization header or as raw bytes. The first
// byte picks which:
//
//   0  a session token as sent           3  `Authorization: PrivateToken ...`
//   1  a challenge and a counter         4  a Privacy Pass token, raw
//   2  a return path                     5  tokens minted here, then edited
//   6  an issuer's name and public key, as an operator configures them
//
// Properties checked, beyond "does not panic":
// - Nothing but the exact string issued verifies: in mode 5 a session token
//   and a challenge are issued under the target's key, then edited as the
//   input says; any edit that changes the string must fail. A token
//   accepted in modes 0 and 1 must stop verifying after any one-byte edit.
// - Session tokens and challenges are not interchangeable.
// - Expiry and binding are enforced: at `expires_at` and with another
//   binding, verification fails.
// - A solution is accepted exactly when its hash has the difficulty's
//   leading zero bits (checked against a separate implementation).
// - A return path stays on the site: resolved against a page URL by a
//   WHATWG URL parser, it keeps the page's origin; and the challenge page
//   never carries it unescaped.
// - A Privacy Pass token accepted stops verifying after any one-byte edit.
// - An issuer name that passes is a plain host and port, so it cannot break
//   out of the challenge or the WWW-Authenticate header; an accepted key's
//   id is the SHA-256 of its SPKI and survives its base64url form.
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use veritell_privacypass::{
    token_challenge, token_from_authorization, valid_server_name, verify as pass_verify, www_authenticate, Accepted,
    IssuerKey,
};
use veritell_token::{issue, pow, verify, Binding, Keys, TokenError};

/// RFC 9578 test vectors: the issuer key, and the challenge and key id its
/// first token answers.
const PKI: &str = "30820152303d06092a864886f70d01010a3030a00d300b0609608648016503040202a11a301806092a864886f70d010108300b0609608648016503040202a2030201300382010f003082010a0282010100cb1aed6b6a95f5b1ce013a4cfcab25b94b2e64a23034e4250a7eab43c0df3a8c12993af12b111908d4b471bec31d4b6c9ad9cdda90612a2ee903523e6de5a224d6b02f09e5c374d0cfe01d8f529c500a78a2f67908fa682b5a2b430c81eaf1af72d7b5e794fc98a3139276879757ce453b526ef9bf6ceb99979b8423b90f4461a22af37aab0cf5733f7597abe44d31c732db68a181c6cbbe607d8c0e52e0655fd9996dc584eca0be87afbcd78a337d17b1dba9e828bbd81e291317144e7ff89f55619709b096cbb9ea474cead264c2073fe49740c01f00e109106066983d21e5f83f086e2e823c879cd43cef700d2a352a9babd612d03cad02db134b7e225a5f0203010001";
const DIGEST_1: &str = "5969f643b4cfda5196d4aa86aeb5368834f4f06de46950ed435b3b81bd036d44";
const KEY_ID: &str = "ca572f8982a9ca248a3056186322d93ca147266121ddeb5632c07f1f71cd2708";
const NOW: u64 = 1_800_000_000;
const PAGE: &str = "https://site.test/shop/item?id=1";

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn keys() -> &'static Keys {
    static K: OnceLock<Keys> = OnceLock::new();
    K.get_or_init(|| Keys::from_secret(&[7u8; 32]).unwrap())
}

fn pass() -> &'static (IssuerKey, Accepted) {
    static P: OnceLock<(IssuerKey, Accepted)> = OnceLock::new();
    P.get_or_init(|| {
        let key = IssuerKey::new("issuer.example", &hex(PKI)).unwrap();
        let accepted = Accepted {
            challenge_digest: hex(DIGEST_1).try_into().unwrap(),
            key_id: hex(KEY_ID).try_into().unwrap(),
        };
        (key, accepted)
    })
}

/// Leading zero bits of SHA-256(challenge ":" counter), written apart from
/// the crate's own check.
fn zero_bits(challenge: &str, counter: u64) -> u32 {
    let d = Sha256::digest(format!("{challenge}:{counter}").as_bytes());
    let mut n = 0;
    for b in d {
        n += b.leading_zeros();
        if b != 0 {
            break;
        }
    }
    n
}

/// Every one-byte change to `s` at up to 64 positions: another character,
/// and the character removed.
fn one_byte_edits(s: &str) -> impl Iterator<Item = String> + '_ {
    let step = (s.len() / 64).max(1);
    (0..s.len()).step_by(step).flat_map(move |i| {
        let mut b = s.as_bytes().to_vec();
        b[i] = if b[i] == b'0' { b'1' } else { b'0' };
        let changed = String::from_utf8(b).unwrap_or_default();
        let mut removed = s.to_string();
        if s.is_char_boundary(i) && s.is_char_boundary(i + 1) {
            removed.remove(i);
        }
        [changed, removed]
    })
}

fn pass_edits(token: &[u8]) {
    let (key, accepted) = pass();
    for i in (0..token.len()).step_by(7) {
        let mut t = token.to_vec();
        t[i] ^= 0x01;
        assert!(
            pass_verify(&t, std::slice::from_ref(key), std::slice::from_ref(accepted)).is_err(),
            "Privacy Pass token still verifies with byte {i} changed"
        );
    }
}

fn return_path(text: &str) {
    let out = pow::sanitize_return_to(text);
    assert!(out == text || out == "/", "sanitize_return_to invented a path: {out:?}");
    let page = url::Url::parse(PAGE).unwrap();
    if let Ok(dest) = page.join(out) {
        assert_eq!(dest.origin(), page.origin(), "return path {out:?} leaves the site: {dest}");
    }
    // Raw, the path may appear no more often than in a page without it.
    if out.contains(['<', '>', '"', '\'']) {
        let html = pow::challenge_page("x", text);
        let without = pow::challenge_page("x", "/");
        assert!(
            html.matches(out).count() <= without.matches(out).count(),
            "challenge page carries the return path unescaped"
        );
    }
}

/// Mode 5: input is binding (16), clock offset (4), ttl (2), budget (2),
/// difficulty (1), solution counter (4), then edits: (position, byte) pairs.
fn minted(d: &[u8]) {
    if d.len() < 29 {
        return;
    }
    let binding = Binding(d[..16].try_into().unwrap());
    let now = NOW + u64::from(u32::from_be_bytes(d[16..20].try_into().unwrap()));
    let ttl = u64::from(u16::from_be_bytes(d[20..22].try_into().unwrap()));
    let budget = u32::from(u16::from_be_bytes(d[22..24].try_into().unwrap()));
    let difficulty = d[24];
    let counter = u64::from(u32::from_be_bytes(d[25..29].try_into().unwrap()));
    let edits = &d[29..];
    let mut other = binding.0;
    other[0] ^= 1;
    let other = Binding(other);

    // Session token.
    let token = issue(keys(), &binding, now, ttl, budget);
    match verify(keys(), &token, &binding, now) {
        Ok(c) => {
            assert!(ttl > 0, "a token issued with ttl 0 verifies");
            assert_eq!((c.issued_at, c.expires_at, c.budget), (now, now + ttl, budget));
        }
        Err(e) => assert!(ttl == 0 && e == TokenError::Expired, "fresh token refused: {e:?}"),
    }
    assert!(verify(keys(), &token, &binding, now + ttl).is_err(), "token verifies at expires_at");
    assert!(verify(keys(), &token, &other, now).is_err(), "token verifies for another client");
    let edited = apply(&token, edits);
    if edited != token {
        assert!(verify(keys(), &edited, &binding, now).is_err(), "edited token verifies: {edited}");
    }

    // Challenge.
    let ch = pow::issue_challenge(keys(), &binding, now, ttl, difficulty);
    let level = difficulty.clamp(pow::MIN_DIFFICULTY, pow::MAX_DIFFICULTY);
    assert_eq!(pow::issued_difficulty(keys(), &ch), Some(level));
    assert!(pow::issued_difficulty(keys(), &token).is_none(), "a session token reads as a challenge");
    assert!(verify(keys(), &ch, &binding, now).is_err(), "a challenge verifies as a session token");
    let edited = apply(&ch, edits);
    if edited != ch {
        assert!(pow::issued_difficulty(keys(), &edited).is_none(), "edited challenge accepted: {edited}");
    }
    let good = zero_bits(&ch, counter) >= u32::from(level);
    match pow::verify_solution(keys(), &ch, counter, &binding, now) {
        Ok(s) => {
            assert!(good, "accepted a counter with too few zero bits");
            assert_eq!(s.difficulty, level);
        }
        Err(pow::PowError::WrongSolution) => assert!(!good, "refused a correct counter"),
        Err(e) => assert!(ttl == 0, "fresh challenge refused: {e:?}"),
    }
    // Low levels are cheap to solve here, so the accepting path, partial
    // zero bytes included, is reached on every run.
    if level <= 12 && ttl > 0 {
        let c = pow::solve(&ch, 1 << 20).expect("no solution in 2^20 tries");
        assert!(zero_bits(&ch, c) >= u32::from(level), "reference solver found a weak counter");
        assert!(pow::verify_solution(keys(), &ch, c, &binding, now).is_ok(), "a solved challenge is refused");
    }
    assert!(pow::verify_solution(keys(), &ch, counter, &other, now).is_err(), "challenge valid for another client");
    if good {
        assert!(pow::verify_solution(keys(), &ch, counter, &binding, now + ttl).is_err(), "solution valid after expiry");
    }
}

/// Mode 6: issuer name, then the SPKI, then origin info, separated by 0xFF.
fn issuer(rest: &[u8]) {
    let mut f = rest.splitn(3, |&b| b == 0xFF);
    let name = std::str::from_utf8(f.next().unwrap_or_default()).unwrap_or("");
    let spki = f.next().unwrap_or_default();
    let origin = std::str::from_utf8(f.next().unwrap_or_default()).unwrap_or("");
    if valid_server_name(name) {
        assert!(name.len() <= 255, "name of {} bytes", name.len());
        assert!(
            name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b':')
                && name.matches(':').count() <= 1,
            "server name {name:?} accepted"
        );
        // With origin info, also a redemption context.
        let context = (!origin.is_empty()).then_some(&[7u8; 32]);
        let c = token_challenge(name, context, origin);
        if let Ok(c) = &c {
            let context_len = if context.is_some() { 33 } else { 1 };
            assert_eq!(c.len(), 2 + 2 + name.len() + context_len + 2 + origin.len(), "challenge length");
            assert_eq!(&c[..2], &[0, 2]);
        }
    }
    if let Ok(key) = IssuerKey::new(name, spki) {
        assert!(valid_server_name(name));
        assert_eq!(key.key_id(), &<[u8; 32]>::from(Sha256::digest(spki)), "key id is not SHA-256 of the SPKI");
        let again = IssuerKey::from_base64url(name, &key.token_key()).expect("token-key does not read back");
        assert_eq!((again.key_id(), again.spki()), (key.key_id(), key.spki()));
        let header = www_authenticate(&[(b"challenge".as_slice(), &key)]);
        assert!(!header.contains(['\r', '\n']) && header.matches('"').count() == 4, "header {header:?}");
    }
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
    String::from_utf8(b).unwrap_or_default()
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some((&pick, rest)) = data.split_first() else { return };
    let text = std::str::from_utf8(rest).unwrap_or("");
    let binding = Binding([pick; 16]);
    match pick % 7 {
        0 => {
            if verify(keys(), text, &binding, NOW).is_ok() {
                for e in one_byte_edits(text) {
                    if e != text {
                        assert!(verify(keys(), &e, &binding, NOW).is_err(), "edited token verifies: {e}");
                    }
                }
            }
        }
        1 => {
            // challenge, then the counter after the last ':'.
            let (challenge, counter) = text.rsplit_once(':').unwrap_or((text, "0"));
            let counter = counter.parse::<u64>().unwrap_or(0);
            if let Ok(s) = pow::verify_solution(keys(), challenge, counter, &binding, NOW) {
                assert!(zero_bits(challenge, counter) >= u32::from(s.difficulty), "accepted a weak solution");
                for e in one_byte_edits(challenge) {
                    if e != challenge {
                        assert!(pow::issued_difficulty(keys(), &e).is_none(), "edited challenge accepted: {e}");
                    }
                }
            }
        }
        2 => {
            let _ = pow::issued_difficulty(keys(), text);
            return_path(text);
        }
        3 => {
            if let Ok(Some(token)) = token_from_authorization(text) {
                let (key, accepted) = pass();
                if pass_verify(&token, std::slice::from_ref(key), std::slice::from_ref(accepted)).is_ok() {
                    pass_edits(&token);
                }
            }
        }
        4 => {
            let (key, accepted) = pass();
            if pass_verify(rest, std::slice::from_ref(key), std::slice::from_ref(accepted)).is_ok() {
                pass_edits(rest);
            }
        }
        5 => minted(rest),
        _ => issuer(rest),
    }
});
