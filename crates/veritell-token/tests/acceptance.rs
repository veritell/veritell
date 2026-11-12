//! Acceptance tests written by the project lead. DO NOT EDIT.

use std::net::IpAddr;

use veritell_token::pow::{self, PowError};
use veritell_token::*;

const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef-test-secret";
const OTHER_SECRET: &[u8] = b"fedcba9876543210fedcba9876543210-other-secret";
const JA4: &str = "t13d1516h2_8daaf6152771_806a8c22fdea";
const UA: &str = "Mozilla/5.0 Chrome/142.0.0.0";
const NOW: u64 = 1_800_000_000;

fn keys() -> Keys {
    Keys::from_secret(SECRET).unwrap()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn binding() -> Binding {
    Binding::derive(Some(JA4), ip("203.0.113.9"), Some(UA))
}

fn cookie_safe(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

#[test]
fn weak_secrets_are_rejected() {
    assert!(matches!(Keys::from_secret(b""), Err(TokenError::WeakSecret)));
    assert!(matches!(Keys::from_secret(&[7u8; 31]), Err(TokenError::WeakSecret)));
    assert!(Keys::from_secret(&[7u8; 32]).is_ok());
}

#[test]
fn issue_then_verify_round_trip() {
    let t = issue(&keys(), &binding(), NOW, 600, 250);
    assert!(cookie_safe(&t), "{t}");
    assert!(t.len() < 300, "token too long for a cookie: {}", t.len());
    let c = verify(&keys(), &t, &binding(), NOW + 10).unwrap();
    assert_eq!((c.issued_at, c.expires_at, c.budget), (NOW, NOW + 600, 250));
}

#[test]
fn token_ids_are_random() {
    let k = keys();
    let a = verify(&k, &issue(&k, &binding(), NOW, 600, 1), &binding(), NOW).unwrap();
    let b = verify(&k, &issue(&k, &binding(), NOW, 600, 1), &binding(), NOW).unwrap();
    assert_ne!(a.id, b.id);
    assert_ne!(a.id, [0u8; 16]);
}

#[test]
fn expiry_boundaries() {
    let k = keys();
    let t = issue(&k, &binding(), NOW, 600, 5);
    assert!(verify(&k, &t, &binding(), NOW + 599).is_ok());
    assert_eq!(verify(&k, &t, &binding(), NOW + 600), Err(TokenError::Expired));
    assert_eq!(verify(&k, &t, &binding(), u64::MAX), Err(TokenError::Expired));
    // Overflowing ttl must not wrap around into the past.
    let t = issue(&k, &binding(), NOW, u64::MAX, 5);
    assert!(verify(&k, &t, &binding(), NOW + 1_000_000).is_ok());
}

#[test]
fn wrong_key_and_tampering_fail_signature() {
    let k = keys();
    let t = issue(&k, &binding(), NOW, 600, 5);
    let other = Keys::from_secret(OTHER_SECRET).unwrap();
    assert_eq!(verify(&other, &t, &binding(), NOW), Err(TokenError::BadSignature));

    // Flip every single character in turn: none may verify.
    let bytes = t.as_bytes();
    for i in 0..bytes.len() {
        let mut m = bytes.to_vec();
        m[i] = if m[i] == b'A' { b'B' } else { b'A' };
        let m = String::from_utf8(m).unwrap();
        if m == t {
            continue;
        }
        let r = verify(&k, &m, &binding(), NOW);
        assert!(
            matches!(r, Err(TokenError::BadSignature) | Err(TokenError::Malformed)),
            "tampered byte {i} gave {r:?}"
        );
    }
}

#[test]
fn malformed_tokens_do_not_panic() {
    let k = keys();
    let long = "A".repeat(100_000);
    for bad in ["", ".", "..", "a.b", "a.b.c.d", "====", "\u{1F600}", " ", long.as_str()] {
        assert!(verify(&k, bad, &binding(), NOW).is_err(), "{bad:?}");
    }
    let t = issue(&k, &binding(), NOW, 600, 5);
    for cut in 0..t.len() {
        assert!(verify(&k, &t[..cut], &binding(), NOW).is_err());
    }
}

#[test]
fn binding_changes_with_each_input() {
    let base = binding();
    assert_eq!(base, Binding::derive(Some(JA4), ip("203.0.113.9"), Some(UA)));
    // Same /24: still the same client.
    assert_eq!(base, Binding::derive(Some(JA4), ip("203.0.113.200"), Some(UA)));
    assert_ne!(base, Binding::derive(Some(JA4), ip("203.0.114.9"), Some(UA)));
    assert_ne!(base, Binding::derive(Some("t13d4907h2_x_y"), ip("203.0.113.9"), Some(UA)));
    assert_ne!(base, Binding::derive(None, ip("203.0.113.9"), Some(UA)));
    assert_ne!(base, Binding::derive(Some(JA4), ip("203.0.113.9"), Some("curl/8")));
    assert_ne!(base, Binding::derive(Some(JA4), ip("203.0.113.9"), None));
    // Concatenation must not collide.
    assert_ne!(
        Binding::derive(Some("ab"), ip("203.0.113.9"), Some("c")),
        Binding::derive(Some("a"), ip("203.0.113.9"), Some("bc"))
    );
    // Absent and empty are different.
    assert_ne!(
        Binding::derive(None, ip("203.0.113.9"), None),
        Binding::derive(Some(""), ip("203.0.113.9"), Some(""))
    );
    // IPv6 uses /48.
    let v6 = Binding::derive(Some(JA4), ip("2001:db8:1:2::1"), Some(UA));
    assert_eq!(v6, Binding::derive(Some(JA4), ip("2001:db8:1:ffff::9"), Some(UA)));
    assert_ne!(v6, Binding::derive(Some(JA4), ip("2001:db8:2:2::1"), Some(UA)));
}

#[test]
fn token_copied_to_another_client_fails() {
    let k = keys();
    let t = issue(&k, &binding(), NOW, 600, 5);
    let thief = Binding::derive(Some("t13d4907h2_0d8feac7bc37_7395dae3b2f3"), ip("198.51.100.1"), Some(UA));
    assert_eq!(verify(&k, &t, &thief, NOW), Err(TokenError::BindingMismatch));
    // Expiry is reported before binding.
    assert_eq!(verify(&k, &t, &thief, NOW + 600), Err(TokenError::Expired));
}

#[test]
fn budget_store_counts_and_bounds() {
    let s = MemoryBudgetStore::new(3);
    let a = [1u8; 16];
    assert!(s.consume(&a, 2, NOW + 100, NOW));
    assert!(s.consume(&a, 2, NOW + 100, NOW));
    assert!(!s.consume(&a, 2, NOW + 100, NOW));
    assert!(!s.consume(&a, 2, NOW + 100, NOW));
    assert_eq!(s.len(), 1);

    // Zero budget never succeeds.
    assert!(!s.consume(&[9u8; 16], 0, NOW + 100, NOW));

    // Fill to capacity with live entries, then a new id is refused.
    assert!(s.consume(&[2u8; 16], 1, NOW + 100, NOW));
    assert!(s.consume(&[3u8; 16], 1, NOW + 100, NOW));
    assert!(s.len() <= 3);
    assert!(!s.consume(&[4u8; 16], 1, NOW + 100, NOW));
    assert!(s.len() <= 3);

    // Once the old entries expire, there is room again.
    assert!(s.consume(&[4u8; 16], 1, NOW + 500, NOW + 101));
    assert!(s.len() <= 3);
}

#[test]
fn budget_store_is_thread_safe() {
    use std::sync::Arc;
    let s = Arc::new(MemoryBudgetStore::new(100));
    let id = [5u8; 16];
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let s = s.clone();
            std::thread::spawn(move || {
                (0..100).filter(|_| s.consume(&id, 50, NOW + 100, NOW)).count()
            })
        })
        .collect();
    let granted: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
    assert_eq!(granted, 50);
}

#[test]
fn pow_round_trip() {
    let k = keys();
    let ch = pow::issue_challenge(&k, &binding(), NOW, 120, 10);
    assert!(cookie_safe(&ch), "{ch}");
    let counter = pow::solve(&ch, 1 << 22).expect("10 bits should be solvable");
    let solved = pow::verify_solution(&k, &ch, counter, &binding(), NOW + 5).unwrap();
    assert_eq!((solved.difficulty, solved.expires_at), (10, NOW + 120));

    // The documented hash construction, checked independently.
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(format!("{ch}:{counter}").as_bytes());
    assert_eq!(h[0], 0);
    assert_eq!(h[1] & 0b1100_0000, 0);
}

#[test]
fn pow_rejects_wrong_expired_foreign_and_cross_type() {
    let k = keys();
    let ch = pow::issue_challenge(&k, &binding(), NOW, 120, 12);
    let counter = pow::solve(&ch, 1 << 24).unwrap();

    // A counter that does not meet the difficulty.
    let wrong = (0..u64::MAX)
        .find(|c| {
            use sha2::{Digest, Sha256};
            Sha256::digest(format!("{ch}:{c}").as_bytes())[0] != 0
        })
        .unwrap();
    assert_eq!(
        pow::verify_solution(&k, &ch, wrong, &binding(), NOW),
        Err(PowError::WrongSolution)
    );
    assert_eq!(
        pow::verify_solution(&k, &ch, counter, &binding(), NOW + 120),
        Err(PowError::Challenge(TokenError::Expired))
    );
    let thief = Binding::derive(None, ip("198.51.100.1"), None);
    assert_eq!(
        pow::verify_solution(&k, &ch, counter, &thief, NOW),
        Err(PowError::Challenge(TokenError::BindingMismatch))
    );
    let other = Keys::from_secret(OTHER_SECRET).unwrap();
    assert_eq!(
        pow::verify_solution(&other, &ch, counter, &binding(), NOW),
        Err(PowError::Challenge(TokenError::BadSignature))
    );

    // A challenge is not a session token, and a session token is not a challenge.
    assert!(verify(&k, &ch, &binding(), NOW).is_err());
    let session = issue(&k, &binding(), NOW, 600, 5);
    assert!(matches!(
        pow::verify_solution(&k, &session, 0, &binding(), NOW),
        Err(PowError::Challenge(_))
    ));
    for bad in ["", ".", "x", "\u{1F600}"] {
        assert!(pow::verify_solution(&k, bad, 0, &binding(), NOW).is_err());
        assert_eq!(pow::solve(bad, 10), None);
    }
}

#[test]
fn pow_solution_is_single_use_via_budget_store() {
    let k = keys();
    let store = MemoryBudgetStore::new(10);
    let ch = pow::issue_challenge(&k, &binding(), NOW, 120, 8);
    let counter = pow::solve(&ch, 1 << 20).unwrap();
    let s = pow::verify_solution(&k, &ch, counter, &binding(), NOW).unwrap();
    assert!(store.consume(&s.id, 1, s.expires_at, NOW));
    let s2 = pow::verify_solution(&k, &ch, counter, &binding(), NOW).unwrap();
    assert_eq!(s.id, s2.id);
    assert!(!store.consume(&s2.id, 1, s2.expires_at, NOW));

    // Two challenges for the same client differ.
    let ch2 = pow::issue_challenge(&k, &binding(), NOW, 120, 8);
    assert_ne!(ch, ch2);
}

#[test]
fn difficulty_is_clamped_and_scaled() {
    let k = keys();
    for (asked, got) in [(0u8, 8u8), (8, 8), (16, 16), (24, 24), (200, 24)] {
        let ch = pow::issue_challenge(&k, &binding(), NOW, 120, asked);
        if got <= 16 {
            let c = pow::solve(&ch, 1 << 24).unwrap();
            assert_eq!(pow::verify_solution(&k, &ch, c, &binding(), NOW).unwrap().difficulty, got);
        }
    }
    assert_eq!(pow::difficulty_for_score(99), 8);
    assert_eq!(pow::difficulty_for_score(70), 8);
    assert_eq!(pow::difficulty_for_score(69), 14);
    assert_eq!(pow::difficulty_for_score(40), 14);
    assert_eq!(pow::difficulty_for_score(39), 18);
    assert_eq!(pow::difficulty_for_score(20), 18);
    assert_eq!(pow::difficulty_for_score(19), 20);
    assert_eq!(pow::difficulty_for_score(0), 20);
}

#[test]
fn return_to_is_restricted_to_same_origin_paths() {
    for ok in ["/", "/products/42?color=red&size=9", "/a/b#frag", "/%2e%2e/x"] {
        assert_eq!(pow::sanitize_return_to(ok), ok);
    }
    for bad in [
        "",
        "products",
        "//evil.example",
        "/\\evil.example",
        "https://evil.example/",
        "javascript:alert(1)",
        "/ok\r\nSet-Cookie: x=1",
        "/ok\u{0}",
        " /x",
    ] {
        assert_eq!(pow::sanitize_return_to(bad), "/", "{bad:?}");
    }
}

#[test]
fn challenge_page_is_self_contained_and_escaped() {
    let k = keys();
    let ch = pow::issue_challenge(&k, &binding(), NOW, 120, 8);
    let page = pow::challenge_page(&ch, "/products/42?a=1&b=2");
    assert!(page.to_ascii_lowercase().contains("<!doctype html"));
    assert!(page.contains(&ch));
    assert!(page.contains(pow::VERIFY_PATH));
    assert!(page.contains("<noscript"));
    for field in ["challenge", "counter", "return_to"] {
        assert!(page.contains(field), "missing form field {field}");
    }
    // No external resources.
    for needle in ["src=\"http", "src='http", "href=\"http", "href='http", "src=\"//", "@import"] {
        assert!(!page.contains(needle), "external reference: {needle}");
    }

    // Hostile inputs must not appear unescaped anywhere in the page.
    let evil_path = "/x\"><script>alert(1)</script><!--'</script>";
    let page = pow::challenge_page(&ch, evil_path);
    assert!(!page.contains("<script>alert(1)"), "return_to was not escaped");
    assert!(!page.contains("\"><script>"), "return_to broke out of an attribute");

    let evil_challenge = "abc\"</script><script>alert(2)</script>";
    let page = pow::challenge_page(evil_challenge, "/");
    assert!(!page.contains("<script>alert(2)"), "challenge was not escaped");

    // An off-site return target is replaced, not embedded.
    let page = pow::challenge_page(&ch, "https://evil.example/phish");
    assert!(!page.contains("evil.example"));
}
