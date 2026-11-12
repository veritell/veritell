//! Junk signatures, the validity window, and replays.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use veritell_wba::*;

const CREATED: u64 = 1_735_689_600;
const NOW: u64 = CREATED + 100;

fn req<'a>(headers: &'a [(&'a str, &'a str)]) -> RequestParts<'a> {
    RequestParts {
        method: "GET",
        authority: "example.com",
        path: "/",
        query: None,
        headers,
    }
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn keyid(k: &SigningKey) -> String {
    jwk_thumbprint_ed25519(&k.verifying_key().to_bytes())
}

fn trusted(k: &SigningKey) -> TrustedAgents {
    let mut t = TrustedAgents::new();
    t.add("agent", None, vec![Ed25519Key::from_public(k.verifying_key().to_bytes())])
        .unwrap();
    t
}

/// (Signature-Input, Signature) for `components`, signed by `k`.
fn signed(k: &SigningKey, components: &str, expires: u64, nonce: &str) -> (String, String) {
    let member = format!(
        "({components});created={CREATED};expires={expires};keyid=\"{}\";nonce=\"{nonce}\";tag=\"web-bot-auth\"",
        keyid(k)
    );
    let base = signature_base(&req(&[]), &member).unwrap();
    let sig = STANDARD.encode(k.sign(base.as_bytes()).to_bytes());
    (format!("s={member}"), format!("s=:{sig}:"))
}

fn with_sig_bytes(input: &str, bytes: &[u8; 64]) -> (String, String) {
    (input.to_string(), format!("s=:{}:", STANDARD.encode(bytes)))
}

#[test]
fn junk_signature_bytes_are_bad_not_unknown_key() {
    let k = key(1);
    let (input, _) = signed(&k, "\"@authority\"", CREATED + 600, "n");
    for junk in [[0xffu8; 64], [0u8; 64], [0x41u8; 64]] {
        let (input, sig) = with_sig_bytes(&input, &junk);
        let h = [("Signature-Input", input.as_str()), ("Signature", sig.as_str())];
        let v = verify(&req(&h), &TrustedAgents::new(), NOW);
        assert_eq!(v, WbaVerdict::Invalid(WbaInvalid::BadSignature), "{junk:?}");
        assert_eq!(v.detection().unwrap().id, "wba_bad_signature");
    }
}

#[test]
fn non_canonical_s_is_bad() {
    let k = key(1);
    let (input, sig) = signed(&k, "\"@authority\"", CREATED + 600, "n");
    let b64 = sig.trim_start_matches("s=:").trim_end_matches(':');
    let mut bytes: [u8; 64] = STANDARD.decode(b64).unwrap().try_into().unwrap();
    // S set to the group order itself: a valid R, but S out of range.
    let order: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    bytes[32..].copy_from_slice(&order);
    let (input, sig) = with_sig_bytes(&input, &bytes);
    let h = [("Signature-Input", input.as_str()), ("Signature", sig.as_str())];
    assert_eq!(
        verify(&req(&h), &TrustedAgents::new(), NOW),
        WbaVerdict::Invalid(WbaInvalid::BadSignature)
    );
}

#[test]
fn a_real_signature_with_an_untrusted_key_is_still_unknown_key() {
    // The limit that remains: anyone can make a key and sign with it.
    let k = key(2);
    let (input, sig) = signed(&k, "\"@authority\"", CREATED + 600, "n");
    let h = [("Signature-Input", input.as_str()), ("Signature", sig.as_str())];
    assert_eq!(
        verify(&req(&h), &TrustedAgents::new(), NOW),
        WbaVerdict::UnknownKey { keyid: keyid(&k) }
    );
}

#[test]
fn unknown_key_with_a_missing_covered_header_is_malformed() {
    let k = key(1);
    let member = format!(
        "(\"@authority\" \"x-absent\");created={CREATED};expires={};keyid=\"{}\";tag=\"web-bot-auth\"",
        CREATED + 600,
        keyid(&k)
    );
    let (input, sig) = with_sig_bytes(&format!("s={member}"), &k.sign(b"x").to_bytes());
    let h = [("Signature-Input", input.as_str()), ("Signature", sig.as_str())];
    assert_eq!(
        verify(&req(&h), &TrustedAgents::new(), NOW),
        WbaVerdict::Invalid(WbaInvalid::Malformed)
    );
}

#[test]
fn a_day_long_window_is_refused() {
    assert_eq!(MAX_WINDOW_SECS, 3_600);
    let k = key(1);
    let (input, sig) = signed(&k, "\"@authority\"", CREATED + 86_400, "n");
    let h = [("Signature-Input", input.as_str()), ("Signature", sig.as_str())];
    assert_eq!(
        verify(&req(&h), &trusted(&k), NOW),
        WbaVerdict::Invalid(WbaInvalid::WindowTooLong)
    );
}

#[test]
fn replay_cache_refuses_a_second_use_until_expiry() {
    let k = key(1);
    let t = trusted(&k);
    let expires = CREATED + 600;
    let (input, sig) = signed(&k, "\"@authority\"", expires, "n1");
    let h = [("Signature-Input", input.as_str()), ("Signature", sig.as_str())];
    assert!(matches!(verify(&req(&h), &t, NOW), WbaVerdict::Verified { .. }));
    let info = signature_info(&req(&h)).unwrap();
    assert_eq!(info.expires, expires);
    assert!(info.covers("@authority"));
    assert!(!info.covers("@method") && !info.covers("@path"));

    let mut cache = ReplayCache::new(16);
    assert!(cache.first_use(&info, NOW));
    assert!(!cache.first_use(&info, NOW + 1));
    // Still refused at the last moment verify accepts it.
    assert!(!cache.first_use(&info, expires + CLOCK_SKEW_SECS));
    // Forgotten once verify would refuse it anyway.
    assert!(cache.first_use(&info, expires + CLOCK_SKEW_SECS + 1));

    // A fresh nonce is a fresh signature.
    let (input2, sig2) = signed(&k, "\"@authority\"", expires, "n2");
    let h2 = [("Signature-Input", input2.as_str()), ("Signature", sig2.as_str())];
    let info2 = signature_info(&req(&h2)).unwrap();
    assert_ne!(info.replay_id, info2.replay_id);
    assert!(cache.first_use(&info2, NOW));
}

#[test]
fn replay_cache_is_bounded() {
    let mut cache = ReplayCache::new(4);
    for i in 0..100u8 {
        let info = SignatureInfo {
            replay_id: [i; 32],
            expires: NOW + u64::from(i),
            components: vec!["@authority".into()],
        };
        assert!(cache.first_use(&info, NOW));
        assert!(cache.len() <= 4);
    }
    // The newest are kept, the soonest to expire were dropped.
    let last = SignatureInfo {
        replay_id: [99; 32],
        expires: NOW + 99,
        components: vec![],
    };
    assert!(!cache.first_use(&last, NOW));
}

#[test]
fn signature_info_lists_method_and_path_when_covered() {
    let k = key(1);
    let (input, sig) = signed(
        &k,
        "\"@method\" \"@path\" \"@authority\"",
        CREATED + 600,
        "n",
    );
    let h = [("Signature-Input", input.as_str()), ("Signature", sig.as_str())];
    assert!(matches!(verify(&req(&h), &trusted(&k), NOW), WbaVerdict::Verified { .. }));
    let info = signature_info(&req(&h)).unwrap();
    assert_eq!(info.components, vec!["@method", "@path", "@authority"]);
    assert!(signature_info(&req(&[])).is_none());
}
