//! The request target in a signature: `@request-target` and `@target-uri`
//! (RFC 9421, sections 2.2.5 and 2.2.2), and the replay cache's save and
//! restore.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use veritell_wba::*;

const CREATED: u64 = 1_735_689_600;
const NOW: u64 = CREATED + 100;

fn req<'a>(path: &'a str, query: Option<&'a str>, headers: &'a [(&'a str, &'a str)]) -> RequestParts<'a> {
    RequestParts { method: "POST", authority: "Shop.Example", path, query, headers }
}

fn key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

fn trusted(k: &SigningKey) -> TrustedAgents {
    let mut t = TrustedAgents::new();
    t.add("agent", None, vec![Ed25519Key::from_public(k.verifying_key().to_bytes())]).unwrap();
    t
}

/// (Signature-Input, Signature) over `components` for the request at `path` and `query`.
fn signed(k: &SigningKey, components: &str, path: &str, query: Option<&str>) -> (String, String) {
    let member = format!(
        "({components});created={CREATED};expires={};keyid=\"{}\";tag=\"web-bot-auth\"",
        CREATED + 600,
        jwk_thumbprint_ed25519(&k.verifying_key().to_bytes())
    );
    let base = signature_base(&req(path, query, &[]), &member).unwrap();
    let sig = STANDARD.encode(k.sign(base.as_bytes()).to_bytes());
    (format!("s={member}"), format!("s=:{sig}:"))
}

#[test]
fn the_derived_target_values() {
    let base = |path, query| {
        signature_base(&req(path, query, &[]), "(\"@request-target\" \"@target-uri\");created=1").unwrap()
    };
    assert_eq!(
        base("/cart/add", Some("a=1&b=2")),
        "\"@request-target\": /cart/add?a=1&b=2\n\"@target-uri\": https://shop.example/cart/add?a=1&b=2\n\"@signature-params\": (\"@request-target\" \"@target-uri\");created=1"
    );
    assert!(base("", None).starts_with("\"@request-target\": /\n\"@target-uri\": https://shop.example/\n"));
    // An empty query keeps its `?`, as the request line would.
    assert!(base("/x", Some("")).starts_with("\"@request-target\": /x?\n"));
}

#[test]
fn a_signature_over_the_target_verifies_and_binds_it() {
    let k = key();
    for components in ["\"@authority\" \"@method\" \"@request-target\"", "\"@authority\" \"@method\" \"@target-uri\""] {
        let (input, sig) = signed(&k, components, "/cart/add", Some("id=4"));
        let h = [("Signature-Input", input.as_str()), ("Signature", sig.as_str())];
        assert!(
            matches!(verify(&req("/cart/add", Some("id=4"), &h), &trusted(&k), NOW), WbaVerdict::Verified { .. }),
            "{components}"
        );
        // Another path or another query breaks it.
        for (path, query) in [("/cart/remove", Some("id=4")), ("/cart/add", Some("id=5")), ("/cart/add", None)] {
            assert_eq!(
                verify(&req(path, query, &h), &trusted(&k), NOW),
                WbaVerdict::Invalid(WbaInvalid::BadSignature),
                "{components} on {path}?{query:?}"
            );
        }
        let info = signature_info(&req("/cart/add", Some("id=4"), &h)).unwrap();
        assert!(info.components.iter().any(|c| c == "@request-target" || c == "@target-uri"));
    }
}

#[test]
fn the_replay_cache_is_saved_and_restored() {
    let k = key();
    let (input, sig) = signed(&k, "\"@authority\"", "/", None);
    let h = [("Signature-Input", input.as_str()), ("Signature", sig.as_str())];
    let info = signature_info(&req("/", None, &h)).unwrap();

    let mut cache = ReplayCache::new(10);
    assert!(cache.first_use(&info, NOW));
    let saved = cache.entries(NOW);
    assert_eq!(saved.len(), 1);

    // A new process: the restored cache refuses the same signature.
    let mut after = ReplayCache::new(10);
    for (id, until) in &saved {
        after.restore(*id, *until, NOW + 5);
    }
    assert!(!after.first_use(&info, NOW + 5));
    // Past its time it is neither saved nor restored.
    let until = saved[0].1;
    assert!(cache.entries(until + 1).is_empty());
    let mut late = ReplayCache::new(10);
    late.restore(saved[0].0, until, until + 1);
    assert!(late.is_empty());
    // Restoring keeps the capacity.
    let mut small = ReplayCache::new(2);
    for n in 0..5u8 {
        small.restore([n; 32], NOW + 100 + u64::from(n), NOW);
    }
    assert_eq!(small.len(), 2);
    assert_eq!(small.entries(NOW).iter().map(|e| e.1).collect::<Vec<_>>(), vec![NOW + 103, NOW + 104]);
}
