//! Acceptance tests written by the project lead. DO NOT EDIT.
//!
//! Vectors are copied from RFC 9421 (appendix B.1.4 and B.2.6) and from
//! draft-meunier-web-bot-auth-architecture-02 (appendix A.2). Other cases are
//! signed here with the RFC's published Ed25519 test key.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use veritell_core::{Class, Layer};
use veritell_wba::*;

/// RFC 9421 B.1.4, JWK form.
const RFC_KEY_D: &str = "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU";
const RFC_KEY_X: &str = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs";
/// Thumbprint of that key as used in the Web Bot Auth draft's vectors.
const DRAFT_KEYID: &str = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";

const CREATED: u64 = 1_735_689_600;
const EXPIRES: u64 = 1_735_693_200;
const NOW: u64 = CREATED + 100;

const A21_INPUT: &str = "sig1=(\"@authority\");created=1735689600;keyid=\"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U\";alg=\"ed25519\";expires=1735693200;nonce=\"mYotfW3CUjI68sbGw6oKd7kyXqPjZEtU8xFPGWFrqOAf5qC6MDe3pys3SWWCudB0MvwslHy32WXUpkR7u0lt/w==\";tag=\"web-bot-auth\"";
const A21_SIG: &str = "sig1=:+NA/cssf4Y2bQTMTkyvTGRCaVzp9quyUevdwwMtMOWhhOOZ2T1subBj0BtvdnrpDEuwSAbiTeElXDzHL3WWKCw==:";

const A22_AGENT: &str = "\"https://signature-agent.test\"";
const A22_INPUT: &str = "sig2=(\"@authority\" \"signature-agent\");created=1735689600;keyid=\"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U\";alg=\"ed25519\";expires=1735693200;nonce=\"e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg==\";tag=\"web-bot-auth\"";
const A22_SIG: &str = "sig2=:jdq0SqOwHdyHr9+r5jw3iYZH6aNGKijYp/EstF4RQTQdi5N5YYKrD+mCT1HA1nZDsi6nJKuHxUi/5Syp3rLWBA==:";

fn rfc_public() -> [u8; 32] {
    URL_SAFE_NO_PAD.decode(RFC_KEY_X).unwrap().try_into().unwrap()
}

fn rfc_signing_key() -> SigningKey {
    let d: [u8; 32] = URL_SAFE_NO_PAD.decode(RFC_KEY_D).unwrap().try_into().unwrap();
    SigningKey::from_bytes(&d)
}

fn trusted(signature_agent: Option<&str>) -> TrustedAgents {
    let mut t = TrustedAgents::new();
    t.add("test-agent", signature_agent, vec![Ed25519Key::from_public(rfc_public())])
        .unwrap();
    t
}

fn req<'a>(headers: &'a [(&'a str, &'a str)]) -> RequestParts<'a> {
    RequestParts {
        method: "GET",
        authority: "example.com",
        path: "/",
        query: None,
        headers,
    }
}

fn verified() -> WbaVerdict {
    WbaVerdict::Verified {
        agent: "test-agent".to_string(),
        keyid: DRAFT_KEYID.to_string(),
    }
}

/// Signs `base` with the RFC key and returns the `:base64:` byte sequence.
fn sign(base: &str) -> String {
    format!(":{}:", STANDARD.encode(rfc_signing_key().sign(base.as_bytes()).to_bytes()))
}

/// Parameters for a signature made by this test file.
fn params(extra: &str) -> String {
    format!(";created={CREATED};expires={EXPIRES};keyid=\"{DRAFT_KEYID}\"{extra};tag=\"web-bot-auth\"")
}

// ---------- published vectors ----------

#[test]
fn thumbprint_matches_the_draft() {
    assert_eq!(jwk_thumbprint_ed25519(&rfc_public()), DRAFT_KEYID);
    assert_eq!(Ed25519Key::from_public(rfc_public()).keyid, DRAFT_KEYID);
}

#[test]
fn rfc9421_b26_signature_base_is_exact() {
    let headers = [
        ("Host", "example.com"),
        ("Date", "Tue, 20 Apr 2021 02:07:55 GMT"),
        ("Content-Type", "application/json"),
        ("Content-Digest", "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"),
        ("Content-Length", "18"),
    ];
    let r = RequestParts {
        method: "POST",
        authority: "example.com",
        path: "/foo",
        query: Some("param=Value&Pet=dog"),
        headers: &headers,
    };
    let member = "(\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\");created=1618884473;keyid=\"test-key-ed25519\"";
    let expected = "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\
\"@method\": POST\n\
\"@path\": /foo\n\
\"@authority\": example.com\n\
\"content-type\": application/json\n\
\"content-length\": 18\n\
\"@signature-params\": (\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\");created=1618884473;keyid=\"test-key-ed25519\"";
    let base = signature_base(&r, member).unwrap();
    assert_eq!(base, expected);

    // The RFC's own signature verifies over that base, which shows the
    // vector was copied correctly.
    let sig = STANDARD
        .decode("wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==")
        .unwrap();
    let sig = ed25519_dalek::Signature::from_slice(&sig).unwrap();
    VerifyingKey::from_bytes(&rfc_public())
        .unwrap()
        .verify(base.as_bytes(), &sig)
        .unwrap();
}

#[test]
fn draft_vector_without_signature_agent_verifies() {
    let h = [("Signature-Input", A21_INPUT), ("Signature", A21_SIG)];
    assert_eq!(verify(&req(&h), &trusted(None), NOW), verified());
}

#[test]
fn draft_vector_with_signature_agent_verifies() {
    let h = [
        ("Signature-Agent", A22_AGENT),
        ("Signature-Input", A22_INPUT),
        ("Signature", A22_SIG),
    ];
    assert_eq!(verify(&req(&h), &trusted(None), NOW), verified());
    assert_eq!(
        verify(&req(&h), &trusted(Some("https://signature-agent.test")), NOW),
        verified()
    );
}

#[test]
fn header_names_and_authority_are_case_insensitive() {
    let h = [("signature-input", A21_INPUT), ("SIGNATURE", A21_SIG)];
    let mut r = req(&h);
    r.authority = "Example.COM";
    assert_eq!(verify(&r, &trusted(None), NOW), verified());
}

// ---------- rejection ----------

#[test]
fn no_signature_is_absent() {
    assert_eq!(verify(&req(&[]), &trusted(None), NOW), WbaVerdict::Absent);
    assert_eq!(
        verify(&req(&[("User-Agent", "curl/8")]), &trusted(None), NOW),
        WbaVerdict::Absent
    );
}

#[test]
fn a_signature_with_another_tag_is_absent() {
    let input = "sig1=(\"@authority\");created=1735689600;keyid=\"k\";expires=1735693200;tag=\"something-else\"";
    let h = [("Signature-Input", input), ("Signature", A21_SIG)];
    assert_eq!(verify(&req(&h), &trusted(None), NOW), WbaVerdict::Absent);

    let untagged = "sig1=(\"@authority\");created=1735689600;keyid=\"k\"";
    let h = [("Signature-Input", untagged), ("Signature", A21_SIG)];
    assert_eq!(verify(&req(&h), &trusted(None), NOW), WbaVerdict::Absent);
}

#[test]
fn changed_authority_fails() {
    let h = [("Signature-Input", A21_INPUT), ("Signature", A21_SIG)];
    let mut r = req(&h);
    r.authority = "evil.example";
    assert_eq!(
        verify(&r, &trusted(None), NOW),
        WbaVerdict::Invalid(WbaInvalid::BadSignature)
    );
}

#[test]
fn changed_signature_fails() {
    let flipped = A21_SIG.replacen("+NA/", "+NB/", 1);
    let h = [("Signature-Input", A21_INPUT), ("Signature", flipped.as_str())];
    assert_eq!(
        verify(&req(&h), &trusted(None), NOW),
        WbaVerdict::Invalid(WbaInvalid::BadSignature)
    );
}

#[test]
fn changed_signature_agent_fails() {
    let h = [
        ("Signature-Agent", "\"https://other.test\""),
        ("Signature-Input", A22_INPUT),
        ("Signature", A22_SIG),
    ];
    assert_eq!(
        verify(&req(&h), &trusted(None), NOW),
        WbaVerdict::Invalid(WbaInvalid::BadSignature)
    );
}

#[test]
fn signature_agent_must_match_the_configured_one() {
    let h = [
        ("Signature-Agent", A22_AGENT),
        ("Signature-Input", A22_INPUT),
        ("Signature", A22_SIG),
    ];
    assert_eq!(
        verify(&req(&h), &trusted(Some("https://someone-else.test")), NOW),
        WbaVerdict::Invalid(WbaInvalid::AgentMismatch)
    );
}

#[test]
fn signature_agent_header_must_be_covered() {
    // The A.2.1 signature does not cover signature-agent.
    let h = [
        ("Signature-Agent", A22_AGENT),
        ("Signature-Input", A21_INPUT),
        ("Signature", A21_SIG),
    ];
    assert_eq!(
        verify(&req(&h), &trusted(None), NOW),
        WbaVerdict::Invalid(WbaInvalid::SignatureAgentUnsigned)
    );
}

#[test]
fn time_window_is_enforced_with_skew() {
    let h = [("Signature-Input", A21_INPUT), ("Signature", A21_SIG)];
    let t = trusted(None);
    assert_eq!(verify(&req(&h), &t, EXPIRES + CLOCK_SKEW_SECS), verified());
    assert_eq!(
        verify(&req(&h), &t, EXPIRES + CLOCK_SKEW_SECS + 1),
        WbaVerdict::Invalid(WbaInvalid::Expired)
    );
    assert_eq!(verify(&req(&h), &t, CREATED - CLOCK_SKEW_SECS), verified());
    assert_eq!(
        verify(&req(&h), &t, CREATED - CLOCK_SKEW_SECS - 1),
        WbaVerdict::Invalid(WbaInvalid::NotYetValid)
    );
}

#[test]
fn unknown_key_is_reported_with_its_id() {
    let h = [("Signature-Input", A21_INPUT), ("Signature", A21_SIG)];
    assert_eq!(
        verify(&req(&h), &TrustedAgents::new(), NOW),
        WbaVerdict::UnknownKey {
            keyid: DRAFT_KEYID.to_string()
        }
    );
}

#[test]
fn key_validity_is_enforced() {
    let h = [("Signature-Input", A21_INPUT), ("Signature", A21_SIG)];
    for (nbf, exp) in [(None, Some(NOW - 1)), (Some(NOW + 1), None)] {
        let mut key = Ed25519Key::from_public(rfc_public());
        key.not_before = nbf;
        key.not_after = exp;
        let mut t = TrustedAgents::new();
        t.add("test-agent", None, vec![key]).unwrap();
        assert_eq!(
            verify(&req(&h), &t, NOW),
            WbaVerdict::Invalid(WbaInvalid::KeyExpired)
        );
    }
    let mut key = Ed25519Key::from_public(rfc_public());
    key.not_before = Some(NOW);
    key.not_after = Some(NOW);
    let mut t = TrustedAgents::new();
    t.add("test-agent", None, vec![key]).unwrap();
    assert_eq!(verify(&req(&h), &t, NOW), verified());
}

// ---------- cases signed here ----------

/// Builds headers for a signature over `@authority` only, with the given
/// parameter string, and returns (Signature-Input, Signature).
fn signed_authority(label: &str, params: &str) -> (String, String) {
    let member = format!("(\"@authority\"){params}");
    let base = format!("\"@authority\": example.com\n\"@signature-params\": {member}");
    (format!("{label}={member}"), format!("{label}={}", sign(&base)))
}

#[test]
fn a_locally_signed_request_verifies() {
    let (input, sig) = signed_authority("s", &params(""));
    let h = [("Signature-Input", input.as_str()), ("Signature", sig.as_str())];
    assert_eq!(verify(&req(&h), &trusted(None), NOW), verified());
}

#[test]
fn the_tagged_member_is_found_among_others() {
    let (input, sig) = signed_authority("bot", &params(""));
    let input = format!(
        "other=(\"@method\" \"x, y\");created=1;keyid=\"a,b=(c)\";tag=\"not-ours\", {input}"
    );
    let sig = format!("other=:AAAA:, {sig}");
    let h = [("Signature-Input", input.as_str()), ("Signature", sig.as_str())];
    assert_eq!(verify(&req(&h), &trusted(None), NOW), verified());
}

#[test]
fn more_components_verify() {
    let member = format!(
        "(\"@authority\" \"@method\" \"@path\" \"@query\" \"x-test\"){}",
        params("")
    );
    let base = format!(
        "\"@authority\": example.com\n\"@method\": GET\n\"@path\": /a/b\n\"@query\": ?q=1&r=2\n\"x-test\": one, two\n\"@signature-params\": {member}"
    );
    let input = format!("s={member}");
    let sig = format!("s={}", sign(&base));
    let h = [
        ("X-Test", "  one "),
        ("Signature-Input", input.as_str()),
        ("x-test", "two"),
        ("Signature", sig.as_str()),
    ];
    let r = RequestParts {
        method: "GET",
        authority: "example.com",
        path: "/a/b",
        query: Some("q=1&r=2"),
        headers: &h,
    };
    assert_eq!(verify(&r, &trusted(None), NOW), verified());

    // Without a query string the component value is a lone "?".
    let r2 = RequestParts { query: None, ..r };
    assert_eq!(
        signature_base(&r2, "(\"@query\");created=1").unwrap(),
        "\"@query\": ?\n\"@signature-params\": (\"@query\");created=1"
    );
}

#[test]
fn authority_must_be_covered() {
    let member = format!("(\"@method\"){}", params(""));
    let base = format!("\"@method\": GET\n\"@signature-params\": {member}");
    let input = format!("s={member}");
    let sig = format!("s={}", sign(&base));
    let h = [("Signature-Input", input.as_str()), ("Signature", sig.as_str())];
    assert_eq!(
        verify(&req(&h), &trusted(None), NOW),
        WbaVerdict::Invalid(WbaInvalid::MissingAuthority)
    );
}

#[test]
fn required_parameters_must_be_present() {
    for p in [
        format!(";created={CREATED};keyid=\"{DRAFT_KEYID}\";tag=\"web-bot-auth\""),
        format!(";expires={EXPIRES};keyid=\"{DRAFT_KEYID}\";tag=\"web-bot-auth\""),
        format!(";created={CREATED};expires={EXPIRES};tag=\"web-bot-auth\""),
    ] {
        let (input, sig) = signed_authority("s", &p);
        let h = [("Signature-Input", input.as_str()), ("Signature", sig.as_str())];
        assert_eq!(
            verify(&req(&h), &trusted(None), NOW),
            WbaVerdict::Invalid(WbaInvalid::MissingParams),
            "{p}"
        );
    }
}

#[test]
fn window_limits() {
    let too_long = format!(
        ";created={CREATED};expires={};keyid=\"{DRAFT_KEYID}\";tag=\"web-bot-auth\"",
        CREATED + MAX_WINDOW_SECS + 1
    );
    let inverted = format!(
        ";created={CREATED};expires={CREATED};keyid=\"{DRAFT_KEYID}\";tag=\"web-bot-auth\""
    );
    for p in [too_long, inverted] {
        let (input, sig) = signed_authority("s", &p);
        let h = [("Signature-Input", input.as_str()), ("Signature", sig.as_str())];
        assert_eq!(
            verify(&req(&h), &trusted(None), CREATED),
            WbaVerdict::Invalid(WbaInvalid::WindowTooLong),
            "{p}"
        );
    }
    let longest = format!(
        ";created={CREATED};expires={};keyid=\"{DRAFT_KEYID}\";tag=\"web-bot-auth\"",
        CREATED + MAX_WINDOW_SECS
    );
    let (input, sig) = signed_authority("s", &longest);
    let h = [("Signature-Input", input.as_str()), ("Signature", sig.as_str())];
    assert_eq!(verify(&req(&h), &trusted(None), CREATED), verified());
}

#[test]
fn other_algorithms_are_refused() {
    let (input, sig) = signed_authority("s", &params(";alg=\"rsa-pss-sha512\""));
    let h = [("Signature-Input", input.as_str()), ("Signature", sig.as_str())];
    assert_eq!(
        verify(&req(&h), &trusted(None), NOW),
        WbaVerdict::Invalid(WbaInvalid::UnsupportedAlg)
    );
}

#[test]
fn unsupported_components_are_refused() {
    for inner in [
        "(\"@authority\" \"@query-param\";name=\"q\")",
        "(\"@authority\" \"x-test\";sf)",
    ] {
        let member = format!("{inner}{}", params(""));
        let input = format!("s={member}");
        let h = [
            ("X-Test", "1"),
            ("Signature-Input", input.as_str()),
            ("Signature", A21_SIG.replacen("sig1", "s", 1).leak() as &str),
        ];
        assert_eq!(
            verify(&req(&h), &trusted(None), NOW),
            WbaVerdict::Invalid(WbaInvalid::UnsupportedComponent),
            "{inner}"
        );
    }
}

#[test]
fn a_covered_header_that_is_absent_is_malformed() {
    let member = format!("(\"@authority\" \"x-missing\"){}", params(""));
    let input = format!("s={member}");
    let sig = A21_SIG.replacen("sig1", "s", 1);
    let h = [("Signature-Input", input.as_str()), ("Signature", sig.as_str())];
    assert_eq!(
        verify(&req(&h), &trusted(None), NOW),
        WbaVerdict::Invalid(WbaInvalid::Malformed)
    );
}

#[test]
fn signature_member_problems_are_malformed() {
    let (input, sig) = signed_authority("s", &params(""));
    let cases = [
        // No Signature header at all.
        vec![("Signature-Input", input.clone())],
        // Label does not match.
        vec![("Signature-Input", input.clone()), ("Signature", sig.replacen("s=", "t=", 1))],
        // Not 64 bytes.
        vec![("Signature-Input", input.clone()), ("Signature", "s=:AAAA:".to_string())],
        // Not a byte sequence.
        vec![("Signature-Input", input.clone()), ("Signature", "s=\"hello\"".to_string())],
        // Not base64.
        vec![("Signature-Input", input.clone()), ("Signature", "s=:!!!!:".to_string())],
    ];
    for case in cases {
        let h: Vec<(&str, &str)> = case.iter().map(|(k, v)| (*k, v.as_str())).collect();
        assert_eq!(
            verify(&req(&h), &trusted(None), NOW),
            WbaVerdict::Invalid(WbaInvalid::Malformed),
            "{case:?}"
        );
    }
}

#[test]
fn oversized_values_are_malformed() {
    let pad = "a".repeat(MAX_HEADER_BYTES);
    let (input, sig) = signed_authority("s", &params(&format!(";nonce=\"{pad}\"")));
    let h = [("Signature-Input", input.as_str()), ("Signature", sig.as_str())];
    assert_eq!(
        verify(&req(&h), &trusted(None), NOW),
        WbaVerdict::Invalid(WbaInvalid::Malformed)
    );

    let long_id = "k".repeat(MAX_KEYID_BYTES + 1);
    let p = format!(";created={CREATED};expires={EXPIRES};keyid=\"{long_id}\";tag=\"web-bot-auth\"");
    let (input, sig) = signed_authority("s", &p);
    let h = [("Signature-Input", input.as_str()), ("Signature", sig.as_str())];
    assert_eq!(
        verify(&req(&h), &trusted(None), NOW),
        WbaVerdict::Invalid(WbaInvalid::Malformed)
    );
}

#[test]
fn too_many_or_duplicate_components_are_malformed() {
    let many: Vec<String> = (0..=MAX_COMPONENTS).map(|i| format!("\"x-h{i}\"")).collect();
    let member = format!("({});created=1", many.join(" "));
    let r = req(&[]);
    assert_eq!(signature_base(&r, &member), Err(WbaInvalid::Malformed));
    assert_eq!(
        signature_base(&r, "(\"@authority\" \"@authority\");created=1"),
        Err(WbaInvalid::Malformed)
    );
}

#[test]
fn garbage_never_panics_and_never_verifies() {
    let t = trusted(None);
    let garbage = [
        "",
        "=",
        "sig1",
        "sig1=",
        "sig1=(",
        "sig1=((((;tag=\"web-bot-auth\"",
        "sig1=(\"@authority\";tag=\"web-bot-auth\"",
        "sig1=(\"@authority\");created=abc;expires=1;keyid=\"k\";tag=\"web-bot-auth\"",
        "sig1=(\"@authority\");created=99999999999999999999999999;expires=1;keyid=\"k\";tag=\"web-bot-auth\"",
        "sig1=(\"@authority\");created=-5;expires=-1;keyid=\"k\";tag=\"web-bot-auth\"",
        "sig1=(\"@authority\");keyid=\"unterminated;tag=\"web-bot-auth\"",
        "\u{0}\u{1}web-bot-auth\u{7f}",
        "sig1=(\"@authority\");tag=\"web-bot-auth\";tag=\"web-bot-auth\";;;;",
        ",,,,,",
        "é=(\"@authority\");tag=\"web-bot-auth\"",
    ];
    for g in garbage {
        for sig in ["", A21_SIG, "sig1=::", "sig1=:", ":"] {
            let h = [("Signature-Input", g), ("Signature", sig)];
            let v = verify(&req(&h), &t, NOW);
            assert!(!matches!(v, WbaVerdict::Verified { .. }), "{g:?} verified");
            let _ = signature_base(&req(&h), g);
        }
    }

    // Every proper prefix of a valid header, and every single-character
    // deletion, must fail without panicking.
    let chars: Vec<char> = A21_INPUT.chars().collect();
    for cut in 0..chars.len() {
        let prefix: String = chars[..cut].iter().collect();
        let deleted: String = chars[..cut].iter().chain(chars[cut + 1..].iter()).collect();
        for candidate in [prefix, deleted] {
            let h = [("Signature-Input", candidate.as_str()), ("Signature", A21_SIG)];
            let v = verify(&req(&h), &t, NOW);
            assert!(
                !matches!(v, WbaVerdict::Verified { .. }),
                "{candidate:?} verified"
            );
        }
    }
}

#[test]
fn a_broken_header_that_mentions_the_tag_is_malformed_not_absent() {
    let h = [("Signature-Input", "sig1=((((;tag=\"web-bot-auth\""), ("Signature", A21_SIG)];
    assert_eq!(
        verify(&req(&h), &trusted(None), NOW),
        WbaVerdict::Invalid(WbaInvalid::Malformed)
    );
    let h = [("Signature-Input", "sig1=((((;tag=\"other\""), ("Signature", A21_SIG)];
    assert_eq!(verify(&req(&h), &trusted(None), NOW), WbaVerdict::Absent);
}

// ---------- directories and trust ----------

#[test]
fn directory_parsing() {
    let json = format!(
        r#"{{"keys":[
            {{"kty":"RSA","n":"abc","e":"AQAB"}},
            {{"kty":"OKP","crv":"Ed25519","kid":"ignored","x":"{RFC_KEY_X}","nbf":100,"exp":200,"use":"sig"}},
            {{"kty":"OKP","crv":"X25519","x":"{RFC_KEY_X}"}}
        ]}}"#
    );
    let keys = parse_directory(&json).unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].keyid, DRAFT_KEYID);
    assert_eq!(keys[0].public, rfc_public());
    assert_eq!((keys[0].not_before, keys[0].not_after), (Some(100), Some(200)));

    assert_eq!(parse_directory(r#"{"keys":[]}"#).unwrap(), vec![]);
    assert!(matches!(parse_directory("not json"), Err(WbaError::Json(_))));
    assert!(matches!(parse_directory(r#"{"nokeys":1}"#), Err(WbaError::Json(_))));
    assert!(matches!(
        parse_directory(r#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"AAAA"}]}"#),
        Err(WbaError::BadKey(_))
    ));
    assert!(matches!(
        parse_directory(r#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"***"}]}"#),
        Err(WbaError::BadKey(_))
    ));

    let one = format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{RFC_KEY_X}"}}"#);
    let many = vec![one; MAX_KEYS + 1].join(",");
    assert_eq!(
        parse_directory(&format!(r#"{{"keys":[{many}]}}"#)),
        Err(WbaError::TooManyKeys)
    );
}

#[test]
fn trusted_agents_file() {
    let json = format!(
        r#"{{"agents":[{{"name":"test-agent","signature_agent":"https://signature-agent.test",
            "keys":[{{"kty":"OKP","crv":"Ed25519","x":"{RFC_KEY_X}"}}]}}]}}"#
    );
    let t = TrustedAgents::from_json(&json).unwrap();
    assert_eq!(t.len(), 1);
    assert!(!t.is_empty());
    let h = [
        ("Signature-Agent", A22_AGENT),
        ("Signature-Input", A22_INPUT),
        ("Signature", A22_SIG),
    ];
    assert_eq!(verify(&req(&h), &t, NOW), verified());

    assert!(TrustedAgents::new().is_empty());
    assert!(matches!(TrustedAgents::from_json("{"), Err(WbaError::Json(_))));
    assert!(matches!(
        TrustedAgents::from_json(r#"{"agents":[{"name":"x","keys":[]}]}"#),
        Err(WbaError::BadAgent(_))
    ));
    assert!(matches!(
        TrustedAgents::from_json(&format!(
            r#"{{"agents":[{{"name":"","keys":[{{"kty":"OKP","crv":"Ed25519","x":"{RFC_KEY_X}"}}]}}]}}"#
        )),
        Err(WbaError::BadAgent(_))
    ));
}

#[test]
fn one_key_cannot_belong_to_two_agents() {
    let mut t = TrustedAgents::new();
    t.add("a", None, vec![Ed25519Key::from_public(rfc_public())]).unwrap();
    assert!(matches!(
        t.add("b", None, vec![Ed25519Key::from_public(rfc_public())]),
        Err(WbaError::BadAgent(_))
    ));
    assert!(matches!(t.add("", None, vec![]), Err(WbaError::BadAgent(_))));
    assert_eq!(t.len(), 1);
}

// ---------- detections ----------

#[test]
fn detections() {
    assert_eq!(WbaVerdict::Absent.detection(), None);
    assert_eq!(verified().detection(), None);

    let d = WbaVerdict::UnknownKey { keyid: "k".into() }.detection().unwrap();
    assert_eq!(
        (d.id.as_str(), d.layer, d.penalty, d.class_hint),
        ("wba_unknown_key", Layer::Identity, 20, Some(Class::UnverifiedAgent))
    );

    for r in [
        WbaInvalid::BadSignature,
        WbaInvalid::AgentMismatch,
        WbaInvalid::SignatureAgentUnsigned,
    ] {
        let d = WbaVerdict::Invalid(r).detection().unwrap();
        assert_eq!(
            (d.id.as_str(), d.layer, d.penalty, d.class_hint),
            ("wba_bad_signature", Layer::Identity, 70, Some(Class::Malicious)),
            "{r:?}"
        );
    }
    for r in [
        WbaInvalid::Expired,
        WbaInvalid::NotYetValid,
        WbaInvalid::WindowTooLong,
        WbaInvalid::KeyExpired,
    ] {
        let d = WbaVerdict::Invalid(r).detection().unwrap();
        assert_eq!(
            (d.id.as_str(), d.penalty, d.class_hint),
            ("wba_expired", 30, Some(Class::UnverifiedAgent)),
            "{r:?}"
        );
    }
    for r in [
        WbaInvalid::Malformed,
        WbaInvalid::MissingAuthority,
        WbaInvalid::MissingParams,
        WbaInvalid::UnsupportedAlg,
        WbaInvalid::UnsupportedComponent,
    ] {
        let d = WbaVerdict::Invalid(r).detection().unwrap();
        assert_eq!(
            (d.id.as_str(), d.penalty, d.class_hint),
            ("wba_malformed", 30, Some(Class::UnverifiedAgent)),
            "{r:?}"
        );
    }
}

#[test]
fn a_long_key_id_in_an_unknown_key_verdict_is_bounded() {
    let id = "k".repeat(MAX_KEYID_BYTES);
    let p = format!(";created={CREATED};expires={EXPIRES};keyid=\"{id}\";tag=\"web-bot-auth\"");
    let (input, sig) = signed_authority("s", &p);
    let h = [("Signature-Input", input.as_str()), ("Signature", sig.as_str())];
    assert_eq!(
        verify(&req(&h), &trusted(None), NOW),
        WbaVerdict::UnknownKey { keyid: id }
    );
}
