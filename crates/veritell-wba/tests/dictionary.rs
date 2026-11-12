//! Acceptance tests written by the project lead. DO NOT EDIT.
//!
//! `Signature-Agent` as a dictionary, covered with the `key` parameter:
//! draft-ietf-webbotauth-httpsig-protocol-01, section 5.2.1. The vector is
//! that draft's appendix E.2.1; everything else is signed here with the
//! Ed25519 test key of RFC 9421 B.1.4.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use veritell_wba::*;

const RFC_KEY_D: &str = "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU";
const RFC_KEY_X: &str = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs";
const DRAFT_KEYID: &str = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";

const CREATED: u64 = 1_735_689_600;
const EXPIRES: u64 = 1_735_693_200;
const NOW: u64 = CREATED + 100;

fn rfc_public() -> [u8; 32] {
    URL_SAFE_NO_PAD.decode(RFC_KEY_X).unwrap().try_into().unwrap()
}

fn sign(base: &str) -> String {
    let d: [u8; 32] = URL_SAFE_NO_PAD.decode(RFC_KEY_D).unwrap().try_into().unwrap();
    format!(":{}:", STANDARD.encode(SigningKey::from_bytes(&d).sign(base.as_bytes()).to_bytes()))
}

fn trusted(signature_agent: Option<&str>) -> TrustedAgents {
    let mut t = TrustedAgents::new();
    t.add("test-agent", signature_agent, vec![Ed25519Key::from_public(rfc_public())]).unwrap();
    t
}

fn req<'a>(headers: &'a [(&'a str, &'a str)]) -> RequestParts<'a> {
    RequestParts { method: "GET", authority: "example.com", path: "/", query: None, headers }
}

fn verified() -> WbaVerdict {
    WbaVerdict::Verified { agent: "test-agent".to_string(), keyid: DRAFT_KEYID.to_string() }
}

fn params() -> String {
    format!(";created={CREATED};expires={EXPIRES};keyid=\"{DRAFT_KEYID}\";tag=\"web-bot-auth\"")
}

/// A request signed under `label`, covering `@authority` and `agent_component`
/// (written as it goes into Signature-Input), where `agent_line` is what the
/// signer believes the value of that component to be.
/// Returns the Signature-Input and Signature header values.
fn signed(label: &str, agent_component: &str, agent_line: &str) -> (String, String) {
    let member = format!("(\"@authority\" {agent_component}){}", params());
    let base = format!("\"@authority\": example.com\n{agent_component}: {agent_line}\n\"@signature-params\": {member}");
    (format!("{label}={member}"), format!("{label}={}", sign(&base)))
}

fn check(agent_header: &str, input: &str, sig: &str, trusted: &TrustedAgents) -> WbaVerdict {
    let h = [("Signature-Agent", agent_header), ("Signature-Input", input), ("Signature", sig)];
    verify(&req(&h), trusted, NOW)
}

const KEYED: &str = "\"signature-agent\";key=\"sig2\"";
const B_TEST: &str = "\"https://b.test/keys.json\"";

// ---------- the draft's vector ----------

const E21_AGENT: &str = "sig2=\"https://signature-agent.test\"";
const E21_MEMBER: &str = "(\"@authority\" \"signature-agent\";key=\"sig2\");created=1735689600;keyid=\"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U\";alg=\"ed25519\";expires=4889289600;nonce=\"n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA==\";tag=\"web-bot-auth\"";
const E21_SIG: &str = "CGokAoY/FrPpyuzTe1Fb2kLTAH9Idw6qSFd1+D77r1firsMRCxeuLu5e6O+ek3zQgDMAzjiXtLVfqE00xnABCQ==";

#[test]
fn draft_e21_signature_base_is_exact_and_its_signature_verifies() {
    let h = [("Signature-Agent", E21_AGENT)];
    let base = signature_base(&req(&h), E21_MEMBER).unwrap();
    let expected = format!(
        "\"@authority\": example.com\n\"signature-agent\";key=\"sig2\": \"https://signature-agent.test\"\n\"@signature-params\": {E21_MEMBER}"
    );
    assert_eq!(base, expected);
    // The draft's own signature verifies over that base, which shows the
    // vector was copied correctly.
    let sig = ed25519_dalek::Signature::from_slice(&STANDARD.decode(E21_SIG).unwrap()).unwrap();
    VerifyingKey::from_bytes(&rfc_public()).unwrap().verify(base.as_bytes(), &sig).unwrap();
}

#[test]
fn draft_e21_as_a_request_is_refused_only_for_its_century_long_window() {
    // The vector is valid for a hundred years; this crate caps a signature's
    // window at a day, so the request as published is not accepted.
    let input = format!("sig2={E21_MEMBER}");
    let sig = format!("sig2=:{E21_SIG}:");
    assert_eq!(
        check(E21_AGENT, &input, &sig, &trusted(None)),
        WbaVerdict::Invalid(WbaInvalid::WindowTooLong)
    );
}

// ---------- verification ----------

#[test]
fn a_dictionary_signature_agent_verifies() {
    let (input, sig) = signed("sig2", KEYED, B_TEST);
    let header = format!("sig2={B_TEST}");
    assert_eq!(check(&header, &input, &sig, &trusted(None)), verified());
    assert_eq!(check(&header, &input, &sig, &trusted(Some("https://b.test/keys.json"))), verified());
    assert_eq!(
        check(&header, &input, &sig, &trusted(Some("https://a.test/keys.json"))),
        WbaVerdict::Invalid(WbaInvalid::AgentMismatch)
    );
    // Not a prefix match and not case-folded.
    assert_eq!(
        check(&header, &input, &sig, &trusted(Some("https://b.test/keys.jso"))),
        WbaVerdict::Invalid(WbaInvalid::AgentMismatch)
    );
}

#[test]
fn the_member_for_this_signatures_label_is_the_agent() {
    let (input, sig) = signed("sig2", KEYED, B_TEST);
    // Other members, before and after, with odd spacing between them.
    let header = format!("sig1=\"https://a.test/keys.json\",   sig2={B_TEST}  ,sig3=\"https://c.test/\"");
    assert_eq!(check(&header, &input, &sig, &trusted(Some("https://b.test/keys.json"))), verified());
    assert_eq!(
        check(&header, &input, &sig, &trusted(Some("https://a.test/keys.json"))),
        WbaVerdict::Invalid(WbaInvalid::AgentMismatch)
    );
    // Two header lines are one dictionary.
    let h = [
        ("Signature-Agent", "sig1=\"https://a.test/keys.json\""),
        ("Signature-Input", input.as_str()),
        ("signature-agent", "sig2=\"https://b.test/keys.json\""),
        ("Signature", sig.as_str()),
    ];
    assert_eq!(verify(&req(&h), &trusted(Some("https://b.test/keys.json")), NOW), verified());
}

#[test]
fn covering_the_whole_header_is_accepted_too() {
    let header = format!("sig1=\"https://a.test/keys.json\", sig2={B_TEST}");
    // The plain-header rule: the line is the header value as sent.
    let (input, sig) = signed("sig2", "\"signature-agent\"", &header);
    assert_eq!(check(&header, &input, &sig, &trusted(Some("https://b.test/keys.json"))), verified());
    assert_eq!(
        check(&header, &input, &sig, &trusted(Some("https://a.test/keys.json"))),
        WbaVerdict::Invalid(WbaInvalid::AgentMismatch)
    );
}

#[test]
fn covering_another_labels_member_is_not_enough() {
    // Signed under sig2, but what is covered is sig1's member.
    let (input, sig) = signed("sig2", "\"signature-agent\";key=\"sig1\"", "\"https://a.test/keys.json\"");
    let header = format!("sig1=\"https://a.test/keys.json\", sig2={B_TEST}");
    assert_eq!(
        check(&header, &input, &sig, &trusted(None)),
        WbaVerdict::Invalid(WbaInvalid::SignatureAgentUnsigned)
    );
}

#[test]
fn a_dictionary_without_this_signatures_member_is_unsigned() {
    let header = "sig1=\"https://a.test/keys.json\"";
    // Covering sig1's member.
    let (input, sig) = signed("sig2", "\"signature-agent\";key=\"sig1\"", "\"https://a.test/keys.json\"");
    assert_eq!(check(header, &input, &sig, &trusted(None)), WbaVerdict::Invalid(WbaInvalid::SignatureAgentUnsigned));
    // Covering the whole header.
    let (input, sig) = signed("sig2", "\"signature-agent\"", header);
    assert_eq!(check(header, &input, &sig, &trusted(None)), WbaVerdict::Invalid(WbaInvalid::SignatureAgentUnsigned));
    // Covering nothing of it.
    let member = format!("(\"@authority\"){}", params());
    let base = format!("\"@authority\": example.com\n\"@signature-params\": {member}");
    let (input, sig) = (format!("sig2={member}"), format!("sig2={}", sign(&base)));
    let header = format!("sig2={B_TEST}");
    assert_eq!(check(&header, &input, &sig, &trusted(None)), WbaVerdict::Invalid(WbaInvalid::SignatureAgentUnsigned));
}

#[test]
fn a_member_with_parameters_is_ignored() {
    let (input, sig) = signed("sig2", KEYED, B_TEST);
    let header = format!("sig2={B_TEST};v=1");
    assert_eq!(
        check(&header, &input, &sig, &trusted(None)),
        WbaVerdict::Invalid(WbaInvalid::SignatureAgentUnsigned)
    );
}

#[test]
fn a_member_that_is_not_a_string_is_malformed() {
    let (input, sig) = signed("sig2", KEYED, B_TEST);
    for header in ["sig2=https", "sig2=42", "sig2=(\"https://b.test/keys.json\")", "sig2", "sig2=:aGk=:"] {
        assert_eq!(
            check(header, &input, &sig, &trusted(None)),
            WbaVerdict::Invalid(WbaInvalid::Malformed),
            "{header}"
        );
    }
}

#[test]
fn a_header_that_is_neither_form_is_malformed() {
    let (input, sig) = signed("sig2", KEYED, B_TEST);
    for header in ["sig2=", "\"unterminated", "sig2=\"a\", sig2=\"b\"", "https://b.test/keys.json", "sig2=\"a\",", "=\"a\""] {
        assert_eq!(
            check(header, &input, &sig, &trusted(None)),
            WbaVerdict::Invalid(WbaInvalid::Malformed),
            "{header}"
        );
    }
}

#[test]
fn a_changed_member_fails_the_signature() {
    let (input, sig) = signed("sig2", KEYED, B_TEST);
    assert_eq!(
        check("sig2=\"https://evil.test/keys.json\"", &input, &sig, &trusted(None)),
        WbaVerdict::Invalid(WbaInvalid::BadSignature)
    );
    // Another member changing does not matter: it was not covered.
    let header = format!("sig9=\"https://anything.test/\", sig2={B_TEST}");
    assert_eq!(check(&header, &input, &sig, &trusted(None)), verified());
}

#[test]
fn the_earlier_string_form_cannot_be_covered_by_key() {
    // A quoted string is not a dictionary, so there is no member to cover.
    let (input, sig) = signed("sig2", KEYED, B_TEST);
    let v = check(B_TEST, &input, &sig, &trusted(None));
    assert_eq!(v, WbaVerdict::Invalid(WbaInvalid::SignatureAgentUnsigned));
}

#[test]
fn no_truncation_of_a_valid_request_verifies_or_panics() {
    let (input, sig) = signed("sig2", KEYED, B_TEST);
    let header = format!("sig2={B_TEST}");
    assert_eq!(check(&header, &input, &sig, &trusted(None)), verified());
    for cut in 0..header.len() {
        let v = check(&header[..cut], &input, &sig, &trusted(None));
        assert!(!matches!(v, WbaVerdict::Verified { .. }), "agent cut at {cut}");
    }
    for cut in 0..input.len() {
        let v = check(&header, &input[..cut], &sig, &trusted(None));
        assert!(!matches!(v, WbaVerdict::Verified { .. }), "input cut at {cut}");
    }
}

// ---------- the signature base ----------

fn base_of(headers: &[(&str, &str)], components: &str) -> Result<String, WbaInvalid> {
    signature_base(&req(headers), &format!("({components});created=1"))
}

#[test]
fn key_selects_one_member_of_any_dictionary_header() {
    let h = [("X-Dict", "a=1, b=tok,  c=\"str\" , d=?1"), ("Signature-Agent", "s=\"https://b.test/\"")];
    assert_eq!(
        base_of(&h, "\"x-dict\";key=\"a\" \"x-dict\";key=\"c\" \"x-dict\";key=\"b\" \"x-dict\" \"signature-agent\";key=\"s\"").unwrap(),
        "\"x-dict\";key=\"a\": 1\n\
\"x-dict\";key=\"c\": \"str\"\n\
\"x-dict\";key=\"b\": tok\n\
\"x-dict\": a=1, b=tok,  c=\"str\" , d=?1\n\
\"signature-agent\";key=\"s\": \"https://b.test/\"\n\
\"@signature-params\": (\"x-dict\";key=\"a\" \"x-dict\";key=\"c\" \"x-dict\";key=\"b\" \"x-dict\" \"signature-agent\";key=\"s\");created=1"
    );
}

#[test]
fn key_problems() {
    let h = [("X-Dict", "a=1, p=2;x=1, l=(1 2)"), ("X-Plain", "\"just a string\"")];
    use WbaInvalid::{Malformed, UnsupportedComponent};
    for (components, expected) in [
        // No such member, no such header, not a dictionary.
        ("\"x-dict\";key=\"zzz\"", Malformed),
        ("\"x-none\";key=\"a\"", Malformed),
        ("\"x-plain\";key=\"a\"", Malformed),
        // The same component twice.
        ("\"x-dict\";key=\"a\" \"x-dict\";key=\"a\"", Malformed),
        // A member that is a list or has parameters.
        ("\"x-dict\";key=\"l\"", UnsupportedComponent),
        ("\"x-dict\";key=\"p\"", UnsupportedComponent),
        // Parameters this crate does not implement.
        ("\"x-dict\";sf", UnsupportedComponent),
        ("\"x-dict\";bs", UnsupportedComponent),
        ("\"x-dict\";req", UnsupportedComponent),
        ("\"x-dict\";key=\"a\";sf", UnsupportedComponent),
        ("\"x-dict\";key=a", UnsupportedComponent),
        ("\"x-dict\";key=1", UnsupportedComponent),
        ("\"x-dict\";name=\"a\"", UnsupportedComponent),
        ("\"@authority\";key=\"a\"", UnsupportedComponent),
        ("\"@authority\";req", UnsupportedComponent),
    ] {
        assert_eq!(base_of(&h, components), Err(expected), "{components}");
    }
}
