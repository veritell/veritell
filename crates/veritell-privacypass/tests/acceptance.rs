//! Acceptance tests written by the project lead. DO NOT EDIT.
//!
//! Vectors are copied from RFC 9578, appendix A.2 (Issuance Protocol 2,
//! Blind RSA 2048-bit): the issuer public key `pkI`, shared by all five
//! vectors, and `token_challenge` and `token` of vectors 1 to 5.

use veritell_privacypass::*;

const PKI: &str = "30820152303d06092a864886f70d01010a3030a00d300b0609608648016503040202a11a301806092a864886f70d010108300b0609608648016503040202a2030201300382010f003082010a0282010100cb1aed6b6a95f5b1ce013a4cfcab25b94b2e64a23034e4250a7eab43c0df3a8c12993af12b111908d4b471bec31d4b6c9ad9cdda90612a2ee903523e6de5a224d6b02f09e5c374d0cfe01d8f529c500a78a2f67908fa682b5a2b430c81eaf1af72d7b5e794fc98a3139276879757ce453b526ef9bf6ceb99979b8423b90f4461a22af37aab0cf5733f7597abe44d31c732db68a181c6cbbe607d8c0e52e0655fd9996dc584eca0be87afbcd78a337d17b1dba9e828bbd81e291317144e7ff89f55619709b096cbb9ea474cead264c2073fe49740c01f00e109106066983d21e5f83f086e2e823c879cd43cef700d2a352a9babd612d03cad02db134b7e225a5f0203010001";

const CONTEXT: &str = "8e7acc900e393381e8810b7c9e4a68b5163f1f880ab6688a6ffe780923609e88";

const CHALLENGE_1: &str = "0002000e6973737565722e6578616d706c65208e7acc900e393381e8810b7c9e4a68b5163f1f880ab6688a6ffe780923609e88000e6f726967696e2e6578616d706c65";
const CHALLENGE_2: &str = "0002000e6973737565722e6578616d706c6500000e6f726967696e2e6578616d706c65";
const CHALLENGE_3: &str = "0002000e6973737565722e6578616d706c65000017666f6f2e6578616d706c652c6261722e6578616d706c65";
const CHALLENGE_4: &str = "0002000e6973737565722e6578616d706c65000000";
const CHALLENGE_5: &str = "0002000e6973737565722e6578616d706c65208e7acc900e393381e8810b7c9e4a68b5163f1f880ab6688a6ffe780923609e880000";

const TOKEN_1: &str = "0002aa72019d1f951df197021ce63876fe8b0a02dc1c31a12b0a2dd1508d07827f055969f643b4cfda5196d4aa86aeb5368834f4f06de46950ed435b3b81bd036d44ca572f8982a9ca248a3056186322d93ca147266121ddeb5632c07f1f71cd2708bc6a21b533d07294b5e900faf5537dd3eb33cee4e08c9670d1e5358fd184b0e00c637174f5206b14c7bb0e724ebf6b56271e5aa2ed94c051c4a433d302b23bc52460810d489fb050f9de5c868c6c1b06e3849fd087629f704cc724bc0d0984d5c339686fcdd75f9a9cdd25f37f855f6f4c584d84f716864f546b696d620c5bd41a811498de84ff9740ba3003ba2422d26b91eb745c084758974642a42078201543246ddb58030ea8e722376aa82484dca9610a8fb7e018e396165462e17a03e40ea7e128c090a911ecc708066cb201833010c1ebd4e910fc8e27a1be467f78671836a508257123a45e4e0ae2180a434bd1037713466347a8ebe46439d3da1970";
const TOKEN_4: &str = "0002494dae41fc7e300c2d09990afcd5d5e1fc95305337dc12f78942c45340bfe8e6b741ec1b6fd05f1e95f8982906aec1612896d9ca97d53eef94ad3c9fe023f7a4ca572f8982a9ca248a3056186322d93ca147266121ddeb5632c07f1f71cd2708a55c83dc04292b5d92add1a87b37e54f22f61c58840586f390c50b231824423378ddcf50e69dc817d45bfad06c7f2a0ac35d2acd7f26b0bc9954c192b0a0ef28a2a5650e390098dd3cb1166a7cb1716d3dd2d19dc5ca3b1ea6206359de0002d82bc4fa7e69fb07214b06addcbd2203d1e17f57fc580bcc5a13e0ac15cf942182cc2b5d6eaa737a712704114e357e2ec2f10047463ded02a1a0766dc346dd7212b9711e03ac95eb258ac1164104dc9a0d3e738ae742ab5ed8c5139fc07145a788b9f891741ee68f0a66782b7b84a9bb4cb4b3d1b26b67106f397b35b641d882d7b0185168946de898ef72349a44a47dbdd6d46e9ba9ba543d5701b65c63d645c2";

/// SHA-256 of `pkI`, which is also bytes 66..98 of every vector token.
const KEY_ID: &str = "ca572f8982a9ca248a3056186322d93ca147266121ddeb5632c07f1f71cd2708";
/// SHA-256 of challenges 1 and 4, which are bytes 34..66 of tokens 1 and 4.
const DIGEST_1: &str = "5969f643b4cfda5196d4aa86aeb5368834f4f06de46950ed435b3b81bd036d44";
const DIGEST_4: &str = "b741ec1b6fd05f1e95f8982906aec1612896d9ca97d53eef94ad3c9fe023f7a4";

fn hex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

fn hex32(text: &str) -> [u8; 32] {
    hex(text).try_into().unwrap()
}

fn key() -> IssuerKey {
    IssuerKey::new("issuer.example", &hex(PKI)).expect("the RFC's key should be accepted")
}

fn accepted(digest: &str) -> Accepted {
    Accepted { challenge_digest: hex32(digest), key_id: hex32(KEY_ID) }
}

// ---------- the RFC's vectors ----------

#[test]
fn the_rfc_key_and_its_identifier() {
    let k = key();
    assert_eq!(k.name(), "issuer.example");
    assert_eq!(k.key_id(), &hex32(KEY_ID));
    assert_eq!(k.spki(), hex(PKI).as_slice());
    // The identifier is what the vector tokens carry.
    assert_eq!(&hex(TOKEN_1)[66..98], k.key_id().as_slice());
}

#[test]
fn the_rfc_challenges_are_rebuilt_byte_for_byte() {
    let ctx = hex32(CONTEXT);
    let cases: [(Option<&[u8; 32]>, &str, &str); 5] = [
        (Some(&ctx), "origin.example", CHALLENGE_1),
        (None, "origin.example", CHALLENGE_2),
        (None, "foo.example,bar.example", CHALLENGE_3),
        (None, "", CHALLENGE_4),
        (Some(&ctx), "", CHALLENGE_5),
    ];
    for (context, origin, expected) in cases {
        assert_eq!(token_challenge("issuer.example", context, origin).unwrap(), hex(expected), "{origin:?}");
    }
    assert_eq!(challenge_digest(&hex(CHALLENGE_1)), hex32(DIGEST_1));
    assert_eq!(challenge_digest(&hex(CHALLENGE_4)), hex32(DIGEST_4));
    assert_eq!(&hex(TOKEN_1)[34..66], hex(DIGEST_1).as_slice());
}

#[test]
fn the_rfc_tokens_verify() {
    assert_eq!(hex(TOKEN_1).len(), TOKEN_BYTES);
    let t = verify(&hex(TOKEN_1), &[key()], &[accepted(DIGEST_1)]).unwrap();
    assert_eq!(t.nonce, hex32("aa72019d1f951df197021ce63876fe8b0a02dc1c31a12b0a2dd1508d07827f05"));
    assert_eq!(t.challenge_digest, hex32(DIGEST_1));
    assert_eq!(t.token_key_id, hex32(KEY_ID));

    let t = verify(&hex(TOKEN_4), &[key()], &[accepted(DIGEST_1), accepted(DIGEST_4)]).unwrap();
    assert_eq!(t.challenge_digest, hex32(DIGEST_4));
    assert_eq!(t.nonce, hex32("494dae41fc7e300c2d09990afcd5d5e1fc95305337dc12f78942c45340bfe8e6"));
}

#[test]
fn the_signature_check_alone() {
    let (k, t) = (key(), hex(TOKEN_1));
    assert!(k.verify_signature(&t[..98], &t[98..]));
    assert!(!k.verify_signature(&t[..97], &t[98..]));
    assert!(!k.verify_signature(&t[..98], &t[99..]));
    assert!(!k.verify_signature(&t[..98], &[]));
    assert!(!k.verify_signature(&[], &t[98..]));
    assert!(!k.verify_signature(&t[..98], &[0u8; 256]));
    assert!(!k.verify_signature(&t[..98], &[0xffu8; 256]));
}

// ---------- tokens that must be refused ----------

#[test]
fn a_token_for_another_challenge() {
    // Token 1 answers challenge 1 (origin.example with a context). A site
    // asking challenge 4, or asking nothing, does not take it.
    assert_eq!(verify(&hex(TOKEN_1), &[key()], &[accepted(DIGEST_4)]), Err(PassError::WrongChallenge));
    assert_eq!(verify(&hex(TOKEN_1), &[key()], &[]), Err(PassError::WrongChallenge));
    // The digest is right but the challenge was made for another issuer key.
    let other_key = Accepted { challenge_digest: hex32(DIGEST_1), key_id: [7; 32] };
    assert_eq!(verify(&hex(TOKEN_1), &[key()], &[other_key]), Err(PassError::WrongChallenge));
}

#[test]
fn a_token_from_a_key_that_is_not_trusted() {
    assert_eq!(verify(&hex(TOKEN_1), &[], &[accepted(DIGEST_1)]), Err(PassError::UnknownKey));
    let mut t = hex(TOKEN_1);
    t[70] ^= 1; // inside token_key_id
    assert_eq!(verify(&t, &[key()], &[accepted(DIGEST_1)]), Err(PassError::UnknownKey));
}

#[test]
fn a_token_that_was_changed() {
    let ok = [accepted(DIGEST_1)];
    // The nonce: still names the key and the challenge, but is not what was signed.
    let mut t = hex(TOKEN_1);
    t[2] ^= 1;
    assert_eq!(verify(&t, &[key()], &ok), Err(PassError::BadAuthenticator));
    // The authenticator: first, middle and last byte.
    for at in [98, 200, 353] {
        let mut t = hex(TOKEN_1);
        t[at] ^= 0x80;
        assert_eq!(verify(&t, &[key()], &ok), Err(PassError::BadAuthenticator), "byte {at}");
    }
    // The digest: no longer a challenge this site asked.
    let mut t = hex(TOKEN_1);
    t[40] ^= 1;
    assert_eq!(verify(&t, &[key()], &ok), Err(PassError::WrongChallenge));
    // One token's signature under another token's fields.
    let mut t = hex(TOKEN_1);
    t[98..].copy_from_slice(&hex(TOKEN_4)[98..]);
    assert_eq!(verify(&t, &[key()], &ok), Err(PassError::BadAuthenticator));
}

#[test]
fn tokens_of_the_wrong_shape() {
    let ok = [accepted(DIGEST_1)];
    let t = hex(TOKEN_1);
    assert_eq!(verify(&[], &[key()], &ok), Err(PassError::Malformed));
    assert_eq!(verify(&[0], &[key()], &ok), Err(PassError::Malformed));
    assert_eq!(verify(&t[..353], &[key()], &ok), Err(PassError::Malformed));
    assert_eq!(verify(&t[..2], &[key()], &ok), Err(PassError::Malformed));
    let mut long = t.clone();
    long.push(0);
    assert_eq!(verify(&long, &[key()], &ok), Err(PassError::Malformed));
    // Another type is reported as such, at any length.
    let mut other = t.clone();
    other[1] = 1;
    assert_eq!(verify(&other, &[key()], &ok), Err(PassError::UnknownType(1)));
    assert_eq!(verify(&[0xda, 0x7a], &[key()], &ok), Err(PassError::UnknownType(0xda7a)));
    assert_eq!(verify(&[0x00, 0x01, 9, 9, 9], &[key()], &ok), Err(PassError::UnknownType(1)));
}

#[test]
fn no_truncation_or_single_bit_flip_verifies() {
    let (k, ok, t) = ([key()], [accepted(DIGEST_1)], hex(TOKEN_1));
    for cut in 0..t.len() {
        assert!(verify(&t[..cut], &k, &ok).is_err(), "cut at {cut}");
    }
    for at in (0..t.len()).step_by(7) {
        let mut changed = t.clone();
        changed[at] ^= 0x10;
        assert!(verify(&changed, &k, &ok).is_err(), "bit flipped at {at}");
    }
}

// ---------- issuer keys ----------

fn key_error(spki: &[u8]) -> bool {
    matches!(IssuerKey::new("issuer.example", spki), Err(PassError::Key(_)))
}

#[test]
fn issuer_keys_that_are_refused() {
    let good = hex(PKI);
    assert!(key_error(&[]));
    assert!(key_error(&good[..good.len() - 1]));
    assert!(key_error(&good[..67]));
    let mut trailing = good.clone();
    trailing.push(0);
    assert!(key_error(&trailing));

    // Byte 66 is the salt length (0x30 = 48); byte 33 ends the hash OID
    // (…2.2 is SHA-384, …2.1 is SHA-256); byte 16 ends the algorithm OID
    // (…1.10 is RSASSA-PSS, …1.1 is rsaEncryption).
    for (at, value) in [(66usize, 0x20u8), (33, 0x01), (59, 0x01), (16, 0x01)] {
        let mut k = good.clone();
        assert_ne!(k[at], value);
        k[at] = value;
        assert!(key_error(&k), "byte {at}");
    }
    // Unused bits in the BIT STRING.
    let mut k = good.clone();
    assert_eq!(k[71], 0x00);
    k[71] = 0x01;
    assert!(key_error(&k));
    // An even exponent (the last byte of 0x010001).
    let mut k = good.clone();
    let last = k.len() - 1;
    k[last] = 0x00;
    assert!(key_error(&k));
    // A modulus without its top bit is not 2048 bits (byte 81 is its first byte, 0xcb).
    let mut k = good.clone();
    assert_eq!((k[80], k[81]), (0x00, 0xcb));
    k[81] = 0x4b;
    assert!(key_error(&k));
    // Not DER at all.
    assert!(key_error(b"-----BEGIN PUBLIC KEY-----"));
    assert!(key_error(&[0x30, 0x82, 0xff, 0xff]));
    assert!(key_error(&vec![0x30; 400]));
}

#[test]
fn issuer_names_are_checked_first() {
    assert_eq!(IssuerKey::new("", &hex(PKI)).err(), Some(PassError::Name));
    assert_eq!(IssuerKey::new("issuer@example", &[]).err(), Some(PassError::Name));
    assert_eq!(IssuerKey::new("issuer.example:8443", &hex(PKI)).unwrap().name(), "issuer.example:8443");
}

#[test]
fn issuer_keys_in_base64url() {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
    use base64::Engine as _;
    let der = hex(PKI);
    let padded = URL_SAFE.encode(&der);
    assert!(padded.contains('_') || padded.contains('-'));
    let k = IssuerKey::from_base64url("issuer.example", &padded).unwrap();
    assert_eq!(k, key());
    assert_eq!(IssuerKey::from_base64url("issuer.example", &URL_SAFE_NO_PAD.encode(&der)).unwrap(), key());
    // Written back with padding, as the RFC requires. 342 bytes need none.
    assert_eq!(k.token_key(), padded);
    for bad in [String::new(), STANDARD.encode(&der), format!(" {padded}"), format!("{padded}\n"), "!!!!".to_string()] {
        assert!(matches!(IssuerKey::from_base64url("issuer.example", &bad), Err(PassError::Key(_))), "{bad:.20}");
    }
}

// ---------- names and challenges ----------

#[test]
fn server_names() {
    let longest = format!("{}.example", "a".repeat(MAX_NAME_BYTES - 8));
    assert_eq!(longest.len(), MAX_NAME_BYTES);
    for good in ["issuer.example", "issuer.example.com:8443", "localhost", "localhost:1", "a", "A.Example", "192.0.2.1", "x-y.example:65535", longest.as_str()] {
        assert!(valid_server_name(good), "{good}");
    }
    let too_long = format!("a{longest}");
    for bad in [
        "", "issuer@example.com", "user:pw@issuer.example", "issuer.example:", "issuer.example:0", "issuer.example:65536",
        "issuer.example:123456", "issuer.example:8a", "issuer..example", ".issuer.example", "issuer.example.", "issuer example",
        "issuer.example/path", "https://issuer.example", "[::1]", "[::1]:443", "issuer_example", "issu\u{e9}r.example",
        "issuer.example,other.example", "issuer.example:80:80", " issuer.example", too_long.as_str(),
    ] {
        assert!(!valid_server_name(bad), "{bad}");
    }
}

#[test]
fn challenges_with_bad_names_are_not_built() {
    assert!(token_challenge("issuer.example", None, "a.example,b.example:8443").is_ok());
    for (issuer, origin) in [
        ("", "origin.example"),
        ("issuer@example", "origin.example"),
        ("issuer.example,other.example", ""),
        ("issuer.example", "origin.example, other.example"),
        ("issuer.example", "origin.example,"),
        ("issuer.example", ",origin.example"),
        ("issuer.example", "a.example,,b.example"),
        ("issuer.example", "user@origin.example"),
        ("issuer.example", " "),
    ] {
        assert_eq!(token_challenge(issuer, None, origin), Err(PassError::Name), "{issuer:?} {origin:?}");
    }
    // Names go in as written: another spelling is another challenge.
    assert_ne!(
        token_challenge("issuer.example", None, "Origin.example").unwrap(),
        token_challenge("issuer.example", None, "origin.example").unwrap()
    );
}

#[test]
fn redemption_contexts() {
    // HMAC-SHA-256 known answers, computed independently.
    assert_eq!(
        redemption_context(b"0123456789abcdef0123456789abcdef", 5),
        hex32("9a8a11abc71ffad160370350a492413f04bc58a33c79027763135b411f3cf6f4")
    );
    assert_eq!(
        redemption_context(b"k", u64::MAX),
        hex32("115f2adfefd8d0a69af456b1f3e0851583329b02c480c87478b6900dfb53ac39")
    );
    assert_ne!(redemption_context(b"k", 1), redemption_context(b"k", 2));
    assert_ne!(redemption_context(b"k", 1), redemption_context(b"l", 1));
    let _ = redemption_context(b"", 0);
    let _ = redemption_context(&[0u8; 1000], 0);
}

// ---------- headers ----------

#[test]
fn the_challenge_header() {
    let k = key();
    let c4 = hex(CHALLENGE_4);
    let c2 = hex(CHALLENGE_2);
    let one = www_authenticate(&[(c4.as_slice(), &k)]);
    assert_eq!(one, format!("PrivateToken challenge=\"AAIADmlzc3Vlci5leGFtcGxlAAAA\", token-key=\"{}\"", k.token_key()));
    let two = www_authenticate(&[(c4.as_slice(), &k), (c2.as_slice(), &k)]);
    assert!(two.starts_with(&format!("{one}, PrivateToken challenge=\"")));
    assert_eq!(two.matches("PrivateToken ").count(), 2);
    // Padding is written: challenge 2 is 35 bytes, so its base64 ends in "=".
    assert!(two.contains("=\", token-key="));
    assert_eq!(www_authenticate(&[]), "");
    // Nothing that could end the quoted value early or start a new header.
    assert!(!one.contains(['\r', '\n', '\\']));
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE.encode(bytes)
}

#[test]
fn the_token_is_found_in_authorization() {
    let token = hex(TOKEN_1);
    let enc = b64(&token);
    assert_eq!(token_from_authorization(&format!("PrivateToken token=\"{enc}\"")), Ok(Some(token.clone())));
    // 354 bytes need no padding, so the bare form is also legal.
    assert!(!enc.contains('='));
    assert_eq!(token_from_authorization(&format!("PrivateToken token={enc}")), Ok(Some(token.clone())));
    assert_eq!(token_from_authorization(&format!("privatetoken  TOKEN = \"{enc}\" ")), Ok(Some(token.clone())));
    // Other parameters are ignored, wherever they are.
    assert_eq!(
        token_from_authorization(&format!("PrivateToken realm=\"x, y\", token=\"{enc}\", extra=1")),
        Ok(Some(token.clone()))
    );
    // Padding is accepted when present and when absent.
    assert_eq!(token_from_authorization("PrivateToken token=\"AAIADg==\""), Ok(Some(vec![0, 2, 0, 14])));
    assert_eq!(token_from_authorization("PrivateToken token=\"AAIADg\""), Ok(Some(vec![0, 2, 0, 14])));
    assert_eq!(token_from_authorization("PrivateToken token=AAIADg=="), Ok(Some(vec![0, 2, 0, 14])));
}

#[test]
fn other_schemes_are_not_ours() {
    for value in ["", "Basic dXNlcjpwYXNz", "Bearer abc.def", "PrivateTokens token=\"AAIA\"", "token=\"AAIA\"", "Private Token token=\"AAIA\""] {
        assert_eq!(token_from_authorization(value), Ok(None), "{value:?}");
    }
}

#[test]
fn our_scheme_without_a_usable_token() {
    let long = format!("PrivateToken token=\"{}\"", "A".repeat(MAX_AUTHORIZATION_BYTES));
    for value in [
        "PrivateToken",
        "PrivateToken ",
        "PrivateToken realm=\"x\"",
        "PrivateToken token",
        "PrivateToken token=",
        "PrivateToken token=\"\"",
        "PrivateToken token=\"AAIA",
        "PrivateToken token=\"AAIA\"x",
        "PrivateToken token=\"AA\\\"IA\"",
        "PrivateToken token=\"AAIA\", token=\"AAIA\"",
        "PrivateToken token=\"AA+/\"",
        "PrivateToken token=\"AA IA\"",
        "PrivateToken token=\"A\"",
        "PrivateToken token=\"AAIADg=\"",
        "PrivateToken token=\"AAIADg===\"",
        "PrivateToken token=\"AAIA=Dg=\"",
        "PrivateToken token=\"=AAIA\"",
        "PrivateToken =\"AAIA\"",
        long.as_str(),
    ] {
        assert_eq!(token_from_authorization(value), Err(PassError::Malformed), "{value:.60}");
    }
}
