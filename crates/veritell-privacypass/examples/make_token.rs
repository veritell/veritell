//! TEST HELPER, not part of the gateway. It plays a client that already
//! holds a Privacy Pass token from a TEST issuer: it signs directly with the
//! issuer's private key instead of running the blind issuance protocol.
//! The key must NEVER be a real issuer's key. The key is read from standard
//! input (PKCS#8 DER, 2048-bit RSA), never from a path argument.
//!
//!     make_token spki < key.der
//!     make_token token <challenge-base64url> [<nonce-hex-64>] < key.der
//!
//! `spki` prints the issuer public key in the RFC 9578 section 6.5 encoding,
//! base64url with padding. `token` prints an Authorization header value.

use std::io::Read;

use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ring::rand::{SecureRandom, SystemRandom};
use ring::rsa::KeyPair;
use ring::signature::RSA_PSS_SHA384;
use sha2::{Digest, Sha256};

/// The AlgorithmIdentifier of RFC 9578 section 6.5, with its SEQUENCE header.
const ALGORITHM: [u8; 63] = [
    0x30, 0x3d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, 0x30, 0x30, 0xa0, 0x0d, 0x30, 0x0b,
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0xa1, 0x1a, 0x30, 0x18, 0x06, 0x09, 0x2a, 0x86,
    0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
    0x02, 0xa2, 0x03, 0x02, 0x01, 0x30,
];

fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.extend([0x81, len as u8]);
    } else {
        out.extend([0x82, (len >> 8) as u8, len as u8]);
    }
    out.extend_from_slice(content);
    out
}

fn spki(key: &KeyPair) -> Vec<u8> {
    let mut bits = vec![0u8];
    bits.extend_from_slice(key.public().as_ref());
    let mut body = ALGORITHM.to_vec();
    body.extend(der(0x03, &bits));
    der(0x30, &body)
}

fn hex_nonce(text: &str) -> [u8; 32] {
    let bytes = text.as_bytes();
    assert!(bytes.len() == 64, "the nonce must be 64 hex digits");
    let mut out = [0u8; 32];
    for (slot, pair) in out.iter_mut().zip(bytes.chunks(2)) {
        let pair = std::str::from_utf8(pair).expect("ASCII");
        *slot = u8::from_str_radix(pair, 16).expect("the nonce must be hex");
    }
    out
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut der_key = Vec::new();
    std::io::stdin().read_to_end(&mut der_key).expect("reading the key from standard input");
    let key = KeyPair::from_pkcs8(&der_key).expect("standard input must be a PKCS#8 DER RSA private key");
    let spki = spki(&key);
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["spki"] => println!("{}", URL_SAFE.encode(&spki)),
        ["token", challenge] => print_token(&key, &spki, challenge, None),
        ["token", challenge, nonce] => print_token(&key, &spki, challenge, Some(hex_nonce(nonce))),
        _ => {
            eprintln!("usage: make_token spki < key.der\n       make_token token <challenge-base64url> [<nonce-hex-64>] < key.der");
            std::process::exit(2);
        }
    }
}

fn print_token(key: &KeyPair, spki: &[u8], challenge: &str, nonce: Option<[u8; 32]>) {
    let rng = SystemRandom::new();
    let challenge = URL_SAFE_NO_PAD.decode(challenge.trim_end_matches('=')).expect("the challenge must be base64url");
    let nonce = nonce.unwrap_or_else(|| {
        let mut n = [0u8; 32];
        rng.fill(&mut n).expect("random bytes");
        n
    });
    let mut token = vec![0x00, 0x02];
    token.extend_from_slice(&nonce);
    token.extend_from_slice(&Sha256::digest(&challenge));
    token.extend_from_slice(&Sha256::digest(spki));
    assert_eq!(token.len(), 98);
    let mut signature = vec![0u8; key.public().modulus_len()];
    key.sign(&RSA_PSS_SHA384, &rng, &token, &mut signature).expect("signing");
    token.extend_from_slice(&signature);
    println!("PrivateToken token=\"{}\"", URL_SAFE.encode(&token));
}
