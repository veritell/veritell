//! Test helper: signs a request the way a Web Bot Auth agent would and
//! prints the two headers, one per line, ready for `curl -H`.
//!
//!   cargo run -q -p veritell-wba --example sign -- <authority> <unix-time> [rfc|other] [signature-agent-url]
//!   cargo run -q -p veritell-wba --example sign -- jwks [rfc|other]
//!
//! With a signature-agent URL a third line is printed, `Signature-Agent` in
//! its dictionary form, and the signature covers that member. `jwks` prints
//! the key directory a server would publish for the key.
//!
//! With `SIGN_METHOD` and `SIGN_PATH` set, the signature also covers
//! `@method` and `@path` with those values (what a write request needs).
//!
//! Each signature gets its own `nonce`, so two requests signed with the same
//! time and key differ, as an agent's do: the gateway refuses a signature it
//! has already seen.
//!
//! `rfc` (the default) uses the published test key from RFC 9421 B.1.4.
//! `other` uses a fixed throwaway key that no configuration trusts.
//! Never use either key for anything real.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};

const RFC_KEY_D: &str = "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("jwks") {
        let key = SigningKey::from_bytes(&seed_of(args.get(1).map(String::as_str)));
        let x = URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes());
        println!("{{\"keys\":[{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"{x}\",\"use\":\"sig\"}}]}}");
        return;
    }
    let (Some(authority), Some(created)) = (args.first(), args.get(1).and_then(|t| t.parse::<u64>().ok()))
    else {
        eprintln!("usage: sign <authority> <unix-time> [rfc|other] [signature-agent-url] | sign jwks [rfc|other]");
        std::process::exit(2);
    };
    let key = SigningKey::from_bytes(&seed_of(args.get(2).map(String::as_str)));
    // The URL goes into a quoted string: nothing that would end it early.
    let agent = args.get(3).filter(|u| !u.contains(['"', '\\']));
    let keyid = veritell_wba::jwk_thumbprint_ed25519(&key.verifying_key().to_bytes());
    let (mut covered, agent_line) = match agent {
        Some(url) => (
            "\"@authority\" \"signature-agent\";key=\"sig1\"".to_string(),
            format!("\"signature-agent\";key=\"sig1\": \"{url}\"\n"),
        ),
        None => ("\"@authority\"".to_string(), String::new()),
    };
    // Method and path go before the agent line in the base, in the order
    // they are listed.
    let mut target_lines = String::new();
    if let (Ok(method), Ok(path)) = (std::env::var("SIGN_METHOD"), std::env::var("SIGN_PATH")) {
        covered = covered.replacen("\"@authority\"", "\"@authority\" \"@method\" \"@path\"", 1);
        target_lines = format!("\"@method\": {}\n\"@path\": {path}\n", method.to_ascii_uppercase());
    }
    let member = format!(
        "({covered});created={created};expires={};keyid=\"{keyid}\";alg=\"ed25519\";nonce=\"{}\";tag=\"web-bot-auth\"",
        created.saturating_add(300),
        nonce()
    );
    let base = format!(
        "\"@authority\": {}\n{target_lines}{agent_line}\"@signature-params\": {member}",
        authority.to_ascii_lowercase()
    );
    let signature = STANDARD.encode(key.sign(base.as_bytes()).to_bytes());
    println!("Signature-Input: sig1={member}");
    println!("Signature: sig1=:{signature}:");
    if let Some(url) = agent {
        println!("Signature-Agent: sig1=\"{url}\"");
    }
}

/// Unique per run: the clock in nanoseconds and the process id. A test
/// helper, not a source of secrets.
fn nonce() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let mut bytes = nanos.to_be_bytes().to_vec();
    bytes.extend_from_slice(&std::process::id().to_be_bytes());
    URL_SAFE_NO_PAD.encode(bytes)
}

fn seed_of(which: Option<&str>) -> [u8; 32] {
    match which {
        Some("other") => [0x42; 32],
        _ => URL_SAFE_NO_PAD
            .decode(RFC_KEY_D)
            .ok()
            .and_then(|d| d.try_into().ok())
            .unwrap_or([0; 32]),
    }
}
