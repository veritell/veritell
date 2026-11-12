//! Checks captured tokens with the gateway's own verifier.
//!
//!   check_tokens < captured.tsv
//!
//! Each input line is four tab-separated fields: the `Authorization` value
//! the client sent, the challenge it answered (base64url, as sent in
//! `WWW-Authenticate`), the issuer name and the issuer key (base64url, as the
//! issuer publishes it). Prints one result per line and exits non-zero if any
//! token was refused. Used for L20, where the tokens came from Safari on an
//! iPhone through Apple's attester and a public demo issuer.

use std::io::BufRead;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use veritell_privacypass::{challenge_digest, token_from_authorization, verify, Accepted, IssuerKey};

fn check(line: &str) -> Result<String, String> {
    let mut fields = line.split('\t');
    let (Some(auth), Some(challenge), Some(issuer), Some(key)) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return Err("expected four tab-separated fields".into());
    };
    let key = IssuerKey::from_base64url(issuer, key).map_err(|e| format!("issuer key: {e:?}"))?;
    let challenge = URL_SAFE_NO_PAD.decode(challenge.trim_end_matches('=')).map_err(|e| format!("challenge: {e}"))?;
    let token = token_from_authorization(auth)
        .map_err(|e| format!("authorization: {e:?}"))?
        .ok_or("no PrivateToken in the authorization value")?;
    let accepted = [Accepted { challenge_digest: challenge_digest(&challenge), key_id: *key.key_id() }];
    let ok = verify(&token, std::slice::from_ref(&key), &accepted).map_err(|e| format!("refused: {e:?}"))?;
    let nonce: String = ok.nonce.iter().take(4).map(|b| format!("{b:02x}")).collect();
    Ok(format!("verified: issuer {issuer}, token nonce {nonce}..."))
}

fn main() {
    let mut refused = 0;
    for line in std::io::stdin().lock().lines().map_while(Result::ok) {
        if line.trim().is_empty() {
            continue;
        }
        match check(&line) {
            Ok(msg) => println!("{msg}"),
            Err(why) => {
                refused += 1;
                println!("{why}");
            }
        }
    }
    std::process::exit(i32::from(refused > 0));
}
