//! Privacy Pass in the response ladder: offering a token challenge beside
//! the proof-of-work page, and redeeming the token a client sends back.
//!
//! A token shows that an issuer the operator trusts vouched for the device.
//! It does not show who is driving it. So a redeemed token is worth exactly
//! this: the proof of work is waived. The client still gets the challenge
//! page at its lightest setting, which runs the probe, and its score is
//! whatever it was.
//!
//! Challenges are bound to this site's name and to a time window, so a token
//! fetched for another site or kept for later is refused, and a redeemed
//! token only has to be remembered until its window closes.
//!
//! The site's name is bound through the redemption context, which is keyed
//! with the gateway's secret and the name, and not through `origin_info`,
//! which is left empty. Safari does not answer a challenge whose
//! `origin_info` is filled in (Phase 3, L20), though RFC 9577 allows it.
//! For the same reason one challenge is sent, for the first issuer key
//! listed; tokens for any listed key are still taken.

use veritell_privacypass::{
    challenge_digest, redemption_context, token_challenge, token_from_authorization, valid_server_name,
    verify, www_authenticate, Accepted, IssuerKey, PassError,
};
use veritell_token::MemoryBudgetStore;

/// Length of a challenge window. A challenge is accepted in its own window
/// and the next, so a token is good for five to ten minutes.
pub const WINDOW_SECS: u64 = 300;
/// Most issuer keys.
pub const MAX_ISSUERS: usize = 16;

pub struct PrivacyPass {
    pub keys: Vec<IssuerKey>,
    /// Keys the redemption contexts. Derived from the gateway secret.
    pub secret: Vec<u8>,
    /// Tokens already redeemed, until their window closes.
    pub used: std::sync::Arc<MemoryBudgetStore>,
}

/// What became of a request that could have carried a token.
#[derive(Debug, PartialEq, Eq)]
pub enum Redemption {
    /// No `PrivateToken` credentials on the request.
    None,
    /// A token that verified and had not been seen before.
    Redeemed,
    /// Credentials that were not accepted; the log outcome that says why.
    Refused(&'static str),
}

/// Parses `--privacy-pass-issuer`: `name=key[,name=key]`, each key the
/// issuer's public key in base64url as it publishes it.
pub fn parse_issuers(raw: &str) -> Result<Vec<IssuerKey>, String> {
    let mut keys: Vec<IssuerKey> = Vec::new();
    for part in raw.split(',') {
        let (name, key) = part
            .trim()
            .split_once('=')
            .ok_or_else(|| format!("{part:?} is not name=key"))?;
        let key = IssuerKey::from_base64url(name, key).map_err(|e| format!("{name}: {e}"))?;
        if keys.iter().any(|k| k.key_id() == key.key_id()) {
            return Err(format!("{name}: the same key is listed twice"));
        }
        if keys.len() >= MAX_ISSUERS {
            return Err(format!("more than {MAX_ISSUERS} issuer keys"));
        }
        keys.push(key);
    }
    Ok(keys)
}

impl PrivacyPass {
    /// The challenge for one key in one window, for the site called
    /// `origin`. `None` when `origin` is not a server name (an address
    /// literal with brackets, or no name at all).
    fn challenge(&self, key: &IssuerKey, origin: &str, window: u64) -> Option<Vec<u8>> {
        if !valid_server_name(origin) {
            return None;
        }
        // The secret, a zero byte and the name: one key per site. A server
        // name has no zero byte, so no two sites share a key.
        let mut site_secret = Vec::with_capacity(self.secret.len() + 1 + origin.len());
        site_secret.extend_from_slice(&self.secret);
        site_secret.push(0);
        site_secret.extend_from_slice(origin.as_bytes());
        let context = redemption_context(&site_secret, window);
        token_challenge(key.name(), Some(&context), "").ok()
    }

    /// The `WWW-Authenticate` value to send at `now`: one challenge, for the
    /// first issuer key listed, in the current window.
    pub fn offer(&self, origin: &str, now: u64) -> Option<String> {
        let window = now / WINDOW_SECS;
        let key = self.keys.first()?;
        let challenge = self.challenge(key, origin, window)?;
        Some(www_authenticate(&[(challenge.as_slice(), key)]))
    }

    /// Every challenge an answer is taken for at `now`, with the time each
    /// stops being taken: this window's and the one before.
    fn accepted(&self, origin: &str, now: u64) -> Vec<(Accepted, u64)> {
        let current = now / WINDOW_SECS;
        let mut out = Vec::new();
        for window in [current, current.saturating_sub(1)] {
            let until = window.saturating_add(2).saturating_mul(WINDOW_SECS);
            for key in &self.keys {
                if let Some(c) = self.challenge(key, origin, window) {
                    let entry = Accepted { challenge_digest: challenge_digest(&c), key_id: *key.key_id() };
                    if !out.iter().any(|(a, _)| *a == entry) {
                        out.push((entry, until));
                    }
                }
            }
        }
        out
    }

    /// Checks the request's `Authorization` value, if it has one.
    pub fn redeem(&self, authorization: Option<&str>, origin: &str, now: u64) -> Redemption {
        let token = match authorization.map(token_from_authorization) {
            None | Some(Ok(None)) => return Redemption::None,
            Some(Err(_)) => return Redemption::Refused("token_invalid"),
            Some(Ok(Some(t))) => t,
        };
        let accepted = self.accepted(origin, now);
        let digests: Vec<Accepted> = accepted.iter().map(|(a, _)| *a).collect();
        let verified = match verify(&token, &self.keys, &digests) {
            Ok(t) => t,
            Err(PassError::UnknownKey) => return Redemption::Refused("token_unknown_issuer"),
            Err(PassError::WrongChallenge) => return Redemption::Refused("token_wrong_challenge"),
            Err(_) => return Redemption::Refused("token_invalid"),
        };
        // Remembered until the challenge it answers is no longer taken;
        // after that the token fails on its challenge instead.
        let until = accepted
            .iter()
            .find(|(a, _)| a.challenge_digest == verified.challenge_digest)
            .map_or(now.saturating_add(WINDOW_SECS), |(_, until)| *until);
        // The store's key: a hash of the whole 32-byte nonce. The first 16
        // bytes alone would make two different tokens that share them look
        // like one replayed token.
        let mut id = [0u8; 16];
        let digest = <sha2::Sha256 as sha2::Digest>::digest(verified.nonce);
        for (slot, byte) in id.iter_mut().zip(digest.iter()) {
            *slot = *byte;
        }
        match self.used.try_consume(&id, 1, until, now) {
            veritell_token::Consumed::Used => Redemption::Redeemed,
            veritell_token::Consumed::Spent => Redemption::Refused("token_replayed"),
            // Not a replay: the store is full. Refused all the same (an
            // untracked token could be used again and again); the proof of
            // work is still there.
            veritell_token::Consumed::Full => Redemption::Refused("token_store_full"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
    use base64::Engine as _;
    use ring::rand::SystemRandom;
    use ring::signature::{RsaKeyPair, RSA_PSS_SHA384};
    use std::sync::Arc;

    // A throwaway key made for these tests; see testdata/README.md.
    const SPKI: &[u8] = include_bytes!("../testdata/pass_issuer_spki.der");
    const PRIVATE: &[u8] = include_bytes!("../testdata/pass_issuer_rsa.der");

    const ISSUER: &str = "issuer.test";
    const SITE: &str = "shop.test";
    const NOW: u64 = 1_800_000_000;

    fn key() -> IssuerKey {
        IssuerKey::new(ISSUER, SPKI).expect("the test key is an RFC 9578 key")
    }

    /// The issuer key from RFC 9578's test vectors: a real key whose private
    /// half these tests do not hold.
    fn rfc_key() -> IssuerKey {
        let hex = "30820152303d06092a864886f70d01010a3030a00d300b0609608648016503040202a11a301806092a864886f70d010108300b0609608648016503040202a2030201300382010f003082010a0282010100cb1aed6b6a95f5b1ce013a4cfcab25b94b2e64a23034e4250a7eab43c0df3a8c12993af12b111908d4b471bec31d4b6c9ad9cdda90612a2ee903523e6de5a224d6b02f09e5c374d0cfe01d8f529c500a78a2f67908fa682b5a2b430c81eaf1af72d7b5e794fc98a3139276879757ce453b526ef9bf6ceb99979b8423b90f4461a22af37aab0cf5733f7597abe44d31c732db68a181c6cbbe607d8c0e52e0655fd9996dc584eca0be87afbcd78a337d17b1dba9e828bbd81e291317144e7ff89f55619709b096cbb9ea474cead264c2073fe49740c01f00e109106066983d21e5f83f086e2e823c879cd43cef700d2a352a9babd612d03cad02db134b7e225a5f0203010001";
        let der: Vec<u8> = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
        IssuerKey::new("rfc.test", &der).unwrap()
    }

    fn pass_with(keys: Vec<IssuerKey>, capacity: usize) -> PrivacyPass {
        PrivacyPass { keys, secret: b"gateway secret".to_vec(), used: Arc::new(MemoryBudgetStore::new(capacity)) }
    }

    fn pass() -> PrivacyPass {
        pass_with(vec![key()], 100)
    }

    /// A token answering `challenge`, signed with the test key, with `nonce`.
    fn mint(challenge: &[u8], nonce: [u8; 32]) -> Vec<u8> {
        let mut token = Vec::with_capacity(veritell_privacypass::TOKEN_BYTES);
        token.extend_from_slice(&veritell_privacypass::TOKEN_TYPE.to_be_bytes());
        token.extend_from_slice(&nonce);
        token.extend_from_slice(&challenge_digest(challenge));
        token.extend_from_slice(key().key_id());
        let signer = RsaKeyPair::from_der(PRIVATE).expect("the test private key");
        let mut signature = vec![0u8; signer.public().modulus_len()];
        signer.sign(&RSA_PSS_SHA384, &SystemRandom::new(), &token, &mut signature).expect("signing");
        token.extend_from_slice(&signature);
        assert_eq!(token.len(), veritell_privacypass::TOKEN_BYTES);
        token
    }

    fn authorization(token: &[u8]) -> String {
        format!("PrivateToken token=\"{}\"", URL_SAFE_NO_PAD.encode(token))
    }

    /// The challenge the gateway sends `origin` at `now`.
    fn offered(p: &PrivacyPass, origin: &str, now: u64) -> Vec<u8> {
        let header = p.offer(origin, now).expect("a challenge is offered");
        let start = header.find("challenge=\"").expect("a challenge") + "challenge=\"".len();
        let end = start + header[start..].find('"').expect("closing quote");
        URL_SAFE.decode(&header[start..end]).expect("base64url challenge")
    }

    // ---------- parse_issuers ----------

    #[test]
    fn issuers_are_read_from_the_flag() {
        let b64 = URL_SAFE_NO_PAD.encode(SPKI);
        let keys = parse_issuers(&format!(" {ISSUER}={b64} ")).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_id(), key().key_id());
    }

    #[test]
    fn bad_issuer_flags_are_refused_with_a_reason() {
        let b64 = URL_SAFE_NO_PAD.encode(SPKI);
        let no_equals = parse_issuers("issuer.test").unwrap_err();
        assert!(no_equals.contains("is not name=key"), "{no_equals}");
        let bad_key = parse_issuers("issuer.test=AAAA").unwrap_err();
        assert!(bad_key.starts_with("issuer.test: "), "{bad_key}");
        let bad_name = parse_issuers(&format!("[::1]={b64}")).unwrap_err();
        assert!(bad_name.starts_with("[::1]: "), "{bad_name}");
        let twice = parse_issuers(&format!("a.test={b64},b.test={b64}")).unwrap_err();
        assert!(twice.contains("listed twice"), "{twice}");
    }

    // ---------- offer ----------

    #[test]
    fn one_challenge_is_offered_for_the_first_key() {
        let p = pass();
        let header = p.offer(SITE, NOW).unwrap();
        assert!(header.starts_with("PrivateToken challenge=\""), "{header}");
        assert_eq!(header.matches("challenge=").count(), 1);
        assert!(header.contains(&format!("token-key=\"{}\"", key().token_key())), "{header}");
    }

    #[test]
    fn no_challenge_without_a_key_or_a_server_name() {
        assert!(pass_with(Vec::new(), 10).offer(SITE, NOW).is_none(), "no issuer configured");
        assert!(pass().offer("[2001:db8::1]", NOW).is_none(), "an address literal is not a name");
        assert!(pass().offer("", NOW).is_none());
    }

    #[test]
    fn challenges_differ_by_site_and_window_and_secret() {
        let p = pass();
        let here = offered(&p, SITE, NOW);
        assert_eq!(here, offered(&p, SITE, NOW + 1), "the same window");
        assert_ne!(here, offered(&p, "other.test", NOW), "another site");
        assert_ne!(here, offered(&p, SITE, NOW + WINDOW_SECS), "the next window");
        let other_gateway = PrivacyPass { secret: b"another secret".to_vec(), ..pass() };
        assert_ne!(here, offered(&other_gateway, SITE, NOW), "another gateway's secret");
    }

    // ---------- redeem ----------

    #[test]
    fn requests_without_our_credentials_are_left_alone() {
        let p = pass();
        assert_eq!(p.redeem(None, SITE, NOW), Redemption::None);
        assert_eq!(p.redeem(Some("Bearer abc"), SITE, NOW), Redemption::None);
        assert_eq!(p.redeem(Some("Basic dXNlcjpwYXNz"), SITE, NOW), Redemption::None);
    }

    #[test]
    fn our_scheme_without_a_usable_token_is_refused() {
        let p = pass();
        assert_eq!(p.redeem(Some("PrivateToken token=\"!!!\""), SITE, NOW), Redemption::Refused("token_invalid"));
        let short = authorization(&[0u8; 10]);
        assert_eq!(p.redeem(Some(&short), SITE, NOW), Redemption::Refused("token_invalid"));
    }

    #[test]
    fn a_token_for_the_offered_challenge_is_redeemed_once() {
        let p = pass();
        let token = mint(&offered(&p, SITE, NOW), [1; 32]);
        let auth = authorization(&token);
        assert_eq!(p.redeem(Some(&auth), SITE, NOW), Redemption::Redeemed);
        assert_eq!(p.redeem(Some(&auth), SITE, NOW + 1), Redemption::Refused("token_replayed"));
    }

    #[test]
    fn tokens_that_share_the_first_half_of_their_nonce_are_two_tokens() {
        let p = pass();
        let challenge = offered(&p, SITE, NOW);
        let mut a = [7u8; 32];
        let mut b = [7u8; 32];
        a[31] = 1;
        b[31] = 2;
        assert_eq!(p.redeem(Some(&authorization(&mint(&challenge, a))), SITE, NOW), Redemption::Redeemed);
        assert_eq!(p.redeem(Some(&authorization(&mint(&challenge, b))), SITE, NOW), Redemption::Redeemed);
    }

    #[test]
    fn a_token_is_taken_in_its_window_and_the_next_only() {
        let p = pass();
        let start = NOW - NOW % WINDOW_SECS;
        let challenge = offered(&p, SITE, start);
        let next = authorization(&mint(&challenge, [2; 32]));
        assert_eq!(p.redeem(Some(&next), SITE, start + WINDOW_SECS + 10), Redemption::Redeemed, "the next window");
        let late = authorization(&mint(&challenge, [3; 32]));
        assert_eq!(
            p.redeem(Some(&late), SITE, start + 2 * WINDOW_SECS),
            Redemption::Refused("token_wrong_challenge"),
            "two windows later"
        );
    }

    #[test]
    fn a_replay_is_remembered_until_its_challenge_is_no_longer_taken() {
        let p = pass();
        let start = NOW - NOW % WINDOW_SECS;
        let auth = authorization(&mint(&offered(&p, SITE, start), [4; 32]));
        assert_eq!(p.redeem(Some(&auth), SITE, start), Redemption::Redeemed);
        let last_moment = start + 2 * WINDOW_SECS - 1;
        assert_eq!(p.redeem(Some(&auth), SITE, last_moment), Redemption::Refused("token_replayed"));
        assert_eq!(
            p.redeem(Some(&auth), SITE, last_moment + 1),
            Redemption::Refused("token_wrong_challenge"),
            "after the window the challenge refuses it, not the store"
        );
    }

    #[test]
    fn a_token_fetched_for_another_site_is_refused() {
        let p = pass();
        let auth = authorization(&mint(&offered(&p, "other.test", NOW), [5; 32]));
        assert_eq!(p.redeem(Some(&auth), SITE, NOW), Redemption::Refused("token_wrong_challenge"));
    }

    #[test]
    fn a_token_from_an_issuer_that_is_not_trusted_is_refused() {
        let signer = pass();
        let auth = authorization(&mint(&offered(&signer, SITE, NOW), [6; 32]));
        let other = pass_with(vec![rfc_key()], 10);
        assert_eq!(other.redeem(Some(&auth), SITE, NOW), Redemption::Refused("token_unknown_issuer"));
    }

    #[test]
    fn a_token_with_a_broken_signature_is_refused() {
        let p = pass();
        let mut token = mint(&offered(&p, SITE, NOW), [8; 32]);
        let last = token.len() - 1;
        token[last] ^= 1;
        assert_eq!(p.redeem(Some(&authorization(&token)), SITE, NOW), Redemption::Refused("token_invalid"));
    }

    #[test]
    fn a_full_store_refuses_rather_than_forgets() {
        let p = pass_with(vec![key()], 1);
        let challenge = offered(&p, SITE, NOW);
        assert_eq!(p.redeem(Some(&authorization(&mint(&challenge, [9; 32]))), SITE, NOW), Redemption::Redeemed);
        assert_eq!(
            p.redeem(Some(&authorization(&mint(&challenge, [10; 32]))), SITE, NOW),
            Redemption::Refused("token_store_full")
        );
    }

    #[test]
    fn tokens_for_any_listed_key_are_taken() {
        let p = pass_with(vec![rfc_key(), key()], 10);
        // Only the first key's challenge is offered; build the second key's
        // the same way the gateway does.
        let challenge = p.challenge(&p.keys[1], SITE, NOW / WINDOW_SECS).unwrap();
        let auth = authorization(&mint(&challenge, [11; 32]));
        assert_eq!(p.redeem(Some(&auth), SITE, NOW), Redemption::Redeemed);
    }
}
