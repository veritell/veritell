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
