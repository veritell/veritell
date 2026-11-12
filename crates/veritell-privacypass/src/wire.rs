//! Challenges, header values and token checking for Privacy Pass (RFC 9577, 9578).

use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::{Accepted, IssuerKey, PassError, Token, MAX_AUTHORIZATION_BYTES, MAX_NAME_BYTES, TOKEN_BYTES, TOKEN_TYPE};

/// Bytes of a token that the authenticator signs: type, nonce, digest, key id.
const SIGNED_BYTES: usize = 98;

/// Whether `name` is a server name as RFC 9577 section 2.1.1.1 uses it: a
/// host and an optional port, nothing else. Here that means: 1 to
/// `MAX_NAME_BYTES` bytes; a host made of ASCII letters, digits, `-` and
/// `.`, with no empty label (no leading, trailing or doubled `.`);
/// optionally `:` and a port of 1 to 5 decimal digits between 1 and 65535.
/// No user information, no brackets, no spaces, nothing outside ASCII.
pub fn valid_server_name(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_NAME_BYTES {
        return false;
    }
    let (host, port) = match name.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (name, None),
    };
    if let Some(port) = port {
        let digits = !port.is_empty() && port.len() <= 5 && port.bytes().all(|b| b.is_ascii_digit());
        if !digits || !matches!(port.parse::<u32>(), Ok(1..=65535)) {
            return false;
        }
    }
    host.split('.').all(|label| !label.is_empty() && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
}

/// Builds a TokenChallenge of type `0x0002`.
///
/// `issuer_name` must be a valid server name. `origin_info` is empty, or
/// one or more valid server names separated by `,` with no whitespace, at
/// most 65535 bytes in all. Otherwise `PassError::Name`. Names go into the
/// challenge exactly as given.
pub fn token_challenge(
    issuer_name: &str,
    redemption_context: Option<&[u8; 32]>,
    origin_info: &str,
) -> Result<Vec<u8>, PassError> {
    if !valid_server_name(issuer_name) {
        return Err(PassError::Name);
    }
    if !origin_info.is_empty() && !origin_info.split(',').all(valid_server_name) {
        return Err(PassError::Name);
    }
    let issuer_len = u16::try_from(issuer_name.len()).map_err(|_| PassError::Name)?;
    let origin_len = u16::try_from(origin_info.len()).map_err(|_| PassError::Name)?;
    let mut out = Vec::new();
    out.extend_from_slice(&TOKEN_TYPE.to_be_bytes());
    out.extend_from_slice(&issuer_len.to_be_bytes());
    out.extend_from_slice(issuer_name.as_bytes());
    match redemption_context {
        Some(context) => {
            out.push(32);
            out.extend_from_slice(context);
        }
        None => out.push(0),
    }
    out.extend_from_slice(&origin_len.to_be_bytes());
    out.extend_from_slice(origin_info.as_bytes());
    Ok(out)
}

/// SHA-256 of a TokenChallenge.
pub fn challenge_digest(challenge: &[u8]) -> [u8; 32] {
    Sha256::digest(challenge).into()
}

/// A redemption context bound to a time window (RFC 9577 section 2.1.1.2):
/// HMAC-SHA-256 keyed with `secret` over the 32 ASCII bytes
/// `veritell privacy pass context v1` followed by `window` as eight bytes,
/// big-endian. A secret of any length is accepted, the empty one included.
pub fn redemption_context(secret: &[u8], window: u64) -> [u8; 32] {
    // HMAC accepts a key of any length, so this cannot fail.
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret) else {
        return [0; 32];
    };
    mac.update(b"veritell privacy pass context v1");
    mac.update(&window.to_be_bytes());
    mac.finalize().into_bytes().into()
}

/// The `WWW-Authenticate` value for one or more challenges, in the order
/// given:
/// `PrivateToken challenge="<b64>", token-key="<b64>", PrivateToken challenge="<b64>", token-key="<b64>"`
/// with both values base64url with padding, always quoted. An empty list
/// gives an empty string.
pub fn www_authenticate(challenges: &[(&[u8], &IssuerKey)]) -> String {
    let parts: Vec<String> = challenges
        .iter()
        .map(|(challenge, key)| {
            format!("PrivateToken challenge=\"{}\", token-key=\"{}\"", URL_SAFE.encode(challenge), key.token_key())
        })
        .collect();
    parts.join(", ")
}

/// Finds the token in an `Authorization` value.
///
/// - `Ok(None)` when the scheme is not `PrivateToken` (compared without
///   regard to case; the scheme is the text before the first space or tab).
/// - `Err(Malformed)` when the scheme is `PrivateToken` and: the value is
///   longer than `MAX_AUTHORIZATION_BYTES`; there is no `token` parameter or
///   more than one; a parameter is not `name=value`; a quoted value is not
///   closed or has text after its closing quote; or the token is empty or
///   not base64url (`A-Z a-z 0-9 - _`, with `=` padding only at the end and
///   only as much as base64 allows).
/// - `Ok(Some(bytes))` otherwise: the decoded token, of whatever length.
///
/// Parameters are separated by commas, with optional spaces or tabs around
/// names, `=` and values. Names are compared without regard to case. A value
/// is a quoted string (no escapes are recognised: a backslash is
/// `Malformed`) or bare text up to the next comma. Parameters other than
/// `token` are ignored, as the RFC requires.
pub fn token_from_authorization(value: &str) -> Result<Option<Vec<u8>>, PassError> {
    let (scheme, rest) = match value.find([' ', '\t']) {
        Some(at) => value.split_at_checked(at).unwrap_or((value, "")),
        None => (value, ""),
    };
    if !scheme.eq_ignore_ascii_case("PrivateToken") {
        return Ok(None);
    }
    if value.len() > MAX_AUTHORIZATION_BYTES {
        return Err(PassError::Malformed);
    }
    let text = token_parameter(rest).ok_or(PassError::Malformed)?;
    decode_token(text).map(Some).ok_or(PassError::Malformed)
}

/// Checks a token. In order; the first failure decides:
///
/// 1. Shorter than two bytes: `Malformed`.
/// 2. `token_type` (the first two bytes, big-endian) other than `0x0002`:
///    `UnknownType`, whatever the length.
/// 3. Not exactly `TOKEN_BYTES` long: `Malformed`.
/// 4. No key in `keys` whose `key_id` equals `token_key_id`: `UnknownKey`.
/// 5. No entry in `accepted` with this `challenge_digest` **and** this
///    `key_id`: `WrongChallenge`. This comes before the signature so that a
///    token for another site costs no RSA operation.
/// 6. The authenticator is not a valid signature by that key over the first
///    98 bytes: `BadAuthenticator`.
///
/// Replay is the caller's to refuse, using `Token::nonce`.
pub fn verify(token: &[u8], keys: &[IssuerKey], accepted: &[Accepted]) -> Result<Token, PassError> {
    let type_bytes: [u8; 2] = token.get(..2).and_then(|b| b.try_into().ok()).ok_or(PassError::Malformed)?;
    let token_type = u16::from_be_bytes(type_bytes);
    if token_type != TOKEN_TYPE {
        return Err(PassError::UnknownType(token_type));
    }
    if token.len() != TOKEN_BYTES {
        return Err(PassError::Malformed);
    }
    let nonce: [u8; 32] = token.get(2..34).and_then(|b| b.try_into().ok()).ok_or(PassError::Malformed)?;
    let digest: [u8; 32] = token.get(34..66).and_then(|b| b.try_into().ok()).ok_or(PassError::Malformed)?;
    let key_id: [u8; 32] = token.get(66..SIGNED_BYTES).and_then(|b| b.try_into().ok()).ok_or(PassError::Malformed)?;
    let signed = token.get(..SIGNED_BYTES).ok_or(PassError::Malformed)?;
    let authenticator = token.get(SIGNED_BYTES..).ok_or(PassError::Malformed)?;

    let key = keys.iter().find(|k| *k.key_id() == key_id).ok_or(PassError::UnknownKey)?;
    if !accepted.iter().any(|a| a.challenge_digest == digest && a.key_id == key_id) {
        return Err(PassError::WrongChallenge);
    }
    if !key.verify_signature(signed, authenticator) {
        return Err(PassError::BadAuthenticator);
    }
    Ok(Token { nonce, challenge_digest: digest, token_key_id: key_id })
}

fn is_blank(c: char) -> bool {
    c == ' ' || c == '\t'
}

/// The text of the one `token` parameter in `params`; `None` when the
/// parameters are malformed, or there is no `token` or more than one.
fn token_parameter(params: &str) -> Option<&str> {
    let mut token = None;
    let mut rest = params;
    loop {
        let (name, after) = rest.split_once('=')?;
        let name = name.trim_matches(is_blank);
        if name.is_empty() || name.contains([',', '"', ' ', '\t']) {
            return None;
        }
        let after = after.trim_start_matches(is_blank);
        // The value, and what follows its comma (`None` at the end).
        let (value, next) = if let Some(quoted) = after.strip_prefix('"') {
            let (inner, tail) = quoted.split_once('"')?;
            let tail = tail.trim_start_matches(is_blank);
            if tail.is_empty() {
                (inner, None)
            } else {
                (inner, Some(tail.strip_prefix(',')?))
            }
        } else {
            let (bare, next) = match after.split_once(',') {
                Some((bare, next)) => (bare, Some(next)),
                None => (after, None),
            };
            let bare = bare.trim_matches(is_blank);
            if bare.contains('"') {
                return None;
            }
            (bare, next)
        };
        if value.contains('\\') {
            return None;
        }
        if name.eq_ignore_ascii_case("token") {
            if token.is_some() {
                return None;
            }
            token = Some(value);
        }
        match next {
            Some(next) => rest = next,
            None => return token,
        }
    }
}

/// Decodes base64url written with padding only at the end and only as much
/// as base64 allows. Empty text is refused.
fn decode_token(text: &str) -> Option<Vec<u8>> {
    let body = text.trim_end_matches('=');
    let padding = text.len().checked_sub(body.len())?;
    if body.is_empty() || padding > 2 {
        return None;
    }
    if !body.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return None;
    }
    if padding > 0 && body.len().checked_add(padding)? % 4 != 0 {
        return None;
    }
    URL_SAFE_NO_PAD.decode(body).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameters_with_commas_in_quotes() {
        assert_eq!(token_parameter("realm=\"x, y\", token=\"AAIA\""), Some("AAIA"));
        assert_eq!(token_parameter(" token = AAIA , b=\"c,d\" "), Some("AAIA"));
        assert_eq!(token_parameter("a=\"token=\\"), None);
        assert_eq!(token_parameter("a=\"x, token=y"), None);
        assert_eq!(token_parameter("a=1"), None);
    }

    #[test]
    fn malformed_parameter_lists() {
        assert_eq!(token_parameter(""), None);
        assert_eq!(token_parameter("token=a,"), None);
        assert_eq!(token_parameter("token=a, token=b"), None);
        assert_eq!(token_parameter("x y=1, token=a"), None);
        assert_eq!(token_parameter("token=\"a\" b"), None);
        assert_eq!(token_parameter("token=a\"b"), None);
    }

    #[test]
    fn scheme_and_size() {
        assert_eq!(token_from_authorization("PrivateToken\ttoken=AAIA"), Ok(Some(vec![0, 2, 0])));
        assert_eq!(token_from_authorization("PRIVATETOKEN token=AAIA"), Ok(Some(vec![0, 2, 0])));
        let at_limit = format!("PrivateToken token={}", "A".repeat(MAX_AUTHORIZATION_BYTES - 20));
        assert!(token_from_authorization(&at_limit).is_ok());
        // The same text, longer by two valid base64 characters: refused for size alone.
        let over = format!("{at_limit}AA");
        assert_eq!(token_from_authorization(&over), Err(PassError::Malformed));
        // A long value of another scheme is simply not ours.
        assert_eq!(token_from_authorization(&format!("Bearer {}", "a".repeat(5000))), Ok(None));
    }

    #[test]
    fn base64_padding_rules() {
        assert_eq!(decode_token("AAIADg=="), Some(vec![0, 2, 0, 14]));
        assert_eq!(decode_token("AAIADg"), Some(vec![0, 2, 0, 14]));
        assert_eq!(decode_token("AAIADg="), None);
        assert_eq!(decode_token("AAIADg==="), None);
        assert_eq!(decode_token("A"), None);
        assert_eq!(decode_token("="), None);
        assert_eq!(decode_token("AA=A"), None);
        assert_eq!(decode_token("AA+/"), None);
    }

    #[test]
    fn names() {
        assert!(valid_server_name("a.b-c:65535"));
        assert!(!valid_server_name("a:00000"));
        assert!(!valid_server_name("a:99999"));
    }
}
