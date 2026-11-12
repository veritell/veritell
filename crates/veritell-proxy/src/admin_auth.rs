//! Who may use the admin listener.
//!
//! The listener serves the dashboard: every request the gateway has seen,
//! with addresses. When a token is configured (`VERITELL_ADMIN_TOKEN`),
//! nothing on the listener is served without it.
//!
//! Two ways to present the token, both in `Authorization`:
//! - `Bearer <token>`, for scripts;
//! - `Basic <base64 of user:password>` with the token as the password and
//!   any user name, so that a browser can ask for it.
//!
//! THE FUNCTION SIGNATURES, DOC COMMENTS AND THE TEST MODULE ARE FIXED BY
//! THE PROJECT LEAD. Implement the two function bodies.

/// Shortest token accepted at start-up.
pub const MIN_TOKEN_BYTES: usize = 16;

/// Compares two byte strings in time that depends only on their lengths:
/// every byte of the shorter is looked at whether or not an earlier one
/// differed. Different lengths are unequal.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = u8::from(a.len() != b.len());
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    std::hint::black_box(diff) == 0
}

/// Whether an `Authorization` header value carries `token`.
///
/// - `None`, or a value longer than 4096 bytes: false.
/// - The scheme is the text before the first space, compared without regard
///   to case; the credentials are the rest, with leading and trailing spaces
///   removed.
/// - `Bearer`: the credentials must equal the token.
/// - `Basic`: the credentials must be standard base64 (with padding) of
///   `user:password`; the password is everything after the first `:` and
///   must equal the token. The user name is ignored. No `:` is false.
/// - Any other scheme: false.
/// - An empty token never matches.
///
/// Every comparison with the token goes through [`constant_time_eq`].
/// Nothing here logs or returns the token or the credentials.
pub fn authorized(header: Option<&str>, token: &[u8]) -> bool {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;

    let Some(value) = header else {
        return false;
    };
    if token.is_empty() || value.len() > 4096 {
        return false;
    }
    let Some((scheme, rest)) = value.split_once(' ') else {
        return false;
    };
    let credentials = rest.trim_matches(' ');
    if scheme.eq_ignore_ascii_case("bearer") {
        constant_time_eq(credentials.as_bytes(), token)
    } else if scheme.eq_ignore_ascii_case("basic") {
        let Ok(decoded) = STANDARD.decode(credentials) else {
            return false;
        };
        match decoded.iter().position(|&b| b == b':') {
            Some(colon) => decoded.get(colon + 1..).is_some_and(|password| constant_time_eq(password, token)),
            None => false,
        }
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    // Written by the project lead. DO NOT EDIT.
    use super::*;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use base64::Engine as _;

    const TOKEN: &[u8] = b"correct-horse-battery-staple";

    fn basic(user_and_password: &str) -> String {
        format!("Basic {}", STANDARD.encode(user_and_password))
    }

    #[test]
    fn constant_time_comparison() {
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"xbc"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"ab", b"abc"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(!constant_time_eq(&[0u8; 64], &[1u8; 64]));
    }

    #[test]
    fn bearer() {
        assert!(authorized(Some("Bearer correct-horse-battery-staple"), TOKEN));
        assert!(authorized(Some("bearer correct-horse-battery-staple"), TOKEN));
        assert!(authorized(Some("BEARER   correct-horse-battery-staple  "), TOKEN));
        for bad in [
            "Bearer",
            "Bearer ",
            "Bearer correct-horse-battery-stapl",
            "Bearer correct-horse-battery-staple!",
            "Bearer Correct-horse-battery-staple",
            "Bearer correct-horse-battery-staple extra",
            "Bearercorrect-horse-battery-staple",
            "correct-horse-battery-staple",
            "Token correct-horse-battery-staple",
            "",
            " Bearer correct-horse-battery-staple",
        ] {
            assert!(!authorized(Some(bad), TOKEN), "{bad:?}");
        }
    }

    #[test]
    fn basic_with_the_token_as_password() {
        assert!(authorized(Some(&basic("admin:correct-horse-battery-staple")), TOKEN));
        assert!(authorized(Some(&basic(":correct-horse-battery-staple")), TOKEN));
        assert!(authorized(Some(&basic("any user at all:correct-horse-battery-staple")), TOKEN));
        assert!(authorized(Some(&basic("a:correct-horse-battery-staple").replace("Basic", "basic")), TOKEN));
        // A token that itself contains a colon: everything after the first one.
        assert!(authorized(Some(&basic("u:part:two-part:two-x")), b"part:two-part:two-x"));
        for bad in [
            basic("correct-horse-battery-staple"),
            basic("correct-horse-battery-staple:"),
            basic("correct-horse-battery-staple:admin"),
            basic("admin:wrong"),
            basic("admin:correct-horse-battery-staple "),
            basic(""),
            "Basic".to_string(),
            "Basic !!!not base64!!!".to_string(),
            format!("Basic {}", URL_SAFE_NO_PAD.encode("admin:correct-horse-battery-staple")),
            "Basic correct-horse-battery-staple".to_string(),
        ] {
            assert!(!authorized(Some(&bad), TOKEN), "{bad:?}");
        }
    }

    #[test]
    fn nothing_and_too_much() {
        assert!(!authorized(None, TOKEN));
        assert!(!authorized(None, b""));
        // An empty token never matches, whatever is sent.
        assert!(!authorized(Some("Bearer "), b""));
        assert!(!authorized(Some("Bearer"), b""));
        assert!(!authorized(Some(&basic("admin:")), b""));
        // Oversized values are refused before they are decoded.
        let long_token = vec![b'a'; 5000];
        let long = format!("Bearer {}", "a".repeat(5000));
        assert!(!authorized(Some(&long), &long_token));
        assert!(authorized(Some(&format!("Bearer {}", "a".repeat(4000))), &[b'a'; 4000]));
        // Bytes that are not text in a Basic value do not panic.
        assert!(!authorized(Some(&format!("Basic {}", STANDARD.encode([0xff, 0xfe, b':', 0xff]))), TOKEN));
        assert!(authorized(Some(&format!("Basic {}", STANDARD.encode([0xff, b':', 0xfe, 0xfd]))), &[0xfe, 0xfd]));
    }
}
