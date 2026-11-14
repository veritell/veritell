//! Known-person marks, for measuring false positives.
//!
//! The operator gives a person a private link, `/__veritell/known/<label>/<mac>`
//! (made with `tools/known_link.py`). Opening it sets a cookie in that browser.
//! From then on every event from that browser carries the label in `known`.
//!
//! The mark is for measurement only. It never reaches scoring, policy or the
//! model: a request is judged the same with or without it (gate G18). Labels
//! are the operator's choice and should not be names: `p03-phone` rather than
//! a person's name. Off unless `VERITELL_KNOWN_KEY` is set.

use hmac::{Hmac, Mac};
use sha2::Sha256;

pub const ENROL_PREFIX: &str = "/__veritell/known/";
/// `__Host-`: only over HTTPS, for this host, path `/`.
pub const COOKIE: &str = "__Host-veritell-known";
/// Ninety days.
pub const COOKIE_MAX_AGE: u64 = 90 * 24 * 3600;
/// Hex characters of the MAC kept in links and cookies (128 bits).
const MAC_HEX: usize = 32;

pub struct KnownKey(Vec<u8>);

fn valid_label(label: &str) -> bool {
    (1..=32).contains(&label.len())
        && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Compares without stopping at the first difference.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl KnownKey {
    /// `None` when `VERITELL_KNOWN_KEY` is not set; an error when it is
    /// shorter than 32 bytes.
    pub fn from_env() -> Option<Result<KnownKey, String>> {
        let raw = std::env::var("VERITELL_KNOWN_KEY").ok()?;
        Some(if raw.len() < 32 {
            Err("VERITELL_KNOWN_KEY must be at least 32 bytes".to_string())
        } else {
            Ok(KnownKey(raw.into_bytes()))
        })
    }

    #[cfg(test)]
    pub(crate) fn new(key: &[u8]) -> KnownKey {
        KnownKey(key.to_vec())
    }

    /// The MAC of a label: HMAC-SHA256 under the key, over
    /// `"veritell-known\0" + label`, the first 32 hex characters.
    fn mac(&self, label: &str) -> String {
        let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(&self.0) else {
            return String::new();
        };
        mac.update(b"veritell-known\0");
        mac.update(label.as_bytes());
        let out = mac.finalize().into_bytes();
        out.iter().map(|b| format!("{b:02x}")).collect::<String>()[..MAC_HEX].to_string()
    }

    fn check<'a>(&self, label: &'a str, mac: &str) -> Option<&'a str> {
        (valid_label(label) && same(self.mac(label).as_bytes(), mac.as_bytes())).then_some(label)
    }

    /// The label of a valid enrolment path.
    pub fn label_from_path<'a>(&self, path: &'a str) -> Option<&'a str> {
        let (label, mac) = path.strip_prefix(ENROL_PREFIX)?.split_once('/')?;
        self.check(label, mac)
    }

    /// The label in a valid cookie, from a `Cookie` header.
    pub fn label_from_cookie<'a>(&self, cookie_header: &'a str) -> Option<&'a str> {
        let value = crate::util::cookie_value(cookie_header, COOKIE)?;
        let (label, mac) = value.split_once('.')?;
        self.check(label, mac)
    }

    /// The `Set-Cookie` value for a label.
    pub fn set_cookie(&self, label: &str) -> String {
        format!(
            "{COOKIE}={label}.{}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={COOKIE_MAX_AGE}",
            self.mac(label)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> KnownKey {
        KnownKey::new(b"0123456789abcdef0123456789abcdef")
    }

    #[test]
    fn a_link_and_its_cookie_name_the_label() {
        let k = key();
        let mac = k.mac("p03-phone");
        assert_eq!(mac.len(), 32);
        assert_eq!(k.label_from_path(&format!("/__veritell/known/p03-phone/{mac}")), Some("p03-phone"));
        let cookie = k.set_cookie("p03-phone");
        let value = cookie.split(';').next().unwrap();
        assert_eq!(k.label_from_cookie(&format!("a=b; {value}; c=d")), Some("p03-phone"));
        assert!(cookie.contains("Secure; HttpOnly; SameSite=Lax"));
    }

    #[test]
    fn anything_else_is_not_a_label() {
        let k = key();
        let mac = k.mac("p03-phone");
        let other = KnownKey::new(b"another key, also 32 bytes long!");
        for path in [
            format!("/__veritell/known/p04-phone/{mac}"),
            format!("/__veritell/known/p03-phone/{}", &mac[..31]),
            format!("/__veritell/known/p03-phone/{mac}0"),
            format!("/__veritell/known/P03-phone/{mac}"),
            format!("/__veritell/known/p03-phone/{}", mac.to_uppercase()),
            "/__veritell/known/p03-phone".to_string(),
            "/__veritell/known/".to_string(),
        ] {
            assert_eq!(k.label_from_path(&path), None, "{path}");
        }
        assert_eq!(other.label_from_path(&format!("/__veritell/known/p03-phone/{mac}")), None);
        assert_eq!(k.label_from_cookie(&format!("{COOKIE}=p03-phone")), None);
        assert_eq!(k.label_from_cookie(&format!("{COOKIE}=p04-phone.{mac}")), None);
        assert_eq!(k.label_from_cookie(&format!("x{COOKIE}=p03-phone.{mac}")), None);
        assert!(!valid_label(&"a".repeat(33)));
        assert!(!valid_label("a b"));
        assert!(!valid_label("a.b"));
    }
}
