//! Issuer public keys for token type 0x0002: strict DER reading and RSA-PSS checking.

use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine as _;
use ring::signature::{UnparsedPublicKey, RSA_PSS_2048_8192_SHA384};
use sha2::{Digest, Sha256};

use crate::{valid_server_name, PassError};

/// The AlgorithmIdentifier of RFC 9578 section 6.5, with its SEQUENCE header.
const ALGORITHM: [u8; 63] = [
    0x30, 0x3d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, 0x30, 0x30, 0xa0, 0x0d, 0x30, 0x0b,
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0xa1, 0x1a, 0x30, 0x18, 0x06, 0x09, 0x2a, 0x86,
    0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
    0x02, 0xa2, 0x03, 0x02, 0x01, 0x30,
];

const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_SEQUENCE: u8 = 0x30;

/// URL-safe alphabet, padding accepted or absent.
const LENIENT: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// Reads one DER element: `(content, rest)`. Refuses indefinite lengths,
/// lengths not in shortest form, and anything that runs past the input.
fn read_tlv(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (found, input) = input.split_first()?;
    if *found != tag {
        return None;
    }
    let (first, input) = input.split_first()?;
    let (len, input) = if *first < 0x80 {
        (usize::from(*first), input)
    } else {
        let count = usize::from(*first & 0x7f);
        // 0x80 is the indefinite form; more than two length bytes is far
        // beyond any key.
        if count == 0 || count > 2 {
            return None;
        }
        let (bytes, input) = input.split_at_checked(count)?;
        // A leading zero length byte is never shortest form.
        if *bytes.first()? == 0 {
            return None;
        }
        let len = bytes.iter().fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
        // Under 128 the short form was required.
        if len < 0x80 {
            return None;
        }
        (len, input)
    };
    input.split_at_checked(len)
}

/// Reads one element that must be the whole of `input`.
fn read_whole(input: &[u8], tag: u8) -> Option<&[u8]> {
    let (content, rest) = read_tlv(input, tag)?;
    rest.is_empty().then_some(content)
}

/// A positive, minimally encoded INTEGER's value without its sign byte.
fn positive_integer(content: &[u8]) -> Option<&[u8]> {
    let (first, rest) = content.split_first()?;
    if *first & 0x80 != 0 {
        return None;
    }
    if *first != 0 {
        return Some(content);
    }
    // A leading zero is only there to keep the number positive.
    (*rest.first()? & 0x80 != 0).then_some(rest)
}

/// Checks the RSAPublicKey and returns it whole (it is what ring wants).
fn check_rsa_public_key(der: &[u8]) -> Result<(), &'static str> {
    let body = read_whole(der, TAG_SEQUENCE).ok_or("RSAPublicKey is not a DER SEQUENCE")?;
    let (modulus, rest) = read_tlv(body, TAG_INTEGER).ok_or("RSAPublicKey has no modulus")?;
    let (exponent, rest) = read_tlv(rest, TAG_INTEGER).ok_or("RSAPublicKey has no exponent")?;
    if !rest.is_empty() {
        return Err("RSAPublicKey has trailing bytes");
    }
    let modulus = positive_integer(modulus).ok_or("modulus is not a minimal positive INTEGER")?;
    if modulus.len() != 256 || modulus.first().is_none_or(|b| b & 0x80 == 0) {
        return Err("modulus is not 2048 bits");
    }
    let exponent = positive_integer(exponent).ok_or("exponent is not a minimal positive INTEGER")?;
    if exponent.len() > 5 {
        return Err("exponent is longer than 5 bytes");
    }
    if exponent.last().is_none_or(|b| b & 1 == 0) {
        return Err("exponent is even");
    }
    if exponent == [1] {
        return Err("exponent is 1");
    }
    Ok(())
}

/// Parses the SPKI and returns the RSAPublicKey inside it.
fn parse_spki(spki_der: &[u8]) -> Result<&[u8], &'static str> {
    let body = read_whole(spki_der, TAG_SEQUENCE).ok_or("not a DER SEQUENCE spanning the input")?;
    let rest = body.strip_prefix(ALGORITHM.as_slice()).ok_or("algorithm is not RSASSA-PSS with SHA-384, MGF1 SHA-384, salt 48")?;
    let bits = read_whole(rest, TAG_BIT_STRING).ok_or("no BIT STRING after the algorithm")?;
    let (unused, rsa) = bits.split_first().ok_or("empty BIT STRING")?;
    if *unused != 0 {
        return Err("BIT STRING has unused bits");
    }
    check_rsa_public_key(rsa)?;
    Ok(rsa)
}

/// An issuer's public key for token type `0x0002`, with the issuer's name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuerKey {
    name: String,
    spki: Vec<u8>,
    key_id: [u8; 32],
    /// The bare DER RSAPublicKey inside `spki`.
    rsa_public_key: Vec<u8>,
}

impl IssuerKey {
    /// `spki_der` is the key as RFC 9578 section 6.5 defines it: a DER
    /// SubjectPublicKeyInfo whose algorithm is `id-RSASSA-PSS` with
    /// parameters SHA-384, MGF1 with SHA-384 and salt length 48, carrying an
    /// RSAPublicKey. This is checked strictly; anything else is
    /// `PassError::Key`:
    ///
    /// - The outer SEQUENCE must span the whole input: no trailing bytes.
    ///   Lengths must be DER (shortest form).
    /// - The AlgorithmIdentifier must be, byte for byte, the 63 bytes
    ///   `303d06092a864886f70d01010a3030a00d300b0609608648016503040202`
    ///   `a11a301806092a864886f70d010108300b0609608648016503040202a2030201`
    ///   `30` (that is what the RFC's example and test vectors carry). A key
    ///   under plain `rsaEncryption`, or with other parameters, is refused.
    /// - The BIT STRING must have no unused bits and hold exactly one
    ///   RSAPublicKey: SEQUENCE { INTEGER modulus, INTEGER exponent }, both
    ///   positive and minimally encoded.
    /// - The modulus must be exactly 2048 bits (256 bytes once the leading
    ///   zero byte is removed, top bit set). The exponent must be 1 to 5
    ///   bytes, odd, and not 1.
    ///
    /// `issuer_name` must satisfy `valid_server_name`, else `PassError::Name`.
    /// The name is checked before the key.
    pub fn new(issuer_name: &str, spki_der: &[u8]) -> Result<IssuerKey, PassError> {
        if !valid_server_name(issuer_name) {
            return Err(PassError::Name);
        }
        let rsa = parse_spki(spki_der).map_err(PassError::Key)?;
        Ok(IssuerKey {
            name: issuer_name.to_owned(),
            spki: spki_der.to_vec(),
            key_id: Sha256::digest(spki_der).into(),
            rsa_public_key: rsa.to_vec(),
        })
    }

    /// Like [`IssuerKey::new`], with the key in base64url (padding optional;
    /// surrounding whitespace is not accepted). Text that is not base64url
    /// is `PassError::Key`.
    pub fn from_base64url(issuer_name: &str, text: &str) -> Result<IssuerKey, PassError> {
        if !valid_server_name(issuer_name) {
            return Err(PassError::Name);
        }
        let der = LENIENT.decode(text).map_err(|_| PassError::Key("not base64url"))?;
        IssuerKey::new(issuer_name, &der)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// SHA-256 of the key exactly as it was given (`token_key_id`).
    pub fn key_id(&self) -> &[u8; 32] {
        &self.key_id
    }

    /// The key exactly as it was given.
    pub fn spki(&self) -> &[u8] {
        &self.spki
    }

    /// The `token-key` parameter value: base64url of the key, with padding.
    pub fn token_key(&self) -> String {
        base64::engine::general_purpose::URL_SAFE.encode(&self.spki)
    }

    /// Checks an RSASSA-PSS signature (SHA-384, MGF1 SHA-384, salt 48) by
    /// this key. Used by `verify`; public so it can be tested alone.
    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> bool {
        UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA384, &self.rsa_public_key).verify(message, signature).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_constant_is_the_rfc_one() {
        assert_eq!(ALGORITHM.len(), 63);
        assert_eq!(read_whole(&ALGORITHM, TAG_SEQUENCE).map(<[u8]>::len), Some(61));
    }

    #[test]
    fn lengths_must_be_shortest_form() {
        // Short form, and long forms.
        assert!(read_tlv(&[0x04, 0x01, 0xaa], 0x04).is_some());
        let mut long = vec![0x04, 0x81, 0x80];
        long.extend([0u8; 128]);
        assert_eq!(read_tlv(&long, 0x04).map(|(c, r)| (c.len(), r.len())), Some((128, 0)));
        let mut two = vec![0x04, 0x82, 0x01, 0x00];
        two.extend([0u8; 256]);
        assert!(read_tlv(&two, 0x04).is_some());
        // 1 written in long form, a length with a leading zero byte, indefinite.
        assert!(read_tlv(&[0x04, 0x81, 0x01, 0xaa], 0x04).is_none());
        assert!(read_tlv(&[0x04, 0x82, 0x00, 0x80], 0x04).is_none());
        assert!(read_tlv(&[0x04, 0x80, 0xaa, 0x00, 0x00], 0x04).is_none());
        // Too many length bytes, or a length that runs past the input.
        assert!(read_tlv(&[0x04, 0x83, 0x00, 0x01, 0x00, 0xaa], 0x04).is_none());
        assert!(read_tlv(&[0x04, 0x05, 0xaa], 0x04).is_none());
        assert!(read_tlv(&[0x04, 0x82, 0xff, 0xff], 0x04).is_none());
        assert!(read_tlv(&[0x04], 0x04).is_none());
        assert!(read_tlv(&[], 0x04).is_none());
        // Wrong tag.
        assert!(read_tlv(&[0x05, 0x00], 0x04).is_none());
    }

    #[test]
    fn trailing_bytes_are_refused() {
        assert_eq!(read_whole(&[0x04, 0x01, 0xaa], 0x04), Some(&[0xaa][..]));
        assert_eq!(read_whole(&[0x04, 0x01, 0xaa, 0x00], 0x04), None);
        assert_eq!(read_tlv(&[0x04, 0x01, 0xaa, 0x00], 0x04), Some((&[0xaa][..], &[0x00][..])));
    }

    #[test]
    fn integers_are_positive_and_minimal() {
        assert_eq!(positive_integer(&[0x01]), Some(&[0x01][..]));
        assert_eq!(positive_integer(&[0x00, 0x80]), Some(&[0x80][..]));
        assert_eq!(positive_integer(&[0x00, 0x7f]), None);
        assert_eq!(positive_integer(&[0x00]), None);
        assert_eq!(positive_integer(&[0x80]), None);
        assert_eq!(positive_integer(&[]), None);
    }
}
