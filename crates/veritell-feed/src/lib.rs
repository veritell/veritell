//! Signed data feed: the bundle that carries truth tables, rules and models
//! from whoever maintains detections to a running gateway.
//!
//! A bundle is one JSON document:
//!
//! ```json
//! { "manifest": "<base64>", "signature": "<base64>", "files": { "<name>": "<base64>", ... } }
//! ```
//!
//! `manifest` decodes to the exact bytes that were signed, a JSON object:
//!
//! ```json
//! { "format": 1, "version": 7, "created": 1700000000, "expires": 1700600000,
//!   "files": { "<name>": { "sha256": "<lowercase hex>", "len": 123 }, ... } }
//! ```
//!
//! `signature` is an Ed25519 signature over those manifest bytes. All base64
//! is the standard alphabet with padding.
//!
//! PUBLIC API IS FIXED. Implement the bodies; do not change signatures.
//! A bundle is untrusted until its signature verifies: nothing inside the
//! manifest may be interpreted before that, and nothing here may panic.
//! All times are Unix seconds supplied by the caller.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Largest accepted bundle, in bytes.
pub const MAX_BUNDLE_BYTES: usize = 8 * 1024 * 1024;
/// Most files in one bundle.
pub const MAX_FILES: usize = 32;
/// Longest file name. Names use only `[a-z0-9_.-]` and do not start with `.`.
pub const MAX_NAME_BYTES: usize = 64;
/// The only bundle format understood.
pub const FORMAT: u64 = 1;
/// A bundle whose `created` is further in the future than this is refused.
pub const CLOCK_SKEW_SECS: u64 = 300;

/// An Ed25519 public key trusted to sign feeds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeedKey(pub [u8; 32]);

impl FeedKey {
    /// Parses 32 bytes of base64url without padding (the JWK `x` form).
    pub fn from_base64url(text: &str) -> Option<FeedKey> {
        let raw = URL_SAFE_NO_PAD.decode(text).ok()?;
        let key: [u8; 32] = raw.as_slice().try_into().ok()?;
        Some(FeedKey(key))
    }
}

/// A verified bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bundle {
    pub version: u64,
    pub created: u64,
    pub expires: u64,
    files: BTreeMap<String, Vec<u8>>,
}

impl Bundle {
    pub fn file(&self, name: &str) -> Option<&[u8]> {
        self.files.get(name).map(Vec::as_slice)
    }

    /// File names in ascending order.
    pub fn names(&self) -> Vec<&str> {
        self.files.keys().map(String::as_str).collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FeedError {
    /// Longer than [`MAX_BUNDLE_BYTES`].
    TooLarge,
    /// The outer document is not JSON of the expected shape, or a base64
    /// field does not decode.
    Malformed,
    /// No trusted key verifies the signature (including: no keys given).
    Signature,
    /// The signed manifest is not valid JSON of the expected shape.
    Manifest,
    /// `format` is not [`FORMAT`].
    Format(u64),
    /// `created` is more than [`CLOCK_SKEW_SECS`] after `now`.
    NotYetValid,
    /// `now` is after `expires`, or `expires < created`.
    Expired,
    /// `version` is lower than the caller's minimum.
    Rollback { minimum: u64, got: u64 },
    /// More than [`MAX_FILES`] files, or a file name that breaks the rules.
    /// The payload is the offending name, or "" for the count.
    Name(String),
    /// The manifest lists a file that the bundle does not carry.
    Missing(String),
    /// The bundle carries a file that the manifest does not list.
    Unlisted(String),
    /// A file's length or SHA-256 differs from the manifest.
    Hash(String),
}

impl std::fmt::Display for FeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FeedError::TooLarge => write!(f, "bundle too large"),
            FeedError::Malformed => write!(f, "bundle is malformed"),
            FeedError::Signature => write!(f, "bundle signature does not verify"),
            FeedError::Manifest => write!(f, "signed manifest is malformed"),
            FeedError::Format(n) => write!(f, "unsupported bundle format {n}"),
            FeedError::NotYetValid => write!(f, "bundle is dated in the future"),
            FeedError::Expired => write!(f, "bundle has expired"),
            FeedError::Rollback { minimum, got } => {
                write!(f, "bundle version {got} is older than {minimum}")
            }
            FeedError::Name(n) => write!(f, "bad file name or too many files: {n:?}"),
            FeedError::Missing(n) => write!(f, "file listed but absent: {n}"),
            FeedError::Unlisted(n) => write!(f, "file present but not listed: {n}"),
            FeedError::Hash(n) => write!(f, "file does not match its hash: {n}"),
        }
    }
}

impl std::error::Error for FeedError {}

/// Verifies and opens a bundle.
///
/// Checks, in this order; the first failure decides the error:
/// 1. Length (`TooLarge`).
/// 2. Outer JSON shape and base64 of `manifest` and `signature`
///    (`Malformed`). A signature that is not 64 bytes is `Malformed`.
/// 3. Signature over the manifest bytes with `verify_strict`, trying each
///    key (`Signature`).
/// 4. Manifest JSON (`Manifest`), then `format` (`Format`).
/// 5. `created > now + CLOCK_SKEW_SECS` (`NotYetValid`); `now > expires` or
///    `expires < created` (`Expired`).
/// 6. `version < min_version` (`Rollback`).
/// 7. File count and names from the manifest (`Name`).
/// 8. Every listed file is present (`Missing`), decodes as base64
///    (`Malformed`), and matches `len` and `sha256` (`Hash`); no file is
///    present that is not listed (`Unlisted`). Files are checked in
///    ascending name order, listed files first.
pub fn open(bytes: &[u8], keys: &[FeedKey], now: u64, min_version: u64) -> Result<Bundle, FeedError> {
    // 1. Length.
    if bytes.len() > MAX_BUNDLE_BYTES {
        return Err(FeedError::TooLarge);
    }
    // 2. Outer shape. Only the shape is read here; nothing is trusted yet.
    let outer: Value = serde_json::from_slice(bytes).map_err(|_| FeedError::Malformed)?;
    let Value::Object(mut outer) = outer else {
        return Err(FeedError::Malformed);
    };
    let manifest_b64 = take_string(&mut outer, "manifest")?;
    let signature_b64 = take_string(&mut outer, "signature")?;
    let carried = match outer.remove("files") {
        Some(Value::Object(map)) => map,
        _ => return Err(FeedError::Malformed),
    };
    drop(outer);
    let manifest_bytes = STANDARD.decode(manifest_b64.as_bytes()).map_err(|_| FeedError::Malformed)?;
    let signature_bytes = STANDARD.decode(signature_b64.as_bytes()).map_err(|_| FeedError::Malformed)?;
    let signature_array: [u8; 64] = signature_bytes.as_slice().try_into().map_err(|_| FeedError::Malformed)?;
    let signature = Signature::from_bytes(&signature_array);

    // 3. Signature over the exact manifest bytes, before any parsing of them.
    let verified = keys.iter().any(|key| {
        VerifyingKey::from_bytes(&key.0)
            .map(|vk| vk.verify_strict(&manifest_bytes, &signature).is_ok())
            .unwrap_or(false)
    });
    if !verified {
        return Err(FeedError::Signature);
    }

    // 4. Manifest JSON, then format.
    let manifest = parse_manifest(&manifest_bytes)?;
    if manifest.format != FORMAT {
        return Err(FeedError::Format(manifest.format));
    }
    // 5. Times.
    if manifest.created > now.saturating_add(CLOCK_SKEW_SECS) {
        return Err(FeedError::NotYetValid);
    }
    if now > manifest.expires || manifest.expires < manifest.created {
        return Err(FeedError::Expired);
    }
    // 6. Rollback.
    if manifest.version < min_version {
        return Err(FeedError::Rollback { minimum: min_version, got: manifest.version });
    }
    // 7. Count, then names in ascending order.
    if manifest.files.len() > MAX_FILES {
        return Err(FeedError::Name(String::new()));
    }
    for name in manifest.files.keys() {
        if !valid_name(name) {
            return Err(FeedError::Name(name.clone()));
        }
    }
    // 8. Files, listed ones first, in ascending order.
    let mut carried: BTreeMap<String, Value> = carried.into_iter().collect();
    let mut files = BTreeMap::new();
    for (name, entry) in manifest.files {
        let Some(value) = carried.remove(&name) else {
            return Err(FeedError::Missing(name));
        };
        let Value::String(text) = value else {
            return Err(FeedError::Malformed);
        };
        let content = STANDARD.decode(text.as_bytes()).map_err(|_| FeedError::Malformed)?;
        drop(text);
        let len_ok = u64::try_from(content.len()).map(|l| l == entry.len).unwrap_or(false);
        let digest = hex_lower(&Sha256::digest(&content));
        if !len_ok || !ct_eq(digest.as_bytes(), entry.sha256.as_bytes()) {
            return Err(FeedError::Hash(name));
        }
        files.insert(name, content);
    }
    if let Some(name) = carried.into_keys().next() {
        return Err(FeedError::Unlisted(name));
    }
    Ok(Bundle { version: manifest.version, created: manifest.created, expires: manifest.expires, files })
}

struct Entry {
    sha256: String,
    len: u64,
}

struct Manifest {
    format: u64,
    version: u64,
    created: u64,
    expires: u64,
    files: BTreeMap<String, Entry>,
}

fn take_string(map: &mut Map<String, Value>, key: &str) -> Result<String, FeedError> {
    match map.remove(key) {
        Some(Value::String(s)) => Ok(s),
        _ => Err(FeedError::Malformed),
    }
}

fn parse_manifest(bytes: &[u8]) -> Result<Manifest, FeedError> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| FeedError::Manifest)?;
    let Value::Object(map) = value else {
        return Err(FeedError::Manifest);
    };
    let num = |key: &str| map.get(key).and_then(Value::as_u64).ok_or(FeedError::Manifest);
    let Some(Value::Object(listed)) = map.get("files") else {
        return Err(FeedError::Manifest);
    };
    let mut files = BTreeMap::new();
    for (name, entry) in listed {
        let Value::Object(entry) = entry else {
            return Err(FeedError::Manifest);
        };
        let sha256 = match entry.get("sha256") {
            Some(Value::String(s)) if is_lower_hex_64(s) => s.clone(),
            _ => return Err(FeedError::Manifest),
        };
        let len = entry.get("len").and_then(Value::as_u64).ok_or(FeedError::Manifest)?;
        files.insert(name.clone(), Entry { sha256, len });
    }
    Ok(Manifest {
        format: num("format")?,
        version: num("version")?,
        created: num("created")?,
        expires: num("expires")?,
        files,
    })
}

fn is_lower_hex_64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_BYTES
        && !name.starts_with('.')
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b'-'))
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        out.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
    }
    out
}

/// Equality that looks at every byte regardless of where they first differ.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Builds and signs a bundle. This is the signer's side; the gateway never
/// calls it. `seed` is the Ed25519 private seed.
///
/// Fails with `Name` if there are too many files or a name breaks the rules,
/// `Expired` if `expires < created`, and `TooLarge` if the result would
/// exceed [`MAX_BUNDLE_BYTES`].
pub fn seal(
    files: &BTreeMap<String, Vec<u8>>,
    version: u64,
    created: u64,
    expires: u64,
    seed: &[u8; 32],
) -> Result<Vec<u8>, FeedError> {
    if files.len() > MAX_FILES {
        return Err(FeedError::Name(String::new()));
    }
    for name in files.keys() {
        if !valid_name(name) {
            return Err(FeedError::Name(name.clone()));
        }
    }
    if expires < created {
        return Err(FeedError::Expired);
    }
    // Cheap lower bound on the output size, so a huge input is refused before
    // it is encoded.
    let encoded_lower_bound = files
        .values()
        .fold(0usize, |acc, v| acc.saturating_add(v.len().div_ceil(3).saturating_mul(4)));
    if encoded_lower_bound > MAX_BUNDLE_BYTES {
        return Err(FeedError::TooLarge);
    }

    let mut listed = Map::new();
    let mut carried = Map::new();
    for (name, content) in files {
        let mut entry = Map::new();
        entry.insert("len".into(), Value::from(content.len() as u64));
        entry.insert("sha256".into(), Value::String(hex_lower(&Sha256::digest(content))));
        listed.insert(name.clone(), Value::Object(entry));
        carried.insert(name.clone(), Value::String(STANDARD.encode(content)));
    }
    let mut manifest = Map::new();
    manifest.insert("created".into(), Value::from(created));
    manifest.insert("expires".into(), Value::from(expires));
    manifest.insert("files".into(), Value::Object(listed));
    manifest.insert("format".into(), Value::from(FORMAT));
    manifest.insert("version".into(), Value::from(version));
    let manifest_bytes = serde_json::to_vec(&Value::Object(manifest)).map_err(|_| FeedError::Manifest)?;
    let signature = SigningKey::from_bytes(seed).sign(&manifest_bytes);

    let mut outer = Map::new();
    outer.insert("files".into(), Value::Object(carried));
    outer.insert("manifest".into(), Value::String(STANDARD.encode(&manifest_bytes)));
    outer.insert("signature".into(), Value::String(STANDARD.encode(signature.to_bytes())));
    let out = serde_json::to_vec(&Value::Object(outer)).map_err(|_| FeedError::Malformed)?;
    if out.len() > MAX_BUNDLE_BYTES {
        return Err(FeedError::TooLarge);
    }
    Ok(out)
}

/// The public key for a private seed, for configuring gateways.
pub fn public_key(seed: &[u8; 32]) -> FeedKey {
    FeedKey(SigningKey::from_bytes(seed).verifying_key().to_bytes())
}

/// A value that can be replaced while other threads are reading it.
///
/// Readers take a cheap reference-counted snapshot and never wait on a
/// writer for longer than it takes to swap one pointer. A poisoned lock
/// must not cause a panic.
pub struct Live<T> {
    current: RwLock<Arc<T>>,
}

impl<T> Live<T> {
    pub fn new(value: T) -> Live<T> {
        Live { current: RwLock::new(Arc::new(value)) }
    }

    /// The current value.
    pub fn load(&self) -> Arc<T> {
        let guard = self.current.read().unwrap_or_else(|e| e.into_inner());
        Arc::clone(&guard)
    }

    /// Replaces the value. Snapshots taken earlier stay valid.
    pub fn store(&self, value: T) {
        let fresh = Arc::new(value);
        let old = {
            let mut guard = self.current.write().unwrap_or_else(|e| e.into_inner());
            std::mem::replace(&mut *guard, fresh)
        };
        // Dropped outside the lock, in case dropping `T` is slow.
        drop(old);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [1; 32];

    fn one(name: &str) -> BTreeMap<String, Vec<u8>> {
        let mut f = BTreeMap::new();
        f.insert(name.to_string(), b"hi".to_vec());
        f
    }

    #[test]
    fn seal_output_has_sorted_stable_shape() {
        let a = seal(&one("a"), 1, 10, 20, &SEED).unwrap();
        assert_eq!(a, seal(&one("a"), 1, 10, 20, &SEED).unwrap());
        let text = String::from_utf8(a).unwrap();
        assert!(text.starts_with("{\"files\":"));
    }

    #[test]
    fn rejects_uppercase_and_short_hex_and_float_numbers() {
        let keys = [public_key(&SEED)];
        let sign = |manifest: &str| {
            let sig = SigningKey::from_bytes(&SEED).sign(manifest.as_bytes());
            format!(
                "{{\"manifest\":\"{}\",\"signature\":\"{}\",\"files\":{{}}}}",
                STANDARD.encode(manifest),
                STANDARD.encode(sig.to_bytes())
            )
            .into_bytes()
        };
        let upper = format!("{{\"format\":1,\"version\":1,\"created\":10,\"expires\":20,\"files\":{{\"a\":{{\"sha256\":\"{}\",\"len\":0}}}}}}", "A".repeat(64));
        assert_eq!(open(&sign(&upper), &keys, 15, 0), Err(FeedError::Manifest));
        let short = "{\"format\":1,\"version\":1,\"created\":10,\"expires\":20,\"files\":{\"a\":{\"sha256\":\"ab\",\"len\":0}}}";
        assert_eq!(open(&sign(short), &keys, 15, 0), Err(FeedError::Manifest));
        let float = "{\"format\":1.0,\"version\":1,\"created\":10,\"expires\":20,\"files\":{}}";
        assert_eq!(open(&sign(float), &keys, 15, 0), Err(FeedError::Manifest));
        let big = "{\"format\":1,\"version\":18446744073709551616,\"created\":10,\"expires\":20,\"files\":{}}";
        assert_eq!(open(&sign(big), &keys, 15, 0), Err(FeedError::Manifest));
        let ok = "{ \"version\": 5, \"files\": {}, \"expires\": 20, \"created\": 10, \"format\": 1 }";
        assert_eq!(open(&sign(ok), &keys, 15, 0).unwrap().version, 5);
    }

    #[test]
    fn name_checks_precede_file_checks_and_are_ascending() {
        let keys = [public_key(&SEED)];
        let h = hex_lower(&Sha256::digest(b""));
        let manifest = format!(
            "{{\"format\":1,\"version\":1,\"created\":10,\"expires\":20,\"files\":{{\"b B\":{{\"sha256\":\"{h}\",\"len\":0}},\"A\":{{\"sha256\":\"{h}\",\"len\":0}}}}}}"
        );
        let sig = SigningKey::from_bytes(&SEED).sign(manifest.as_bytes());
        let doc = format!(
            "{{\"manifest\":\"{}\",\"signature\":\"{}\",\"files\":{{}}}}",
            STANDARD.encode(&manifest),
            STANDARD.encode(sig.to_bytes())
        );
        // "A" sorts before "b B".
        assert_eq!(open(doc.as_bytes(), &keys, 15, 0), Err(FeedError::Name("A".into())));
    }

    #[test]
    fn non_string_file_value_is_malformed_and_bad_key_bytes_do_not_panic() {
        let s = seal(&one("a"), 1, 10, 20, &SEED).unwrap();
        let mut v: Value = serde_json::from_slice(&s).unwrap();
        v["files"]["a"] = Value::from(5);
        assert_eq!(open(v.to_string().as_bytes(), &[public_key(&SEED)], 15, 0), Err(FeedError::Malformed));
        // An off-curve style key must simply fail to verify.
        assert_eq!(open(&s, &[FeedKey([0xff; 32])], 15, 0), Err(FeedError::Signature));
    }

    #[test]
    fn padded_or_noncanonical_base64url_keys_are_refused() {
        let key = public_key(&SEED);
        let padded = format!("{}=", URL_SAFE_NO_PAD.encode(key.0));
        assert_eq!(FeedKey::from_base64url(&padded), None);
        let std_alpha = STANDARD.encode(key.0);
        if std_alpha.contains('+') || std_alpha.contains('/') {
            assert_eq!(FeedKey::from_base64url(&std_alpha), None);
        }
    }

    #[test]
    fn live_store_survives_poison() {
        let live = Arc::new(Live::new(1u32));
        let l2 = Arc::clone(&live);
        let _ = std::thread::spawn(move || {
            let _g = l2.current.write().unwrap();
            panic!("poison");
        })
        .join();
        live.store(2);
        assert_eq!(*live.load(), 2);
    }
}
