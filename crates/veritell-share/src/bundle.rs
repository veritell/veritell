//! The share file format (JSON entries) and its signed `veritell-feed` bundle: encode, decode, seal and open.

use std::collections::{BTreeMap, HashMap, HashSet};

use veritell_core::{Class, Detection, Layer};
use veritell_feed::FeedKey;
use serde_json::Value;

use crate::{Entry, ShareError, ShareKey, DETECTION_ID, FILE_NAME, HASH_BYTES, MAX_ENTRIES, PENALTY};

fn shareable(class: Class) -> Option<&'static str> {
    match class {
        Class::Automated => Some("automated"),
        Class::Malicious => Some("malicious"),
        _ => None,
    }
}

fn hex_digit(n: u8) -> char {
    char::from(if n < 10 { b'0' + n } else { b'a' + (n - 10) })
}

fn parse_hash(text: &str) -> Option<[u8; HASH_BYTES]> {
    let bytes = text.as_bytes();
    if bytes.len() != HASH_BYTES * 2 {
        return None;
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; HASH_BYTES];
    for (o, pair) in out.iter_mut().zip(bytes.chunks(2)) {
        let hi = nibble(*pair.first()?)?;
        let lo = nibble(*pair.get(1)?)?;
        *o = (hi << 4) | lo;
    }
    Some(out)
}

/// Writes entries as the file described in the crate documentation, in the
/// order given, with no whitespace:
/// `{"v":1,"entries":[{"h":"00112233445566778899aabbccddeeff","c":"malicious"}]}`
/// An entry whose class is neither automated nor malicious is left out.
pub fn encode(entries: &[Entry]) -> Vec<u8> {
    let mut out = String::from("{\"v\":1,\"entries\":[");
    let mut first = true;
    for e in entries {
        let Some(class) = shareable(e.class) else { continue };
        if !first {
            out.push(',');
        }
        first = false;
        out.push_str("{\"h\":\"");
        for byte in e.hash {
            out.push(hex_digit(byte >> 4));
            out.push(hex_digit(byte & 15));
        }
        out.push_str("\",\"c\":\"");
        out.push_str(class);
        out.push_str("\"}");
    }
    out.push_str("]}");
    out.into_bytes()
}

/// Reads that file, strictly. `Format` unless it is UTF-8 JSON, an object
/// with exactly the members `v` (the number 1) and `entries` (an array),
/// each entry an object with exactly `h` (32 lowercase hex digits) and `c`
/// (`"automated"` or `"malicious"`), and no hash appears twice. More than
/// `MAX_ENTRIES` entries is `TooMany`. The order of the file is kept.
pub fn decode(bytes: &[u8]) -> Result<Vec<Entry>, ShareError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ShareError::Format("not UTF-8"))?;
    let value: Value = serde_json::from_str(text).map_err(|_| ShareError::Format("not JSON"))?;
    let Value::Object(top) = value else { return Err(ShareError::Format("not an object")) };
    if top.len() != 2 {
        return Err(ShareError::Format("members are not exactly v and entries"));
    }
    if top.get("v").and_then(Value::as_u64) != Some(1) {
        return Err(ShareError::Format("v is not the number 1"));
    }
    let Some(Value::Array(list)) = top.get("entries") else {
        return Err(ShareError::Format("entries is not an array"));
    };
    if list.len() > MAX_ENTRIES {
        return Err(ShareError::TooMany);
    }
    let mut seen = HashSet::with_capacity(list.len());
    let mut out = Vec::with_capacity(list.len());
    for item in list {
        let Value::Object(obj) = item else { return Err(ShareError::Format("entry is not an object")) };
        if obj.len() != 2 {
            return Err(ShareError::Format("entry members are not exactly h and c"));
        }
        let hash = obj
            .get("h")
            .and_then(Value::as_str)
            .and_then(parse_hash)
            .ok_or(ShareError::Format("h is not 32 lowercase hex digits"))?;
        let class = match obj.get("c").and_then(Value::as_str) {
            Some("automated") => Class::Automated,
            Some("malicious") => Class::Malicious,
            _ => return Err(ShareError::Format("c is not automated or malicious")),
        };
        if !seen.insert(hash) {
            return Err(ShareError::Format("a hash appears twice"));
        }
        out.push(Entry { hash, class });
    }
    Ok(out)
}

/// Signs a bundle holding these entries (through `veritell_feed::seal`,
/// with the single file `FILE_NAME`). `TooMany` above `MAX_ENTRIES`.
pub fn seal_bundle(
    entries: &[Entry],
    version: u64,
    created: u64,
    expires: u64,
    seed: &[u8; 32],
) -> Result<Vec<u8>, ShareError> {
    if entries.len() > MAX_ENTRIES {
        return Err(ShareError::TooMany);
    }
    let mut files = BTreeMap::new();
    files.insert(FILE_NAME.to_string(), encode(entries));
    veritell_feed::seal(&files, version, created, expires, seed).map_err(ShareError::Bundle)
}

/// Verifies a bundle (through `veritell_feed::open`, so an unknown key, a
/// bad signature, an expired bundle or a version below `min_version` is
/// `ShareError::Bundle`) and reads its entries. Returns the bundle's version
/// with them. A verified bundle that holds any file other than `FILE_NAME`,
/// or not that file, is `Files`.
pub fn open_bundle(
    bytes: &[u8],
    keys: &[FeedKey],
    now: u64,
    min_version: u64,
) -> Result<(u64, Vec<Entry>), ShareError> {
    let bundle = veritell_feed::open(bytes, keys, now, min_version).map_err(ShareError::Bundle)?;
    if bundle.names() != [FILE_NAME] {
        return Err(ShareError::Files);
    }
    let file = bundle.file(FILE_NAME).ok_or(ShareError::Files)?;
    Ok((bundle.version, decode(file)?))
}

/// The entries another install shared, ready to be looked up.
#[derive(Clone, Debug, Default)]
pub struct Imported {
    by_hash: HashMap<[u8; HASH_BYTES], Class>,
}

impl Imported {
    /// Nothing imported.
    pub fn empty() -> Imported {
        Imported::default()
    }

    pub fn new(entries: &[Entry]) -> Imported {
        let mut by_hash: HashMap<[u8; HASH_BYTES], Class> = HashMap::new();
        for e in entries.iter().filter(|e| shareable(e.class).is_some()).take(MAX_ENTRIES) {
            let slot = by_hash.entry(e.hash).or_insert(e.class);
            if e.class == Class::Malicious {
                *slot = Class::Malicious;
            }
        }
        Imported { by_hash }
    }

    pub fn len(&self) -> usize {
        self.by_hash.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_hash.is_empty()
    }

    /// The detection for a fingerprint another install reported, if it did:
    /// id `DETECTION_ID`, `Layer::Population`, `PENALTY` points, **no class
    /// hint**, and a detail that names the reported class but not the hash.
    pub fn detection(&self, key: &ShareKey, fingerprint: &str) -> Option<Detection> {
        if self.by_hash.is_empty() {
            return None;
        }
        let class = self.by_hash.get(&key.hash(fingerprint))?;
        Some(Detection::new(
            DETECTION_ID,
            Layer::Population,
            PENALTY,
            format!("another install reported this fingerprint as {}", class.as_str()),
        ))
    }
}
