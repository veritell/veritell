//! State files that survive a restart: written whole or not at all, and
//! refused whole when anything about them is wrong.
//!
//! FIXED BY THE PROJECT LEAD: the public items and their documentation are
//! the contract. Implement the bodies (and private helpers); do not change a
//! signature. Nothing may panic for any file content.
//!
//! # Format
//!
//! ```text
//! magic     b"VERITELL-STATE 1\n"           17 bytes
//! kind_len  u8                               1 byte, 1..=64
//! kind      ASCII [a-z0-9_-]                 kind_len bytes
//! len       u64 big-endian                   8 bytes
//! payload                                    len bytes
//! digest    SHA-256 of every byte above      32 bytes
//! ```
//!
//! Nothing may follow the digest. `kind` names what the payload is (for
//! example `quota` or `used-tokens`), so that one store's file is never
//! loaded into another.

use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};

const MAGIC: &[u8; 17] = b"VERITELL-STATE 1\n";
const DIGEST_LEN: usize = 32;
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn kind_valid(kind: &str) -> bool {
    (1..=64).contains(&kind.len())
        && kind
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

fn invalid_kind() -> PersistError {
    PersistError::Io(io::Error::new(
        io::ErrorKind::InvalidInput,
        "kind must be 1..=64 bytes of [a-z0-9_-]",
    ))
}

fn write_tmp(tmp: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(tmp)?;
    f.write_all(bytes)?;
    f.sync_all()
}

/// Files larger than this are refused without being read.
pub const MAX_BYTES: u64 = 64 << 20;

#[derive(Debug)]
pub enum PersistError {
    /// Reading or writing failed, or `kind` is not valid for [`write`].
    Io(std::io::Error),
    /// The file is not a whole, intact state file of the expected kind.
    /// The text says which check failed; it never contains file content.
    Corrupt(&'static str),
}

impl fmt::Display for PersistError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PersistError::Io(e) => write!(f, "state file: {e}"),
            PersistError::Corrupt(why) => write!(f, "state file refused: {why}"),
        }
    }
}

impl std::error::Error for PersistError {}

/// Writes `payload` to `path` so that a reader sees either the old file or
/// the new one in full, never a mix, even if the process dies part-way:
/// the bytes go to a temporary file in the same directory (its name starts
/// with `.` and contains `.tmp`), which is created with mode 0600 on Unix,
/// written, synced, renamed over `path`, and then the directory is synced.
/// On any failure the temporary file is removed and `path` is untouched.
/// A `kind` that breaks the format's rules, or a payload larger than
/// [`MAX_BYTES`] (which [`read`] would refuse), is an `Io` error of kind
/// `InvalidInput`, and nothing is written.
pub fn write(path: &Path, kind: &str, payload: &[u8]) -> Result<(), PersistError> {
    if !kind_valid(kind) {
        return Err(invalid_kind());
    }
    let kind_len = u8::try_from(kind.len()).map_err(|_| invalid_kind())?;
    let len = u64::try_from(payload.len())
        .ok()
        .filter(|n| *n <= MAX_BYTES)
        .ok_or_else(|| PersistError::Io(io::Error::new(io::ErrorKind::InvalidInput, "payload larger than MAX_BYTES")))?;

    let mut buf: Vec<u8> = Vec::with_capacity(
        MAGIC
            .len()
            .saturating_add(1)
            .saturating_add(kind.len())
            .saturating_add(8)
            .saturating_add(payload.len())
            .saturating_add(DIGEST_LEN),
    );
    buf.extend_from_slice(MAGIC);
    buf.push(kind_len);
    buf.extend_from_slice(kind.as_bytes());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(payload);
    let digest = Sha256::digest(&buf);
    buf.extend_from_slice(&digest);

    let file_name = path.file_name().ok_or_else(|| {
        PersistError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path has no file name",
        ))
    })?;
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(file_name);
    tmp_name.push(format!(
        ".tmp-{}-{}",
        std::process::id(),
        TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let tmp = dir.join(tmp_name);
    // A file of this name can only be left by an earlier process with the
    // same id (in a container the gateway is always process 1) that died
    // part-way; no write in this process uses it, as the counter is atomic.
    let _ = fs::remove_file(&tmp);

    if let Err(e) = write_tmp(&tmp, &buf) {
        let _ = fs::remove_file(&tmp);
        return Err(PersistError::Io(e));
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(PersistError::Io(e));
    }
    match fs::File::open(dir).and_then(|d| d.sync_all()) {
        Ok(()) => Ok(()),
        #[cfg(unix)]
        Err(e) => Err(PersistError::Io(e)),
        #[cfg(not(unix))]
        Err(_) => Ok(()),
    }
}

/// Reads a file written by [`write`] with the same `kind`.
///
/// `Ok(None)` when there is no file at `path`. `Corrupt` when the file is
/// larger than [`MAX_BYTES`] (checked before reading), or the magic, kind,
/// length or digest is wrong, or bytes are missing or follow the digest.
/// Any other failure to read is `Io`.
pub fn read(path: &Path, kind: &str) -> Result<Option<Vec<u8>>, PersistError> {
    if !kind_valid(kind) {
        return Err(invalid_kind());
    }
    let mut f = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(PersistError::Io(e)),
    };
    let size = f.metadata().map_err(PersistError::Io)?.len();
    if size > MAX_BYTES {
        return Err(PersistError::Corrupt("file larger than the maximum size"));
    }
    let cap = usize::try_from(size)
        .map_err(|_| PersistError::Corrupt("file larger than the maximum size"))?;
    let mut data = Vec::with_capacity(cap);
    // Bounded read: one byte past the limit detects a file that grew.
    (&mut f)
        .take(MAX_BYTES.saturating_add(1))
        .read_to_end(&mut data)
        .map_err(PersistError::Io)?;
    if !matches!(u64::try_from(data.len()), Ok(n) if n <= MAX_BYTES) {
        return Err(PersistError::Corrupt("file larger than the maximum size"));
    }

    let rest = data
        .strip_prefix(MAGIC.as_slice())
        .ok_or(PersistError::Corrupt("bad magic"))?;
    let (&kind_len, rest) = rest
        .split_first()
        .ok_or(PersistError::Corrupt("truncated before kind length"))?;
    let kind_len = usize::from(kind_len);
    if !(1..=64).contains(&kind_len) {
        return Err(PersistError::Corrupt("kind length out of range"));
    }
    if rest.len() < kind_len {
        return Err(PersistError::Corrupt("truncated in kind"));
    }
    let (found_kind, rest) = rest.split_at(kind_len);
    if found_kind != kind.as_bytes() {
        return Err(PersistError::Corrupt("kind does not match"));
    }
    if rest.len() < 8 {
        return Err(PersistError::Corrupt("truncated before length"));
    }
    let (len_bytes, rest) = rest.split_at(8);
    let mut lb = [0u8; 8];
    lb.copy_from_slice(len_bytes);
    let len = u64::from_be_bytes(lb);
    let remaining = rest
        .len()
        .checked_sub(DIGEST_LEN)
        .ok_or(PersistError::Corrupt("truncated before digest"))?;
    if u64::try_from(remaining) != Ok(len) {
        return Err(PersistError::Corrupt("length does not match file size"));
    }
    let (payload, digest) = rest.split_at(remaining);
    let signed_len = data
        .len()
        .checked_sub(DIGEST_LEN)
        .ok_or(PersistError::Corrupt("truncated before digest"))?;
    let signed = data
        .get(..signed_len)
        .ok_or(PersistError::Corrupt("truncated before digest"))?;
    if Sha256::digest(signed).as_slice() != digest {
        return Err(PersistError::Corrupt("digest mismatch"));
    }
    Ok(Some(payload.to_vec()))
}
