//! Opt-in sharing with other installs: noting what this gateway judged,
//! writing the export bundle, and picking up a bundle another install wrote.
//! Off unless configured (`--share-export`, `--share-import`).

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use veritell_core::{Class, Detection};
use veritell_feed::{FeedKey, Live};
use veritell_share::{Imported, Ledger, ShareKey};

/// An exported bundle is good for this long.
const EXPORT_LIFETIME_SECS: u64 = 86_400;

pub struct Sharing {
    pub key: ShareKey,
    /// What this install has judged; present when exporting.
    pub ledger: Option<Ledger>,
    /// What another install shared; empty unless importing.
    pub imported: Live<Imported>,
    /// When the imported bundle expires (Unix seconds); 0 when none is
    /// loaded. A bundle's expiry was only checked when it was loaded, so an
    /// exporter that stopped left its last hints in force for good.
    pub imported_until: AtomicU64,
}

impl Sharing {
    /// The hint for a fingerprint another install reported, if any.
    pub fn reported(&self, fingerprint: &str) -> Option<Detection> {
        self.reported_at(fingerprint, now_secs())
    }

    fn reported_at(&self, fingerprint: &str, now: u64) -> Option<Detection> {
        if now >= self.imported_until.load(Ordering::Relaxed) {
            return None;
        }
        self.imported.load().detection(&self.key, fingerprint)
    }

    /// Notes this gateway's own judgement. A judgement that leaned on
    /// another install's report is not noted: it would come back to that
    /// install as if it were independent.
    pub fn note(&self, fingerprint: &str, network: [u8; 8], class: Class, leaned_on_report: bool, now: u64) {
        if let (Some(ledger), false) = (&self.ledger, leaned_on_report) {
            ledger.record(fingerprint, network, class, now);
        }
    }
}

pub struct ExportTo {
    pub path: PathBuf,
    /// Ed25519 seed the bundle is signed with.
    pub seed: [u8; 32],
    pub every: Duration,
}

pub struct ImportFrom {
    pub path: PathBuf,
    pub keys: Vec<FeedKey>,
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Writes the export bundle beside its final name, then renames it, so a
/// reader never sees half a file.
fn write_export(sharing: &Sharing, to: &ExportTo, now: u64) -> Result<usize, String> {
    let Some(ledger) = &sharing.ledger else {
        return Ok(0);
    };
    let entries = ledger.export(now);
    let bundle = veritell_share::seal_bundle(&entries, now, now, now.saturating_add(EXPORT_LIFETIME_SECS), &to.seed)
        .map_err(|e| e.to_string())?;
    let mut tmp = to.path.clone().into_os_string();
    tmp.push(".tmp");
    std::fs::write(&tmp, bundle).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &to.path).map_err(|e| e.to_string())?;
    Ok(entries.len())
}

/// Runs forever on its own thread.
pub fn run(sharing: Arc<Sharing>, export: Option<ExportTo>, import: Option<ImportFrom>) {
    let mut last_export: Option<std::time::Instant> = None;
    let mut last_count: Option<usize> = None;
    let mut last_seen: Option<SystemTime> = None;
    let mut version = 0u64;
    loop {
        if let Some(to) = &export {
            if last_export.is_none_or(|t| t.elapsed() >= to.every) {
                last_export = Some(std::time::Instant::now());
                match write_export(&sharing, to, now_secs()) {
                    Ok(n) if last_count != Some(n) => {
                        eprintln!("veritell: share export written: {n} fingerprints");
                        last_count = Some(n);
                    }
                    Ok(_) => {}
                    Err(e) => eprintln!("veritell: share export failed: {e}"),
                }
            }
        }
        if let Some(from) = &import {
            let modified = std::fs::metadata(&from.path).ok().and_then(|m| m.modified().ok());
            if modified.is_some() && modified != last_seen {
                last_seen = modified;
                let now = now_secs();
                let outcome = std::fs::read(&from.path)
                    .map_err(|e| format!("cannot read: {e}"))
                    .and_then(|bytes| {
                        let (v, entries) =
                            veritell_share::open_bundle(&bytes, &from.keys, now, version).map_err(|e| e.to_string())?;
                        // The same bytes, already verified: only for the expiry.
                        let expires = veritell_feed::open(&bytes, &from.keys, now, 0).map_err(|e| e.to_string())?.expires;
                        Ok((v, expires, entries))
                    });
                match outcome {
                    Ok((v, expires, entries)) => {
                        version = v;
                        let imported = Imported::new(&entries);
                        eprintln!("veritell: share bundle version {v} taken: {} fingerprints", imported.len());
                        sharing.imported.store(imported);
                        sharing.imported_until.store(expires, Ordering::Relaxed);
                    }
                    Err(e) => eprintln!("veritell: share bundle refused, keeping version {version}: {e}"),
                }
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veritell_share::Entry;

    #[test]
    fn imported_hints_stop_at_the_bundles_expiry() {
        let key = ShareKey::new(b"0123456789abcdef0123456789abcdef").unwrap();
        let entry = Entry { hash: key.hash("fp"), class: Class::Automated };
        let sharing = Sharing {
            key,
            ledger: None,
            imported: Live::new(Imported::new(&[entry])),
            imported_until: AtomicU64::new(1_000),
        };
        assert!(sharing.reported_at("fp", 999).is_some());
        assert!(sharing.reported_at("fp", 1_000).is_none(), "expired");
        assert!(sharing.reported_at("other", 999).is_none());
        sharing.imported_until.store(0, Ordering::Relaxed);
        assert!(sharing.reported_at("fp", 1).is_none(), "nothing loaded");
    }
}
