//! Opt-in sharing with other installs: noting what this gateway judged,
//! writing the export bundle, and picking up a bundle another install wrote.
//! Off unless configured (`--share-export`, `--share-import`).

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use veritell_core::{Class, Detection};
use veritell_feed::{FeedKey, Live};
use veritell_share::{Entry, Imported, Ledger, ShareError, ShareKey, FILE_NAME};

use crate::state::now_secs;

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
    pub fn note(
        &self,
        fingerprint: &str,
        network: [u8; 8],
        class: Class,
        leaned_on_report: bool,
        now: u64,
    ) {
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

/// Writes the export bundle beside its final name, then renames it, so a
/// reader never sees half a file.
fn write_export(sharing: &Sharing, to: &ExportTo, now: u64) -> Result<usize, String> {
    let Some(ledger) = &sharing.ledger else {
        return Ok(0);
    };
    let entries = ledger.export(now);
    let bundle = veritell_share::seal_bundle(
        &entries,
        now,
        now,
        now.saturating_add(EXPORT_LIFETIME_SECS),
        &to.seed,
    )
    .map_err(|e| e.to_string())?;
    let mut tmp = to.path.clone().into_os_string();
    tmp.push(".tmp");
    std::fs::write(&tmp, bundle).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &to.path).map_err(|e| e.to_string())?;
    Ok(entries.len())
}

/// One look at the import file. Takes it if its modification time changed
/// since `last_seen` (`None` when there is nothing new to try). A file that
/// could not be read is tried again on the next look; one that was read
/// (taken or refused) waits until it changes. On success returns the
/// version and how many fingerprints are now imported, and `version`
/// becomes it.
fn check_import(
    sharing: &Sharing,
    from: &ImportFrom,
    last_seen: &mut Option<SystemTime>,
    version: &mut u64,
    now: u64,
) -> Option<Result<(u64, usize), String>> {
    let modified = std::fs::metadata(&from.path)
        .ok()
        .and_then(|m| m.modified().ok());
    if modified.is_none() || modified == *last_seen {
        return None;
    }
    let bytes = match std::fs::read(&from.path) {
        Ok(bytes) => bytes,
        Err(e) => return Some(Err(format!("cannot read: {e}"))),
    };
    *last_seen = modified;
    Some(
        open_import(&bytes, &from.keys, now, *version).map(|(v, expires, entries)| {
            *version = v;
            let imported = Imported::new(&entries);
            let count = imported.len();
            sharing.imported.store(imported);
            sharing.imported_until.store(expires, Ordering::Relaxed);
            (v, count)
        }),
    )
}

/// What `veritell_share::open_bundle` does, opening the bundle once and
/// keeping its expiry as well: the version, the expiry and the entries.
fn open_import(
    bytes: &[u8],
    keys: &[FeedKey],
    now: u64,
    min_version: u64,
) -> Result<(u64, u64, Vec<Entry>), String> {
    let bundle = veritell_feed::open(bytes, keys, now, min_version)
        .map_err(|e| ShareError::Bundle(e).to_string())?;
    let file = match (bundle.names().as_slice(), bundle.file(FILE_NAME)) {
        ([name], Some(file)) if *name == FILE_NAME => file,
        _ => return Err(ShareError::Files.to_string()),
    };
    let entries = veritell_share::decode(file).map_err(|e| e.to_string())?;
    Ok((bundle.version, bundle.expires, entries))
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
            match check_import(&sharing, from, &mut last_seen, &mut version, now_secs()) {
                None => {}
                Some(Ok((v, n))) => {
                    eprintln!("veritell: share bundle version {v} taken: {n} fingerprints")
                }
                Some(Err(e)) => {
                    eprintln!("veritell: share bundle refused, keeping version {version}: {e}")
                }
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imported_hints_stop_at_the_bundles_expiry() {
        let key = ShareKey::new(b"0123456789abcdef0123456789abcdef").unwrap();
        let entry = Entry {
            hash: key.hash("fp"),
            class: Class::Automated,
        };
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

    const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";
    const SEED: [u8; 32] = [3; 32];
    const NOW: u64 = 1_800_000_000;

    fn sharing(ledger: Option<Ledger>) -> Sharing {
        Sharing {
            key: ShareKey::new(SECRET).unwrap(),
            ledger,
            imported: Live::new(Imported::empty()),
            imported_until: AtomicU64::new(0),
        }
    }

    fn ledger() -> Ledger {
        let config = veritell_share::Config {
            min_networks: veritell_share::MIN_NETWORKS_FLOOR,
            ..Default::default()
        };
        Ledger::new(ShareKey::new(SECRET).unwrap(), config).unwrap()
    }

    /// A fresh directory for one test, removed by the caller.
    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("veritell-share-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn network(n: u8) -> [u8; 8] {
        [n, 0, 0, 0, 0, 0, 0, 0]
    }

    #[test]
    fn judgements_are_noted_unless_they_leaned_on_a_report() {
        let s = sharing(Some(ledger()));
        for n in 0..5 {
            s.note("own", network(n), Class::Automated, false, NOW);
            s.note("echo", network(n), Class::Automated, true, NOW);
        }
        let exported = s.ledger.as_ref().unwrap().export(NOW);
        assert_eq!(exported.len(), 1, "only the independent judgement");
        assert_eq!(exported[0].hash, s.key.hash("own"));
        // Without a ledger (importing only) nothing is noted and nothing breaks.
        sharing(None).note("own", network(0), Class::Automated, false, NOW);
    }

    #[test]
    fn nothing_is_written_without_a_ledger() {
        let dir = temp_dir("no-ledger");
        let to = ExportTo {
            path: dir.join("out.json"),
            seed: SEED,
            every: Duration::from_secs(60),
        };
        assert_eq!(write_export(&sharing(None), &to, NOW), Ok(0));
        assert!(!to.path.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn an_export_is_written_whole_and_another_install_takes_it() {
        let dir = temp_dir("round-trip");
        let exporter = sharing(Some(ledger()));
        for n in 0..5 {
            exporter.note("bot-fp", network(n), Class::Automated, false, NOW);
        }
        let to = ExportTo {
            path: dir.join("share.json"),
            seed: SEED,
            every: Duration::from_secs(60),
        };
        assert_eq!(write_export(&exporter, &to, NOW), Ok(1));
        assert!(
            !dir.join("share.json.tmp").exists(),
            "the temporary file was renamed"
        );

        let importer = sharing(None);
        let from = ImportFrom {
            path: to.path.clone(),
            keys: vec![veritell_feed::public_key(&SEED)],
        };
        let (mut last_seen, mut version) = (None, 0u64);
        assert_eq!(
            check_import(&importer, &from, &mut last_seen, &mut version, NOW),
            Some(Ok((NOW, 1)))
        );
        assert_eq!(version, NOW, "an export's version is its time");
        assert_eq!(
            importer.imported_until.load(Ordering::Relaxed),
            NOW + EXPORT_LIFETIME_SECS
        );
        assert!(importer.reported_at("bot-fp", NOW).is_some());
        assert!(
            importer
                .reported_at("bot-fp", NOW + EXPORT_LIFETIME_SECS)
                .is_none(),
            "gone at expiry"
        );
        assert_eq!(
            check_import(&importer, &from, &mut last_seen, &mut version, NOW),
            None,
            "unchanged"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn a_bundle_that_could_not_be_read_is_tried_again() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("unreadable");
        let path = dir.join("share.json");
        let entry = Entry {
            hash: ShareKey::new(SECRET).unwrap().hash("bot-fp"),
            class: Class::Automated,
        };
        std::fs::write(
            &path,
            veritell_share::seal_bundle(&[entry], 7, NOW, NOW + 60, &SEED).unwrap(),
        )
        .unwrap();
        // Unreadable, without touching the modification time.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read(&path).is_ok() {
            // Running as root: permissions do not stop the read.
            std::fs::remove_dir_all(dir).unwrap();
            return;
        }
        let importer = sharing(None);
        let from = ImportFrom {
            path: path.clone(),
            keys: vec![veritell_feed::public_key(&SEED)],
        };
        let (mut last_seen, mut version) = (None, 0u64);
        let failed = check_import(&importer, &from, &mut last_seen, &mut version, NOW)
            .unwrap()
            .unwrap_err();
        assert!(failed.starts_with("cannot read"), "{failed}");
        assert_eq!((last_seen, version), (None, 0), "not marked as seen");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            check_import(&importer, &from, &mut last_seen, &mut version, NOW),
            Some(Ok((7, 1))),
            "taken on a later look"
        );
        assert_eq!(importer.imported_until.load(Ordering::Relaxed), NOW + 60);
        assert!(importer.reported_at("bot-fp", NOW).is_some());
        assert_eq!(
            check_import(&importer, &from, &mut last_seen, &mut version, NOW),
            None,
            "and then seen"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn an_export_to_a_missing_directory_fails_with_a_reason() {
        let dir = temp_dir("missing");
        let to = ExportTo {
            path: dir.join("no-such-dir").join("share.json"),
            seed: SEED,
            every: Duration::from_secs(60),
        };
        assert!(write_export(&sharing(Some(ledger())), &to, NOW).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_refused_bundle_keeps_what_was_imported() {
        let dir = temp_dir("refused");
        let path = dir.join("share.json");
        let importer = sharing(None);
        let entry = veritell_share::Entry {
            hash: importer.key.hash("kept"),
            class: Class::Automated,
        };
        importer.imported.store(Imported::new(&[entry]));
        importer.imported_until.store(NOW + 10, Ordering::Relaxed);
        let (mut last_seen, mut version) = (None, 5u64);
        let from = ImportFrom {
            path: path.clone(),
            keys: vec![veritell_feed::public_key(&SEED)],
        };

        assert_eq!(
            check_import(&importer, &from, &mut last_seen, &mut version, NOW),
            None,
            "no file"
        );

        // Signed by a key this install does not trust.
        let bundle = veritell_share::seal_bundle(&[], 9, NOW, NOW + 60, &[4; 32]).unwrap();
        std::fs::write(&path, bundle).unwrap();
        let refused = check_import(&importer, &from, &mut last_seen, &mut version, NOW)
            .unwrap()
            .unwrap_err();
        assert_eq!(refused, "bundle signature does not verify");
        assert_eq!(version, 5);
        assert!(
            importer.reported_at("kept", NOW).is_some(),
            "the earlier import stays"
        );
        assert_eq!(
            check_import(&importer, &from, &mut last_seen, &mut version, NOW),
            None,
            "tried once per change"
        );

        // An older version than the one in force is a rollback.
        let old = veritell_share::seal_bundle(&[], 4, NOW, NOW + 60, &SEED).unwrap();
        std::fs::write(&path, &old).unwrap();
        last_seen = None;
        let refused = check_import(&importer, &from, &mut last_seen, &mut version, NOW)
            .unwrap()
            .unwrap_err();
        assert_eq!(refused, "bundle version 4 is older than 5");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
