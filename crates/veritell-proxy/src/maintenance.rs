//! Background upkeep, off the request path: rotating probe builds and
//! picking up new feed bundles.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use veritell_feed::{FeedKey, Live};
use veritell_probe::EngineTruth;
use veritell_probe_build::{Build, Builder};
use veritell_ua::TruthTable;

use crate::state::now_secs;

/// Names of the files a bundle may carry.
pub const FEED_TRUTH: &str = "truth_v1.json";
pub const FEED_ENGINE: &str = "engine_v1.json";

/// The data a feed can replace while the gateway runs.
pub struct LiveData {
    pub truth: Live<TruthTable>,
    pub engine_truth: Live<EngineTruth>,
}

/// The probe builder and the build currently being served.
pub struct ProbeBuilds {
    pub builder: Builder,
    pub current: Live<Build>,
    /// A new build is made this often.
    pub rotate_every: Duration,
    /// A build's reports are accepted for this long.
    pub ttl_secs: u64,
}

impl ProbeBuilds {
    pub fn new(builder: Builder, rotate_every: Duration, ttl_secs: u64) -> Self {
        let first = builder.build(now_secs(), ttl_secs);
        ProbeBuilds {
            builder,
            current: Live::new(first),
            rotate_every,
            ttl_secs,
        }
    }

    fn rotate(&self) {
        self.current
            .store(self.builder.build(now_secs(), self.ttl_secs));
    }
}

pub struct FeedSource {
    pub path: PathBuf,
    pub keys: Vec<FeedKey>,
}

/// Why a bundle was not applied. Nothing changes when this is returned.
#[derive(Debug)]
pub enum FeedProblem {
    Read(String),
    Bundle(veritell_feed::FeedError),
    File(&'static str, String),
}

impl std::fmt::Display for FeedProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FeedProblem::Read(e) => write!(f, "cannot read: {e}"),
            FeedProblem::Bundle(e) => write!(f, "{e}"),
            FeedProblem::File(name, e) => write!(f, "{name}: {e}"),
        }
    }
}

/// Verifies a bundle and applies it. Every file is parsed before anything is
/// swapped, so a bundle with one bad file changes nothing. Returns the
/// version now in effect.
pub fn apply_feed(
    bytes: &[u8],
    keys: &[FeedKey],
    data: &LiveData,
    min_version: u64,
    now: u64,
) -> Result<u64, FeedProblem> {
    let bundle = veritell_feed::open(bytes, keys, now, min_version).map_err(FeedProblem::Bundle)?;
    let text = |name: &'static str| -> Result<Option<&str>, FeedProblem> {
        match bundle.file(name) {
            None => Ok(None),
            Some(raw) => std::str::from_utf8(raw)
                .map(Some)
                .map_err(|e| FeedProblem::File(name, e.to_string())),
        }
    };
    let truth = text(FEED_TRUTH)?
        .map(|t| TruthTable::from_json(t).map_err(|e| FeedProblem::File(FEED_TRUTH, e.to_string())))
        .transpose()?;
    let engine = text(FEED_ENGINE)?
        .map(|t| {
            veritell_probe::parse_truth(t)
                .map_err(|e| FeedProblem::File(FEED_ENGINE, e.to_string()))
        })
        .transpose()?;
    if let Some(t) = truth {
        data.truth.store(t);
    }
    if let Some(e) = engine {
        data.engine_truth.store(e);
    }
    Ok(bundle.version)
}

/// A file's modification time and size, or `None` when it cannot be read.
/// Both, because a writer that is not atomic can leave a half-written file
/// and finish it within the same second (same mtime), and the finished file
/// must be read.
type Stamp = Option<(SystemTime, u64)>;

fn stamp(path: &std::path::Path) -> Stamp {
    std::fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok().map(|t| (t, m.len())))
}

/// One look at the feed file. Applies it if it changed since `last_seen`
/// (`None` when there is nothing new to try). A file that could not be read
/// is tried again on the next look; one that was read (taken or refused)
/// waits until it changes. `version` becomes the version taken.
fn check_feed(
    source: &FeedSource,
    data: &LiveData,
    last_seen: &mut Stamp,
    version: &mut u64,
    now: u64,
) -> Option<Result<u64, FeedProblem>> {
    let seen = stamp(&source.path);
    if seen.is_none() || seen == *last_seen {
        return None;
    }
    let outcome = std::fs::read(&source.path)
        .map_err(|e| FeedProblem::Read(e.to_string()))
        .and_then(|bytes| apply_feed(&bytes, &source.keys, data, *version, now));
    if !matches!(outcome, Err(FeedProblem::Read(_))) {
        *last_seen = seen;
    }
    if let Ok(v) = outcome {
        *version = v;
    }
    Some(outcome)
}

/// Runs forever on its own thread.
pub fn run(
    builds: Arc<ProbeBuilds>,
    data: Arc<LiveData>,
    feed: Option<FeedSource>,
    mut version: u64,
) {
    let mut last_rotation = std::time::Instant::now();
    let mut last_seen: Stamp = feed.as_ref().and_then(|f| stamp(&f.path));
    loop {
        std::thread::sleep(Duration::from_millis(250));
        if last_rotation.elapsed() >= builds.rotate_every {
            builds.rotate();
            last_rotation = std::time::Instant::now();
        }
        let Some(source) = &feed else { continue };
        match check_feed(source, &data, &mut last_seen, &mut version, now_secs()) {
            None => {}
            Some(Ok(v)) => eprintln!("veritell: feed version {v} loaded"),
            Some(Err(e)) => eprintln!("veritell: feed refused, keeping version {version}: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const SEED: [u8; 32] = [7; 32];
    const NOW: u64 = 1_800_000_000;
    const ENGINE_NOTE: &str = "from the feed";

    fn engine_json(note: &str) -> String {
        format!(r#"{{"version":1,"note":"{note}","profiles":[]}}"#)
    }

    fn truth_json() -> &'static str {
        r#"{"version":1,"engines":{},"tools":[]}"#
    }

    fn data() -> LiveData {
        LiveData {
            truth: Live::new(TruthTable::default()),
            engine_truth: Live::new(veritell_probe::parse_truth(&engine_json("built in")).unwrap()),
        }
    }

    fn bundle(files: &[(&str, &[u8])], version: u64) -> Vec<u8> {
        let files: BTreeMap<String, Vec<u8>> = files
            .iter()
            .map(|(n, b)| (n.to_string(), b.to_vec()))
            .collect();
        veritell_feed::seal(&files, version, NOW, NOW + 3600, &SEED).unwrap()
    }

    fn keys() -> Vec<FeedKey> {
        vec![veritell_feed::public_key(&SEED)]
    }

    #[test]
    fn a_good_bundle_replaces_both_tables() {
        let d = data();
        let truth_before = d.truth.load();
        let b = bundle(
            &[
                (FEED_TRUTH, truth_json().as_bytes()),
                (FEED_ENGINE, engine_json(ENGINE_NOTE).as_bytes()),
            ],
            3,
        );
        assert_eq!(apply_feed(&b, &keys(), &d, 0, NOW).unwrap(), 3);
        assert_eq!(d.engine_truth.load().note, ENGINE_NOTE);
        assert!(
            !Arc::ptr_eq(&truth_before, &d.truth.load()),
            "the UA truth was swapped"
        );
    }

    #[test]
    fn a_bundle_without_a_file_leaves_that_table_alone() {
        let d = data();
        let truth_before = d.truth.load();
        let b = bundle(&[(FEED_ENGINE, engine_json(ENGINE_NOTE).as_bytes())], 1);
        apply_feed(&b, &keys(), &d, 0, NOW).unwrap();
        assert_eq!(d.engine_truth.load().note, ENGINE_NOTE);
        assert!(
            Arc::ptr_eq(&truth_before, &d.truth.load()),
            "no truth file, no swap"
        );
    }

    #[test]
    fn one_bad_file_changes_nothing() {
        let d = data();
        let truth_before = d.truth.load();
        let b = bundle(
            &[
                (FEED_TRUTH, truth_json().as_bytes()),
                (FEED_ENGINE, b"{not json"),
            ],
            2,
        );
        let e = apply_feed(&b, &keys(), &d, 0, NOW).unwrap_err();
        assert!(matches!(e, FeedProblem::File(FEED_ENGINE, _)), "{e:?}");
        assert!(e.to_string().starts_with("engine_v1.json: "), "{e}");
        assert!(
            Arc::ptr_eq(&truth_before, &d.truth.load()),
            "the good truth file was not applied either"
        );
        assert_eq!(d.engine_truth.load().note, "built in");
    }

    #[test]
    fn a_bad_truth_file_or_one_that_is_not_text_is_refused() {
        let d = data();
        let b = bundle(&[(FEED_TRUTH, b"[]")], 1);
        let e = apply_feed(&b, &keys(), &d, 0, NOW).unwrap_err();
        assert!(matches!(e, FeedProblem::File(FEED_TRUTH, _)), "{e:?}");
        let b = bundle(&[(FEED_ENGINE, &[0xff, 0xfe])], 1);
        let e = apply_feed(&b, &keys(), &d, 0, NOW).unwrap_err();
        assert!(
            matches!(e, FeedProblem::File(FEED_ENGINE, _)),
            "not UTF-8: {e:?}"
        );
    }

    #[test]
    fn bundles_that_do_not_verify_are_refused() {
        let d = data();
        let b = bundle(&[(FEED_ENGINE, engine_json(ENGINE_NOTE).as_bytes())], 4);
        let other_key = vec![veritell_feed::public_key(&[8; 32])];
        let e = apply_feed(&b, &other_key, &d, 0, NOW).unwrap_err();
        assert_eq!(e.to_string(), "bundle signature does not verify");
        let e = apply_feed(&b, &keys(), &d, 5, NOW).unwrap_err();
        assert_eq!(
            e.to_string(),
            "bundle version 4 is older than 5",
            "no rollback"
        );
        assert_eq!(
            FeedProblem::Read("gone".into()).to_string(),
            "cannot read: gone"
        );
        assert_eq!(d.engine_truth.load().note, "built in");
    }

    fn temp_feed(name: &str) -> FeedSource {
        let dir =
            std::env::temp_dir().join(format!("veritell-feed-test-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        FeedSource {
            path: dir.join("feed.json"),
            keys: keys(),
        }
    }

    #[test]
    fn the_feed_file_is_read_when_it_changes_and_not_before() {
        let source = temp_feed("changes");
        let d = data();
        let (mut last_seen, mut version) = (None, 0u64);
        assert!(
            check_feed(&source, &d, &mut last_seen, &mut version, NOW).is_none(),
            "no file yet"
        );

        std::fs::write(
            &source.path,
            bundle(&[(FEED_ENGINE, engine_json("v1").as_bytes())], 1),
        )
        .unwrap();
        assert_eq!(
            check_feed(&source, &d, &mut last_seen, &mut version, NOW)
                .unwrap()
                .unwrap(),
            1
        );
        assert_eq!(version, 1);
        assert!(
            check_feed(&source, &d, &mut last_seen, &mut version, NOW).is_none(),
            "unchanged"
        );

        // A different size is a change even within the same second.
        std::fs::write(
            &source.path,
            bundle(&[(FEED_ENGINE, engine_json("version two").as_bytes())], 2),
        )
        .unwrap();
        assert_eq!(
            check_feed(&source, &d, &mut last_seen, &mut version, NOW)
                .unwrap()
                .unwrap(),
            2
        );
        assert_eq!(d.engine_truth.load().note, "version two");
        std::fs::remove_dir_all(source.path.parent().unwrap()).unwrap();
    }

    #[test]
    fn a_refused_file_waits_until_it_changes_and_keeps_the_version() {
        let source = temp_feed("refused");
        let d = data();
        let (mut last_seen, mut version) = (None, 3u64);
        std::fs::write(
            &source.path,
            bundle(&[(FEED_ENGINE, engine_json("old").as_bytes())], 2),
        )
        .unwrap();
        let outcome = check_feed(&source, &d, &mut last_seen, &mut version, NOW).unwrap();
        assert!(
            matches!(outcome, Err(FeedProblem::Bundle(_))),
            "older than 3"
        );
        assert_eq!(version, 3);
        assert!(
            check_feed(&source, &d, &mut last_seen, &mut version, NOW).is_none(),
            "not tried again"
        );
        std::fs::remove_dir_all(source.path.parent().unwrap()).unwrap();
    }

    #[test]
    fn rotating_serves_a_new_build() {
        let builder = Builder::new(crate::probe::TEMPLATE, &[1u8; 32]).unwrap();
        let builds = ProbeBuilds::new(builder, Duration::from_secs(60), 600);
        let first = builds.current.load().id.clone();
        assert!(builds.current.load().expires_at >= now_secs() + 590);
        builds.rotate();
        assert_ne!(builds.current.load().id, first);
    }
}
