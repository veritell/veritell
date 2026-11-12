//! Background upkeep, off the request path: rotating probe builds and
//! picking up new feed bundles.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use veritell_feed::{FeedKey, Live};
use veritell_probe::EngineTruth;
use veritell_probe_build::{Build, Builder};
use veritell_ua::TruthTable;

/// Names of the files a bundle may carry.
pub const FEED_TRUTH: &str = "truth_v1.json";
pub const FEED_ENGINE: &str = "engine_v1.json";

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

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
        self.current.store(self.builder.build(now_secs(), self.ttl_secs));
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
        .map(|t| veritell_probe::parse_truth(t).map_err(|e| FeedProblem::File(FEED_ENGINE, e.to_string())))
        .transpose()?;
    if let Some(t) = truth {
        data.truth.store(t);
    }
    if let Some(e) = engine {
        data.engine_truth.store(e);
    }
    Ok(bundle.version)
}

/// Runs forever on its own thread.
pub fn run(builds: Arc<ProbeBuilds>, data: Arc<LiveData>, feed: Option<FeedSource>, mut version: u64) {
    let mut last_rotation = std::time::Instant::now();
    // What was last read: modification time and size. Both, because a writer
    // that is not atomic can leave a half-written file and finish it within
    // the same second (same mtime), and the finished file must be read.
    let stamp = |m: std::fs::Metadata| m.modified().ok().map(|t| (t, m.len()));
    let mut last_seen: Option<(SystemTime, u64)> =
        feed.as_ref().and_then(|f| std::fs::metadata(&f.path).ok()).and_then(stamp);
    loop {
        std::thread::sleep(Duration::from_millis(250));
        if last_rotation.elapsed() >= builds.rotate_every {
            builds.rotate();
            last_rotation = std::time::Instant::now();
        }
        let Some(source) = &feed else { continue };
        let seen = std::fs::metadata(&source.path).ok().and_then(stamp);
        if seen.is_none() || seen == last_seen {
            continue;
        }
        let outcome = std::fs::read(&source.path)
            .map_err(|e| FeedProblem::Read(e.to_string()))
            .and_then(|bytes| apply_feed(&bytes, &source.keys, &data, version, now_secs()));
        // A file that could not be read is tried again on the next tick; one
        // that was read (taken or refused) waits until it changes.
        if !matches!(outcome, Err(FeedProblem::Read(_))) {
            last_seen = seen;
        }
        match outcome {
            Ok(v) => {
                version = v;
                eprintln!("veritell: feed version {v} loaded");
            }
            Err(e) => eprintln!("veritell: feed refused, keeping version {version}: {e}"),
        }
    }
}
