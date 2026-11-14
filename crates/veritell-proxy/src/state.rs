//! State that survives a restart (`--state-dir`): the day's quota use, every
//! single-use store (redeemed Privacy Pass tokens, solved challenges, session
//! token budgets, probe and behaviour nonces), and the probe results (without
//! which every client holding a token would be marked `probe_missing` after a
//! restart).
//!
//! Loaded once at start, before anything is served. Saved every
//! `--state-flush` seconds and once more when a graceful shutdown (SIGTERM)
//! is broadcast. A fast shutdown (SIGINT) or a crash loses at most the time
//! since the last save. A file that is refused (torn, changed, another kind)
//! is moved aside to `<name>.refused`, the store starts empty, and the reason
//! is logged; the gateway never stops for it. The store files hold random
//! ids, counts, expiry times and keyed hashes of agent identities.
//!
//! The dashboard's recent events (`events.state`) are kept too, so a restart
//! or update doesn't empty the dashboard. Unlike the stores, they hold what
//! the events hold: the address as `--ip-mode` writes it, the path and the
//! User-Agent. They are saved once a minute and on shutdown, newest first up
//! to `EVENTS_MAX_BYTES`, and none older than 30 days is saved or loaded.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;

use veritell_quota::Quotas;
use veritell_token::MemoryBudgetStore;

pub fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// A store whose contents survive a restart.
pub trait Snapshot: Send + Sync {
    fn export(&self, now: u64) -> Vec<u8>;
    /// Loads an export; the store is unchanged if the input is refused.
    fn import(&self, bytes: &[u8], now: u64) -> Result<usize, String>;
    /// Whether an interval save should write this store now. The save on
    /// shutdown always writes.
    fn due(&self, _now: u64) -> bool {
        true
    }
}

/// Size limit of `events.state`, well under the persist format's own limit.
pub const EVENTS_MAX_BYTES: usize = 32 << 20;
/// Seconds between interval saves of the events.
const EVENTS_EVERY_SECS: u64 = 60;
/// Events older than this are neither saved nor loaded: the same 30 days
/// the kit's ClickHouse table keeps them.
const EVENTS_MAX_AGE_SECS: u64 = 30 * 86_400;

fn fresh(event: &veritell_events::Event, now: u64) -> bool {
    event.ts_ms / 1000 + EVENTS_MAX_AGE_SECS > now
}

/// The dashboard's recent events, as JSON lines, oldest first.
pub struct Events {
    pub ring: Arc<veritell_events::MemoryRing>,
    last_save: AtomicU64,
}

impl Events {
    pub fn new(ring: Arc<veritell_events::MemoryRing>) -> Events {
        Events { ring, last_save: AtomicU64::new(0) }
    }
}

impl Snapshot for Events {
    fn export(&self, now: u64) -> Vec<u8> {
        self.last_save.store(now, Ordering::Relaxed);
        // Newest first until the limit, then back to oldest first.
        let mut lines = Vec::new();
        let mut size = 0;
        for event in self.ring.events().iter().rev().filter(|e| fresh(e, now)) {
            let Ok(line) = serde_json::to_vec(event) else { continue };
            size += line.len() + 1;
            if size > EVENTS_MAX_BYTES {
                break;
            }
            lines.push(line);
        }
        let mut out = Vec::with_capacity(size.min(EVENTS_MAX_BYTES));
        for line in lines.iter().rev() {
            out.extend_from_slice(line);
            out.push(b'\n');
        }
        out
    }

    fn import(&self, bytes: &[u8], now: u64) -> Result<usize, String> {
        let mut events = Vec::new();
        for (n, line) in bytes.split(|b| *b == b'\n').enumerate() {
            if line.is_empty() {
                continue;
            }
            let event: veritell_events::Event =
                serde_json::from_slice(line).map_err(|e| format!("line {}: {e}", n + 1))?;
            if fresh(&event, now) {
                events.push(event);
            }
        }
        let count = events.len();
        self.ring.restore(events);
        Ok(count)
    }

    fn due(&self, now: u64) -> bool {
        now.saturating_sub(self.last_save.load(Ordering::Relaxed)) >= EVENTS_EVERY_SECS
    }
}

impl Snapshot for MemoryBudgetStore {
    fn export(&self, now: u64) -> Vec<u8> {
        MemoryBudgetStore::export(self, now)
    }
    fn import(&self, bytes: &[u8], now: u64) -> Result<usize, String> {
        MemoryBudgetStore::import(self, bytes, now).map_err(|e| e.to_string())
    }
}

impl Snapshot for crate::probe::ProbeStore {
    fn export(&self, now: u64) -> Vec<u8> {
        crate::probe::ProbeStore::export(self, now)
    }
    fn import(&self, bytes: &[u8], now: u64) -> Result<usize, String> {
        crate::probe::ProbeStore::import(self, bytes, now)
    }
}

/// The Web Bot Auth replay cache: signatures already used, each with the
/// time until which it is refused. Saved so that a restart does not let a
/// captured signature through once more. Format: `VWR1`, then 40 bytes per
/// signature (its 32-byte id, the time as a big-endian u64).
pub struct Replays(pub Arc<std::sync::Mutex<veritell_wba::ReplayCache>>);

const REPLAYS_MAGIC: &[u8; 4] = b"VWR1";

impl Snapshot for Replays {
    fn export(&self, now: u64) -> Vec<u8> {
        let entries = self.0.lock().unwrap_or_else(|e| e.into_inner()).entries(now);
        let mut out = Vec::with_capacity(4 + entries.len() * 40);
        out.extend_from_slice(REPLAYS_MAGIC);
        for (id, until) in entries {
            out.extend_from_slice(&id);
            out.extend_from_slice(&until.to_be_bytes());
        }
        out
    }

    fn import(&self, bytes: &[u8], now: u64) -> Result<usize, String> {
        let body = bytes.strip_prefix(REPLAYS_MAGIC.as_slice()).ok_or("not a replay cache file")?;
        if body.len() % 40 != 0 {
            return Err(format!("{} bytes is not a whole number of entries", body.len()));
        }
        let mut cache = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let mut kept = 0;
        for chunk in body.as_chunks::<40>().0 {
            let (id, until) = chunk.split_at(32);
            let id: [u8; 32] = id.try_into().map_err(|_| "bad entry")?;
            let until = u64::from_be_bytes(until.try_into().map_err(|_| "bad entry")?);
            if until >= now {
                cache.restore(id, until, now);
                kept += 1;
            }
        }
        Ok(kept)
    }
}

pub struct State {
    dir: PathBuf,
    quotas: Arc<Quotas>,
    /// File kind and store.
    stores: Vec<(&'static str, Arc<dyn Snapshot>)>,
}

impl State {
    pub fn new(dir: PathBuf, quotas: Arc<Quotas>, stores: Vec<(&'static str, Arc<dyn Snapshot>)>) -> State {
        State { dir, quotas, stores }
    }

    fn path(&self, kind: &str) -> PathBuf {
        self.dir.join(format!("{kind}.state"))
    }

    fn refuse(path: &Path, kind: &str, why: &dyn std::fmt::Display) {
        let aside = path.with_extension("state.refused");
        let moved = std::fs::rename(path, &aside).is_ok();
        eprintln!(
            "veritell: state {kind} refused ({why}); starting empty{}",
            if moved { ", the file is kept as .refused" } else { "" }
        );
    }

    /// Loads every file that exists. Call before serving.
    pub fn load(&self, now: u64) {
        let path = self.path("quota");
        match veritell_persist::read(&path, "quota") {
            Ok(None) => {}
            Ok(Some(bytes)) => match self.quotas.import(&bytes, now) {
                Ok(n) => eprintln!("veritell: state quota loaded: {n} identities"),
                Err(e) => Self::refuse(&path, "quota", &e),
            },
            Err(e) => Self::refuse(&path, "quota", &e),
        }
        for (kind, store) in &self.stores {
            let path = self.path(kind);
            match veritell_persist::read(&path, kind) {
                Ok(None) => {}
                Ok(Some(bytes)) => match store.import(&bytes, now) {
                    Ok(n) => eprintln!("veritell: state {kind} loaded: {n} entries"),
                    Err(e) => Self::refuse(&path, kind, &e),
                },
                Err(e) => Self::refuse(&path, kind, &e),
            }
        }
    }

    /// Writes every file. A failure is logged and the next save tries again.
    pub fn save(&self, now: u64) -> bool {
        self.write(now, true)
    }

    /// Writes the files that are due (see `Snapshot::due`).
    pub fn save_due(&self, now: u64) -> bool {
        self.write(now, false)
    }

    fn write(&self, now: u64, all: bool) -> bool {
        let mut ok = true;
        let mut put = |kind: &str, bytes: Vec<u8>| {
            if let Err(e) = veritell_persist::write(&self.path(kind), kind, &bytes) {
                eprintln!("veritell: state {kind} not saved: {e}");
                ok = false;
            }
        };
        put("quota", self.quotas.export(now));
        for (kind, store) in &self.stores {
            if all || store.due(now) {
                put(kind, store.export(now));
            }
        }
        ok
    }
}

/// Saves on an interval and on a graceful shutdown.
pub struct Saver {
    pub state: Arc<State>,
    pub every: Duration,
}

#[async_trait]
impl BackgroundService for Saver {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(self.every) => {
                    let state = Arc::clone(&self.state);
                    let _ = tokio::task::spawn_blocking(move || state.save_due(now_secs())).await;
                }
                _ = shutdown.changed() => {
                    let state = Arc::clone(&self.state);
                    let saved = tokio::task::spawn_blocking(move || state.save(now_secs())).await.unwrap_or(false);
                    eprintln!("veritell: state saved on shutdown{}", if saved { "" } else { " (with errors)" });
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veritell_token::BudgetStore;

    const NOW: u64 = 1_800_000_000;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("veritell-state-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn quotas() -> Arc<Quotas> {
        Arc::new(Quotas::new(veritell_quota::Config::default()).unwrap())
    }

    fn state(d: &Path, q: &Arc<Quotas>, s: &Arc<MemoryBudgetStore>) -> State {
        State::new(d.to_path_buf(), Arc::clone(q), vec![("used-tokens", Arc::clone(s) as Arc<dyn Snapshot>)])
    }

    #[test]
    fn the_replay_cache_survives_a_restart_and_refuses_junk() {
        use veritell_wba::ReplayCache;
        let cache = Arc::new(std::sync::Mutex::new(ReplayCache::new(10)));
        cache.lock().unwrap().restore([1; 32], NOW + 60, NOW);
        cache.lock().unwrap().restore([2; 32], NOW + 5, NOW);
        let bytes = Replays(Arc::clone(&cache)).export(NOW);
        assert_eq!(bytes.len(), 4 + 2 * 40);

        // A new process, ten seconds later: the one still valid comes back.
        let after = Arc::new(std::sync::Mutex::new(ReplayCache::new(10)));
        assert_eq!(Replays(Arc::clone(&after)).import(&bytes, NOW + 10), Ok(1));
        assert_eq!(after.lock().unwrap().entries(NOW + 10), vec![([1; 32], NOW + 60)]);

        let empty = Arc::new(std::sync::Mutex::new(ReplayCache::new(10)));
        let r = Replays(Arc::clone(&empty));
        assert!(r.import(b"nope", NOW).is_err());
        assert!(r.import(&bytes[..bytes.len() - 1], NOW).is_err());
        assert!(empty.lock().unwrap().is_empty(), "a refused file changes nothing");
    }

    #[test]
    fn saved_state_is_loaded_by_a_new_process() {
        let d = dir("roundtrip");
        let (q, s) = (quotas(), Arc::new(MemoryBudgetStore::new(10)));
        q.take("agent", 10, NOW);
        assert!(s.consume(&[1; 16], 1, NOW + 600, NOW));
        assert!(state(&d, &q, &s).save(NOW));
        let (q2, s2) = (quotas(), Arc::new(MemoryBudgetStore::new(10)));
        state(&d, &q2, &s2).load(NOW + 1);
        assert_eq!(q2.left("agent", 10, NOW + 1), 9);
        assert!(!s2.consume(&[1; 16], 1, NOW + 600, NOW + 1), "a spent token came back");
    }

    #[test]
    fn nothing_saved_yet_is_an_empty_start() {
        let d = dir("empty");
        let (q, s) = (quotas(), Arc::new(MemoryBudgetStore::new(10)));
        state(&d, &q, &s).load(NOW);
        assert_eq!(q.tracked(), 0);
        assert!(s.is_empty());
        assert!(std::fs::read_dir(&d).unwrap().next().is_none(), "load wrote something");
    }

    #[test]
    fn a_bad_file_is_set_aside_and_the_store_starts_empty() {
        let d = dir("bad");
        let (q, s) = (quotas(), Arc::new(MemoryBudgetStore::new(10)));
        assert!(s.consume(&[2; 16], 1, NOW + 600, NOW));
        assert!(state(&d, &q, &s).save(NOW));
        let tokens = d.join("used-tokens.state");
        let mut bytes = std::fs::read(&tokens).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        std::fs::write(&tokens, &bytes).unwrap();
        let (q2, s2) = (quotas(), Arc::new(MemoryBudgetStore::new(10)));
        state(&d, &q2, &s2).load(NOW + 1);
        assert!(s2.is_empty());
        assert!(!tokens.exists());
        assert!(d.join("used-tokens.state.refused").exists());
        // The other file was fine and was loaded.
        assert!(d.join("quota.state").exists());
        // The next save writes a good file again.
        assert!(state(&d, &q2, &s2).save(NOW + 2));
        let (q3, s3) = (quotas(), Arc::new(MemoryBudgetStore::new(10)));
        state(&d, &q3, &s3).load(NOW + 3);
        assert!(!d.join("used-tokens.state.refused.refused").exists());
        assert!(s3.is_empty());
    }

    #[test]
    fn probe_results_survive_a_restart() {
        let d = dir("probes");
        let probes = Arc::new(crate::probe::ProbeStore::new(10));
        probes.put([7; 16], Vec::new(), NOW + 600, NOW);
        let st = State::new(d.clone(), quotas(), vec![("probe-results", Arc::clone(&probes) as Arc<dyn Snapshot>)]);
        assert!(st.save(NOW));
        let again = Arc::new(crate::probe::ProbeStore::new(10));
        State::new(d, quotas(), vec![("probe-results", Arc::clone(&again) as Arc<dyn Snapshot>)]).load(NOW + 1);
        assert_eq!(again.get(&[7; 16], NOW + 1), Some(Vec::new()), "the client's clean report is still on record");
    }

    /// An event `ms` milliseconds after `NOW`.
    fn event(ms: u64, path: &str) -> veritell_events::Event {
        use veritell_core::{Class, Detection, Layer};
        use veritell_events::{Event, EventKind};
        Event {
            ts_ms: NOW * 1000 + ms,
            kind: EventKind::Request,
            ip: "192.0.2.1".into(),
            method: "GET".into(),
            host: "example.test".into(),
            path: path.into(),
            user_agent: "ua".into(),
            ja4: String::new(),
            h2: String::new(),
            score: 5,
            class: Class::Human,
            detections: vec![Detection::new("x_y", Layer::Network, 1, "why")],
            identity: String::new(),
            asn: 0,
            net_class: String::new(),
            token: "none".into(),
            action: String::new(),
            enforced: false,
            route: String::new(),
            rule: String::new(),
            outcome: "passed".into(),
            known: String::new(),
            summary: String::new(),
            tcp: String::new(),
            tcp_ttl: 0,
        }
    }

    #[test]
    fn dashboard_events_survive_a_restart() {
        let d = dir("events");
        let ring = Arc::new(veritell_events::MemoryRing::new(10));
        use veritell_events::EventSink;
        ring.record(&event(1, "/a"));
        ring.record(&event(2, "/b"));
        let st = State::new(d.clone(), quotas(), vec![("events", Arc::new(Events::new(Arc::clone(&ring))) as Arc<dyn Snapshot>)]);
        assert!(st.save(NOW));
        let again = Arc::new(veritell_events::MemoryRing::new(10));
        State::new(d, quotas(), vec![("events", Arc::new(Events::new(Arc::clone(&again))) as Arc<dyn Snapshot>)]).load(NOW + 1);
        let paths: Vec<String> = again.events().into_iter().map(|e| e.path).collect();
        assert_eq!(paths, ["/a", "/b"], "same events, oldest first");
    }

    #[test]
    fn events_are_saved_once_a_minute_and_always_on_shutdown() {
        let ring = Arc::new(veritell_events::MemoryRing::new(10));
        let events = Events::new(ring);
        assert!(events.due(NOW));
        events.export(NOW);
        assert!(!events.due(NOW + EVENTS_EVERY_SECS - 1));
        assert!(events.due(NOW + EVENTS_EVERY_SECS));
        // `save` (shutdown) writes whatever `due` says.
        let d = dir("events-due");
        let st = State::new(d.clone(), quotas(), vec![("events", Arc::new(events) as Arc<dyn Snapshot>)]);
        assert!(st.save(NOW + 1));
        assert!(d.join("events.state").exists());
    }

    #[test]
    fn events_keep_the_newest_within_the_size_limit() {
        let ring = Arc::new(veritell_events::MemoryRing::new(100_000));
        use veritell_events::EventSink;
        let long = "x".repeat(4000);
        let n = EVENTS_MAX_BYTES / 4000 + 100;
        for i in 0..n as u64 {
            ring.record(&event(i, &long));
        }
        let bytes = Events::new(ring).export(NOW);
        assert!(bytes.len() <= EVENTS_MAX_BYTES);
        let again = Arc::new(veritell_events::MemoryRing::new(100_000));
        let kept = Events::new(Arc::clone(&again)).import(&bytes, NOW).unwrap();
        assert!(kept > 0 && kept < n);
        assert_eq!(again.events().last().unwrap().ts_ms, NOW * 1000 + n as u64 - 1, "the newest is kept");
    }

    #[test]
    fn events_older_than_30_days_are_dropped() {
        use veritell_events::EventSink;
        let ring = Arc::new(veritell_events::MemoryRing::new(10));
        ring.record(&event(0, "/old"));
        ring.record(&event(EVENTS_MAX_AGE_SECS * 1000, "/new"));
        let later = NOW + EVENTS_MAX_AGE_SECS + 1;
        let bytes = Events::new(Arc::clone(&ring)).export(later);
        let again = Arc::new(veritell_events::MemoryRing::new(10));
        assert_eq!(Events::new(Arc::clone(&again)).import(&bytes, later).unwrap(), 1);
        assert_eq!(again.events()[0].path, "/new");
        // A file saved long ago loads nothing that has aged out since.
        let all = Events::new(ring).export(NOW);
        let empty = Arc::new(veritell_events::MemoryRing::new(10));
        assert_eq!(Events::new(Arc::clone(&empty)).import(&all, NOW + 2 * EVENTS_MAX_AGE_SECS).unwrap(), 0);
    }

    #[test]
    fn a_bad_events_line_leaves_the_ring_empty() {
        let ring = Arc::new(veritell_events::MemoryRing::new(10));
        assert!(Events::new(Arc::clone(&ring)).import(b"{\"ts_ms\":1}\nnot json\n", NOW).is_err());
        assert!(ring.is_empty());
    }

    #[test]
    fn a_failed_save_is_reported_and_keeps_going() {
        let d = dir("unwritable").join("gone");
        let (q, s) = (quotas(), Arc::new(MemoryBudgetStore::new(10)));
        assert!(!state(&d, &q, &s).save(NOW));
    }
}
