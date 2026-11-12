//! ClickHouse sink over the HTTP interface.
//! Implement the bodies; do not change signatures.
//!
//! `record` puts the event on a bounded queue and returns. A background
//! thread takes events off the queue and sends them in batches:
//!
//! ```text
//! POST {url}/?query=INSERT%20INTO%20{database}.{table}%20FORMAT%20JSONEachRow
//! X-ClickHouse-User: {user}
//! X-ClickHouse-Key: {password}
//! Content-Type: application/x-ndjson
//!
//! {row}\n{row}\n...
//! ```
//!
//! Credentials go in headers, never in the URL. A batch is sent when it
//! reaches `batch_size` rows or when `flush_interval` has passed since its
//! first row. A batch that fails (connection error, timeout, or a status
//! other than 2xx) is dropped and counted; it is not retried, so a dead
//! server cannot build up memory. When the queue is full, `record` drops the
//! event and counts it.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Map, Value};

use crate::types::{Event, EventSink};

/// `CREATE TABLE` statement for the events table. `{database}` and `{table}`
/// are placeholders. Column names and order match [`to_row`].
///
/// Columns: `ts DateTime64(3)`, `kind`, `ip`, `method`, `host`, `path`,
/// `user_agent`, `ja4`, `h2`, `score UInt8`, `class`, `detection_ids
/// Array(String)`, `detections String` (the full detections as JSON text),
/// `identity`, `asn UInt32`, `net_class`, `token`, `action`, `enforced
/// UInt8`, `route`, `rule`, `outcome`, `known` (a known-person label, or
/// empty), `summary` (a behaviour report's counts as JSON, or empty), `tcp`
/// (the SYN signature, or empty), `tcp_ttl UInt8`. Low-cardinality text columns use
/// `LowCardinality(String)`. Engine `MergeTree`, ordered by `ts`, partitioned
/// by day, with a `TTL` of 30 days.
pub const DDL: &str = "\
CREATE TABLE IF NOT EXISTS {database}.{table}
(
    ts DateTime64(3),
    kind LowCardinality(String),
    ip String,
    method LowCardinality(String),
    host String,
    path String,
    user_agent String,
    ja4 String,
    h2 String,
    score UInt8,
    class LowCardinality(String),
    detection_ids Array(String),
    detections String,
    identity LowCardinality(String),
    asn UInt32,
    net_class LowCardinality(String),
    token LowCardinality(String),
    action LowCardinality(String),
    enforced UInt8,
    route LowCardinality(String),
    rule LowCardinality(String),
    outcome LowCardinality(String),
    known LowCardinality(String) DEFAULT '',
    summary String DEFAULT '',
    tcp LowCardinality(String) DEFAULT '',
    tcp_ttl UInt8 DEFAULT 0
)
ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY ts
TTL toDateTime(ts) + INTERVAL 30 DAY
";

/// Names of the columns produced by [`to_row`], in order.
pub const COLUMNS: [&str; 26] = [
    "ts", "kind", "ip", "method", "host", "path", "user_agent", "ja4", "h2", "score", "class",
    "detection_ids", "detections", "identity", "asn", "net_class", "token", "action", "enforced",
    "route", "rule", "outcome", "known", "summary", "tcp", "tcp_ttl",
];

/// One event as a single-line JSON object for `FORMAT JSONEachRow`, without
/// a trailing newline. Keys are exactly [`COLUMNS`]. `ts` is the time in
/// milliseconds as a number (ClickHouse reads that into `DateTime64(3)`),
/// `enforced` is 0 or 1, `detections` is a string containing JSON.
pub fn to_row(event: &Event) -> String {
    let mut m = Map::new();
    let mut put = |k: &str, v: Value| {
        m.insert(k.to_string(), v);
    };
    put("ts", Value::from(event.ts_ms));
    put("kind", Value::from(event.kind.as_str()));
    put("ip", Value::from(event.ip.as_str()));
    put("method", Value::from(event.method.as_str()));
    put("host", Value::from(event.host.as_str()));
    put("path", Value::from(event.path.as_str()));
    put("user_agent", Value::from(event.user_agent.as_str()));
    put("ja4", Value::from(event.ja4.as_str()));
    put("h2", Value::from(event.h2.as_str()));
    put("score", Value::from(event.score));
    put("class", Value::from(event.class.as_str()));
    put(
        "detection_ids",
        Value::Array(event.detections.iter().map(|d| Value::from(d.id.as_str())).collect()),
    );
    let detections = serde_json::to_string(&event.detections).unwrap_or_else(|_| "[]".to_string());
    put("detections", Value::from(detections));
    put("identity", Value::from(event.identity.as_str()));
    put("asn", Value::from(event.asn));
    put("net_class", Value::from(event.net_class.as_str()));
    put("token", Value::from(event.token.as_str()));
    put("action", Value::from(event.action.as_str()));
    put("enforced", Value::from(u8::from(event.enforced)));
    put("route", Value::from(event.route.as_str()));
    put("rule", Value::from(event.rule.as_str()));
    put("outcome", Value::from(event.outcome.as_str()));
    put("known", Value::from(event.known.as_str()));
    put("summary", Value::from(event.summary.as_str()));
    put("tcp", Value::from(event.tcp.as_str()));
    put("tcp_ttl", Value::from(event.tcp_ttl));
    // `Value`'s Display cannot fail and escapes control characters, so the
    // result is a single line.
    Value::Object(m).to_string()
}

#[derive(Clone, Debug)]
pub struct ClickHouseConfig {
    /// Base URL, for example `http://127.0.0.1:8123`.
    pub url: String,
    pub database: String,
    pub table: String,
    pub user: String,
    pub password: String,
    pub batch_size: usize,
    pub flush_interval: Duration,
    /// Most events waiting to be sent.
    pub queue_capacity: usize,
    /// Timeout for one HTTP request.
    pub timeout: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// `url` does not start with `http://` or `https://`.
    Url,
    /// `database` or `table` is empty or has characters outside
    /// `[A-Za-z0-9_]`.
    Identifier,
    /// `batch_size` or `queue_capacity` is zero.
    Size,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Url => write!(f, "ClickHouse URL must start with http:// or https://"),
            ConfigError::Identifier => write!(f, "database and table must match [A-Za-z0-9_]+"),
            ConfigError::Size => write!(f, "batch size and queue capacity must be positive"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Counters, readable at any time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SinkStats {
    /// Rows the server accepted.
    pub sent: u64,
    /// Rows dropped because the queue was full.
    pub dropped_queue: u64,
    /// Rows dropped because their batch failed.
    pub dropped_send: u64,
}

#[derive(Default)]
struct Counters {
    sent: AtomicU64,
    dropped_queue: AtomicU64,
    dropped_send: AtomicU64,
}

fn add(counter: &AtomicU64, n: u64) {
    // Saturating on purpose: a counter must never wrap back to zero.
    let _ = counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_add(n)));
}

/// The host of a plain `http://` URL that leaves this machine, if it does.
/// A loopback address doesn't, and neither, by assumption, does a
/// single-label name such as a compose service (`http://clickhouse:8123`):
/// those resolve on a local container network.
fn key_sent_in_clear_to(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("http://")?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if let Some(v6) = hostport.strip_prefix('[') {
        v6.split(']').next().unwrap_or("")
    } else {
        hostport.split(':').next().unwrap_or("")
    };
    if host.is_empty() || host.eq_ignore_ascii_case("localhost") {
        return None;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) if ip.is_loopback() => None,
        Ok(_) => Some(host),
        Err(_) if host.contains('.') => Some(host),
        Err(_) => None,
    }
}

pub struct ClickHouseSink {
    /// Dropping this is the shutdown signal for the background thread.
    tx: SyncSender<String>,
    counters: Arc<Counters>,
    /// Receives (or disconnects) when the background thread ends.
    done: Mutex<Receiver<()>>,
}

fn valid_identifier(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

struct Worker {
    rx: Receiver<String>,
    counters: Arc<Counters>,
    agent: ureq::Agent,
    endpoint: String,
    user: String,
    password: String,
    batch_size: usize,
    flush_interval: Duration,
    last_log: Option<Instant>,
}

impl Worker {
    fn run(mut self) {
        while let Ok(first) = self.rx.recv() {
            let deadline = Instant::now().checked_add(self.flush_interval);
            let mut batch = vec![first];
            let mut closed = false;
            while batch.len() < self.batch_size {
                let remaining = match deadline {
                    Some(d) => d.saturating_duration_since(Instant::now()),
                    None => self.flush_interval,
                };
                if remaining.is_zero() {
                    break;
                }
                match self.rx.recv_timeout(remaining) {
                    Ok(row) => batch.push(row),
                    Err(mpsc::RecvTimeoutError::Timeout) => break,
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        closed = true;
                        break;
                    }
                }
            }
            self.send(&batch);
            if closed {
                break;
            }
        }
    }

    fn send(&mut self, batch: &[String]) {
        let rows = u64::try_from(batch.len()).unwrap_or(u64::MAX);
        let mut body = String::with_capacity(batch.iter().map(|r| r.len().saturating_add(1)).sum());
        for row in batch {
            body.push_str(row);
            body.push('\n');
        }
        let result = self
            .agent
            .post(&self.endpoint)
            .set("X-ClickHouse-User", &self.user)
            .set("X-ClickHouse-Key", &self.password)
            .set("Content-Type", "application/x-ndjson")
            .send_string(&body);
        let failure = match result {
            Ok(resp) if (200..300).contains(&resp.status()) => None,
            Ok(resp) => Some(format!("status {}", resp.status())),
            Err(ureq::Error::Status(code, _)) => Some(format!("status {code}")),
            Err(_) => Some("transport error".to_string()),
        };
        match failure {
            None => add(&self.counters.sent, rows),
            Some(why) => {
                add(&self.counters.dropped_send, rows);
                self.log_failure(&why, rows);
            }
        }
    }

    /// At most one line per minute; never prints credentials or event data.
    fn log_failure(&mut self, why: &str, rows: u64) {
        let now = Instant::now();
        let due = self
            .last_log
            .is_none_or(|t| now.saturating_duration_since(t) >= Duration::from_secs(60));
        if due {
            self.last_log = Some(now);
            eprintln!("veritell-events: clickhouse batch of {rows} rows dropped ({why})");
        }
    }
}

impl ClickHouseSink {
    /// Validates the configuration and starts the background thread.
    pub fn start(config: ClickHouseConfig) -> Result<ClickHouseSink, ConfigError> {
        if !(config.url.starts_with("http://") || config.url.starts_with("https://")) {
            return Err(ConfigError::Url);
        }
        if !valid_identifier(&config.database) || !valid_identifier(&config.table) {
            return Err(ConfigError::Identifier);
        }
        if config.batch_size == 0 || config.queue_capacity == 0 {
            return Err(ConfigError::Size);
        }
        if !config.password.is_empty() {
            if let Some(host) = key_sent_in_clear_to(&config.url) {
                eprintln!(
                    "veritell-events: warning: --clickhouse-url is plain http:// to {host}, so the \
                     ClickHouse key crosses the network in clear; use https:// or a loopback address"
                );
            }
        }
        let endpoint = format!(
            "{}/?query=INSERT%20INTO%20{}.{}%20FORMAT%20JSONEachRow",
            config.url.trim_end_matches('/'),
            config.database,
            config.table
        );
        let agent = ureq::AgentBuilder::new().timeout(config.timeout).redirects(0).build();
        let (tx, rx) = mpsc::sync_channel::<String>(config.queue_capacity);
        let (done_tx, done) = mpsc::channel::<()>();
        let counters = Arc::new(Counters::default());
        let worker = Worker {
            rx,
            counters: Arc::clone(&counters),
            agent,
            endpoint,
            user: config.user,
            password: config.password,
            batch_size: config.batch_size,
            flush_interval: config.flush_interval,
            last_log: None,
        };
        // If the thread cannot be spawned the closure (and with it the
        // receiver) is dropped, so `record` just counts drops.
        let _ = std::thread::Builder::new().name("veritell-clickhouse".into()).spawn(move || {
            worker.run();
            let _ = done_tx.send(());
        });
        Ok(ClickHouseSink { tx, counters, done: Mutex::new(done) })
    }

    pub fn stats(&self) -> SinkStats {
        SinkStats {
            sent: self.counters.sent.load(Ordering::Relaxed),
            dropped_queue: self.counters.dropped_queue.load(Ordering::Relaxed),
            dropped_send: self.counters.dropped_send.load(Ordering::Relaxed),
        }
    }

    /// Sends what is queued and stops the background thread. Returns when
    /// the thread has finished or `wait` has passed, whichever is first.
    pub fn shutdown(self, wait: Duration) {
        let ClickHouseSink { tx, counters: _, done } = self;
        // Closing the queue lets the thread drain it, flush and exit.
        drop(tx);
        // Ok or Disconnected: the thread is gone. Timeout: it is stuck in a
        // request and is left to finish on its own.
        let done = done.into_inner().unwrap_or_else(|e| e.into_inner());
        let _ = done.recv_timeout(wait);
    }
}

impl EventSink for ClickHouseSink {
    fn record(&self, event: &Event) {
        if let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) =
            self.tx.try_send(to_row(event))
        {
            add(&self.counters.dropped_queue, 1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veritell_core::{Class, Detection, Layer};

    #[test]
    fn plain_http_to_another_machine_is_flagged() {
        for (url, want) in [
            ("http://127.0.0.1:8123", None),
            ("http://localhost:8123/", None),
            ("http://[::1]:8123", None),
            ("http://clickhouse:8123", None),
            ("http://user@clickhouse:8123", None),
            ("https://ch.example.com:8443", None),
            ("http://ch.example.com:8123", Some("ch.example.com")),
            ("http://10.0.0.5:8123/", Some("10.0.0.5")),
            ("http://u@10.0.0.5", Some("10.0.0.5")),
            ("http://[2001:db8::1]:8123", Some("2001:db8::1")),
            ("http://ch.example.com?x=1", Some("ch.example.com")),
        ] {
            assert_eq!(key_sent_in_clear_to(url), want, "{url}");
        }
    }

    #[test]
    fn every_event_field_has_a_column_and_the_ddl_has_every_column() {
        // A field added to `Event` must reach the store: `to_row` and
        // `COLUMNS` and the DDL all have to change with it.
        let event = serde_json::to_value(ev()).unwrap();
        let row: serde_json::Value = serde_json::from_str(&to_row(&ev())).unwrap();
        for field in event.as_object().unwrap().keys() {
            let column = if field == "ts_ms" { "ts" } else { field.as_str() };
            assert!(COLUMNS.contains(&column), "Event.{field} has no column");
            assert!(row.get(column).is_some(), "to_row leaves out {column}");
        }
        let body = &DDL[DDL.find('(').unwrap() + 1..DDL.find("\n)").unwrap()];
        let ddl: Vec<&str> = body
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(|l| l.split_whitespace().next().unwrap())
            .collect();
        assert_eq!(ddl, COLUMNS.to_vec(), "the DDL's columns, in order");
    }

    fn ev() -> Event {
        Event {
            ts_ms: 1,
            kind: crate::EventKind::Probe,
            ip: "1.1.1.1".into(),
            method: "GET".into(),
            host: "h".into(),
            path: "/\n\"".into(),
            user_agent: "ua\r\n\u{2028}".into(),
            ja4: String::new(),
            h2: String::new(),
            score: 1,
            class: Class::Malicious,
            detections: vec![Detection::new("x", Layer::Network, 1, "line1\nline2")],
            identity: String::new(),
            asn: 1,
            net_class: String::new(),
            token: String::new(),
            action: String::new(),
            enforced: true,
            route: String::new(),
            rule: String::new(),
            outcome: String::new(),
            known: String::new(),
            summary: String::new(),
            tcp: String::new(),
            tcp_ttl: 0,
        }
    }

    #[test]
    fn row_is_one_line_of_valid_json() {
        let row = to_row(&ev());
        assert!(!row.contains('\n') && !row.contains('\r'));
        assert!(serde_json::from_str::<Value>(&row).is_ok());
    }

    #[test]
    fn ddl_column_order_matches_columns() {
        let names: Vec<&str> = DDL
            .lines()
            .filter(|l| l.starts_with("    "))
            .filter_map(|l| l.split_whitespace().next())
            .collect();
        assert_eq!(names, COLUMNS);
    }

    #[test]
    fn full_queue_counts_drops_and_drop_does_not_hang() {
        // A listener that accepts (via the backlog) and never answers keeps
        // the worker busy in its first request.
        let Ok(listener) = std::net::TcpListener::bind("127.0.0.1:0") else { return };
        let Ok(addr) = listener.local_addr() else { return };
        let sink = ClickHouseSink::start(ClickHouseConfig {
            url: format!("http://{addr}/"),
            database: "d".into(),
            table: "t".into(),
            user: String::new(),
            password: String::new(),
            batch_size: 1,
            flush_interval: Duration::from_secs(3600),
            queue_capacity: 2,
            timeout: Duration::from_secs(3),
        })
        .map_err(|_| ())
        .ok();
        let Some(sink) = sink else { return };
        for _ in 0..100 {
            sink.record(&ev());
        }
        // At most one row is in flight and two are queued.
        assert!(sink.stats().dropped_queue >= 90);
        drop(sink);
        drop(listener);
    }
}
