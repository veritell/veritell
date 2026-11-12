//! Acceptance tests written by the project lead. DO NOT EDIT.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use veritell_core::{Class, Detection, Layer};
use veritell_events::clickhouse::{
    to_row, ClickHouseConfig, ClickHouseSink, ConfigError, SinkStats, COLUMNS, DDL,
};
use veritell_events::*;

fn event(ts_ms: u64, score: u8, class: Class, detections: &[&str]) -> Event {
    Event {
        ts_ms,
        kind: EventKind::Request,
        ip: "203.0.113.9".into(),
        method: "GET".into(),
        host: "example.com".into(),
        path: "/products".into(),
        user_agent: "curl/8.7.1".into(),
        ja4: "t13d4907h2_0d8feac7bc37_7395dae3b2f3".into(),
        h2: "3:100;4:10485760;2:0|1048510465|0|m,s,a,p".into(),
        score,
        class,
        detections: detections
            .iter()
            .map(|id| Detection::new(id, Layer::Network, 10, format!("why {id}")))
            .collect(),
        identity: String::new(),
        asn: 64500,
        net_class: "hosting".into(),
        token: "none".into(),
        action: "challenge(pow)".into(),
        enforced: true,
        route: "0".into(),
        rule: "1".into(),
        outcome: "challenged".into(),
        known: String::new(),
        summary: String::new(),
        tcp: String::new(),
        tcp_ttl: 0,
    }
}

// ---------- ring ----------

#[test]
fn ring_returns_newest_first_and_respects_limit() {
    let ring = MemoryRing::new(10);
    assert!(ring.is_empty());
    for i in 0..5 {
        ring.record(&event(i, 50, Class::Human, &[]));
    }
    assert_eq!(ring.len(), 5);
    let all = ring.recent(100, &Filter::default());
    assert_eq!(all.iter().map(|e| e.ts_ms).collect::<Vec<_>>(), [4, 3, 2, 1, 0]);
    let two = ring.recent(2, &Filter::default());
    assert_eq!(two.iter().map(|e| e.ts_ms).collect::<Vec<_>>(), [4, 3]);
    assert!(ring.recent(0, &Filter::default()).is_empty());
}

#[test]
fn ring_is_bounded_and_counts_evictions() {
    let ring = MemoryRing::new(3);
    for i in 0..10 {
        ring.record(&event(i, 50, Class::Human, &[]));
    }
    assert_eq!(ring.len(), 3);
    let kept = ring.recent(100, &Filter::default());
    assert_eq!(kept.iter().map(|e| e.ts_ms).collect::<Vec<_>>(), [9, 8, 7]);
    assert_eq!(ring.summary(0).evicted, 7);

    let one = MemoryRing::new(0);
    one.record(&event(1, 50, Class::Human, &[]));
    one.record(&event(2, 50, Class::Human, &[]));
    assert_eq!(one.len(), 1);
}

#[test]
fn ring_filters() {
    let ring = MemoryRing::new(100);
    ring.record(&event(1, 99, Class::Human, &[]));
    ring.record(&event(2, 39, Class::Automated, &["ua_declared_tool"]));
    ring.record(&event(3, 9, Class::Malicious, &["crawler_spoofed", "ua_declared_bot"]));
    let mut probe = event(4, 99, Class::Human, &[]);
    probe.kind = EventKind::Probe;
    probe.ip = "198.51.100.1".into();
    probe.outcome = "probe_ok".into();
    ring.record(&probe);

    let ts = |f: Filter| ring.recent(100, &f).iter().map(|e| e.ts_ms).collect::<Vec<_>>();
    assert_eq!(ts(Filter { class: Some(Class::Human), ..Default::default() }), [4, 1]);
    assert_eq!(ts(Filter { detection: Some("ua_declared_bot".into()), ..Default::default() }), [3]);
    assert_eq!(ts(Filter { detection: Some("ua_declared".into()), ..Default::default() }), Vec::<u64>::new());
    assert_eq!(ts(Filter { max_score: Some(39), ..Default::default() }), [3, 2]);
    assert_eq!(ts(Filter { ip: Some("198.51.100.1".into()), ..Default::default() }), [4]);
    assert_eq!(ts(Filter { kind: Some(EventKind::Request), ..Default::default() }), [3, 2, 1]);
    assert_eq!(ts(Filter { outcome: Some("challenged".into()), ..Default::default() }), [3, 2, 1]);
    assert_eq!(
        ts(Filter { class: Some(Class::Human), kind: Some(EventKind::Request), ..Default::default() }),
        [1]
    );
    // The limit applies after filtering.
    let f = Filter { max_score: Some(39), ..Default::default() };
    assert_eq!(ring.recent(1, &f).iter().map(|e| e.ts_ms).collect::<Vec<_>>(), [3]);
}

#[test]
fn ring_summary() {
    let ring = MemoryRing::new(100);
    ring.record(&event(100, 99, Class::Human, &[]));
    ring.record(&event(200, 39, Class::Automated, &["b_det", "a_det"]));
    ring.record(&event(300, 9, Class::Malicious, &["b_det", "c_det"]));
    ring.record(&event(400, 1, Class::Malicious, &["a_det"]));
    let mut passed = event(500, 95, Class::Human, &[]);
    passed.outcome = "passed".into();
    ring.record(&passed);
    let mut probe = event(600, 5, Class::Automated, &["webdriver_true"]);
    probe.kind = EventKind::Probe;
    ring.record(&probe);

    let s = ring.summary(0);
    assert_eq!(s.total, 5);
    assert_eq!(s.by_class.get("human"), Some(&2));
    assert_eq!(s.by_class.get("automated"), Some(&1));
    assert_eq!(s.by_class.get("malicious"), Some(&2));
    assert_eq!(s.by_outcome.get("challenged"), Some(&4));
    assert_eq!(s.by_outcome.get("passed"), Some(&1));
    assert_eq!(
        s.top_detections,
        [("a_det".to_string(), 2), ("b_det".to_string(), 2), ("c_det".to_string(), 1)]
    );
    assert_eq!(s.score_histogram, [2, 0, 0, 1, 0, 0, 0, 0, 0, 2]);
    assert_eq!(s.evicted, 0);

    let later = ring.summary(300);
    assert_eq!(later.total, 3);
    assert_eq!(later.by_class.get("automated"), None);
    assert_eq!(ring.summary(10_000), Summary::default());
}

#[test]
fn top_detections_is_capped_at_twenty() {
    let ring = MemoryRing::new(100);
    let names: Vec<String> = (0..30).map(|i| format!("d{i:02}")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    ring.record(&event(1, 50, Class::Human, &refs));
    ring.record(&event(2, 50, Class::Human, &refs[25..]));
    let top = ring.summary(0).top_detections;
    assert_eq!(top.len(), 20);
    assert_eq!(top[0], ("d25".to_string(), 2));
    assert_eq!(top[5], ("d00".to_string(), 1));
}

#[test]
fn ring_is_safe_to_share_between_threads() {
    let ring = Arc::new(MemoryRing::new(1000));
    let handles: Vec<_> = (0..8)
        .map(|t| {
            let ring = Arc::clone(&ring);
            std::thread::spawn(move || {
                for i in 0..500 {
                    ring.record(&event(t * 1000 + i, 50, Class::Human, &[]));
                    let _ = ring.recent(5, &Filter::default());
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(ring.len(), 1000);
    assert_eq!(ring.summary(0).evicted, 3000);
}

#[test]
fn fanout_reaches_every_sink() {
    let a = Arc::new(MemoryRing::new(10));
    let b = Arc::new(MemoryRing::new(10));
    let sinks: Vec<Arc<dyn EventSink>> = vec![a.clone() as Arc<dyn EventSink>, b.clone() as Arc<dyn EventSink>];
    let fan = Fanout::new(sinks);
    fan.record(&event(1, 50, Class::Human, &[]));
    assert_eq!((a.len(), b.len()), (1, 1));
    Fanout::new(vec![]).record(&event(1, 50, Class::Human, &[]));
}

// ---------- ClickHouse rows ----------

#[test]
fn row_has_exactly_the_documented_columns() {
    let mut e = event(1_700_000_000_123, 39, Class::Automated, &["ua_declared_tool", "tls_known_tool"]);
    e.user_agent = "evil\"\n\u{1}</script>\u{2028}é".into();
    e.identity = "Googlebot".into();
    let row = to_row(&e);
    assert!(!row.contains('\n'), "row must be one line");
    let v: serde_json::Value = serde_json::from_str(&row).unwrap();
    let obj = v.as_object().unwrap();
    let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
    let mut expected = COLUMNS.to_vec();
    keys.sort_unstable();
    expected.sort_unstable();
    assert_eq!(keys, expected);

    assert_eq!(v["ts"], 1_700_000_000_123u64);
    assert_eq!(v["kind"], "request");
    assert_eq!(v["score"], 39);
    assert_eq!(v["class"], "automated");
    assert_eq!(v["enforced"], 1);
    assert_eq!(v["asn"], 64500);
    assert_eq!(v["user_agent"], "evil\"\n\u{1}</script>\u{2028}é");
    assert_eq!(v["detection_ids"], serde_json::json!(["ua_declared_tool", "tls_known_tool"]));
    assert_eq!(v["identity"], "Googlebot");
    let inner: Vec<Detection> = serde_json::from_str(v["detections"].as_str().unwrap()).unwrap();
    assert_eq!(inner, e.detections);

    e.enforced = false;
    let v: serde_json::Value = serde_json::from_str(&to_row(&e)).unwrap();
    assert_eq!(v["enforced"], 0);
}

#[test]
fn ddl_declares_every_column() {
    assert!(DDL.contains("CREATE TABLE IF NOT EXISTS {database}.{table}"), "{DDL}");
    for column in COLUMNS {
        assert!(
            DDL.lines().any(|l| l.trim_start().starts_with(&format!("{column} "))),
            "DDL has no line starting with column {column}"
        );
    }
    for needle in ["DateTime64(3)", "Array(String)", "MergeTree", "ORDER BY", "PARTITION BY", "TTL"] {
        assert!(DDL.contains(needle), "DDL lacks {needle}");
    }
}

// ---------- ClickHouse sink against a local mock ----------

struct Received {
    request_line: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl Received {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

fn read_request(stream: &mut TcpStream) -> Option<Received> {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).ok()? == 0 {
        return None;
    }
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).ok()?;
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        let (k, v) = line.split_once(':')?;
        headers.push((k.trim().to_string(), v.trim().to_string()));
    }
    let find = |n: &str| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(n))
            .map(|(_, v)| v.clone())
    };
    let mut body = Vec::new();
    if let Some(len) = find("content-length") {
        body.resize(len.parse().ok()?, 0);
        reader.read_exact(&mut body).ok()?;
    } else if find("transfer-encoding").is_some() {
        loop {
            let mut size = String::new();
            reader.read_line(&mut size).ok()?;
            let n = usize::from_str_radix(size.trim(), 16).ok()?;
            let mut chunk = vec![0; n + 2];
            reader.read_exact(&mut chunk).ok()?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
        }
    }
    Some(Received {
        request_line: request_line.trim_end().to_string(),
        headers,
        body: String::from_utf8(body).ok()?,
    })
}

/// Starts a server that answers every request with `status` and forwards
/// what it received. Returns its base URL.
fn mock(status: u16) -> (String, mpsc::Receiver<Received>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let tx = tx.clone();
            std::thread::spawn(move || {
                while let Some(received) = read_request(&mut stream) {
                    let _ = tx.send(received);
                    let reply = format!(
                        "HTTP/1.1 {status} X\r\ncontent-length: 0\r\nconnection: keep-alive\r\n\r\n"
                    );
                    if stream.write_all(reply.as_bytes()).is_err() {
                        break;
                    }
                }
            });
        }
    });
    (url, rx)
}

fn config(url: &str) -> ClickHouseConfig {
    ClickHouseConfig {
        url: url.to_string(),
        database: "veritell".into(),
        table: "events".into(),
        user: "writer".into(),
        password: "s3cret/pw?&".into(),
        batch_size: 3,
        flush_interval: Duration::from_millis(200),
        queue_capacity: 100,
        timeout: Duration::from_secs(2),
    }
}

fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() < Duration::from_secs(10), "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn sink_sends_batches_with_credentials_in_headers() {
    let (url, rx) = mock(200);
    let sink = ClickHouseSink::start(config(&url)).unwrap();
    for i in 0..3 {
        sink.record(&event(i, 50, Class::Human, &["d"]));
    }
    let got = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(got.request_line.starts_with("POST /?query="), "{}", got.request_line);
    let query = got.request_line.to_ascii_lowercase();
    assert!(query.contains("insert"), "{query}");
    assert!(query.contains("veritell.events"), "{query}");
    assert!(query.contains("jsoneachrow"), "{query}");
    assert!(!got.request_line.contains("s3cret"), "password in the URL");
    assert!(!got.request_line.contains("writer"), "user in the URL");
    assert!(!got.request_line.contains(' ') || got.request_line.matches(' ').count() == 2);
    assert_eq!(got.header("x-clickhouse-user"), Some("writer"));
    assert_eq!(got.header("x-clickhouse-key"), Some("s3cret/pw?&"));

    let lines: Vec<&str> = got.body.lines().collect();
    assert_eq!(lines.len(), 3);
    for (i, line) in lines.iter().enumerate() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["ts"], i as u64);
    }
    wait_for("sent counter", || sink.stats().sent == 3);
    assert_eq!(
        sink.stats(),
        SinkStats { sent: 3, dropped_queue: 0, dropped_send: 0 }
    );
    sink.shutdown(Duration::from_secs(2));
}

#[test]
fn a_partial_batch_is_flushed_after_the_interval() {
    let (url, rx) = mock(200);
    let sink = ClickHouseSink::start(config(&url)).unwrap();
    sink.record(&event(7, 50, Class::Human, &[]));
    let got = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(got.body.lines().count(), 1);
    sink.shutdown(Duration::from_secs(2));
}

#[test]
fn shutdown_flushes_what_is_queued() {
    let (url, rx) = mock(200);
    let mut c = config(&url);
    c.flush_interval = Duration::from_secs(3600);
    c.batch_size = 1000;
    let sink = ClickHouseSink::start(c).unwrap();
    sink.record(&event(1, 50, Class::Human, &[]));
    sink.record(&event(2, 50, Class::Human, &[]));
    sink.shutdown(Duration::from_secs(5));
    let got = rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(got.body.lines().count(), 2);
}

#[test]
fn a_failing_server_drops_batches_and_does_not_stall_the_caller() {
    let (url, rx) = mock(500);
    let sink = ClickHouseSink::start(config(&url)).unwrap();
    let start = Instant::now();
    for i in 0..6 {
        sink.record(&event(i, 50, Class::Human, &[]));
    }
    assert!(start.elapsed() < Duration::from_millis(200), "record blocked");
    wait_for("dropped counter", || sink.stats().dropped_send == 6);
    assert_eq!(sink.stats().sent, 0);
    // Two batches arrived; neither is sent again.
    assert!(rx.recv_timeout(Duration::from_secs(1)).is_ok());
    assert!(rx.recv_timeout(Duration::from_secs(1)).is_ok());
    assert!(rx.recv_timeout(Duration::from_millis(600)).is_err(), "a failed batch was retried");
    sink.shutdown(Duration::from_secs(2));
}

#[test]
fn an_unreachable_server_never_blocks_record() {
    // Bind then drop, so nothing listens on this port.
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let mut c = config(&format!("http://127.0.0.1:{port}"));
    c.queue_capacity = 5;
    c.batch_size = 5;
    c.timeout = Duration::from_millis(300);
    let sink = ClickHouseSink::start(c).unwrap();
    let start = Instant::now();
    for i in 0..10_000 {
        sink.record(&event(i, 50, Class::Human, &[]));
    }
    assert!(start.elapsed() < Duration::from_secs(2), "record blocked: {:?}", start.elapsed());
    let s = sink.stats();
    assert_eq!(s.sent, 0);
    // A refused connection fails at once, so the worker may keep up with the
    // caller and nothing is dropped at the queue. Only the total is fixed.
    wait_for("all rows accounted for", || {
        let s = sink.stats();
        s.dropped_queue + s.dropped_send == 10_000
    });
    sink.shutdown(Duration::from_secs(2));
}

#[test]
fn shutdown_returns_within_its_deadline() {
    // A server that accepts and never answers.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming() {
            held.push(stream);
        }
    });
    let mut c = config(&url);
    c.timeout = Duration::from_secs(30);
    c.batch_size = 1;
    let sink = ClickHouseSink::start(c).unwrap();
    sink.record(&event(1, 50, Class::Human, &[]));
    std::thread::sleep(Duration::from_millis(100));
    let start = Instant::now();
    sink.shutdown(Duration::from_millis(300));
    assert!(start.elapsed() < Duration::from_secs(2), "{:?}", start.elapsed());
}

#[test]
fn configuration_is_validated() {
    let bad = |f: fn(&mut ClickHouseConfig)| {
        let mut c = config("http://127.0.0.1:1");
        f(&mut c);
        ClickHouseSink::start(c).err()
    };
    assert_eq!(bad(|c| c.url = "ftp://x".into()), Some(ConfigError::Url));
    assert_eq!(bad(|c| c.url = "127.0.0.1:8123".into()), Some(ConfigError::Url));
    assert_eq!(bad(|c| c.table = "events; DROP TABLE x".into()), Some(ConfigError::Identifier));
    assert_eq!(bad(|c| c.database = "".into()), Some(ConfigError::Identifier));
    assert_eq!(bad(|c| c.database = "a.b".into()), Some(ConfigError::Identifier));
    assert_eq!(bad(|c| c.batch_size = 0), Some(ConfigError::Size));
    assert_eq!(bad(|c| c.queue_capacity = 0), Some(ConfigError::Size));
    assert_eq!(bad(|_| {}), None);
}
