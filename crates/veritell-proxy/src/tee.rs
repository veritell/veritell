//! A pass-through stream wrapper that copies the first bytes read from the
//! client (after TLS) into a bounded buffer, so the HTTP/2 preamble can be
//! fingerprinted without patching the `h2` crate, and that puts total
//! deadlines on what a slow client sends: every HTTP/1 request's headers,
//! and every HTTP/2 frame and header block.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::time::{Instant, Sleep};

use async_trait::async_trait;
use pingora::protocols::tls::{SslDigest, TlsRef};
use pingora::protocols::{
    GetProxyDigest, GetSocketDigest, GetTimingDigest, Peek, Shutdown, Ssl, Stream, TimingDigest,
    UniqueID, UniqueIDType, ALPN,
};
use pingora::protocols::raw_connect::ProxyDigest;
use pingora::protocols::SocketDigest;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use veritell_fp::h2::{self as h2fp, H2Fp, Parse};

/// Upper bound on bytes kept per connection.
const CAPTURE_LIMIT: usize = 16 * 1024;

#[derive(Default)]
pub struct H2Capture {
    buf: Mutex<Vec<u8>>,
    done: AtomicBool,
    attached: AtomicBool,
    parsed: OnceLock<Option<H2Fp>>,
}

impl H2Capture {
    /// Returns true the first time it is called for this connection.
    pub fn attach(&self) -> bool {
        !self.attached.swap(true, Ordering::AcqRel)
    }

    fn record(&self, bytes: &[u8]) {
        if bytes.is_empty() || self.done.load(Ordering::Acquire) {
            return;
        }
        let Ok(mut buf) = self.buf.lock() else {
            return;
        };
        let room = CAPTURE_LIMIT.saturating_sub(buf.len());
        buf.extend_from_slice(&bytes[..bytes.len().min(room)]);
        if buf.len() >= CAPTURE_LIMIT {
            self.done.store(true, Ordering::Release);
        }
    }

    /// The fingerprint, once the first header block has been seen.
    pub fn fingerprint(&self) -> Option<&H2Fp> {
        if let Some(cached) = self.parsed.get() {
            return cached.as_ref();
        }
        let Ok(mut buf) = self.buf.lock() else {
            return None;
        };
        let result = match h2fp::parse(&buf) {
            Parse::Incomplete if !self.done.load(Ordering::Acquire) => return None,
            Parse::Done(fp) => Some(fp),
            Parse::Incomplete | Parse::Invalid => None,
        };
        // Finished either way: stop capturing and release the buffer.
        self.done.store(true, Ordering::Release);
        *buf = Vec::new();
        drop(buf);
        self.parsed.get_or_init(|| result).as_ref()
    }
}

/// A total deadline for one HTTP/1 request's headers. Pingora times out
/// each read, not the header block, so a client sending a byte every few
/// seconds would otherwise hold the connection for ever.
pub struct HeaderDeadline {
    sleep: Pin<Box<Sleep>>,
    /// The last three bytes read, to find a terminator split across reads.
    tail: [u8; 3],
    tail_len: usize,
}

impl HeaderDeadline {
    pub fn new(after: Duration) -> Self {
        HeaderDeadline { sleep: Box::pin(tokio::time::sleep_until(Instant::now() + after)), tail: [0; 3], tail_len: 0 }
    }

    /// Whether `bytes`, following what was read before, complete a header block.
    fn sees_end(&mut self, bytes: &[u8]) -> bool {
        let mut window = Vec::with_capacity(self.tail_len + bytes.len());
        window.extend_from_slice(&self.tail[..self.tail_len]);
        window.extend_from_slice(bytes);
        if window.windows(4).any(|w| w == b"\r\n\r\n") {
            return true;
        }
        let keep = window.len().min(3);
        self.tail[..keep].copy_from_slice(&window[window.len() - keep..]);
        self.tail_len = keep;
        false
    }
}

/// HTTP/1: each request's headers within `timeout`. The first request's
/// deadline starts with the connection; a later request's starts with its
/// first byte, read after the gateway has written a response (a `1xx`
/// response doesn't count: after `100 Continue` the client sends a body).
/// Bodies have their own deadline in the gateway.
pub struct H1Guard {
    timeout: Duration,
    deadline: Option<HeaderDeadline>,
    /// A response went out since the last header block: the next byte read
    /// starts a new request.
    next_request: bool,
}

impl H1Guard {
    pub fn new(timeout: Duration) -> Self {
        H1Guard { timeout, deadline: Some(HeaderDeadline::new(timeout)), next_request: false }
    }

    /// False when the headers in progress are out of time.
    fn read(&mut self, bytes: &[u8], cx: &mut Context<'_>) -> bool {
        if bytes.is_empty() {
            return true;
        }
        if self.next_request && self.deadline.is_none() {
            self.deadline = Some(HeaderDeadline::new(self.timeout));
        }
        self.next_request = false;
        let Some(deadline) = &mut self.deadline else { return true };
        if deadline.sees_end(bytes) {
            self.deadline = None;
            return true;
        }
        deadline.sleep.as_mut().poll(cx).is_pending()
    }

    /// Polling the timer registers the waker, so a client that stops sending
    /// mid-headers is also woken and cut off at the deadline.
    fn pending(&mut self, cx: &mut Context<'_>) -> bool {
        self.deadline.as_mut().is_none_or(|d| d.sleep.as_mut().poll(cx).is_pending())
    }

    fn wrote(&mut self, bytes: &[u8]) {
        let informational = bytes.starts_with(b"HTTP/1.1 1") || bytes.starts_with(b"HTTP/1.0 1");
        if !bytes.is_empty() && !informational {
            self.next_request = true;
        }
    }
}

const H2_PREFACE_LEN: usize = 24;
const H2_DATA: u8 = 0x0;
const H2_HEADERS: u8 = 0x1;
const H2_PUSH_PROMISE: u8 = 0x5;
const H2_CONTINUATION: u8 = 0x9;
const H2_END_HEADERS: u8 = 0x4;

/// HTTP/2: every frame must arrive whole within a time limit from its first
/// byte (`header` for control and header frames, the longer `body` for DATA,
/// which a slow link may carry slowly), and every header block, from its
/// HEADERS frame to the CONTINUATION that ends it, within `header`. The h2
/// crate puts no limit on either. Follows frame boundaries only; the h2
/// crate still parses everything.
pub struct H2Guard {
    header: Duration,
    body: Duration,
    sleep: Pin<Box<Sleep>>,
    /// Preface bytes still to come.
    preface_left: usize,
    head: [u8; 9],
    head_len: usize,
    payload_left: usize,
    frame_type: u8,
    /// When the frame in progress started, if one is.
    frame_since: Option<Instant>,
    /// When the open header block started, if one is.
    block_since: Option<Instant>,
}

impl H2Guard {
    pub fn new(header: Duration, body: Duration) -> Self {
        let now = Instant::now();
        H2Guard {
            header,
            body,
            sleep: Box::pin(tokio::time::sleep_until(now + header)),
            preface_left: H2_PREFACE_LEN,
            head: [0; 9],
            head_len: 0,
            payload_left: 0,
            frame_type: 0,
            // The preface counts as a frame: it must arrive within `header`.
            frame_since: Some(now),
            block_since: None,
        }
    }

    fn feed(&mut self, mut bytes: &[u8], now: Instant) {
        while !bytes.is_empty() {
            if self.preface_left > 0 {
                let n = self.preface_left.min(bytes.len());
                self.preface_left -= n;
                bytes = &bytes[n..];
                if self.preface_left == 0 {
                    self.frame_since = None;
                }
                continue;
            }
            if self.head_len < 9 {
                if self.head_len == 0 && self.payload_left == 0 {
                    self.frame_since = Some(now);
                }
                let n = (9 - self.head_len).min(bytes.len());
                self.head[self.head_len..self.head_len + n].copy_from_slice(&bytes[..n]);
                self.head_len += n;
                bytes = &bytes[n..];
                if self.head_len < 9 {
                    break;
                }
                self.payload_left = usize::from(self.head[0]) << 16 | usize::from(self.head[1]) << 8 | usize::from(self.head[2]);
                self.frame_type = self.head[3];
                let end_headers = self.head[4] & H2_END_HEADERS != 0;
                match self.frame_type {
                    H2_HEADERS | H2_PUSH_PROMISE if !end_headers => {
                        self.block_since.get_or_insert(self.frame_since.unwrap_or(now));
                    }
                    H2_CONTINUATION if end_headers => self.block_since = None,
                    _ => {}
                }
            }
            let n = self.payload_left.min(bytes.len());
            self.payload_left -= n;
            bytes = &bytes[n..];
            if self.payload_left == 0 {
                // Frame complete.
                self.head_len = 0;
                self.frame_since = None;
            }
        }
    }

    /// The earliest moment something in progress runs out of time.
    fn due(&self) -> Option<Instant> {
        let frame_limit = if self.preface_left == 0 && self.head_len == 9 && self.frame_type == H2_DATA {
            self.body
        } else {
            self.header
        };
        let frame = self.frame_since.map(|t| t + frame_limit);
        let block = self.block_since.map(|t| t + self.header);
        match (frame, block) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// False when a frame or header block in progress is out of time.
    fn check(&mut self, cx: &mut Context<'_>) -> bool {
        let Some(due) = self.due() else { return true };
        if self.sleep.deadline() != due {
            self.sleep.as_mut().reset(due);
        }
        self.sleep.as_mut().poll(cx).is_pending()
    }

    fn read(&mut self, bytes: &[u8], cx: &mut Context<'_>) -> bool {
        self.feed(bytes, Instant::now());
        self.check(cx)
    }
}

/// What a connection's reads are held to.
pub enum Guard {
    H1(H1Guard),
    H2(H2Guard),
}

pub struct TeeStream {
    inner: Stream,
    capture: Option<Arc<H2Capture>>,
    guard: Option<Guard>,
}

impl TeeStream {
    pub fn new(inner: Stream, capture: Option<Arc<H2Capture>>, guard: Option<Guard>) -> Self {
        TeeStream { inner, capture, guard }
    }
}

fn too_slow() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::TimedOut, "request not complete in time")
}

impl fmt::Debug for TeeStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TeeStream").field("inner", &self.inner).finish()
    }
}

impl AsyncRead for TeeStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let this = &mut *self;
        let res = Pin::new(&mut this.inner).poll_read(cx, buf);
        match &res {
            Poll::Ready(Ok(())) => {
                let read = &buf.filled()[before..];
                if let Some(capture) = &this.capture {
                    capture.record(read);
                }
                let in_time = match &mut this.guard {
                    Some(Guard::H1(g)) => g.read(read, cx),
                    Some(Guard::H2(g)) => g.read(read, cx),
                    None => true,
                };
                if !in_time {
                    return Poll::Ready(Err(too_slow()));
                }
            }
            Poll::Pending => {
                // Polling the timer registers the waker, so a client that
                // stops sending is also woken and cut off at the deadline.
                let in_time = match &mut this.guard {
                    Some(Guard::H1(g)) => g.pending(cx),
                    Some(Guard::H2(g)) => g.check(cx),
                    None => true,
                };
                if !in_time {
                    return Poll::Ready(Err(too_slow()));
                }
            }
            Poll::Ready(Err(_)) => {}
        }
        res
    }
}

impl AsyncWrite for TeeStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = &mut *self;
        let res = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let (Poll::Ready(Ok(n)), Some(Guard::H1(g))) = (&res, &mut this.guard) {
            g.wrote(&buf[..*n]);
        }
        res
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let this = &mut *self;
        let res = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        if let (Poll::Ready(Ok(n)), Some(Guard::H1(g))) = (&res, &mut this.guard) {
            if *n > 0 {
                let first = bufs.iter().find(|b| !b.is_empty()).map_or(&[][..], |b| &b[..]);
                g.wrote(&first[..first.len().min(*n)]);
            }
        }
        res
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[async_trait]
impl Shutdown for TeeStream {
    async fn shutdown(&mut self) {
        self.inner.shutdown().await
    }
}

impl UniqueID for TeeStream {
    fn id(&self) -> UniqueIDType {
        self.inner.id()
    }
}

impl Ssl for TeeStream {
    fn get_ssl(&self) -> Option<&TlsRef> {
        self.inner.get_ssl()
    }
    fn get_ssl_digest(&self) -> Option<Arc<SslDigest>> {
        self.inner.get_ssl_digest()
    }
    fn selected_alpn_proto(&self) -> Option<ALPN> {
        self.inner.selected_alpn_proto()
    }
}

impl GetTimingDigest for TeeStream {
    fn get_timing_digest(&self) -> Vec<Option<TimingDigest>> {
        self.inner.get_timing_digest()
    }
    fn get_read_pending_time(&self) -> Duration {
        self.inner.get_read_pending_time()
    }
    fn get_write_pending_time(&self) -> Duration {
        self.inner.get_write_pending_time()
    }
}

impl GetProxyDigest for TeeStream {
    fn get_proxy_digest(&self) -> Option<Arc<ProxyDigest>> {
        self.inner.get_proxy_digest()
    }
    fn set_proxy_digest(&mut self, digest: ProxyDigest) {
        self.inner.set_proxy_digest(digest)
    }
}

impl GetSocketDigest for TeeStream {
    fn get_socket_digest(&self) -> Option<Arc<SocketDigest>> {
        self.inner.get_socket_digest()
    }
    fn set_socket_digest(&mut self, digest: SocketDigest) {
        self.inner.set_socket_digest(digest)
    }
}

#[async_trait]
impl Peek for TeeStream {
    async fn try_peek(&mut self, buf: &mut [u8]) -> std::io::Result<bool> {
        self.inner.try_peek(buf).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cx() -> Context<'static> {
        Context::from_waker(std::task::Waker::noop())
    }

    const T: Duration = Duration::from_secs(15);
    const BODY: Duration = Duration::from_secs(60);

    async fn wait(secs: u64) {
        tokio::time::advance(Duration::from_secs(secs)).await;
    }

    #[tokio::test(start_paused = true)]
    async fn h1_first_request_headers_in_time_or_cut() {
        let mut g = H1Guard::new(T);
        assert!(g.read(b"GET / HTTP/1.1\r\n", &mut cx()));
        wait(5).await;
        assert!(g.read(b"Host: a\r\n\r\n", &mut cx()), "complete within 15 s");
        let mut g = H1Guard::new(T);
        assert!(g.read(b"GET / HTTP/1.1\r\n", &mut cx()));
        wait(16).await;
        assert!(!g.read(b"H", &mut cx()), "a byte after the deadline");
        let mut g = H1Guard::new(T);
        wait(16).await;
        assert!(!g.pending(&mut cx()), "nothing at all: cut while waiting");
    }

    #[tokio::test(start_paused = true)]
    async fn h1_a_later_request_on_a_kept_alive_connection_has_its_own_deadline() {
        let mut g = H1Guard::new(T);
        assert!(g.read(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", &mut cx()));
        g.wrote(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok");
        // Idle between requests: the keep-alive timeout's business, not ours.
        wait(100).await;
        assert!(g.pending(&mut cx()));
        assert!(g.read(b"G", &mut cx()), "the next request's first byte starts its deadline");
        wait(10).await;
        assert!(g.read(b"ET /2 HTTP/1.1\r\n", &mut cx()));
        wait(6).await;
        assert!(!g.read(b"H", &mut cx()), "16 s after its first byte");
    }

    #[tokio::test(start_paused = true)]
    async fn h1_a_body_after_100_continue_is_not_taken_for_headers() {
        let mut g = H1Guard::new(T);
        assert!(g.read(b"POST /up HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 9\r\n\r\n", &mut cx()));
        g.wrote(b"HTTP/1.1 100 Continue\r\n\r\n");
        assert!(g.read(b"body", &mut cx()));
        wait(30).await;
        assert!(g.read(b"bytes", &mut cx()), "body bytes: the gateway's body deadline, not this one");
    }

    fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let mut f = (payload.len() as u32).to_be_bytes()[1..].to_vec();
        f.extend_from_slice(&[kind, flags]);
        f.extend_from_slice(&stream.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

    #[tokio::test(start_paused = true)]
    async fn h2_whole_frames_may_come_slowly() {
        let mut g = H2Guard::new(T, BODY);
        assert!(g.read(PREFACE, &mut cx()));
        assert!(g.read(&frame(0x4, 0, 0, &[]), &mut cx()));
        for _ in 0..5 {
            wait(20).await;
            assert!(g.check(&mut cx()), "idle between frames");
            assert!(g.read(&frame(0x6, 0, 0, &[0; 8]), &mut cx()), "a PING now and then");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn h2_a_trickled_headers_frame_is_cut() {
        let mut g = H2Guard::new(T, BODY);
        assert!(g.read(PREFACE, &mut cx()));
        let headers = frame(0x1, 0x5, 1, &[0x82; 40]);
        for (i, b) in headers.iter().enumerate() {
            let ok = g.read(&[*b], &mut cx());
            if i * 2 > 15 {
                assert!(!ok, "byte {i} at {} s", i * 2);
                return;
            }
            assert!(ok, "byte {i}");
            wait(2).await;
        }
        panic!("never cut");
    }

    #[tokio::test(start_paused = true)]
    async fn h2_a_header_block_must_end_in_time() {
        let mut g = H2Guard::new(T, BODY);
        assert!(g.read(PREFACE, &mut cx()));
        assert!(g.read(&frame(0x1, 0x1, 1, &[0x82]), &mut cx()), "HEADERS without END_HEADERS");
        wait(10).await;
        assert!(g.read(&frame(0x9, 0, 1, &[0x84]), &mut cx()), "a CONTINUATION, not the last");
        wait(6).await;
        assert!(!g.check(&mut cx()), "the block is 16 s old");
        let mut g = H2Guard::new(T, BODY);
        assert!(g.read(PREFACE, &mut cx()));
        assert!(g.read(&frame(0x1, 0x1, 1, &[0x82]), &mut cx()));
        wait(10).await;
        assert!(g.read(&frame(0x9, 0x4, 1, &[0x84]), &mut cx()), "ended within 15 s");
        wait(60).await;
        assert!(g.check(&mut cx()));
    }

    #[tokio::test(start_paused = true)]
    async fn h2_a_data_frame_gets_the_body_limit() {
        let mut g = H2Guard::new(T, BODY);
        assert!(g.read(PREFACE, &mut cx()));
        let data = frame(0x0, 0x1, 1, &[7; 1000]);
        assert!(g.read(&data[..100], &mut cx()));
        wait(40).await;
        assert!(g.read(&data[100..500], &mut cx()), "slow link: 40 s into a DATA frame is fine");
        wait(21).await;
        assert!(!g.read(&data[500..600], &mut cx()), "61 s");
    }

    #[tokio::test(start_paused = true)]
    async fn h2_a_preface_must_come_in_time() {
        let mut g = H2Guard::new(T, BODY);
        assert!(g.read(&PREFACE[..10], &mut cx()));
        wait(16).await;
        assert!(!g.check(&mut cx()));
    }

    #[tokio::test]
    async fn finds_the_end_of_headers_across_reads() {
        let mut d = HeaderDeadline::new(Duration::from_secs(1));
        assert!(!d.sees_end(b"GET / HTTP/1.1\r\nHost: a\r"));
        assert!(!d.sees_end(b"\n"));
        assert!(!d.sees_end(b"\r"));
        assert!(d.sees_end(b"\n"));
        let mut d = HeaderDeadline::new(Duration::from_secs(1));
        assert!(!d.sees_end(b""));
        assert!(!d.sees_end(b"\r\n"));
        assert!(d.sees_end(b"\r\nbody"));
        let mut d = HeaderDeadline::new(Duration::from_secs(1));
        assert!(!d.sees_end(b"\n\r\n"), "LF CR LF is not the end");
        assert!(!d.sees_end(b"x\r\n\rx"));
    }
}
