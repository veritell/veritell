#!/usr/bin/env python3
"""Hostile-traffic generator for scripts/soak.sh (python3 stdlib only).

Runs several kinds of misbehaving clients against the gateway at a modest,
steady rate and prints per-kind counts on exit (SIGTERM/SIGINT).

For the slow kinds, `<kind>_closed_by_server` means the gateway cut the
client off (closed the connection or, on HTTP/2, ended the stream), and
`<kind>_finished` means it let a byte-every-2-s client send everything: a
missing deadline, worth a look.

  soak_client.py --port 8463 [--duration SECONDS]

Certificate checks are off: the gateway uses a throwaway certificate.
"""
import argparse
import asyncio
import os
import signal
import socket
import ssl
import struct
import sys
import time

COUNTS = {}
STOP = None  # asyncio.Event


def bump(kind, n=1):
    COUNTS[kind] = COUNTS.get(kind, 0) + n


def tls_ctx(alpn=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if alpn:
        ctx.set_alpn_protocols(alpn)
    return ctx


def abort_close(writer):
    """Close with RST (SO_LINGER 0) where the socket is reachable."""
    try:
        sock = writer.get_extra_info("socket")
        if sock is not None:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        writer.transport.abort()
    except Exception:
        pass


async def sleep_or_stop(seconds):
    try:
        await asyncio.wait_for(STOP.wait(), timeout=seconds)
    except asyncio.TimeoutError:
        pass


async def connect_tls(port, alpn=None):
    return await asyncio.open_connection(
        "127.0.0.1", port, ssl=tls_ctx(alpn), server_hostname="localhost"
    )


async def closed_by_peer(reader, writer, poll=1.0):
    """Wait until the server closes (EOF/error) or we are stopping."""
    while not STOP.is_set():
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=poll)
            if data == b"":
                return
        except asyncio.TimeoutError:
            continue
        except Exception:
            return


# a. slow headers: one byte every 2 s
async def slow_headers(port, idx):
    req = (
        b"GET /slow HTTP/1.1\r\nHost: localhost\r\n"
        b"User-Agent: slow-soak/1\r\nX-Pad: " + b"a" * 4000 + b"\r\n\r\n"
    )
    while not STOP.is_set():
        try:
            reader, writer = await connect_tls(port)
        except Exception:
            bump("slow_connect_fail")
            await sleep_or_stop(1.0)
            continue
        bump("slow_headers")
        i = 0
        try:
            while not STOP.is_set():
                writer.write(req[i:i + 1])
                await writer.drain()
                i = (i + 1) % len(req)
                try:
                    data = await asyncio.wait_for(reader.read(4096), timeout=2.0)
                    if data == b"":
                        bump("slow_closed_by_server")
                        break
                except asyncio.TimeoutError:
                    pass
        except Exception:
            bump("slow_closed_by_server")
        finally:
            abort_close(writer)
        await sleep_or_stop(0.5 + (idx % 5) * 0.2)


# b. idle TLS / idle plain TCP
async def idle_tls(port, idx):
    while not STOP.is_set():
        try:
            reader, writer = await connect_tls(port)
        except Exception:
            bump("idle_tls_connect_fail")
            await sleep_or_stop(1.0)
            continue
        bump("idle_tls")
        await closed_by_peer(reader, writer)
        bump("idle_tls_closed")
        abort_close(writer)
        await sleep_or_stop(0.5 + (idx % 5) * 0.2)


async def idle_tcp(port, idx):
    while not STOP.is_set():
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
        except Exception:
            bump("idle_tcp_connect_fail")
            await sleep_or_stop(1.0)
            continue
        bump("idle_tcp")
        await closed_by_peer(reader, writer)
        bump("idle_tcp_closed")
        abort_close(writer)
        await sleep_or_stop(0.5 + (idx % 5) * 0.2)


# c. HTTP/2 resets
def h2_frame(ftype, flags, stream, payload=b""):
    return struct.pack(">I", len(payload))[1:] + bytes([ftype, flags]) + struct.pack(">I", stream) + payload


def hpack_literal(name, value):
    # 6.2.2 literal header field without indexing, new name; no Huffman.
    assert len(name) < 127 and len(value) < 127
    return b"\x00" + bytes([len(name)]) + name + bytes([len(value)]) + value


H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def h2_request_block(path):
    return b"".join(
        [
            hpack_literal(b":method", b"GET"),
            hpack_literal(b":scheme", b"https"),
            hpack_literal(b":path", path),
            hpack_literal(b":authority", b"localhost"),
            hpack_literal(b"user-agent", b"h2-reset-soak/1"),
        ]
    )


async def h2_reset(port, idx):
    n = 0
    while not STOP.is_set():
        n += 1
        try:
            reader, writer = await connect_tls(port, ["h2"])
            sid = 1
            buf = H2_PREFACE
            buf += h2_frame(0x4, 0, 0)  # SETTINGS
            # HEADERS, END_HEADERS (0x4) only: request left open, then reset
            buf += h2_frame(0x1, 0x4, sid, h2_request_block(b"/?r=%d" % n))
            buf += h2_frame(0x3, 0, sid, struct.pack(">I", 0x8))  # RST_STREAM CANCEL
            writer.write(buf)
            await writer.drain()
            await asyncio.sleep(0.05)
            bump("h2_reset")
            abort_close(writer)
        except Exception:
            bump("h2_reset_fail")
        await sleep_or_stop(0.25)


# d. garbage POSTs
async def garbage_post(port, idx):
    paths = [b"/__veritell/probe", b"/__veritell/behavior"]
    n = 0
    while not STOP.is_set():
        n += 1
        path = paths[n % 2]
        size = int.from_bytes(os.urandom(2), "big") % 65537
        body = os.urandom(size)
        req = (
            b"POST " + path + b" HTTP/1.1\r\nHost: localhost\r\n"
            b"User-Agent: garbage-soak/1\r\nContent-Type: application/octet-stream\r\n"
            b"Content-Length: " + str(size).encode() + b"\r\nConnection: close\r\n\r\n" + body
        )
        try:
            reader, writer = await connect_tls(port)
            writer.write(req)
            await writer.drain()
            try:
                await asyncio.wait_for(reader.read(65536), timeout=5.0)
            except asyncio.TimeoutError:
                pass
            bump("garbage_post")
            abort_close(writer)
        except Exception:
            bump("garbage_post_fail")
        await sleep_or_stop(0.2)


# e. abandoned: half a request then abrupt close
async def abandoned(port, idx):
    while not STOP.is_set():
        try:
            reader, writer = await connect_tls(port)
            writer.write(b"POST /__veritell/behavior HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5000\r\n\r\n" + os.urandom(100))
            await writer.drain()
            await asyncio.sleep(0.1)
            bump("abandoned")
            abort_close(writer)
        except Exception:
            bump("abandoned_fail")
        await sleep_or_stop(0.3)


async def trickle(reader, writer, data, every=2.0):
    """Send `data` one byte every `every` seconds, watching for the server
    to close. Returns "closed", "sent" or "stopped"."""
    for i in range(len(data)):
        if STOP.is_set():
            return "stopped"
        try:
            writer.write(data[i:i + 1])
            await writer.drain()
        except Exception:
            return "closed"
        try:
            got = await asyncio.wait_for(reader.read(4096), timeout=every)
            if got == b"":
                return "closed"
        except asyncio.TimeoutError:
            pass
        except Exception:
            return "closed"
    return "sent"


def count_outcome(kind, outcome):
    if outcome == "closed":
        bump(kind + "_closed_by_server")
    elif outcome == "sent":
        bump(kind + "_finished")


# f. trickled POST body: headers at once, then the body one byte every 2 s
async def trickle_post(port, idx):
    paths = [b"/__veritell/verify", b"/__veritell/behavior"]
    body = b"challenge=" + b"a" * 990
    while not STOP.is_set():
        try:
            reader, writer = await connect_tls(port)
        except Exception:
            bump("trickle_post_connect_fail")
            await sleep_or_stop(1.0)
            continue
        bump("trickle_post")
        head = (
            b"POST " + paths[idx % 2] + b" HTTP/1.1\r\nHost: localhost\r\n"
            b"User-Agent: trickle-soak/1\r\nContent-Type: application/x-www-form-urlencoded\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n"
        )
        try:
            writer.write(head)
            await writer.drain()
            count_outcome("trickle_post", await trickle(reader, writer, body))
        except Exception:
            bump("trickle_post_closed_by_server")
        finally:
            abort_close(writer)
        await sleep_or_stop(0.5 + (idx % 5) * 0.2)


async def read_response(reader, timeout=10.0):
    """Read one HTTP/1.1 response. Returns True if the connection can carry
    another request (a complete, length-delimited response, no close)."""
    raw = b""
    while b"\r\n\r\n" not in raw:
        chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        if not chunk:
            return False
        raw += chunk
    head, rest = raw.split(b"\r\n\r\n", 1)
    lines = head.decode("latin-1").lower().split("\r\n")
    fields = dict(l.split(":", 1) for l in lines[1:] if ":" in l)
    fields = {k.strip(): v.strip() for k, v in fields.items()}
    if "close" in fields.get("connection", ""):
        return False
    if "content-length" in fields:
        need = int(fields["content-length"]) - len(rest)
        while need > 0:
            chunk = await asyncio.wait_for(reader.read(min(need, 65536)), timeout=timeout)
            if not chunk:
                return False
            need -= len(chunk)
        return True
    if "chunked" in fields.get("transfer-encoding", ""):
        while not rest.endswith(b"0\r\n\r\n"):
            chunk = await asyncio.wait_for(reader.read(65536), timeout=timeout)
            if not chunk:
                return False
            rest += chunk
        return True
    return False


# g. slow request later on a kept-alive connection: one normal request,
#    then the next one's headers one byte every 2 s
async def keepalive_slow(port, idx):
    first = b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: keepalive-soak/1\r\n\r\n"
    second = (
        b"GET /later HTTP/1.1\r\nHost: localhost\r\n"
        b"User-Agent: keepalive-soak/1\r\nX-Pad: " + b"a" * 4000 + b"\r\n\r\n"
    )
    while not STOP.is_set():
        try:
            reader, writer = await connect_tls(port, ["http/1.1"])
        except Exception:
            bump("keepalive_connect_fail")
            await sleep_or_stop(1.0)
            continue
        try:
            writer.write(first)
            await writer.drain()
            if not await read_response(reader):
                bump("keepalive_not_kept")
            else:
                bump("keepalive_slow")
                count_outcome("keepalive_slow", await trickle(reader, writer, second))
        except Exception:
            bump("keepalive_closed_by_server")
        finally:
            abort_close(writer)
        await sleep_or_stop(0.5 + (idx % 5) * 0.2)


async def h2_open(port, settings=b""):
    """TLS with ALPN h2, preface and SETTINGS, then ACK the server's SETTINGS."""
    reader, writer = await connect_tls(port, ["h2"])
    if writer.get_extra_info("ssl_object").selected_alpn_protocol() != "h2":
        abort_close(writer)
        raise ConnectionError("no h2")
    writer.write(H2_PREFACE + h2_frame(0x4, 0, 0, settings))
    await writer.drain()
    buf = b""
    while True:
        while len(buf) < 9:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            if not chunk:
                raise ConnectionError("closed during setup")
            buf += chunk
        length = int.from_bytes(buf[:3], "big")
        while len(buf) < 9 + length:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            if not chunk:
                raise ConnectionError("closed during setup")
            buf += chunk
        ftype, flags = buf[3], buf[4]
        buf = buf[9 + length:]
        if ftype == 0x4 and not flags & 0x1:
            writer.write(h2_frame(0x4, 0x1, 0))  # SETTINGS ACK
            await writer.drain()
            return reader, writer


class H2Frames:
    """Reads whole frames from a connection, to see the server end a stream."""

    def __init__(self, reader):
        self.reader = reader
        self.buf = b""

    async def ended(self, stream, timeout):
        """True when, within `timeout`, the server resets `stream`, answers on
        it with END_STREAM, sends GOAWAY or closes the connection."""
        try:
            chunk = await asyncio.wait_for(self.reader.read(4096), timeout=timeout)
        except asyncio.TimeoutError:
            return False
        except Exception:
            return True
        if chunk == b"":
            return True
        self.buf += chunk
        while len(self.buf) >= 9:
            length = int.from_bytes(self.buf[:3], "big")
            if len(self.buf) < 9 + length:
                break
            ftype, flags = self.buf[3], self.buf[4]
            sid = int.from_bytes(self.buf[5:9], "big") & 0x7FFFFFFF
            self.buf = self.buf[9 + length:]
            if ftype == 0x7:  # GOAWAY
                return True
            if sid == stream and (ftype == 0x3 or flags & 0x1):  # RST_STREAM, or END_STREAM
                return True
        return False


# h. slow HTTP/2 clients, three kinds by idx:
#    0: the HEADERS frame one byte every 2 s
#    1: a POST whose DATA comes one byte every 2 s, one frame per byte
#    2: a GET with a zero flow-control window, never opened (a reader that never reads)
H2_SLOW = ["h2_slow_headers", "h2_slow_body", "h2_zero_window"]


async def h2_slow(port, idx):
    kind = H2_SLOW[idx % 3]
    n = 0
    while not STOP.is_set():
        n += 1
        try:
            settings = struct.pack(">HI", 0x4, 0) if kind == "h2_zero_window" else b""
            reader, writer = await h2_open(port, settings)
        except Exception:
            bump(kind + "_connect_fail")
            await sleep_or_stop(1.0)
            continue
        bump(kind)
        try:
            frames = H2Frames(reader)
            if kind == "h2_slow_headers":
                frame = h2_frame(0x1, 0x5, 1, h2_request_block(b"/?s=%d" % n))
                outcome = "sent"
                for i in range(len(frame)):
                    if STOP.is_set():
                        outcome = "stopped"
                        break
                    writer.write(frame[i:i + 1])
                    await writer.drain()
                    if await frames.ended(1, 2.0):
                        outcome = "closed"
                        break
                count_outcome(kind, outcome)
            elif kind == "h2_slow_body":
                block = b"".join([
                    hpack_literal(b":method", b"POST"),
                    hpack_literal(b":scheme", b"https"),
                    hpack_literal(b":path", b"/__veritell/verify"),
                    hpack_literal(b":authority", b"localhost"),
                    hpack_literal(b"user-agent", b"h2-slow-soak/1"),
                    hpack_literal(b"content-length", b"1000"),
                ])
                writer.write(h2_frame(0x1, 0x4, 1, block))  # END_HEADERS, body to follow
                await writer.drain()
                outcome = "sent"
                for i in range(1000):
                    if STOP.is_set():
                        outcome = "stopped"
                        break
                    writer.write(h2_frame(0x0, 0x1 if i == 999 else 0, 1, b"a"))
                    await writer.drain()
                    if await frames.ended(1, 2.0):
                        outcome = "closed"
                        break
                count_outcome(kind, outcome)
            else:
                writer.write(h2_frame(0x1, 0x5, 1, h2_request_block(b"/?w=%d" % n)))
                await writer.drain()
                while not STOP.is_set():
                    if await frames.ended(1, 2.0):
                        bump(kind + "_closed_by_server")
                        break
        except Exception:
            bump(kind + "_closed_by_server")
        finally:
            abort_close(writer)
        await sleep_or_stop(0.5 + (idx % 5) * 0.2)


def print_counts():
    print("soak_client counts:")
    for k in sorted(COUNTS):
        print(f"  {k}: {COUNTS[k]}")
    sys.stdout.flush()


async def main():
    global STOP
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8463)
    ap.add_argument("--duration", type=float, default=0, help="seconds, 0 = until signalled")
    a = ap.parse_args()
    STOP = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, STOP.set)
    p = a.port
    tasks = []
    tasks += [asyncio.create_task(slow_headers(p, i)) for i in range(30)]
    tasks += [asyncio.create_task(idle_tls(p, i)) for i in range(30)]
    tasks += [asyncio.create_task(idle_tcp(p, i)) for i in range(30)]
    tasks += [asyncio.create_task(h2_reset(p, i)) for i in range(5)]
    tasks += [asyncio.create_task(garbage_post(p, i)) for i in range(5)]
    tasks += [asyncio.create_task(abandoned(p, i)) for i in range(5)]
    tasks += [asyncio.create_task(trickle_post(p, i)) for i in range(10)]
    tasks += [asyncio.create_task(keepalive_slow(p, i)) for i in range(10)]
    tasks += [asyncio.create_task(h2_slow(p, i)) for i in range(9)]
    if a.duration > 0:
        loop.call_later(a.duration, STOP.set)
    await STOP.wait()
    await asyncio.wait(tasks, timeout=5)
    for t in tasks:
        t.cancel()
    print_counts()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print_counts()
