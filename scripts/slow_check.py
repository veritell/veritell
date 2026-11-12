#!/usr/bin/env python3
"""E41 helper: slow and surplus HTTP/1 connections against the gateway.

  slow_check.py slow PORT     trickle a request one byte a second; print how
                              many seconds until the gateway closed it
  slow_check.py cap PORT N    open N idle TLS connections, then one more;
                              print whether the extra one was closed at once
"""
import socket, ssl, sys, time

def tls(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["http/1.1"])
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=5), server_hostname="localhost")
    return s

def closed(s, wait):
    s.settimeout(wait)
    try:
        return s.recv(1) == b""
    except socket.timeout:
        return False
    except (ConnectionError, ssl.SSLError, OSError):
        return True

def slow(port):
    s = tls(port)
    start = time.time()
    for b in b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: slow/1\r\nX-Pad: " + b"a" * 60:
        try:
            s.send(bytes([b]))
        except (ConnectionError, ssl.SSLError, OSError):
            break
        if closed(s, 1.0):
            break
        if time.time() - start > 30:
            print("open after 30s"); return
    print(f"closed after {round(time.time() - start)}s")

def cap(port, n):
    held = [tls(port) for _ in range(n)]
    extra = tls(port)
    print("extra closed" if closed(extra, 1.0) else "extra open")
    first_ok = not closed(held[0], 0.2)
    print("held open" if first_ok else "held closed")

if __name__ == "__main__":
    if sys.argv[1] == "slow":
        slow(int(sys.argv[2]))
    else:
        cap(int(sys.argv[2]), int(sys.argv[3]))
