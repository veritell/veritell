#!/usr/bin/env python3
"""TLS origin for the R1 checks (scripts/e2e_upstream_tls.sh).

    tls_origin.py <port> <cert.pem> <key.pem> <log file>

Serves HTTPS on 127.0.0.1:<port>. Each request appends one JSON line to the
log file: the SNI the client sent, the path and the request headers. Paths:

    /html/page  an HTML page, gzip-compressed when Accept-Encoding allows gzip,
                as a web server with compression on would serve it
    /html/etag  an HTML page with ETag "v1"; 304 to a matching If-None-Match
    anything    a fixed JSON body; what the request carried is in the log only
"""
import gzip
import json
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT, CERT, KEY, LOG = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
PAGE = b"<!doctype html><html><head><title>t</title></head><body><p>tls origin page</p></body></html>"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        sni = getattr(self.connection, "veritell_sni", None)
        headers = {k.lower(): v for k, v in self.headers.items()}
        with open(LOG, "a") as f:
            f.write(json.dumps({"sni": sni, "path": self.path, "headers": headers}) + "\n")
        if self.path == "/html/etag":
            # ETag "v1"; a matching If-None-Match, weak or strong, is a 304
            # (weak comparison, RFC 9110 13.1.2), as nginx does.
            inm = [t.strip() for t in headers.get("if-none-match", "").split(",") if t.strip()]
            if any(t.removeprefix("W/") == '"v1"' for t in inm):
                self.send_response(304)
                self.send_header("etag", '"v1"')
                self.end_headers()
                return
            body, extra = PAGE, [("content-type", "text/html; charset=utf-8"), ("etag", '"v1"')]
        elif self.path == "/html/page":
            body, extra = PAGE, [("content-type", "text/html; charset=utf-8")]
            if "gzip" in headers.get("accept-encoding", ""):
                body = gzip.compress(PAGE)
                extra.append(("content-encoding", "gzip"))
                extra.append(("vary", "accept-encoding"))
        else:
            # Nothing of the request goes back to the client.
            body = b'{"origin": true}'
            extra = [("content-type", "application/json")]
        self.send_response(200)
        for k, v in extra:
            self.send_header(k, v)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def main():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)

    def on_sni(sock, name, _ctx):
        sock.veritell_sni = name

    ctx.sni_callback = on_sni
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


main()
