#!/usr/bin/env python3
"""Key directory server for end-to-end tests.

    directory_server.py <port> <cert.pem> <key.pem> < jwks.json > requests.log

Serves over HTTPS on 127.0.0.1:
  /keys.json   the JWK Set, with a Cache-Control lifetime
  /redirect    a 302 to /keys.json, which a verifier must not follow
  /big         a body larger than a directory may be
The JWK Set is read from standard input. Every request path is written to
standard output, one per line.
"""
import ssl
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT, CERT, KEY = int(sys.argv[1]), sys.argv[2], sys.argv[3]
BODY = sys.stdin.buffer.read()


class Directory(BaseHTTPRequestHandler):
    def do_GET(self):
        print(self.path.split("?")[0][:64], flush=True)
        if self.path == "/keys.json":
            self.answer(200, BODY, [("cache-control", "max-age=600")])
        elif self.path == "/redirect":
            self.answer(302, b"", [("location", "/keys.json")])
        elif self.path == "/big":
            self.answer(200, BODY + b" " * 70000, [])
        else:
            self.answer(404, b"", [])

    def answer(self, status, body, headers):
        self.send_response(status)
        self.send_header("content-type", "application/http-message-signatures-directory+json")
        self.send_header("content-length", str(len(body)))
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", PORT), Directory)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CERT, KEY)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
