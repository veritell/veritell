#!/usr/bin/env python3
"""Tiny origin for end-to-end tests: echoes the request headers as JSON."""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class Echo(BaseHTTPRequestHandler):
    def do_GET(self):
        # HTML pages for the probe injection checks (E44).
        if self.path.startswith("/html/"):
            kind = self.path.split("/")[2]
            page = b"<!doctype html><html><head><title>t</title></head><body><p>origin page</p></body></html>"
            headers = [("content-type", "text/html; charset=utf-8"), ("etag", '"v1"')]
            if kind == "gz":
                headers.append(("content-encoding", "gzip"))
            elif kind == "big":
                page = b"<!doctype html><html><head></head><body>" + b"x" * (600 * 1024) + b"</body></html>"
            elif kind == "notags":
                page = b"plain text, no tags"
            self.send_response(200)
            for k, v in headers:
                self.send_header(k, v)
            self.send_header("content-length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)
            return
        body = json.dumps(
            {"origin": True, "path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}}
        ).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", int(sys.argv[1])), Echo).serve_forever()
