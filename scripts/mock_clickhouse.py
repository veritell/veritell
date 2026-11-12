#!/usr/bin/env python3
"""Stand-in for ClickHouse's HTTP interface in end-to-end tests: appends each
request line, the user header and the body to a file. Usage: PORT OUTFILE"""
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

OUT = sys.argv[2]


class Sink(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length", "0")))
        with open(OUT, "ab") as f:
            f.write(f"REQUEST {self.path} user={self.headers.get('x-clickhouse-user')}\n".encode())
            f.write(body)
        self.send_response(200)
        self.send_header("content-length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", int(sys.argv[1])), Sink).serve_forever()
