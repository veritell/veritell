#!/usr/bin/env python3
"""Acceptance tests for report.py. Fixed by the lead: the numbers are
worked out by hand from fixtures/report_events.jsonl.  python3 deploy/test_report.py"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPORT = os.path.join(HERE, "report.py")
FIX = os.path.join(HERE, "fixtures", "report_events.jsonl")
EVIL_UA = "evil\x1b[31m<script>alert(1)</script>\\"


def vid(day, ip, ja4, ua):
    return hashlib.sha256((day + "\0" + ip + "\0" + ja4 + "\0" + ua).encode()).hexdigest()[:12]


V1 = vid("2026-11-02", "k:aa", "J1", "Mozilla/5.0 Chrome/149")
V2 = vid("2026-11-02", "k:bb", "J2", "python-requests/2.32")
V5 = vid("2026-11-02", "k:ee", "J1", "Mozilla/5.0 Safari/27")
V6 = vid("2026-11-03", "k:bb", "J2", "python-requests/2.32")
V7 = vid("2026-11-03", "k:ff", "J4", "curl/8.7")
V8 = vid("2026-11-03", "k:hh", "J5", EVIL_UA)


def run(args, stdin=None):
    return subprocess.run([sys.executable, REPORT] + args, input=stdin, capture_output=True, text=True)


class Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.html_path = os.path.join(cls.tmp, "r.html")
        cls.json_path = os.path.join(cls.tmp, "r.json")
        p = run(["--events", FIX, "--site", "shop <test>", "--html", cls.html_path, "--json", cls.json_path])
        if p.returncode != 0:
            raise AssertionError("report.py failed: %s" % p.stderr)
        with open(cls.json_path, encoding="utf-8") as f:
            cls.j = json.load(f)
        with open(cls.html_path, encoding="utf-8") as f:
            cls.html = f.read()

    def test_totals(self):
        j = self.j
        self.assertEqual(j["site"], "shop <test>")
        self.assertEqual((j["first_day"], j["last_day"]), ("2026-11-02", "2026-11-03"))
        self.assertEqual(j["requests"], 13)
        self.assertEqual(j["visits"], 8)

    def test_kinds(self):
        self.assertEqual(self.j["kinds"], {"person": 1, "crawler": 1, "automated": 4, "human": 2})

    def test_actions(self):
        self.assertEqual(self.j["actions"], {
            "block": {"visits": 3, "requests": 5},
            "challenge": {"visits": 3, "requests": 3},
            "pass": {"visits": 2, "requests": 5},
        })

    def test_known_person_alarm(self):
        self.assertEqual(self.j["known"], {
            "visits": 1, "acted_on": 1,
            "acted": [{"visit": V1, "known": "p1-laptop", "action": "challenge", "fired": ["missing_accept_language"]}],
        })

    def test_rules(self):
        self.assertEqual(self.j["rules"], [
            {"id": "ua_declared_tool", "visits": 3, "requests": 5, "known_visits": 0},
            {"id": "tls_known_tool", "visits": 2, "requests": 2, "known_visits": 0},
            {"id": "h2_settings_mismatch", "visits": 1, "requests": 1, "known_visits": 0},
            {"id": "missing_accept_language", "visits": 1, "requests": 1, "known_visits": 1},
        ])

    def test_clients(self):
        self.assertEqual(self.j["clients"], [
            {"user_agent": "python-requests/2.32", "ja4": "J2", "visits": 2, "requests": 4, "action": "block"},
            {"user_agent": "curl/8.7", "ja4": "J4", "visits": 1, "requests": 1, "action": "challenge"},
            {"user_agent": EVIL_UA, "ja4": "J5", "visits": 1, "requests": 1, "action": "block"},
        ])

    def test_paths(self):
        self.assertEqual(self.j["paths"], [
            {"path": "/.env", "requests": 3},
            {"path": "/", "requests": 1},
            {"path": "/<img src=x>", "requests": 1},
            {"path": "/wp-login.php", "requests": 1},
        ])

    def test_probe(self):
        self.assertEqual(self.j["probe"], {"browser_visits": 2, "with_probe": 1})

    def test_h2_fixture(self):
        # V4 and V5 are the browser visits; their requests have no h2 (h1).
        self.assertEqual(self.j["h2"], {"visits": 2, "changed": 0, "mixed_h1": 0})

    def test_samples(self):
        s = self.j["samples"]
        blocks = sorted([V6, V8])
        challenges = [V5, V7]  # V5 has 2 requests, V7 1
        self.assertEqual([x["visit"] for x in s], [V2] + blocks + challenges)
        first = s[0]
        self.assertEqual(first, {
            "visit": V2, "day": "2026-11-02", "kind": "automated", "action": "block", "requests": 3,
            "user_agent": "python-requests/2.32", "ja4": "J2",
            "fired": ["ua_declared_tool", "tls_known_tool"], "paths": ["/wp-login.php", "/.env"],
        })
        self.assertNotIn(V1, [x["visit"] for x in s], "a known person is never a sample")

    def test_no_addresses(self):
        for addr in ("k:aa", "k:bb", "k:dd", "k:ee", "k:ff", "k:gg", "k:hh"):
            self.assertNotIn(addr, self.html)
            self.assertNotIn(addr, json.dumps(self.j))

    def test_html_self_contained(self):
        h = self.html.lower()
        self.assertNotIn("<script", h)
        self.assertNotIn("http://", h)
        self.assertNotIn("https://", h)
        self.assertIn('content="default-src \'none\'; style-src \'unsafe-inline\'"', self.html)

    def test_html_escapes_client_text(self):
        self.assertNotIn("\x1b", self.html)
        self.assertIn("evil\\x1b[31m&lt;script&gt;alert(1)&lt;/script&gt;\\x5c", self.html)
        self.assertIn("/&lt;img src=x&gt;", self.html)
        self.assertIn("shop &lt;test&gt;", self.html)

    def test_html_shows_the_alarm_and_ids(self):
        self.assertIn(V1, self.html)
        self.assertIn("p1-laptop", self.html)
        self.assertLess(self.html.index(V1), self.html.index("ua_declared_tool"), "the alarm comes before the rules")
        for v in (V2, V5, V6, V7, V8):
            self.assertIn(v, self.html)


class Edges(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.html = os.path.join(self.tmp, "r.html")
        self.json = os.path.join(self.tmp, "r.json")

    def test_stdin_and_empty(self):
        p = run(["--events", "-", "--html", self.html, "--json", self.json], stdin="")
        self.assertEqual(p.returncode, 0, p.stderr)
        with open(self.json) as f:
            j = json.load(f)
        self.assertEqual((j["requests"], j["visits"], j["first_day"], j["samples"]), (0, 0, None, []))
        self.assertEqual(j["actions"]["block"], {"visits": 0, "requests": 0})
        self.assertTrue(os.path.getsize(self.html) > 0)

    def test_stdin_same_as_file(self):
        with open(FIX) as f:
            data = f.read()
        p = run(["--events", "-", "--html", self.html, "--json", self.json], stdin=data)
        self.assertEqual(p.returncode, 0, p.stderr)
        with open(self.json) as f:
            self.assertEqual(json.load(f)["visits"], 8)

    def test_bad_line_writes_nothing(self):
        bad = os.path.join(self.tmp, "bad.jsonl")
        with open(FIX) as f, open(bad, "w") as g:
            g.write(f.read() + "not json\n")
        p = run(["--events", bad, "--html", self.html, "--json", self.json])
        self.assertEqual(p.returncode, 2)
        self.assertIn(":17", p.stderr)
        self.assertFalse(os.path.exists(self.html))
        self.assertFalse(os.path.exists(self.json))

    def test_missing_field(self):
        bad = os.path.join(self.tmp, "bad.jsonl")
        with open(bad, "w") as g:
            g.write('{"ts":"2026-11-02 10:00:00","kind":"request","ja4":"J","user_agent":"u","detection_ids":[],"action":"pass","path":"/"}\n')
        p = run(["--events", bad, "--html", self.html])
        self.assertEqual(p.returncode, 2)
        self.assertIn("ip", p.stderr)

    def test_long_text_is_cut(self):
        ev = os.path.join(self.tmp, "long.jsonl")
        ua = "A" * 400
        with open(ev, "w") as g:
            g.write(json.dumps({"ts": "2026-11-02 10:00:00", "kind": "request", "ip": "k:x", "ja4": "J",
                                "user_agent": ua, "detection_ids": ["r"], "action": "block", "path": "/",
                                "class": "automated"}) + "\n")
        p = run(["--events", ev, "--html", self.html])
        self.assertEqual(p.returncode, 0, p.stderr)
        with open(self.html, encoding="utf-8") as f:
            h = f.read()
        self.assertIn("A" * 160 + "…", h)
        self.assertNotIn("A" * 161, h)

    def test_browser_visits(self):
        ev = os.path.join(self.tmp, "browsers.jsonl")
        rows = [
            ("k:1", "/", "request"), ("k:1", "/a.js", "request"), ("k:1", "/__veritell/probe", "probe"),
            ("k:2", "/shop/", "request"), ("k:2", "/s.css", "request"),
            ("k:3", "/", "request"), ("k:3", "/robots.txt", "request"),
            ("k:4", "/a.js", "request"), ("k:4", "/b.css", "request"),
            ("k:5", "/.env", "request"), ("k:5", "/x.js", "request"),
        ]
        with open(ev, "w") as g:
            for ip, path, kind in rows:
                g.write(json.dumps({"ts": "2026-11-02 10:00:00", "kind": kind, "ip": ip, "ja4": "J",
                                    "user_agent": "Mozilla/5.0", "detection_ids": [], "action": "pass" if kind == "request" else "",
                                    "path": path, "class": "human"}) + "\n")
        p = run(["--events", ev, "--html", self.html, "--json", self.json])
        self.assertEqual(p.returncode, 0, p.stderr)
        with open(self.json) as f:
            j = json.load(f)
        # k:1 and k:2 load a page and its scripts or styles; k:3 has no script
        # or style, k:4 no page, k:5's only "page" is a file (/.env).
        self.assertEqual(j["probe"], {"browser_visits": 2, "with_probe": 1})

    def test_h2_changes(self):
        ev = os.path.join(self.tmp, "h2.jsonl")
        A = "1:65536;2:0;4:6291456|15663105|0|m,a,s,p"
        A_PRIO = "1:65536;2:0;4:6291456|15663105|3:0:0:201|m,a,s,p"
        B = "1:65536;2:0;4:131072|15663105|0|m,a,s,p"
        visits = {
            "k:1": [A, A],            # one value
            "k:2": [A, A_PRIO],       # only PRIORITY differs: one value
            "k:3": [A, B],            # SETTINGS differ: changed
            "k:4": [A, ""],           # HTTP/2 then HTTP/1.1: changed, mixed
            "k:5": [""],              # one request only: not measured
        }
        with open(ev, "w") as g:
            for ip, h2s in visits.items():
                paths = ["/", "/a.js", "/b.css"][:max(len(h2s), 2)]
                for n, path in enumerate(paths):
                    h2 = h2s[n] if n < len(h2s) else h2s[-1]
                    if ip == "k:5" and n > 0:
                        # k:5's asset is a probe-free second event of another kind
                        g.write(json.dumps({"ts": "2026-11-02 10:00:01", "kind": "probe", "ip": ip, "ja4": "J",
                                            "user_agent": "Mozilla/5.0", "detection_ids": [], "action": "",
                                            "path": "/a.js", "class": "human", "h2": ""}) + "\n")
                        continue
                    g.write(json.dumps({"ts": "2026-11-02 10:00:00", "kind": "request", "ip": ip, "ja4": "J",
                                        "user_agent": "Mozilla/5.0", "detection_ids": [], "action": "pass",
                                        "path": path, "class": "human", "h2": h2}) + "\n")
        p = run(["--events", ev, "--html", self.html, "--json", self.json])
        self.assertEqual(p.returncode, 0, p.stderr)
        with open(self.json) as f:
            j = json.load(f)
        self.assertEqual(j["h2"], {"visits": 4, "changed": 2, "mixed_h1": 1})

    def test_twenty_samples_at_most(self):
        ev = os.path.join(self.tmp, "many.jsonl")
        with open(ev, "w") as g:
            for i in range(30):
                g.write(json.dumps({"ts": "2026-11-02 10:00:00", "kind": "request", "ip": "k:%d" % i, "ja4": "J",
                                    "user_agent": "bot", "detection_ids": ["r"], "action": "block", "path": "/",
                                    "class": "automated"}) + "\n")
        p = run(["--events", ev, "--html", self.html, "--json", self.json])
        self.assertEqual(p.returncode, 0, p.stderr)
        with open(self.json) as f:
            j = json.load(f)
        self.assertEqual(len(j["samples"]), 20)
        self.assertEqual(j["clients"], [{"user_agent": "bot", "ja4": "J", "visits": 30, "requests": 30, "action": "block"}])


if __name__ == "__main__":
    unittest.main(verbosity=1)
