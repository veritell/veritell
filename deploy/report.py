#!/usr/bin/env python3
"""The weekly partner report: reads events, writes one HTML page and
one JSON file. Standard library only, Python 3.9 or later.

  report.py --events FILE|- [--site NAME] --html OUT [--json OUT]

Events are streamed line by line; only a small record per visit is kept.
Nothing is written unless every line was read and valid (exit 2 otherwise).
No client address appears in the output: it only goes into the visit id.
"""
import argparse
import datetime
import hashlib
import html
import json
import os
import re
import sys

KINDS = ("request", "probe", "challenge")
CRAWLER_CLASSES = ("verified_bot", "signed_agent")
AUTOMATED_CLASSES = ("automated", "malicious", "unverified_agent")
RANK = {"pass": 0, "challenge": 1, "block": 2}
_TS = re.compile(r"^(\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d)(\.\d+)?$")


class Bad(Exception):
    pass


# ---- reading events (visits are grouped by visit id) ----

def _day(where, o):
    if "ts_ms" in o:
        v = o["ts_ms"]
        if isinstance(v, bool) or not isinstance(v, int):
            raise Bad("%s: ts_ms is not an integer" % where)
        try:
            d = datetime.datetime(1970, 1, 1) + datetime.timedelta(milliseconds=v)
        except (OverflowError, ValueError):
            raise Bad("%s: ts_ms out of range" % where)
        return d.strftime("%Y-%m-%d")
    if "ts" not in o:
        raise Bad("%s: missing field ts or ts_ms" % where)
    v = o["ts"]
    m = _TS.match(v) if isinstance(v, str) else None
    if not m:
        raise Bad("%s: ts is not YYYY-MM-DD hh:mm:ss[.fff]" % where)
    try:
        datetime.datetime.strptime(m.group(1) + " " + m.group(2), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        raise Bad("%s: ts is not a valid time" % where)
    return m.group(1)


def _ids(where, o):
    if "detection_ids" in o:
        v = o["detection_ids"]
        if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
            raise Bad("%s: detection_ids is not a list of strings" % where)
        return v
    if "detections" in o:
        v = o["detections"]
        if not isinstance(v, list) or not all(isinstance(x, dict) and isinstance(x.get("id"), str) for x in v):
            raise Bad("%s: detections is not a list of objects with id" % where)
        return [x["id"] for x in v]
    raise Bad("%s: missing field detection_ids or detections" % where)


def _opt(where, o, f):
    v = o.get(f, "")
    if v is None:
        return ""
    if not isinstance(v, str):
        raise Bad("%s: field %s is not a string" % (where, f))
    return v


def visit_id(day, ip, ja4, ua):
    s = day + "\0" + ip + "\0" + ja4 + "\0" + ua
    return hashlib.sha256(s.encode("utf-8", "surrogatepass")).hexdigest()[:12]


def norm_action(a):
    if a == "block":
        return "block"
    if a.startswith("challenge"):
        return "challenge"
    return "pass"


class Visit(object):
    __slots__ = ("day", "ua", "ja4", "known", "crawler", "auto", "requests", "rank",
                 "probe", "page", "asset", "h2s", "fired", "paths3", "pathcount")

    def __init__(self, day, ua, ja4):
        self.day = day
        self.ua = ua
        self.ja4 = ja4
        self.known = ""
        self.crawler = False
        self.auto = False
        self.requests = 0
        self.rank = 0
        self.probe = False
        self.page = False    # a request for a page: a path ending in /, or with no . in its last segment
        self.asset = False   # a request for a script or stylesheet (.js, .css)
        self.h2s = set()     # stable HTTP/2 fingerprints of its requests ("h1" for HTTP/1.1); at most 3 kept
        self.fired = {}      # detection id -> events listing it
        self.paths3 = []     # first 3 distinct request paths
        self.pathcount = {}  # request path -> count

    def kind(self):
        if self.known:
            return "person"
        if self.crawler:
            return "crawler"
        if self.auto:
            return "automated"
        return "human"

    def action(self):
        return ("pass", "challenge", "block")[self.rank]


def stable_h2(value):
    """The part of an HTTP/2 fingerprint a browser keeps: SETTINGS,
    WINDOW_UPDATE and pseudo-header order, without PRIORITY (the third
    field). Empty (HTTP/1.1) is "h1"."""
    if not isinstance(value, str) or not value:
        return "h1"
    parts = value.split("|")
    if len(parts) == 4:
        del parts[2]
    return "|".join(parts)


def read_events(stream, name):
    visits = {}
    act_requests = {"block": 0, "challenge": 0, "pass": 0}
    rule_requests = {}
    requests = 0
    for no, raw in enumerate(stream, 1):
        where = "%s:%d" % (name, no)
        try:
            line = raw.decode("utf-8")
        except UnicodeDecodeError as e:
            raise Bad("%s: not valid UTF-8: %s" % (where, e))
        line = line.rstrip("\r\n")
        if not line.strip():
            continue
        try:
            o = json.loads(line)
        except ValueError as e:
            raise Bad("%s: not valid JSON: %s" % (where, e))
        if not isinstance(o, dict):
            raise Bad("%s: not a JSON object" % where)
        day = _day(where, o)
        for f in ("kind", "ip", "ja4", "user_agent", "action", "path"):
            if f not in o:
                raise Bad("%s: missing field %s" % (where, f))
            if not isinstance(o[f], str):
                raise Bad("%s: field %s is not a string" % (where, f))
        if o["kind"] not in KINDS:
            raise Bad("%s: kind is not request, probe or challenge" % where)
        ids = _ids(where, o)
        known = _opt(where, o, "known")
        cls = _opt(where, o, "class")
        identity = _opt(where, o, "identity")

        vid = visit_id(day, o["ip"], o["ja4"], o["user_agent"])
        v = visits.get(vid)
        if v is None:
            v = visits[vid] = Visit(day, o["user_agent"], o["ja4"])
        if known and not v.known:
            v.known = known
        if identity or cls in CRAWLER_CLASSES:
            v.crawler = True
        distinct = set(ids)
        for i in distinct:
            v.fired[i] = v.fired.get(i, 0) + 1
        if o["kind"] == "probe":
            v.probe = True
        elif o["kind"] == "request":
            requests += 1
            v.requests += 1
            if cls in AUTOMATED_CLASSES:
                v.auto = True
            a = norm_action(o["action"])
            act_requests[a] += 1
            if RANK[a] > v.rank:
                v.rank = RANK[a]
            for i in distinct:
                rule_requests[i] = rule_requests.get(i, 0) + 1
            p = o["path"]
            v.pathcount[p] = v.pathcount.get(p, 0) + 1
            if len(v.h2s) < 3:
                v.h2s.add(stable_h2(o.get("h2")))
            last = p.rsplit("/", 1)[-1]
            if p.endswith("/") or "." not in last:
                v.page = True
            if last.endswith((".js", ".css")):
                v.asset = True
            if len(v.paths3) < 3 and p not in v.paths3:
                v.paths3.append(p)
    return visits, requests, act_requests, rule_requests


# ---- the numbers ----

def summarize(visits, requests, act_requests, rule_requests, site):
    ids = sorted(visits)
    days = [visits[i].day for i in ids]
    kinds = {"person": 0, "crawler": 0, "automated": 0, "human": 0}
    actions = {a: {"visits": 0, "requests": act_requests[a]} for a in ("block", "challenge", "pass")}
    acted = []
    rules = {}
    clients = {}
    paths = {}
    browser_visits = with_probe = 0
    h2_visits = h2_changed = h2_mixed = 0
    samples = []
    known_visits = 0
    for i in ids:
        v = visits[i]
        k = v.kind()
        a = v.action()
        kinds[k] += 1
        actions[a]["visits"] += 1
        for r in v.fired:
            e = rules.setdefault(r, [0, 0, 0])
            e[0] += 1
            if k == "person":
                e[2] += 1
        if k == "person":
            known_visits += 1
            if a != "pass":
                acted.append({"visit": i, "known": v.known, "action": a, "fired": sorted(v.fired)})
        if k == "automated":
            c = clients.setdefault((v.ua, v.ja4), [0, 0, 0])
            c[0] += 1
            c[1] += v.requests
            c[2] = max(c[2], v.rank)
            for p, n in v.pathcount.items():
                paths[p] = paths.get(p, 0) + n
        # What a browser does and a scanner almost never: a page and its
        # scripts or styles. Only these can be expected to run the probe.
        if k in ("human", "person") and v.page and v.asset:
            browser_visits += 1
            if v.requests >= 2:
                h2_visits += 1
                if len(v.h2s) > 1:
                    h2_changed += 1
                    if "h1" in v.h2s:
                        h2_mixed += 1
            if v.probe:
                with_probe += 1
        if a != "pass" and k != "person":
            samples.append(i)
    for r, n in rule_requests.items():
        rules[r][1] = n
    samples.sort(key=lambda i: (visits[i].rank != 2, -visits[i].requests, i))
    out_samples = []
    for i in samples[:20]:
        v = visits[i]
        out_samples.append({
            "visit": i, "day": v.day, "kind": v.kind(), "action": v.action(), "requests": v.requests,
            "user_agent": v.ua, "ja4": v.ja4,
            "fired": [r for r, _ in sorted(v.fired.items(), key=lambda kv: (-kv[1], kv[0]))],
            "paths": list(v.paths3),
        })
    return {
        "site": site,
        "first_day": min(days) if days else None,
        "last_day": max(days) if days else None,
        "requests": requests,
        "visits": len(ids),
        "kinds": kinds,
        "actions": actions,
        "known": {"visits": known_visits, "acted_on": len(acted), "acted": acted},
        "rules": [{"id": r, "visits": e[0], "requests": e[1], "known_visits": e[2]}
                  for r, e in sorted(rules.items(), key=lambda kv: (-kv[1][0], kv[0]))],
        "clients": [{"user_agent": ua, "ja4": j, "visits": c[0], "requests": c[1],
                     "action": ("pass", "challenge", "block")[c[2]]}
                    for (ua, j), c in sorted(clients.items(), key=lambda kv: (-kv[1][1], kv[0][0], kv[0][1]))[:10]],
        "paths": [{"path": p, "requests": n}
                  for p, n in sorted(paths.items(), key=lambda kv: (-kv[1], kv[0]))[:10]],
        "probe": {"browser_visits": browser_visits, "with_probe": with_probe},
        "h2": {"visits": h2_visits, "changed": h2_changed, "mixed_h1": h2_mixed},
        "samples": out_samples,
    }


# ---- the page ----

def esc_client(s):
    """Escape the text: anything outside printable ASCII, and the
    backslash, becomes \\xNN per UTF-8 byte; cut at 160 characters."""
    out = []
    for ch in s:
        if ch != "\\" and " " <= ch <= "~":
            out.append(ch)
        else:
            for b in ch.encode("utf-8", "surrogatepass"):
                out.append("\\x%02x" % b)
    r = "".join(out)
    if len(r) > 160:
        r = r[:160] + "\u2026"
    return r


def h(s):
    """A string from a client, for the page: escaped twice."""
    return html.escape(esc_client(s))


CSS = """
body{margin:0;padding:16px;background:#fff;color:#1a1a1a;font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{max-width:50rem;margin:0 auto}
h1{font-size:1.6rem;margin:0 0 .25rem}
h2{font-size:1.2rem;margin:2rem 0 .25rem;border-bottom:1px solid #ccc;padding-bottom:.2rem}
p{margin:.3rem 0 .6rem}
.meta{color:#555;font-size:.9rem}
.note{color:#444;font-size:.92rem}
.box{border:3px solid #b00020;background:#fdecee;padding:.6rem .9rem;margin:1rem 0;border-radius:4px}
.box h2{border:0;margin:0 0 .25rem;color:#8a0017}
.warn{border-color:#a66a00;background:#fff4de}
.warn h2{color:#7a4b00}
.ok{border:1px solid #2e7d32;background:#edf7ee;padding:.5rem .9rem;margin:1rem 0;border-radius:4px}
.big{font-size:2rem;font-weight:700;line-height:1.1}
table{border-collapse:collapse;width:100%;table-layout:fixed;margin:.4rem 0 1rem;font-size:.9rem}
th,td{border:1px solid #bbb;padding:.3rem .45rem;text-align:left;vertical-align:top;overflow-wrap:anywhere}
th{background:#f0f0f0}
td.n,th.n{text-align:right;width:5.5rem}
.brk{word-break:break-all}
.card{border:1px solid #d0d0d0;border-radius:6px;padding:.6em .8em;margin:.6em 0;break-inside:avoid}
.card-head{margin:0 0 .4em}
.card dl{display:grid;grid-template-columns:auto 1fr;gap:.2em .8em;margin:0}
.card dt{color:#555}.card dd{margin:0;min-width:0}
code,.id{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.88em}
@media print{body{padding:0;font-size:11pt}.box,.ok{break-inside:avoid}tr{break-inside:avoid}h2{break-after:avoid}}
"""


def pct(n, total):
    return "%.1f%%" % (100.0 * n / total) if total else "0%"


def table(head, rows, numeric=()):
    """head: list of column names; rows: lists of ready-made HTML; numeric: column indexes."""
    t = ["<table><thead><tr>"]
    for i, c in enumerate(head):
        t.append('<th class="n">%s</th>' % c if i in numeric else "<th>%s</th>" % c)
    t.append("</tr></thead><tbody>")
    for r in rows:
        t.append("<tr>")
        for i, c in enumerate(r):
            t.append('<td class="n">%s</td>' % c if i in numeric else "<td>%s</td>" % c)
        t.append("</tr>")
    t.append("</tbody></table>")
    return "".join(t)


def render(j, generated):
    p = []
    add = p.append
    visits = j["visits"]
    rng = "no events" if j["first_day"] is None else (
        j["first_day"] if j["first_day"] == j["last_day"] else "%s to %s" % (j["first_day"], j["last_day"]))
    add('<!doctype html><html lang="en"><head><meta charset="utf-8">')
    add('<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">')
    add('<meta name="viewport" content="width=device-width, initial-scale=1">')
    add("<title>Bot report: %s</title><style>%s</style></head><body><main>" % (h(j["site"]), CSS))
    add("<h1>Bot report for %s</h1>" % h(j["site"]))
    add('<p class="meta">Days covered (UTC): %s. Made on %s UTC. This page was made on your server and was sent nowhere.</p>'
        % (html.escape(rng), html.escape(generated)))

    kn = j["known"]
    if kn["acted"]:
        add('<div class="box"><h2>Warning: a known person would have been challenged or blocked</h2>')
        add("<p>These visits come from people you told the gateway about (through a known-person link). "
            "The policy asked to challenge or block them, so it would have got them wrong. "
            "Fix this before the policy is switched on. Each line names the visit, the person's label, what was asked "
            "and which rules fired.</p>")
        add(table(["Visit", "Known as", "Action", "Rules that fired"],
                  [['<span class="id">%s</span>' % x["visit"], h(x["known"]), html.escape(x["action"]),
                    "<br>".join(h(r) for r in x["fired"]) or "none"] for x in kn["acted"]]))
        add("</div>")
    elif kn["visits"] == 0:
        add('<div class="box warn"><h2>The false-positive alarm cannot work yet</h2>'
            "<p>No known-person visit was seen in this period. The alarm only works once someone you trust "
            "(you, a colleague, a test phone) has opened a known-person link, because that is how the gateway "
            "learns who is a real person. Open one on your own devices and the next report will say whether "
            "the policy would have bothered you.</p></div>")
    else:
        add('<div class="ok"><strong>No known person was challenged or blocked.</strong> '
            "%d visit%s from known people %s seen, and the policy would have let all of them through.</div>"
            % (kn["visits"], "" if kn["visits"] == 1 else "s", "was" if kn["visits"] == 1 else "were"))

    add("<h2>The week in short</h2>")
    if visits == 0:
        add("<p>No events were recorded in this period. Either nobody visited, or the gateway is not in front of the site.</p>")
    else:
        add('<p><span class="big">%d</span> visits, <span class="big">%d</span> page requests.</p>' % (visits, j["requests"]))
        add('<p class="note">A visit is one address, with one browser fingerprint and one browser name, in one day. '
            "A request is one page or file asked for. The address itself is not kept in this report.</p>")
    k = j["kinds"]
    labels = [("person", "Known people", "visits from people you told the gateway about"),
              ("crawler", "Crawlers", "search engines and other bots that proved who they are"),
              ("automated", "Automated", "scripts, scanners and tools that were not welcome or did not say who they are"),
              ("human", "Other visitors", "everyone else, assumed to be people")]
    add("<h3>Who visited</h3><p class=\"note\">Every visit is put in one group, the first that fits.</p>")
    add(table(["Group", "Visits", "Share", "What it means"],
              [[html.escape(n), str(k[key]), pct(k[key], visits), html.escape(m)] for key, n, m in labels],
              numeric=(1, 2)))
    a = j["actions"]
    add("<h3>What the policy would have done</h3>"
        '<p class="note">For each visit, the strongest thing the policy asked for. If the gateway runs in shadow mode, '
        "nothing was actually blocked: this is what would have happened.</p>")
    add(table(["Action", "Visits", "Share", "Requests", "What it means"],
              [["Block", str(a["block"]["visits"]), pct(a["block"]["visits"], visits), str(a["block"]["requests"]),
                "the visitor is turned away"],
               ["Challenge", str(a["challenge"]["visits"]), pct(a["challenge"]["visits"], visits), str(a["challenge"]["requests"]),
                "the visitor must pass a small check first"],
               ["Pass", str(a["pass"]["visits"]), pct(a["pass"]["visits"], visits), str(a["pass"]["requests"]),
                "the visitor is let through"]],
              numeric=(1, 2, 3)))

    add("<h2>Rules that fired</h2><p class=\"note\">A rule is one test in the policy. Visits is how many visits it fired on, "
        "requests how many page requests, and known is how many of those visits were from known people "
        "(that number should be 0).</p>")
    if j["rules"]:
        add(table(["Rule", "Visits", "Requests", "Known"],
                  [[h(r["id"]), str(r["visits"]), str(r["requests"]), str(r["known_visits"])] for r in j["rules"]],
                  numeric=(1, 2, 3)))
    else:
        add("<p>No rule fired.</p>")

    add("<h2>Automated clients</h2><p class=\"note\">The tools behind the automated visits, grouped by the name they give "
        "(user agent) and their TLS fingerprint (ja4). The top 10 by requests.</p>")
    if j["clients"]:
        add(table(["Client", "ja4", "Visits", "Requests", "Action"],
                  [['<span class="brk">%s</span>' % h(c["user_agent"]), '<span class="brk">%s</span>' % h(c["ja4"]),
                    str(c["visits"]), str(c["requests"]), html.escape(c["action"])] for c in j["clients"]],
                  numeric=(2, 3)))
    else:
        add("<p>No automated visits.</p>")

    add("<h2>What they asked for</h2><p class=\"note\">The paths most requested by automated visits. Paths like "
        "<code>/.env</code> or <code>/wp-login.php</code> mean someone is looking for weak spots.</p>")
    if j["paths"]:
        add(table(["Path", "Requests"],
                  [['<span class="brk">%s</span>' % h(x["path"]), str(x["requests"])] for x in j["paths"]], numeric=(1,)))
    else:
        add("<p>None.</p>")

    pr = j["probe"]
    add("<h2>Is the browser check running?</h2>")
    if pr["browser_visits"]:
        add("<p><strong>%d of %d</strong> (%s) browser visits ran the gateway's small browser script.</p>"
            % (pr["with_probe"], pr["browser_visits"], pct(pr["with_probe"], pr["browser_visits"])))
    else:
        add("<p>No visit loaded a page and its scripts the way a browser does, so there is nothing to measure.</p>")
    add('<p class="note">A browser visit is one that loaded a page and its scripts or styles, as browsers do and '
        "scanners almost never do. A low share means the script is not running: a strict Content-Security-Policy "
        "on the site, or pages kept in browsers' caches from before the gateway. The gateway then judges people "
        "with less information.</p>")

    hh = j["h2"]
    add("<h2>Does each browser keep one connection fingerprint?</h2>")
    if hh["visits"]:
        add("<p><strong>%d of %d</strong> browser visits kept one HTTP/2 fingerprint from start to end%s.</p>"
            % (hh["visits"] - hh["changed"], hh["visits"],
               "" if not hh["changed"] else "; %d changed, %d of them by switching between HTTP/2 and HTTP/1.1"
               % (hh["changed"], hh["mixed_h1"])))
    else:
        add("<p>No browser visit with two or more requests, so there is nothing to measure.</p>")
    add('<p class="note">For a planned change (tying a session to this fingerprint). If browsers keep it, the change '
        "is safe for people; each one that changes would have been asked to pass the check again.</p>")

    add("<h2>Examples</h2><p class=\"note\">Up to 20 visits the policy would have blocked or challenged, blocks first. "
        "Known people are never listed here: they are in the alarm above.</p>")
    if j["samples"]:
        # One card per visit: six columns do not fit a phone.
        for s in j["samples"]:
            add('<div class="card"><p class="card-head"><span class="id">%s</span> &middot; %s &middot; '
                '<strong>%s</strong> &middot; %d request%s</p><dl>'
                '<dt>Client</dt><dd class="brk">%s<br>%s</dd>'
                '<dt>Rules</dt><dd>%s</dd>'
                '<dt>Paths</dt><dd class="brk">%s</dd></dl></div>'
                % (s["visit"], html.escape(s["day"]), html.escape(s["action"]), s["requests"],
                   "" if s["requests"] == 1 else "s",
                   h(s["user_agent"]), h(s["ja4"]),
                   ", ".join(h(r) for r in s["fired"]) or "none",
                   "<br>".join(h(x) for x in s["paths"]) or "none"))
    else:
        add("<p>None.</p>")

    add("<h2>If something here is wrong</h2><p>Reply with the visit id (the 12 letters and digits in the tables above) "
        "and say who it really was. That is enough for us to look at it; no address is needed.</p>")
    add("</main></body></html>\n")
    return "".join(p)


# ---- writing ----

def write_all(files):
    """files: list of (path, text). All temp files are written first, then renamed."""
    tmps = []
    try:
        for path, text in files:
            tmp = "%s.tmp%d" % (path, os.getpid())
            tmps.append((tmp, path))
            with open(tmp, "w", encoding="utf-8", newline="\n") as f:
                f.write(text)
        for tmp, path in tmps:
            os.replace(tmp, path)
        tmps = []
    finally:
        for tmp, _ in tmps:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def main(argv):
    ap = argparse.ArgumentParser(description="The weekly report.")
    ap.add_argument("--events", required=True, help="JSON lines file, or - for stdin")
    ap.add_argument("--site", default="")
    ap.add_argument("--html", required=True)
    ap.add_argument("--json")
    args = ap.parse_args(argv)
    try:
        if args.events == "-":
            visits, requests, acts, rules = read_events(sys.stdin.buffer, "stdin")
        else:
            try:
                f = open(args.events, "rb")
            except OSError as e:
                raise Bad("%s: cannot read: %s" % (args.events, e))
            with f:
                visits, requests, acts, rules = read_events(f, args.events)
    except Bad as e:
        print("report.py: %s" % e, file=sys.stderr)
        return 2
    j = summarize(visits, requests, acts, rules, args.site)
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M")
    files = [(args.html, render(j, now))]
    if args.json:
        jj = dict(j)
        jj["generated"] = now + " UTC"
        files.append((args.json, json.dumps(jj, indent=1, ensure_ascii=True) + "\n"))
    try:
        write_all(files)
    except OSError as e:
        print("report.py: cannot write: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
