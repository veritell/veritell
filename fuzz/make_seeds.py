#!/usr/bin/env python3
"""Seeds and dictionaries for the fuzz targets in this directory.

    python3 -I fuzz/make_seeds.py        (from the repository root)

Writes fuzz/seeds/<target>/* and fuzz/dicts/<target>.dict. Seeds are valid
inputs, so a fuzzer starts past the first rejection: published test vectors,
the probe's captured reports, the lab's synthetic behaviour sessions, real
User-Agent strings, SYNs built here. Standard library only.
"""
import base64
import json
import os
import re
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "fuzz")
SEP = b"\xff"


def write(target, name, data):
    d = os.path.join(OUT, "seeds", target)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "wb") as f:
        f.write(data)


def write_dict(target, words):
    os.makedirs(os.path.join(OUT, "dicts"), exist_ok=True)
    with open(os.path.join(OUT, "dicts", target + ".dict"), "w") as f:
        for w in sorted(set(words)):
            esc = "".join(c if 32 <= ord(c) < 127 and c not in '"\\' else "\\x%02x" % ord(c) for c in w)
            f.write('"%s"\n' % esc)


def const(path, name):
    """A Rust string constant from a test file, so vectors are copied, not retyped."""
    text = open(os.path.join(ROOT, path)).read()
    m = re.search(r"const " + name + r': &str = "((?:[^"\\]|\\.)*)";', text, re.S)
    if not m:
        sys.exit("constant %s not found in %s" % (name, path))
    return m.group(1).encode().decode("unicode_escape")


# ---- syn_parse -------------------------------------------------------------
def v4(ttl, df, ident, tcp, extra=0, tos=0):
    total = 20 + len(tcp) + extra
    hdr = bytes([0x45, tos]) + struct.pack(">HH", total, ident)
    hdr += bytes([0x40 if df else 0, 0, ttl, 6, 0, 0]) + bytes([203, 0, 113, 9, 198, 51, 100, 1])
    return hdr + tcp


def tcp(window, opts, flags=0x02):
    o = bytes(opts)
    while len(o) % 4:
        o += b"\x00"
    doff = (20 + len(o)) // 4
    return bytes([0xC3, 0x50, 0x01, 0xBB, 0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0, doff << 4, flags]) + struct.pack(">H", window) + b"\x00\x00\x00\x00" + o


LINUX = [2, 4, 0x05, 0xB4, 4, 2, 8, 10, 0, 1, 2, 3, 0, 0, 0, 0, 1, 3, 3, 7]
WINDOWS = [2, 4, 0x05, 0xB4, 1, 3, 3, 8, 1, 1, 4, 2]
write("syn_parse", "linux", v4(57, True, 0x1C46, tcp(64240, LINUX)))
write("syn_parse", "windows", v4(113, True, 0x7A01, tcp(64240, WINDOWS)))
write("syn_parse", "fast_open", v4(57, True, 0x1C46, tcp(64240, LINUX), extra=100))
write("syn_parse", "ecn", v4(64, True, 1, tcp(1024, [], flags=0xC2), tos=2))
t6 = tcp(65535, [2, 4, 0x05, 0xA0, 1, 3, 3, 6, 1, 1, 8, 10, 0, 0, 0, 9, 0, 0, 0, 0, 4, 2])
v6 = bytes([0x60, 0x0A, 0xBC, 0xDE]) + struct.pack(">H", len(t6)) + bytes([6, 64]) + bytes(15) + b"\x07" + bytes(16) + t6
write("syn_parse", "ipv6", v6)
# A timestamp clock large enough that the target checks it is not kept.
LINUX_TS = [2, 4, 0x05, 0xB4, 4, 2, 8, 10, 0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0, 1, 3, 3, 7]
write("syn_parse", "linux_clock", v4(57, True, 0x1C46, tcp(64240, LINUX_TS)))

# ---- wba_request -----------------------------------------------------------
WBA = "crates/veritell-wba/tests/acceptance.rs"
a21i, a21s = const(WBA, "A21_INPUT"), const(WBA, "A21_SIG")
a22a, a22i, a22s = const(WBA, "A22_AGENT"), const(WBA, "A22_INPUT"), const(WBA, "A22_SIG")


def req(*fields):
    return SEP.join(f.encode() for f in fields)


write("wba_request", "a21", b"\x02" + req("GET", "example.com", "/", "", a21i, a21s))
write("wba_request", "a22_agent_string", b"\x02" + req("GET", "example.com", "/", "", a22i, a22s, a22a))
write("wba_request", "a22_agent_dictionary", b"\x02" + req("GET", "example.com", "/", "", a22i, a22s, "sig2=" + a22a))
bound = 'sig1=("@authority" "@method" "@path" "@query");created=1735689600;expires=1735693200;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";nonce="n";tag="web-bot-auth"'
write("wba_request", "bound_post", b"\x03" + req("POST", "example.com", "/cart", "a=1", bound, "sig1=:" + "A" * 86 + "==:"))
# Signed mode (first byte 5..7 mod 8): the target signs the request itself
# with the key that bits 6 and 7 pick (0: "listed", pinned to the agent
# below; 1 and 3: "plain"; 2: "dated", valid 1000 to 5000 s after 1735689600), writing `%k` as that key's id. `now` is 1735689600 + 37 *
# the first byte, so each seed's window is set around its own `now`.
def window(pick):
    now = 1735689600 + 37 * pick
    return ";created=%d;expires=%d" % (now - 10, now + 290)


AGENT = '"https://signature-agent.test"'
signed = {
    "signed_plain": (0x45, ("GET", "example.com", "/", "", 'sig1=("@authority" "@method" "@path")' + window(0x45) + ';keyid="%k";tag="web-bot-auth"', "")),
    "signed_post": (0x46, ("POST", "shop.example", "/cart/add", "id=7", 'sig1=("@authority" "@method" "@path" "@query")' + window(0x46) + ';keyid="%k";nonce="n1";tag="web-bot-auth"', "")),
    "signed_agent": (0x05, ("GET", "example.com", "/", "", 'sig1=("@authority" "signature-agent")' + window(0x05) + ';keyid="%k";tag="web-bot-auth"', "", AGENT)),
    "signed_agent_keyed": (0x06, ("GET", "example.com", "/", "", 'sig2=("@authority" "signature-agent";key="sig2")' + window(0x06) + ';keyid="%k";tag="web-bot-auth"', "", "sig2=" + AGENT)),
    "signed_two_members": (0x47, ("GET", "example.com", "/a", "", 'sig1=("@authority")' + window(0x47) + ';keyid="%k";tag="web-bot-auth"', "sig1=%s, sig0=:AAAA:", "", 'sig0=("@method");created=1;expires=2;keyid="x"')),
    "signed_extra_header": (0x07, ("GET", "example.com", "/", "", 'sig1=("@authority" "signature-agent" "x-forwarded-host")' + window(0x07) + ';keyid="%k";tag="web-bot-auth"', "", AGENT, "", "X-Forwarded-Host", "victim.example")),
}
COMPONENTS = " ".join('"x-h%d"' % i for i in range(17))
signed.update({
    "signed_dated": (0x85, ("GET", "example.com", "/", "", 'sig1=("@authority")' + window(0x85) + ';keyid="%k";tag="web-bot-auth"', "")),
    "signed_dated_expired": (0x8D, ("GET", "example.com", "/", "", 'sig1=("@authority")' + window(0x8D) + ';keyid="%k";tag="web-bot-auth"', "")),
    "signed_17_components": (0x45, ("GET", "example.com", "/", "", 'sig1=("@authority" ' + COMPONENTS + ")" + window(0x45) + ';keyid="%k";tag="web-bot-auth"', "")),
    "signed_oversized": (0x45, ("GET", "example.com", "/", "", 'sig1=("@authority")' + window(0x45) + ';keyid="%k";nonce="' + "n" * 4100 + '";tag="web-bot-auth"', "")),
})
for name, (pick, fields) in signed.items():
    write("wba_request", name, bytes([pick]) + req(*fields))
# Signatures that cannot verify under any key: S at or above the group
# order, and R a small-order point.
a21_sig = base64.b64decode(a21s.split(":")[1])
for name, sig in {"sig_s_too_big": a21_sig[:32] + b"\xff" * 32, "sig_r_small_order": b"\x01" + bytes(31) + a21_sig[32:]}.items():
    write("wba_request", name, b"\x02" + req("GET", "example.com", "/", "", a21i, "sig1=:" + base64.b64encode(sig).decode() + ":"))
jwks = json.dumps({"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs", "use": "sig"}]})
write("wba_request", "directory", b"\x00" + jwks.encode())
agents = json.dumps({"agents": [{"name": "a", "keys": [{"kty": "OKP", "crv": "Ed25519", "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}]}, {"name": "b", "signature_agent": "https://agent.test/keys"}]})
write("wba_request", "agents", b"\x01" + agents.encode())
X1 = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
X2 = base64.urlsafe_b64encode(bytes([0x11] * 32)).rstrip(b"=").decode()
okp = lambda x, **kw: dict({"kty": "OKP", "crv": "Ed25519", "x": x}, **kw)
for name, doc in {
    "agents_valid": {"agents": [{"name": "a", "signature_agent": "https://agent.test", "keys": [okp(X1)]}, {"name": "b", "keys": [okp(X2, nbf=1735690000, exp=1735699000)]}]},
    "agents_shared_key": {"agents": [{"name": "a", "keys": [okp(X1)]}, {"name": "b", "keys": [okp(X1)]}]},
    "agents_empty_name": {"agents": [{"name": "", "keys": [okp(X1)]}]},
}.items():
    write("wba_request", name, b"\x01" + json.dumps(doc).encode())
write("wba_request", "directory_65_keys", b"\x00" + json.dumps({"keys": [okp(base64.urlsafe_b64encode(bytes([i] * 32)).rstrip(b"=").decode()) for i in range(65)]}).encode())
write("wba_request", "directory_not_object", b"\x00" + b'{"keys":[1]}')
write_dict("wba_request", ["sig1=", "sig2=", "(", ")", '"@authority"', '"@method"', '"@path"', '"@query"', '"@target-uri"',
                           '"signature-agent"', ';key="sig1"', ";created=", ";expires=", ';keyid="', ';alg="ed25519"', ';nonce="',
                           ';tag="web-bot-auth"', '"%k"', "%s", ":", "=:", '"https://', "\xff", '"kty"', '"OKP"', '"crv"', '"Ed25519"', '"x"', '"keys"',
                           '"agents"', '"name"', '"signature_agent"', '"not_before"', '"not_after"'])

# ---- reports ---------------------------------------------------------------
report_keys = set()
for name in ("chromium", "firefox", "safari"):
    raw = open(os.path.join(ROOT, "probe", "test", "captured-%s.json" % name), "rb").read()
    write("reports", "probe_" + name, b"\x00" + raw)
    report_keys.update(re.findall(r'"([A-Za-z0-9_]+)"\s*:', raw.decode()))
for i, line in enumerate(open(os.path.join(ROOT, "lab", "recordings", "human.jsonl"))):
    summary = json.loads(line)["summary"]
    summary["nonce"] = "recording"
    write("reports", "behavior_%02d" % i, b"\x01" + json.dumps(summary, separators=(",", ":")).encode())
    report_keys.update(summary.keys())
# One summary per behaviour rule, at the default parameters' thresholds,
# so every rule fires from the start and mutations explore its edges.
quiet = {"v": 1, "trigger": "submit", "dur_ms": 9000, "hidden_ms": 0, "moves": 0, "strokes": 0, "straight": 0, "steady": 0,
         "clicks": 0, "sized": 0, "centered": 0, "teleport": 0, "touches": 0, "keys": 0, "pastes": 0, "scrolls": 0, "submits": 0,
         "untrusted": 0, "actions": 0, "key_gap_cv": None, "gap_cv": None, "gap_med_ms": None, "nonce": "rule"}
rules = {
    "no_input": {"submits": 1},
    "untrusted_submit": {"submits": 1, "untrusted": 1, "moves": 3},
    "pointer_scripted": {"moves": 80, "strokes": 10, "straight": 10, "steady": 10},
    "click_centered": {"moves": 20, "clicks": 3, "sized": 3, "centered": 3},
    "click_jumped": {"moves": 2, "clicks": 3, "teleport": 3},
    "keys_metronomic": {"keys": 10, "key_gap_cv": 10},
    "cadence_fixed": {"moves": 5, "actions": 6, "gap_cv": 10},
    "agent_rhythm": {"actions": 5, "gap_med_ms": 3000, "clicks": 2, "teleport": 2, "moves": 2},
}
for name, fields in rules.items():
    write("reports", "behavior_rule_" + name, b"\x01" + json.dumps(dict(quiet, **fields), separators=(",", ":")).encode())

# One probe report per automation sign, from the captured Chromium report.
chromium = json.loads(open(os.path.join(ROOT, "probe", "test", "captured-chromium.json")).read())
def variant(change):
    r = json.loads(json.dumps(chromium))
    change(r)
    return json.dumps(r, separators=(",", ":")).encode()
signs = {
    "webdriver": lambda r: r["main"].update(webdriver=True),
    "globals": lambda r: r["page"].update(globals=["cdc_adoQpoasnfa76pfcZLmcfl_Array", "__playwright__binding__"]),
    "tamper": lambda r: r["main"].update(tamper=[{"target": "Navigator.prototype.webdriver", "kinds": ["getter"]}, {"target": "Function.prototype.toString", "kinds": ["source"]}]),
    "realms_differ": lambda r: (r["iframe"].update(webdriver=True, hc=2), r["worker"].update(ua="HeadlessChrome")),
    "uad_mismatch": lambda r: r["main"]["uad"].update(platform="Windows", mobile=True),
    "software_gpu": lambda r: r["page"].update(webgl_renderer="ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero)), SwiftShader driver)"),
    "zero_window": lambda r: r["page"].update(window=[0, 0, 0, 0], screen=[0, 0, 0, 0]),
    "no_languages": lambda r: [x.update(languages=[]) for x in (r["main"], r["iframe"], r["worker"])],
    "headless_permissions": lambda r: r["page"].update(notif_permission="denied", perm_query_notif="prompt"),
    "engine_gecko_math": lambda r: r["main"]["engine"].update(math="0,0,0", err_msg="x is null", eval_len=37),
}
for name, change in signs.items():
    # 0x04 claims a Gecko engine on Windows: the report is Blink on macOS.
    for pick in (0x00, 0x04 | (1 << 3)):
        write("reports", "probe_%s_%02x" % (name, pick), bytes([pick]) + variant(change))
write_dict("reports", ['"%s":' % k for k in report_keys] + ["true", "false", "null", "[]", "{}", '"', "0", "-1", "1e308", "4294967296"])

# ---- ua_check --------------------------------------------------------------
UA = "crates/veritell-ua/tests/acceptance.rs"
chrome, googlebot = const(UA, "CHROME_WIN"), const(UA, "GOOGLEBOT")
cja4, curl_ja4 = const(UA, "CHROMIUM_JA4"), const(UA, "CURL_JA4")
ch2, curl_h2 = const(UA, "CHROMIUM_H2"), const(UA, "CURL_H2")
chrome_headers = "host\nsec-ch-ua\nsec-ch-ua-mobile\nsec-ch-ua-platform\nupgrade-insecure-requests\nuser-agent\naccept\nsec-fetch-site\nsec-fetch-mode\nsec-fetch-user\nsec-fetch-dest\naccept-encoding\naccept-language"
cases = {
    "chrome": (chrome, cja4, ch2, chrome_headers),
    "chrome_curl_tls": (chrome, curl_ja4, curl_h2, "host\nuser-agent\naccept"),
    "googlebot": (googlebot, curl_ja4, "", "host\nuser-agent\naccept"),
    "firefox": ("Mozilla/5.0 (X11; Linux x86_64; rv:159.0) Gecko/20100101 Firefox/159.0", cja4, ch2, chrome_headers),
    "safari": ("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1", cja4, "", chrome_headers),
    "headless": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/149.0.0.0 Safari/537.36", cja4, ch2, chrome_headers),
    "curl": ("curl/8.7.1", curl_ja4, "", "host\nuser-agent\naccept"),
    "ios_system_fetcher": ("NetworkingExtension/8620.1.16.10.11 Network/4277.0.1 iOS/18.0", curl_ja4, "", "host\nuser-agent"),
    "made_up_bot": ("ExampleBot/1.0 (+https://example.test/bot)", curl_ja4, "", "host\nuser-agent"),
}
for name, fields in cases.items():
    write("ua_check", name, SEP.join(f.encode() for f in fields))
write_dict("ua_check", ["Mozilla/5.0 (", "Windows NT 10.0", "Macintosh; Intel Mac OS X 10_15_7", "X11; Linux x86_64", "Android 14",
                        "iPhone; CPU iPhone OS", "AppleWebKit/537.36", "(KHTML, like Gecko)", "Chrome/", "Firefox/", "Version/",
                        "Safari/", "Edg/", "HeadlessChrome/", "Mobile", "Googlebot/2.1", "bingbot", "GPTBot", "bot/", "crawler/",
                        "spider/", "curl/", "python-requests/", "Go-http-client/", "t13d", "t12d", "h2_", "h1_", "|", ";", ":",
                        "m,a,s,p", "m,s,a,p", "sec-ch-ua", "sec-fetch-", "accept-language", "\xff", "\n"])

# ---- tokens ----------------------------------------------------------------
# A session token and a solved challenge under the target's fixed key
# (Keys::from_secret([7; 32])), bound to Binding([pick; 16]), made with
# veritell-token's issue() and pow::issue_challenge()/solve() at
# now = 1_800_000_000 - 60. Regenerate them that way if the token format
# changes.
TOKEN = "01d1b04645bb2cc4c417eb7672d1373d23000000006b49d1c4000000006b49dfd40000003200000000000000000000000000000000.0bf51523c54d99e6aeee58f65ce9265803ae3e4322aafe53c91b10941a1bfe8e"
SOLVED = "020ef15c95240dd6dbe4710c3bcadec644000000006b49d23c0801010101010101010101010101010101.c24ae228d1daeb9eba0899fa5826ef218f29cfb87dd219aeb7e0868053ee2852:254"
CHALLENGE = "02d0f13da2791b0143d655b2acdbabcb7b000000006b49d23c0e02020202020202020202020202020202.c75df3a9b770114f7d9339258a308712f7f74387edcaf1f16e57b5fd37fd0284"
PP = "crates/veritell-privacypass/tests/acceptance.rs"
token1 = bytes.fromhex(const(PP, "TOKEN_1"))
write("tokens", "session", b"\x00" + TOKEN.encode())
write("tokens", "solved", b"\x01" + SOLVED.encode())
write("tokens", "issued", b"\x02" + CHALLENGE.encode())
write("tokens", "return_to", b"\x02" + b"/products/42?a=1&b=2")
write("tokens", "authorization", b"\x03" + b"PrivateToken token=" + base64.urlsafe_b64encode(token1))
write("tokens", "authorization_two", b"\x03" + b'PrivateToken token="' + base64.urlsafe_b64encode(token1).rstrip(b"=") + b'", PrivateToken token=AAAA')
write("tokens", "raw_token", b"\x04" + token1)
# Mode 5: binding, clock offset, ttl, budget, difficulty, counter, then
# (position, byte) edits; 0xFF truncates, 0xFE appends.
for name, (ttl, diff, edits) in {"mint": (300, 8, b""), "mint_flip": (300, 8, b"\x05a"), "mint_expired": (0, 24, b"\xff\x10"),
                                  "mint_append": (60, 12, b"\xfe0")}.items():
    write("tokens", name, b"\x05" + bytes(range(16)) + struct.pack(">IHHBI", 1000, ttl, 5, diff, 254) + edits)
PKI = bytes.fromhex(const(PP, "PKI"))
for name, (issuer, spki, origin) in {
    "issuer": ("issuer.example", PKI, "origin.example,shop.example"),
    "issuer_port": ("issuer.example:8443", PKI, ""),
    "issuer_short_key": ("issuer.example", PKI[:-20], ""),
    "issuer_bad_port": ("issuer.example:0", PKI, "a,,b"),
}.items():
    write("tokens", name, b"\x06" + issuer.encode() + SEP + spki + SEP + origin.encode())
write_dict("tokens", ["PrivateToken", "token=", ",", '"', ".", ":", "0002", "/", "//", "?", "#", "%2F", "\\"])

# ---- directory_keys --------------------------------------------------------
write("directory_keys", "jwks", b"\x00" + jwks.encode())
write("directory_keys", "jwks_two", b"\x00" + json.dumps({"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs", "nbf": 1, "exp": 2000000000}, {"kty": "RSA", "n": "x", "e": "AQAB"}]}).encode())
for i, u in enumerate(["https://agent.example/.well-known/http-message-signatures-directory", "https://[2001:db8::1]:8443/keys", "https://127.0.0.1/keys", "http://agent.example/k"]):
    write("directory_keys", "url_%d" % i, b"\x01" + u.encode())
write("directory_keys", "jwks_65", b"\x00" + json.dumps({"keys": [okp(base64.urlsafe_b64encode(bytes([i] * 32)).rstrip(b"=").decode()) for i in range(65)]}).encode())
write("directory_keys", "jwks_rsa_only", b"\x00" + json.dumps({"keys": [{"kty": "RSA", "n": "x", "e": "AQAB"}]}).encode())
write("directory_keys", "jwks_bad_x", b"\x00" + json.dumps({"keys": [okp("short")]}).encode())
for i, c in enumerate(["max-age", "Max-Age=0600, NO-CACHE", "max-age=600,", "max-age=600", "public, max-age=86400, must-revalidate", "no-store", "max-age=99999999999999999999"]):
    write("directory_keys", "cache_%d" % i, b"\x02" + c.encode())
for i, ip in enumerate([b"::ffff:0:10.0.0.1", b"64:ff9b::10.0.0.1", b"::10.0.0.1", b"2002:a00:1::1", b"2606:4700::1111", b"1.1.1.1", b"64:ff9b:1::1", bytes([10, 0, 0, 1]), bytes([169, 254, 169, 254]), bytes([203, 0, 113, 5]), bytes(15) + b"\x01", bytes([0xFE, 0x80]) + bytes(14)]):
    write("directory_keys", "ip_%d" % i, b"\x03" + ip)
write_dict("directory_keys", ['"keys"', '"kty"', '"OKP"', '"crv"', '"Ed25519"', '"x"', '"nbf"', '"exp"', '"use"', '"sig"', "https://",
                              "http://", "[", "]", ":443", "max-age=", "no-store", "no-cache", "s-maxage=", ","])

print("seeds written:", sum(len(f) for _, _, f in os.walk(os.path.join(OUT, "seeds"))))
