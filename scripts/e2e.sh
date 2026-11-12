#!/usr/bin/env bash
# End-to-end checks E1-E35. Needs: a release build, curl with
# HTTP/2, python3, and a certificate pair (default: certs/, which is git-ignored).
set -u
cd "$(dirname "$0")/.."
BIN=target/release/veritell
CERT=${CERT:-certs/cert.pem}
KEY=${KEY:-certs/key.pem}
PORT=${PORT:-8443}
ORIGIN_PORT=${ORIGIN_PORT:-9099}
ADMIN_PORT=${ADMIN_PORT:-9098}
CH_PORT=${CH_PORT:-9097}
URL="https://localhost:$PORT"
WORK=$(mktemp -d)
CHROME_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
GOOGLEBOT_UA="Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
export VERITELL_SECRET="e2e-test-secret-0123456789abcdef0123456789"
fails=0
PIDS=()

# SIGINT is Pingora's fast shutdown; SIGTERM would wait out a graceful period.
cleanup() { for p in "${PIDS[@]:-}"; do kill -INT "$p" 2>/dev/null; done; sleep 0.5; for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null; done; }
trap cleanup EXIT

check() { # name, haystack, needle
  if printf '%s' "$2" | grep -q -- "$3"; then echo "PASS  $1"; else echo "FAIL  $1  (wanted: $3)"; fails=$((fails+1)); fi
}
refute() {
  if printf '%s' "$2" | grep -q -- "$3"; then echo "FAIL  $1  (unwanted: $3)"; fails=$((fails+1)); else echo "PASS  $1"; fi
}
skip() { # name, why: a check this machine can't make
  echo "SKIP  $1  ($2)"; skips=$((skips+1))
}
skips=0
# The built-in truth table knows one curl TLS stack: macOS's, built on
# LibreSSL. Checks that need curl recognised by name run only with that curl.
if curl --version | head -1 | grep -q LibreSSL; then CURL_KNOWN=1; else CURL_KNOWN=0; fi
CURL_NOT_KNOWN="this curl isn't the LibreSSL build the truth table lists: $(curl --version | head -1 | grep -oE '(OpenSSL|LibreSSL|BoringSSL|GnuTLS|wolfSSL|mbedTLS|Schannel|SecureTransport)/[^ ]+' | head -1)"
wait_port() { for _ in $(seq 1 50); do nc -z 127.0.0.1 "$1" 2>/dev/null && return 0; sleep 0.1; done; echo "port $1 never opened"; exit 1; }
stop_proxy() { kill -INT "$PROXY" 2>/dev/null; for _ in $(seq 1 30); do nc -z 127.0.0.1 "$PORT" 2>/dev/null || return 0; sleep 0.1; done; kill -9 "$PROXY" 2>/dev/null; sleep 0.2; }

# A throwaway self-signed certificate when none is supplied.
if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
  CERT="$WORK/cert.pem"; KEY="$WORK/key.pem"
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=localhost" \
    -keyout "$KEY" -out "$CERT" >/dev/null 2>&1 || { echo "could not create a test certificate"; exit 1; }
fi
SIGN=target/debug/examples/sign
SEAL=target/debug/examples/seal_report
BUNDLE=target/debug/examples/make_bundle
cargo build -q -p veritell-wba --example sign -p veritell-probe-build --example seal_report \
  -p veritell-feed --example make_bundle || { echo "could not build the test helpers"; exit 1; }
FEED_SEED=$(printf '07%.0s' $(seq 1 32)); WRONG_SEED=$(printf '09%.0s' $(seq 1 32))
FEED_KEY=$("$BUNDLE" pubkey "$FEED_SEED")
FEED="$WORK/feed.json"

# ---- shadow mode, no upstream: the gateway answers with its own report ----
python3 scripts/mock_clickhouse.py "$CH_PORT" "$WORK/clickhouse.txt" & PIDS+=("$!"); wait_port "$CH_PORT"
"$BIN" --cert "$CERT" --key "$KEY" --listen "127.0.0.1:$PORT" --wba-agents scripts/e2e_agents.json \
  --admin "127.0.0.1:$ADMIN_PORT" --clickhouse-url "http://127.0.0.1:$CH_PORT" \
  --feed "$FEED" --feed-key "$FEED_KEY" --probe-build-rotate 1 --probe-build-ttl 6 >"$WORK/shadow.log" 2>"$WORK/shadow.err" &
PROXY=$!; PIDS+=("$PROXY"); wait_port "$PORT"

r=$(curl -sk --http2 "$URL/")
check "E1 curl default UA: declared tool"        "$r" '"id": "ua_declared_tool"'
check "E1 class automated"                       "$r" '"class": "automated"'
check "E1 passes in shadow mode (report served)" "$r" '"score": 39'

r=$(curl -sk --http2 -A "$CHROME_UA" "$URL/")
if [ "$CURL_KNOWN" = 1 ]; then
  check "E2 fake Chrome UA: known tool TLS"      "$r" '"id": "tls_known_tool"'
else
  skip "E2 fake Chrome UA: known tool TLS"       "$CURL_NOT_KNOWN"
fi
check "E2 missing client hints"                  "$r" '"id": "missing_client_hints"'
check "E2 HTTP/2 mismatch"                       "$r" '"id": "h2_pseudo_order_mismatch"'
# A client claiming Safari is checked against what WebKit was seen to send.
r=$(curl -sk --http2 -A "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.2 Mobile/15E148 Safari/604.1" "$URL/")
check "E2 fake Safari UA: HTTP/2 settings are not WebKit's" "$r" '"id": "h2_settings_mismatch"'
check "E2 fake Safari UA: class automated"       "$r" '"class": "automated"'

r=$(curl -sk --http2 -A "$GOOGLEBOT_UA" "$URL/")
check "E3 spoofed Googlebot"                     "$r" '"id": "crawler_spoofed"'
check "E3 class malicious"                       "$r" '"class": "malicious"'
check "E1-3 decisions are logged as JSON"        "$(cat "$WORK/shadow.log")" '"outcome":"passed"'

# ---- Phase 1 and 2: probe, served as per-build scripts with sealed reports ----
nonce_of() { sed -n 's/.*"nonce":"\([A-Za-z0-9_-]*\)".*/\1/p' | head -1; }
build_of() { sed -n 's/.*{"id":"\([A-Za-z0-9_-]*\)".*/\1/p' | head -1; }
plain() { sed -e "s/__NONCE__/$1/" -e "s|__UA__|$2|" scripts/e2e_report.json; }
# sealed <nonce> <ua in the report> <build id> [nonce to seal under]
sealed() { plain "$1" "$2" | "$SEAL" probe/probe.js "$VERITELL_SECRET" "$3" "${4:-$1}"; }
post_report() { printf '%s' "$2" | curl -sk --http2 -o /dev/null -w '%{http_code}' -A "$1" -H 'content-type: application/json' --data-binary @- "$URL/__veritell/probe"; }
# fetch_probe <user agent> <file>: sets $nonce and $build from a fresh script.
fetch_probe() { curl -sk --http2 -A "$1" -o "$2" "$URL/__veritell/probe.js"; nonce=$(nonce_of < "$2"); build=$(build_of < "$2"); }

hdrs=$(curl -sk --http2 -D - -o /dev/null -A "probe-client/1" "$URL/__veritell/probe.js")
check "E10 probe script served as JavaScript"    "$hdrs" 'content-type: text/javascript'
check "E10 not cacheable"                        "$hdrs" 'cache-control: no-store'
fetch_probe "probe-client/1" "$WORK/probe1.js"; nonce1=$nonce; build1=$build
check "E10 carries a nonce"                      "${#nonce1}" '^96$'
refute "E10 config token was replaced"           "$(cat "$WORK/probe1.js")" '"__VERITELL_CONFIG__"'
refute "E18 build token was replaced"            "$(cat "$WORK/probe1.js")" '"__VERITELL_BUILD__"'
refute "E18 no template identifiers are left"    "$(cat "$WORK/probe1.js")" '\$\$'
refute "E18 comments are stripped"               "$(cat "$WORK/probe1.js")" 'Veritell client probe'
check "E10 POST on the script path is refused"   "$(curl -sk --http2 -o /dev/null -w '%{http_code}' -X POST "$URL/__veritell/probe.js")" '405'
sleep 1.6
fetch_probe "probe-client/1" "$WORK/probe2.js"; nonce2=$nonce; build2=$build
refute "E10 each fetch gets a new nonce"         "$nonce2" "^$nonce1\$"
refute "E18 a later fetch is a different build"  "$build2" "^$build1\$"
refute "E18 and a different script"              "$(cmp -s "$WORK/probe1.js" "$WORK/probe2.js" && echo same)" 'same'

# E11: reports that must be rejected, all sent by the client "reject-client/1".
fetch_probe "someone-else/1" "$WORK/other.js"
check "E11 nonce issued to another client"       "$(post_report "reject-client/1" "$(sealed "$nonce" x "$build")")" '403'
fetch_probe "reject-client/1" "$WORK/reject.js"; rbuild=$build; rnonce=$nonce
forged=$(printf 'A%.0s' $(seq 1 96))
check "E11 forged nonce"                         "$(post_report "reject-client/1" "$(sealed "$forged" x "$rbuild")")" '403'
check "E11 garbage body"                         "$(post_report "reject-client/1" 'not json')" '403'
check "E11 oversized body"                       "$(head -c 70000 /dev/zero | tr '\0' 'a' | curl -sk --http2 -o /dev/null -w '%{http_code}' -A "reject-client/1" --data-binary @- "$URL/__veritell/probe")" '413'
check "E11 GET on the report path is refused"    "$(curl -sk --http2 -o /dev/null -w '%{http_code}' "$URL/__veritell/probe")" '405'
# E19: the seal itself.
check "E19 plain report with a valid nonce"      "$(post_report "reject-client/1" "$(plain "$rnonce" x)")" '403'
check "E19 sealed under a different nonce"       "$(post_report "reject-client/1" "$(sealed "$rnonce" x "$rbuild" "$forged" | sed "s/\"n\":\"$forged\"/\"n\":\"$rnonce\"/")")" '403'
# Change the build id's first character to one it isn't (ids are random
# base64url: a fixed "-" would leave one in 64 unchanged).
nowhere=-; [ "${rbuild:0:1}" = - ] && nowhere=_
check "E19 build id from nowhere"                "$(post_report "reject-client/1" "$(sealed "$rnonce" x "$rbuild" | sed "s/\"b\":\"./\"b\":\"$nowhere/")")" '403'
log=$(cat "$WORK/shadow.log")
check "E11 logged: other client"                 "$log" '"outcome":"probe_nonce_other_client"'
check "E11 logged: invalid nonce"                "$log" '"outcome":"probe_nonce_invalid"'
check "E11 logged: malformed"                    "$log" '"outcome":"probe_malformed"'
check "E19 logged: seal invalid"                 "$log" '"outcome":"probe_seal_invalid"'
check "E19 logged: unknown build"                "$log" '"outcome":"probe_build_unknown"'
refute "E11 rejected reports leave no state"     "$(curl -sk --http2 -A "reject-client/1" "$URL/")" '"layer": "client"'

# E12: an accepted report whose User-Agent differs from the HTTP one.
fetch_probe "probe-client/1" "$WORK/probe3.js"; nonce3=$nonce; build3=$build
refute "E12 no client detections before the report" "$(curl -sk --http2 -A "probe-client/1" "$URL/")" '"layer": "client"'
body=$(sealed "$nonce3" "a-different-agent" "$build3")
refute "E19 the report text is not on the wire"  "$body" 'a-different-agent'
check "E12 report accepted (204)"                "$(post_report "probe-client/1" "$body")" '204'
check "E12 the same nonce cannot be used twice"  "$(post_report "probe-client/1" "$body")" '403'
check "E12 logged: reused"                       "$(cat "$WORK/shadow.log")" '"outcome":"probe_nonce_reused"'
r=$(curl -sk --http2 -A "probe-client/1" "$URL/")
check "E12 later requests carry the finding"     "$r" '"id": "http_ua_mismatch"'
check "E12 class automated"                      "$r" '"class": "automated"'
fetch_probe "probe-client/1" "$WORK/probe4.js"
check "E12 a consistent report is clean"         "$(post_report "probe-client/1" "$(sealed "$nonce" "probe-client/1" "$build")")" '204'
check "E12 a clean report does not erase it"     "$(curl -sk --http2 -A "probe-client/1" "$URL/")" '"id": "http_ua_mismatch"'
refute "E12 other clients are unaffected"        "$(curl -sk --http2 -A "bystander/1" "$URL/")" 'http_ua_mismatch'

# E19: a build stops being accepted after its lifetime (6 s in this run).
fetch_probe "late-client/1" "$WORK/late.js"; late=$(sealed "$nonce" "late-client/1" "$build")
sleep 7
check "E19 report for an expired build"          "$(post_report "late-client/1" "$late")" '403'
check "E19 logged: build expired"                "$(cat "$WORK/shadow.log")" '"outcome":"probe_build_expired"'

# ---- Phase 2: signed feed, swapped while running ----
tool_name() { curl -sk --http2 -A "$CHROME_UA" "$URL/" | grep -o 'belongs to [^,]*' | head -1; }
# This curl's own TLS cipher hash, as the gateway sees it. The test bundles
# give the renamed curl entry that hash, so the feed checks below work with
# any curl, not only the one the built-in table lists.
CURL_CIPHER=$(curl -sk --http2 -A "$CHROME_UA" "$URL/" | grep -oE '"ja4": ?"[^"]+"' | head -1 | cut -d_ -f2)
bundle() { # seed, version, tool name, [expires]
  sed -e "s/curl (LibreSSL, macOS system build)/$3/" -e "s/\"0d8feac7bc37\"/\"$CURL_CIPHER\"/" \
    crates/veritell-ua/data/truth_v1.json > "$WORK/truth.json"
  "$BUNDLE" seal "$1" "$2" "$(($(date +%s) - 60))" "${4:-$(($(date +%s) + 3600))}" truth_v1.json="$WORK/truth.json" > "$WORK/feed.tmp" && mv "$WORK/feed.tmp" "$FEED"
  sleep 1.2
}
check "E20 this curl's cipher hash was read"   "$CURL_CIPHER" '^[0-9a-f]\{12\}$'
if [ "$CURL_KNOWN" = 1 ]; then
  check "E20 built-in data before any feed"      "$(tool_name)" 'belongs to curl (LibreSSL'
else
  skip "E20 built-in data before any feed"       "$CURL_NOT_KNOWN"
fi
bundle "$FEED_SEED" 2 "feed-two"
check "E20 a signed bundle takes effect"         "$(tool_name)" 'belongs to feed-two'
bundle "$WRONG_SEED" 3 "feed-wrong-key"
check "E20 a bundle from another key is refused" "$(tool_name)" 'belongs to feed-two'
bundle "$FEED_SEED" 1 "feed-rollback"
check "E20 an older version is refused"          "$(tool_name)" 'belongs to feed-two'
bundle "$FEED_SEED" 4 "feed-expired" "$(($(date +%s) - 30))"
check "E20 an expired bundle is refused"         "$(tool_name)" 'belongs to feed-two'
printf '{"manifest":"' > "$FEED"; sleep 1.2
check "E20 a half-written file is refused"       "$(tool_name)" 'belongs to feed-two'
bundle "$FEED_SEED" 5 "feed-five"
check "E20 the next good bundle is taken"        "$(tool_name)" 'belongs to feed-five'
err=$(cat "$WORK/shadow.err")
check "E20 refusals are logged with the reason"  "$err" 'feed refused, keeping version 2: bundle signature does not verify'
check "E20 rollback logged"                      "$err" 'feed refused, keeping version 2: bundle version 1 is older than 2'
check "E20 loads logged"                         "$err" 'feed version 5 loaded'

# ---- Phase 1: Web Bot Auth ----
now=$(date +%s)
signed() { # key, then extra curl args
  local key=$1; shift
  local in sig
  { read -r in; read -r sig; } < <("$SIGN" "localhost:$PORT" "$now" "$key")
  curl -sk --http2 -H "$in" -H "$sig" "$@" "$URL/"
}
r=$(signed rfc)
check "E13 trusted signature: class signed_agent" "$r" '"class": "signed_agent"'
check "E13 agent named"                          "$r" '"identity": "rfc-test-agent"'
refute "E13 no signature detection"              "$r" '"id": "wba_'
{ read -r in; read -r sig; } < <("$SIGN" "localhost:$PORT" "$now" rfc)
bad=$(printf '%s' "$sig" | sed 's/sig1=:\(.\)\(.\)/sig1=:\2\1/')
[ "$bad" = "$sig" ] && bad=$(printf '%s' "$sig" | sed 's/sig1=:../sig1=:AB/')
r=$(curl -sk --http2 -H "$in" -H "$bad" "$URL/")
check "E14 changed signature"                    "$r" '"id": "wba_bad_signature"'
check "E14 class malicious"                      "$r" '"class": "malicious"'
r=$(curl -sk --http2 -H "$in" -H "$sig" -H "host: evil.example" "$URL/")
refute "E14 signature for another authority is not accepted" "$r" '"class": "signed_agent"'
# A neutral User-Agent, so the class reflects the signature finding alone
# (curl's own User-Agent would make it "automated").
r=$(signed other -A "ExampleAgent/1.0")
check "E15 untrusted key"                        "$r" '"id": "wba_unknown_key"'
check "E15 class unverified_agent"               "$r" '"class": "unverified_agent"'

# ---- Phase 1: dashboard and event store ----
ADMIN="http://127.0.0.1:$ADMIN_PORT"
r=$(curl -s "$ADMIN/api/events?detection=crawler_spoofed")
check "E16 events API has the spoofed crawler"   "$r" '"crawler_spoofed"'
check "E16 with its explanation"                 "$r" '"detail":"'
check "E16 probe events are there"               "$(curl -s "$ADMIN/api/events?kind=probe")" '"outcome":"probe_flagged"'
check "E16 summary counts requests"              "$(curl -s "$ADMIN/api/summary")" '"malicious":'
hdrs=$(curl -s -D - -o "$WORK/dash.html" "$ADMIN/")
check "E16 page loads"                           "$(cat "$WORK/dash.html")" 'Veritell'
check "E16 strict content security policy"       "$hdrs" "content-security-policy: default-src 'none'"
check "E16 script loads"                         "$(curl -s -o /dev/null -w '%{http_code}' "$ADMIN/app.js")" '200'
check "E16 POST refused"                         "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$ADMIN/api/events")" '405'
check "E16 dashboard is not on the public listener" "$(curl -sk --http2 "$URL/api/events")" '"score"'
err=$(env -u VERITELL_ADMIN_TOKEN "$BIN" --cert "$CERT" --key "$KEY" --listen "127.0.0.1:$((PORT+1))" --admin "0.0.0.0:$((ADMIN_PORT+1))" 2>&1; echo "exit=$?")
check "E16 non-loopback admin bind is refused without a token" "$err" 'a non-loopback address needs VERITELL_ADMIN_TOKEN'
check "E16 and the process exits"                "$err" 'exit=2'
sleep 1.5
ch=$(cat "$WORK/clickhouse.txt" 2>/dev/null)
check "E17 event store received an insert"       "$ch" 'REQUEST /?query=INSERT%20INTO%20veritell.events%20FORMAT%20JSONEachRow user=default'
check "E17 rows carry the decisions"             "$ch" '"detection_ids":\[[^]]*"crawler_spoofed"'
check "E17 one JSON object per line"             "$(printf '%s\n' "$ch" | grep -c '^{.*}$')" '^[1-9]'
stop_proxy

# ---- enforce mode with an origin ----
python3 scripts/echo_origin.py "$ORIGIN_PORT" & PIDS+=("$!"); wait_port "$ORIGIN_PORT"
"$BIN" --cert "$CERT" --key "$KEY" --listen "127.0.0.1:$PORT" --upstream "127.0.0.1:$ORIGIN_PORT" \
  --policy scripts/e2e_policy.yaml --token-budget 3 >"$WORK/enforce.log" 2>"$WORK/enforce.err" &
PROXY=$!; PIDS+=("$PROXY"); wait_port "$PORT"

code=$(curl -sk --http2 -o "$WORK/page.html" -w '%{http_code}' "$URL/products?id=7")
page=$(cat "$WORK/page.html")
check "E4 low score is challenged (403)"         "$code" '403'
check "E4 challenge page served"                 "$page" 'Checking your browser'
refute "E31 without a token issuer the page never waits" \
  "$(curl -sk --http2 -A 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.2 Mobile/15E148 Safari/604.1' -H 'sec-fetch-mode: navigate' "$URL/products?id=7")" 'data-probe data-wait='
check "E4 challenge page runs the probe"         "$page" '<script src="/__veritell/probe.js" async></script>'
check "E48 challenge page links to the source"   "$page" '<a href="https://github.com/veritell/veritell">Source code</a> (AGPL-3.0)'
check "E48 and says what it is"                  "$page" 'Powered by <a href="https://veritell.io">Veritell</a>'
check "E4 and waits for it"                      "$page" '<html lang="en" data-probe>'
refute "E4 origin not reached"                   "$page" '"origin": true'
check "E4 unchallenged route still reaches origin" "$(curl -sk --http2 "$URL/open/x")" '"origin": true'
check "E3 enforce: spoofed Googlebot blocked"    "$(curl -sk --http2 -A "$GOOGLEBOT_UA" -o /dev/null -w '%{http_code}' "$URL/")" '403'

read -r challenge counter < <(python3 scripts/solve.py < "$WORK/page.html")
hdrs=$(curl -sk --http2 -D - -o /dev/null -c "$WORK/jar" --data-urlencode "challenge=$challenge" \
  --data-urlencode "counter=$counter" --data-urlencode "return_to=/products?id=7" "$URL/__veritell/verify")
check "E5 solution accepted (303)"               "$hdrs" 'HTTP/2 303'
check "E5 redirect to the original page"         "$hdrs" 'location: /products?id=7'
check "E5 cookie is HttpOnly and Secure"         "$hdrs" 'HttpOnly; Secure; SameSite=Lax'

r=$(curl -sk --http2 -b "$WORK/jar" -H 'x-veritell-score: 99' -H 'x-veritell-evil: 1' "$URL/products?id=7")
check "E5 token lets the request through"        "$r" '"origin": true'
# The token holder never sent a probe report, which now costs 40 points.
check "E9 origin sees the gateway's score"       "$r" '"x-veritell-score": "1"'
check "token without a probe report is flagged"  "$r" 'probe_missing'
refute "E9 client-supplied score is dropped"     "$r" '"x-veritell-score": "99"'
refute "E9 unknown x-veritell header is dropped" "$r" 'x-veritell-evil'
check "E9 origin sees the JA4"                   "$r" '"x-veritell-ja4": "t13d'

code=$(curl -sk --http2 -o /dev/null -w '%{http_code}' --data-urlencode "challenge=$challenge" \
  --data-urlencode "counter=$counter" "$URL/__veritell/verify")
check "E6 replayed solution rejected"            "$code" '403'
code=$(curl -sk --http2 -o /dev/null -w '%{http_code}' --data-urlencode "challenge=$challenge" \
  --data-urlencode "counter=1" "$URL/__veritell/verify")
check "E6 wrong counter rejected"                "$code" '403'
code=$(curl -sk --http2 -o /dev/null -w '%{http_code}' -d 'challenge=garbage&counter=x' "$URL/__veritell/verify")
check "E6 garbage rejected"                      "$code" '403'

r=$(curl -sk --http2 -b "$WORK/jar" -A "curl/9.9.9" -o /dev/null -w '%{http_code}' "$URL/products")
check "E8 token with another User-Agent is challenged" "$r" '403'
check "E8 logged as binding mismatch"            "$(cat "$WORK/enforce.log")" '"token":"binding_mismatch"'

# Budget is 3: one use above, two more allowed, then challenged again.
a=$(curl -sk --http2 -b "$WORK/jar" -o /dev/null -w '%{http_code}' "$URL/products")
b=$(curl -sk --http2 -b "$WORK/jar" -o /dev/null -w '%{http_code}' "$URL/products")
c=$(curl -sk --http2 -b "$WORK/jar" -o /dev/null -w '%{http_code}' "$URL/products")
check "E7 uses 2 and 3 pass, use 4 is challenged" "$a $b $c" '200 200 403'
check "E7 logged as budget spent"                "$(cat "$WORK/enforce.log")" '"token":"budget_spent"'

check "HTTP/1.1 clients are handled too"         "$(curl -sk --http1.1 -o /dev/null -w '%{http_code}' "$URL/open/x")" '200'
code=$(curl -sk --http2 -o /dev/null -w '%{http_code}' "$URL/__veritell/verify")
check "GET on the verify path is refused"        "$code" '405'

# ---- Phase 2 wave B: behaviour summaries and population rules (E21, E22) ----
refute "E24 forwarded address from an untrusted peer is ignored" \
  "$(curl -sk --http2 -o /dev/null -A "forger/1" -H 'x-forwarded-for: 10.9.9.9' "$URL/open/x"; cat "$WORK/enforce.log")" '"ip":"10.9.9.9"'
stop_proxy
# Windows of 6 one-second slots and entries that last 3 s, so expiry can be watched.
"$BIN" --cert "$CERT" --key "$KEY" --listen "127.0.0.1:$PORT" --trusted-proxy 127.0.0.1 \
  --agg-warmup 0 --agg-slot 1 --agg-reputation-ttl 3 --admin "127.0.0.1:${WAVEB_ADMIN_PORT:-9087}" >"$WORK/waveb.log" 2>"$WORK/waveb.err" &
PROXY=$!; PIDS+=("$PROXY"); wait_port "$PORT"

# summary <nonce> [field=value ...]: a behaviour summary, all counts zero unless given.
summary() { python3 - "$@" <<'PY'
import json, sys
s = {k: 0 for k in "dur_ms hidden_ms moves strokes straight steady clicks sized centered teleport touches keys pastes scrolls submits untrusted actions".split()}
s.update(v=1, nonce=sys.argv[1], trigger="hide", key_gap_cv=None, gap_cv=None, gap_med_ms=None, dur_ms=9000)
for pair in sys.argv[2:]:
    k, v = pair.split("=", 1)
    s[k] = v if k in ("trigger", "extra") else int(v)
print(json.dumps(s), end="")
PY
}
bnonce() { curl -sk --http2 -A "$1" "$URL/__veritell/behavior.js" | sed -n 's/.*"nonce":"\([A-Za-z0-9_-]*\)".*/\1/p' | head -1; }
post_summary() { printf '%s' "$2" | curl -sk --http2 -o /dev/null -w '%{http_code}' -A "$1" -H 'content-type: application/json' --data-binary @- "$URL/__veritell/behavior"; }

hdrs=$(curl -sk --http2 -D - -o "$WORK/behavior.js" -A "quiet-client/1" "$URL/__veritell/behavior.js")
check "E21 behaviour script served as JavaScript" "$hdrs" 'content-type: text/javascript'
refute "E21 config token was replaced"           "$(cat "$WORK/behavior.js")" '"__VERITELL_BEHAVIOR__"'
check "E21 POST on the script path is refused"   "$(curl -sk --http2 -o /dev/null -w '%{http_code}' -X POST "$URL/__veritell/behavior.js")" '405'
check "E21 GET on the report path is refused"    "$(curl -sk --http2 -o /dev/null -w '%{http_code}' "$URL/__veritell/behavior")" '405'

# A page that was opened and saw nothing, then a form POST from the same client.
n=$(bnonce "quiet-client/1")
refute "E21 nothing before any summary"          "$(curl -sk --http2 -A "quiet-client/1" -d 'a=1' "$URL/login")" '"layer": "behavior"'
check "E21 empty summary accepted (204)"         "$(post_summary "quiet-client/1" "$(summary "$n")")" '204'
refute "E21 a GET is not held against it"        "$(curl -sk --http2 -A "quiet-client/1" "$URL/")" 'behavior_no_input'
r=$(curl -sk --http2 -A "quiet-client/1" -d 'user=a&pass=b' "$URL/login")
check "E21 form POST with no input before it"    "$r" '"id": "behavior_no_input"'
check "E21 class automated"                      "$r" '"class": "automated"'
check "E21 a nonce is good for three summaries"  "$(post_summary "quiet-client/1" "$(summary "$n")") $(post_summary "quiet-client/1" "$(summary "$n")") $(post_summary "quiet-client/1" "$(summary "$n")")" '204 204 403'
check "E21 logged: nonce spent"                  "$(cat "$WORK/waveb.log")" '"outcome":"behavior_nonce_spent"'

# The summary itself reports a submit with no input.
n=$(bnonce "submitter/1")
check "E21 submit summary accepted"              "$(post_summary "submitter/1" "$(summary "$n" trigger=submit submits=1)")" '204'
check "E21 later requests carry it"              "$(curl -sk --http2 -A "submitter/1" "$URL/")" '"id": "behavior_no_input"'
check "E21 logged as flagged"                    "$(cat "$WORK/waveb.log")" '"outcome":"behavior_flagged"'

# A person: input seen, nothing found, and a POST afterwards is clean.
n=$(bnonce "person/1")
check "E21 a person's summary accepted"          "$(post_summary "person/1" "$(summary "$n" trigger=submit submits=1 moves=412 strokes=9 clicks=3 sized=2 keys=24 key_gap_cv=612 scrolls=2 actions=8 gap_cv=840 gap_med_ms=1450)")" '204'
ev=$(curl -s "http://127.0.0.1:${WAVEB_ADMIN_PORT:-9087}/api/events?limit=20")
check "E21 its counts are in the event, for the event store" "$ev" '"summary":"{\\"actions\\":8,'
check "E21 all of them"                          "$ev" '\\"moves\\":412,'
refute "E21 no behaviour detection for a person" "$(curl -sk --http2 -A "person/1" -d 'user=a' "$URL/login")" '"layer": "behavior"'

n=$(bnonce "scripted/1")
post_summary "scripted/1" "$(summary "$n" moves=150 strokes=9 straight=9 clicks=2 sized=2 centered=2 actions=2)" >/dev/null
r=$(curl -sk --http2 -A "scripted/1" "$URL/")
check "E21 straight pointer paths"               "$r" '"id": "behavior_pointer_scripted"'
check "E21 clicks on exact centres"              "$r" '"id": "behavior_click_centered"'

n=$(bnonce "llm-agent/1")
post_summary "llm-agent/1" "$(summary "$n" moves=5 clicks=5 teleport=5 actions=6 gap_cv=400 gap_med_ms=4200)" >/dev/null
r=$(curl -sk --http2 -A "llm-agent/1" "$URL/")
check "E21 think-act rhythm"                     "$r" '"id": "behavior_agent_rhythm"'
check "E21 classed as an unverified agent"       "$r" '"class": "unverified_agent"'
refute "E21 other clients are unaffected"        "$(curl -sk --http2 -A "bystander/2" "$URL/")" '"layer": "behavior"'

# Summaries that must be rejected, and what repeated rejections do.
n=$(bnonce "someone-else/2")
check "E21 nonce issued to another client"       "$(post_summary "forger/2" "$(summary "$n")")" '403'
pn=$(curl -sk --http2 -A "forger/2" "$URL/__veritell/probe.js" | nonce_of)
check "E21 a probe nonce is not a behaviour nonce" "$(post_summary "forger/2" "$(summary "$pn")")" '403'
refute "E21 two rejections do not mark a client" "$(curl -sk --http2 -A "forger/2" "$URL/")" 'client_rejections'
n=$(bnonce "forger/2")
check "E21 a field outside the schema"           "$(post_summary "forger/2" "$(summary "$n" extra=1)")" '403'
check "E21 oversized summary"                    "$(head -c 5000 /dev/zero | tr '\0' ' ' | curl -sk --http2 -o /dev/null -w '%{http_code}' -A "forger/2" --data-binary @- "$URL/__veritell/behavior")" '413'
log=$(cat "$WORK/waveb.log")
check "E21 logged: other client"                 "$log" '"outcome":"behavior_nonce_other_client"'
check "E21 logged: malformed"                    "$log" '"outcome":"behavior_malformed"'
r=$(curl -sk --http2 -A "forger/2" "$URL/")
check "E21 three rejections mark the client"     "$r" '"id": "client_rejections"'
check "E21 in the population layer"              "$r" '"layer": "population"'

# E22: one fingerprint from 60 networks, then from one more.
check "E22 forwarded address from a trusted peer is used" \
  "$(curl -sk --http2 -o /dev/null -A "rotator/1" -H 'x-forwarded-for: 1.1.1.1, 10.250.0.1' "$URL/"; cat "$WORK/waveb.log")" '"ip":"10.250.0.1"'
for i in $(seq 1 60); do curl -sk --http2 -o /dev/null -A "rotator/1" -H "x-forwarded-for: 10.$i.0.1" "$URL/"; done
r=$(curl -sk --http2 -A "rotator/1" -H "x-forwarded-for: 10.251.0.1" "$URL/")
check "E22 one fingerprint over many networks"   "$r" '"id": "cluster_fp_spread"'
check "E22 class automated"                      "$r" '"class": "automated"'
refute "E22 another fingerprint on one of those networks" "$(curl -sk --http2 -A "resident/1" -H "x-forwarded-for: 10.7.0.9" "$URL/")" 'cluster_fp_spread'
sleep 10   # the window (6 s) and then the entry (3 s) run out
refute "E22 gone after the entry expires"        "$(curl -sk --http2 -A "rotator/1" -H "x-forwarded-for: 10.251.0.1" "$URL/")" 'cluster_fp_spread'

# ---- Phase 2 wave C: shadow model and the sidecar endpoint (E23, E24, E25) ----
stop_proxy
SC_PORT=${SC_PORT:-9096}; SC="http://127.0.0.1:$SC_PORT"
# A model trained on lab sessions only (scripts/fixtures/e2e_model.json); the
# trainer itself is not part of this repository.
cp scripts/fixtures/e2e_model.json "$WORK/model.json"
check "E23 the test model is a model"            "$(head -c 20 "$WORK/model.json")" '"base"'
printf '{"v":1,"features":["a"],"base":0,"trees":[]}' > "$WORK/other-features.json"
check "E23 a model for other features is refused at start" \
  "$("$BIN" --cert "$CERT" --key "$KEY" --listen "127.0.0.1:$PORT" --model "$WORK/other-features.json" 2>&1; echo "exit $?")" 'exit 2'
check "E23 a broken model is refused at start" \
  "$(echo '{' > "$WORK/broken.json"; "$BIN" --cert "$CERT" --key "$KEY" --listen "127.0.0.1:$PORT" --model "$WORK/broken.json" 2>&1; echo "exit $?")" 'malformed'
check "E24 a sidecar listener needs a trusted proxy" \
  "$("$BIN" --cert "$CERT" --key "$KEY" --listen "127.0.0.1:$PORT" --sidecar-listen "127.0.0.1:$SC_PORT" 2>&1; echo "exit $?")" 'exit 2'

# First with a trusted proxy that is not us: everything we send is a stranger's.
"$BIN" --cert "$CERT" --key "$KEY" --listen "127.0.0.1:$PORT" --policy scripts/e2e_policy.yaml \
  --sidecar-listen "127.0.0.1:$SC_PORT" --trusted-proxy 10.255.255.1 >"$WORK/stranger.log" 2>"$WORK/stranger.err" &
PROXY=$!; PIDS+=("$PROXY"); wait_port "$PORT"; wait_port "$SC_PORT"
authz() { curl -s -o /dev/null -D - "$@" | tr -d '\r'; }
r=$(authz -A "$CHROME_UA" -H 'x-original-uri: /open/x' -H 'x-forwarded-for: 198.51.100.7' "$SC/__veritell/authz")
check "E24 an untrusted peer is refused"         "$r" '^HTTP/1.1 403'
refute "E24 and is told no score"                "$r" 'x-veritell-score'
check "E24 logged"                               "$(cat "$WORK/stranger.log")" '"outcome":"sidecar_untrusted_peer"'
refute "E24 forged address never used"           "$(cat "$WORK/stranger.log")" '198.51.100.7'
check "E24 the plain listener serves nothing else" "$(authz "$SC/open/x")" '^HTTP/1.1 404'
check "E24 not even the probe script"            "$(authz "$SC/__veritell/probe.js")" '^HTTP/1.1 404'
stop_proxy

"$BIN" --cert "$CERT" --key "$KEY" --listen "127.0.0.1:$PORT" --policy scripts/e2e_policy.yaml --model "$WORK/model.json" \
  --sidecar-listen "127.0.0.1:$SC_PORT" --trusted-proxy 127.0.0.1 >"$WORK/wavec.log" 2>"$WORK/wavec.err" &
PROXY=$!; PIDS+=("$PROXY"); wait_port "$PORT"; wait_port "$SC_PORT"
check "E23 model loaded in shadow"               "$(cat "$WORK/wavec.err")" 'model with 20 trees loaded (shadow)'

r=$(authz -A "$CHROME_UA" -H 'x-original-uri: /open/x?q=1' -H 'x-forwarded-for: 1.1.1.1, 198.51.100.7' "$SC/__veritell/authz")
check "E24 a request on an open route passes"    "$r" '^HTTP/1.1 200'
check "E24 with the score"                       "$r" '^x-veritell-score: [0-9]'
check "E24 and the class"                        "$r" '^x-veritell-class: '
log=$(cat "$WORK/wavec.log")
check "E24 scored as the client, not the proxy"  "$log" '"ip":"198.51.100.7"'
check "E24 on the original path"                 "$log" '"path":"/open/x"'
refute "E24 the proxy's own headers are not scored" "$log" 'x-original-uri'
check "E23 the log line carries the model score" "$log" '"model":{"probability":[0-9.]*,"score":[0-9]*,"top":\['
r=$(authz -H 'x-original-uri: /products' -H 'x-forwarded-for: 198.51.100.8' "$SC/__veritell/authz")
check "E24 a declared tool is refused"           "$r" '^HTTP/1.1 403'
check "E24 because a challenge is required"      "$r" '^x-veritell-action: challenge(pow)'
check "E23 the model names what moved it"        "$(cat "$WORK/wavec.log")" '"by":[-0-9.]*,"feature":"[a-z_]*"'
r=$(authz -A "$GOOGLEBOT_UA" -H 'x-forwarded-uri: /products' -H 'x-forwarded-method: POST' -H 'x-forwarded-for: 198.51.100.9' "$SC/__veritell/authz")
check "E24 an unconfirmed crawler claim is classed as such" "$r" '^x-veritell-class: unverified_agent'
check "E24 the forwarded method is used"         "$(cat "$WORK/wavec.log")" '"method":"POST"'
check "E24 path-prefix form (Envoy)"             "$(authz -A "$CHROME_UA" -H 'x-forwarded-for: 198.51.100.7' "$SC/__veritell/authz/open/y?z=2")" '^HTTP/1.1 200'
check "E24 its path is the suffix"               "$(cat "$WORK/wavec.log")" '"path":"/open/y"'
check "E24 no original URI is a 400"             "$(authz -H 'x-forwarded-for: 198.51.100.7' "$SC/__veritell/authz")" '^HTTP/1.1 400'
check "E24 no client address is a 400"           "$(authz -H 'x-original-uri: /open/x' "$SC/__veritell/authz")" '^HTTP/1.1 400'
check "E24 a URI that is not a path is a 400"    "$(authz -H 'x-original-uri: http://evil.example/' -H 'x-forwarded-for: 198.51.100.7' "$SC/__veritell/authz")" '^HTTP/1.1 400'
check "E24 a look-alike path is not the endpoint" "$(authz -H 'x-forwarded-for: 198.51.100.7' "$SC/__veritell/authzx")" '^HTTP/1.1 404'
# On the main listener the path is nothing special, and the model changes no action.
r=$(curl -sk --http2 -o /dev/null -w '%{http_code}' -H 'x-original-uri: /open/x' -H 'x-forwarded-for: 198.51.100.7' "$URL/__veritell/authz")
check "E24 on the main listener it is an ordinary path" "$r" '403'
r=$(curl -sk --http2 -H 'x-forwarded-for: 198.51.100.20' "$URL/open/x")
check "E23 the self-report carries the model"    "$r" '"model": {'
check "E23 it names a feature"                   "$r" '"feature": "[a-z_]*"'
check "E23 actions are the rules', not the model's" "$(curl -sk --http2 -o /dev/null -w '%{http_code}' -H 'x-forwarded-for: 198.51.100.20' "$URL/open/x") $(curl -sk --http2 -o /dev/null -w '%{http_code}' -H 'x-forwarded-for: 198.51.100.20' "$URL/products")" '200 403'
# The challenge page on request, for a proxy that was told to challenge.
page=$(curl -sk --http2 -H 'x-forwarded-for: 198.51.100.8' "$URL/__veritell/challenge?return_to=/products%3Fa%3D1")
check "E24 challenge page on request"            "$page" 'data-probe'
check "E24 it returns to the given path"         "$page" '/products?a=1'
refute "E24 it does not return off-site"         "$(curl -sk --http2 -H 'x-forwarded-for: 198.51.100.8' "$URL/__veritell/challenge?return_to=//evil.example/")" 'evil.example'
if command -v nginx >/dev/null 2>&1; then echo "E25 nginx is installed: run sidecar/check.sh"; else echo "NOT RUN  E25 nginx auth_request: nginx is not installed"; fi

# ---- Phase 3 wave A: agents as customers (E26 to E30) ----
stop_proxy
DIR_PORT=${DIR_PORT:-9095}
DIR="https://127.0.0.1:$DIR_PORT"
# The directory server's certificate: for the address, and not a CA.
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=veritell-e2e-directory" \
  -addext "subjectAltName=IP:127.0.0.1" -addext "basicConstraints=critical,CA:FALSE" \
  -keyout "$WORK/dir-key.pem" -out "$WORK/dir-cert.pem" >/dev/null 2>&1 || { echo "could not create the directory certificate"; exit 1; }
"$SIGN" jwks other > "$WORK/jwks.json"
python3 scripts/directory_server.py "$DIR_PORT" "$WORK/dir-cert.pem" "$WORK/dir-key.pem" <"$WORK/jwks.json" >"$WORK/dir-requests.log" & PIDS+=("$!"); wait_port "$DIR_PORT"
cat > "$WORK/agents.json" <<JSON
{"agents":[
  {"name":"rfc-test-agent","keys":[{"kty":"OKP","crv":"Ed25519","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}]},
  {"name":"dir-ok","signature_agent":"$DIR/keys.json"},
  {"name":"dir-redirect","signature_agent":"$DIR/redirect"},
  {"name":"dir-big","signature_agent":"$DIR/big"},
  {"name":"dir-loopback","signature_agent":"https://127.0.0.1:$ORIGIN_PORT/keys.json"},
  {"name":"dir-private","signature_agent":"https://10.255.255.1/keys.json"},
  {"name":"dir-metadata","signature_agent":"https://169.254.169.254/latest/meta-data/"}
]}
JSON
"$BIN" --cert "$CERT" --key "$KEY" --listen "127.0.0.1:$PORT" --upstream "127.0.0.1:$ORIGIN_PORT" \
  --policy scripts/e2e_agents_policy.yaml --trusted-proxy 127.0.0.1 --wba-agents "$WORK/agents.json" \
  --wba-directory-allow "127.0.0.1:$DIR_PORT" --wba-directory-ca "$WORK/dir-cert.pem" >"$WORK/wavea.log" 2>"$WORK/wavea.err" &
PROXY=$!; PIDS+=("$PROXY"); wait_port "$PORT"
now=$(date +%s)
# agent <key> <signature-agent url or ""> <curl args...>: a signed request; prints status, headers and body.
agent() {
  local key=$1 sa=$2; shift 2
  local hs=() line
  while IFS= read -r line; do hs+=(-H "$line"); done < <("$SIGN" "localhost:$PORT" "$now" "$key" $sa)
  curl -sk --http2 -D - "${hs[@]}" "$@" | tr -d '\r'
}
# Let the directory thread make its first round.
for _ in $(seq 1 50); do grep -q 'dir-metadata' "$WORK/wavea.err" && break; sleep 0.1; done
err=$(cat "$WORK/wavea.err")

# E30 and E29 first, so what follows can use the fetched agent.
check "E30 an allowed directory is fetched"      "$err" 'key directory for dir-ok loaded: 1 keys, next fetch in 600 s'
check "E29 a redirect is not followed"           "$err" 'key directory for dir-redirect refused: status 302'
check "E29 an oversized directory is refused"    "$err" 'key directory for dir-big refused: directory larger than 65536 bytes'
check "E29 loopback is refused by address"       "$err" 'key directory for dir-loopback refused: address 127.0.0.1 may not be fetched from'
check "E29 a private address is refused"         "$err" 'key directory for dir-private refused: address 10.255.255.1 may not be fetched from'
check "E29 the metadata address is refused"      "$err" 'key directory for dir-metadata refused: address 169.254.169.254 may not be fetched from'
r=$(agent other "$DIR/keys.json" -H 'x-forwarded-for: 198.51.100.40' "$URL/open/a")
check "E30 a signature by a fetched key verifies" "$r" '"x-veritell-class": "signed_agent"'
check "E30 the agent is the configured one"      "$(cat "$WORK/wavea.log")" '"identity":"dir-ok"'
r=$(agent other "$DIR/redirect" -H 'x-forwarded-for: 198.51.100.41' "$URL/open/a")
refute "E29 the same key under a refused directory is not that agent" "$r" 'signed_agent'
refute "E29 no identity for it"                  "$(cat "$WORK/wavea.log")" '"identity":"dir-redirect"'
r=$(agent other "" -H 'x-forwarded-for: 198.51.100.42' "$URL/open/a")
refute "E30 a fetched key is only good with its Signature-Agent" "$r" 'signed_agent'
r=$(agent other "$DIR/unlisted.json" -H 'x-forwarded-for: 198.51.100.43' "$URL/open/a")
refute "E29 an unlisted Signature-Agent is not believed" "$r" 'signed_agent'
agent other "$DIR/keys.json" -H 'x-forwarded-for: 198.51.100.40' "$URL/open/b" >/dev/null
sleep 1.5
reqs=$(cat "$WORK/dir-requests.log")
refute "E29 an unlisted Signature-Agent is never fetched" "$reqs" 'unlisted'
check "E30 the directory was fetched once, then cached" "$(printf '%s\n' "$reqs" | grep -c '^/keys.json$')" '^1$'
check "E29 one request each, and none to the redirect's target" "$(printf '%s\n' "$reqs" | sort | tr '\n' ' ')" '^/big /keys.json /redirect $'

# E27 (first half): the quota is there while it lasts.
check "E27 within the quota a request passes"    "$(agent rfc "" -H 'x-forwarded-for: 198.51.100.50' "$URL/quota/1")" '^HTTP/2 200'
check "E27 the log carries what was left"        "$(cat "$WORK/wavea.log")" '"quota_left":7'

# E26: two a minute for the agent, wherever it comes from.
check "E26 first request, first address"         "$(agent rfc "" -H 'x-forwarded-for: 198.51.100.51' "$URL/rate")" '^HTTP/2 200'
check "E26 second request, second address"       "$(agent rfc "" -H 'x-forwarded-for: 198.51.100.52' "$URL/rate")" '^HTTP/2 200'
r=$(agent rfc "" -H 'x-forwarded-for: 198.51.100.53' "$URL/rate")
check "E26 third request, third address: throttled" "$r" '^HTTP/2 429'
check "E26 with a retry-after"                   "$r" '^retry-after: 60'
check "E26 another agent has its own allowance"  "$(agent other "$DIR/keys.json" -H 'x-forwarded-for: 198.51.100.51' "$URL/rate")" '^HTTP/2 200'
check "E26 an unsigned client on those addresses is not caught by it" \
  "$(curl -sk --http2 -o /dev/null -w '%{http_code}' -A "$CHROME_UA" -H 'x-forwarded-for: 198.51.100.51' "$URL/rate")" '200'
check "E26 logged as throttled"                  "$(cat "$WORK/wavea.log")" '"outcome":"throttled"'

# E28: a price for agents, the next rule for everyone else.
r=$(agent rfc "" -H 'x-forwarded-for: 198.51.100.54' "$URL/paid/x")
check "E28 a signed agent gets 402"              "$r" '^HTTP/2 402'
check "E28 the offer in one header"              "$r" '^veritell-offer: offer="crawl", price="0.002", currency="USD", unit="request", terms="https://shop.example/agents/terms"$'
check "E28 and as JSON"                          "$r" '^{"offer":"crawl","price":"0.002","currency":"USD","unit":"request","terms":"https://shop.example/agents/terms"}$'
check "E28 as application/json"                  "$r" '^content-type: application/json'
refute "E28 the origin was not reached"          "$r" '"origin": true'
r2=$(agent other "$DIR/keys.json" -H 'x-forwarded-for: 198.51.100.55' "$URL/paid/x")
check "E28 the answer is the same for another agent" "$(printf '%s\n' "$r2" | grep -c -e '^veritell-offer: offer="crawl"' -e '^{"offer":"crawl"')" '^2$'
check "E28 an unsigned client gets the next rule" "$(curl -sk --http2 -o /dev/null -w '%{http_code}' -A "$CHROME_UA" -H 'x-forwarded-for: 198.51.100.54' "$URL/paid/x")" '403'
check "E28 a Signature-Agent header alone is not an identity" \
  "$(curl -sk --http2 -o /dev/null -w '%{http_code}' -A "$CHROME_UA" -H "signature-agent: sig1=\"$DIR/keys.json\"" -H 'x-forwarded-for: 198.51.100.56' "$URL/paid/x")" '403'
check "E28 logged with the offer"                "$(cat "$WORK/wavea.log")" '"offer":"crawl","outcome":"charged"'
r=$(agent rfc "" -H 'x-forwarded-for: 198.51.100.54' "$URL/receipt/x")
check "E28 an offer that takes receipts still asks first" "$r" '^HTTP/2 402'
r=$(agent rfc "" -H 'x-forwarded-for: 198.51.100.54' -H 'payment-receipt: opaque-value-1' "$URL/receipt/x")
check "E28 a receipt claim reaches the origin"   "$r" '"origin": true'
check "E28 marked as unverified"                 "$r" '"x-veritell-receipt": "unverified"'
check "E28 with the receipt itself"              "$r" '"payment-receipt": "opaque-value-1"'
check "E28 logged as a receipt claim"            "$(cat "$WORK/wavea.log")" '"outcome":"charge_receipt"'
check "E28 a receipt from an unsigned client buys nothing" \
  "$(curl -sk --http2 -o /dev/null -w '%{http_code}' -A "$CHROME_UA" -H 'payment-receipt: x' -H 'x-forwarded-for: 198.51.100.57' "$URL/receipt/x")" '200'

# E47: a write request proves an agent only when its signature binds the
# method and path; an @authority-only signature could be replayed to any.
# bound_agent <method> <path> <url path> <curl args...>: signed over @method and @path.
bound_agent() {
  local method=$1 path=$2 url=$3; shift 3
  local hs=() line
  while IFS= read -r line; do hs+=(-H "$line"); done < <(SIGN_METHOD=$method SIGN_PATH=$path "$SIGN" "localhost:$PORT" "$now" rfc)
  curl -sk --http2 -D - -X "$method" "${hs[@]}" "$@" "$URL$url" | tr -d '\r'
}
check "E47 a signed POST over the authority alone is not the agent" \
  "$(agent rfc "" -X POST -H 'x-forwarded-for: 198.51.100.60' "$URL/paid/x")" '^HTTP/2 403'
check "E47 noted as an unbound write"            "$(cat "$WORK/wavea.log")" 'wba_write_unbound'
check "E47 a POST signed over its method and path is the agent" \
  "$(bound_agent POST /paid/x /paid/x -H 'x-forwarded-for: 198.51.100.61')" '^HTTP/2 402'
check "E47 that signature is not good for another path" \
  "$(bound_agent POST /paid/x /paid/y -H 'x-forwarded-for: 198.51.100.62')" '^HTTP/2 403'
check "E47 a GET over the authority alone is still the agent" \
  "$(agent rfc "" -H 'x-forwarded-for: 198.51.100.63' "$URL/paid/z")" '^HTTP/2 402'
refute "E28 and is not marked"                   "$(curl -sk --http2 -A "$CHROME_UA" -H 'payment-receipt: x' -H 'x-forwarded-for: 198.51.100.57' "$URL/receipt/x")" 'x-veritell-receipt'

# E27 (second half): seven requests by rfc-test-agent so far, which is its day.
r=$(agent rfc "" -H 'x-forwarded-for: 198.51.100.58' "$URL/quota/2")
check "E27 the quota is used up: the policy's action" "$r" '^HTTP/2 403'
check "E27 logged with nothing left"             "$(cat "$WORK/wavea.log")" '"quota_left":0'
check "E27 another identity is not affected"     "$(agent other "$DIR/keys.json" -H 'x-forwarded-for: 198.51.100.58' "$URL/quota/2")" '^HTTP/2 200'
refute "E27 a client without an identity has no quota" "$(grep '"identity":""' "$WORK/wavea.log")" '"quota_left":[0-9]'

# ---- Phase 3 wave B: Privacy Pass tokens in place of the proof of work (E31, E32) ----
stop_proxy
MKTOK=target/debug/examples/make_token
cargo build -q -p veritell-privacypass --example make_token || { echo "could not build the token helper"; exit 1; }
# A test issuer and a second one that the gateway is not told about.
# PKCS#8 explicitly: OpenSSL 3's genpkey writes an RSA key as PKCS#1 in DER,
# LibreSSL as PKCS#8, and the token helper (ring) takes PKCS#8 only.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 2>/dev/null | openssl pkcs8 -topk8 -nocrypt -outform DER -out "$WORK/issuer.der"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 2>/dev/null | openssl pkcs8 -topk8 -nocrypt -outform DER -out "$WORK/stranger.der"
ISSUER_KEY=$("$MKTOK" spki < "$WORK/issuer.der")
"$BIN" --cert "$CERT" --key "$KEY" --listen "127.0.0.1:$PORT" --upstream "127.0.0.1:$ORIGIN_PORT" \
  --policy scripts/e2e_policy.yaml --privacy-pass-issuer "issuer.e2e.test=$ISSUER_KEY" >"$WORK/pass.log" 2>"$WORK/pass.err" &
PROXY=$!; PIDS+=("$PROXY"); wait_port "$PORT"
check "E31 issuer key accepted at start"         "$(cat "$WORK/pass.err")" 'Privacy Pass tokens accepted from 1 issuer keys'
challenge_of() { tr -d '\r' | sed -n 's/^www-authenticate: PrivateToken challenge="\([A-Za-z0-9_=-]*\)".*/\1/p' | head -1; }
last_outcome() { tail -1 "$WORK/pass.log" | sed -n 's/.*"outcome":"\([a-z_]*\)".*/\1/p'; }

r=$(curl -sk --http2 -D - "$URL/products?id=7" | tr -d '\r')
check "E31 a challenge with an issuer configured is a 401" "$r" '^HTTP/2 401'
check "E31 it names the scheme, a challenge and the key" "$r" "^www-authenticate: PrivateToken challenge=\"[A-Za-z0-9_=-]*\", token-key=\"$ISSUER_KEY\"\$"
check "E31 the page is still there for everyone else" "$r" 'Checking your browser'
check "E31 logged as an ordinary challenge"      "$(last_outcome)" '^challenged$'
ch=$(printf '%s\n' "$r" | challenge_of)
check "E31 the challenge names no origin (Safari answers no other)" \
  "$(python3 -c 'import base64,sys; c=base64.urlsafe_b64decode(sys.argv[1]+"="*(-len(sys.argv[1])%4)); print(c[-2:].hex(), c[:2].hex())' "$ch")" '^0000 0002$'
tok=$("$MKTOK" token "$ch" < "$WORK/issuer.der")
check "E31 the helper made a token"              "$tok" '^PrivateToken token="[A-Za-z0-9_=-]*"$'

code=$(curl -sk --http2 -o "$WORK/light.html" -D "$WORK/light.hdr" -w '%{http_code}' -H "authorization: $tok" "$URL/products?id=7")
check "E31 a valid token is taken: the light page (403)" "$code" '403'
refute "E31 no second token challenge"           "$(cat "$WORK/light.hdr")" 'www-authenticate'
check "E31 logged as redeemed"                   "$(last_outcome)" '^token_redeemed$'
check "E31 the score is what it was"             "$(tail -1 "$WORK/pass.log")" '"class":"automated"'
check "E31 the page still runs the probe"        "$(cat "$WORK/light.html")" '/__veritell/probe.js'
read -r challenge counter < <(python3 scripts/solve.py < "$WORK/light.html")
hdrs=$(curl -sk --http2 -D - -o /dev/null -c "$WORK/passjar" --data-urlencode "challenge=$challenge" \
  --data-urlencode "counter=$counter" --data-urlencode "return_to=/products?id=7" "$URL/__veritell/verify")
check "E31 the light page's challenge is solved" "$hdrs" 'HTTP/2 303'
check "E31 and the session reaches the origin"   "$(curl -sk --http2 -b "$WORK/passjar" "$URL/products?id=7")" '"origin": true'
sess=$(sed 's/^#HttpOnly_//' "$WORK/passjar" | awk -F'\t' 'NF>=7 && $6=="__pal" {print $6"="$7}' | head -1)
check "E31 the session also counts in a second cookie field (HTTP/2 may split them)" \
  "$(curl -sk --http2 -H 'cookie: unrelated=1' -H "cookie: $sess" "$URL/products?id=7")" '"origin": true'

code=$(curl -sk --http2 -o /dev/null -w '%{http_code}' -H "authorization: $tok" "$URL/products?id=7")
check "E31 the same token a second time is refused" "$code $(last_outcome)" '^401 token_replayed$'

# E31: on a page load in Safari the page waits for the token before leaving.
SAFARI_UA="Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.2 Mobile/15E148 Safari/604.1"
check "E31 Safari loading a page: the page waits for a token" \
  "$(curl -sk --http2 -A "$SAFARI_UA" -H 'sec-fetch-mode: navigate' "$URL/products?id=7")" 'data-probe data-wait="1500"'
refute "E31 Chrome loading a page: no wait"      "$(curl -sk --http2 -A "$CHROME_UA" -H 'sec-fetch-mode: navigate' "$URL/products?id=7")" 'data-probe data-wait='
refute "E31 Safari's script request: no wait"    "$(curl -sk --http2 -A "$SAFARI_UA" -H 'sec-fetch-mode: cors' "$URL/products?id=7")" 'data-probe data-wait='

# E31: a script's request with a token goes to the origin; a page load gets the page.
tok2=$("$MKTOK" token "$ch" < "$WORK/issuer.der")
r=$(curl -sk --http2 -H "authorization: $tok2" -H 'sec-fetch-mode: cors' "$URL/products?id=7")
check "E31 a script's request with a token reaches the origin" "$r" '"origin": true'
check "E31 the origin is told a token let it through" "$r" '"x-veritell-token": "privacy-pass"'
check "E31 logged as passed on a token"          "$(last_outcome)" '^token_passed$'
check "E31 that token is spent"                  "$(curl -sk --http2 -o /dev/null -w '%{http_code}' -H "authorization: $tok2" -H 'sec-fetch-mode: cors' "$URL/products?id=7") $(last_outcome)" '^401 token_replayed$'
refute "E31 a client cannot claim it"            "$(curl -sk --http2 -H 'x-veritell-token: privacy-pass' -H 'sec-fetch-mode: cors' -A "$CHROME_UA" "$URL/open/x")" '"x-veritell-token"'
tok3=$("$MKTOK" token "$ch" < "$WORK/issuer.der")
check "E31 a page load with a token still gets the light page" \
  "$(curl -sk --http2 -o /dev/null -w '%{http_code}' -H "authorization: $tok3" -H 'sec-fetch-mode: navigate' "$URL/products?id=7") $(last_outcome)" '^403 token_redeemed$'

# E32: tokens that must not be taken. Each gets the full challenge again.
refused() { # name, expected outcome, authorization value
  local code; code=$(curl -sk --http2 -o "$WORK/refused.html" -w '%{http_code}' -H "authorization: $3" "$URL/products?id=7")
  check "E32 $1" "$code $(last_outcome) $(grep -q 'Checking your browser' "$WORK/refused.html" && echo page)" "^401 $2 page\$"
}
other=$(curl -sk --http2 -D - -o /dev/null -H 'host: other.example' "$URL/products?id=7" | challenge_of)
refute "E32 another site's challenge is another challenge" "$other" "^$ch\$"
refused "a token for another origin"             token_wrong_challenge "$("$MKTOK" token "$other" < "$WORK/issuer.der")"
refused "a token from an issuer that is not listed" token_unknown_issuer "$("$MKTOK" token "$ch" < "$WORK/stranger.der")"
fresh=$("$MKTOK" token "$ch" < "$WORK/issuer.der")
refused "a token with one character changed"     token_invalid "$(printf '%s' "$fresh" | sed 's/\(token="....\)\(.\)\(.\)/\1\3\2/')"
refused "a token cut short"                      token_invalid "$(printf '%s' "$fresh" | cut -c1-200)\""
refused "a token that is not base64"             token_invalid 'PrivateToken token="!!!!"'
refused "the scheme with no token"               token_invalid 'PrivateToken realm="x"'
refused "another scheme is not looked at"        challenged 'Basic dXNlcjpwYXNz'
check "E32 the unchanged token is still good"    "$(curl -sk --http2 -o /dev/null -w '%{http_code}' -H "authorization: $fresh" "$URL/products?id=7") $(last_outcome)" '^403 token_redeemed$'
check "E32 a route with no challenge is untouched" "$(curl -sk --http2 -o /dev/null -w '%{http_code}' -H "authorization: $tok" "$URL/open/x")" '200'

# ---- Phase 3 wave C: sharing between two gateways (E33, E34), the admin token (E35) ----
stop_proxy
PORT2=${PORT2:-8444}
export VERITELL_SHARE_KEY="e2e-share-secret-0123456789abcdef0123456789"
SHARE_SEED_HEX=$(printf '0b%.0s' $(seq 1 32))
SHARE_SEED=$(python3 -c 'import base64,sys; print(base64.urlsafe_b64encode(bytes.fromhex(sys.argv[1])).decode().rstrip("="))' "$SHARE_SEED_HEX")
SHARE_PUB=$("$BUNDLE" pubkey "$SHARE_SEED_HEX")
ADMIN_TOKEN="e2e-admin-token-$(openssl rand -hex 12)"
SHARED="$WORK/share.bundle"; : >"$WORK/shareb.err"
# The exporting gateway, in shadow mode, with its dashboard behind a token.
VERITELL_ADMIN_TOKEN="$ADMIN_TOKEN" VERITELL_SHARE_SEED="$SHARE_SEED" \
"$BIN" --cert "$CERT" --key "$KEY" --listen "127.0.0.1:$PORT" --trusted-proxy 127.0.0.1 \
  --admin "127.0.0.1:$ADMIN_PORT" --share-export "$SHARED" --share-min-networks 5 --share-interval 1 \
  >"$WORK/sharea.log" 2>"$WORK/sharea.err" &
PROXY=$!; PIDS+=("$PROXY"); wait_port "$PORT"; wait_port "$ADMIN_PORT"
check "E33 sharing is on only where asked"       "$(cat "$WORK/sharea.err")" 'sharing on (export: yes, import: no)'
RARE_UA="Wget/1.21.4"
CURL_UA=$(curl --version | head -1 | awk '{print "curl/" $2}')
# Requests forwarded by a trusted proxy carry no handshake of the client's
# own, so they are never noted for sharing, from however many networks.
PROXIED_UA="python-requests/2.32.3"
for n in 120 121 122 123 124 125 126; do curl -sk --http2 -o /dev/null -A "$PROXIED_UA" -H "x-forwarded-for: 198.18.$n.9" "$URL/"; done
check "E33 proxied requests are judged automated" "$(grep -c '"class":"automated".*"user_agent":"python-requests' "$WORK/sharea.log")" '^7$'
# Six real source networks need loopback aliases, which only an
# administrator can add (macOS: sudo ifconfig lo0 alias 127.0.N.1 for N in
# 100-105 and 110-111; Linux routes all of 127/8 already).
aliases=yes
for n in 100 101 102 103 104 105 110 111; do
  curl -s --interface "127.0.$n.1" -o /dev/null --max-time 2 "http://127.0.0.1:$ADMIN_PORT/" 2>/dev/null || aliases=no
done
if [ "$aliases" = yes ]; then
  for n in 100 101 102 103 104 105; do curl -sk --http2 -o /dev/null --interface "127.0.$n.1" "$URL/"; done
  r=$(curl -sk --http2 -A "$RARE_UA" --interface 127.0.110.1 "$URL/")
  curl -sk --http2 -o /dev/null -A "$RARE_UA" --interface 127.0.111.1 "$URL/"
  check "E33 the rare client is judged automated too" "$r" '"class": "automated"'
  sleep 1.2
  for _ in $(seq 1 40); do tail -1 "$WORK/sharea.err" | grep -q 'share export written: 1 fingerprints' && break; sleep 0.1; done
  check "E33 the export lists one fingerprint"   "$(cat "$WORK/sharea.err")" 'share export written: 1 fingerprints'
  hashes=$(python3 scripts/share_check.py hashes "$WORK/sharea.log" "$SHARED" "$CURL_UA" "$RARE_UA")
  check "E33 the widely seen fingerprint is in the bundle" "$hashes" "^$CURL_UA: present\$"
  check "E33 a rare fingerprint is not"          "$hashes" "^$RARE_UA: absent\$"
  # E34: nothing that identifies a client in what is written.
  leaks=$(python3 scripts/share_check.py leaks "$WORK/sharea.log" "$SHARED" \
    127.0.100.1 127.0.101.1 127.0.102.1 127.0.103.1 127.0.104.1 127.0.105.1 127.0.110.1 127.0.111.1 \
    198.18.120.9 "$VERITELL_SHARE_KEY")
  check "E34 the search had fingerprints to look for" "$(grep -c '"ja4":"t13' "$WORK/sharea.log")" '^[1-9]'
  check "E34 no address, User-Agent, fingerprint or unkeyed hash in the bundle" "${leaks:-clean}" '^clean$'

  # The importing gateway, reading its own copy: the first one rewrites
  # the export every second.
  cp "$SHARED" "$WORK/import.bundle"
  "$BIN" --cert "$CERT" --key "$KEY" --listen "127.0.0.1:$PORT2" \
    --share-import "$WORK/import.bundle" --share-import-key "$SHARE_PUB" >"$WORK/shareb.log" 2>"$WORK/shareb.err" &
  PROXY2=$!; PIDS+=("$PROXY2"); wait_port "$PORT2"
  for _ in $(seq 1 40); do grep -q 'share bundle version' "$WORK/shareb.err" && break; sleep 0.1; done
  check "E33 the second gateway takes the bundle" "$(cat "$WORK/shareb.err")" 'share bundle version [0-9]* taken: 1 fingerprints'
  r=$(curl -sk --http2 "https://localhost:$PORT2/")
  check "E33 the reported fingerprint is a hint there" "$r" '"id": "shared_fp_reported"'
  check "E33 worth ten points"                   "$(printf '%s' "$r" | tr -d ' \n' | grep -o '{[^{}]*"id":"shared_fp_reported"[^{}]*}')" '"penalty":10'
  check "E33 with no class of its own"           "$(printf '%s' "$r" | tr -d ' \n' | grep -o '{[^{}]*"id":"shared_fp_reported"[^{}]*}')" '"class_hint":null'
  refute "E33 the rare fingerprint is not reported" "$(curl -sk --http2 -A "$RARE_UA" "https://localhost:$PORT2/")" 'shared_fp_reported'
  refute "E33 nor is a different client"         "$(curl -sk --http2 -A "$CHROME_UA" "https://localhost:$PORT2/")" 'shared_fp_reported'
  # A bundle signed by another key is refused and the one held is kept.
  "$BUNDLE" seal "$WRONG_SEED" 99999999999 "$(date +%s)" "$(( $(date +%s) + 3600 ))" "share_v1.json=/dev/null" >"$WORK/forged" 2>/dev/null
  sleep 1.1; cp "$WORK/forged" "$WORK/import.bundle"
  for _ in $(seq 1 40); do grep -q 'share bundle refused' "$WORK/shareb.err" && break; sleep 0.1; done
  check "E33 a bundle from an unknown key is refused" "$(cat "$WORK/shareb.err")" 'share bundle refused, keeping version'
  check "E33 and the report is still there"        "$(curl -sk --http2 "https://localhost:$PORT2/")" 'shared_fp_reported'
  kill -INT "$PROXY2" 2>/dev/null
else
  echo "SKIP  E33 E34 sharing across networks: no loopback aliases 127.0.100-105.1 and 127.0.110-111.1"
  sleep 1.5
  check "E33 the export ran"                     "$(cat "$WORK/sharea.err")" 'share export written: 0 fingerprints'
  refute "E33 proxied requests are not shared"   "$(cat "$WORK/sharea.err")" 'share export written: [1-9]'
fi

# E35: the admin listener with a token.
ADMIN="http://127.0.0.1:$ADMIN_PORT"
codes=""
for path in / /api/events /api/summary /api/events?limit=1 /nothing-here; do
  codes="$codes $(curl -s -o /dev/null -w '%{http_code}' "$ADMIN$path")"
done
check "E35 every path refuses without the token" "$codes" '^ 401 401 401 401 401$'
check "E35 the refusal asks for Basic"           "$(curl -s -D - -o /dev/null "$ADMIN/" | tr -d '\r')" '^www-authenticate: Basic realm="veritell admin"'
check "E35 a wrong token is refused"             "$(curl -s -o /dev/null -w '%{http_code}' -H 'authorization: Bearer wrong-token-0123456789' "$ADMIN/api/events")" '401'
check "E35 the token as a bearer is accepted"    "$(curl -s -o /dev/null -w '%{http_code}' -H "authorization: Bearer $ADMIN_TOKEN" "$ADMIN/api/events")" '200'
check "E35 and as a Basic password"              "$(curl -s -o /dev/null -w '%{http_code}' -u "admin:$ADMIN_TOKEN" "$ADMIN/")" '200'
check "E35 the start-up line says so"            "$(cat "$WORK/sharea.err")" 'dashboard on http://127.0.0.1:[0-9]* (token required)'
refute "E35 the token is never logged"           "$(cat "$WORK/sharea.log" "$WORK/sharea.err")" "$ADMIN_TOKEN"
check "E35 a token that is too short stops start-up" \
  "$(VERITELL_ADMIN_TOKEN=short "$BIN" --cert "$CERT" --key "$KEY" --listen "127.0.0.1:$PORT2" --admin "127.0.0.1:9096" 2>&1 >/dev/null; echo "exit $?")" 'VERITELL_ADMIN_TOKEN must be at least 16 bytes'

# E35: with a token the admin listener may bind every address (a container's
# port, published on the host's loopback). It answers to loopback names only.
PORT4=${PORT4:-8446}; ANY_ADMIN_PORT=${ANY_ADMIN_PORT:-9088}
VERITELL_ADMIN_TOKEN="$ADMIN_TOKEN" "$BIN" --cert "$CERT" --key "$KEY" --listen "127.0.0.1:$PORT4" --admin "0.0.0.0:$ANY_ADMIN_PORT" \
  >"$WORK/anyadmin.log" 2>"$WORK/anyadmin.err" &
ANYGW=$!; PIDS+=("$ANYGW"); wait_port "$ANY_ADMIN_PORT"
ANY="http://127.0.0.1:$ANY_ADMIN_PORT"
check "E35 all-addresses bind starts with a token" "$(cat "$WORK/anyadmin.err")" 'dashboard on http://0.0.0.0:[0-9]* (token required) (not loopback'
check "E35 and still refuses without the token"   "$(curl -s -o /dev/null -w '%{http_code}' "$ANY/api/events")" '401'
check "E35 and answers with it on 127.0.0.1"      "$(curl -s -o /dev/null -w '%{http_code}' -u "admin:$ADMIN_TOKEN" "$ANY/")" '200'
check "E35 and on localhost"                      "$(curl -s -o /dev/null -w '%{http_code}' -u "admin:$ADMIN_TOKEN" "http://localhost:$ANY_ADMIN_PORT/api/summary")" '200'
check "E35 another Host is misdirected"           "$(curl -s -o /dev/null -w '%{http_code}' -u "admin:$ADMIN_TOKEN" -H "host: attacker.example:$ANY_ADMIN_PORT" "$ANY/")" '421'
check "E35 so is 0.0.0.0 as a Host"               "$(curl -s -o /dev/null -w '%{http_code}' -u "admin:$ADMIN_TOKEN" -H "host: 0.0.0.0:$ANY_ADMIN_PORT" "$ANY/")" '421'
refute "E35 the token is not logged there either" "$(cat "$WORK/anyadmin.log" "$WORK/anyadmin.err")" "$ADMIN_TOKEN"
kill -INT "$ANYGW" 2>/dev/null; for _ in $(seq 1 30); do nc -z 127.0.0.1 "$ANY_ADMIN_PORT" 2>/dev/null || break; sleep 0.1; done

# E39: what is written for an address (--ip-mode). Scoring is unchanged.
PORT3=${PORT3:-8445}; IP_ADMIN_PORT=${IP_ADMIN_PORT:-9089}
for mode in keyed truncated; do
  "$BIN" --cert "$CERT" --key "$KEY" --listen "127.0.0.1:$PORT3" --ip-mode "$mode" --admin "127.0.0.1:$IP_ADMIN_PORT" \
    >"$WORK/ip_$mode.log" 2>"$WORK/ip_$mode.err" &
  IPGW=$!; PIDS+=("$IPGW"); wait_port "$PORT3"
  curl -sk --http2 -o /dev/null -A "$CHROME_UA" "https://localhost:$PORT3/"
  curl -sk --http2 -o /dev/null -A "python-requests/2.32" "https://localhost:$PORT3/a"
  printf 'not a report' | curl -sk --http2 -o /dev/null -A "$CHROME_UA" --data-binary @- "https://localhost:$PORT3/__veritell/probe"
  sleep 0.3
  curl -s "http://127.0.0.1:$IP_ADMIN_PORT/api/events?limit=50" >"$WORK/ip_$mode.api"
  kill -INT "$IPGW" 2>/dev/null; for _ in $(seq 1 30); do nc -z 127.0.0.1 "$PORT3" 2>/dev/null || break; sleep 0.1; done
done
check  "E39 keyed: log lines carry a keyed address"   "$(cat "$WORK/ip_keyed.log")" '"ip":"k:[0-9a-f]\{32\}"'
check  "E39 keyed: one address, one value in a day"   "$(grep -o '"ip":"[^"]*"' "$WORK/ip_keyed.log" | sort -u | wc -l | tr -d ' ')" '^1$'
check  "E39 keyed: the probe report is logged too"    "$(cat "$WORK/ip_keyed.log")" '"kind":"probe".*"ip":"k:\|"ip":"k:[^"]*".*"kind":"probe"'
refute "E39 keyed: the address is in no log line"     "$(cat "$WORK/ip_keyed.log")" '127\.0\.0\.1'
check  "E39 keyed: the dashboard has the events"      "$(cat "$WORK/ip_keyed.api")" '"ip":"k:'
refute "E39 keyed: nor in the dashboard"              "$(cat "$WORK/ip_keyed.api")" '127\.0\.0\.1'
check  "E39 keyed: the scraper is still automated"    "$(grep 'python-requests' "$WORK/ip_keyed.log")" '"class":"automated"'
check  "E39 truncated: the /24 is written"            "$(cat "$WORK/ip_truncated.log")" '"ip":"127\.0\.0\.0/24"'
refute "E39 truncated: the address is not"            "$(cat "$WORK/ip_truncated.log") $(cat "$WORK/ip_truncated.api")" '127\.0\.0\.1'
check  "E39 an unknown mode stops start-up" \
  "$("$BIN" --cert "$CERT" --key "$KEY" --listen "127.0.0.1:$PORT3" --ip-mode hashed 2>&1 >/dev/null; echo "exit $?")" '--ip-mode: "hashed" is not full, truncated or keyed'
refute "E39 no panics"                                "$(cat "$WORK/ip_keyed.err" "$WORK/ip_truncated.err")" 'panicked'

# E41: clients that hold connections by sending slowly.
"$BIN" --cert "$CERT" --key "$KEY" --listen "127.0.0.1:$PORT3" --header-timeout 3 --max-conns-per-network 3 \
  >"$WORK/slow.log" 2>"$WORK/slow.err" &
SLOWGW=$!; PIDS+=("$SLOWGW"); wait_port "$PORT3"
check  "E41 a trickled request is cut off at the header deadline" "$(python3 scripts/slow_check.py slow "$PORT3")" '^closed after [345]s$'
cap=$(python3 scripts/slow_check.py cap "$PORT3" 3)
check  "E41 a fourth connection from one address is closed at once" "$cap" 'extra closed'
check  "E41 the three before it stay open"        "$cap" 'held open'
check  "E41 and it is logged without the address" "$(cat "$WORK/slow.log")" '"kind":"conn_refused","reason":"per_network_cap"'
sleep 3.5
check  "E41 places are given back"               "$(curl -sk -o /dev/null -w '%{http_code}' --http1.1 -A "$CHROME_UA" "https://localhost:$PORT3/")" '^200$'
check  "E41 HTTP/2 is unaffected"                "$(curl -sk -o /dev/null -w '%{http_code}' --http2 -A "$CHROME_UA" "https://localhost:$PORT3/")" '^200$'
check  "E41 a keep-alive connection serves a second request" \
  "$(curl -sk -o /dev/null -o /dev/null -w '%{http_code}\n' --http1.1 -A "$CHROME_UA" "https://localhost:$PORT3/a" "https://localhost:$PORT3/b" | tr '\n' ' ')" '^200 200 $'
refute "E41 no panics"                           "$(cat "$WORK/slow.err")" 'panicked'
kill -INT "$SLOWGW" 2>/dev/null; for _ in $(seq 1 30); do nc -z 127.0.0.1 "$PORT3" 2>/dev/null || break; sleep 0.1; done

# ---- Phase 4 wave A: state that survives a restart (E36 to E38) ----
U3="https://localhost:$PORT3"
STATE_A="$WORK/state-a"; STATE_B="$WORK/state-b"; mkdir -p "$STATE_A" "$STATE_B"
cat > "$WORK/agents3.json" <<'JSON'
{"agents":[{"name":"rfc-test-agent","keys":[{"kty":"OKP","crv":"Ed25519","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}]}]}
JSON
start3() { # log name, then extra arguments
  local name=$1; shift
  "$BIN" --cert "$CERT" --key "$KEY" --listen "127.0.0.1:$PORT3" --upstream "127.0.0.1:$ORIGIN_PORT" --state-flush 1 "$@" \
    >"$WORK/$name.log" 2>"$WORK/$name.err" &
  GW3=$!; PIDS+=("$GW3"); wait_port "$PORT3"
}
stop3() { kill -9 "$GW3" 2>/dev/null; wait "$GW3" 2>/dev/null; for _ in $(seq 1 30); do nc -z 127.0.0.1 "$PORT3" 2>/dev/null || break; sleep 0.1; done; }
agent3() {
  local hs=() line
  while IFS= read -r line; do hs+=(-H "$line"); done < <("$SIGN" "localhost:$PORT3" "$(date +%s)" rfc)
  curl -sk --http2 -o /dev/null -w '%{http_code}' "${hs[@]}" -H 'x-forwarded-for: 198.51.100.70' "$@"
}
# --ip-mode keyed, as the rollout kit runs it: the saved dashboard events
# (events.state) then hold keyed values. With `full` they hold addresses,
# as documented for --ip-mode (decided 2026-11-12).
QARGS=(--policy scripts/e2e_agents_policy.yaml --trusted-proxy 127.0.0.1 --wba-agents "$WORK/agents3.json" --state-dir "$STATE_A" --ip-mode keyed)

# E36: a quota half used, a graceful shutdown, a restart.
start3 quota1 "${QARGS[@]}"
for i in 1 2 3; do agent3 "$U3/quota/$i" >/dev/null; done
check "E36 three of seven taken"                 "$(cat "$WORK/quota1.log")" '"quota_left":5'
kill -TERM "$GW3"
for _ in $(seq 1 50); do grep -q 'state saved on shutdown' "$WORK/quota1.err" && break; sleep 0.1; done
check "E36 saved on a graceful shutdown"         "$(cat "$WORK/quota1.err")" 'veritell: state saved on shutdown$'
stop3
check "E36 the files are private"                "$(stat -f '%Lp' "$STATE_A/quota.state" 2>/dev/null || stat -c '%a' "$STATE_A/quota.state")" '^600$'
refute "E36 no address in the state files"       "$(cat "$STATE_A"/*.state | LC_ALL=C tr -c '[:print:]' '.')" '198\.51\.100'
start3 quota2 "${QARGS[@]}"
check "E36 loaded at start"                      "$(cat "$WORK/quota2.err")" 'state quota loaded: 1 identities'
agent3 "$U3/quota/4" >/dev/null
check "E36 the day goes on where it was: four left before this one" "$(cat "$WORK/quota2.log")" '"quota_left":4'
for i in 5 6 7; do agent3 "$U3/quota/$i" >/dev/null; done
check "E36 and runs out on the seventh"          "$(agent3 "$U3/quota/8")" '^403$'
stop3

# E37: a redeemed token, a fast shutdown after the periodic save, a restart.
PARGS=(--policy scripts/e2e_policy.yaml --privacy-pass-issuer "issuer.e2e.test=$ISSUER_KEY" --state-dir "$STATE_B")
start3 pass1 "${PARGS[@]}"
ch3=$(curl -sk --http2 -D - -o /dev/null "$U3/products?id=7" | challenge_of)
tok3a=$("$MKTOK" token "$ch3" < "$WORK/issuer.der")
check "E37 a token is redeemed"                  "$(curl -sk --http2 -o /dev/null -w '%{http_code}' -H "authorization: $tok3a" "$U3/products?id=7") $(tail -1 "$WORK/pass1.log" | sed -n 's/.*"outcome":"\([a-z_]*\)".*/\1/p')" '^403 token_redeemed$'
sleep 1.5
kill -INT "$GW3"; stop3
check "E37 the periodic save wrote the token store" "$(ls "$STATE_B")" 'used-tokens.state'
start3 pass2 "${PARGS[@]}"
check "E37 loaded at start"                      "$(cat "$WORK/pass2.err")" 'state used-tokens loaded: 1 entries'
check "E37 the same token after the restart is refused" \
  "$(curl -sk --http2 -o /dev/null -w '%{http_code}' -H "authorization: $tok3a" "$U3/products?id=7") $(tail -1 "$WORK/pass2.log" | sed -n 's/.*"outcome":"\([a-z_]*\)".*/\1/p')" '^401 token_replayed$'
tok3b=$("$MKTOK" token "$ch3" < "$WORK/issuer.der")
check "E37 a new token for the same challenge is taken" \
  "$(curl -sk --http2 -o /dev/null -w '%{http_code}' -H "authorization: $tok3b" "$U3/products?id=7") $(tail -1 "$WORK/pass2.log" | sed -n 's/.*"outcome":"\([a-z_]*\)".*/\1/p')" '^403 token_redeemed$'
stop3

# E38: a torn file and a changed file.
head -c 30 "$STATE_A/quota.state" > "$STATE_A/quota.cut" && mv "$STATE_A/quota.cut" "$STATE_A/quota.state"
python3 -c 'import sys; p=sys.argv[1]; b=bytearray(open(p,"rb").read()); b[-1]^=1; open(p,"wb").write(b)' "$STATE_B/used-tokens.state"
start3 torn "${QARGS[@]}"
check "E38 a torn file is refused and the store starts empty" "$(cat "$WORK/torn.err")" 'state quota refused (state file refused: .*); starting empty, the file is kept as .refused'
check "E38 the file is kept aside"               "$(ls "$STATE_A")" 'quota.state.refused'
check "E38 the gateway serves"                   "$(curl -sk --http2 -o /dev/null -w '%{http_code}' -A "$CHROME_UA" "$U3/open/x")" '^200$'
check "E38 with a fresh day for the agent"       "$(agent3 "$U3/quota/9"; grep -o '"quota_left":[0-9]*' "$WORK/torn.log" | tail -1)" '"quota_left":7'
stop3
start3 changed "${PARGS[@]}"
check "E38 a changed file is refused"            "$(cat "$WORK/changed.err")" 'state used-tokens refused (state file refused: digest'
stop3
check "E38 an unwritable state directory stops start-up" \
  "$("$BIN" --cert "$CERT" --key "$KEY" --listen "127.0.0.1:$PORT3" --state-dir "$WORK/no-such-dir" 2>&1 >/dev/null; echo "exit $?")" '--state-dir: .* is not a directory'
refute "E36-E38 no panics"                      "$(cat "$WORK"/quota1.err "$WORK"/quota2.err "$WORK"/pass1.err "$WORK"/pass2.err "$WORK"/torn.err "$WORK"/changed.err)" 'panicked'

# ---- Phase 4: known-person marks (E42, gate G18) ----
export VERITELL_KNOWN_KEY="e2e-known-key-0123456789abcdef0123456789"
start3 known --policy scripts/e2e_policy.yaml
check  "E42 marks are on"                        "$(cat "$WORK/known.err")" 'known-person marks on'
link=$(python3 tools/known_link.py p01-test)
check  "E42 the tool makes a link"               "$link" '^/__veritell/known/p01-test/[0-9a-f]\{32\}$'
hdr=$(curl -sk --http2 -D - -o "$WORK/known.html" "$U3$link" | tr -d '\r')
check  "E42 the link sets the mark"              "$hdr" '^set-cookie: __Host-veritell-known=p01-test\.[0-9a-f]\{32\}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=7776000$'
check  "E42 and says what it did"                "$(cat "$WORK/known.html")" 'marked <b>p01-test</b>'
check  "E42 the enrolment is logged"             "$(cat "$WORK/known.log")" '"kind":"known_enrolled","known":"p01-test"'
mark=$(printf '%s\n' "$hdr" | sed -n 's/^set-cookie: \([^;]*\);.*/\1/p')
refute "E42 a forged link sets nothing"          "$(curl -sk --http2 -D - -o /dev/null "$U3/__veritell/known/p01-test/00000000000000000000000000000000" | tr -d '\r')" 'set-cookie: __Host-veritell-known'
refute "E42 nor does another label with this mac" "$(curl -sk --http2 -D - -o /dev/null "$U3/__veritell/known/p02-test/${link##*/}" | tr -d '\r')" 'set-cookie: __Host-veritell-known'
# G18: the same requests with and without the mark are judged the same.
for path in /products?id=7 /open/x /admin; do
  for ua in "$CHROME_UA" "python-requests/2.32"; do
    curl -sk --http2 -o /dev/null -A "$ua" "$U3$path"
    curl -sk --http2 -o /dev/null -A "$ua" -b "$mark" "$U3$path"
  done
done
curl -sk --http2 -o /dev/null -A "$CHROME_UA" -b "__Host-veritell-known=p01-test.ffffffffffffffffffffffffffffffff" "$U3/open/y"
sleep 0.3
same=$(python3 - "$WORK/known.log" <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1]) if l.startswith("{") and '"score"' in l]
rows = [r for r in rows if not r["path"].startswith("/__veritell/known/")]
keys = ("score", "class", "detections", "action", "outcome", "rule", "route", "enforced", "model")
pairs = list(zip(rows[0:12:2], rows[1:12:2]))
bad = [(a["path"], a["user_agent"]) for a, b in pairs if any(a.get(k) != b.get(k) for k in keys)]
marks = [(a.get("known"), b.get("known")) for a, b in pairs]
print("pairs=%d differ=%d marks=%s forged=%r" % (len(pairs), len(bad), sorted(set(marks)), rows[12].get("known")))
PY
)
check  "E42 six pairs, judged the same with and without the mark" "$same" '^pairs=6 differ=0 '
check  "E42 only the marked one carries the label" "$same" "marks=\[('', 'p01-test')\]"
check  "E42 a cookie with a wrong mac carries nothing" "$same" "forged=''"
# HTTP/2 lets a client send its cookies as several fields; all are read.
curl -sk --http2 -o /dev/null -A "$CHROME_UA" -H "cookie: other=1" -H "cookie: $mark" "$U3/split-cookies"
sleep 0.3
check  "E42 the mark in a second cookie field counts" "$(grep '"path":"/split-cookies"' "$WORK/known.log")" '"known":"p01-test"' 
stop3
unset VERITELL_KNOWN_KEY
check  "E42 a short key stops start-up" \
  "$(VERITELL_KNOWN_KEY=short "$BIN" --cert "$CERT" --key "$KEY" --listen "127.0.0.1:$PORT3" 2>&1 >/dev/null; echo "exit $?")" 'VERITELL_KNOWN_KEY must be at least 32 bytes'
refute "E42 no panics"                           "$(cat "$WORK/known.err")" 'panicked'

# E43: the origin is told who connected.
start3 xff --policy scripts/e2e_policy.yaml
r=$(curl -sk --http2 -A "$CHROME_UA" "$U3/open/x")
check  "E43 the origin gets the client's address" "$r" '"x-forwarded-for": "127.0.0.1"'
check  "E43 and the scheme"                       "$r" '"x-forwarded-proto": "https"'
r=$(curl -sk --http2 -A "$CHROME_UA" -H 'x-forwarded-for: 6.6.6.6' -H 'x-forwarded-proto: http' "$U3/open/x")
check  "E43 a forged entry stays in front of the real one" "$r" '"x-forwarded-for": "6.6.6.6, 127.0.0.1"'
check  "E43 a forged scheme is replaced"          "$r" '"x-forwarded-proto": "https"'
stop3

# ---- Phase 4: passive probe injection (E44) ----
start3 inject --inject-probe on
SNIP='<script src="/__veritell/probe.js" async></script><script src="/__veritell/behavior.js" async></script>'
page=$(curl -sk --http2 -A "$CHROME_UA" -H 'sec-fetch-dest: document' "$U3/html/page")
check  "E44 a page load gets the scripts before </head>" "$page" "<title>t</title>$SNIP</head>"
check  "E44 the rest of the page is untouched"   "$page" '<body><p>origin page</p></body></html>$'
hdr=$(curl -sk --http2 -D - -o "$WORK/inj.html" -A "$CHROME_UA" "$U3/html/page" | tr -d '\r')
refute "E44 no stale length"                     "$hdr" '^content-length: 88$'
check  "E44 the changed page's ETag is weak"      "$hdr" '^etag: W/"v1"$'
check  "E44 an untouched page keeps its strong ETag" "$(curl -sk --http2 -D - -o /dev/null -A "$CHROME_UA" -H 'sec-fetch-dest: empty' "$U3/html/page" | tr -d '\r')" '^etag: "v1"$'
check  "E44 the length that arrives is the page's" "$(wc -c < "$WORK/inj.html" | tr -d ' ')" "^$((88 + ${#SNIP}))\$"
check  "E44 over HTTP/1.1 too"                   "$(curl -sk --http1.1 -A "$CHROME_UA" "$U3/html/page")" "$SNIP</head>"
refute "E44 not for a script's fetch"            "$(curl -sk --http2 -A "$CHROME_UA" -H 'sec-fetch-dest: empty' "$U3/html/page")" 'probe.js'
refute "E44 not for an iframe"                   "$(curl -sk --http2 -A "$CHROME_UA" -H 'sec-fetch-dest: iframe' "$U3/html/page")" 'probe.js'
refute "E44 not for a compressed page"           "$(curl -sk --http2 -A "$CHROME_UA" "$U3/html/gz")" 'probe.js'
refute "E44 not for a page with nowhere to put them" "$(curl -sk --http2 -A "$CHROME_UA" "$U3/html/notags")" 'probe.js'
check  "E44 not for JSON"                        "$(curl -sk --http2 -A "$CHROME_UA" "$U3/open/x")" '"origin": true'
big=$(curl -sk --http2 -A "$CHROME_UA" "$U3/html/big" | wc -c | tr -d ' ')
check  "E44 a page over the limit arrives whole and unchanged" "$big" "^$((40 + 600*1024 + 14))\$"
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
if [ -x "$CHROME" ]; then
  "$CHROME" --headless=new --disable-gpu --no-first-run --user-data-dir="$WORK/chrome-inject" --ignore-certificate-errors \
    --virtual-time-budget=8000 --dump-dom "$U3/html/page" >"$WORK/inject-dom.html" 2>/dev/null
  sleep 1
  check  "E44 in Chrome, the page shows"         "$(cat "$WORK/inject-dom.html")" 'origin page'
  check  "E44 in Chrome, the probe reports from it" "$(grep '"kind":"probe"' "$WORK/inject.log")" '"outcome":"probe_\(clean\|flagged\)"'
else
  echo "SKIP  E44 in Chrome: Google Chrome is not installed"
fi
stop3
start3 noinject
refute "E44 off by default"                      "$(curl -sk --http2 -A "$CHROME_UA" "$U3/html/page")" 'probe.js'
stop3
check  "E44 a wrong value stops start-up" \
  "$("$BIN" --cert "$CERT" --key "$KEY" --listen "127.0.0.1:$PORT3" --inject-probe yes 2>&1 >/dev/null; echo "exit $?")" '--inject-probe: "yes" is not on or off'
# E48: the AGPL source link on the gateway's own pages (section 13).
start3 source --source-url "https://code.example/fork?b=main&x=1"
check  "E48 a fork's own source URL"             "$(curl -sk --http2 "$U3/__veritell/challenge?return_to=/")" 'href="https://code.example/fork?b=main&amp;x=1"'
stop3
start3 nosource --source-url off
nosrc=$(curl -sk --http2 "$U3/__veritell/challenge?return_to=/")
refute "E48 off: no link"                        "$nosrc" 'Source code'
refute "E48 off: no name either"                 "$nosrc" 'Powered by'
stop3
check  "E48 a URL that isn't plain http(s) stops start-up" \
  "$("$BIN" --cert "$CERT" --key "$KEY" --listen "127.0.0.1:$PORT3" --source-url 'javascript:alert(1)' 2>&1 >/dev/null; echo "exit $?")" 'is not a plain http(s) URL'
refute "E44 no panics"                           "$(cat "$WORK/inject.err" "$WORK/noinject.err")" 'panicked'

# ---- Audit of Phases 0-3: a full single-use store is not the client's fault (E45) ----
# Not its fault, so no strike; but refused, because a full store can't tell a
# replay, and taking summaries then would let replays through (decided
# 2026-11-12).
start3 full --single-use-capacity 2
bn3() { curl -sk --http2 -A "$1" "$U3/__veritell/behavior.js" | sed -n 's/.*"nonce":"\([A-Za-z0-9_-]*\)".*/\1/p' | head -1; }
ps3() { printf '%s' "$2" | curl -sk --http2 -o /dev/null -w '%{http_code}' -A "$1" -H 'content-type: application/json' --data-binary @- "$U3/__veritell/behavior"; }
check  "E45 the first summary fills a place"     "$(ps3 filler/1 "$(summary "$(bn3 filler/1)")")" '^204$'
n2=$(bn3 filler/2)
check  "E45 the second fills the store"          "$(ps3 filler/2 "$(summary "$n2")")" '^204$'
check  "E45 with the store full, a new summary is refused" \
  "$(ps3 honest/9 "$(summary "$(bn3 honest/9)" moves=200 strokes=8 clicks=2 sized=2)")" '^403$'
sleep 0.3
refute "E45 and is not called spent"             "$(grep 'honest/9' "$WORK/full.log")" 'behavior_nonce_spent'
check  "E45 it is logged as the store being full" "$(grep 'honest/9' "$WORK/full.log")" '"outcome":"behavior_store_full"'
check  "E45 the operator is told"                "$(cat "$WORK/full.err")" 'behaviour nonces store is full'
# A nonce already in the store keeps its budget of three summaries.
ps3 filler/2 "$(summary "$n2")" >/dev/null; ps3 filler/2 "$(summary "$n2")" >/dev/null
check  "E45 a nonce in the store, used up, is still refused" "$(ps3 filler/2 "$(summary "$n2")")" '^403$'
sleep 0.3
check  "E45 as spent"                            "$(grep 'filler/2' "$WORK/full.log" | tail -1)" '"outcome":"behavior_nonce_spent"'
stop3

# ---- Audit of Phases 0-3: unverified crawler claims, the admin listener's Host (E46) ----
IP_ADMIN46=${IP_ADMIN46:-9086}
start3 crawl --admin "127.0.0.1:$IP_ADMIN46"
for ua in "Googlebot/2.1 (+http://www.google.com/bot.html)" "Googlebot-Image/1.0" "MyCrawler/1.0"; do
  curl -sk --http2 -o /dev/null -A "$ua" "$U3/crawl-check"
done
sleep 0.3
line() { grep '"path":"/crawl-check"' "$WORK/crawl.log" | grep -F "\"user_agent\":\"$1"; }
check  "E46 Googlebot from an unverifiable address is unverified" "$(line 'Googlebot/2.1')" 'bot_unverified'
check  "E46 so is Googlebot-Image (a hyphenated variant)"         "$(line 'Googlebot-Image')" 'bot_unverified'
refute "E46 and it is not scored a person"                         "$(line 'Googlebot-Image')" '"class":"human"'
check  "E46 a self-declared crawler too"                           "$(line 'MyCrawler')" 'bot_unverified'
check  "E46 the dashboard answers its own name" \
  "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$IP_ADMIN46/api/events")" '^200$'
check  "E46 and localhost" \
  "$(curl -s -o /dev/null -w '%{http_code}' -H "host: localhost:$IP_ADMIN46" "http://127.0.0.1:$IP_ADMIN46/api/events")" '^200$'
check  "E46 a rebinding page's name is refused, even without a token" \
  "$(curl -s -o /dev/null -w '%{http_code}' -H "host: rebind.example:$IP_ADMIN46" "http://127.0.0.1:$IP_ADMIN46/api/events")" '^421$'
stop3

refute "no panics in the proxy log"              "$(cat "$WORK/enforce.err" "$WORK/shadow.err" "$WORK/waveb.err" "$WORK/wavec.err" "$WORK/stranger.err" "$WORK/wavea.err" "$WORK/pass.err" "$WORK/sharea.err" "$WORK/shareb.err")" 'panicked'

echo
[ "$skips" -gt 0 ] && echo "$skips skipped: see the SKIP lines for why"
if [ "$fails" -eq 0 ]; then echo "ALL PASSED (logs in $WORK)"; else echo "$fails FAILED (logs in $WORK)"; fi
exit "$fails"
