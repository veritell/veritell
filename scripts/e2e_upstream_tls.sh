#!/usr/bin/env bash
# The gateway in front of an HTTPS upstream, and the probe
# injected into pages the upstream would compress. Needs a release build,
# curl, openssl and python3.  scripts/e2e_upstream_tls.sh
set -u
cd "$(dirname "$0")/.."
BIN=target/release/veritell
PORT=${PORT:-8543}
ORIGIN_PORT=${ORIGIN_PORT:-9543}
WORK=$(mktemp -d)
export VERITELL_SECRET="e2e-test-secret-0123456789abcdef0123456789"
CHROME_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
SNIP='<script src="/__veritell/probe.js" async></script><script src="/__veritell/behavior.js" async></script>'
fails=0
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill -INT "$p" 2>/dev/null; done; sleep 0.5; for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null; done; rm -rf "$WORK"; }
trap cleanup EXIT
check() { if printf '%s' "$2" | grep -q -- "$3"; then echo "PASS  $1"; else echo "FAIL  $1  (wanted: $3)"; fails=$((fails+1)); fi; }
refute() { if printf '%s' "$2" | grep -q -- "$3"; then echo "FAIL  $1  (unwanted: $3)"; fails=$((fails+1)); else echo "PASS  $1"; fi; }
wait_port() { for _ in $(seq 1 50); do nc -z 127.0.0.1 "$1" 2>/dev/null && return 0; sleep 0.1; done; echo "port $1 never opened"; exit 1; }
stop_proxy() { kill -INT "$PROXY" 2>/dev/null; for _ in $(seq 1 30); do nc -z 127.0.0.1 "$PORT" 2>/dev/null || return 0; sleep 0.1; done; kill -9 "$PROXY" 2>/dev/null; sleep 0.2; }

# A test CA, and an origin certificate from it for site.test and www.site.test.
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=veritell test CA" \
  -keyout "$WORK/ca.key" -out "$WORK/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=site.test" -keyout "$WORK/origin.key" -out "$WORK/origin.csr" >/dev/null 2>&1
printf 'subjectAltName=DNS:site.test,DNS:www.site.test\n' > "$WORK/san.ext"
openssl x509 -req -in "$WORK/origin.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" -CAcreateserial \
  -days 2 -extfile "$WORK/san.ext" -out "$WORK/origin.pem" >/dev/null 2>&1
# The gateway's own certificate (what visitors see), self-signed.
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=site.test" \
  -addext "subjectAltName=DNS:site.test,DNS:www.site.test,DNS:evil.test,IP:127.0.0.1" \
  -keyout "$WORK/gw.key" -out "$WORK/gw.pem" >/dev/null 2>&1
[ -f "$WORK/origin.pem" ] && [ -f "$WORK/gw.pem" ] || { echo "could not create the test certificates"; exit 1; }

python3 scripts/tls_origin.py "$ORIGIN_PORT" "$WORK/origin.pem" "$WORK/origin.key" "$WORK/origin.log" & PIDS+=("$!")
wait_port "$ORIGIN_PORT"

start_proxy() { # extra gateway arguments
  "$BIN" --cert "$WORK/gw.pem" --key "$WORK/gw.key" --listen "127.0.0.1:$PORT" \
    --upstream "127.0.0.1:$ORIGIN_PORT" "$@" >"$WORK/gw.log" 2>"$WORK/gw.err" &
  PROXY=$!; PIDS+=("$PROXY"); wait_port "$PORT"
}
# get <host name> <path> [curl args]: through the gateway, by name.
get() { local h=$1 p=$2; shift 2; curl -sk --max-time 10 --resolve "$h:$PORT:127.0.0.1" "$@" "https://$h:$PORT$p"; }
code() { local h=$1 p=$2; shift 2; curl -sk --max-time 10 -o /dev/null -w '%{http_code}' --resolve "$h:$PORT:127.0.0.1" "$@" "https://$h:$PORT$p"; }
last_log() { tail -1 "$WORK/origin.log" 2>/dev/null; }
lines() { wc -l < "$WORK/origin.log" 2>/dev/null | tr -d ' ' || echo 0; }

# ---- U1-U5: TLS to the upstream, checked against the test CA ----
start_proxy --upstream-tls on --upstream-ca "$WORK/ca.pem" --upstream-sni site.test --inject-probe on
r=$(get site.test /json -A "$CHROME_UA"); r=$(last_log)
check  "U1 a request reaches the TLS upstream"          "$r" '"path": "/json"'
check  "U1 SNI is the request's host name"              "$r" '"sni": "site.test"'
check  "U1 Host is passed on"                           "$r" '"host": "site.test'
r=$(get www.site.test /json -A "$CHROME_UA"); r=$(last_log)
check  "U2 another name on the certificate: its own SNI" "$r" '"sni": "www.site.test"'
r=$(curl -sk --max-time 10 -A "$CHROME_UA" "https://127.0.0.1:$PORT/json"); r=$(last_log)
check  "U3 an address as the host: --upstream-sni"      "$r" '"sni": "site.test"'
before=$(lines)
check  "U4 a name the certificate does not cover: 502"  "$(code evil.test /json -A "$CHROME_UA")" '^502$'
check  "U4 and no request reached the origin"           "$(lines)" "^$before\$"
r=$(get site.test /json -A "$CHROME_UA"); r=$(last_log)
check  "U5 X-Forwarded-For ends with the client"        "$r" '"x-forwarded-for": "127.0.0.1"'
check  "U5 X-Forwarded-Proto https"                     "$r" '"x-forwarded-proto": "https"'

# ---- U6-U9: injection into a page the upstream would compress ----
page=$(get site.test /html/page -A "$CHROME_UA" -H 'accept: text/html,application/xhtml+xml' -H 'accept-encoding: gzip, br' -H 'sec-fetch-dest: document')
check  "U6 a page load gets the scripts"                "$page" "<title>t</title>$SNIP</head>"
refute "U6 the origin was not asked to compress it"     "$(last_log)" '"accept-encoding"'
hdr=$(get site.test /html/page -D - -o /dev/null -A "$CHROME_UA" -H 'accept: text/html' -H 'accept-encoding: gzip' -H 'sec-fetch-dest: document' | tr -d '\r')
refute "U7 what the client gets is not marked gzip"     "$hdr" '^content-encoding: gzip'
get site.test /json -A "$CHROME_UA" -H 'accept: application/json' -H 'accept-encoding: gzip, br' -H 'sec-fetch-dest: empty' >/dev/null
check  "U8 a fetch keeps Accept-Encoding"               "$(last_log)" '"accept-encoding": "gzip, br"'
get site.test /app.js -A "$CHROME_UA" -H 'accept: */*' -H 'accept-encoding: gzip' >/dev/null
check  "U9 a GET without text/html in Accept keeps it"  "$(last_log)" '"accept-encoding": "gzip"'
stop_proxy

# ---- U10: injection off leaves Accept-Encoding alone ----
start_proxy --upstream-tls on --upstream-ca "$WORK/ca.pem" --inject-probe off
get site.test /html/page -A "$CHROME_UA" -H 'accept: text/html' -H 'accept-encoding: gzip' -H 'sec-fetch-dest: document' -o /dev/null
check  "U10 injection off: Accept-Encoding passed on"   "$(last_log)" '"accept-encoding": "gzip"'
stop_proxy

# ---- U11: no --upstream-ca, a private CA: the check fails, it is not skipped ----
start_proxy --upstream-tls on
before=$(lines)
check  "U11 an untrusted upstream certificate: 502"     "$(code site.test /json -A "$CHROME_UA")" '^502$'
check  "U11 and no request reached the origin"          "$(lines)" "^$before\$"
stop_proxy

# ---- U12: --upstream-tls off (the default) still speaks plain HTTP ----
start_proxy
check  "U12 TLS off against a TLS origin fails (plain HTTP sent)" "$(code site.test /json -A "$CHROME_UA")" '^502$'
stop_proxy

# ---- U14: --forwarded-for replace drops what the client wrote ----
start_proxy --upstream-tls on --upstream-ca "$WORK/ca.pem" --forwarded-for replace
r=$(get site.test /json -A "$CHROME_UA" -H 'x-forwarded-for: 6.6.6.6' -H 'x-real-ip: 6.6.6.6' -H 'forwarded: for=6.6.6.6'); r=$(last_log)
check  "U14 replace: X-Forwarded-For is the peer only"  "$r" '"x-forwarded-for": "127.0.0.1"'
check  "U14 replace: X-Real-IP is the peer"             "$r" '"x-real-ip": "127.0.0.1"'
refute "U14 replace: nothing the client wrote"          "$r" '6.6.6.6'
stop_proxy
start_proxy --upstream-tls on --upstream-ca "$WORK/ca.pem"
r=$(get site.test /json -A "$CHROME_UA" -H 'x-forwarded-for: 6.6.6.6'); r=$(last_log)
check  "U14 append (default): as before"                "$r" '"x-forwarded-for": "6.6.6.6, 127.0.0.1"'
stop_proxy

# ---- U15: --log-requests off writes no line per visitor ----
start_proxy --upstream-tls on --upstream-ca "$WORK/ca.pem" --inject-probe on --log-requests off
get site.test /u15-off-marker -A "$CHROME_UA" >/dev/null
get site.test /html/page -A "$CHROME_UA" -H 'accept: text/html' -H 'sec-fetch-dest: document' >/dev/null
sleep 0.5
check  "U15 off: the request still reaches the origin"  "$(last_log)" '"path": "/html/page"'
refute "U15 off: no request line on standard output"    "$(cat "$WORK/gw.log")" 'u15-off-marker'
refute "U15 off: no address in standard output"         "$(cat "$WORK/gw.log")" '"ip"'
check  "U15 off: start-up messages still on stderr"     "$(cat "$WORK/gw.err")" 'listening on'
stop_proxy
start_proxy --upstream-tls on --upstream-ca "$WORK/ca.pem"
get site.test /u15-on-marker -A "$CHROME_UA" >/dev/null
sleep 0.5
check  "U15 on (the default): the request line is there" "$(cat "$WORK/gw.log")" 'u15-on-marker'
stop_proxy

# ---- U16: a cached copy from before the gateway is not kept by a 304 ----
# The gateway weakens the ETag of every page it changes, so a page load with
# a strong If-None-Match holds a copy without the scripts: it is asked for
# in full. A weak one is the gateway's own copy: the 304 stands.
start_proxy --upstream-tls on --upstream-ca "$WORK/ca.pem" --inject-probe on
nav() { get site.test /html/etag -A "$CHROME_UA" -H 'accept: text/html' -H "sec-fetch-dest: $1" -H "if-none-match: $2" -o "$WORK/u16.body" -w '%{http_code}'; }
check  "U16 strong validator on a page load: 200"        "$(nav document '"v1"')" '^200$'
check  "U16   with the scripts"                          "$(cat "$WORK/u16.body")" "$SNIP</head>"
refute "U16   the origin was not given the validator"    "$(last_log)" 'if-none-match'
check  "U16   the page's ETag is weak"                   "$(get site.test /html/etag -D - -o /dev/null -A "$CHROME_UA" -H 'accept: text/html' -H 'sec-fetch-dest: document' | tr -d '\r')" '^etag: W/"v1"$'
check  "U16 the gateway's own weak validator: 304 stands" "$(nav document 'W/"v1"')" '^304$'
check  "U16 a list with a strong one: 200"               "$(nav document 'W/"v0", "v1"')" '^200$'
check  "U16 not a page load (a fetch): 304 stands"       "$(nav empty '"v1"')" '^304$'
stop_proxy
start_proxy --upstream-tls on --upstream-ca "$WORK/ca.pem" --inject-probe off
check  "U16 injection off: 304 stands"                   "$(nav document '"v1"')" '^304$'
stop_proxy

# ---- U13: arguments ----
err=$("$BIN" --cert "$WORK/gw.pem" --key "$WORK/gw.key" --listen "127.0.0.1:$PORT" --upstream "127.0.0.1:$ORIGIN_PORT" --upstream-tls maybe 2>&1)
check  "U13 --upstream-tls takes on or off only"        "$err" 'upstream-tls'
err=$("$BIN" --cert "$WORK/gw.pem" --key "$WORK/gw.key" --listen "127.0.0.1:$PORT" --upstream "127.0.0.1:$ORIGIN_PORT" --upstream-tls on --upstream-ca /nonexistent.pem 2>&1)
check  "U13 an unreadable --upstream-ca is refused at start" "$err" 'nonexistent.pem'
err=$("$BIN" --cert "$WORK/gw.pem" --key "$WORK/gw.key" --listen "127.0.0.1:$PORT" --log-requests maybe 2>&1)
check  "U13 --log-requests takes on or off only"      "$err" 'log-requests'
err=$("$BIN" --cert "$WORK/gw.pem" --key "$WORK/gw.key" --listen "127.0.0.1:$PORT" --forwarded-for both 2>&1)
check  "U13 --forwarded-for takes append or replace only" "$err" 'forwarded-for'
err=$("$BIN" --cert "$WORK/gw.pem" --key "$WORK/gw.key" --listen "127.0.0.1:$PORT" --upstream-tsl on 2>&1); rc=$?
check  "U13 an unknown flag is refused, not ignored"  "$err" 'unknown flag --upstream-tsl'
check  "U13   with exit code 2"                     "exit=$rc" '^exit=2$'
err=$("$BIN" --cert "$WORK/gw.pem" --key "$WORK/gw.key" --listen "127.0.0.1:$PORT" --upstream 2>&1)
check  "U13 a known flag still needs its value"       "$err" 'upstream needs a value'

echo
if [ "$fails" = 0 ]; then echo "ALL PASSED"; else echo "$fails FAILED"; fi
exit "$fails"
