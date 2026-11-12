#!/usr/bin/env bash
# Several sites behind one gateway: a certificate per name (--sni-dir) and an
# upstream per name (--upstream-host). Needs a release build, curl, openssl
# and python3.  scripts/e2e_sni.sh
set -u
cd "$(dirname "$0")/.."
BIN=target/release/veritell
PORT=${PORT:-8643}
ORIGIN_PORT=${ORIGIN_PORT:-9643}
STATIC_PORT=${STATIC_PORT:-9644}
WORK=$(mktemp -d)
export VERITELL_SECRET="e2e-test-secret-0123456789abcdef0123456789"
CHROME_UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
fails=0
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill -INT "$p" 2>/dev/null; done; sleep 0.5; for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null; done; rm -rf "$WORK"; }
trap cleanup EXIT
check() { if printf '%s' "$2" | grep -q -- "$3"; then echo "PASS  $1"; else echo "FAIL  $1  (wanted: $3)"; fails=$((fails+1)); fi; }
refute() { if printf '%s' "$2" | grep -q -- "$3"; then echo "FAIL  $1  (unwanted: $3)"; fails=$((fails+1)); else echo "PASS  $1"; fi; }
wait_port() { for _ in $(seq 1 50); do nc -z 127.0.0.1 "$1" 2>/dev/null && return 0; sleep 0.1; done; echo "port $1 never opened"; exit 1; }
stop_proxy() { kill -INT "$PROXY" 2>/dev/null; for _ in $(seq 1 30); do nc -z 127.0.0.1 "$PORT" 2>/dev/null || return 0; sleep 0.1; done; kill -9 "$PROXY" 2>/dev/null; sleep 0.2; }
cert() { # dir CN SAN...
  local d=$1 cn=$2; shift 2; mkdir -p "$d"
  local san; san=$(printf 'DNS:%s,' "$@"); san=${san%,}
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/CN=$cn" \
    -addext "subjectAltName=$san" -keyout "$d/privkey.pem" -out "$d/fullchain.pem" >/dev/null 2>&1
}
# The certificate a client is given for a server name ("" sends no SNI).
served() {
  if [ -n "$1" ]; then
    openssl s_client -connect "127.0.0.1:$PORT" -servername "$1" </dev/null 2>/dev/null | openssl x509 -noout -subject 2>/dev/null
  else
    openssl s_client -connect "127.0.0.1:$PORT" -noservername </dev/null 2>/dev/null | openssl x509 -noout -subject 2>/dev/null
  fi
}
get() { local h=$1 p=$2; shift 2; curl -sk --max-time 10 --resolve "$h:$PORT:127.0.0.1" "$@" "https://$h:$PORT$p"; }

# The default certificate (the existing site) and two more for other sites.
cert "$WORK/default" site.test site.test www.site.test
cert "$WORK/sni/veritell.test" veritell.test veritell.test www.veritell.test
cert "$WORK/sni/wild" wild.test '*.apps.test'
mkdir -p "$WORK/sni/not-a-pair" "$WORK/static"
printf '<!doctype html><html><head><title>launch</title></head><body><h1>static launch page</h1></body></html>' > "$WORK/static/index.html"

python3 scripts/echo_origin.py "$ORIGIN_PORT" >/dev/null 2>&1 & PIDS+=("$!")
python3 -m http.server "$STATIC_PORT" --bind 127.0.0.1 --directory "$WORK/static" >/dev/null 2>&1 & PIDS+=("$!")
wait_port "$ORIGIN_PORT"; wait_port "$STATIC_PORT"

start_proxy() {
  "$BIN" --cert "$WORK/default/fullchain.pem" --key "$WORK/default/privkey.pem" --listen "127.0.0.1:$PORT" \
    --upstream "127.0.0.1:$ORIGIN_PORT" "$@" >"$WORK/gw.log" 2>"$WORK/gw.err" &
  PROXY=$!; PIDS+=("$PROXY"); wait_port "$PORT"
}

# ---- S1-S5: the certificate follows the SNI name ----
start_proxy --sni-dir "$WORK/sni" --upstream-host "veritell.test=127.0.0.1:$STATIC_PORT,WWW.Veritell.test=127.0.0.1:$STATIC_PORT" --inject-probe on
check  "S1 the extra certificates are listed at start"   "$(cat "$WORK/gw.err")" 'certificate veritell.test served for veritell.test, www.veritell.test'
check  "S1 and the wildcard"                             "$(cat "$WORK/gw.err")" 'certificate wild served for \*.apps.test'
check  "S1 the per-name upstream is listed"              "$(cat "$WORK/gw.err")" 'requests for veritell.test go to http://127.0.0.1:'
check  "S2 the existing site keeps its certificate"      "$(served site.test)" 'CN *= *site.test'
check  "S2 and www"                                      "$(served www.site.test)" 'CN *= *site.test'
check  "S3 the new site gets its own certificate"        "$(served veritell.test)" 'CN *= *veritell.test'
check  "S3 and its www"                                  "$(served www.veritell.test)" 'CN *= *veritell.test'
check  "S3 a name is matched without case"               "$(served VERITELL.test)" 'CN *= *veritell.test'
check  "S4 a wildcard covers one label"                  "$(served x.apps.test)" 'CN *= *wild.test'
check  "S4 but not its parent"                           "$(served apps.test)" 'CN *= *site.test'
check  "S5 an unknown name gets the default"             "$(served other.test)" 'CN *= *site.test'
check  "S5 so does no SNI at all"                        "$(served "")" 'CN *= *site.test'

# ---- S6-S9: HTTP/2, routing by host name, the gateway still at work ----
check  "S6 HTTP/2 on a switched certificate"             "$(get veritell.test / -A "$CHROME_UA" -o /dev/null -w '%{http_version}')" '^2$'
check  "S6 and on the default one"                       "$(get site.test /json -A "$CHROME_UA" -o /dev/null -w '%{http_version}')" '^2$'
r=$(get veritell.test / -A "$CHROME_UA")
check  "S7 the new site's requests reach its upstream"   "$r" 'static launch page'
check  "S7 its pages get the probe"                      "$r" '/__veritell/probe.js'
check  "S7 www goes there too (names without case)"      "$(get www.veritell.test / -A "$CHROME_UA")" 'static launch page'
r=$(get site.test /json -A "$CHROME_UA")
check  "S8 the existing site still reaches its upstream" "$r" '"origin": true'
refute "S8 and never the new one"                        "$r" 'static launch page'
check  "S8 an unknown name goes to the main upstream"    "$(get other.test /json -A "$CHROME_UA")" '"origin": true'
line=$(grep '"host":"veritell.test' "$WORK/gw.log" | tail -1)
check  "S9 requests to the new site are scored"          "$line" '"score":'
check  "S9 with the TLS fingerprint of the connection"   "$line" '"ja4":"t13'
refute "no panics in the gateway log"                    "$(cat "$WORK/gw.err")" 'panicked'
stop_proxy

# ---- S10: bad settings stop the start ----
bad() { "$BIN" --cert "$WORK/default/fullchain.pem" --key "$WORK/default/privkey.pem" --listen "127.0.0.1:$PORT" "$@" 2>&1; echo "exit $?"; }
check  "S10 a missing --sni-dir is refused"              "$(bad --sni-dir "$WORK/nope")" 'exit 2'
check  "S10 a malformed --upstream-host is refused"      "$(bad --upstream-host 'veritell.test')" 'is not name=host:port'
check  "S10 a name given twice is refused"               "$(bad --upstream-host "a.test=127.0.0.1:1,A.test=127.0.0.1:2")" 'names a.test twice'
cert "$WORK/sni/dupe" veritell.test veritell.test
check  "S10 two certificates for one name are refused"   "$(bad --sni-dir "$WORK/sni")" 'listed by more than one certificate'
rm -rf "$WORK/sni/dupe"; cp "$WORK/default/privkey.pem" "$WORK/sni/wild/privkey.pem"
check  "S10 a key that doesn't match is refused"         "$(bad --sni-dir "$WORK/sni")" 'private key'
rm -rf "$WORK/sni"
start_proxy --sni-dir '' --upstream-host ''
check  "S11 empty values mean none: it starts"           "$(served site.test)" 'CN *= *site.test'
refute "S11 and lists no extra certificate"              "$(cat "$WORK/gw.err")" 'served for'
stop_proxy

echo
if [ "$fails" -eq 0 ]; then echo "ALL PASSED"; else echo "$fails FAILED"; fi
exit "$fails"
