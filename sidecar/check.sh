#!/usr/bin/env bash
# Example check script for the sidecar proxy configurations in this directory.
# It is an example to adapt. It does not start the gateway or the upstream.
#
# Usage: sidecar/check.sh
#   Gateway first, with the end-to-end test policy (it passes everything under
#   /open and challenges a low score elsewhere):
#     veritell --cert cert.pem --key key.pem --policy scripts/e2e_policy.yaml \
#       --sidecar-listen 127.0.0.1:9191 --trusted-proxy 127.0.0.1
#   Upstream answering on 127.0.0.1:8080 and echoing the request headers it
#   receives (scripts/echo_origin.py 8080).
#
# For each of nginx, traefik, caddy, envoy: NOT RUN if the binary is not on PATH;
# otherwise it is started with the example configuration in this directory on
# 127.0.0.1:8000, checked, and stopped before the next one.
#
# Exit status: 2 if the gateway endpoint or the upstream does not answer,
# 1 if any check FAILs, 0 otherwise.

set -u

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROXY_PORT=8000
AUTHZ_PORT=9191
UPSTREAM_PORT=8080
BROWSER_UA='Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'

TMP=""
PROXY_PID=""
PASS_COUNT=0
FAIL_COUNT=0
NOTRUN_COUNT=0

# Prints the HTTP status for the given curl arguments, or 000 if nothing answers.
http_status() {
  curl -s -o /dev/null -m 3 -w '%{http_code}' "$@"
}

result_pass()   { PASS_COUNT=$((PASS_COUNT + 1));   printf 'PASS  %s\n' "$*"; }
result_fail()   { FAIL_COUNT=$((FAIL_COUNT + 1));   printf 'FAIL  %s\n' "$*"; }
result_notrun() { NOTRUN_COUNT=$((NOTRUN_COUNT + 1)); printf 'NOT RUN  %s\n' "$*"; }
info()          { printf 'INFO  %s\n' "$*"; }

# Stops the proxy this script started, then waits until the port is free.
stop_proxy() {
  if [ -n "$PROXY_PID" ]; then
    kill "$PROXY_PID" 2>/dev/null
    wait "$PROXY_PID" 2>/dev/null
    PROXY_PID=""
  fi
  local i=0
  while [ "$(http_status "http://127.0.0.1:$PROXY_PORT/")" != "000" ] && [ "$i" -lt 25 ]; do
    sleep 0.2
    i=$((i + 1))
  done
}

cleanup() {
  if [ -n "$PROXY_PID" ]; then
    kill "$PROXY_PID" 2>/dev/null
    wait "$PROXY_PID" 2>/dev/null
    PROXY_PID=""
  fi
  if [ -n "$TMP" ] && [ -d "$TMP" ]; then
    rm -rf "$TMP"
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# Waits until something answers on the port. Fails early if the proxy has exited.
wait_for_port() { # port seconds
  local i=0
  while [ "$i" -lt $(( $2 * 5 )) ]; do
    if [ "$(http_status "http://127.0.0.1:$1/")" != "000" ]; then
      return 0
    fi
    if [ -n "$PROXY_PID" ] && ! kill -0 "$PROXY_PID" 2>/dev/null; then
      return 1
    fi
    sleep 0.2
    i=$((i + 1))
  done
  return 1
}

start_and_check() {
  local name="$1"
  local log="$TMP/$name.log"
  local url="http://127.0.0.1:$PROXY_PORT/"
  local s_browser s_curl s_probe body echoed

  if [ "$(http_status "$url")" != "000" ]; then
    result_fail "$name: port $PROXY_PORT is already in use; not started"
    return
  fi

  case "$name" in
    nginx)
      nginx -g "pid $TMP/nginx.pid; error_log $TMP/nginx-error.log; daemon off;" \
        -c "$DIR/nginx.conf" >"$log" 2>&1 &
      ;;
    traefik)
      # Static configuration: the :8000 entry point and the file provider.
      cat >"$TMP/traefik-static.yml" <<EOF
entryPoints:
  web:
    address: "127.0.0.1:$PROXY_PORT"
providers:
  file:
    filename: "$DIR/traefik.yml"
EOF
      traefik --configFile="$TMP/traefik-static.yml" >"$log" 2>&1 &
      ;;
    caddy)
      caddy run --config "$DIR/Caddyfile" --adapter caddyfile >"$log" 2>&1 &
      ;;
    envoy)
      envoy -c "$DIR/envoy.yaml" --log-level warn >"$log" 2>&1 &
      ;;
  esac
  PROXY_PID=$!

  if ! wait_for_port "$PROXY_PORT" 10; then
    result_fail "$name: did not answer on 127.0.0.1:$PROXY_PORT (log: $log)"
    stop_proxy
    return
  fi

  # (a) A request the policy passes must reach the upstream: 200.
  s_browser="$(http_status -A "$BROWSER_UA" "${url}open/x")"
  if [ "$s_browser" = "200" ]; then
    result_pass "$name: a passed request gets 200 from the upstream"
  else
    result_fail "$name: a passed request got $s_browser, expected 200"
  fi

  # (b) A declared tool outside /open is challenged by the policy: the proxy must refuse.
  s_curl="$(http_status -A 'curl/8.0' "$url")"
  if [ "$s_curl" = "403" ]; then
    result_pass "$name: a refused request gets 403 and does not reach the upstream"
  else
    result_fail "$name: a refused request got $s_curl, expected 403"
  fi

  # (b2) The gateway's own pages are routed to its main listener, unchecked.
  s_probe="$(http_status -A "$BROWSER_UA" "${url}__veritell/probe.js")"
  if [ "$s_probe" = "200" ]; then
    result_pass "$name: /__veritell/probe.js is served by the gateway"
  else
    result_fail "$name: /__veritell/probe.js got $s_probe, expected 200"
  fi

  # (c) The upstream must get the gateway's score, and never a client's
  # forged one. Needs an upstream that echoes its request headers.
  body="$(curl -s -m 5 -A "$BROWSER_UA" -H 'X-Veritell-Score: forged' "${url}open/x")"
  echoed="$(printf '%s' "$body" | grep -io '"x-veritell-score": *"[^"]*"' | head -n 1)"
  if [ -z "$echoed" ]; then
    result_fail "$name: the upstream received no X-Veritell-Score"
  elif printf '%s' "$echoed" | grep -q 'forged'; then
    result_fail "$name: the upstream received the forged header: $echoed"
  else
    result_pass "$name: the upstream received the gateway's score ($echoed)"
  fi

  # (d) A client cannot choose the path that is scored: the refused request
  # of (b), claiming in a header to be for /open/x, must still be refused.
  for spoof in X-Original-URI X-Forwarded-Uri; do
    s_spoof="$(http_status -A 'curl/8.0' -H "$spoof: /open/x" "$url")"
    case "$s_spoof" in
      400|403) result_pass "$name: a client's $spoof is not believed ($s_spoof)" ;;
      *)       result_fail "$name: a client's $spoof got $s_spoof, expected 403 (or 400)" ;;
    esac
  done

  # (e) No client-sent X-Veritell-* header reaches the upstream, including
  # the ones the gateway does not set on this request.
  body="$(curl -s -m 5 -A "$BROWSER_UA" -H 'X-Veritell-Token: forged' \
    -H 'X-Veritell-Receipt: forged' -H 'X-Veritell-Ja4: forged' "${url}open/x")"
  if [ -z "$body" ]; then
    result_fail "$name: no answer from the upstream for the forged-header check"
  elif printf '%s' "$body" | grep -qi 'forged'; then
    result_fail "$name: a client's X-Veritell-* header reached the upstream"
  else
    result_pass "$name: no client X-Veritell-* header reached the upstream"
  fi

  stop_proxy
}

# Preconditions: curl, and both the gateway endpoint and the upstream answering.
if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 2
fi

gw_status="$(http_status "http://127.0.0.1:$AUTHZ_PORT/__veritell/authz")"
up_status="$(http_status "http://127.0.0.1:$UPSTREAM_PORT/")"
missing=0
if [ "$gw_status" = "000" ]; then
  echo "not running: no gateway sidecar endpoint on 127.0.0.1:$AUTHZ_PORT" >&2
  echo "  start veritell with --sidecar-listen 127.0.0.1:9191 --trusted-proxy 127.0.0.1" >&2
  missing=1
fi
if [ "$up_status" = "000" ]; then
  echo "not running: no upstream on 127.0.0.1:$UPSTREAM_PORT" >&2
  missing=1
fi
if [ "$missing" -ne 0 ]; then
  exit 2
fi

TMP="$(mktemp -d)" || { echo "cannot create a temporary directory" >&2; exit 2; }
info "gateway endpoint answered ($gw_status), upstream answered ($up_status)"

for name in nginx traefik caddy envoy; do
  if ! command -v "$name" >/dev/null 2>&1; then
    result_notrun "$name: not installed"
    continue
  fi
  start_and_check "$name"
done

echo
echo "Summary: $PASS_COUNT PASS, $FAIL_COUNT FAIL, $NOTRUN_COUNT NOT RUN"
if [ "$FAIL_COUNT" -gt 0 ]; then
  exit 1
fi
exit 0
