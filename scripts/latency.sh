#!/usr/bin/env bash
# Measures the gateway's own request handling time: shadow mode, no upstream,
# so each request is fingerprinted, scored, logged and answered by the gateway.
# Needs `hey` and a release build. Prints the latency distribution.
#   scripts/latency.sh [requests] [concurrency]
set -u
cd "$(dirname "$0")/.."
N=${1:-30000}; C=${2:-20}; PORT=${PORT:-8453}
WORK=$(mktemp -d)
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=localhost" \
  -keyout "$WORK/key.pem" -out "$WORK/cert.pem" >/dev/null 2>&1 || exit 1
VERITELL_SECRET="latency-test-secret-0123456789abcdef0123" target/release/veritell \
  --cert "$WORK/cert.pem" --key "$WORK/key.pem" --listen "127.0.0.1:$PORT" "${@:3}" >/dev/null 2>"$WORK/err" &
PID=$!
trap 'kill -INT $PID 2>/dev/null; sleep 0.3; kill -9 $PID 2>/dev/null; rm -rf "$WORK"' EXIT
for _ in $(seq 1 50); do nc -z 127.0.0.1 "$PORT" 2>/dev/null && break; sleep 0.1; done
UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
hey -n 2000 -c "$C" -h2 -H "User-Agent: $UA" "https://localhost:$PORT/" >/dev/null 2>&1   # warm-up
hey -n "$N" -c "$C" -h2 -H "User-Agent: $UA" "https://localhost:$PORT/" | grep -E "Requests/sec|Average|50%|90%|99%|\[200\]|Error"
