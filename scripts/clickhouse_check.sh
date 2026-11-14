#!/usr/bin/env bash
# E40: the events sink against a real ClickHouse server, and the table's TTL.
# Needs Docker and a release build. Starts a throwaway ClickHouse container
# on loopback, creates the table from the DDL in veritell-events, sends
# requests through the gateway and reads the rows back.
#   scripts/clickhouse_check.sh
set -u
cd "$(dirname "$0")/.."
IMAGE=${CH_IMAGE:-clickhouse/clickhouse-server:25.8}
# Not 18123: the kit's own ClickHouse publishes that port.
HTTP=${CH_HTTP:-18133}; PORT=${PORT:-8447}
NAME="veritell-ch-check-$$"
WORK=$(mktemp -d)
PASSWORD="check-$(openssl rand -hex 12)"
export VERITELL_SECRET="clickhouse-check-secret-0123456789abcdef"
fails=0
check() { if printf '%s' "$2" | grep -q -- "$3"; then echo "PASS  $1"; else echo "FAIL  $1  (wanted: $3, got: $(printf '%s' "$2" | head -c 200))"; fails=$((fails+1)); fi; }
cleanup() { [ -n "${GW:-}" ] && kill -INT "$GW" 2>/dev/null; docker rm -f "$NAME" >/dev/null 2>&1; rm -rf "$WORK"; }
trap cleanup EXIT

docker run -d --name "$NAME" -p "127.0.0.1:$HTTP:8123" \
  -e CLICKHOUSE_PASSWORD="$PASSWORD" -e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 \
  --ulimit nofile=262144:262144 "$IMAGE" >/dev/null || exit 1
q() { curl -s -u "default:$PASSWORD" "http://127.0.0.1:$HTTP/" --data-binary "$1"; }
for _ in $(seq 1 60); do [ "$(q 'SELECT 1' 2>/dev/null)" = "1" ] && break; sleep 1; done
check "E40 server is up"               "$(q 'SELECT version()')" '^25\.8'

# The DDL as the crate defines it.
python3 - crates/veritell-events/src/clickhouse.rs >"$WORK/ddl.sql" <<'PY'
import re, sys
src = open(sys.argv[1]).read()
m = re.search(r'pub const DDL: &str = "\\\n(.*?)";', src, re.S)
print(m.group(1).replace("{database}", "veritell").replace("{table}", "events"))
PY
q 'CREATE DATABASE IF NOT EXISTS veritell' >/dev/null
check "E40 the DDL is accepted"        "$(q "$(cat "$WORK/ddl.sql")"; echo ok)" '^ok$'
check "E40 the TTL is on the table"    "$(q "SELECT engine_full FROM system.tables WHERE database='veritell' AND name='events'")" 'TTL toDateTime(ts) + toIntervalDay(30)'

CERT="$WORK/cert.pem"; KEY="$WORK/key.pem"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=localhost" -keyout "$KEY" -out "$CERT" >/dev/null 2>&1
VERITELL_CLICKHOUSE_PASSWORD="$PASSWORD" target/release/veritell --cert "$CERT" --key "$KEY" \
  --listen "127.0.0.1:$PORT" --ip-mode keyed --clickhouse-url "http://127.0.0.1:$HTTP" \
  >"$WORK/gw.log" 2>"$WORK/gw.err" &
GW=$!
for _ in $(seq 1 50); do nc -z 127.0.0.1 "$PORT" 2>/dev/null && break; sleep 0.1; done
UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
for i in $(seq 1 20); do curl -sk --http2 -o /dev/null -A "$UA" "https://localhost:$PORT/page/$i"; done
curl -sk --http2 -o /dev/null -A "python-requests/2.32" "https://localhost:$PORT/it's%20\"quoted\"%5C"
printf 'garbage' | curl -sk --http2 -o /dev/null --data-binary @- "https://localhost:$PORT/__veritell/probe"
rows=0
for _ in $(seq 1 30); do rows=$(q 'SELECT count() FROM veritell.events'); [ "${rows:-0}" -ge 22 ] 2>/dev/null && break; sleep 1; done
check "E40 every event arrived"         "$rows" '^22$'
check "E40 timestamps are now, in ms"   "$(q 'SELECT countIf(abs(dateDiff('"'"'second'"'"', ts, now64(3))) < 120) FROM veritell.events')" '^22$'
check "E40 milliseconds are kept"       "$(q 'SELECT countIf(toUnixTimestamp64Milli(ts) % 1000 != 0) > 0 FROM veritell.events')" '^1$'
check "E40 addresses are keyed"         "$(q "SELECT countIf(match(ip, '^k:[0-9a-f]{32}\$')) FROM veritell.events")" '^22$'
check "E40 kinds are request and probe" "$(q 'SELECT groupUniqArray(kind) FROM veritell.events ORDER BY 1 FORMAT TSV')" 'probe'
check "E40 a hostile path is stored as text" "$(q "SELECT count() FROM veritell.events WHERE path LIKE '%quoted%'")" '^1$'
check "E40 detections are JSON"         "$(q 'SELECT countIf(isValidJSON(detections)) FROM veritell.events')" '^22$'
check "E40 the scraper is automated"    "$(q "SELECT class FROM veritell.events WHERE user_agent LIKE 'python-requests%'")" '^automated$'
check "E40 the sink reported no failure" "$(grep -c -i 'clickhouse' "$WORK/gw.err")" '^[01]$'

# The TTL drops rows older than 30 days on the real server.
q "INSERT INTO veritell.events (ts, kind, ip) VALUES (now64(3) - INTERVAL 31 DAY, 'request', 'old'), (now64(3) - INTERVAL 29 DAY, 'request', 'recent')" >/dev/null
q 'OPTIMIZE TABLE veritell.events FINAL' >/dev/null
check "E40 a row older than 30 days is dropped" "$(q "SELECT count() FROM veritell.events WHERE ip = 'old'")" '^0$'
check "E40 a row of 29 days is kept"    "$(q "SELECT count() FROM veritell.events WHERE ip = 'recent'")" '^1$'
check "E40 no panics"                   "$(grep -c panicked "$WORK/gw.err")" '^0$'

echo
if [ "$fails" -eq 0 ]; then echo "ALL PASSED"; else echo "$fails FAILED"; cat "$WORK/gw.err"; fi
exit "$fails"
