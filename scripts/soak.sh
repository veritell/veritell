#!/usr/bin/env bash
# Soak test: runs the gateway (shadow mode, no upstream) under mixed normal and
# hostile traffic, samples memory / file descriptors / latency, and prints a
# verdict for gate G14. Needs `hey`, `openssl`, `nc`, `lsof`, `ps`, python3 and
# a release build (cargo +stable build --release -p veritell-proxy).
#   scripts/soak.sh [minutes]          default 240
# Env: SOAK_SAMPLE_SECS (60), PORT (8463), SOAK_OUT (a new mktemp -d)
set -u
cd "$(dirname "$0")/.."
MIN=${1:-240}; SAMPLE=${SOAK_SAMPLE_SECS:-60}; PORT=${PORT:-8463}
OUT=${SOAK_OUT:-$(mktemp -d)}
mkdir -p "$OUT" || exit 1
WORK=$(mktemp -d)
echo "soak output dir: $OUT"
echo "minutes=$MIN sample_secs=$SAMPLE port=$PORT"

openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=localhost" \
  -keyout "$WORK/key.pem" -out "$WORK/cert.pem" >/dev/null 2>&1 || { echo "openssl failed"; exit 1; }
VERITELL_SECRET="soak-test-secret-0123456789abcdef0123456789" target/release/veritell \
  --cert "$WORK/cert.pem" --key "$WORK/key.pem" --listen "127.0.0.1:$PORT" \
  >"$OUT/gateway.out" 2>"$OUT/gateway.err" &
PID=$!
PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
  kill -INT $PID 2>/dev/null; sleep 0.3; kill -9 $PID 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

for _ in $(seq 1 50); do nc -z 127.0.0.1 "$PORT" 2>/dev/null && break; sleep 0.1; done
kill -0 $PID 2>/dev/null || { echo "gateway failed to start"; cat "$OUT/gateway.err"; exit 1; }

UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
DUR=$((MIN * 60))
BASE="https://localhost:$PORT"

# Normal page loads: about 200 req/s in total across a few paths.
hey -z "${DUR}s" -c 5 -q 20 -h2 -H "User-Agent: $UA" "$BASE/" >"$OUT/hey_root.txt" 2>&1 & PIDS+=($!)
hey -z "${DUR}s" -c 3 -q 20 -h2 -H "User-Agent: $UA" "$BASE/about" >"$OUT/hey_about.txt" 2>&1 & PIDS+=($!)
hey -z "${DUR}s" -c 2 -q 20 -h2 -H "User-Agent: $UA" "$BASE/products?id=7" >"$OUT/hey_products.txt" 2>&1 & PIDS+=($!)

# Hostile clients.
python3 scripts/soak_client.py --port "$PORT" >"$OUT/client.out" 2>&1 & CLIENT=$!
PIDS+=($CLIENT)

sleep 2
echo "elapsed_s,rss_kb,fds,p50_ms,p99_ms" >"$OUT/soak.csv"
START=$(date +%s)
END=$((START + DUR))
EARLY=""
while :; do
  NOW=$(date +%s)
  [ "$NOW" -ge "$END" ] && break
  if ! kill -0 $PID 2>/dev/null; then
    wait $PID; EARLY="gateway exited early (status $?) after $((NOW - START))s"
    break
  fi
  RSS=$(ps -o rss= -p $PID 2>/dev/null | tr -d ' ')
  FDS=$(( $(lsof -p $PID 2>/dev/null | wc -l) - 1 ))
  HEY=$(hey -n 500 -c 5 -h2 -H "User-Agent: $UA" "$BASE/" 2>/dev/null)
  P50=$(printf '%s\n' "$HEY" | awk '$1~/^50%+$/{printf "%.3f", $3*1000}')
  P99=$(printf '%s\n' "$HEY" | awk '$1~/^99%+$/{printf "%.3f", $3*1000}')
  NOW=$(date +%s)
  if [ -n "${RSS:-}" ] && [ -n "$P50" ] && [ -n "$P99" ]; then
    echo "$((NOW - START)),$RSS,$FDS,$P50,$P99" >>"$OUT/soak.csv"
    echo "sample t=$((NOW - START))s rss=${RSS}KB fds=$FDS p50=${P50}ms p99=${P99}ms"
  else
    echo "sample t=$((NOW - START))s skipped (rss='${RSS:-}' p50='$P50' p99='$P99')"
  fi
  # sleep out the remainder of the interval (bounded by the end of the run)
  REM=$((SAMPLE - (NOW - START) % SAMPLE))
  [ $((NOW + REM)) -gt "$END" ] && REM=$((END - NOW))
  [ "$REM" -gt 0 ] && sleep "$REM"
done

# Stop everything, then judge.
ALIVE=0; kill -0 $PID 2>/dev/null && ALIVE=1
kill -TERM $CLIENT 2>/dev/null; wait $CLIENT 2>/dev/null
for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
sleep 0.5
echo
echo "---- hostile client counts ----"
cat "$OUT/client.out"
echo
echo "---- gate G14 verdict ($OUT/soak.csv) ----"
python3 - "$OUT/soak.csv" "$ALIVE" "$EARLY" "$OUT/gateway.out" "$OUT/gateway.err" <<'PY'
import sys, csv, statistics
path, alive, early, *logs = sys.argv[1:]
rows = []
with open(path) as f:
    for r in csv.DictReader(f):
        try:
            rows.append({k: float(v) for k, v in r.items()})
        except (ValueError, TypeError):
            pass
ok = True
def say(name, passed, detail):
    global ok
    ok = ok and passed
    print(f"{'PASS' if passed else 'FAIL'}  {name}: {detail}")
if early:
    say("gateway alive", False, early)
else:
    say("gateway alive", alive == "1", "still running at end" if alive == "1" else "not running at end")
if len(rows) < 4:
    say("enough samples", False, f"only {len(rows)} rows, too short (need at least 4)")
else:
    # Memory may rise and fall as bounded tables fill and are swept, so the
    # peaks are compared: the last half's against the first half's after a
    # warm-up of the first tenth. Latency is compared by median, not maximum:
    # a single 500-request sample is noisy under the hostile load.
    end = rows[-1]["elapsed_s"]
    first = [r for r in rows if end * 0.1 <= r["elapsed_s"] <= end / 2]
    last = [r for r in rows if r["elapsed_s"] > end / 2]
    if not first or not last:
        say("enough samples", False, f"{len(first)} rows in the first half after warm-up, {len(last)} in the last")
    else:
        base = max(r["rss_kb"] for r in first); mx = max(r["rss_kb"] for r in last); lim = base * 1.10 + 8192
        say("memory", mx <= lim, f"peak rss last half {mx:.0f} KB, limit {lim:.0f} KB (peak first half {base:.0f} KB)")
        base = max(r["fds"] for r in first); mx = max(r["fds"] for r in last); lim = base + 16
        say("fds", mx <= lim, f"peak fds last half {mx:.0f}, limit {lim:.0f} (peak first half {base:.0f})")
        q = rows[:max(1, len(rows) // 4)]
        base = statistics.median(r["p99_ms"] for r in q)
        med = statistics.median(r["p99_ms"] for r in last); lim = 1.5 * base
        say("latency", med <= lim, f"median p99 last half {med:.3f} ms (max {max(r['p99_ms'] for r in last):.3f}), limit {lim:.3f} ms (first-quarter median {base:.3f} ms, {len(q)} rows)")
panics = 0
for p in logs:
    try:
        with open(p, errors="replace") as f:
            panics += sum(1 for line in f if "panicked" in line)
    except OSError:
        pass
say("panics", panics == 0, f"{panics} 'panicked' lines in gateway output")
print("OVERALL: " + ("PASS" if ok else "FAIL"))
sys.exit(0 if ok else 1)
PY
exit $?
