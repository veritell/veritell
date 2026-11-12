#!/usr/bin/env bash
# The weekly report:  report.sh [days]      default 7, 1 to 31
# Reads the last N days of events from ClickHouse (through docker exec, as
# the review tools' fetch.sh does) and writes, in /opt/veritell/reports/:
#   report-<UTC date>.html   one page to read, forward or print
#   report-<UTC date>.json   the same numbers
# The newest 8 of each are kept. Nothing leaves the host. Run every Monday by
# veritell-report.timer (journalctl -u veritell-report), or by hand as root.
SCRIPT=report
. "$(dirname "$0")/lib.sh"
days=${1:-7}
case "$days" in ''|*[!0-9]*) echo "usage: report.sh [days]   (1 to 31, digits only)" >&2; exit 2;; esac
days=$((10#$days))
{ [ "$days" -ge 1 ] && [ "$days" -le 31 ]; } || { echo "usage: report.sh [days]   (1 to 31)" >&2; exit 2; }

health=$(docker inspect -f '{{.State.Running}}' veritell-clickhouse 2>/dev/null || echo missing)
[ "$health" = true ] || { log "ClickHouse (container veritell-clickhouse) is not running: start the gateway (status.sh) and run this again"; exit 1; }
P=$(get_kv "$KIT/kit.env" CLICKHOUSE_PASSWORD)
[ -n "$P" ] || { log "no CLICKHOUSE_PASSWORD in $KIT/kit.env"; exit 1; }

umask 027
mkdir -p "$KIT/reports"
chmod 0750 "$KIT/reports"
[ "$REHEARSAL" = 1 ] || chown root:root "$KIT/reports"
stamp=$(date -u +%Y-%m-%d)
work=$(mktemp -d "$KIT/reports/.work.XXXXXX")
trap 'rm -rf "$work"' EXIT

# The host's python3 when it is 3.9 or later; otherwise a container.
if command -v python3 >/dev/null && python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
  run_report() { python3 "$KIT/report.py" "$@"; }
  out=$work
else
  run_report() { docker run --rm -i -v "$KIT:/kit:ro" -v "$work:/out" python:3.12-slim python3 /kit/report.py "$@"; }
  out=/out
fi

# Same way as migrate.sh and the review tools' fetch.sh: the password is an argument
# of clickhouse-client inside the container (visible to root in ps there).
if ! docker exec veritell-clickhouse clickhouse-client --user veritell --password "$P" \
    --query "SELECT ts, kind, ip, ja4, h2, user_agent, detection_ids, action, path, known, class, score, identity FROM veritell.events WHERE ts > now() - INTERVAL $days DAY ORDER BY ts FORMAT JSONEachRow" \
    | run_report --events - --site "$SITE_HOST" --html "$out/report.html" --json "$out/report.json"; then
  log "the report was not made (ClickHouse or report.py failed: see above); nothing was changed in $KIT/reports"
  exit 1
fi
chmod 0640 "$work/report.html" "$work/report.json"
[ "$REHEARSAL" = 1 ] || chown root:root "$work/report.html" "$work/report.json"
mv -f "$work/report.html" "$KIT/reports/report-$stamp.html"
mv -f "$work/report.json" "$KIT/reports/report-$stamp.json"

# Keep the newest 8 of each (the names sort by date).
for ext in html json; do
  ls -1 "$KIT"/reports/report-*."$ext" 2>/dev/null | sort -r | tail -n +9 | while IFS= read -r old; do
    rm -f "$old"; log "removed old report: $old"
  done
done
log "report for the last $days days:"
echo "$KIT/reports/report-$stamp.html"
echo "$KIT/reports/report-$stamp.json"
