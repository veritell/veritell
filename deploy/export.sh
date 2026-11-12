#!/usr/bin/env bash
# Sends us your data, encrypted:  export.sh [days] [--no-paths]
#   days         1 to 30, default 30 (the store keeps 30 days), digits only
#   --no-paths   the path of every event is replaced by an empty string
# Reads the events from ClickHouse (through docker exec, as report.sh does),
# compresses them and encrypts them to recipient.pem, our certificate shipped
# in the kit. Only we hold the private key. Writes in /opt/veritell/exports/:
#   export-<UTC date>.cms   the encrypted file: send this one
#   export-<UTC date>.txt   what is in it, in plain text: read it, keep it
# The newest 3 of each are kept. Nothing unencrypted is written to disk.
SCRIPT=export
. "$(dirname "$0")/lib.sh"
usage() { echo "usage: export.sh [days] [--no-paths]   (days: 1 to 30, digits only, default 30)" >&2; exit 2; }
days=30; paths=included; seen_days=0
for a in "$@"; do
  case "$a" in
    --no-paths) paths=removed;;
    ''|*[!0-9]*) usage;;
    *) [ "$seen_days" = 0 ] || usage; days=$((10#$a)); seen_days=1;;
  esac
done
{ [ "$days" -ge 1 ] && [ "$days" -le 30 ]; } || usage

OPENSSL=${OPENSSL:-openssl}
# CMS with AES-GCM needs OpenSSL 3 or later (LibreSSL, as on macOS, has none).
case "$("$OPENSSL" version 2>/dev/null)" in
  "OpenSSL "[3-9]*|"OpenSSL "[1-9][0-9]*) ;;
  *) echo "needs OpenSSL 3 or later as \$OPENSSL (found: $("$OPENSSL" version 2>/dev/null || echo none))" >&2; exit 1;;
esac
[ -f "$KIT/recipient.pem" ] || { log "no $KIT/recipient.pem (our certificate, shipped in the kit): nothing was read or written. Ask us for an up-to-date kit"; exit 1; }
health=$(docker inspect -f '{{.State.Running}}' veritell-clickhouse 2>/dev/null || echo missing)
[ "$health" = true ] || { log "ClickHouse (container veritell-clickhouse) is not running: start the gateway (status.sh) and run this again"; exit 1; }
P=$(get_kv "$KIT/kit.env" CLICKHOUSE_PASSWORD)
[ -n "$P" ] || { log "no CLICKHOUSE_PASSWORD in $KIT/kit.env"; exit 1; }

cols="ts, kind, ip, method, host, path, user_agent, ja4, h2, score, class, detection_ids, detections, identity, asn, net_class, token, action, enforced, route, rule, outcome, known, summary, tcp, tcp_ttl"
sel=$cols
[ "$paths" = removed ] && sel=${cols/ path,/ \'\' AS path,}
query="SELECT $sel FROM veritell.events WHERE ts > now() - INTERVAL $days DAY ORDER BY ts FORMAT JSONEachRow"

umask 027
mkdir -p "$KIT/exports"
chmod 0750 "$KIT/exports"
[ "$REHEARSAL" = 1 ] || chown root:root "$KIT/exports"
stamp=$(date -u +%Y-%m-%d)
work=$(mktemp -d "$KIT/exports/.work.XXXXXX")
trap 'rm -rf "$work"' EXIT

# The events are counted as they pass (awk writes the count at its end, and
# is finished when the pipeline is), then compressed and encrypted.
if ! docker exec veritell-clickhouse clickhouse-client --user veritell --password "$P" --query "$query" \
    | awk -v f="$work/count" '{ n++; print } END { print n + 0 > f }' \
    | gzip -c \
    | "$OPENSSL" cms -encrypt -binary -stream -aes-256-gcm -outform DER -recip "$KIT/recipient.pem" > "$work/export.cms"; then
  log "the export was not made (ClickHouse, gzip or openssl failed: see above); nothing was changed in $KIT/exports"
  exit 1
fi
[ -s "$work/export.cms" ] && [ -s "$work/count" ] || { log "the export is empty or incomplete; nothing was changed in $KIT/exports"; exit 1; }
events=$(cat "$work/count")
if command -v sha256sum >/dev/null; then hash=$(sha256sum "$work/export.cms" | cut -d' ' -f1); else hash=$(shasum -a 256 "$work/export.cms" | cut -d' ' -f1); fi

{
  echo "Veritell export, made $(date -u +%Y-%m-%dT%H:%M:%SZ) for $SITE_HOST"
  echo
  echo "days: $days"
  echo "events: $events"
  echo "paths: $paths"
  echo "sha256: $hash"
  echo "columns: $cols"
  echo
  echo "What is in the .cms file: one record per request the gateway saw in the last $days days. The columns are: the time (ts) and the kind of record; the request line (method, host, path; with paths: removed the path is empty); the browser and TLS fingerprints (user_agent, ja4, h2, tcp, tcp_ttl); what the gateway decided and why (score, class, detections, action, enforced, route, rule, outcome, identity, asn, net_class, token); a label when the visitor is a person you told us about (known); and counts of behaviour such as how many keys, clicks and strokes (summary). No keystroke content is recorded, only counts and timings."
  echo
  echo "Visitor addresses (ip) are keyed hashes: the key changes every day and is not stored, so an address cannot be recovered from the file, nor matched from one day to the next."
  echo
  echo "Only the holder of our private key can open the .cms file; you cannot either, and neither can anyone who intercepts it. Its SHA-256 is above, so you can check that the file we received is the one you sent."
  echo
  echo "Send the .cms file; keep this .txt."
} > "$work/export.txt"

chmod 0640 "$work/export.cms" "$work/export.txt"
[ "$REHEARSAL" = 1 ] || chown root:root "$work/export.cms" "$work/export.txt"
mv -f "$work/export.cms" "$KIT/exports/export-$stamp.cms"
mv -f "$work/export.txt" "$KIT/exports/export-$stamp.txt"

# Keep the newest 3 of each (the names sort by date).
for ext in cms txt; do
  ls -1 "$KIT"/exports/export-*."$ext" 2>/dev/null | sort -r | tail -n +4 | while IFS= read -r old; do
    rm -f "$old"; log "removed old export: $old"
  done
done
log "export of the last $days days: $events events, paths $paths"
echo "$KIT/exports/export-$stamp.cms"
echo "$KIT/exports/export-$stamp.txt"
echo "Send us the .cms file (email or a file share); keep the .txt."
