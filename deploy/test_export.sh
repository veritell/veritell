#!/usr/bin/env bash
# Tests for export.sh and tools/export/export_key.sh, open_export.sh,
# with a stub docker and a real openssl (3.0 or later).  deploy/test_export.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fails=0
eq() { if [ "$2" = "$3" ]; then echo "PASS  $1"; else echo "FAIL  $1: wanted '$3', got '$2'"; fails=$((fails+1)); fi; }
has() { if printf '%s' "$2" | grep -qF -- "$3"; then echo "PASS  $1"; else echo "FAIL  $1: wanted '$3' in '$(printf '%s' "$2" | head -c 300)'"; fails=$((fails+1)); fi; }
mode() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"; }
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

mkdir -p "$T/kit" "$T/bin" "$T/keys"
cp "$HERE/lib.sh" "$HERE/export.sh" "$T/kit/"
cat > "$T/kit/site.conf" <<CONF
FRONT=redirect
IPV6=off
SITE_HOST=example.test
CERT_FULLCHAIN=$T/none.pem
CERT_KEY=$T/none.key
UPSTREAM=127.0.0.1:443
CONF
printf 'CLICKHOUSE_PASSWORD=pw\nVERITELL_FRONT=gateway\n' > "$T/kit/kit.env"
cat > "$T/events.jsonl" <<'EOF'
{"ts":"2026-11-02 10:00:00.100","kind":"request","ip":"k:aa","path":"/users/alice","user_agent":"Mozilla/5.0","action":"pass"}
{"ts":"2026-11-02 10:00:01.000","kind":"probe","ip":"k:aa","path":"/__veritell/probe","user_agent":"Mozilla/5.0","action":""}
{"ts":"2026-11-03 11:00:00.000","kind":"request","ip":"k:bb","path":"/.env","user_agent":"curl/8","action":"block"}
EOF
# docker: `inspect` says ClickHouse runs; `exec` records its --query and
# prints the events (or fails half way with STUB_FAIL=1).
cat > "$T/bin/docker" <<'STUB'
#!/usr/bin/env bash
case "$1" in
  inspect) echo true; exit 0;;
  exec)
    while [ $# -gt 0 ]; do [ "$1" = --query ] && { printf '%s' "$2" > "$STUB_QUERY"; }; shift; done
    if [ "${STUB_FAIL:-0}" = 1 ]; then head -1 "$STUB_EVENTS"; exit 1; fi
    cat "$STUB_EVENTS"; exit 0;;
esac
exit 0
STUB
chmod +x "$T/bin/docker"
export PATH="$T/bin:$PATH" STUB_QUERY="$T/query" STUB_EVENTS="$T/events.jsonl" REHEARSAL=1
EXPORT="$T/kit/export.sh"
KEYGEN="$ROOT/tools/export/export_key.sh"
OPEN="$ROOT/tools/export/open_export.sh"

# ---- no recipient: nothing ----
out=$("$EXPORT" 2>&1); rc=$?
eq "no recipient.pem: exit 1" "$rc" "1"
has "  and says so" "$out" "recipient.pem"
eq "  nothing written" "$(ls "$T/kit/exports" 2>/dev/null | wc -l | tr -d ' ')" "0"
eq "  nothing read" "$([ -f "$T/query" ] && echo read || echo none)" "none"

# ---- keys ----
"$KEYGEN" "$T/keys/key.pem" "$T/kit/recipient.pem" >/dev/null 2>&1
eq "export_key.sh: key mode 600" "$(mode "$T/keys/key.pem")" "600"
has "export_key.sh: certificate CN" "$(openssl x509 -in "$T/kit/recipient.pem" -noout -subject 2>&1)" "veritell export recipient"
c="$T/kit/recipient.pem"
eq "export_key.sh: valid about 5 years" \
  "$(openssl x509 -in "$c" -noout -checkend $((1820*86400)) >/dev/null && ! openssl x509 -in "$c" -noout -checkend $((1830*86400)) >/dev/null && echo yes || echo no)" "yes"
before=$(sha "$T/keys/key.pem")
"$KEYGEN" "$T/keys/key.pem" "$T/keys/other.pem" >/dev/null 2>&1; rc=$?
eq "export_key.sh refuses to overwrite the key" "$rc" "1"
eq "  the key is unchanged" "$(sha "$T/keys/key.pem")" "$before"
"$KEYGEN" "$T/keys/other-key.pem" "$T/kit/recipient.pem" >/dev/null 2>&1; rc=$?
eq "export_key.sh refuses to overwrite the certificate" "$rc" "1"
eq "  and wrote no new key" "$([ -f "$T/keys/other-key.pem" ] && echo written || echo none)" "none"

# ---- a round trip ----
today=$(date -u +%Y-%m-%d)
out=$("$EXPORT" 7 2>&1); rc=$?
eq "export 7 days: exit 0" "$rc" "0"
cms="$T/kit/exports/export-$today.cms"; txt="$T/kit/exports/export-$today.txt"
eq "the .cms file" "$([ -s "$cms" ] && echo yes || echo no)" "yes"
has "  its path is printed" "$out" "$cms"
eq "the query, exactly" "$(cat "$T/query")" "SELECT ts, kind, ip, method, host, path, user_agent, ja4, h2, score, class, detection_ids, detections, identity, asn, net_class, token, action, enforced, route, rule, outcome, known, summary, tcp, tcp_ttl FROM veritell.events WHERE ts > now() - INTERVAL 7 DAY ORDER BY ts FORMAT JSONEachRow"
eq "no plain text in the .cms" "$(grep -c -a 'alice\|curl/8' "$cms")" "0"
eq "folder mode 750" "$(mode "$T/kit/exports")" "750"
eq ".cms mode 640" "$(mode "$cms")" "640"
eq ".txt mode 640" "$(mode "$txt")" "640"
m=$(cat "$txt")
has "manifest: events" "$m" "events: 3"
has "manifest: days" "$m" "days: 7"
has "manifest: paths included" "$m" "paths: included"
has "manifest: the hash" "$m" "$(sha "$cms")"
has "manifest: the columns" "$m" "tcp_ttl"
eq "no unencrypted copy left" "$(ls -a "$T/kit/exports" | grep -v '^\.\{1,2\}$' | grep -vcE '\.(cms|txt)$')" "0"
"$OPEN" "$cms" "$T/keys/key.pem" "$T/opened" >/dev/null 2>&1; rc=$?
eq "open_export.sh: exit 0" "$rc" "0"
eq "  the same events" "$(cat "$T/opened/events.jsonl")" "$(cat "$T/events.jsonl")"
(cd "$T" && "$OPEN" "$cms" "$T/keys/key.pem" >/dev/null 2>&1)
eq "  default folder review-<name>" "$([ -f "$T/review-export-$today/events.jsonl" ] && echo yes || echo no)" "yes"

# ---- the wrong key ----
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$T/keys/wrong.pem" 2>/dev/null
"$OPEN" "$cms" "$T/keys/wrong.pem" "$T/wrong" >/dev/null 2>&1; rc=$?
eq "the wrong key: exit 1" "$rc" "1"
eq "  nothing written" "$([ -e "$T/wrong/events.jsonl" ] && echo written || echo none)" "none"
printf 'garbage' > "$T/bad.cms"
"$OPEN" "$T/bad.cms" "$T/keys/key.pem" "$T/bad" >/dev/null 2>&1; rc=$?
eq "a damaged file: exit 1" "$rc" "1"

# ---- --no-paths ----
"$EXPORT" 30 --no-paths >/dev/null 2>&1; rc=$?
eq "--no-paths: exit 0" "$rc" "0"
has "--no-paths: the query blanks the path" "$(cat "$T/query")" "SELECT ts, kind, ip, method, host, '' AS path, user_agent,"
has "--no-paths: 30 days" "$(cat "$T/query")" "INTERVAL 30 DAY"
has "manifest: paths removed" "$(cat "$txt")" "paths: removed"
"$EXPORT" --no-paths 5 >/dev/null 2>&1
has "--no-paths before days works too" "$(cat "$T/query")" "INTERVAL 5 DAY"
"$EXPORT" >/dev/null 2>&1
has "default: 30 days" "$(cat "$T/query")" "INTERVAL 30 DAY"

# ---- days checked ----
for bad in 0 31 abc 7x -3; do
  "$EXPORT" "$bad" >/dev/null 2>&1; rc=$?
  eq "days '$bad' refused (exit 2)" "$rc" "2"
done
"$EXPORT" 7 --paths >/dev/null 2>&1; rc=$?
eq "an unknown option refused (exit 2)" "$rc" "2"

# ---- a failing pipeline changes nothing ----
before=$(sha "$cms"); before_txt=$(sha "$txt")
STUB_FAIL=1 "$EXPORT" 7 >/dev/null 2>&1; rc=$?
eq "ClickHouse failing: exit 1" "$rc" "1"
eq "  today's export unchanged" "$(sha "$cms")" "$before"
eq "  and its manifest" "$(sha "$txt")" "$before_txt"
eq "  no temp files left" "$(ls -a "$T/kit/exports" | grep -v '^\.\{1,2\}$' | grep -vcE '\.(cms|txt)$')" "0"

# ---- newest 3 kept ----
for d in 2026-01-01 2026-01-02 2026-01-03 2026-01-04; do
  printf x > "$T/kit/exports/export-$d.cms"; printf x > "$T/kit/exports/export-$d.txt"
done
"$EXPORT" 7 >/dev/null 2>&1
eq "newest 3 .cms kept" "$(cd "$T/kit/exports" && ls export-*.cms | tr '\n' ' ')" "export-2026-01-03.cms export-2026-01-04.cms export-$today.cms "
eq "newest 3 .txt kept" "$(cd "$T/kit/exports" && ls export-*.txt | wc -l | tr -d ' ')" "3"

echo
if [ "$fails" = 0 ]; then echo "ALL PASSED"; else echo "$fails FAILED"; fi
exit "$fails"
