#!/usr/bin/env bash
# Opens a partner's export:
#   tools/export/open_export.sh <export.cms> <private key> [out dir]
# -> <out dir>/events.jsonl   (default out dir: review-<the .cms name without .cms>)
# Checks that every line is a JSON object. On any failure: exit 1 and no
# events.jsonl, one gateway event per line.
set -euo pipefail
CMS=${1:?usage: open_export.sh <export.cms> <private key> [out dir]}
KEY=${2:?usage: open_export.sh <export.cms> <private key> [out dir]}
b=$(basename "$CMS"); OUT=${3:-review-${b%.cms}}
OPENSSL=${OPENSSL:-openssl}
# CMS with AES-GCM needs OpenSSL 3 or later (LibreSSL, as on macOS, has none).
case "$("$OPENSSL" version 2>/dev/null)" in
  "OpenSSL "[3-9]*|"OpenSSL "[1-9][0-9]*) ;;
  *) echo "needs OpenSSL 3 or later as \$OPENSSL (found: $("$OPENSSL" version 2>/dev/null || echo none))" >&2; exit 1;;
esac
[ -f "$CMS" ] && [ -f "$KEY" ] || { echo "open_export.sh: $CMS or $KEY is not a file" >&2; exit 1; }
created=0
if [ ! -d "$OUT" ]; then mkdir -p "$OUT"; created=1; fi
parent=$(cd "$OUT/.." && pwd)
tmp=$(mktemp "$parent/.events.XXXXXX")
cleanup() { rm -f "$tmp"; [ "$created" = 1 ] && rmdir "$OUT" 2>/dev/null; return 0; }
trap cleanup EXIT
fail() { echo "open_export.sh: $1" >&2; exit 1; }
"$OPENSSL" cms -decrypt -binary -inform DER -in "$CMS" -inkey "$KEY" 2>/dev/null | gunzip -c > "$tmp" \
  || fail "could not open $CMS with $KEY (wrong key, or the file is damaged)"
n=$(python3 -I -c '
import json, sys
n = 0
for i, line in enumerate(open(sys.argv[1], encoding="utf-8"), 1):
    if not line.strip():
        continue
    try:
        ok = isinstance(json.loads(line), dict)
    except ValueError:
        ok = False
    if not ok:
        sys.exit("line %d is not a JSON object" % i)
    n += 1
print(n)' "$tmp") || fail "the decrypted data is not events (see above)"
mv "$tmp" "$OUT/events.jsonl"
created=0
echo "$n events in $OUT/events.jsonl"
