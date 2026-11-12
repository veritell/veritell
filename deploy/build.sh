#!/usr/bin/env bash
# On the workstation: builds the gateway for the host and assembles the kit
# in dist/veritell-kit, ready to copy to the host (see README.md).
#   deploy/build.sh [target]      default x86_64-unknown-linux-gnu.2.36
# For a rehearsal on an Apple-silicon machine's Linux VM, use
# aarch64-unknown-linux-musl.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET=${1:-x86_64-unknown-linux-gnu.2.36}
cd "$ROOT"
cargo +stable zigbuild --release --target "$TARGET" -p veritell-proxy
python3 deploy/make_events_sql.py
OUT="$ROOT/dist/veritell-kit"
rm -rf "$OUT"; mkdir -p "$OUT/clickhouse"
BIN="target/${TARGET%.2.*}/release/veritell"
# A binary older than a source file was not relinked (for example, another
# checkout built into this target folder): refuse it.
newest=$(find crates -name '*.rs' -newer "$BIN" -print -quit)
[ -z "$newest" ] || { echo "$BIN is older than $newest: stale build; run cargo clean -p veritell-proxy --release --target ${TARGET%.2.*} and build again" >&2; exit 1; }
cp "$BIN" "$OUT/veritell"
cp Dockerfile.prebuilt deploy/compose.yml deploy/policy.yaml deploy/lib.sh deploy/site.conf.example \
   deploy/install.sh deploy/cutover.sh deploy/rollback.sh deploy/renew-hook.sh deploy/watch.sh deploy/install-watch.sh deploy/update.sh deploy/migrate.sh deploy/status.sh \
   deploy/compose.host.yml deploy/restore-front.sh deploy/uninstall.sh deploy/report.py deploy/report.sh deploy/export.sh deploy/README.md "$OUT/"
if [ -f deploy/recipient.pem ]; then
  cp deploy/recipient.pem "$OUT/"
elif [ "${VERITELL_KIT_NO_EXPORT:-0}" = 1 ]; then
  echo "warning: deploy/recipient.pem is missing; this kit cannot run export.sh" >&2
else
  echo "deploy/recipient.pem is missing, so export.sh would fail on the host. Add it, or set VERITELL_KIT_NO_EXPORT=1 to build a kit without export." >&2
  exit 1
fi
cp tools/known_link.py "$OUT/"
[ -f deploy/client-address.md ] && cp deploy/client-address.md "$OUT/"
cp deploy/clickhouse/low-memory.xml deploy/clickhouse/events.sql deploy/clickhouse/migrate.sql "$OUT/clickhouse/"
( cd "$OUT" && shasum -a 256 veritell > veritell.sha256 )
echo "kit in $OUT ($(cut -c1-16 "$OUT/veritell.sha256")...)"
