#!/usr/bin/env bash
# The fast test suite: fixed contracts, Rust tests, the rollout kit's tests.
# Slow or environment-bound runs are separate (see AGENTS.md):
# scripts/e2e.sh, scripts/e2e_sni.sh, node lab/run.mjs, scripts/fuzz.sh, scripts/soak.sh.
set -euo pipefail
cd "$(dirname "$0")"

LOG=$(mktemp); trap 'rm -f "$LOG"' EXIT
step() { echo "-- $1"; shift; "$@" >"$LOG" 2>&1 || { cat "$LOG"; echo "FAILED: $*"; exit 1; }; }

step "fixed contracts"  shasum -a 256 -c .acceptance.sha256 --quiet
step "cargo test"       cargo test --workspace -q
step "deploy/lib.sh"    bash deploy/test_lib.sh
step "deploy/front"     bash deploy/test_front.sh
step "deploy/export"    bash deploy/test_export.sh
step "deploy/report"    python3 -I deploy/test_report.py
step "deploy/certs"     bash deploy/test_certs.sh
step "deploy/asn"       bash deploy/test_asn.sh
echo "core: all passed"
