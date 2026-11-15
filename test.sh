#!/usr/bin/env bash
# The fast test suite: fixed contracts, Rust tests, the probe scripts and
# their captured reports, the rollout kit's tests.
# Slow or environment-bound runs are separate (see AGENTS.md):
# scripts/e2e.sh, scripts/e2e_sni.sh, node lab/run.mjs, scripts/fuzz.sh, scripts/soak.sh.
set -euo pipefail
cd "$(dirname "$0")"

LOG=$(mktemp); trap 'rm -f "$LOG"' EXIT
step() { echo "-- $1"; shift; "$@" >"$LOG" 2>&1 || { cat "$LOG"; echo "FAILED: $*"; exit 1; }; }

step "fixed contracts"  shasum -a 256 -c .acceptance.sha256 --quiet
step "cargo test"       cargo test --workspace -q
step "probe parses"     node --check probe/probe.js
step "behavior parses"  node --check probe/behavior.js
for f in probe/test/captured-*.json; do
  step "probe report $(basename "$f")" node probe/validate.mjs "$f"
done
step "deploy/lib.sh"    bash deploy/test_lib.sh
step "deploy/conf"      bash deploy/test_conf.sh
step "deploy/front"     bash deploy/test_front.sh
step "deploy/export"    bash deploy/test_export.sh
step "deploy/report"    python3 -I deploy/test_report.py
step "deploy/certs"     bash deploy/test_certs.sh
step "deploy/asn"       bash deploy/test_asn.sh
step "deploy/agents"    bash deploy/test_agents.sh
step "deploy/ipv6"      bash deploy/test_ipv6.sh
echo "core: all passed"
