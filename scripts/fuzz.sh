#!/usr/bin/env bash
# Run every veritell-fp fuzz target for a fixed time.
# Usage: scripts/fuzz.sh [seconds_per_target]   (default 60)
# Env:   FUZZ_TOOLCHAIN  rustup toolchain (default: stable, run with RUSTC_BOOTSTRAP=1;
#                        set to nightly in CI, where no bootstrap is needed)
set -u

secs="${1:-60}"
toolchain="${FUZZ_TOOLCHAIN:-stable}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
crate="$root/crates/veritell-fp"
fuzz="$crate/fuzz"
targets=(tls_clienthello h2_parse hpack_decode)

if [ "$toolchain" = "stable" ]; then
  export RUSTC_BOOTSTRAP=1
fi

cd "$crate" || exit 2
python3 "$fuzz/make_seeds.py" >/dev/null 2>&1 || true

fail=0
summary=()
for t in "${targets[@]}"; do
  corpus="$fuzz/corpus/$t"
  mkdir -p "$corpus" "$fuzz/artifacts/$t"
  # Copy seeds that are not already in the corpus (never overwrite).
  if [ -d "$fuzz/seeds/$t" ]; then
    for s in "$fuzz/seeds/$t"/*; do
      [ -f "$s" ] || continue
      [ -e "$corpus/seed_$(basename "$s")" ] || cp "$s" "$corpus/seed_$(basename "$s")"
    done
  fi

  log="$(mktemp "${TMPDIR:-/tmp}/fuzz_${t}.XXXXXX")"
  echo "== $t: ${secs}s ==" >&2
  cargo "+$toolchain" fuzz run "$t" "$corpus" -- \
    "-max_total_time=$secs" -timeout=1 -rss_limit_mb=2048 -malloc_limit_mb=64 \
    >"$log" 2>&1
  rc=$?

  runs="$(grep -E '^#[0-9]+' "$log" | tail -1 | sed -E 's/^#([0-9]+).*/\1/')"
  done_line="$(grep -E "^Done [0-9]+ runs" "$log" | tail -1 | sed -E 's/^Done ([0-9]+) runs.*/\1/')"
  runs="${done_line:-${runs:-?}}"
  cov="$(grep -E '^#[0-9]+.* cov: ' "$log" | tail -1 | sed -E 's/.* cov: ([0-9]+).*/\1/')"
  cov="${cov:-?}"
  artifact="$(grep -E 'Test unit written to ' "$log" | tail -1 | sed -E 's/.*written to //')"
  if grep -qE 'ERROR: libFuzzer|Test unit written|panicked at|out-of-memory|timeout after|AddressSanitizer' "$log" || [ "$rc" -ne 0 ]; then
    crashed=yes
    fail=1
    reason="$(grep -E 'ERROR: libFuzzer|panicked at|SUMMARY' "$log" | head -2 | tr '\n' ' ')"
    summary+=("$t: runs=$runs cov=$cov crash=yes artifact=${artifact:-none} rc=$rc ${reason}(log: $log)")
  else
    crashed=no
    summary+=("$t: runs=$runs cov=$cov crash=no artifact=none")
    rm -f "$log"
  fi
done

echo
for line in "${summary[@]}"; do echo "$line"; done
exit "$fail"
