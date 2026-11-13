#!/usr/bin/env bash
# Where a target's corpus stops: the lines of this repository's crates that
# no input in the corpus reaches, grouped by function. Use it to find the
# gate a fuzzer cannot pass, then add a seed or dictionary word that passes
# it (see README.md, "Finding the gates").
#
#   fuzz/gaps.sh <target> [corpus dir...]  (from the repository root)
#
# Default: the target's corpus and its seeds (libFuzzer never copies seeds
# into the corpus, so both are needed).
#
# Needs: rustup component add llvm-tools-preview --toolchain nightly
set -euo pipefail
t="${1:?target}"
root="$(cd "$(dirname "$0")/.." && pwd)"
shift
dirs=("$@")
[ ${#dirs[@]} -gt 0 ] || dirs=("$root/fuzz/corpus/$t" "$root/fuzz/seeds/$t")
cd "$root"
rm -rf "fuzz/coverage/$t"
cargo +nightly fuzz coverage "$t" "${dirs[@]}" >/dev/null 2>&1 || cargo +nightly fuzz coverage "$t" "${dirs[@]}"
bin="$(rustc +nightly --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin"
exe=""
for d in fuzz/target target; do
  c="$d/x86_64-unknown-linux-gnu/coverage/x86_64-unknown-linux-gnu/release/$t"
  [ -x "$c" ] && { exe="$c"; break; }
done
[ -n "$exe" ] || { echo "coverage build of $t not found" >&2; exit 1; }
prof="fuzz/coverage/$t/coverage.profdata"
"$bin/llvm-cov" export -format=text -instr-profile="$prof" "$exe" -ignore-filename-regex='/(\.cargo|rustc|fuzz)/|/tests/' |
  python3 -I -c '
import json, sys, os
root = sys.argv[1]
data = json.load(sys.stdin)["data"][0]
# A gate is an unreached line in a function that some input entered.
# Functions no input entered are counted, not listed: the target does not
# call them, or a gate in a caller stops every input first.
missed, entered, skipped = {}, {}, 0
for fn in data["functions"]:
    f = fn["filenames"][0]
    if not f.startswith(root + "/crates/"):
        continue
    if fn["count"] == 0:
        skipped += 1
        continue
    hit = set()
    for r in fn["regions"]:
        ls, cs, le, ce, count, fid, _, kind = r[:8]
        if kind != 0 or fn["filenames"][fid] != f:
            continue
        if count > 0:
            hit.add(ls)
        else:
            missed.setdefault(f, {}).setdefault(ls, fn["name"])
    entered.setdefault(f, set()).update(hit)
total = 0
for f in sorted(missed):
    lines = open(f).read().split("\n")
    rows = [(l, n) for l, n in sorted(missed[f].items()) if l not in entered[f]]
    rows = [(l, lines[l - 1].strip()) for l, n in rows if l - 1 < len(lines) and lines[l - 1].strip() and not lines[l - 1].strip().startswith("//")]
    if not rows:
        continue
    total += len(rows)
    print("\n== %s" % os.path.relpath(f, root))
    for l, text in rows:
        print("  %5d  %s" % (l, text[:110]))
print("\n%d gate lines in entered functions; %d functions never entered" % (total, skipped))
' "$root"
