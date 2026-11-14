#!/usr/bin/env bash
# Tests for the trusted Web Bot Auth agents in the kit: agents_wire in lib.sh
# and what the other files carry. Runs anywhere, as any user:
#   deploy/test_agents.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fails=0
eq() { if [ "$2" = "$3" ]; then echo "PASS  $1"; else echo "FAIL  $1: wanted '$3', got '$2'"; fails=$((fails+1)); fi; }

KIT="$T/kit"
mkdir -p "$KIT"
cp "$HERE/lib.sh" "$KIT/"
cat > "$KIT/site.conf" <<CONF
SITE_HOST=example.test
SITE_NETWORK=site_default
SITE_UPSTREAM=web:8081
CONF
printf 'CLICKHOUSE_PASSWORD=x\n' > "$KIT/kit.env"; chmod 600 "$KIT/kit.env"
wire() { (cd "$KIT" && SCRIPT=test RUN_ID=t KIT="$KIT" bash -c '. ./lib.sh >/dev/null; agents_wire'); }
val() { sed -n 's/^VERITELL_WBA_AGENTS=//p' "$KIT/kit.env"; }

# ---- agents_wire ----
eq "no file: empty"                     "$(wire)" ""
eq "no file: kit.env has the empty key" "$(grep -c '^VERITELL_WBA_AGENTS=$' "$KIT/kit.env")" 1
eq "makes agents/"                      "$([ -d "$KIT/agents" ] && echo yes)" yes
: > "$KIT/agents/agents.json"
eq "empty file: still none"             "$(wire)" ""
printf '{"agents":[]}\n' > "$KIT/agents/agents.json"
eq "a file: its path in the gateway"    "$(wire)" /etc/veritell/agents/agents.json
eq "a file: written to kit.env"         "$(val)" /etc/veritell/agents/agents.json
eq "a file: one line only"              "$(grep -c '^VERITELL_WBA_AGENTS=' "$KIT/kit.env")" 1
rm "$KIT/agents/agents.json"
eq "file removed: back to none"         "$(wire)" ""
eq "file removed: kit.env empty again"  "$(val)" ""
eq "kit.env keeps its other keys"       "$(grep -c '^CLICKHOUSE_PASSWORD=x$' "$KIT/kit.env")" 1

# ---- the kit carries it ----
for f in compose.yml compose.host.yml; do
  eq "$f passes --wba-agents from kit.env" "$(grep -A1 -- '- --wba-agents' "$HERE/$f" | tail -1 | tr -d ' ')" '-${VERITELL_WBA_AGENTS:-}'
  eq "$f mounts agents/ read-only"         "$(grep -c -- '- ./agents:/etc/veritell/agents:ro' "$HERE/$f")" 1
done
eq "update.sh keeps agents/"               "$(grep -c -- '--exclude agents/' "$HERE/update.sh")" 1
eq "update.sh wires it"                    "$(grep -c '^agents_wire' "$HERE/update.sh")" 1
eq "install.sh wires it"                   "$(grep -c '^agents_wire' "$HERE/install.sh")" 1

echo
if [ "$fails" = 0 ]; then echo "ALL PASSED"; else echo "$fails FAILED"; fi
exit "$fails"
