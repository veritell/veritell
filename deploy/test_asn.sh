#!/usr/bin/env bash
# Tests for asn.sh and the ASN functions in lib.sh: download, refusal,
# unchanged, restart and going back. Downloads are file: URLs; `docker` is a
# stub, and so is `curl` for the gateway's answer (it answers 000 while the
# ASN file in place has a row with GATEWAY-REJECTS, as a gateway that cannot
# load it would). Runs anywhere, as any user:  deploy/test_asn.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fails=0
eq() { if [ "$2" = "$3" ]; then echo "PASS  $1"; else echo "FAIL  $1: wanted '$3', got '$2'"; fails=$((fails+1)); fi; }

KIT="$T/kit"
mkdir -p "$KIT" "$T/bin" "$T/src"
cp "$HERE/lib.sh" "$HERE/asn.sh" "$KIT/"
cat > "$KIT/site.conf" <<CONF
SITE_HOST=example.test
SITE_NETWORK=site_default
SITE_UPSTREAM=web:8081
CONF
printf 'CLICKHOUSE_PASSWORD=x\nVERITELL_PUBLISH=127.0.0.1:9443\n' > "$KIT/kit.env"; chmod 600 "$KIT/kit.env"

# docker: `ps` prints $STUB_PS; `compose ... up` is counted in $T/up.
cat > "$T/bin/docker" <<'STUB'
#!/usr/bin/env bash
case "$1" in
  ps) printf '%b' "${STUB_PS:-}";;
  compose) case " $* " in *" up "*) echo up >> "$STUB_DIR/up";; esac;;
esac
exit 0
STUB
# curl: downloads go to the real one; the gateway check (-w) answers 200,
# or 000 while the ASN file in place has GATEWAY-REJECTS.
REAL_CURL=$(command -v curl)
cat > "$T/bin/curl" <<STUB
#!/usr/bin/env bash
case " \$* " in
  *" -w "*) if grep -q GATEWAY-REJECTS "$KIT/asn/ip2asn.tsv" 2>/dev/null; then printf 000; else printf 200; fi;;
  *) exec "$REAL_CURL" "\$@";;
esac
STUB
chmod +x "$T/bin/docker" "$T/bin/curl"
export PATH="$T/bin:$PATH" STUB_DIR="$T" ASN_DB_MIN_ROWS=5 GATEWAY_WAIT=2

fix="$HERE/fixtures/ip2asn.tsv"
gz() { gzip -c > "$T/src/$1"; }
gz good.tsv.gz < "$fix"
{ cat "$fix"; printf '100.64.0.0\t100.64.0.255\t64510\tUS\tEXAMPLE-NEW\n'; } | gz good2.tsv.gz
{ cat "$fix"; printf '100.65.0.0\t100.65.0.255\t64511\tUS\tGATEWAY-REJECTS\n'; } | gz rejects.tsv.gz
head -3 "$fix" | gz short.tsv.gz
{ cat "$fix"; printf '100.66.0.0\t100.66.0.255\t64512\tUS\n'; } | gz fields.tsv.gz
{ cat "$fix"; printf '100.67.0.0\t100.67.0.255\tAS64513\tUS\tX\n'; } | gz asnum.tsv.gz
{ cat "$fix"; printf '100.68.0.0\t2001:db8::1\t64514\tUS\tX\n'; } | gz family.tsv.gz
cat "$fix" > "$T/src/notgz.tsv.gz"
cp "$fix" "$T/src/plain.tsv"

GW='veritell-gateway\n'
run_asn() { (cd "$T" && ASN_DB_URL="file://$T/src/$1" STUB_PS="${STUB_PS:-}" "$KIT/asn.sh" ${2:+"$2"} >"$T/out" 2>&1); echo $?; }
ups() { [ -f "$T/up" ] && wc -l < "$T/up" | tr -d ' ' || echo 0; }
inplace() { if [ -f "$KIT/asn/ip2asn.tsv" ]; then gzip -dc "$T/src/$1" | cmp -s - "$KIT/asn/ip2asn.tsv" && echo same || echo different; else echo missing; fi; }
wired() { sed -n 's/^VERITELL_ASN_DB=//p' "$KIT/kit.env"; }
mode() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"; }
P=/etc/veritell/asn/ip2asn.tsv

# ---- first download, no gateway running ----
eq "a good file is put in place"           "$(run_asn good.tsv.gz --no-restart)" 0
eq "  the same rows"                        "$(inplace good.tsv.gz)" same
eq "  kit.env points the gateway at it"     "$(wired)" "$P"
eq "  readable by the gateway's user"       "$(mode "$KIT/asn/ip2asn.tsv")" 644
eq "  kit.env stays mode 600"               "$(mode "$KIT/kit.env")" 600
eq "  nothing left half-done"               "$(ls "$KIT/asn" | tr '\n' ' ')" "ip2asn.tsv "
eq "  no restart"                           "$(ups)" 0

# ---- the same file again, the gateway running ----
eq "the same file again"                    "$(STUB_PS=$GW run_asn good.tsv.gz)" 0
eq "  is said to be unchanged"              "$(grep -c 'unchanged (6 ranges)' "$T/out")" 1
eq "  and does not restart the gateway"     "$(ups)" 0

# ---- refused files keep the one in place ----
for bad in short.tsv.gz fields.tsv.gz asnum.tsv.gz family.tsv.gz notgz.tsv.gz missing.tsv.gz; do
  eq "refused: $bad"                        "$(STUB_PS=$GW run_asn "$bad")" 1
  eq "  the file in place is kept"          "$(inplace good.tsv.gz)" same
  eq "  and stays wired"                    "$(wired)" "$P"
  eq "  nothing left behind"                "$(ls "$KIT/asn" | tr '\n' ' ')" "ip2asn.tsv "
done
eq "  no restart for any of them"           "$(ups)" 0
eq "why: too few rows"                      "$(STUB_PS=$GW run_asn short.tsv.gz >/dev/null; grep -c '3 rows, fewer than 5' "$T/out")" 1
eq "why: a row without 5 fields"            "$(STUB_PS=$GW run_asn fields.tsv.gz >/dev/null; grep -c 'line 7: 4 fields' "$T/out")" 1
eq "why: an AS that is not a number"        "$(STUB_PS=$GW run_asn asnum.tsv.gz >/dev/null; grep -c 'AS number AS64513' "$T/out")" 1
eq "why: two address families"              "$(STUB_PS=$GW run_asn family.tsv.gz >/dev/null; grep -c 'is not an address range' "$T/out")" 1
eq "only https or file: URLs"               "$(cd "$T" && ASN_DB_URL=http://127.0.0.1:9/x.tsv.gz "$KIT/asn.sh" --no-restart >/dev/null 2>&1; echo $?)" 1
rm -f "$T/up"

# ---- a new file, the gateway running ----
eq "a new file"                             "$(STUB_PS=$GW run_asn good2.tsv.gz)" 0
eq "  is put in place"                      "$(inplace good2.tsv.gz)" same
eq "  the gateway is restarted once"        "$(ups)" 1
eq "  and the previous file dropped"        "$(ls "$KIT/asn" | tr '\n' ' ')" "ip2asn.tsv "
rm -f "$T/up"

# ---- a new file the gateway does not start with ----
eq "a file the gateway refuses"             "$(STUB_PS=$GW run_asn rejects.tsv.gz)" 1
eq "  goes back to the previous file"       "$(inplace good2.tsv.gz)" same
eq "  restarted, then restarted back"       "$(ups)" 2
eq "  still wired"                          "$(wired)" "$P"
eq "  says so"                              "$(grep -c 'back on the previous ASN database' "$T/out")" 1
rm -f "$T/up"

# ---- a new file, the gateway not running: no restart ----
eq "a new file, no gateway running"         "$(run_asn good.tsv.gz)" 0
eq "  is put in place"                      "$(inplace good.tsv.gz)" same
eq "  without a restart"                    "$(ups)" 0

# ---- refused with no file before it: the gateway goes on without one ----
rm -rf "$KIT/asn"
eq "the first file refused by the gateway"  "$(STUB_PS=$GW run_asn rejects.tsv.gz)" 1
eq "  leaves no file"                       "$(inplace good.tsv.gz)" missing
eq "  and kit.env says none"                "$(wired)" ""
rm -f "$T/up"

# ---- a plain .tsv URL ----
eq "an uncompressed .tsv URL"               "$(run_asn plain.tsv --no-restart)" 0
eq "  is put in place"                      "$(cmp -s "$fix" "$KIT/asn/ip2asn.tsv" && echo same)" same
eq "  and wired"                            "$(wired)" "$P"

# ---- ASN_DB=off ----
echo 'ASN_DB=off' >> "$KIT/site.conf"
eq "ASN_DB=off"                             "$(STUB_PS=$GW run_asn good.tsv.gz)" 0
eq "  kit.env says none"                    "$(wired)" ""
eq "  and the gateway restarts without it"  "$(ups)" 1
sed -i.bak '/^ASN_DB=/d' "$KIT/site.conf"; rm -f "$KIT/site.conf.bak" "$T/up"
echo 'ASN_DB=maybe' >> "$KIT/site.conf"
eq "ASN_DB must be on or off"               "$(run_asn good.tsv.gz)" 2
sed -i.bak '/^ASN_DB=/d' "$KIT/site.conf"; rm -f "$KIT/site.conf.bak"
eq "usage"                                  "$(run_asn good.tsv.gz --now)" 2

# ---- the kit carries it ----
for f in compose.yml compose.host.yml; do
  eq "$f passes --asn-db from kit.env"      "$(grep -A1 -- '- --asn-db' "$HERE/$f" | tail -1 | tr -d ' ')" '-${VERITELL_ASN_DB:-}'
  eq "$f mounts asn/ read-only"             "$(grep -c -- '- ./asn:/etc/veritell/asn:ro' "$HERE/$f")" 1
done
eq "build.sh puts asn.sh in the kit"        "$(grep -c 'deploy/asn.sh' "$HERE/build.sh")" 1
eq "update.sh keeps asn/"                   "$(grep -c -- '--exclude asn/' "$HERE/update.sh")" 1
eq "install.sh downloads it"                "$(grep -c 'asn.sh" --no-restart' "$HERE/install.sh")" 1
eq "install-watch.sh adds the weekly timer" "$(grep -c 'enable --now veritell-asn.timer' "$HERE/install-watch.sh")" 1
eq "uninstall.sh removes the timer"         "$(grep -c 'veritell-asn.timer' "$HERE/uninstall.sh")" 1

echo
if [ "$fails" = 0 ]; then echo "ALL PASSED"; else echo "$fails FAILED"; fi
exit "$fails"
