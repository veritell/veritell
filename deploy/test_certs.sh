#!/usr/bin/env bash
# Tests for copy_certs and copy_extra_certs in lib.sh: the site's certificate
# and the certificates of other sites on the host (EXTRA_CERT_NAMES). Runs
# anywhere, as any user, in rehearsal mode:  deploy/test_certs.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fails=0
eq() { if [ "$2" = "$3" ]; then echo "PASS  $1"; else echo "FAIL  $1: wanted '$3', got '$2'"; fails=$((fails+1)); fi; }
has() { if printf '%s' "$2" | grep -q -- "$3"; then echo "PASS  $1"; else echo "FAIL  $1: wanted '$3' in '$2'"; fails=$((fails+1)); fi; }

mkdir -p "$T/kit" "$T/le"
cp "$HERE/lib.sh" "$T/kit/"
for n in example.test veritell.test www.veritell.test; do
  mkdir -p "$T/le/$n"; echo "chain $n" > "$T/le/$n/fullchain.pem"; echo "key $n" > "$T/le/$n/privkey.pem"
done
conf() { # extra names
  cat > "$T/kit/site.conf" <<CONF
FRONT=compose
SITE_NETWORK=site_default
SITE_UPSTREAM=web:8081
SITE_HOST=example.test
CERT_NAME=example.test
LETSENCRYPT_LIVE=$T/le
PUBLIC_PORT=443
EXTRA_CERT_NAMES="$1"
CONF
}
run() { (SCRIPT=test; REHEARSAL=1; . "$T/kit/lib.sh"; "$@") 2>&1; }

# ---- no extra names: the site's certificate only, an empty sni folder ----
conf ""
out=$(run copy_certs)
eq  "the site's certificate is copied"          "$(cat "$T/kit/certs/cert.pem")" "chain example.test"
eq  "and its key"                               "$(cat "$T/kit/certs/key.pem")" "key example.test"
eq  "no extra names: certs/sni exists, empty"   "$(ls -A "$T/kit/certs/sni" | wc -l | tr -d ' ')" "0"

# ---- two extra names ----
conf "veritell.test www.veritell.test"
out=$(run copy_certs)
eq  "an extra certificate is copied by name"    "$(cat "$T/kit/certs/sni/veritell.test/fullchain.pem")" "chain veritell.test"
eq  "with its key"                              "$(cat "$T/kit/certs/sni/veritell.test/privkey.pem")" "key veritell.test"
eq  "the second name too"                       "$(cat "$T/kit/certs/sni/www.veritell.test/fullchain.pem")" "chain www.veritell.test"
eq  "the site's certificate is unchanged"       "$(cat "$T/kit/certs/cert.pem")" "chain example.test"

# ---- a name dropped from the list is removed on the next copy ----
conf "veritell.test"
out=$(run copy_certs)
eq  "a dropped name leaves certs/sni"           "$([ -d "$T/kit/certs/sni/www.veritell.test" ] && echo there || echo gone)" "gone"

# ---- a missing certificate or a bad name: skipped, the rest still copied ----
conf "missing.test ../etc veritell.test"
out=$(run copy_certs)
has "a name without a certificate is reported"  "$out" "no certificate for missing.test"
has "a name that is not a host name is refused" "$out" "../etc is not a host name"
eq  "and the valid name is still copied"        "$(cat "$T/kit/certs/sni/veritell.test/fullchain.pem")" "chain veritell.test"
eq  "nothing is written outside certs/sni"      "$(ls "$T/kit/certs/sni")" "veritell.test"
eq  "the site's certificate is still there"     "$(cat "$T/kit/certs/cert.pem")" "chain example.test"

# ---- a renewal is seen in the checksums (redirect and port modes) ----
cat >> "$T/kit/site.conf" <<CONF
FRONT=redirect
CERT_FULLCHAIN=$T/le/example.test/fullchain.pem
CERT_KEY=$T/le/example.test/privkey.pem
CONF
before=$(run cert_sums)
echo "renewed" > "$T/le/veritell.test/fullchain.pem"
after=$(run cert_sums)
eq  "renewing an extra certificate changes the sums" "$([ "$before" != "$after" ] && echo changed || echo same)" "changed"

echo
if [ "$fails" -eq 0 ]; then echo "ALL PASSED"; else echo "$fails FAILED"; fi
exit "$fails"
