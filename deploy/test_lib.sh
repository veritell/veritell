#!/usr/bin/env bash
# Tests for lib.sh: set_kv and front_state, with a stub `docker`. Runs
# anywhere, as any user:  deploy/test_lib.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fails=0
eq() { if [ "$2" = "$3" ]; then echo "PASS  $1"; else echo "FAIL  $1: wanted '$3', got '$2'"; fails=$((fails+1)); fi; }

# A kit folder with lib.sh, a site.conf, and a stub docker on PATH that
# prints $STUB_PS for `docker ps`.
mkdir -p "$T/kit" "$T/site" "$T/bin"
cp "$HERE/lib.sh" "$T/kit/"
cat > "$T/kit/site.conf" <<CONF
SITE_DIR=$T/site
SITE_COMPOSE="true"
SITE_ENV_FILE=.env.production
SITE_WEB_SERVICE=web
SITE_NETWORK=site_default
SITE_UPSTREAM=web:8081
SITE_HOST=example.test
CERT_NAME=example.test
LETSENCRYPT_LIVE=$T/le
PUBLIC_PORT=443
NGINX_LOCAL_HTTPS=127.0.0.1:8444
CONF
cat > "$T/bin/docker" <<'STUB'
#!/usr/bin/env bash
[ "$1" = ps ] && printf '%b' "${STUB_PS:-}"
exit 0
STUB
chmod +x "$T/bin/docker"
export PATH="$T/bin:$PATH"
run() { (SCRIPT=test; . "$T/kit/lib.sh"; "$@"); }

# ---- set_kv ----
f="$T/site/.env.production"
printf 'A=1\nWEB_HTTPS_PUBLISH=443\nB=2\n' > "$f"; chmod 640 "$f"
RUN_ID=r1 run set_kv "$f" WEB_HTTPS_PUBLISH 127.0.0.1:8444
eq "set_kv replaces the value"           "$(cat "$f")" "$(printf 'A=1\nWEB_HTTPS_PUBLISH=127.0.0.1:8444\nB=2')"
eq "set_kv keeps the mode"               "$(stat -c '%a' "$f" 2>/dev/null || stat -f '%Lp' "$f")" "640"
eq "set_kv keeps the file as it was"     "$(cat "$f.before-test-r1")" "$(printf 'A=1\nWEB_HTTPS_PUBLISH=443\nB=2')"
RUN_ID=r1 run set_kv "$f" C 3
eq "set_kv appends a new key"            "$(tail -1 "$f")" "C=3"
eq "one backup per run"                  "$(ls "$f".before-test-* | wc -l | tr -d ' ')" "1"
eq "the run's backup is from before its first change" "$(grep -c '^C=' "$f.before-test-r1")" "0"
for r in r2 r3 r4 r5 r6 r7; do RUN_ID=$r run set_kv "$f" C "$r"; done
eq "at most five backups per script"     "$(ls "$f".before-test-* | wc -l | tr -d ' ')" "5"
eq "the oldest are the ones removed"     "$(ls "$f".before-test-* | sed 's/.*-//' | tr '\n' ' ')" "r3 r4 r5 r6 r7 "
RUN_ID=r8 run set_kv "$f" A "x=y"
eq "a value may contain ="               "$(grep '^A=' "$f")" "A=x=y"
eq "get_kv reads it back"                "$(run get_kv "$f" A)" "x=y"
eq "get_kv of a missing key is empty"    "$(run get_kv "$f" NOPE)" ""

# ---- ensure_admin_token ----
printf 'VERITELL_SECRET=s\n' > "$T/kit/gateway.env"; chmod 600 "$T/kit/gateway.env"
RUN_ID=r3 run ensure_admin_token >/dev/null
tok=$(sed -n 's/^VERITELL_ADMIN_TOKEN=//p' "$T/kit/gateway.env")
eq "ensure_admin_token adds a 64-hex token" "$(printf '%s' "$tok" | grep -cE '^[0-9a-f]{64}$')" "1"
eq "and keeps the other keys"               "$(head -1 "$T/kit/gateway.env")" "VERITELL_SECRET=s"
RUN_ID=r4 run ensure_admin_token >/dev/null
eq "a second run keeps the token"           "$(sed -n 's/^VERITELL_ADMIN_TOKEN=//p' "$T/kit/gateway.env")" "$tok"
eq "and the file stays mode 600"            "$(stat -c '%a' "$T/kit/gateway.env" 2>/dev/null || stat -f '%Lp' "$T/kit/gateway.env")" "600"

# ---- front_state ----
state() { STUB_PS="$1" run front_state; }
GW='veritell-gateway|0.0.0.0:443->8443/tcp, [::]:443->8443/tcp\n'
GW_LOCAL='veritell-gateway|127.0.0.1:9443->8443/tcp\n'
WEB='site-web-1|0.0.0.0:80->80/tcp, [::]:80->80/tcp, 0.0.0.0:443->443/tcp, [::]:443->443/tcp\n'
WEB_LOCAL='site-web-1|0.0.0.0:80->80/tcp, 127.0.0.1:8444->443/tcp\n'
rm -f "$T/kit/kit.env"
eq "no kit.env: not installed"           "$(state "")" "not-installed"
printf 'VERITELL_PUBLISH=127.0.0.1:9443\n' > "$T/kit/kit.env"; printf 'X=1\n' > "$f"
eq "before the cutover: nginx"           "$(state "$GW_LOCAL$WEB")" "nginx"
printf 'WEB_HTTPS_PUBLISH=443\n' > "$f"
eq "nginx, said explicitly"              "$(state "$GW_LOCAL$WEB")" "nginx"
printf 'VERITELL_PUBLISH=443\n' > "$T/kit/kit.env"; printf 'WEB_HTTPS_PUBLISH=127.0.0.1:8444\n' > "$f"
eq "after the cutover: gateway"          "$(state "$GW$WEB_LOCAL")" "gateway"
eq "set for the gateway, nothing on 443" "$(state "$GW_LOCAL$WEB_LOCAL")" "inconsistent: set for the gateway, but nothing publishes 443"
eq "set for the gateway, nginx on 443"   "$(state "$GW_LOCAL$WEB")" "inconsistent: set for the gateway, but site-web-1 publishes 443"
printf 'VERITELL_PUBLISH=127.0.0.1:9443\n' > "$T/kit/kit.env"; printf 'WEB_HTTPS_PUBLISH=443\n' > "$f"
eq "set for nginx, the gateway on 443"   "$(state "$GW$WEB_LOCAL")" "inconsistent: set for nginx, but veritell-gateway publishes 443"
eq "set for nginx, nothing on 443"       "$(state "$GW_LOCAL$WEB_LOCAL")" "inconsistent: set for nginx, but nothing publishes 443"
printf 'VERITELL_PUBLISH=443\n' > "$T/kit/kit.env"; printf 'WEB_HTTPS_PUBLISH=443\n' > "$f"
eq "both set for 443"                    "$(state "$GW")" "inconsistent: kit.env VERITELL_PUBLISH=443, site WEB_HTTPS_PUBLISH=443"
printf 'VERITELL_PUBLISH=443\n' > "$T/kit/kit.env"; printf 'WEB_HTTPS_PUBLISH=127.0.0.1:8444\n' > "$f"
eq "a gateway on 127.0.0.1:443 does not hold the public port" \
  "$(state 'veritell-gateway|127.0.0.1:443->8443/tcp\n'"$WEB_LOCAL")" "inconsistent: set for the gateway, but nothing publishes 443"
eq "nor does 8443 match 443"              "$(state 'veritell-gateway|0.0.0.0:8443->8443/tcp\n'"$WEB_LOCAL")" "inconsistent: set for the gateway, but nothing publishes 443"

echo
if [ "$fails" = 0 ]; then echo "ALL PASSED"; else echo "$fails FAILED"; fi
exit "$fails"
