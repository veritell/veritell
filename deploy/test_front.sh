#!/usr/bin/env bash
# Tests for the redirect and port modes of lib.sh: front_state,
# rules_apply and rules_remove, with stub iptables, ip6tables, ss and docker.
# Runs anywhere, as any user:  deploy/test_front.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fails=0
eq() { if [ "$2" = "$3" ]; then echo "PASS  $1"; else echo "FAIL  $1: wanted '$3', got '$2'"; fails=$((fails+1)); fi; }
has() { if printf '%s\n' "$2" | grep -qF -- "$3"; then echo "PASS  $1"; else echo "FAIL  $1: wanted a line with '$3' in:"; printf '%s\n' "$2" | sed 's/^/        /'; fails=$((fails+1)); fi; }
hasnt() { if printf '%s\n' "$2" | grep -qF -- "$3"; then echo "FAIL  $1: unwanted '$3'"; fails=$((fails+1)); else echo "PASS  $1"; fi; }

mkdir -p "$T/kit" "$T/bin"
cp "$HERE/lib.sh" "$T/kit/"
# Stubs. Reading (-S) prints the matching STUB_ variable; anything else is
# recorded in $T/calls as "<command> <arguments>". -w and its value are
# accepted anywhere.
cat > "$T/bin/iptables" <<'STUB'
#!/usr/bin/env bash
fam=4; case "$(basename "$0")" in ip6tables) fam=6;; esac
args="$*"
if printf '%s' " $args " | grep -q ' -S '; then
  case "$args" in
    *PREROUTING*) v="STUB_NAT$fam"; printf '%b' "${!v:-}";;
    *OUTPUT*)     v="STUB_OUT$fam"; printf '%b' "${!v:-}";;
    *INPUT*)      v="STUB_IN$fam";  printf '%b' "${!v:-}";;
  esac
  exit 0
fi
echo "$(basename "$0") $args" >> "$STUB_CALLS"
exit 0
STUB
chmod +x "$T/bin/iptables"; cp "$T/bin/iptables" "$T/bin/ip6tables"
cat > "$T/bin/ss" <<'STUB'
#!/usr/bin/env bash
printf '%b' "${STUB_SS:-}"
STUB
cat > "$T/bin/docker" <<'STUB'
#!/usr/bin/env bash
[ "$1" = ps ] && printf '%b' "${STUB_PS:-}"
exit 0
STUB
chmod +x "$T/bin/ss" "$T/bin/docker"
export PATH="$T/bin:$PATH" STUB_CALLS="$T/calls"

conf() { # mode, ipv6 on|off
  cat > "$T/kit/site.conf" <<CONF
FRONT=$1
IPV6=$2
SITE_HOST=example.test
CERT_FULLCHAIN=$T/le/fullchain.pem
CERT_KEY=$T/le/privkey.pem
UPSTREAM=127.0.0.1:443
UPSTREAM_TLS=on
PUBLIC_PORT=443
GATEWAY_PORT=8443
SITE_RELEASE_CMD="true"
SITE_RESTORE_CMD="true"
CONF
}
intent() { if [ -z "$1" ]; then printf 'CLICKHOUSE_PASSWORD=x\n' > "$T/kit/kit.env"; else printf 'CLICKHOUSE_PASSWORD=x\nVERITELL_FRONT=%s\n' "$1" > "$T/kit/kit.env"; fi; }
run() { (SCRIPT=test; . "$T/kit/lib.sh"; "$@"); }

# iptables -S lines as iptables prints them.
P4='-P PREROUTING ACCEPT\n'
NAT='-A PREROUTING -p tcp -m tcp --dport 443 -m addrtype --dst-type LOCAL -m comment --comment veritell -j REDIRECT --to-ports 8443\n'
OUT='-A OUTPUT ! -d 127.0.0.0/8 -p tcp -m tcp --dport 443 -m addrtype --dst-type LOCAL -m comment --comment veritell -j REDIRECT --to-ports 8443\n'
OUT6='-A OUTPUT ! -d ::1/128 -p tcp -m tcp --dport 443 -m addrtype --dst-type LOCAL -m comment --comment veritell -j REDIRECT --to-ports 8443\n'
IN='-A INPUT -p tcp -m tcp --dport 8443 -m conntrack --ctstate DNAT --ctorigdstport 443 -m comment --comment veritell -j ACCEPT\n'
DOCKER='-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER\n'
UFW='-A INPUT -j ufw-before-logging-input\n'
GW='veritell-gateway|\n'
state() { run front_state; }
# rules <nat4> <out4> <in4> [<nat6> <out6> <in6>]
rules() { STUB_NAT4=$1 STUB_OUT4=$2 STUB_IN4=$3 STUB_NAT6=${4:-} STUB_OUT6=${5:-} STUB_IN6=${6:-}; export STUB_NAT4 STUB_OUT4 STUB_IN4 STUB_NAT6 STUB_OUT6 STUB_IN6; }

# ---- redirect: front_state ----
conf redirect off
rm -f "$T/kit/kit.env"; rules "" "" ""
eq "redirect: no kit.env: not installed"         "$(state)" "not-installed"
intent site; rules "$P4" "" "$UFW"; export STUB_PS="$GW"
eq "redirect: site, no rules"                    "$(state)" "site"
intent ""
eq "redirect: no VERITELL_FRONT means site"      "$(state)" "site"
intent gateway; rules "$P4$NAT$DOCKER" "$OUT" "$IN$UFW"
eq "redirect: gateway, all rules, running"       "$(state)" "gateway"
export STUB_PS='site-web-1|\n'
eq "redirect: rules but no gateway"              "$(state)" "inconsistent: the gateway is not running"
export STUB_PS="$GW"
rules "$P4$DOCKER" "" "$UFW"
eq "redirect: gateway wanted, no rules"          "$(state)" "inconsistent: rules missing: nat4 out4 input4"
rules "$P4$NAT" "$OUT" "$UFW"
eq "redirect: no input rule"                     "$(state)" "inconsistent: rules missing: input4"
intent site; rules "$P4$NAT" "" "$IN"
eq "redirect: site wanted, rules set"            "$(state)" "inconsistent: rules set but kit.env says site: nat4 input4"
intent gateway; rules "$P4$DOCKER$NAT" "$OUT" "$IN"
eq "redirect: a DOCKER rule before ours"         "$(state)" "inconsistent: a DOCKER rule comes before the redirect (nat4)"
conf redirect on
rules "$P4$NAT" "$OUT" "$IN" "" "" ""
eq "redirect, IPv6 on: v4 rules only"            "$(state)" "inconsistent: rules missing: nat6 out6 input6"
rules "$P4$NAT" "$OUT" "$IN" "$NAT" "$OUT6" "$IN"
eq "redirect, IPv6 on: all six"                  "$(state)" "gateway"

# ---- redirect: rules_apply and rules_remove ----
conf redirect off
: > "$T/calls"; rules "$P4" "" "$UFW"
run rules_apply >/dev/null
calls=$(cat "$T/calls")
has "apply: the redirect, first in PREROUTING"  "$calls" "iptables -w -t nat -I PREROUTING 1 -p tcp --dport 443 -m addrtype --dst-type LOCAL -m comment --comment veritell -j REDIRECT --to-ports 8443"
has "apply: the same for the host's own connections, loopback excepted" "$calls" "iptables -w -t nat -I OUTPUT 1 ! -d 127.0.0.0/8 -p tcp --dport 443 -m addrtype --dst-type LOCAL -m comment --comment veritell -j REDIRECT --to-ports 8443"
has "apply: accept redirected only, first in INPUT" "$calls" "iptables -w -I INPUT 1 -p tcp --dport 8443 -m conntrack --ctstate DNAT --ctorigdstport 443 -m comment --comment veritell -j ACCEPT"
hasnt "apply, IPv6 off: no ip6tables"            "$calls" "ip6tables"
: > "$T/calls"; rules "$P4$NAT" "$OUT" "$IN"
run rules_apply >/dev/null
eq "apply when present: nothing added"           "$(grep -c -- ' -I ' "$T/calls")" "0"
: > "$T/calls"; rules "$P4$NAT" "" "$IN"
run rules_apply >/dev/null
eq "apply with one missing: only that one added" "$(grep -c -- ' -I ' "$T/calls")" "1"
has "  and it is the OUTPUT rule"                "$(cat "$T/calls")" "-t nat -I OUTPUT 1"
conf redirect on
: > "$T/calls"; rules "$P4" "" "$UFW" "" "" ""
run rules_apply >/dev/null
has "apply, IPv6 on: ip6tables too"              "$(cat "$T/calls")" "ip6tables -w -t nat -I PREROUTING 1"
has "apply, IPv6 on: ::1 excepted in OUTPUT"     "$(cat "$T/calls")" "ip6tables -w -t nat -I OUTPUT 1 ! -d ::1/128"
conf redirect off
: > "$T/calls"; rules "$P4$NAT$DOCKER$NAT" "$OUT" "$IN$UFW"
run rules_remove >/dev/null
calls=$(cat "$T/calls")
eq "remove: each copy of the nat rule"           "$(grep -c -- 'iptables -w -t nat -D PREROUTING -p tcp -m tcp --dport 443 -m addrtype --dst-type LOCAL -m comment --comment veritell -j REDIRECT --to-ports 8443' "$T/calls")" "2"
has "remove: the OUTPUT rule"                    "$calls" "iptables -w -t nat -D OUTPUT ! -d 127.0.0.0/8 -p tcp -m tcp --dport 443"
has "remove: the input rule"                     "$calls" "iptables -w -D INPUT -p tcp -m tcp --dport 8443 -m conntrack --ctstate DNAT --ctorigdstport 443 -m comment --comment veritell -j ACCEPT"
hasnt "remove: Docker's rule is left alone"      "$calls" "-j DOCKER"
hasnt "remove: ufw's rule is left alone"         "$calls" "ufw-before"
: > "$T/calls"; rules "$P4" "" "$UFW"
run rules_remove >/dev/null
eq "remove when absent: nothing deleted"         "$(grep -c -- ' -D ' "$T/calls")" "0"

# ---- port: front_state ----
conf port off
SS_NGINX='LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=12,fd=6),("nginx",pid=13,fd=6))\nLISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=12,fd=5))\n'
SS_GW='LISTEN 0 4096 *:443 *:* users:(("veritell",pid=99,fd=9))\nLISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=12,fd=5))\n'
SS_GW_LOCAL='LISTEN 0 4096 127.0.0.1:443 0.0.0.0:* users:(("veritell",pid=99,fd=9))\n'
SS_NONE='LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=12,fd=5))\nLISTEN 0 511 0.0.0.0:8443 0.0.0.0:* users:(("caddy",pid=7,fd=5))\n'
intent site; export STUB_SS="$SS_NGINX"
eq "port: site, nginx on 443"                    "$(state)" "site"
intent gateway; export STUB_SS="$SS_GW"
eq "port: gateway on 443"                        "$(state)" "gateway"
export STUB_SS="$SS_NGINX"
eq "port: gateway wanted, nginx holds it"        "$(state)" "inconsistent: kit.env says gateway but nginx listens on 443"
intent site; export STUB_SS="$SS_GW"
eq "port: site wanted, the gateway holds it"     "$(state)" "inconsistent: kit.env says site but veritell listens on 443"
export STUB_SS="$SS_NONE"
eq "port: nothing on 443 (80 and 8443 ignored)"  "$(state)" "inconsistent: nothing listens on 443"
intent gateway; export STUB_SS="$SS_GW_LOCAL"
eq "port: 127.0.0.1:443 is not the public port"  "$(state)" "inconsistent: nothing listens on 443"

# ---- compose mode is today's: FRONT missing ----
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
mkdir -p "$T/site"; printf 'WEB_HTTPS_PUBLISH=443\n' > "$T/site/.env.production"
printf 'VERITELL_PUBLISH=127.0.0.1:9443\n' > "$T/kit/kit.env"
export STUB_PS='veritell-gateway|127.0.0.1:9443->8443/tcp\nsite-web-1|0.0.0.0:443->443/tcp\n'
eq "no FRONT: the compose mode, as before"       "$(state)" "nginx"

echo
if [ "$fails" = 0 ]; then echo "ALL PASSED"; else echo "$fails FAILED"; fi
exit "$fails"
