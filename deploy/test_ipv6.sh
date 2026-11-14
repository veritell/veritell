#!/usr/bin/env bash
# Tests for IPv6: ipv6_wire in lib.sh, the IPv6 UPSTREAM split, and what
# compose.yml carries. Runs anywhere, as any user:  deploy/test_ipv6.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fails=0
eq() { if [ "$2" = "$3" ]; then echo "PASS  $1"; else echo "FAIL  $1: wanted '$3', got '$2'"; fails=$((fails+1)); fi; }

KIT="$T/kit"; mkdir -p "$KIT"
cp "$HERE/lib.sh" "$KIT/"
printf 'SITE_HOST=example.test\nSITE_NETWORK=site_default\nSITE_UPSTREAM=web:8081\n' > "$KIT/site.conf"
printf 'CLICKHOUSE_PASSWORD=x\n' > "$KIT/kit.env"; chmod 600 "$KIT/kit.env"
: > "$T/if_inet6"
# wire IPV6 [proc file]: run ipv6_wire with that setting.
wire() { (cd "$KIT" && SCRIPT=test RUN_ID=t KIT="$KIT" IPV6="$1" IPV6_PROC="${2:-$T/if_inet6}" bash -c '. ./lib.sh >/dev/null; ipv6_wire'); }
kv() { sed -n "s/^$1=//p" "$KIT/kit.env"; }

eq "auto, host with IPv6: on"          "$(wire auto)" on
eq "  network gets IPv6"               "$(kv VERITELL_FRONT_IPV6)" true
eq "  listens on both families"        "$(kv VERITELL_INNER_LISTEN)" '[::]:8443'
eq "auto, host without IPv6: off"      "$(wire auto "$T/none")" off
eq "  network IPv4 only"               "$(kv VERITELL_FRONT_IPV6)" false
eq "  listens on IPv4"                 "$(kv VERITELL_INNER_LISTEN)" 0.0.0.0:8443
eq "on: on"                            "$(wire on "$T/none")" on
eq "off: off"                          "$(wire off)" off
eq "  one line per key"                "$(grep -c '^VERITELL_FRONT_IPV6=' "$KIT/kit.env")" 1
eq "unset means auto"                  "$(cd "$KIT" && SCRIPT=test RUN_ID=t KIT="$KIT" IPV6_PROC="$T/if_inet6" bash -c 'unset IPV6; . ./lib.sh >/dev/null; ipv6_wire')" on
eq "kit.env keeps its other keys"      "$(grep -c '^CLICKHOUSE_PASSWORD=x$' "$KIT/kit.env")" 1

C="$HERE/compose.yml"
eq "compose.yml: --listen from kit.env"   "$(grep -A1 -- '- --listen' "$C" | tail -1 | tr -d ' ')" '-${VERITELL_INNER_LISTEN:-[::]:8443}'
eq "compose.yml: gateway on front"        "$(grep -c 'networks: \[front, site, store\]' "$C")" 1
eq "compose.yml: front's IPv6 from kit.env" "$(grep -A1 '^  front:' "$C" | tail -1 | tr -d ' ')" 'enable_ipv6:${VERITELL_FRONT_IPV6:-true}'
eq "update.sh wires it"                   "$(grep -c '^ipv6_wire' "$HERE/update.sh")" 1
eq "install.sh wires it"                  "$(grep -c '^ipv6_wire' "$HERE/install.sh")" 1

# UPSTREAM split for curl --resolve (install.sh, upstream_status).
up() { (cd "$KIT" && SCRIPT=test RUN_ID=t KIT="$KIT" bash -c ". ./lib.sh >/dev/null; $1 $2"); }
eq "upstream_host IPv4"               "$(up upstream_host 127.0.0.1:8444)" 127.0.0.1
eq "upstream_port IPv4"               "$(up upstream_port 127.0.0.1:8444)" 8444
eq "upstream_host name"               "$(up upstream_host site.internal:443)" site.internal
eq "upstream_host [::1]:8444"         "$(up upstream_host '[::1]:8444')" '[::1]'
eq "upstream_port [::1]:8444"         "$(up upstream_port '[::1]:8444')" 8444
eq "upstream_host brackets added"     "$(up upstream_host ::1:8444)" '[::1]'
eq "upstream_port ::1:8444"           "$(up upstream_port ::1:8444)" 8444
eq "upstream_host [2001:db8::5]:443"  "$(up upstream_host '[2001:db8::5]:443')" '[2001:db8::5]'
eq "install.sh uses the helpers"      "$(grep -c -- '--resolve "$SITE_HOST:$(upstream_port):$(upstream_host)"' "$HERE/install.sh")" 1

echo
if [ "$fails" = 0 ]; then echo "ALL PASSED"; else echo "$fails FAILED"; fi
exit "$fails"
