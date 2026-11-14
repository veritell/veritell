#!/usr/bin/env bash
# Who holds the public HTTPS port (any mode), and is it answering. Changes nothing.
SCRIPT=status
. "$(dirname "$0")/lib.sh"
state=$(front_state)
echo "front: $state"
echo "mode: $FRONT"
case "$FRONT:$state" in
  compose:gateway) echo "public $PUBLIC_PORT through the gateway: $(status_via "$PUBLIC_PORT" /__veritell/probe.js)"; echo "nginx on $NGINX_LOCAL_HTTPS: $(status_via "${NGINX_LOCAL_HTTPS##*:}")";;
  compose:nginx) echo "public $PUBLIC_PORT (nginx): $(status_via "$PUBLIC_PORT")"; echo "gateway beside it on 9443: $(status_via 9443 /__veritell/probe.js)";;
  redirect:gateway) echo "public $PUBLIC_PORT through the redirect: $(status_public "$PUBLIC_PORT" /__veritell/probe.js)"; echo "gateway on $GATEWAY_PORT: $(status_via "$GATEWAY_PORT" /__veritell/probe.js)"; echo "the site on $UPSTREAM: $(upstream_status /)";;
  redirect:site) echo "public $PUBLIC_PORT (the site): $(status_public "$PUBLIC_PORT")"; echo "gateway beside it on $GATEWAY_PORT: $(status_via "$GATEWAY_PORT" /__veritell/probe.js)";;
  port:gateway) echo "public $PUBLIC_PORT through the gateway: $(status_via "$PUBLIC_PORT" /__veritell/probe.js)"; echo "the site on $UPSTREAM: $(upstream_status /)";;
  port:site) echo "public $PUBLIC_PORT (the site): $(status_via "$PUBLIC_PORT")"; echo "gateway beside it on 9443: $(status_via 9443 /__veritell/probe.js)";;
esac
# The dashboard on the host's loopback: 401 without the token, 200 with it.
# The token goes to curl on stdin, never on its command line.
admin=$(get_kv "$KIT/kit.env" VERITELL_ADMIN_PUBLISH); admin=${admin:-127.0.0.1:9090}
token=$(get_kv "$KIT/gateway.env" VERITELL_ADMIN_TOKEN)
bare=$(curl -s --max-time 5 -o /dev/null -w '%{http_code}' "http://$admin/api/summary" || true)
with=$(printf 'user = "admin:%s"\n' "$token" | curl -s --max-time 5 -K - -o /dev/null -w '%{http_code}' "http://$admin/api/summary" || true)
echo "dashboard on $admin: $bare without the token, $with with it"
asn=$(get_kv "$KIT/kit.env" VERITELL_ASN_DB)
if [ "$ASN_DB" = off ]; then echo "ASN database: off (site.conf)"
elif [ -n "$asn" ] && [ -s "$KIT/asn/ip2asn.tsv" ]; then
  echo "ASN database: $(asn_rows "$KIT/asn/ip2asn.tsv") ranges, downloaded $(date -u -r "$KIT/asn/ip2asn.tsv" '+%Y-%m-%d %H:%M UTC' 2>/dev/null || echo '?')"
else echo "ASN database: none (asn=0, net_class unknown in the events): run $KIT/asn.sh"; fi
if [ -n "$(get_kv "$KIT/kit.env" VERITELL_WBA_AGENTS)" ] && [ -s "$KIT/agents/agents.json" ]; then
  echo "Web Bot Auth: trusted agents from agents/agents.json"
else echo "Web Bot Auth: no trusted agent"; fi
case "$(get_kv "$KIT/kit.env" VERITELL_FRONT_IPV6)" in
  true) echo "IPv6 visitors: their own address (front network with IPv6)";;
  false) echo "IPv6 visitors: none expected (IPV6=off or no IPv6 on this host)";;
  *) [ "$FRONT" = compose ] && echo "IPv6 visitors: through docker-proxy, all with the bridge's address: run update.sh";;
esac
[ "${state%%:*}" = inconsistent ] && exit 1 || exit 0
