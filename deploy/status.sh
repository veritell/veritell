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
[ "${state%%:*}" = inconsistent ] && exit 1 || exit 0
