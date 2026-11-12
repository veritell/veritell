#!/usr/bin/env bash
# Puts the gateway in front.
#   compose   nginx's HTTPS moves to NGINX_LOCAL_HTTPS and the gateway takes
#             PUBLIC_PORT. A few seconds without HTTPS while the two swap.
#   redirect  the firewall rules send PUBLIC_PORT to the gateway. No downtime.
#   port      SITE_RELEASE_CMD moves the site off PUBLIC_PORT, then the gateway
#             takes it. A few seconds without HTTPS.
#   site (nginx in compose) -> gateway   (from any other state it does nothing)
# If any step fails, or the site does not answer through the gateway
# afterwards, rollback.sh runs (from the EXIT trap) and the front is the site again.
SCRIPT=cutover
. "$(dirname "$0")/lib.sh"

state=$(front_state)
case "$state" in
  gateway) log "already done: the gateway is in front on $PUBLIC_PORT"; exit 0;;
  nginx|site) ;;
  *) log "not cutting over from '$state'. See status.sh; rollback.sh brings it back to the site"; exit 1;;
esac
case "$FRONT" in
  compose)
    [ "$(status_via 9443 /__veritell/probe.js)" = 200 ] || { log "the gateway is not answering on 127.0.0.1:9443: run install.sh first"; exit 1; }
    [ "$(status_via "$PUBLIC_PORT")" = 200 ] || { log "the site is not answering on $PUBLIC_PORT now; not touching it"; exit 1; };;
  redirect)
    [ "$(status_via "$GATEWAY_PORT" /__veritell/probe.js)" = 200 ] || { log "the gateway is not answering on 127.0.0.1:$GATEWAY_PORT: run install.sh first"; exit 1; }
    code_ok "$(upstream_status /)" || { log "the site is not answering on $UPSTREAM now; not touching it"; exit 1; };;
  port)
    [ "$(status_via 9443 /__veritell/probe.js)" = 200 ] || { log "the gateway is not answering on 127.0.0.1:9443: run install.sh first"; exit 1; }
    code_ok "$(status_via "$PUBLIC_PORT")" || { log "the site is not answering on $PUBLIC_PORT now; not touching it"; exit 1; };;
esac

# Whatever ends this script after the first change (a failed step under
# set -e, the check below, a signal), unless it got to the end: roll back.
changed=0; finished=0
on_exit() {
  if [ "$changed" = 1 ] && [ "$finished" != 1 ]; then
    log "the cutover did not finish: rolling back"
    "$KIT/rollback.sh" || log "the rollback reported a problem: run status.sh"
  fi
}
trap on_exit EXIT

changed=1
case "$FRONT" in
  compose)
    log "nginx HTTPS -> $NGINX_LOCAL_HTTPS"
    set_kv "$SITE_DIR/$SITE_ENV_FILE" WEB_HTTPS_PUBLISH "$NGINX_LOCAL_HTTPS"
    site_compose up -d --no-build "$SITE_WEB_SERVICE"
    log "gateway -> $PUBLIC_PORT"
    set_kv "$KIT/kit.env" VERITELL_PUBLISH "$PUBLIC_PORT"
    gateway_compose up -d gateway;;
  redirect)
    log "firewall: $PUBLIC_PORT -> the gateway on $GATEWAY_PORT"
    rules_apply
    set_kv "$KIT/kit.env" VERITELL_FRONT gateway;;
  port)
    run_cmd "$SITE_RELEASE_CMD"
    for _ in $(seq 1 15); do port_busy "$PUBLIC_PORT" || break; sleep 1; done
    if port_busy "$PUBLIC_PORT"; then log "$PUBLIC_PORT is still in use 15 s after SITE_RELEASE_CMD"; exit 1; fi
    log "gateway -> [::]:$PUBLIC_PORT"
    set_kv "$KIT/kit.env" VERITELL_LISTEN "[::]:$PUBLIC_PORT"
    set_kv "$KIT/kit.env" VERITELL_FRONT gateway
    gateway_compose up -d gateway;;
esac

# In the path, not the query: the event store keeps the path only.
mark="veritell-cutover-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
ok=0
for _ in $(seq 1 30); do
  if code_ok "$(marker_status "$mark")" && [ "$(marker_seen "$mark")" -gt 0 ]; then ok=1; break; fi
  sleep 1
done
[ "$ok" = 1 ] && [ "$(front_state)" = gateway ] || { log "the site does not answer through the gateway on $PUBLIC_PORT"; exit 1; }
finished=1
log "done: $SITE_HOST:$PUBLIC_PORT goes through the gateway (shadow mode). Undo with rollback.sh"
