#!/usr/bin/env bash
# Takes the gateway out of the path; the site is served directly again.
#   compose   the gateway goes back to 127.0.0.1:9443 and nginx takes PUBLIC_PORT
#             again. A few seconds without HTTPS.
#   redirect  the firewall rules are deleted. No downtime.
#   port      the gateway goes back to 127.0.0.1:9443 and SITE_RESTORE_CMD puts
#             the site back on PUBLIC_PORT. A few seconds without HTTPS.
#   gateway or inconsistent -> site (nginx)   (from the site it does nothing)
# It is the way back from any half-done state, so it does every step even
# if one fails, and says what is left.
SCRIPT=rollback
. "$(dirname "$0")/lib.sh"

state=$(front_state)
case "$state" in
  nginx|site) log "already done: the site is served directly on $PUBLIC_PORT"; exit 0;;
  not-installed) log "nothing to roll back: the kit is not installed"; exit 0;;
esac
log "from: $state"
failed=0
case "$FRONT" in
  compose)
    log "gateway -> 127.0.0.1:9443"
    set_kv "$KIT/kit.env" VERITELL_PUBLISH 127.0.0.1:9443 || failed=1
    gateway_compose up -d gateway || failed=1
    log "nginx HTTPS -> $PUBLIC_PORT"
    set_kv "$SITE_DIR/$SITE_ENV_FILE" WEB_HTTPS_PUBLISH "$PUBLIC_PORT" || failed=1
    site_compose up -d --no-build "$SITE_WEB_SERVICE" || failed=1;;
  redirect)
    log "firewall: removing the redirect"
    rules_remove || failed=1
    set_kv "$KIT/kit.env" VERITELL_FRONT site || failed=1;;
  port)
    log "gateway -> 127.0.0.1:9443"
    set_kv "$KIT/kit.env" VERITELL_LISTEN 127.0.0.1:9443 || failed=1
    gateway_compose up -d gateway || failed=1
    run_cmd "$SITE_RESTORE_CMD" || failed=1
    set_kv "$KIT/kit.env" VERITELL_FRONT site || failed=1;;
esac

# In the path, not the query: the event store keeps the path only.
mark="veritell-rollback-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
for _ in $(seq 1 30); do code_ok "$(marker_status "$mark")" && break; sleep 1; done
if ! code_ok "$(marker_status "$mark")"; then
  if [ "$FRONT" = compose ]; then
    log "the site does not answer on $PUBLIC_PORT after the rollback: look at '$SITE_COMPOSE ps' in $SITE_DIR"
  else
    log "the site does not answer on $PUBLIC_PORT after the rollback: look at the site's own server"
  fi
  exit 1
fi
# The gateway hands events to the store within a second; give it three.
sleep 3
if [ "$(marker_seen "$mark")" != 0 ]; then
  log "requests on $PUBLIC_PORT still reach the gateway"; exit 1
fi
state=$(front_state)
case "$state" in nginx|site) ;; *) log "the site answers, but the state is '$state'"; exit 1;; esac
[ "$failed" = 0 ] || { log "the site answers, but a step failed on the way: check the output above"; exit 1; }
log "done: $SITE_HOST:$PUBLIC_PORT is served directly again"
