#!/usr/bin/env bash
# Redirect mode only; run at boot by veritell-front.service (install-watch.sh).
# Firewall rules do not survive a reboot. If kit.env says the gateway is in
# front, wait for it to answer on GATEWAY_PORT (up to 60 s), then put the
# rules back. If it does not answer, the rules stay off, so that visitors get
# the site directly, and the problem goes to the journal at err:
#   journalctl -t veritell-watch -p err
SCRIPT=restore-front
. "$(dirname "$0")/lib.sh"
[ "$FRONT" = redirect ] || { log "FRONT is $FRONT: nothing to restore"; exit 0; }
[ "$(want_front)" = gateway ] || { log "kit.env says the site is in front: no rules to restore"; exit 0; }
for _ in $(seq 1 30); do
  [ "$(status_via "$GATEWAY_PORT" /__veritell/probe.js)" = 200 ] && break
  sleep 2
done
if [ "$(status_via "$GATEWAY_PORT" /__veritell/probe.js)" = 200 ]; then
  rules_apply
  log "the gateway answers on $GATEWAY_PORT: redirect rules restored"
  logger -t veritell-watch -p user.notice "restore-front: the gateway answers on $GATEWAY_PORT; redirect rules restored after boot"
else
  log "the gateway does not answer on $GATEWAY_PORT after 60 s: the rules stay off, visitors reach the site directly"
  logger -t veritell-watch -p user.err "restore-front: the gateway does not answer on $GATEWAY_PORT after 60 s; the redirect rules were NOT restored (kit.env says gateway). Check docker logs veritell-gateway, then run cutover.sh or rollback.sh"
  exit 1
fi
