#!/usr/bin/env bash
# Takes the gateway off the host, as root:  uninstall.sh --yes
# Rolls back first if the gateway is in front (and stops if that fails), removes
# the firewall rules (redirect mode), stops and removes the containers and the
# ClickHouse volume (the stored events are gone), the check, report, ASN and boot units, the weekly reports (reports/), the exports (exports/), the ASN database (asn/), the
# certbot hook, the secrets, the certificate copy and the state. Prints each
# thing it removes.
# It never touches site.conf, the kit's own files (scripts, binary, compose
# files) or anything of the site, except the copies cutover and rollback kept
# of the site's env file.
SCRIPT=uninstall
. "$(dirname "$0")/lib.sh"
[ "${1:-}" = --yes ] || { echo "usage: uninstall.sh --yes   (removes the gateway, its data and its secrets; the site is left as it was)" >&2; exit 2; }

state=$(front_state)
case "$state" in
  site|nginx|not-installed) ;;
  *) log "the front is '$state': rolling back first"
     "$KIT/rollback.sh" || { log "the rollback failed: not uninstalling. Fix it (status.sh) and run this again"; exit 1; };;
esac

if [ "$FRONT" = redirect ]; then
  if rules_remove; then log "removed: veritell firewall rules (any left)"; else log "some firewall rules could not be deleted: check iptables -t nat -S | grep veritell"; fi
fi
if [ -f "$KIT/kit.env" ]; then
  gateway_compose down -v && log "removed: containers veritell-gateway and veritell-clickhouse, volume clickhouse" \
    || log "could not run compose down: check docker ps"
fi
if [ "$REHEARSAL" != 1 ] && command -v systemctl >/dev/null; then
  for u in veritell-watch.timer veritell-watch.service veritell-report.timer veritell-report.service veritell-asn.timer veritell-asn.service veritell-front.service; do
    if [ -f "/etc/systemd/system/$u" ]; then
      systemctl disable --now "$u" >/dev/null 2>&1 || true
      rm -f "/etc/systemd/system/$u"; log "removed: /etc/systemd/system/$u"
    fi
  done
  systemctl daemon-reload || true
fi
hook=/etc/letsencrypt/renewal-hooks/deploy/veritell.sh
[ -f "$hook" ] && { rm -f "$hook"; log "removed: $hook"; }
for f in gateway.env kit.env watch.state upstream-ca.pem; do
  [ -e "$KIT/$f" ] && { rm -f "$KIT/$f"; log "removed: $KIT/$f"; }
done
for d in certs state reports exports asn; do
  [ -e "$KIT/$d" ] && { rm -rf "${KIT:?}/$d"; log "removed: $KIT/$d/"; }
done
for f in "$KIT"/*.before-*; do
  [ -e "$f" ] && { rm -f "$f"; log "removed: $f"; }
done
# The copies set_kv kept of the site's env file (cutover and rollback, Compose
# mode) hold the site's own secrets. The kit made them; nothing else needs them.
if [ -n "${SITE_DIR:-}" ] && [ -n "${SITE_ENV_FILE:-}" ]; then
  for f in "$SITE_DIR/$SITE_ENV_FILE".before-cutover-* "$SITE_DIR/$SITE_ENV_FILE".before-rollback-*; do
    [ -e "$f" ] && { rm -f "$f"; log "removed: $f"; }
  done
fi
log "done. site.conf and the kit's files are still in $KIT; the site was not touched."
exit 0
