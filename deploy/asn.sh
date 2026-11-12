#!/usr/bin/env bash
# The ASN database the gateway reads with --asn-db (which network each
# address belongs to: net_hosting, and asn and net_class in the events and
# the policy). As root:
#   asn.sh                 download, check, put in place; if it changed and the
#                          gateway runs, restart the gateway, and if it does not
#                          answer within 20 s, go back to the previous file
#   asn.sh --no-restart    the same without the restart (install.sh and
#                          update.sh, which start the gateway themselves)
# Run weekly by veritell-asn.timer (install-watch.sh):
#   journalctl -u veritell-asn
# ASN_DB=off in site.conf: the gateway runs without one. ASN_DB_URL: another
# copy of iptoasn.com's ip2asn-combined.tsv(.gz). A failed download or a file
# that does not check keeps the file in place; the exit status is then 1.
SCRIPT=asn
. "$(dirname "$0")/lib.sh"
restart=1
case "${1:-}" in
  "") ;;
  --no-restart) restart=0;;
  *) echo "usage: asn.sh [--no-restart]" >&2; exit 2;;
esac
cur="$KIT/asn/ip2asn.tsv"
was=$(get_kv "$KIT/kit.env" VERITELL_ASN_DB)

running() { docker ps --format '{{.Names}}' 2>/dev/null | grep -qx veritell-gateway; }
# recreate: start the gateway again on what kit.env and asn/ say now.
recreate() { gateway_compose up -d --force-recreate gateway >/dev/null 2>&1 && gateway_answers; }

rc=0
if [ "$ASN_DB" = off ]; then
  log "ASN_DB=off in site.conf: the gateway runs without an ASN database"
elif asn_fetch; then
  if [ -f "$cur" ] && cmp -s "$cur.new" "$cur"; then
    rm -f "$cur.new"
    log "ASN database unchanged ($(asn_rows "$cur") ranges)"
  else
    [ -f "$cur" ] && mv -f "$cur" "$cur.previous"
    mv -f "$cur.new" "$cur"
    changed=1
    log "ASN database in place: $(asn_rows "$cur") ranges from $ASN_DB_URL"
  fi
else
  rc=1
  if [ -s "$cur" ]; then log "keeping the ASN database in place ($(asn_rows "$cur") ranges)"; else log "no ASN database yet: the gateway runs without one"; fi
fi
now=$(asn_wire)
[ "$now" != "$was" ] && changed=1

if [ "${changed:-0}" != 1 ] || [ "$restart" = 0 ] || ! running; then exit "$rc"; fi
if recreate; then
  log "the gateway answers with the new ASN database"
  rm -f "$cur.previous"
  exit "$rc"
fi
log "the gateway does not answer with the new ASN database: going back to the previous one"
docker logs --tail 5 veritell-gateway 2>&1 | sed 's/^/  /'
if [ -f "$cur.previous" ]; then mv -f "$cur.previous" "$cur"; else rm -f "$cur"; fi
asn_wire >/dev/null
if recreate; then log "back on the previous ASN database; the gateway answers"; else log "the gateway does not answer on the previous ASN database either: look at docker logs veritell-gateway"; fi
exit 1
