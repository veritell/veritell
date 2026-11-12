#!/usr/bin/env bash
# Certbot deploy hook (installed by install.sh): the renewed certificate goes
# to the gateway, which is restarted to load it. A restart is a SIGTERM, which
# saves the gateway's state first; HTTPS is down for about a second.
SCRIPT=renew
. "$(dirname "$0")/lib.sh"
copy_certs
if docker ps --format '{{.Names}}' | grep -qx veritell-gateway; then
  docker restart veritell-gateway >/dev/null
  log "certificate renewed; gateway restarted"
fi
