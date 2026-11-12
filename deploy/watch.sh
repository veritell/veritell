#!/usr/bin/env bash
# A check of the gateway every few minutes (veritell-watch.timer), written to
# the system journal only:  journalctl -t veritell-watch
# Problems at priority err, a short "ok" line otherwise. It changes nothing:
# no rollback and, apart from the one change below, no restart; those stay a
# person's decision.
#
# It does not load a page through the gateway, so as not to add its own
# visits to the data under review: the gateway is checked through its own
# probe script (TLS and the gateway, no event recorded) and the site through
# nginx's local HTTPS port (compose) or at UPSTREAM (redirect, port).
#
# One thing it does change, in redirect and port mode: if CERT_FULLCHAIN or
# CERT_KEY no longer match the checksums stored in certs/source.sha256 (a
# renewal by Caddy or a cron job, which no certbot hook announced), it copies
# them again and restarts the gateway, and logs a note.
SCRIPT=watch
. "$(dirname "$0")/lib.sh"
problems=()
notes=()

read -r running restarts started id < <(docker inspect -f '{{.State.Running}} {{.RestartCount}} {{.State.StartedAt}} {{.Id}}' veritell-gateway 2>/dev/null || echo "missing 0 - -")
[ "$running" = true ] || problems+=("gateway container is not running ($running)")
health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' veritell-clickhouse 2>/dev/null || echo missing)
[ "$health" = healthy ] || problems+=("ClickHouse is $health")

# Since the last run: a new container (a deploy), a crash that Docker's
# restart policy recovered (the count goes up), or a restart by hand or by
# the certificate hook (same container and count, a new start time).
last="$KIT/watch.state"
if [ -f "$last" ]; then
  read -r prev_id prev_restarts prev_started < "$last" || true
  if [ "${prev_id:-}" != "$id" ]; then
    notes+=("gateway container was recreated (a deploy)")
  elif [ "$restarts" -gt "${prev_restarts:-0}" ]; then
    problems+=("gateway crashed and was restarted by Docker ($prev_restarts -> $restarts restarts)")
  elif [ "${prev_started:-}" != "$started" ]; then
    # (`docker restart` by hand also sets the count back to 0.)
    notes+=("gateway was restarted (certificate renewal or by hand)")
  fi
fi
printf '%s %s %s\n' "$id" "$restarts" "$started" > "$last"

front=$(front_state)
case "$front" in
  gateway) in_front=yes;;
  nginx|site) in_front=no;;
  *) in_front=?; problems+=("the front is $front (status.sh; rollback.sh restores the site)");;
esac
if [ "$FRONT" = compose ]; then
  if [ "$in_front" = yes ]; then port=$PUBLIC_PORT; else port=9443; fi
else
  port=$(gateway_port)
fi

# Events the store refused or could not take since the last run (a column
# missing after an update, ClickHouse down): the gateway logs each batch.
dropped=$(docker logs --since 6m veritell-gateway 2>&1 | grep -c 'clickhouse batch of .* dropped' || true)
[ "${dropped:-0}" = 0 ] || problems+=("$dropped event batches dropped by the store in the last minutes: docker logs veritell-gateway | grep dropped")
code=$(curl -sk --max-time 10 -o /dev/null -w '%{http_code}' --resolve "$SITE_HOST:$port:127.0.0.1" "https://$SITE_HOST:$port/__veritell/probe.js" || true)
[ "$code" = 200 ] || problems+=("gateway does not answer on $port ($code)")
if [ "$in_front" = yes ] && [ "$FRONT" != compose ]; then
  site=$(upstream_status /)
  [ "$site" = 200 ] || problems+=("the site behind it does not answer on $UPSTREAM ($site)")
elif [ "$in_front" = yes ]; then
  site=$(curl -sk --max-time 10 -o /dev/null -w '%{http_code}' --resolve "$SITE_HOST:${NGINX_LOCAL_HTTPS##*:}:127.0.0.1" "https://$SITE_HOST:${NGINX_LOCAL_HTTPS##*:}/" || true)
  [ "$site" = 200 ] || problems+=("the site behind it does not answer on $NGINX_LOCAL_HTTPS ($site)")
fi

if [ "$FRONT" != compose ]; then
  if now=$(cert_sums 2>/dev/null); then
    if [ "$now" != "$(cat "$KIT/certs/source.sha256" 2>/dev/null || true)" ]; then
      if copy_certs && docker restart veritell-gateway >/dev/null; then
        notes+=("the certificate files changed: copied again, gateway restarted")
      else
        problems+=("the certificate files changed but copying them or restarting the gateway failed")
      fi
    fi
  else
    problems+=("cannot read CERT_FULLCHAIN or CERT_KEY")
  fi
fi
if end=$(openssl x509 -enddate -noout -in "$KIT/certs/cert.pem" 2>/dev/null | cut -d= -f2); then
  days=$(( ( $(date -d "$end" +%s) - $(date +%s) ) / 86400 ))
  [ "$days" -ge 14 ] || problems+=("the gateway's certificate expires in $days days: renewal or its hook is not working")
else
  problems+=("cannot read the gateway's certificate"); days="?"
fi
disk=$(df --output=pcent / | tail -1 | tr -dc 0-9)
[ "${disk:-0}" -lt 90 ] || problems+=("disk ${disk}% full")
mem=$(docker stats --no-stream --format '{{.Name}}={{.MemUsage}}' veritell-gateway veritell-clickhouse 2>/dev/null | sed 's/ \/ .*//' | tr '\n' ' ')

summary="front=$front restarts=$restarts cert_days=$days disk=${disk}% $mem"
if [ ${#problems[@]} -gt 0 ]; then
  for p in "${problems[@]}"; do logger -p user.err -t veritell-watch "PROBLEM: $p"; done
  logger -p user.err -t veritell-watch "state: $summary"
  exit 1
fi
for n in "${notes[@]:-}"; do [ -n "$n" ] && logger -p user.notice -t veritell-watch "note: $n"; done
logger -p user.info -t veritell-watch "ok: $summary"
