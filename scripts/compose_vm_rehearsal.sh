#!/usr/bin/env bash
# Rehearsal of compose mode (as on a production host) in a throwaway Debian VM, starting from
# the kit that is on the host, as an update there would. Run as root:
#   sudo scripts/compose_vm_rehearsal.sh <old kit dir> <new kit dir>
# Both kits built for the VM (deploy/build.sh aarch64-unknown-linux-musl); the
# old one from the commit deployed on the host. Uses the test CA from
# r1_vm_check.sh (/etc/ssl/r1). A stand-in Compose site with nginx: HTTPS on
# ${WEB_HTTPS_PUBLISH:-443}, plain HTTP on 8081 for the gateway, which answers
# with the client address it sees.
set -u
OLD=${1:?old kit}; NEW=${2:?new kit}
KIT=/opt/veritell
SITE=/home/site
HOST=site.test
R1=/etc/ssl/r1
ADDR=$(ip -4 route get 1.1.1.1 | sed -n 's/.* src \([0-9.]*\).*/\1/p')
fails=0
check() { if printf '%s' "$2" | grep -q -- "$3"; then echo "PASS  $1"; else echo "FAIL  $1  (wanted: $3; got: $(printf '%s' "$2" | tail -c 400))"; fails=$((fails+1)); fi; }
refute() { if printf '%s' "$2" | grep -q -- "$3"; then echo "FAIL  $1  (unwanted: $3)"; fails=$((fails+1)); else echo "PASS  $1"; fi; }
outside() { docker run --rm --add-host "$HOST:$ADDR" curlimages/curl -sk --max-time 10 "$@"; }
# seen PATH: events in the store with that path (the gateway writes no line
# per request to its log). Waits 2 s for the gateway's batch first.
seen() {
  sleep 2
  docker exec veritell-clickhouse clickhouse-client --user veritell \
    --password "$(sed -n 's/^CLICKHOUSE_PASSWORD=//p' "$KIT/kit.env")" \
    --query "SELECT count() FROM veritell.events WHERE path = '$1'" 2>/dev/null || echo 0
}
through_gateway() { # mark: 200 from outside, and the gateway logged it
  local m="rh-$1-$RANDOM$RANDOM"
  printf '%s %s' "$(outside -o /dev/null -w '%{http_code}' "https://$HOST/$m")" "$(seen "/$m")"
}
st() { "$KIT/status.sh" 2>&1 | head -1; }

# Load from outside during every swap: one request every 50 ms.
load_start() {
  docker rm -f rh-load >/dev/null 2>&1
  docker run -d --name rh-load --add-host "$HOST:$ADDR" --entrypoint sh curlimages/curl -c \
    'ok=0; bad=0; while [ ! -f /tmp/stop ]; do c=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" https://'"$HOST"'/rh-load); if [ "$c" = 200 ]; then ok=$((ok+1)); else bad=$((bad+1)); fi; sleep 0.05; done; echo "$((ok+bad)) $bad"' >/dev/null
}
load_stop() { docker exec rh-load touch /tmp/stop; docker wait rh-load >/dev/null; echo "INFO  requests during $1: $(docker logs rh-load 2>/dev/null | tail -1) (total, failed)"; docker rm -f rh-load >/dev/null; }

# ---- clean slate ----
systemctl stop nginx apache2 caddy 2>/dev/null
docker rm -f r1-web r1-load rh-load >/dev/null 2>&1
[ -x "$KIT/uninstall.sh" ] && "$KIT/uninstall.sh" --yes >/dev/null 2>&1
docker rm -f veritell-gateway veritell-clickhouse >/dev/null 2>&1; docker volume rm veritell_clickhouse >/dev/null 2>&1
(cd "$SITE" 2>/dev/null && docker compose --env-file .env.production down >/dev/null 2>&1)
rm -rf "$KIT" "$SITE"
iptables -S | grep -q veritell && { echo "veritell rules left from an earlier run"; exit 1; }

# ---- the stand-in site, owned by a user, its env file mode 640 ----
mkdir -p "$SITE" /etc/letsencrypt/live/$HOST
cp "$R1/site.pem" /etc/letsencrypt/live/$HOST/fullchain.pem; cp "$R1/site.key" /etc/letsencrypt/live/$HOST/privkey.pem
cat > "$SITE/docker-compose.yml" <<'YML'
services:
  web:
    image: nginx:1.27-alpine
    ports: ["80:80", "${WEB_HTTPS_PUBLISH:-443}:443"]
    volumes:
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
      - /etc/letsencrypt:/etc/letsencrypt:ro
    restart: unless-stopped
YML
cat > "$SITE/nginx.conf" <<CONF
server {
  listen 443 ssl; server_name $HOST;
  ssl_certificate /etc/letsencrypt/live/$HOST/fullchain.pem; ssl_certificate_key /etc/letsencrypt/live/$HOST/privkey.pem;
  location / { default_type text/plain; return 200 "site https \$remote_addr\n"; }
}
server {
  listen 8081;
  set_real_ip_from 172.16.0.0/12; real_ip_header X-Forwarded-For; real_ip_recursive off;
  location / { default_type text/plain; return 200 "site gateway-block \$remote_addr\n"; }
}
CONF
printf 'APP=1\n' > "$SITE/.env.production"
chown -R lima:lima "$SITE" 2>/dev/null || chown -R 1000:1000 "$SITE"; chmod 640 "$SITE/.env.production"
owner=$(stat -c '%U:%G %a' "$SITE/.env.production")
(cd "$SITE" && docker compose --env-file .env.production up -d >/dev/null 2>&1)
for _ in $(seq 1 30); do [ "$(outside -o /dev/null -w '%{http_code}' "https://$HOST/")" = 200 ] && break; sleep 1; done
check "the stand-in site answers on 443" "$(outside "https://$HOST/")" 'site https'

systemctl disable --now veritell-report.timer >/dev/null 2>&1; rm -f /etc/systemd/system/veritell-report.*; systemctl daemon-reload
# ---- the old kit, as on the host ----
mkdir -p "$KIT"; cp -a "$OLD"/. "$KIT"/
cat > "$KIT/site.conf" <<CONF
SITE_DIR=$SITE
SITE_COMPOSE="docker compose --env-file .env.production -f docker-compose.yml"
DOCKER_COMPOSE="docker compose"
SITE_ENV_FILE=.env.production
SITE_WEB_SERVICE=web
SITE_NETWORK=site_default
SITE_UPSTREAM=web:8081
SITE_HOST=$HOST
CERT_NAME=$HOST
LETSENCRYPT_LIVE=/etc/letsencrypt/live
PUBLIC_PORT=443
NGINX_LOCAL_HTTPS=127.0.0.1:8444
CONF
chmod 600 "$KIT/site.conf"
r=$("$KIT/install.sh" 2>&1); check "old kit: install" "$r$?" '0$'
check "old kit: front nginx" "$(st)" 'front: nginx'
load_start
r=$("$KIT/cutover.sh" 2>&1); check "old kit: cutover" "$r$?" '0$'
load_stop "the old kit's cutover"
check "old kit: front gateway" "$(st)" 'front: gateway'
check "old kit: from outside, through the gateway" "$(through_gateway old)" '^200 1$'
check "the site's env file keeps its owner and mode" "$(stat -c '%U:%G %a' "$SITE/.env.production")" "^$owner\$"

# ---- update to the new kit, run by the old kit's update.sh ----
mkdir -p /home/lima/veritell-kit-new; rm -rf /home/lima/veritell-kit-new/*; cp -a "$NEW"/. /home/lima/veritell-kit-new/
load_start
r=$("$KIT/update.sh" /home/lima/veritell-kit-new 2>&1); check "update old -> new: succeeds" "$r$?" '0$'
load_stop "the update"
check "update: the new binary is in place" "$(cat "$KIT/veritell.sha256")" "$(cut -c1-64 "$NEW/veritell.sha256")"
check "update: the new scripts are in place" "$(ls "$KIT")" 'uninstall.sh'
check "update: the new kit's report timer is installed" "$(systemctl is-enabled veritell-report.timer 2>&1) $(systemctl is-active veritell-report.timer 2>&1)" '^enabled active$'
check "new kit: front gateway" "$(st)" 'front: gateway'
check "new kit: status says compose" "$("$KIT/status.sh" 2>&1)" 'compose\|front: gateway'
check "new kit: from outside, through the gateway" "$(through_gateway new)" '^200 1$'
check "new kit: the gateway's log has no visitor lines (--log-requests off)" "$(docker logs veritell-gateway 2>&1 | grep -c '"ip"')" '^0$'
gw_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' veritell-gateway)
seen=$(outside "https://$HOST/whoami")
check "new kit: the site's gateway block answers" "$seen" 'site gateway-block'
refute "new kit: the site sees the visitor, not the gateway ($seen; gateway $gw_ip)" "$seen" "gateway-block ${gw_ip%% *}\$"
"$KIT/watch.sh"; check "new kit: watch.sh finds no problem" "$(journalctl -t veritell-watch -n 1 --no-pager -o cat)" '^ok: front=gateway'

# ---- every transition with the new kit ----
check "cutover again: nothing to do" "$("$KIT/cutover.sh" 2>&1 | tr '\n' ' '; echo "exit=${PIPESTATUS[0]}")" 'already done.*exit=0'
load_start
r=$("$KIT/rollback.sh" 2>&1); check "rollback" "$r$?" '0$'
load_stop "the rollback"
check "front nginx" "$(st)" 'front: nginx'
check "from outside: the site itself" "$(outside "https://$HOST/")" 'site https'
check "rollback again: nothing to do" "$("$KIT/rollback.sh" 2>&1 | tr '\n' ' '; echo "exit=${PIPESTATUS[0]}")" 'already done.*exit=0'
load_start
r=$("$KIT/cutover.sh" 2>&1); check "cutover with the new kit" "$r$?" '0$'
load_stop "the new kit's cutover"
check "front gateway" "$(st)" 'front: gateway'
r=$("$KIT/install.sh" 2>&1); check "install again while cut over" "$r$?" '0$'
check "  still gateway" "$(st)" 'front: gateway'
# A deploy of the site while cut over: its env file keeps nginx off 443.
(cd "$SITE" && docker compose --env-file .env.production up -d --force-recreate web >/dev/null 2>&1)
sleep 3
check "a site deploy under cutover: still gateway" "$(st)" 'front: gateway'
check "  and through it from outside" "$(through_gateway deploy)" '^200 1$'
# A certificate renewal under cutover (certbot's deploy hook).
cp "$R1/site.pem" /etc/letsencrypt/live/$HOST/fullchain.pem
r=$("$KIT/renew-hook.sh" 2>&1); check "renew hook" "$r$?" '0$'
sleep 2; check "  still answering through the gateway" "$(through_gateway renew)" '^200 1$'

# ---- a broken update is put back ----
rm -rf /home/lima/veritell-kit-bad; cp -a "$NEW" /home/lima/veritell-kit-bad
printf '#!/bin/sh\nexit 1\n' > /home/lima/veritell-kit-bad/veritell
(cd /home/lima/veritell-kit-bad && sha256sum veritell > veritell.sha256)
r=$("$KIT/update.sh" /home/lima/veritell-kit-bad 2>&1); check "a broken update fails" "$r exit=$?" 'exit=1'
check "  and says it went back" "$r" 'back on the previous kit'
check "  the good binary is back" "$(cat "$KIT/veritell.sha256")" "$(cut -c1-64 "$NEW/veritell.sha256")"
check "  through the gateway again" "$(through_gateway afterbad)" '^200 1$'

# ---- uninstall in compose mode ----
load_start
r=$("$KIT/uninstall.sh" --yes 2>&1); check "uninstall" "$r$?" '0$'
load_stop "the uninstall"
refute "uninstall: no veritell container" "$(docker ps -a --format '{{.Names}}')" 'veritell'
refute "uninstall: no secrets" "$(ls "$KIT")" 'gateway.env\|kit.env'
check "the site answers on 443 by itself" "$(outside "https://$HOST/")" 'site https'
check "  and its env file says 443" "$(grep WEB_HTTPS_PUBLISH "$SITE/.env.production")" 'WEB_HTTPS_PUBLISH=443'
check "  still owned by its user" "$(stat -c '%U:%G %a' "$SITE/.env.production")" "^$owner\$"

echo
if [ "$fails" = 0 ]; then echo "ALL PASSED"; else echo "$fails FAILED"; fi
exit "$fails"
