#!/usr/bin/env bash
# Install check in a throwaway Debian 12 VM. Run as
# root inside the VM, with the kit in /opt/veritell-src (from deploy/build.sh):
#   sudo scripts/r1_vm_check.sh [scenario ...]
# Scenarios: nginx caddy apache docker port (default: all). Each installs a
# web server with a local test CA, puts the gateway in front, checks it, takes
# it out and uninstalls it. Needs docker, nginx, caddy, apache2, ufw and the
# images clickhouse/clickhouse-server:25.8, debian:bookworm-slim,
# nginx:1.27-alpine and curlimages/curl.
#
# "Outside" requests come from a container on a Docker bridge network: they
# enter the host through PREROUTING, as a visitor's do.
set -u
SRC=${SRC:-/opt/veritell-src}
KIT=/opt/veritell
R1=/etc/ssl/r1
HOST=site.test
ADDR=$(ip -4 route get 1.1.1.1 | sed -n 's/.* src \([0-9.]*\).*/\1/p')
fails=0
check() { if printf '%s' "$2" | grep -q -- "$3"; then echo "PASS  [$S] $1"; else echo "FAIL  [$S] $1  (wanted: $3; got: $(printf '%s' "$2" | head -c 300))"; fails=$((fails+1)); fi; }
refute() { if printf '%s' "$2" | grep -q -- "$3"; then echo "FAIL  [$S] $1  (unwanted: $3)"; fails=$((fails+1)); else echo "PASS  [$S] $1"; fi; }
# seen PATH: events in the store with that path (the gateway writes no line
# per request to its log). Waits 2 s for the gateway's batch first.
seen() {
  sleep 2
  docker exec veritell-clickhouse clickhouse-client --user veritell \
    --password "$(sed -n 's/^CLICKHOUSE_PASSWORD=//p' "$KIT/kit.env")" \
    --query "SELECT count() FROM veritell.events WHERE path = '$1'" 2>/dev/null || echo 0
}
outside() { docker run --rm --add-host "$HOST:$ADDR" curlimages/curl -sk --max-time 10 "$@"; }

# ---- once: a CA, the site's certificate, the firewall ----
if [ ! -f "$R1/ca.pem" ]; then
  mkdir -p "$R1"
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=r1 test CA" -keyout "$R1/ca.key" -out "$R1/ca.pem" 2>/dev/null
  cp "$R1/ca.pem" /usr/local/share/ca-certificates/r1-test-ca.crt; update-ca-certificates >/dev/null 2>&1
fi
new_cert() { # a fresh leaf for site.test
  openssl req -newkey rsa:2048 -nodes -subj "/CN=$HOST" -keyout "$R1/site.key" -out "$R1/site.csr" 2>/dev/null
  printf 'subjectAltName=DNS:%s\n' "$HOST" > "$R1/san.ext"
  openssl x509 -req -in "$R1/site.csr" -CA "$R1/ca.pem" -CAkey "$R1/ca.key" -CAcreateserial -days 30 -extfile "$R1/san.ext" -out "$R1/site.pem" 2>/dev/null
  chmod 644 "$R1/site.pem" "$R1/site.key"
}
new_cert
grep -q " $HOST\$" /etc/hosts || echo "$ADDR $HOST" >> /etc/hosts
ufw --force reset >/dev/null; ufw default deny incoming >/dev/null; ufw allow 22/tcp >/dev/null
ufw allow 80/tcp >/dev/null; ufw allow 443/tcp >/dev/null; ufw --force enable >/dev/null
mkdir -p /var/www/r1
printf '<!doctype html><html><head><title>r1</title></head><body>%s</body></html>\n' "$(head -c 3000 /dev/zero | tr '\0' 'x')" > /var/www/r1/index.html

stop_all() {
  systemctl stop nginx apache2 caddy 2>/dev/null
  docker rm -f r1-web >/dev/null 2>&1
  rm -f /etc/nginx/sites-enabled/r1 /etc/nginx/conf.d/veritell-realip.conf
}

# ---- web servers ----
nginx_site() { # listen lines
  cat > /etc/nginx/sites-available/r1 <<CONF
server {
  $1
  server_name $HOST;
  ssl_certificate $R1/site.pem; ssl_certificate_key $R1/site.key;
  root /var/www/r1;
  gzip on; gzip_types text/html; gzip_min_length 100;
  location / { try_files \$uri /index.html; }
  location /r1-limited { limit_req zone=r1 nodelay; return 200 "limited ok\n"; }
}
CONF
  printf 'limit_req_zone $binary_remote_addr zone=r1:1m rate=1r/m;\n' > /etc/nginx/conf.d/r1-zone.conf
  rm -f /etc/nginx/sites-enabled/default; ln -sfn /etc/nginx/sites-available/r1 /etc/nginx/sites-enabled/r1
}
start_web() {
  case "$S" in
    nginx)
      nginx_site 'listen 443 ssl; listen [::]:443 ssl;'
      printf 'set_real_ip_from 127.0.0.1;\nset_real_ip_from ::1;\nreal_ip_header X-Forwarded-For;\n' > /etc/nginx/conf.d/veritell-realip.conf
      systemctl start nginx;;
    port)
      printf 'listen 443 ssl; listen [::]:443 ssl;\n' > /etc/nginx/veritell-listen-public.conf
      : > /etc/nginx/veritell-listen-none.conf
      ln -sfn /etc/nginx/veritell-listen-public.conf /etc/nginx/veritell-listen.conf
      nginx_site 'listen 127.0.0.1:8444 ssl; include /etc/nginx/veritell-listen.conf;'
      printf 'set_real_ip_from 127.0.0.1;\nset_real_ip_from ::1;\nreal_ip_header X-Forwarded-For;\n' > /etc/nginx/conf.d/veritell-realip.conf
      systemctl start nginx;;
    caddy)
      cat > /etc/caddy/Caddyfile <<CONF
{
	servers {
		trusted_proxies static 127.0.0.1/32 ::1/128
	}
	auto_https disable_redirects
}
$HOST {
	tls $R1/site.pem $R1/site.key
	root * /var/www/r1
	encode gzip
	try_files {path} /index.html
	file_server
	log {
		output file /var/log/caddy/r1.log
	}
}
CONF
      mkdir -p /var/log/caddy; chown caddy:caddy /var/log/caddy; systemctl start caddy;;
    apache)
      a2enmod -q ssl remoteip >/dev/null; a2dissite -q 000-default >/dev/null
      cat > /etc/apache2/sites-available/r1.conf <<CONF
<VirtualHost *:443>
  ServerName $HOST
  DocumentRoot /var/www/r1
  SSLEngine on
  SSLCertificateFile $R1/site.pem
  SSLCertificateKeyFile $R1/site.key
  RemoteIPHeader X-Forwarded-For
  RemoteIPInternalProxy 127.0.0.1 ::1
  LogFormat "%a %r %>s" r1
  CustomLog /var/log/apache2/r1.log r1
  AddOutputFilterByType DEFLATE text/html
  FallbackResource /index.html
</VirtualHost>
CONF
      a2ensite -q r1 >/dev/null; systemctl start apache2;;
    docker)
      mkdir -p /etc/r1-docker
      gw=$(docker network inspect bridge -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}')
      cat > /etc/r1-docker/default.conf <<CONF
server {
  listen 443 ssl;
  server_name $HOST;
  ssl_certificate /r1/site.pem; ssl_certificate_key /r1/site.key;
  root /var/www/r1; gzip on; gzip_types text/html; gzip_min_length 100;
  location / { try_files \$uri /index.html; }
  set_real_ip_from 127.0.0.1; set_real_ip_from $gw; real_ip_header X-Forwarded-For;
}
CONF
      docker run -d --restart unless-stopped --name r1-web -p 443:443 -v /etc/r1-docker:/etc/nginx/conf.d:ro -v "$R1:/r1:ro" -v /var/www/r1:/var/www/r1:ro nginx:1.27-alpine >/dev/null;;
  esac
  for _ in $(seq 1 30); do [ "$(curl -s --max-time 2 -o /dev/null -w '%{http_code}' --resolve "$HOST:443:127.0.0.1" "https://$HOST/")" = 200 ] && return 0; sleep 0.5; done
  echo "FAIL  [$S] the web server does not start"; fails=$((fails+1)); return 1
}
last_client() { # the client address of the site's last logged request
  case "$S" in
    nginx|port) tail -1 /var/log/nginx/access.log | cut -d' ' -f1;;
    caddy) tail -1 /var/log/caddy/r1.log | python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["request"].get("client_ip",""))';;
    apache) tail -1 /var/log/apache2/r1.log | cut -d' ' -f1;;
    docker) docker logs r1-web 2>/dev/null | tail -1 | cut -d' ' -f1;;
  esac
}

site_conf() {
  local mode=redirect upstream=127.0.0.1:443
  [ "$S" = port ] && { mode=port; upstream=127.0.0.1:8444; }
  cat > "$KIT/site.conf" <<CONF
FRONT=$mode
SITE_HOST=$HOST
CERT_FULLCHAIN=$R1/site.pem
CERT_KEY=$R1/site.key
UPSTREAM=$upstream
UPSTREAM_TLS=on
UPSTREAM_CA=$R1/ca.pem
PUBLIC_PORT=443
GATEWAY_PORT=8443
SITE_RELEASE_CMD="ln -sfn /etc/nginx/veritell-listen-none.conf /etc/nginx/veritell-listen.conf && nginx -t -q && systemctl reload nginx"
SITE_RESTORE_CMD="ln -sfn /etc/nginx/veritell-listen-public.conf /etc/nginx/veritell-listen.conf && nginx -t -q && systemctl reload nginx"
CONF
}

# A load loop from outside, one request every 50 ms; prints "<total> <failed>".
load_start() {
  docker rm -f r1-load >/dev/null 2>&1
  docker run -d --name r1-load --add-host "$HOST:$ADDR" --entrypoint sh curlimages/curl -c \
    'ok=0; bad=0; while [ ! -f /tmp/stop ]; do c=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" https://'"$HOST"'/r1-load); if [ "$c" = 200 ] || [ "$c" = 404 ]; then ok=$((ok+1)); else bad=$((bad+1)); echo "bad $c" >&2; fi; sleep 0.05; done; echo "$((ok+bad)) $bad"' >/dev/null
}
# load_check WHAT: stop the loop; redirect modes must not lose a request, port
# mode reports how many it lost (its swap has a gap by design).
load_check() {
  local counts; counts=$(load_stop)
  if [ "$S" = port ]; then echo "INFO  [$S] requests during the $1: $counts (total, failed)"
  else check "no failed request during the $1 ($counts)" "$counts" '^[1-9][0-9]* 0$'; fi
}
load_stop() {
  if [ "$(docker inspect -f '{{.State.Running}}' r1-load 2>/dev/null)" != true ]; then
    echo "load loop stopped early: $(docker inspect -f 'exit={{.State.ExitCode}} oom={{.State.OOMKilled}} finished={{.State.FinishedAt}}' r1-load 2>&1); $(docker logs --tail 3 r1-load 2>&1 | tr '\n' ' ')" >&2
  else
    docker exec r1-load touch /tmp/stop; docker wait r1-load >/dev/null; docker logs r1-load 2>/dev/null | tail -1
  fi
  docker rm -f r1-load >/dev/null 2>&1
}

scenario() {
  S=$1
  echo "==== $S"
  stop_all
  rm -rf "$KIT"; mkdir -p "$KIT"; cp -a "$SRC"/. "$KIT"/
  site_conf
  start_web || return
  r=$("$KIT/install.sh" 2>&1); check "install.sh succeeds" "$r$?" '0$'
  check "state: site after install" "$("$KIT/status.sh" 2>&1)" 'front: site'
  load_start
  r=$("$KIT/cutover.sh" 2>&1); check "cutover.sh succeeds" "$r$?" '0$'
  check "state: gateway" "$("$KIT/status.sh" 2>&1)" 'front: gateway'
  mark="r1-$S-$RANDOM$RANDOM"
  check "outside: 200 through the front" "$(outside -o /dev/null -w '%{http_code}' "https://$HOST/$mark")" '^200$'
  check "outside: the request went through the gateway" "$(seen "/$mark")" '^1$'
  refute "the gateway's own log has no line for it (--log-requests off)" "$(docker logs veritell-gateway 2>&1)" "$mark"
  page=$(outside -H 'accept: text/html' -H 'accept-encoding: gzip' -H 'sec-fetch-dest: document' -A 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36' --compressed "https://$HOST/")
  check "the probe is in a page the server compresses" "$page" '__veritell/probe.js'
  outside -o /dev/null "https://$HOST/client-$mark"
  sleep 0.5
  client=$(last_client)
  refute "the site logs the visitor's address, not loopback ($client)" "$client" '^127\.\|^::1$\|^$'
  if [ "$S" = nginx ]; then
    a=$(outside -o /dev/null -w '%{http_code}' "https://$HOST/r1-limited"); b=$(curl -s -o /dev/null -w '%{http_code}' --resolve "$HOST:8443:127.0.0.1" -k "https://$HOST:8443/r1-limited")
    check "rate limits are per visitor, not one bucket for all ($a $b)" "$a $b" '^200 200$'
    spoof=$(outside -H 'x-forwarded-for: 6.6.6.6' -o /dev/null "https://$HOST/spoof-$mark"; sleep 0.3; last_client)
    refute "a client's own X-Forwarded-For is not believed" "$spoof" '6.6.6.6'
  fi
  load_check "cutover"
  if [ "$S" != port ]; then
    # Docker restarted: its rules may move; the state must say so or stay right.
    systemctl restart docker; sleep 5
    st=$("$KIT/status.sh" 2>&1)
    if printf '%s' "$st" | grep -q 'front: gateway'; then
      outside -o /dev/null "https://$HOST/after-docker-$mark"
      check "after a Docker restart, still through the gateway" "$(seen "/after-docker-$mark")" '^1$'
    else
      check "after a Docker restart, the state says what broke" "$st" 'front: inconsistent'
      "$KIT/rollback.sh" >/dev/null 2>&1; "$KIT/cutover.sh" >/dev/null 2>&1
    fi
  fi
  # A renewed certificate: watch.sh copies it and restarts the gateway.
  old=$(echo | openssl s_client -connect "127.0.0.1:${GW_CHECK_PORT:-8443}" -servername "$HOST" 2>/dev/null | openssl x509 -noout -fingerprint 2>/dev/null)
  new_cert; [ "$S" = caddy ] && systemctl reload caddy; [ "$S" = nginx ] || [ "$S" = port ] && systemctl reload nginx; [ "$S" = apache ] && systemctl reload apache2; [ "$S" = docker ] && docker exec r1-web nginx -s reload
  "$KIT/watch.sh" >/dev/null 2>&1; sleep 3
  check "watch.sh: the gateway serves the new certificate" "$(echo | openssl s_client -connect "$ADDR:443" -servername "$HOST" 2>/dev/null | openssl x509 -noout -fingerprint 2>/dev/null)" "$(openssl x509 -noout -fingerprint -in "$R1/site.pem")"
  refute "  and it is not the old one" "$old" "$(openssl x509 -noout -fingerprint -in "$R1/site.pem")"
  load_start
  r=$("$KIT/rollback.sh" 2>&1); check "rollback.sh succeeds" "$r$?" '0$'
  check "state: site again" "$("$KIT/status.sh" 2>&1)" 'front: site'
  mark2="r1-back-$S-$RANDOM"
  check "outside: 200 after the rollback" "$(outside -o /dev/null -w '%{http_code}' "https://$HOST/$mark2")" '^200$'
  check "outside: no longer through the gateway" "$(seen "/$mark2")" '^0$'
  load_check "rollback"
  r=$("$KIT/uninstall.sh" --yes 2>&1); check "uninstall.sh succeeds" "$r$?" '0$'
  refute "uninstall: no veritell rule left" "$(iptables -S; iptables -t nat -S; ip6tables -S; ip6tables -t nat -S)" 'veritell'
  refute "uninstall: no veritell container left" "$(docker ps -a --format '{{.Names}}')" 'veritell'
  refute "uninstall: no secrets left" "$(ls "$KIT")" 'gateway.env\|kit.env'
  check "the site still answers" "$(outside -o /dev/null -w '%{http_code}' "https://$HOST/")" '^200$'
}

docker image inspect curlimages/curl >/dev/null 2>&1 || docker pull -q curlimages/curl >/dev/null
for s in ${@:-nginx caddy apache docker port}; do scenario "$s"; done
stop_all
echo
if [ "$fails" = 0 ]; then echo "ALL PASSED"; else echo "$fails FAILED"; fi
exit "$fails"
