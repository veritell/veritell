#!/usr/bin/env bash
# Weekly-report check in the throwaway Debian VM: the weekly report on real events. Run
# as root, with the kit in /opt/veritell-src and the test CA from
# r1_vm_check.sh:  sudo scripts/r3_vm_check.sh
# nginx on 443 in redirect mode; traffic from a few clients, a real headless
# Chromium among them (one profile opens a known-person link first); then
# report.sh. Leaves the report in /opt/veritell/reports and the gateway
# installed, for the lead to open the page.
set -u
SRC=${SRC:-/opt/veritell-src}
KIT=/opt/veritell
R1=/etc/ssl/r1
HOST=site.test
ADDR=$(ip -4 route get 1.1.1.1 | sed -n 's/.* src \([0-9.]*\).*/\1/p')
fails=0
check() { if printf '%s' "$2" | grep -q -- "$3"; then echo "PASS  $1"; else echo "FAIL  $1  (wanted: $3; got: $(printf '%s' "$2" | tail -c 300))"; fails=$((fails+1)); fi; }
outside() { docker run --rm --add-host "$HOST:$ADDR" curlimages/curl -sk --max-time 10 -o /dev/null "$@"; }

[ -x "$KIT/uninstall.sh" ] && "$KIT/uninstall.sh" --yes >/dev/null 2>&1
(cd /home/site 2>/dev/null && docker compose --env-file .env.production down >/dev/null 2>&1)
systemctl stop apache2 caddy 2>/dev/null; docker rm -f r1-web >/dev/null 2>&1
cat > /etc/nginx/sites-available/r1 <<CONF
server {
  listen 443 ssl; listen [::]:443 ssl;
  server_name $HOST;
  ssl_certificate $R1/site.pem; ssl_certificate_key $R1/site.key;
  root /var/www/r1;
  gzip on; gzip_types text/html; gzip_min_length 100;
  location / { try_files \$uri /index.html; }
}
CONF
rm -f /etc/nginx/sites-enabled/default /etc/nginx/conf.d/r1-zone.conf; ln -sfn /etc/nginx/sites-available/r1 /etc/nginx/sites-enabled/r1
printf 'set_real_ip_from 127.0.0.1;\nset_real_ip_from ::1;\nreal_ip_header X-Forwarded-For;\n' > /etc/nginx/conf.d/veritell-realip.conf
systemctl restart nginx

rm -rf "$KIT"; mkdir -p "$KIT"; cp -a "$SRC"/. "$KIT"/
cat > "$KIT/site.conf" <<CONF
FRONT=redirect
SITE_HOST=$HOST
CERT_FULLCHAIN=$R1/site.pem
CERT_KEY=$R1/site.key
UPSTREAM=127.0.0.1:443
UPSTREAM_TLS=on
UPSTREAM_CA=$R1/ca.pem
PUBLIC_PORT=443
GATEWAY_PORT=8443
CONF
r=$("$KIT/install.sh" 2>&1); check "install" "$r$?" '0$'
check "the report timer is installed" "$(systemctl list-timers --all --no-pager veritell-report.timer)" 'veritell-report.timer'
r=$("$KIT/cutover.sh" 2>&1); check "cutover" "$r$?" '0$'

# ---- traffic ----
for p in / /.env /wp-login.php /.git/config /admin; do outside "https://$HOST$p"; done
for i in 1 2 3; do outside -A "python-requests/2.32.3" "https://$HOST/api/items?page=$i"; done
outside -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36" "https://$HOST/pricing"
outside -A "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" "https://$HOST/"
outside -A $'evil\x1b[31m<script>alert(1)</script>' "https://$HOST/<img src=x>"
CH=$(command -v chromium || true)
if [ -n "$CH" ]; then
  key=$(sed -n 's/^VERITELL_KNOWN_KEY=//p' "$KIT/gateway.env")
  mac=$(python3 -c 'import hashlib,hmac,sys; print(hmac.new(sys.argv[1].encode(), b"veritell-known\0p01-test", hashlib.sha256).hexdigest()[:32])' "$key")
  run_chrome() { # profile, url
    timeout 60 "$CH" --headless=new --no-sandbox --ignore-certificate-errors --user-data-dir="$1" \
      --host-resolver-rules="MAP $HOST $ADDR" --virtual-time-budget=8000 --dump-dom "$2" >/dev/null 2>&1
  }
  rm -rf /tmp/r3-known /tmp/r3-plain
  run_chrome /tmp/r3-known "https://$HOST/__veritell/known/p01-test/$mac"
  run_chrome /tmp/r3-known "https://$HOST/"
  run_chrome /tmp/r3-known "https://$HOST/shop"
  run_chrome /tmp/r3-plain "https://$HOST/"
  run_chrome /tmp/r3-plain "https://$HOST/about"
else
  echo "INFO  no chromium: no browser traffic, no probe events"
fi
sleep 6   # the gateway sends events to ClickHouse in batches

# ---- the report ----
r=$("$KIT/report.sh" 2>&1); check "report.sh" "$r$?" '0$'
html=$(ls -1 "$KIT"/reports/report-*.html | tail -1); json=${html%.html}.json
check "the html file, mode 640" "$(stat -c '%a %U' "$html")" '^640 root$'
check "the reports folder, mode 750" "$(stat -c '%a' "$KIT/reports")" '^750$'
jq() { python3 -c 'import json,sys; j=json.load(open(sys.argv[1])); print(eval(sys.argv[2], {"j": j}))' "$json" "$1"; }
check "requests counted" "$(jq 'j["requests"]')" '^[1-9]'
check "a known-person visit" "$(jq 'j["known"]["visits"]')" '^[1-9]'
check "the probe ran in the browser (a probe-only finding fired)" "$(jq '[r["id"] for r in j["rules"]]')" 'gpu_software\|native_tampered\|webdriver'
check "scanner paths" "$(jq '[p["path"] for p in j["paths"]]')" '/.env'
check "no address in the json" "$(python3 -c 'import json,sys; j=json.load(open(sys.argv[1])); print(json.dumps(j))' "$json" | grep -c "$ADDR\|172\.17\.")" '^0$'
check "no address in the html" "$(grep -c "$ADDR\|172\.17\." "$html")" '^0$'
check "a second run the same day replaces the file" "$("$KIT/report.sh" >/dev/null 2>&1; ls "$KIT"/reports/report-*.html | wc -l)" '^1$'
r=$(systemctl start veritell-report.service 2>&1; systemctl is-failed veritell-report.service)
check "the timer's service runs" "$r" 'inactive'
echo "REPORT $html"
echo
if [ "$fails" = 0 ]; then echo "ALL PASSED"; else echo "$fails FAILED"; fi
exit "$fails"
