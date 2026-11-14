#!/usr/bin/env bash
# One-time setup on the host, as root. Leaves the site untouched: the gateway
# starts beside it (127.0.0.1:9443 in compose and port mode, GATEWAY_PORT in
# redirect mode, where nothing sends visitors to it yet). cutover.sh puts it
# in front. In redirect and port mode, everything is checked before anything
# is changed.
SCRIPT=install
. "$(dirname "$0")/lib.sh"
cd "$KIT"

[ -x "$KIT/veritell" ] || { echo "no gateway binary at $KIT/veritell (see build.sh)" >&2; exit 2; }

# Redirect and port: refuse, with the reason, before touching anything.
host_checks() {
  local why=0 names hdr
  fail() { log "CANNOT INSTALL: $*"; why=1; }
  local code; code=$(upstream_status /)
  if [ "$code" = 000 ] || [ -z "$code" ]; then
    if [ "$UPSTREAM_TLS" = off ]; then fail "nothing answers HTTP on UPSTREAM $UPSTREAM"; else fail "nothing answers TLS on UPSTREAM $UPSTREAM (UPSTREAM_TLS=$UPSTREAM_TLS; is the site running, and is that its HTTPS port?)"; fi
  elif [ "$UPSTREAM_TLS" != off ]; then
    if ! openssl s_client -connect "$UPSTREAM" -servername "$SITE_HOST" </dev/null 2>/dev/null \
        | openssl x509 -noout -checkhost "$SITE_HOST" 2>/dev/null | grep -q 'does match certificate'; then
      fail "the certificate that $UPSTREAM presents for $SITE_HOST does not cover $SITE_HOST; the gateway would refuse the site"
    fi
  fi
  if [ ! -r "$CERT_FULLCHAIN" ] || [ ! -r "$CERT_KEY" ]; then
    fail "cannot read CERT_FULLCHAIN ($CERT_FULLCHAIN) or CERT_KEY ($CERT_KEY)"
  elif ! openssl x509 -in "$CERT_FULLCHAIN" -noout -checkhost "$SITE_HOST" 2>/dev/null | grep -q 'does match certificate'; then
    fail "CERT_FULLCHAIN does not cover $SITE_HOST"
  fi
  if [ "$FRONT" = redirect ]; then
    command -v iptables >/dev/null && iptables -w -t nat -S PREROUTING >/dev/null 2>&1 || fail "iptables is missing or does not work here (redirect mode needs iptables, nft or legacy); FRONT=port does not"
    if ipv6_on; then ip6tables -w -t nat -S PREROUTING >/dev/null 2>&1 || fail "ip6tables does not work here; set IPV6=off in site.conf if the host has no IPv6 firewall"; fi
  fi
  # Our own gateway and ClickHouse hold these ports when install.sh runs again.
  if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -Eqx 'veritell-(gateway|clickhouse)'; then
    [ "$FRONT" = redirect ] && port_busy "$GATEWAY_PORT" && fail "GATEWAY_PORT $GATEWAY_PORT is already in use"
    port_busy 9090 && fail "port 9090 (the dashboard) is already in use"
    port_busy 18123 && fail "port 18123 (ClickHouse, on 127.0.0.1) is already in use"
  fi
  [ "$why" = 0 ] || exit 1
  # Warnings: not reasons to stop.
  if [ "$UPSTREAM_TLS" != off ]; then
    hdr=$(curl -skI --max-time 10 --resolve "$SITE_HOST:$(upstream_port):$(upstream_host)" "https://$SITE_HOST:$(upstream_port)/" 2>/dev/null || true)
    if printf '%s' "$hdr" | grep -iq '^alt-svc:.*h3'; then
      log "WARNING: the site sends an Alt-Svc header for HTTP/3. Browsers that follow it use UDP 443, which does not go through the gateway. Turn HTTP/3 off or block UDP 443 for the run."
    fi
  fi
  names=$(openssl x509 -in "$CERT_FULLCHAIN" -noout -text 2>/dev/null | grep -A1 'Subject Alternative Name' | tail -1 | sed 's/DNS://g; s/^ *//')
  log "the certificate the gateway will present covers: ${names:-$SITE_HOST}"
  log "Every name this host serves on port 443 must be among them: the gateway presents this one certificate for all of them."
}
[ "$FRONT" = compose ] || host_checks

if [ ! -f gateway.env ]; then
  ch=$(rand)
  umask 077
  printf 'VERITELL_SECRET=%s\nVERITELL_KNOWN_KEY=%s\nVERITELL_CLICKHOUSE_PASSWORD=%s\n' "$(rand)" "$(rand)" "$ch" > gateway.env
  printf 'CLICKHOUSE_PASSWORD=%s\n' "$ch" > kit.env
  umask 022
  log "secrets written to gateway.env and kit.env (mode 600)"
fi
ensure_admin_token
if [ "$FRONT" = compose ]; then
  set_kv kit.env SITE_NETWORK "$SITE_NETWORK"
  set_kv kit.env SITE_UPSTREAM "$SITE_UPSTREAM"
  grep -q '^VERITELL_PUBLISH=' kit.env || set_kv kit.env VERITELL_PUBLISH 127.0.0.1:9443
else
  # What compose.host.yml reads. The front starts as the site; running
  # install.sh again after a cutover keeps it where it is.
  grep -q '^VERITELL_FRONT=' kit.env || set_kv kit.env VERITELL_FRONT site
  set_kv kit.env SITE_HOST "$SITE_HOST"
  set_kv kit.env UPSTREAM "$UPSTREAM"
  set_kv kit.env UPSTREAM_TLS "$UPSTREAM_TLS"
  if [ "$FRONT" = redirect ]; then
    set_kv kit.env VERITELL_LISTEN "[::]:$GATEWAY_PORT"
  else
    grep -q '^VERITELL_LISTEN=' kit.env || set_kv kit.env VERITELL_LISTEN 127.0.0.1:9443
  fi
  if [ -n "${UPSTREAM_CA:-}" ]; then
    cp "$UPSTREAM_CA" "$KIT/upstream-ca.pem"
    set_kv kit.env VERITELL_UPSTREAM_CA /etc/veritell/upstream-ca.pem
  else
    # An empty file, so the mount stays a file; the empty value below means
    # the system roots to the gateway.
    : > "$KIT/upstream-ca.pem"
    set_kv kit.env VERITELL_UPSTREAM_CA ""
  fi
  chmod 0644 "$KIT/upstream-ca.pem"
fi
# Other sites on this host (all modes): certificates by name, read from
# certs/sni, and the upstream for each name. Empty means none.
if [ -n "${EXTRA_CERT_NAMES:-}" ]; then set_kv kit.env SNI_DIR /certs/sni; else set_kv kit.env SNI_DIR ""; fi
set_kv kit.env HOST_UPSTREAMS "${HOST_UPSTREAMS:-}"
chmod 600 gateway.env kit.env

mkdir -p state
if [ "$REHEARSAL" != 1 ]; then chown "$GATEWAY_UID:0" state; chmod 0700 state; else chmod 0777 state; fi
copy_certs

if [ "$REHEARSAL" != 1 ] && { [ "$FRONT" = compose ] || [ -d /etc/letsencrypt ]; }; then
  hook=/etc/letsencrypt/renewal-hooks/deploy/veritell.sh
  mkdir -p "$(dirname "$hook")"
  printf '#!/bin/sh\nexec %q/renew-hook.sh\n' "$KIT" > "$hook"
  chmod 0755 "$hook"
  log "certbot deploy hook: $hook"
fi

# The ASN database, before the gateway starts. Without it (no network, the
# site's host blocks the download) the gateway starts anyway, and
# veritell-asn.timer tries again every week; or run asn.sh.
"$KIT/asn.sh" --no-restart || log "the gateway starts without an ASN database for now: run $KIT/asn.sh once the download works"
# Trusted Web Bot Auth agents, if agents/agents.json is there (README.md).
agents_wire >/dev/null
ipv6_wire >/dev/null
docker build -q -f Dockerfile.prebuilt -t veritell:latest . >/dev/null
log "image veritell:latest built"
gateway_compose up -d
# Where the gateway answers now: beside the site before the cutover, in
# front of it after. Running install.sh again after a cutover is safe.
state=$(front_state)
if [ "$FRONT" = compose ]; then
  case "$state" in
    gateway) port=$PUBLIC_PORT;;
    nginx|not-installed) port=9443;;
    *) log "the front is '$state': see status.sh"; exit 1;;
  esac
  path=/
else
  case "$state" in
    gateway|site|not-installed) port=$(gateway_port);;
    *) log "the front is '$state': see status.sh"; exit 1;;
  esac
  path=/__veritell/probe.js
fi
for _ in $(seq 1 60); do [ "$(status_via "$port" "$path")" = 200 ] && break; sleep 1; done
code=$(status_via "$port" "$path")
if [ "$code" != 200 ]; then
  if [ "$FRONT" = compose ]; then
    log "the gateway does not reach the site through $SITE_UPSTREAM (status $code on $port)."
    log "Is the site deployed with its gateway server block? Logs: docker logs veritell-gateway"
  else
    log "the gateway does not answer on $port (status $code). Logs: docker logs veritell-gateway"
  fi
  exit 1
fi
"$KIT/install-watch.sh"
if [ "$state" = gateway ]; then
  log "the gateway is in front and answers on $port."
else
  if [ "$FRONT" = compose ]; then
    log "the gateway answers on 127.0.0.1:9443 and reaches the site. Nothing public has changed."
  else
    log "the gateway answers on $port and reaches the site. Nothing public has changed."
  fi
  log "Next: cutover.sh"
fi
if [ "$FRONT" != compose ]; then
  log "The site will see the gateway's address (127.0.0.1) for every visitor until it is told to trust X-Forwarded-For from loopback: see client-address.md."
fi
