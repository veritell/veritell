# Shared by the kit's scripts. Sourced, not run.
set -euo pipefail
KIT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "$KIT/site.conf" ] || { echo "no $KIT/site.conf: copy site.conf.example and fill it in" >&2; exit 2; }
# shellcheck source=/dev/null
. "$KIT/site.conf"
# The gateway's user in the image (Dockerfile.prebuilt).
GATEWAY_UID=10001
# REHEARSAL=1 is for trying the kit on a workstation: no chown, no certbot hook.
REHEARSAL=${REHEARSAL:-0}

# How the gateway is put in front of the site (site.conf). A missing FRONT is
# the Compose mode, which is what the kit did before the other two existed.
#   compose   the site is a Docker Compose project whose nginx moves off 443
#   redirect  a firewall rule sends 443 to the gateway; the site is untouched
#   port      the site's own commands move it off 443, then the gateway takes it
FRONT=${FRONT:-compose}
case "$FRONT" in compose|redirect|port) ;; *) echo "site.conf: FRONT must be compose, redirect or port (it is '$FRONT')" >&2; exit 2;; esac
# IPv6 rules in redirect mode: auto = when the host has IPv6 and ip6tables.
IPV6=${IPV6:-auto}
PUBLIC_PORT=${PUBLIC_PORT:-443}
GATEWAY_PORT=${GATEWAY_PORT:-8443}
UPSTREAM_TLS=${UPSTREAM_TLS:-on}

log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*"; }

# One id per run of a script, for its backups.
RUN_ID=${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}
# How many backups of one file to keep per script.
KEEP_BACKUPS=${KEEP_BACKUPS:-5}

# set_kv FILE KEY VALUE: replace KEY=... or append it. The file as it was
# before this run first changed it is kept as FILE.before-<script>-<run id>;
# older copies beyond KEEP_BACKUPS for that script are removed.
set_kv() {
  local file=$1 key=$2 value=$3
  [ -f "$file" ] || touch "$file"
  local backup="$file.before-$SCRIPT-$RUN_ID"
  if [ ! -f "$backup" ]; then
    cp -p "$file" "$backup"
    # Newest first by name (the run id is a UTC timestamp); drop the rest.
    ls -1 "$file.before-$SCRIPT-"* 2>/dev/null | sort -r | tail -n +$((KEEP_BACKUPS + 1)) | while IFS= read -r old; do rm -f "$old"; done
  fi
  if grep -q "^$key=" "$file"; then
    local tmp; tmp=$(mktemp "$file.XXXXXX")
    awk -v k="$key" -v v="$value" -F= 'BEGIN{OFS="="} $1==k {print k, v; next} {print}' "$file" >"$tmp"
    # Keep the file's mode and owner: the scripts run as root, and the site's
    # own deploys, run as its user, must still read its env file.
    chmod --reference="$file" "$tmp" 2>/dev/null || chmod "$(stat -f '%Lp' "$file")" "$tmp"
    chown --reference="$file" "$tmp" 2>/dev/null || true
    mv "$tmp" "$file"
  else
    printf '%s=%s\n' "$key" "$value" >>"$file"
  fi
}

# rand: 32 random bytes as hex.
rand() { head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

# ensure_admin_token: VERITELL_ADMIN_TOKEN in gateway.env, made once. The
# gateway refuses to bind its dashboard beyond loopback without it.
ensure_admin_token() {
  if [ -z "$(get_kv "$KIT/gateway.env" VERITELL_ADMIN_TOKEN)" ]; then
    set_kv "$KIT/gateway.env" VERITELL_ADMIN_TOKEN "$(rand)"
    log "dashboard token written to gateway.env"
  fi
}

# get_kv FILE KEY: the value, or nothing.
get_kv() { [ -f "$1" ] && sed -n "s/^$2=//p" "$1" | tail -1 || true; }

# How Compose is run: the plugin on the host; the standalone binary elsewhere.
DOCKER_COMPOSE=${DOCKER_COMPOSE:-docker compose}
# compose.yml has the gateway on the site's Docker network; compose.host.yml
# (redirect and port) has it on the host's network.
gateway_compose() {
  local file=compose.yml; [ "$FRONT" = compose ] || file=compose.host.yml
  (cd "$KIT" && $DOCKER_COMPOSE --env-file kit.env -f "$file" "$@")
}
site_compose() { (cd "$SITE_DIR" && eval "$SITE_COMPOSE" '"$@"'); }

# status_via PORT [PATH]: the status code of an HTTPS request for SITE_HOST
# made to 127.0.0.1:PORT, certificate checked against the name only.
status_via() {
  curl -sk --max-time 10 -o /dev/null -w '%{http_code}' \
    --resolve "$SITE_HOST:$1:127.0.0.1" "https://$SITE_HOST:$1${2:-/}" || true
}

# _sha256 FILE: the checksum, with sha256sum or, on a Mac, shasum.
_sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

# cert_sums: the checksums of CERT_FULLCHAIN and CERT_KEY, one per line
# (redirect and port). copy_certs stores them in certs/source.sha256 and
# watch.sh compares: a renewal that no hook announced (Caddy, a cron job) shows
# up as a difference.
cert_sums() {
  _sha256 "$CERT_FULLCHAIN"; _sha256 "$CERT_KEY"
  local name
  for name in ${EXTRA_CERT_NAMES:-}; do
    _sha256 "${LETSENCRYPT_LIVE:-/etc/letsencrypt/live}/$name/fullchain.pem" 2>/dev/null || true
  done
}

# copy_extra_certs: the certificates for other sites on this host, by their
# Let's Encrypt name (EXTRA_CERT_NAMES in site.conf), into certs/sni/<name>/,
# which the gateway reads with --sni-dir. A name without a certificate is
# skipped with a warning, so it never stops the site's own certificate.
copy_extra_certs() {
  local live_root=${LETSENCRYPT_LIVE:-/etc/letsencrypt/live} name src dst
  [ -n "$KIT" ] || return 1
  rm -rf "$KIT/certs/sni"; mkdir -p "$KIT/certs/sni"
  for name in ${EXTRA_CERT_NAMES:-}; do
    case "$name" in
      *[!a-zA-Z0-9.-]*|.*|*..*) echo "EXTRA_CERT_NAMES: $name is not a host name; skipped" >&2; continue ;;
    esac
    src="$live_root/$name"; dst="$KIT/certs/sni/$name"
    if [ ! -f "$src/fullchain.pem" ] || [ ! -f "$src/privkey.pem" ]; then
      echo "EXTRA_CERT_NAMES: no certificate for $name in $live_root; skipped" >&2; continue
    fi
    mkdir -p "$dst"
    if [ "$REHEARSAL" = 1 ]; then
      cp "$src/fullchain.pem" "$src/privkey.pem" "$dst/"; chmod 0644 "$dst"/*.pem
    else
      install -o "$GATEWAY_UID" -g 0 -m 0400 "$src/fullchain.pem" "$dst/fullchain.pem"
      install -o "$GATEWAY_UID" -g 0 -m 0400 "$src/privkey.pem" "$dst/privkey.pem"
      chown "$GATEWAY_UID:0" "$dst"; chmod 0500 "$dst"
    fi
  done
  if [ "$REHEARSAL" != 1 ]; then chown "$GATEWAY_UID:0" "$KIT/certs/sni"; chmod 0500 "$KIT/certs/sni"; fi
}

# copy_certs: the certificate and key, readable by the gateway's user only.
# Compose: from LETSENCRYPT_LIVE/CERT_NAME. Redirect and port: from the paths
# CERT_FULLCHAIN and CERT_KEY.
copy_certs() {
  local fullchain privkey
  if [ "$FRONT" = compose ]; then
    local live="$LETSENCRYPT_LIVE/$CERT_NAME"
    fullchain="$live/fullchain.pem"; privkey="$live/privkey.pem"
  else
    fullchain=$CERT_FULLCHAIN; privkey=$CERT_KEY
  fi
  mkdir -p "$KIT/certs"
  if [ "$REHEARSAL" = 1 ]; then
    cp "$fullchain" "$KIT/certs/cert.pem"; cp "$privkey" "$KIT/certs/key.pem"
    chmod 0644 "$KIT/certs/cert.pem" "$KIT/certs/key.pem"
  else
    install -o "$GATEWAY_UID" -g 0 -m 0400 "$fullchain" "$KIT/certs/cert.pem"
    install -o "$GATEWAY_UID" -g 0 -m 0400 "$privkey" "$KIT/certs/key.pem"
    chown "$GATEWAY_UID:0" "$KIT/certs"; chmod 0500 "$KIT/certs"
  fi
  copy_extra_certs
  if [ "$FRONT" != compose ]; then cert_sums > "$KIT/certs/source.sha256"; fi
}

# want_front: what kit.env says the front should be, site or gateway. Only
# the cutover and the rollback change it.
want_front() { local v; v=$(get_kv "$KIT/kit.env" VERITELL_FRONT); echo "${v:-site}"; }

# gateway_port: the port the gateway answers on at the moment.
gateway_port() {
  local v
  case "$FRONT" in
    redirect) echo "$GATEWAY_PORT";;
    port) v=$(get_kv "$KIT/kit.env" VERITELL_LISTEN); v=${v:-127.0.0.1:9443}; echo "${v##*:}";;
    *) v=$(get_kv "$KIT/kit.env" VERITELL_PUBLISH); v=${v:-127.0.0.1:9443}; echo "${v##*:}";;
  esac
}

# gateway_answers: 200 from the gateway's own script, on the port it answers
# on now, within GATEWAY_WAIT seconds (20: the time a restart takes, ASN
# database included).
gateway_answers() {
  local port; port=$(gateway_port)
  for _ in $(seq 1 "${GATEWAY_WAIT:-20}"); do
    [ "$(curl -sk --max-time 3 -o /dev/null -w '%{http_code}' --resolve "$SITE_HOST:$port:127.0.0.1" "https://$SITE_HOST:$port/__veritell/probe.js" || true)" = 200 ] && return 0
    sleep 1
  done
  return 1
}

# ---- the ASN database (--asn-db) --------------------------------------------
# Which network (autonomous system) each address belongs to: iptoasn.com's
# ip2asn-combined, public domain (PDDL 1.0), about 11 MB gzipped. asn.sh
# downloads it into asn/ip2asn.tsv, weekly (veritell-asn.timer); kit.env's
# VERITELL_ASN_DB tells the gateway where it is, or is empty for none.
ASN_DB=${ASN_DB:-on}
case "$ASN_DB" in on|off) ;; *) echo "site.conf: ASN_DB must be on or off (it is '$ASN_DB')" >&2; exit 2;; esac
ASN_DB_URL=${ASN_DB_URL:-https://iptoasn.com/data/ip2asn-combined.tsv.gz}
# A file with fewer rows is a truncated download, not the database (the real
# one has about 720 000).
ASN_DB_MIN_ROWS=${ASN_DB_MIN_ROWS:-100000}
# Where the gateway's container sees asn/ip2asn.tsv (the compose files mount asn/).
ASN_DB_IN_GATEWAY=/etc/veritell/asn/ip2asn.tsv

# asn_check FILE: does FILE look like an ip2asn TSV the gateway will load:
# every row start, end, AS number, country, description, tab-separated, the
# two addresses of one family; at least ASN_DB_MIN_ROWS rows. Prints why not.
# The gateway refuses the whole file for one bad row, so this runs before a
# file is put in place (and a gateway that still does not start is put back
# on the previous file, see asn.sh).
asn_check() {
  awk -F'\t' -v min="$ASN_DB_MIN_ROWS" '
    /^[ \t\r]*$/ { next }
    { n++
      sub(/\r$/, "")
      if (NF < 5) { printf "line %d: %d fields, not 5\n", NR, NF; bad = 1; exit }
      if ($3 !~ /^ *[0-9]+ *$/) { printf "line %d: AS number %s is not a number\n", NR, $3; bad = 1; exit }
      four = "^ *[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+ *$"; six = "^ *[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]* *$"
      if (!(($1 ~ four && $2 ~ four) || ($1 ~ six && $2 ~ six))) { printf "line %d: %s - %s is not an address range\n", NR, $1, $2; bad = 1; exit }
    }
    END {
      if (bad) exit 1
      if (n < min) { printf "%d rows, fewer than %d\n", n, min; exit 1 }
    }' "$1"
}

# asn_rows FILE: the number of routed ranges, the number the gateway loads and
# logs: rows with AS 0 (not routed) are skipped, as the gateway skips them.
asn_rows() { awk -F'\t' '$3 ~ /[0-9]/ && $3 + 0 != 0 { n++ } END { print n + 0 }' "$1" 2>/dev/null || echo 0; }

# asn_fetch: download ASN_DB_URL (gzipped when it ends in .gz) into
# asn/ip2asn.tsv.new and check it. 0 when that file is good; 1, with the
# reason logged and nothing left behind, otherwise. Never touches asn/ip2asn.tsv.
asn_fetch() {
  local dir="$KIT/asn" new="$KIT/asn/ip2asn.tsv.new" why
  mkdir -p "$dir"; chmod 0755 "$dir"
  rm -f "$new" "$new.download"
  # https only (file: for the tests), redirects included; at most 5 minutes.
  if ! curl -fsSL --proto '=https,file' --proto-redir '=https' --max-time 300 --retry 2 \
      -o "$new.download" "$ASN_DB_URL"; then
    log "ASN database: cannot download $ASN_DB_URL"; rm -f "$new.download"; return 1
  fi
  case "$ASN_DB_URL" in
    *.gz) if ! gzip -dc "$new.download" > "$new" 2>/dev/null; then
            log "ASN database: $ASN_DB_URL is not a gzip file"; rm -f "$new" "$new.download"; return 1
          fi; rm -f "$new.download";;
    *) mv -f "$new.download" "$new";;
  esac
  if ! why=$(asn_check "$new"); then
    log "ASN database from $ASN_DB_URL refused: $why"; rm -f "$new"; return 1
  fi
  # Public data; the gateway's user must read it.
  chmod 0644 "$new"
}

# asn_wire: kit.env's VERITELL_ASN_DB, from what is there: the path in the
# gateway when ASN_DB is on and asn/ip2asn.tsv exists, else empty (none).
# Makes asn/ so the compose files' mount has a folder. Prints the value.
asn_wire() {
  local want=""
  mkdir -p "$KIT/asn"; chmod 0755 "$KIT/asn"
  [ "$ASN_DB" = on ] && [ -s "$KIT/asn/ip2asn.tsv" ] && want=$ASN_DB_IN_GATEWAY
  if [ "$(get_kv "$KIT/kit.env" VERITELL_ASN_DB)" != "$want" ] || ! grep -q '^VERITELL_ASN_DB=' "$KIT/kit.env" 2>/dev/null; then
    set_kv "$KIT/kit.env" VERITELL_ASN_DB "$want"
  fi
  echo "$want"
}

# ipv6_wire: kit.env's VERITELL_FRONT_IPV6 and VERITELL_INNER_LISTEN (compose
# mode). With IPv6 (IPV6 on, or auto on a host that has it) the gateway's
# front network gets IPv6, so IPv6 visitors keep their own address instead of
# arriving through docker-proxy, and the gateway listens on [::]:8443;
# otherwise the network is IPv4 only and it listens on 0.0.0.0:8443. Prints on
# or off. See README.md, "IPv6 visitors".
ipv6_wire() {
  local on=off v6=false listen=0.0.0.0:8443
  case "${IPV6:-auto}" in
    on) on=on;;
    off) ;;
    *) [ -e "${IPV6_PROC:-/proc/net/if_inet6}" ] && on=on;;
  esac
  [ "$on" = on ] && { v6=true; listen='[::]:8443'; }
  [ "$(get_kv "$KIT/kit.env" VERITELL_FRONT_IPV6)" = "$v6" ] || set_kv "$KIT/kit.env" VERITELL_FRONT_IPV6 "$v6"
  [ "$(get_kv "$KIT/kit.env" VERITELL_INNER_LISTEN)" = "$listen" ] || set_kv "$KIT/kit.env" VERITELL_INNER_LISTEN "$listen"
  echo "$on"
}

# agents_wire: kit.env's VERITELL_WBA_AGENTS, from what is there: the path in
# the gateway when agents/agents.json exists and is not empty, else empty
# (no agent trusted). Makes agents/ so the compose files' mount has a folder.
# Prints the value.
AGENTS_IN_GATEWAY=/etc/veritell/agents/agents.json
agents_wire() {
  local want=""
  mkdir -p "$KIT/agents"; chmod 0755 "$KIT/agents"
  [ -s "$KIT/agents/agents.json" ] && want=$AGENTS_IN_GATEWAY
  if [ "$(get_kv "$KIT/kit.env" VERITELL_WBA_AGENTS)" != "$want" ] || ! grep -q '^VERITELL_WBA_AGENTS=' "$KIT/kit.env" 2>/dev/null; then
    set_kv "$KIT/kit.env" VERITELL_WBA_AGENTS "$want"
  fi
  echo "$want"
}

# public_addr: the host's own address as a visitor reaches it: PUBLIC_ADDR in
# site.conf, else the source address of the route to the internet.
public_addr() {
  if [ -n "${PUBLIC_ADDR:-}" ]; then echo "$PUBLIC_ADDR"; return; fi
  ip route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([^ ]*\).*/\1/p' | head -1
}

# status_public PORT [PATH]: like status_via, but to the host's public address.
# In redirect mode the OUTPUT rule sends this the way a visitor's request goes.
status_public() {
  curl -sk --max-time 10 -o /dev/null -w '%{http_code}' \
    --resolve "$SITE_HOST:$1:$(public_addr)" "https://$SITE_HOST:$1${2:-/}" || true
}

# upstream_status [PATH]: the status code of the site itself at UPSTREAM
# (redirect and port), over TLS or plain HTTP as UPSTREAM_TLS says.
upstream_status() {
  local scheme=https host=${UPSTREAM%:*} port=${UPSTREAM##*:}
  [ "$UPSTREAM_TLS" = off ] && scheme=http
  curl -sk --max-time 10 -o /dev/null -w '%{http_code}' \
    --resolve "$SITE_HOST:$port:$host" "$scheme://$SITE_HOST:$port${1:-/}" || true
}

# marker_status MARK: the code for a request to /MARK on the public port, sent
# the way the mode's visitors come.
marker_status() {
  if [ "$FRONT" = redirect ]; then status_public "$PUBLIC_PORT" "/$1"; else status_via "$PUBLIC_PORT" "/$1"; fi
}

# marker_seen MARK: how many events in the store have the path /MARK (from
# the last 10 minutes). The kit's checks send a request with a fresh mark
# and look for it here: the gateway writes no line per request to its log
# (--log-requests off). "0" when the store cannot be asked.
marker_seen() {
  local p n
  p=$(get_kv "$KIT/kit.env" CLICKHOUSE_PASSWORD)
  n=$(docker exec veritell-clickhouse clickhouse-client --user veritell --password "$p" \
    --query "SELECT count() FROM veritell.events WHERE path = '/$1' AND ts > now() - INTERVAL 10 MINUTE" 2>/dev/null || true)
  case "$n" in ''|*[!0-9]*) echo 0;; *) echo "$n";; esac
}

# code_ok CODE: did the site answer. Compose: 200, as it always was. The
# other modes serve any site, whose unknown paths may well be a 404: anything
# below 500 is an answer (a 502 from the gateway is not).
code_ok() {
  if [ "$FRONT" = compose ]; then [ "$1" = 200 ]; else printf '%s' "$1" | grep -Eq '^[1-4][0-9][0-9]$'; fi
}

# run_cmd COMMAND: one of the site's own commands (SITE_RELEASE_CMD,
# SITE_RESTORE_CMD), eval'ed, its output logged line by line. The command's
# exit status is the result.
run_cmd() {
  log "running: $1"
  { eval "$1" 2>&1; } | while IFS= read -r line; do log "  $line"; done
}

# port_busy PORT: is anything listening on it, on any address.
port_busy() {
  ss -ltn 2>/dev/null | awk -v s=":$1" '$1=="LISTEN" { a=$4; if (substr(a, length(a)-length(s)+1) == s) found=1 } END { exit !found }'
}

# ---- redirect mode: the firewall rules --------------------------------------
# Per address family (4, and 6 when IPv6 is on), three rules, each with the
# comment "veritell" so that they are ours to find and delete:
#   nat4 / nat6      nat PREROUTING: tcp PUBLIC_PORT to a local address -> REDIRECT GATEWAY_PORT
#   out4 / out6      nat OUTPUT: the same for the host's own connections to
#                    its own address (loopback excepted), so that checks made on
#                    the host take the path a visitor's request takes
#   input4 / input6  filter INPUT: accept redirected connections only (conntrack
#                    DNAT, original port PUBLIC_PORT), so that a default deny
#                    does not drop them and GATEWAY_PORT stays closed otherwise

# ipv6_on: are the IPv6 rules wanted.
ipv6_on() {
  case "$IPV6" in
    on) return 0;;
    off) return 1;;
    *) [ -e /proc/net/if_inet6 ] && command -v ip6tables >/dev/null;;
  esac
}
_families() { if ipv6_on; then echo "4 6"; else echo 4; fi; }
# _ipt FAMILY ARGS...: iptables or ip6tables.
_ipt() { local fam=$1; shift; if [ "$fam" = 6 ]; then ip6tables "$@"; else iptables "$@"; fi; }
# _rule_list FAMILY KIND: `iptables -S` of the chain that kind lives in.
_rule_list() {
  case "$2" in
    nat) _ipt "$1" -w -t nat -S PREROUTING;;
    out) _ipt "$1" -w -t nat -S OUTPUT;;
    input) _ipt "$1" -w -S INPUT;;
  esac 2>/dev/null || true
}
_veritell_re='--comment "?veritell"?( |$)'
# _rule_present FAMILY KIND
_rule_present() {
  local list; list=$(_rule_list "$1" "$2")
  grep -Eq -- "$_veritell_re" <<<"$list"
}
# _docker_first FAMILY KIND: does a `-j DOCKER` line come before our rule.
_docker_first() {
  local list; list=$(_rule_list "$1" "$2")
  awk -v re="$_veritell_re" '$0 ~ re && !p {p=NR} /-j DOCKER/ && !d {d=NR} END { exit !(p && d && d < p) }' <<<"$list"
}

# rules_apply: insert the rules that are missing, first in their chains (before
# Docker's and ufw's). Safe to run again.
rules_apply() {
  local fam lo
  for fam in $(_families); do
    lo=127.0.0.0/8; [ "$fam" = 6 ] && lo=::1/128
    if ! _rule_present "$fam" nat; then
      _ipt "$fam" -w -t nat -I PREROUTING 1 -p tcp --dport "$PUBLIC_PORT" -m addrtype --dst-type LOCAL \
        -m comment --comment veritell -j REDIRECT --to-ports "$GATEWAY_PORT"
      log "ip${fam}tables: nat PREROUTING $PUBLIC_PORT -> $GATEWAY_PORT"
    fi
    if ! _rule_present "$fam" out; then
      _ipt "$fam" -w -t nat -I OUTPUT 1 ! -d "$lo" -p tcp --dport "$PUBLIC_PORT" -m addrtype --dst-type LOCAL \
        -m comment --comment veritell -j REDIRECT --to-ports "$GATEWAY_PORT"
      log "ip${fam}tables: nat OUTPUT $PUBLIC_PORT -> $GATEWAY_PORT (the host's own connections)"
    fi
    if ! _rule_present "$fam" input; then
      _ipt "$fam" -w -I INPUT 1 -p tcp --dport "$GATEWAY_PORT" -m conntrack --ctstate DNAT --ctorigdstport "$PUBLIC_PORT" \
        -m comment --comment veritell -j ACCEPT
      log "ip${fam}tables: INPUT accept redirected $PUBLIC_PORT -> $GATEWAY_PORT"
    fi
  done
}

# rules_remove: delete every line with the veritell comment, by turning its -A
# into -D. Keeps going if one deletion fails; the result is 1 then.
rules_remove() {
  local fam kind list line rc=0 table
  local -a words
  for fam in $(_families); do
    for kind in nat out input; do
      list=$(_rule_list "$fam" "$kind")
      table=(); [ "$kind" != input ] && table=(-t nat)
      while IFS= read -r line; do
        case "$line" in -A\ *) ;; *) continue;; esac
        grep -Eq -- "$_veritell_re" <<<"$line" || continue
        read -ra words <<<"-D${line#-A}"
        if _ipt "$fam" -w ${table[@]+"${table[@]}"} "${words[@]}"; then log "ip${fam}tables: deleted $line"; else log "ip${fam}tables: could not delete $line"; rc=1; fi
      done <<<"$list"
    done
  done
  return "$rc"
}

# _front_state_redirect: see front_state.
_front_state_redirect() {
  local want fam kind present="" missing="" dockers=""
  want=$(want_front)
  for fam in $(_families); do
    for kind in nat out input; do
      if _rule_present "$fam" "$kind"; then present="$present $kind$fam"; else missing="$missing $kind$fam"; fi
      if [ "$kind" != input ] && _docker_first "$fam" "$kind"; then dockers="$dockers $kind$fam"; fi
    done
  done
  present=${present# }; missing=${missing# }; dockers=${dockers# }
  case "$want" in
    site)
      [ -z "$present" ] && { echo site; return; }
      echo "inconsistent: rules set but kit.env says site: $present";;
    gateway)
      [ -n "$missing" ] && { echo "inconsistent: rules missing: $missing"; return; }
      [ -n "$dockers" ] && { echo "inconsistent: a DOCKER rule comes before the redirect ($dockers)"; return; }
      if docker ps --format '{{.Names}}|' 2>/dev/null | cut -d'|' -f1 | grep -qx veritell-gateway; then echo gateway
      else echo "inconsistent: the gateway is not running"; fi;;
    *) echo "inconsistent: kit.env VERITELL_FRONT=$want";;
  esac
}

# _front_state_port: see front_state.
_front_state_port() {
  local want out holder
  want=$(want_front)
  out=$(ss -ltnp 2>/dev/null || true)
  # The process on PUBLIC_PORT at a public address (not 127.x or ::1).
  holder=$(awk -v s=":$PUBLIC_PORT" '
    $1=="LISTEN" { a=$4
      if (a ~ /^127\./ || a ~ /^\[::1\]/) next
      if (substr(a, length(a)-length(s)+1) != s) next
      if (match($0, /users:\(\("[^"]*"/)) print substr($0, RSTART+9, RLENGTH-10); else print "something"
      exit }' <<<"$out")
  [ -n "$holder" ] || { echo "inconsistent: nothing listens on $PUBLIC_PORT"; return; }
  case "$want:$holder" in
    site:veritell) echo "inconsistent: kit.env says site but veritell listens on $PUBLIC_PORT";;
    site:*) echo site;;
    gateway:veritell) echo gateway;;
    gateway:*) echo "inconsistent: kit.env says gateway but $holder listens on $PUBLIC_PORT";;
    *) echo "inconsistent: kit.env VERITELL_FRONT=$want";;
  esac
}

# front_state: who holds the public HTTPS port. Prints one of
#   not-installed   no kit.env yet
#   site            (redirect, port) the site is served directly
#   nginx           (compose) the site's nginx holds it; the gateway is beside it
#   gateway         the gateway is in front
#   inconsistent: <why>
# Compose: from both settings and what Docker actually publishes. Redirect:
# from the veritell firewall rules, VERITELL_FRONT in kit.env and whether the
# gateway runs. Port: from who listens on PUBLIC_PORT (ss) and VERITELL_FRONT.
# The scripts only move between site (nginx) and gateway; from inconsistent,
# only rollback.sh runs (it is the way back).
front_state() {
  [ -f "$KIT/kit.env" ] || { echo not-installed; return; }
  case "$FRONT" in
    redirect) _front_state_redirect;;
    port) _front_state_port;;
    *) _front_state_compose;;
  esac
}

_front_state_compose() {
  [ -f "$KIT/kit.env" ] || { echo not-installed; return; }
  local kit site holder
  kit=$(get_kv "$KIT/kit.env" VERITELL_PUBLISH); kit=${kit:-127.0.0.1:9443}
  site=$(get_kv "$SITE_DIR/$SITE_ENV_FILE" WEB_HTTPS_PUBLISH); site=${site:-$PUBLIC_PORT}
  # The container publishing PUBLIC_PORT on every address (not 127.0.0.1).
  holder=$(docker ps --format '{{.Names}}|{{.Ports}}' 2>/dev/null \
    | awk -F'|' -v p=":$PUBLIC_PORT->" '{ n=split($2, a, ", "); for (i=1;i<=n;i++) if (index(a[i], p) && a[i] !~ /^127\./) { print $1; next } }' | head -1)
  if [ "$kit" = "$PUBLIC_PORT" ] && [ "$site" = "$NGINX_LOCAL_HTTPS" ]; then
    [ "$holder" = veritell-gateway ] && { echo gateway; return; }
    echo "inconsistent: set for the gateway, but ${holder:-nothing} publishes $PUBLIC_PORT"; return
  fi
  if [ "$kit" != "$PUBLIC_PORT" ] && [ "$site" = "$PUBLIC_PORT" ]; then
    [ -n "$holder" ] && [ "$holder" != veritell-gateway ] && { echo nginx; return; }
    echo "inconsistent: set for nginx, but ${holder:-nothing} publishes $PUBLIC_PORT"; return
  fi
  echo "inconsistent: kit.env VERITELL_PUBLISH=$kit, site WEB_HTTPS_PUBLISH=$site"
}
