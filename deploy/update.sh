#!/usr/bin/env bash
# Updates the gateway on the host from a new kit, as root:
#   rsync -a dist/veritell-kit/ host:veritell-kit/      (on the workstation)
#   sudo /opt/veritell/update.sh /home/me/veritell-kit  (on the host)
# Files are compared by checksum, not size and time.
# Copies the kit's files but never the secrets, site.conf, the certificate, the
# reports and exports, the ASN database (asn/), the trusted agents (agents/) or the state, and never changes who owns them. Keeps the running kit (binary,
# scripts, compose.yml) in previous/ and the running image as
# veritell:previous, builds the new one, restarts the gateway and checks that
# HTTPS answers through it. If it does not within 20 s, the previous kit and
# image are put back and the gateway restarted on them.
#
# Two stages. The script that is started is the one already on the host, from
# the previous kit; it only checks, keeps and copies (stage 1), then runs the
# new kit's own update.sh for the rest (stage 2), so that whatever the new kit
# needs before its gateway starts is done by the script that knows about it.
SCRIPT=update
. "$(dirname "$0")/lib.sh"
SRC=${1:?usage: update.sh <folder with the new kit>}
[ -f "$SRC/veritell" ] && [ -f "$SRC/veritell.sha256" ] || { log "no kit in $SRC"; exit 2; }
sum_check() { if command -v sha256sum >/dev/null; then sha256sum -c --quiet "$@"; else shasum -a 256 -c --quiet "$@"; fi; }
(cd "$SRC" && sum_check veritell.sha256) || { log "the binary in $SRC does not match its checksum"; exit 2; }

# What belongs to this host and is never copied, kept or put back.
local_files=(--exclude gateway.env --exclude kit.env --exclude site.conf --exclude certs/ --exclude state/
  --exclude watch.state --exclude reports/ --exclude exports/ --exclude asn/ --exclude agents/ --exclude upstream-ca.pem --exclude '*.before-*' --exclude previous/
  --exclude veritell.previous --exclude veritell.sha256.previous)
# Our certificate for exports stays unless the new kit brings its own (that is
# how we change our key with an update); then it is copied like any kit file.
[ -f "$SRC/recipient.pem" ] || local_files+=(--exclude recipient.pem)
owner=(--no-owner --no-group --chown=root:root); [ "$REHEARSAL" = 1 ] && owner=()

if [ "${VERITELL_UPDATE_STAGE:-1}" != 2 ]; then
  # The running kit, as it is, put back if the new one fails.
  rsync -a --checksum --delete "${local_files[@]}" "$KIT"/ "$KIT/previous"/
  rsync -a --checksum ${owner[@]+"${owner[@]}"} "${local_files[@]}" "$SRC"/ "$KIT"/
  log "kit copied; the previous one is in $KIT/previous"
  VERITELL_UPDATE_STAGE=2 RUN_ID=$RUN_ID exec "$KIT/update.sh" "$SRC"
fi

# Until the restart below the old gateway keeps running: a step that fails
# before it (migrate.sh, the image build) puts the previous kit back, so the
# kit's files match what runs.
put_back_kit() {
  log "the update stopped before the restart: putting back the previous kit (the gateway was not touched)"
  rsync -a --checksum --delete "${local_files[@]}" "$KIT/previous"/ "$KIT"/
}
trap put_back_kit ERR

# Compose: the published port; redirect: GATEWAY_PORT; port: the end of VERITELL_LISTEN.
port=$(gateway_port)
answers() { gateway_answers; } # 200 from the gateway's own script within 20 s

# Kits from before the dashboard have no token, and the gateway would not start.
ensure_admin_token
# The table first: a column the new gateway writes must exist before it starts.
# Columns are only ever added, so the previous gateway still writes to it.
"$KIT/migrate.sh"
# The ASN database stays in asn/ across updates. A kit from before it has
# none: download it now (a failure is not a reason to stop the update), and
# say where it is in kit.env either way.
if [ "$ASN_DB" = on ] && [ ! -s "$KIT/asn/ip2asn.tsv" ]; then
  "$KIT/asn.sh" --no-restart || log "the gateway goes on without an ASN database: run $KIT/asn.sh once the download works"
fi
asn_wire >/dev/null
# Trusted Web Bot Auth agents stay in agents/ across updates, like asn/.
agents_wire >/dev/null
# The front network's IPv6 (README.md, "IPv6 visitors").
ipv6_wire >/dev/null
docker tag veritell:latest veritell:previous 2>/dev/null || true
docker build -q -f "$KIT/Dockerfile.prebuilt" -t veritell:latest "$KIT" >/dev/null
trap - ERR
# A compose.yml that Compose refuses fails here, before any restart: that
# goes back too, rather than leave the new kit beside the old container.
if gateway_compose up -d gateway >/dev/null 2>&1 && answers; then
  log "updated: the gateway answers on $port ($(cut -c1-16 "$KIT/veritell.sha256"))"
  # asn.sh --no-restart above kept the database it replaced, for a restart
  # that has now gone well.
  rm -f "$KIT/asn/ip2asn.tsv.previous"
  # ClickHouse reads its settings when it starts, and the file is mounted on
  # its own, so a restart would keep reading the replaced one: a changed file
  # needs the container made again. The data stays in its volume; the
  # gateway drops the few events it sends in those seconds. Settings it does
  # not start on are put back.
  ch_conf=clickhouse/low-memory.xml
  if ! cmp -s "$KIT/$ch_conf" "$KIT/previous/$ch_conf"; then
    if gateway_compose up -d --force-recreate --wait clickhouse >/dev/null 2>&1; then
      log "ClickHouse restarted on its new settings"
    else
      log "ClickHouse does not start on the new $ch_conf: putting back the previous one"
      docker logs --tail 5 veritell-clickhouse 2>&1 | sed 's/^/  /'
      [ -f "$KIT/previous/$ch_conf" ] && cp "$KIT/previous/$ch_conf" "$KIT/$ch_conf"
      gateway_compose up -d --force-recreate --wait clickhouse >/dev/null 2>&1 \
        || log "ClickHouse does not start on the previous settings either: look at docker logs veritell-clickhouse"
    fi
  fi
  # The new kit's timers and units (a kit can add one, as the weekly report
  # did). install-watch.sh only rewrites unit files and enables timers; it
  # touches neither the gateway nor the front. A failure here leaves the
  # update in place and says what to run.
  "$KIT/install-watch.sh" || log "the update is in place, but its timers were not installed: run $KIT/install-watch.sh"
  exit 0
fi
log "the new gateway does not answer on $port: going back to the previous kit and image"
docker logs --tail 5 veritell-gateway 2>&1 | sed 's/^/  /'
docker tag veritell:previous veritell:latest
# The whole previous kit, compose.yml and scripts included, not only the
# binary: a new compose.yml can be what failed.
rsync -a --checksum --delete "${local_files[@]}" "$KIT/previous"/ "$KIT"/
gateway_compose up -d --force-recreate gateway >/dev/null 2>&1
if answers; then log "back on the previous kit; it answers on $port"; else log "the previous kit does not answer either: look at docker logs veritell-gateway"; fi
exit 1
