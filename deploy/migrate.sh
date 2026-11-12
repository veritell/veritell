#!/usr/bin/env bash
# Brings the events table up to the gateway's schema: adds any missing column
# (clickhouse/migrate.sql, generated from the gateway's DDL). Never removes
# or changes a column. Safe to run any number of times. Run by update.sh
# before the gateway restarts; can be run on its own, as root.
SCRIPT=migrate
. "$(dirname "$0")/lib.sh"
P=$(get_kv "$KIT/kit.env" CLICKHOUSE_PASSWORD)
docker exec -i veritell-clickhouse clickhouse-client --user veritell --password "$P" --multiquery < "$KIT/clickhouse/migrate.sql"
have=$(printf 'SELECT name FROM system.columns WHERE database = %s AND table = %s FORMAT TSV\n' "'veritell'" "'events'" \
  | docker exec -i veritell-clickhouse clickhouse-client --user veritell --password "$P" | sort)
want=$(sed -n 's/^ALTER TABLE veritell.events ADD COLUMN IF NOT EXISTS \([a-z0-9_]*\) .*/\1/p' "$KIT/clickhouse/migrate.sql" | sort)
# Every ALTER line must have given a name (a name the pattern misses would
# be reported as missing or extra for no reason).
[ "$(printf '%s\n' "$want" | grep -c .)" = "$(grep -c '^ALTER TABLE' "$KIT/clickhouse/migrate.sql")" ] \
  || { log "could not read every column name in migrate.sql"; exit 1; }
missing=$(comm -13 <(printf '%s\n' "$have") <(printf '%s\n' "$want"))
extra=$(comm -23 <(printf '%s\n' "$have") <(printf '%s\n' "$want"))
[ -z "$missing" ] || { log "still missing after the migration: $(echo $missing)"; exit 1; }
[ -z "$extra" ] || log "in the table but no longer written by the gateway (left as they are): $(echo $extra)"
log "events table: all $(printf '%s\n' "$want" | wc -l | tr -d ' ') columns the gateway writes are there"
