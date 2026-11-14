#!/usr/bin/env bash
# lib.sh sources site.conf as root: one that others can write, or in a kit
# folder others can write, is refused before anything in it runs. Runs
# anywhere, as any user:  deploy/test_conf.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fails=0
eq() { if [ "$2" = "$3" ]; then echo "PASS  $1"; else echo "FAIL  $1: wanted '$3', got '$2'"; fails=$((fails+1)); fi; }

mkdir -p "$T/kit"
cp "$HERE/lib.sh" "$T/kit/"
cat > "$T/kit/site.conf" <<CONF
SITE_HOST=example.test
PUBLIC_PORT=443
CONF
# The exit status of sourcing lib.sh in a subshell, then what it printed.
lib_rc() { out=$( ( . "$T/kit/lib.sh" ) 2>&1 ); echo "$? $out"; }

chmod 0755 "$T/kit"; chmod 0644 "$T/kit/site.conf"
eq "a site.conf only its owner writes is sourced" "$(lib_rc | cut -d' ' -f1)" "0"
chmod 0664 "$T/kit/site.conf"
eq "a site.conf the group can write is refused, saying how to fix it" \
  "$(lib_rc | grep -c '^2 .*site.conf can be written by others (mode 664): chmod go-w')" "1"
chmod 0646 "$T/kit/site.conf"
eq "a site.conf anyone can write is refused" "$(lib_rc | cut -d' ' -f1)" "2"
chmod 0644 "$T/kit/site.conf"; chmod 0777 "$T/kit"
eq "a kit folder anyone can write is refused" "$(lib_rc | cut -d' ' -f1)" "2"
chmod 0755 "$T/kit"
eq "with both put right it is sourced again" "$(lib_rc | cut -d' ' -f1)" "0"

echo
if [ "$fails" = 0 ]; then echo "ALL PASSED"; else echo "$fails FAILED"; fi
exit "$fails"
