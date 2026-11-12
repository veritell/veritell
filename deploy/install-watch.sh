#!/usr/bin/env bash
# Installs the check (watch.sh) as a systemd timer, every 5 minutes, as root,
# and the weekly report (report.sh) as veritell-report.timer.
# In redirect mode also veritell-front.service, which runs restore-front.sh at
# boot (firewall rules do not survive a reboot).
# Run by install.sh; can be run on its own. Read it with:
#   journalctl -t veritell-watch            # all
#   journalctl -t veritell-watch -p err     # problems only
SCRIPT=install-watch
. "$(dirname "$0")/lib.sh"
[ "$REHEARSAL" = 1 ] && { log "rehearsal: no systemd timer"; exit 0; }
cat > /etc/systemd/system/veritell-watch.service <<UNIT
[Unit]
Description=Check the veritell gateway (journalctl -t veritell-watch)
After=docker.service

[Service]
Type=oneshot
ExecStart=$KIT/watch.sh
UNIT
cat > /etc/systemd/system/veritell-watch.timer <<'UNIT'
[Unit]
Description=Check the veritell gateway every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now veritell-watch.timer >/dev/null
log "veritell-watch.timer installed: journalctl -t veritell-watch"
# The weekly report (report.sh), Mondays 06:00 UTC; a run missed while the host
# was off is made at the next boot.
cat > /etc/systemd/system/veritell-report.service <<UNIT
[Unit]
Description=Write the weekly veritell report (reports/ in the kit)
After=docker.service

[Service]
Type=oneshot
ExecStart=$KIT/report.sh
UNIT
cat > /etc/systemd/system/veritell-report.timer <<'UNIT'
[Unit]
Description=Write the weekly veritell report on Mondays

[Timer]
OnCalendar=Mon *-*-* 06:00:00 UTC
Persistent=true

[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now veritell-report.timer >/dev/null
log "veritell-report.timer installed: $KIT/reports/, by hand: $KIT/report.sh"
if [ "$FRONT" = redirect ]; then
  cat > /etc/systemd/system/veritell-front.service <<UNIT
[Unit]
Description=Put the veritell redirect rules back after boot (journalctl -t veritell-watch)
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$KIT/restore-front.sh

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable veritell-front.service >/dev/null
  log "veritell-front.service installed: the redirect comes back after a reboot"
fi
