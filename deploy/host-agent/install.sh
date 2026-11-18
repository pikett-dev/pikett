#!/usr/bin/env bash
# Installs the collector on this server. Run as root on the server, from a copy of this folder:
#
#   sudo ./install.sh            collector, units and timers (reads only; changes nothing else)
#
# Re-running is safe. Undo: see README.md, section "Undo".
set -Eeuo pipefail
trap 'echo "error: step failed (line $LINENO): $BASH_COMMAND" >&2' ERR

here="$(cd "$(dirname "$0")" && pwd)"
[ "$(id -u)" = 0 ] || { echo "error: run as root" >&2; exit 1; }

install -d -m 755 /opt/ops-collect
install -m 755 "$here/ops-collect.py" /opt/ops-collect/ops-collect.py
if [ ! -f /etc/ops-collect.env ]; then
  install -m 600 "$here/ops-collect.env.example" /etc/ops-collect.env
  echo "created /etc/ops-collect.env from the example: fill it in, then run this script again"
  exit 0
fi

for unit in "$here"/ops-collect-*.service "$here"/ops-collect-*.timer; do
  install -m 644 "$unit" /etc/systemd/system/
done
systemctl daemon-reload
systemctl enable --now ops-collect-hourly.timer ops-collect-daily.timer ops-collect-weekly.timer

echo "installed. First run now:"
for timer in hourly daily weekly; do
  systemctl start "ops-collect-$timer.service" || echo "warning: ops-collect-$timer failed, see journalctl -u ops-collect-$timer"
done
systemctl list-timers 'ops-collect-*' --no-pager
