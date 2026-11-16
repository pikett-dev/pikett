#!/usr/bin/env bash
# Retrofits the patch window on a running server (Ubuntu 24.04). Run as root on the server:
#
#   sudo ./install-patching.sh
#
# Installs unattended-upgrades and needrestart if missing, writes the files of this folder and moves the apt timers
# to the window. Re-running is safe. Undo: see ../README.md, "Patch window", "Undo".
set -Eeuo pipefail
trap 'echo "error: step failed (line $LINENO): $BASH_COMMAND" >&2' ERR

here="$(cd "$(dirname "$0")" && pwd)"
[ "$(id -u)" = 0 ] || { echo "error: run as root" >&2; exit 1; }

DEBIAN_FRONTEND=noninteractive apt-get install -y -q unattended-upgrades needrestart
install -m 644 "$here/20auto-upgrades" /etc/apt/apt.conf.d/20auto-upgrades
install -m 644 "$here/52ops-unattended-upgrades" /etc/apt/apt.conf.d/52ops-unattended-upgrades
install -d /etc/needrestart/conf.d /etc/systemd/system/apt-daily.timer.d /etc/systemd/system/apt-daily-upgrade.timer.d
install -m 644 "$here/needrestart-ops.conf" /etc/needrestart/conf.d/ops.conf
install -m 644 "$here/apt-daily.timer.conf" /etc/systemd/system/apt-daily.timer.d/ops-window.conf
install -m 644 "$here/apt-daily-upgrade.timer.conf" /etc/systemd/system/apt-daily-upgrade.timer.d/ops-window.conf
systemctl daemon-reload
systemctl restart apt-daily.timer apt-daily-upgrade.timer

echo "Check: only the security pockets are allowed:"
unattended-upgrade --dry-run --debug 2>&1 | grep -i "allowed origins" || true
systemctl list-timers 'apt-daily*' --no-pager
