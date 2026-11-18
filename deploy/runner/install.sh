#!/usr/bin/env bash
# Installs the ops-runner on this server. Run as root on the server, from a copy of the repo's `runner/` and
# `deploy/runner/` folders (rsync -R both, see README.md).
#
#   sudo ./install.sh            runner, user, unit; stops after creating the env file the first time
#
# Re-running is safe. Undo: see README.md, section "Undo".
set -Eeuo pipefail
trap 'echo "error: step failed (line $LINENO): $BASH_COMMAND" >&2' ERR

here="$(cd "$(dirname "$0")" && pwd)"
src="$here/../../runner"
[ "$(id -u)" = 0 ] || { echo "error: run as root" >&2; exit 1; }
[ -f "$src/catalog.json" ] || { echo "error: no runner/ folder next to this script" >&2; exit 1; }
# Optional own catalog (the same file as deploy/ops-server/catalog/catalog.json on the ops server). It is checked with
# the runner's own parser before anything on this server changes, and kept in /etc/ops-runner, so a later run of this
# script without CATALOG_FILE leaves it alone. Pass it on the remote command line: ssh root@host CATALOG_FILE=... script
if [ -n "${CATALOG_FILE:-}" ]; then
  [ -f "$CATALOG_FILE" ] || { echo "error: CATALOG_FILE $CATALOG_FILE is not a file" >&2; exit 1; }
  python3 -I -c 'import sys; from pathlib import Path; sys.path.insert(0, sys.argv[1]); from runner.catalog import load_catalog; load_catalog(Path(sys.argv[2]))' \
    "$src/.." "$CATALOG_FILE" || { echo "error: $CATALOG_FILE is not a valid catalog (see above)" >&2; exit 1; }
fi

# python3-cryptography verifies the signatures; Ubuntu 24.04 ships 41.x, which has everything the runner uses.
python3 -I -c "import cryptography" 2>/dev/null || { apt-get update -qq && apt-get install -y python3-cryptography; }

# The runner user has no login, no home and no groups. The code is owned by root and not writable by the runner,
# so a compromised runner cannot change its own catalog or code.
id ops-runner >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin ops-runner
install -d -m 755 -o root -g root /opt/ops-runner /opt/ops-runner/runner
rm -f /opt/ops-runner/runner/*.py /opt/ops-runner/runner/catalog.json  # no stale module from an older version
for file in "$src"/*.py "$src"/catalog.json; do
  install -m 644 -o root -g root "$file" /opt/ops-runner/runner/
done
install -d -m 700 -o ops-runner -g ops-runner /var/lib/ops-runner
install -d -m 755 -o root -g root /etc/ops-runner
[ -z "${CATALOG_FILE:-}" ] || install -m 644 -o root -g root "$CATALOG_FILE" /etc/ops-runner/catalog.json

if [ ! -f /etc/ops-runner/job-signing.pub ]; then
  echo "error: put the public signing key into /etc/ops-runner/job-signing.pub first (see README.md)" >&2
  exit 1
fi
if [ ! -f /etc/ops-runner/ops-runner.env ]; then
  install -m 600 -o root -g root "$here/ops-runner.env.example" /etc/ops-runner/ops-runner.env
  echo "created /etc/ops-runner/ops-runner.env from the example: fill it in, then run this script again"
  exit 0
fi
chmod 600 /etc/ops-runner/ops-runner.env
chown root:root /etc/ops-runner/job-signing.pub
chmod 644 /etc/ops-runner/job-signing.pub  # the runner user reads it; it is a public key
# A bad key would make the unit crash-loop; check it parses before the restart.
(cd /opt/ops-runner && python3 -c "from runner.jobs import public_key_from_b64; public_key_from_b64(open('/etc/ops-runner/job-signing.pub').read())") \
  || { echo "error: /etc/ops-runner/job-signing.pub is not a 32 byte Ed25519 public key in base64" >&2; exit 1; }
grep -q "^HOST_NAME=$(hostname)\$" /etc/ops-runner/ops-runner.env \
  || echo "warning: HOST_NAME in the env file is not this server's hostname ($(hostname)); jobs are for the name in RUNNER_TOKENS" >&2
# A half-filled env file would make the runner poll with a wrong token for ever while the unit looks active.
grep -Eq '^OPS_URL=http' /etc/ops-runner/ops-runner.env && ! grep -q '^OPS_URL=.*<' /etc/ops-runner/ops-runner.env \
  || { echo "error: OPS_URL in /etc/ops-runner/ops-runner.env is not filled in" >&2; exit 1; }
grep -Eq '^RUNNER_TOKEN=.{32,}' /etc/ops-runner/ops-runner.env \
  || { echo "error: RUNNER_TOKEN in /etc/ops-runner/ops-runner.env is missing or too short" >&2; exit 1; }

# Root actions of the runbooks: fixed systemd units plus a polkit rule that lets the runner start exactly those.
ls "$here"/ops-runbook-*.service "$here/50-ops-runner.rules" "$here/ops-runbook.tmpfiles.conf" >/dev/null \
  || { echo "error: the runbook units, the polkit rule or the tmpfiles file are missing from this copy" >&2; exit 1; }
# Without polkit systemd refuses every start from the unprivileged runner user, and all root runbooks would fail.
dpkg -s polkitd >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y polkitd; }
install -m 644 "$here"/ops-runbook-*.service /etc/systemd/system/
install -d -m 755 /etc/polkit-1/rules.d
install -m 644 "$here/50-ops-runner.rules" /etc/polkit-1/rules.d/50-ops-runner.rules
install -m 644 "$here/ops-runbook.tmpfiles.conf" /etc/tmpfiles.d/ops-runbook.conf
systemd-tmpfiles --create /etc/tmpfiles.d/ops-runbook.conf
systemctl daemon-reload

install -m 644 "$here/ops-runner.service" /etc/systemd/system/ops-runner.service
systemctl daemon-reload
systemctl enable ops-runner.service
systemctl restart ops-runner.service
sleep 3
systemctl --no-pager --lines=15 status ops-runner.service || true
