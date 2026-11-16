#!/bin/bash
# Deploy wrapper for the ops server. Installed as /usr/local/bin/ops-deploy by `provision.sh pipeline`.
# The pipeline's SSH key may run only this script (authorized_keys: restrict,command="sudo /usr/local/bin/ops-deploy"),
# and the commit to deploy arrives as SSH_ORIGINAL_COMMAND. It checks out that commit, builds the image and restarts
# the stack. Env files stay on the server (they are gitignored), so the pipeline never holds a secret.
# Repository access (read-only key, Bitbucket host key) is configured in /root/.ssh/config by `provision.sh pipeline`.
# The server holds a copy of this file: after changing it, run `provision.sh pipeline` again.
set -euo pipefail

repo=/opt/ops
compose_dir="$repo/deploy/ops-server"
sha="${SSH_ORIGINAL_COMMAND:-}"

if ! [[ "$sha" =~ ^[0-9a-f]{40}$ ]]; then
  echo "expected a full 40-character commit SHA" >&2
  exit 1
fi

# One deploy at a time; a second call waits instead of building next to the first.
exec 9>/run/ops-deploy.lock
flock -w 600 9 || { echo "another deploy is still running" >&2; exit 1; }

echo "== Fetching main"
git -C "$repo" fetch --quiet origin main
# Only commits that are on main may be deployed, even if the pipeline was started from another branch.
git -C "$repo" merge-base --is-ancestor "$sha" origin/main \
  || { echo "$sha is not part of origin/main" >&2; exit 1; }
git -C "$repo" checkout --quiet --force "$sha"

cd "$compose_dir"
# The ops-service is bound to the Tailscale IP only, so the check has to run here and not in the pipeline.
ts_ip="$(sed -n 's/^TAILSCALE_IP=//p' .env)"
[ -n "$ts_ip" ] || { echo "TAILSCALE_IP is missing in $compose_dir/.env" >&2; exit 1; }

# vmalert reads the alert webhook token from ./alert-token (a compose secret that is not in git). Stop before the
# build when it is missing, and say what to do; compose would only report a missing secret file.
if [ ! -f alert-token ]; then
  echo "deploy/ops-server/alert-token is missing: create it from ALERT_TOKEN in .env (CHANGELOG, Unreleased: upgrade notes)" >&2
  exit 1
fi
# After a rotation in .env the file keeps the old value, vmalert then sends it and every alert is answered with 401.
# Compose strips quotes and trailing comments from .env, sed does not: only a plain value can be compared and copied.
env_token="$(sed -n 's/^ALERT_TOKEN=//p' .env | head -n 1 | tr -d '\n')"
[[ "$env_token" =~ ^[A-Za-z0-9._~+/=-]*$ ]] \
  || { echo "ALERT_TOKEN in .env must be a plain value (no quotes, spaces or comment)" >&2; exit 1; }
# A token in ops-service.env is discarded: the environment: entry of compose.yml wins over env_file.
! grep -qE '^ALERT_TOKEN=.' ops-service.env 2>/dev/null \
  || echo "warning: ALERT_TOKEN in ops-service.env is ignored; set it in .env" >&2
if [ "$(sed -n 's/^ALERT_TOKEN=//p' .env | head -n 1 | tr -d '\n')" != "$(cat alert-token)" ]; then
  echo "deploy/ops-server/alert-token differs from ALERT_TOKEN in .env: write the same value to both" >&2
  exit 1
fi
grep -qE '^ALERT_TOKEN=.{32,}' .env || echo "warning: ALERT_TOKEN in .env is empty: the alert webhook accepts every caller in the tailnet" >&2

# Compose runs pikett:latest. Remember what it points to now, so a failed deploy can put it back.
previous="$(docker image inspect --format '{{.Id}}' pikett:latest 2>/dev/null || true)"

echo "== Building pikett:${sha:0:12}"
docker build --build-arg "SERVICE_VERSION=$sha" -t "pikett:${sha:0:12}" -t pikett:latest "$repo"

echo "== Starting the stack"
docker compose up -d --remove-orphans

for i in $(seq 1 75); do
  if curl -fsS -m 5 -o /dev/null "http://$ts_ip:8030/health"; then
    echo "Healthy (attempt $i)"
    # Unreferenced layers and old build cache pile up with every deploy; the ops server has a small disk.
    docker image prune -f >/dev/null
    docker builder prune -f --filter until=168h >/dev/null
    exit 0
  fi
  echo "Attempt $i: not healthy yet"
  sleep 2
done

echo "Deployment verification failed; last log lines of ops-service:" >&2
docker compose logs --tail 40 ops-service >&2 || true
if [ -n "$previous" ]; then
  echo "Rolling back to the previous image" >&2
  docker tag "$previous" pikett:latest
  docker compose up -d --remove-orphans >&2
fi
exit 1
