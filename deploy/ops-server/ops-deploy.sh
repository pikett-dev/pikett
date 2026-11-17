#!/bin/bash
# Deploy wrapper for the ops server. Installed as /usr/local/bin/ops-deploy by `provision.sh pipeline`.
# The pipeline's SSH key may run only this script (authorized_keys: restrict,command="sudo /usr/local/bin/ops-deploy"),
# and what to deploy arrives as SSH_ORIGINAL_COMMAND: a release tag such as v1.2.3, or a full 40-character commit
# hash. It checks out that commit, builds the image and restarts the stack. Env files stay on the server (they are
# gitignored), so the pipeline never holds a secret.
# For an SSH URL, repository access (read-only key, host key of your Git host) is configured in /root/.ssh/config by
# `provision.sh pipeline`. A public HTTPS URL needs none.
# The server holds a copy of this file: after changing it, run `provision.sh pipeline` again.
set -euo pipefail

repo=/opt/ops
compose_dir="$repo/deploy/ops-server"
ref="${SSH_ORIGINAL_COMMAND:-}"

# --- resolve_ref: tested by tests/test_ops_deploy_ref.py, which extracts this block ---
ref_usage="expected a release tag such as v1.2.3 or a full 40-character commit hash"
# A release tag (v1.2.3) or a full commit hash. Nothing else of the SSH command may reach git.
valid_ref() { [[ "$1" =~ ^[0-9a-f]{40}$ || "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; }

# main and the release tags, as origin has them right now. The tags go into a namespace of their own (forced, and
# pruned): a tag that origin moved or deleted follows, and a tag created or left over in this checkout is never used.
fetch_refs() {
  git -C "$repo" fetch --quiet --prune origin main '+refs/tags/*:refs/remotes/origin/tags/*'
}

# What was asked for as a commit that is on main of origin.
resolve_ref() {
  local ref="$1" sha="$1"
  valid_ref "$ref" || { echo "$ref_usage" >&2; return 1; }
  if [[ "$ref" == v* ]]; then
    sha="$(git -C "$repo" rev-parse --verify --quiet "refs/remotes/origin/tags/$ref^{commit}")" \
      || { echo "tag $ref does not exist in origin" >&2; return 1; }
  fi
  # Only commits that are on main may be deployed, whatever the tag or hash points to.
  git -C "$repo" merge-base --is-ancestor "$sha" origin/main \
    || { echo "$ref ($sha) is not part of origin/main" >&2; return 1; }
  printf '%s\n' "$sha"
}
# --- end resolve_ref ---

# Refuse nonsense before waiting for the lock.
valid_ref "$ref" || { echo "$ref_usage" >&2; exit 1; }

# One deploy at a time; a second call waits instead of building next to the first.
exec 9>/run/ops-deploy.lock
flock -w 600 9 || { echo "another deploy is still running" >&2; exit 1; }

echo "== Fetching main and the tags"
fetch_refs
sha="$(resolve_ref "$ref")"
echo "== Deploying $ref ($sha)"
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
