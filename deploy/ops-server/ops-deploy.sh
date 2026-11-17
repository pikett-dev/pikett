#!/bin/bash
# Deploy wrapper for the ops server. Installed as /usr/local/bin/ops-deploy by `provision.sh pipeline`.
# The pipeline's SSH key may run only this script (authorized_keys: restrict,command="sudo /usr/local/bin/ops-deploy"),
# and what to deploy arrives as SSH_ORIGINAL_COMMAND: a release tag such as v1.2.3, or a full 40-character commit
# hash, optionally followed by the word "rules" (`v1.2.3 rules`). With "rules" a tar of *.yml files arrives on stdin
# and replaces deploy/vmalert/rules.local/ (the installation's own alert rules). It checks out that commit, builds the
# image and restarts the stack. Env files stay on the server (they are gitignored), so the pipeline never holds a
# secret.
# For an SSH URL, repository access (read-only key, host key of your Git host) is configured in /root/.ssh/config by
# `provision.sh pipeline`. A public HTTPS URL needs none.
# The server holds a copy of this file: after changing it, run `provision.sh pipeline` again.
set -euo pipefail

repo=/opt/ops
compose_dir="$repo/deploy/ops-server"
vmalert_dir="$repo/deploy/vmalert"

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

# --- rules: tested by tests/test_ops_deploy_rules.py, which extracts this block ---
rules_max_bytes=1048576
rules_max_files=100

# The SSH command is "<ref>" or "<ref> rules". Sets ref and with_rules; valid_ref refuses everything else.
parse_command() {
  ref="$1"
  with_rules=0
  if [[ "$ref" == *" rules" ]]; then
    ref="${ref% rules}"
    with_rules=1
  fi
}

# Reads a tar from stdin into the empty directory $1. Only plain *.yml files at the top level are accepted, at most
# 1 MiB and 100 entries; links, devices, sparse files, directories other than "./", compressed archives and every path
# with a slash or ".." are refused, and no unpacked file may exceed 1 MiB. An empty stream is refused too: a client
# that sends the word "rules" always sends at least "./", so nothing at all means its tar failed, and that must not
# delete the installation's rules.
receive_rules() {
  local dest="$1" raw="$1.raw" names types name type size count
  head -c $((rules_max_bytes + 1)) > "$raw"  # the caller's trap removes it with the staging directory
  size="$(wc -c < "$raw")"
  if [ "$size" -gt "$rules_max_bytes" ]; then
    echo "the rules tar is larger than $rules_max_bytes bytes" >&2; return 1
  fi
  [ "$size" -gt 0 ] || { echo "the rules tar is empty (the client's tar probably failed); nothing was changed" >&2; return 1; }
  # Only an uncompressed tar: tar would unpack gzip or xz by itself, and 1 MiB of them can hold gigabytes.
  [ "$(dd if="$raw" bs=1 skip=257 count=5 2>/dev/null)" = ustar ] || { echo "the rules tar must be an uncompressed tar" >&2; return 1; }
  names="$(tar -tf "$raw" 2>/dev/null)" || { echo "the rules tar cannot be read" >&2; return 1; }
  [ -n "$names" ] || { echo "the rules tar has no entries" >&2; return 1; }
  types="$(tar -tvf "$raw" 2>/dev/null | cut -c1)"
  count="$(printf '%s\n' "$names" | wc -l)"
  [ "$count" = "$(printf '%s\n' "$types" | wc -l)" ] || { echo "the rules tar cannot be listed" >&2; return 1; }
  if [ "$count" -gt "$rules_max_files" ]; then
    echo "the rules tar has more than $rules_max_files entries" >&2; return 1
  fi
  while IFS= read -r name <&3 && IFS= read -r type <&4; do
    if [[ "$name" == "./" || "$name" == "." ]]; then
      [ "$type" = d ] || { echo "unexpected entry type for $name" >&2; return 1; }
    elif [[ ! "$name" =~ ^(\./)?[A-Za-z0-9][A-Za-z0-9._-]*\.yml$ || "$type" != - ]]; then
      echo "the rules tar may only hold plain *.yml files at the top level, not: $name" >&2; return 1
    fi
  done 3<<<"$names" 4<<<"$types"
  # ulimit -f: a file larger than 1 MiB (also a sparse one) makes tar fail instead of filling the disk.
  (ulimit -f $((rules_max_bytes / 1024)); tar -xf "$raw" -C "$dest" --no-same-owner --no-same-permissions) || { echo "the rules tar cannot be unpacked" >&2; return 1; }
  # Belt and braces: whatever the listing said, only regular *.yml files may be there.
  if [ -n "$(find "$dest" -mindepth 1 \( ! -type f -o ! -name '*.yml' \) -print -quit)" ]; then
    echo "the rules tar unpacked to something other than *.yml files" >&2; return 1
  fi
}

# The rules as vmalert will load them: the shipped ones of commit $1, replaced by name with the files of $2.
# The shipped ones come from the commit and not from the working tree, so the check happens before the checkout.
build_candidate() {
  local sha="$1" local_dir="$2" cand="$3"
  git -C "$repo" archive "$sha" deploy/vmalert/rules | tar -x -C "$cand" --strip-components=3
  if [ -d "$local_dir" ] && compgen -G "$local_dir/*.yml" >/dev/null; then cp "$local_dir"/*.yml "$cand"/; fi
}

# The vmalert image that compose.yml of commit $1 pins.
vmalert_image() {
  git -C "$repo" show "$1:deploy/ops-server/compose.yml" \
    | sed -n 's|^ *image: *\(victoriametrics/vmalert:[^ ]*\).*|\1|p' | head -n 1
}

# vmalert's own check of a rules directory; the shipped files are always there, so the glob is never empty.
rules_check() {
  local dir="$1" image="$2"
  docker run --rm --network none -v "$dir:/check:ro" "$image" -dryRun -rule='/check/*.yml' >/dev/null
}

# Makes directory $2 hold the *.yml files of $1. The directory is changed in place (a bind mount follows the inode,
# so replacing the directory would leave vmalert looking at the old one); each file arrives by rename, so vmalert
# never reads half a file.
sync_rules() {
  local src="$1" dst="$2" f
  mkdir -p "$dst"
  shopt -s nullglob
  for f in "$src"/*.yml; do
    cmp -s "$f" "$dst/${f##*/}" && continue  # unchanged: leave it alone
    cp "$f" "$dst/.${f##*/}.tmp" && mv -f "$dst/.${f##*/}.tmp" "$dst/${f##*/}"
  done
  for f in "$dst"/*.yml; do
    [ -e "$src/${f##*/}" ] || rm -f "$f"
  done
  shopt -u nullglob
}
# --- end rules ---

# Refuse nonsense before waiting for the lock.
parse_command "${SSH_ORIGINAL_COMMAND:-}"
valid_ref "$ref" || { echo "$ref_usage" >&2; exit 1; }
rules_local="$vmalert_dir/rules.local"
rules_live="$vmalert_dir/rules.live"

# Staging area for the new rules, next to the repository files so that it is on the same file system.
stage="$(mktemp -d "$vmalert_dir.stage.XXXXXX")"
trap 'rm -rf "$stage"' EXIT
if [ "$with_rules" = 1 ]; then
  mkdir "$stage/new"
  receive_rules "$stage/new" || exit 1
  rules_local_src="$stage/new"
else
  rules_local_src="$rules_local"
fi

# One deploy at a time; a second call waits instead of building next to the first.
exec 9>/run/ops-deploy.lock
flock -w 600 9 || { echo "another deploy is still running" >&2; exit 1; }

echo "== Fetching main and the tags"
fetch_refs
sha="$(resolve_ref "$ref")"

# Check the rules of the target release together with the installation's own ones before anything on the server
# changes. A rule that vmalert refuses stops the deploy here: no checkout, no build, no restart.
echo "== Checking the alert rules"
mkdir "$stage/cand"
build_candidate "$sha" "$rules_local_src" "$stage/cand"
image="$(vmalert_image "$sha")"
[ -n "$image" ] || { echo "no vmalert image found in compose.yml of $ref" >&2; exit 1; }
docker image inspect "$image" >/dev/null 2>&1 || docker pull -q "$image" >/dev/null \
  || { echo "cannot pull $image to check the alert rules; nothing was changed" >&2; exit 1; }
rules_check "$stage/cand" "$image" || { echo "vmalert refuses the alert rules (run vmalert -dryRun on them); nothing was changed" >&2; exit 1; }

echo "== Deploying $ref ($sha)"
git -C "$repo" checkout --quiet --force "$sha"
if [ "$with_rules" = 1 ]; then sync_rules "$stage/new" "$rules_local"; fi
sync_rules "$stage/cand" "$rules_live"

cd "$compose_dir"
# The ops-service is bound to the Tailscale IP only, so the check has to run here and not in the pipeline.
ts_ip="$(sed -n 's/^TAILSCALE_IP=//p' .env)"
[ -n "$ts_ip" ] || { echo "TAILSCALE_IP is missing in $compose_dir/.env" >&2; exit 1; }

# vmalert reads the alert webhook token from ./alert-token (a compose secret that is not in git). Stop before the
# build when it is missing, and say what to do; compose would only report a missing secret file.
if [ ! -f alert-token ]; then
  echo "deploy/ops-server/alert-token is missing: create it from ALERT_TOKEN in .env (see the upgrade notes in CHANGELOG.md, 0.2.0)" >&2
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
