#!/usr/bin/env bash
# Installs and checks the Alloy agent on the test server. You run it from your own machine:
#
#   agent.sh deploy   copies deploy/app-host to /opt/ops-agent on the test server and starts Alloy
#   agent.sh status   container state, Alloy log, and whether metrics arrive at the ops server
#
# Needs: ssh access to the test server over Tailscale, rsync. Set DRY_RUN=1 to print instead of run.
#
# ALLOY_LOCAL_DIR=<folder> (for example ../acme-ops/alloy) adds your own Alloy files to `deploy`: the folder may hold
# only files named local-*.alloy; they are copied next to config.alloy, and a local-*.alloy that is gone from the
# folder is removed from the server. Without the variable the server keeps what it has. Secrets for these files
# belong in /opt/ops-agent/secrets.env on the server (mode 600), which this script never writes or deletes.
set -Eeuo pipefail
trap 'echo "error: step failed (line $LINENO): $BASH_COMMAND" >&2' ERR

TEST_HOST="${TEST_HOST:-app-1}"
TEST_SSH_KEY="${TEST_SSH_KEY:-$HOME/.ssh/app_server}"
HOST_NAME="${HOST_NAME:-app-1}"
OPS_HOST="${OPS_HOST:-ops-server}"
DRY_RUN="${DRY_RUN:-0}"
ALLOY_LOCAL_DIR="${ALLOY_LOCAL_DIR:-}"

here="$(cd "$(dirname "$0")" && pwd)"
ssh_opts=(-i "$TEST_SSH_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10)

run() { if [ "$DRY_RUN" = 1 ]; then echo "+ $*"; else "$@"; fi; }
say() { printf '\n== %s\n' "$*"; }
die() { echo "error: $*" >&2; exit 1; }

ops_ip() {
  if [ -n "${OPS_SERVER:-}" ]; then echo "$OPS_SERVER"; return; fi
  tailscale ip -4 "$OPS_HOST" 2>/dev/null | head -1 || true
}

# The checks ask the ops server from the app server, not from your machine: with the tailnet policy of
# deploy/tailscale-acl.example.hujson only the app servers reach the telemetry ports, and this is the path Alloy uses.
from_app() { ssh "${ssh_opts[@]}" "root@$TEST_HOST" "curl -fsS -m 10 $(printf '%q ' "$@")"; }

# ALLOY_LOCAL_DIR must hold local-*.alloy files and nothing else: another name would be silently left behind on the
# server (the copy and its --delete only touch local-*.alloy).
check_local_dir() {
  [ -d "$ALLOY_LOCAL_DIR" ] || die "ALLOY_LOCAL_DIR=$ALLOY_LOCAL_DIR is not a directory"
  local bad
  bad="$(find "$ALLOY_LOCAL_DIR" -mindepth 1 -maxdepth 1 \( ! -name 'local-*.alloy' -o ! -type f \) -print -quit)"
  [ -z "$bad" ] || die "$bad: ALLOY_LOCAL_DIR may only hold plain files named local-*.alloy"
}

cmd_deploy() {
  [ -z "$ALLOY_LOCAL_DIR" ] || check_local_dir
  ip="$(ops_ip)"
  [ -n "$ip" ] || die "cannot find the Tailscale address of $OPS_HOST (set OPS_SERVER=...)"
  say "Copying the agent to root@$TEST_HOST:/opt/ops-agent (ops server at $ip)"
  run ssh "${ssh_opts[@]}" "root@$TEST_HOST" mkdir -p /opt/ops-agent
  run rsync -az -e "ssh ${ssh_opts[*]}" --exclude "*.env" "$here/" "root@$TEST_HOST:/opt/ops-agent/"
  if [ -n "$ALLOY_LOCAL_DIR" ]; then
    say "Copying the local Alloy files from $ALLOY_LOCAL_DIR"
    run rsync -az --delete -e "ssh ${ssh_opts[*]}" --include 'local-*.alloy' --exclude '*' "${ALLOY_LOCAL_DIR%/}/" "root@$TEST_HOST:/opt/ops-agent/alloy/"
  fi
  if [ "$DRY_RUN" = 1 ]; then
    echo "+ write /opt/ops-agent/.env (OPS_SERVER=$ip, HOST_NAME=$HOST_NAME)"
  else
    printf 'OPS_SERVER=%s\nHOST_NAME=%s\n' "$ip" "$HOST_NAME" | ssh "${ssh_opts[@]}" "root@$TEST_HOST" 'umask 077; cat > /opt/ops-agent/.env'
  fi
  say "Checking the mode of secrets.env"
  run ssh "${ssh_opts[@]}" "root@$TEST_HOST" 'f=/opt/ops-agent/secrets.env; [ ! -e "$f" ] || [ "$(stat -c %a "$f")" = 600 ] || echo "warning: $f has mode $(stat -c %a "$f"), expected 600" >&2'
  say "Starting Alloy"
  run ssh "${ssh_opts[@]}" "root@$TEST_HOST" 'cd /opt/ops-agent && docker compose up -d --force-recreate'  # a changed config file alone would not restart Alloy
  say "Done. Check with: $0 status"
}

cmd_status() {
  say "Alloy on $TEST_HOST"
  run ssh "${ssh_opts[@]}" "root@$TEST_HOST" 'cd /opt/ops-agent && docker compose ps && docker compose logs --tail 25 alloy 2>&1 | grep -iE "level=(error|warn)" | cut -c1-220 || true'
  ip="$(ops_ip)"
  say "Data that arrived at the ops server ($ip) from host $HOST_NAME"
  if [ "$DRY_RUN" = 1 ]; then echo "+ (on $TEST_HOST) curl http://$ip:8428/api/v1/query?query=count(node_uname_info{host=\"$HOST_NAME\"})"; return; fi
  count="$(from_app -G "http://$ip:8428/api/v1/query" --data-urlencode "query=count(node_uname_info{host=\"$HOST_NAME\"})" \
    | python3 -c 'import json,sys; r=json.load(sys.stdin)["data"]["result"]; print(r[0]["value"][1] if r else 0)')"
  echo "host metrics series: $count (1 means the agent delivers)"
  containers="$(from_app -G "http://$ip:8428/api/v1/query" --data-urlencode "query=count(count by (name) (container_last_seen{host=\"$HOST_NAME\",name!=\"\"}))" \
    | python3 -c 'import json,sys; r=json.load(sys.stdin)["data"]["result"]; print(r[0]["value"][1] if r else 0)')"
  echo "containers seen by cAdvisor: $containers (different names; should match the running containers, 0 means ContainerGone cannot fire)"
  logs="$(from_app "http://$ip:9428/select/logsql/query" -d "query=host:$HOST_NAME" -d "limit=1" | wc -l | tr -d ' ')"
  echo "log lines found: $logs (1 or more means logs arrive)"
}

case "${1:-}" in
  deploy) cmd_deploy ;;
  status) cmd_status ;;
  *) sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
