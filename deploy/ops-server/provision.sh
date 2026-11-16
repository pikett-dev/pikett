#!/usr/bin/env bash
# Creates the ops server at Hetzner and brings the stack up. You run it, step by step, from your own machine:
#
#   provision.sh create     firewall and server (costs money, asks first)
#   provision.sh join       installs Tailscale on the server and joins your tailnet
#   provision.sh deploy     copies the repo and the two env files, builds the image, starts the stack (manual path)
#   provision.sh pipeline   one-time setup so the Bitbucket pipeline can deploy (needs OPS_DEPLOY_PUBKEY)
#   provision.sh lockdown   closes public SSH once Tailscale SSH works
#   provision.sh status     server, Tailscale address and a health check
#
# Needs: hcloud (brew install hcloud) with an active context for a Hetzner project of its own, ssh, rsync, python3.
# Set DRY_RUN=1 to print every command that talks to Hetzner or the server instead of running it.
# create asks before ordering; without a terminal, confirm with OPS_CONFIRM=yes in front of the command.
set -Eeuo pipefail
# Never fail silently: say which command stopped the script.
trap 'echo "error: step failed (line $LINENO): $BASH_COMMAND" >&2' ERR

NAME="${OPS_NAME:-ops-server}"
TYPE="${OPS_TYPE:-cpx22}"
LOCATION="${OPS_LOCATION:-hel1}"
IMAGE="${OPS_IMAGE_OS:-ubuntu-24.04}"
SSH_KEY_NAME="${OPS_SSH_KEY_NAME:-ops-server}"
SSH_PUBKEY="${OPS_SSH_PUBKEY:-$HOME/.ssh/ops-server.pub}"
TS_TAGS="${TS_TAGS:-tag:pikett-ops}"
DRY_RUN="${DRY_RUN:-0}"

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
# Always use the key that was uploaded to Hetzner, not whichever key the agent offers first.
ssh_opts=(-i "${SSH_PUBKEY%.pub}" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10)

run() {  # prints in dry-run mode, runs otherwise
  if [ "$DRY_RUN" = 1 ]; then echo "+ $*"; else "$@"; fi
}
say() { printf '\n== %s\n' "$*"; }
die() { echo "error: $*" >&2; exit 1; }

need() { command -v "$1" >/dev/null || die "$1 is not installed"; }

server_ip() {  # public IPv4 of the server
  if [ "$DRY_RUN" = 1 ]; then echo "<public-ip>"; else hcloud server ip "$NAME"; fi
}

tailscale_ip() {
  [ "$DRY_RUN" = 1 ] && { echo "<tailscale-ip>"; return; }
  ssh "${ssh_opts[@]}" "root@$(server_ip)" tailscale ip -4 2>/dev/null \
    || ssh "${ssh_opts[@]}" "root@$NAME" tailscale ip -4
}

# After lockdown only the Tailscale path works, so prefer it when the server resolves on the tailnet.
ssh_target() {
  if [ "$DRY_RUN" != 1 ] && ssh "${ssh_opts[@]}" -o BatchMode=yes "root@$NAME" true 2>/dev/null; then
    echo "root@$NAME"
  else
    echo "root@$(server_ip)"
  fi
}

cmd_create() {
  [ "$DRY_RUN" = 1 ] || { need hcloud; hcloud server list >/dev/null || die "no active hcloud context (hcloud context create <project>)"; }
  [ -f "$SSH_PUBKEY" ] || die "public key $SSH_PUBKEY not found (set OPS_SSH_PUBKEY)"

  say "About to create: server $NAME, type $TYPE, location $LOCATION, image $IMAGE"
  echo "Check the current price of $TYPE in the Hetzner console first. Delete protection will be switched on."
  if [ "$DRY_RUN" != 1 ] && [ "${OPS_CONFIRM:-}" != yes ]; then
    # Without a terminal (a "!" command in Claude Code, a pipeline) there is nobody to ask: confirm on the command line.
    [ -t 0 ] || die "no terminal to ask in. If the price is fine, run: OPS_CONFIRM=yes $0 create"
    read -r -p "Continue? [y/N] " answer || die "aborted"
    [ "$answer" = y ] || die "aborted"
  fi

  if [ "$DRY_RUN" = 1 ] || ! hcloud ssh-key describe "$SSH_KEY_NAME" >/dev/null 2>&1; then
    run hcloud ssh-key create --name "$SSH_KEY_NAME" --public-key-from-file "$SSH_PUBKEY"
  fi
  if [ "$DRY_RUN" = 1 ] || ! hcloud firewall describe "$NAME" >/dev/null 2>&1; then
    run hcloud firewall create --name "$NAME"
    run hcloud firewall replace-rules --rules-file "$here/firewall.json" "$NAME"
  fi
  if [ "$DRY_RUN" = 1 ] || ! hcloud server describe "$NAME" >/dev/null 2>&1; then
    run hcloud server create --name "$NAME" --type "$TYPE" --image "$IMAGE" --location "$LOCATION" \
      --ssh-key "$SSH_KEY_NAME" --firewall "$NAME" --without-ipv6 --enable-protection delete,rebuild \
      --label role=ops --user-data-from-file "$here/cloud-init.yaml"
  fi
  say "Server is up at $(server_ip). Next: TS_AUTHKEY=tskey-... $0 join"
}

cmd_join() {
  : "${TS_AUTHKEY:?set TS_AUTHKEY to a single-use Tailscale auth key allowed for $TS_TAGS}"
  ip="$(server_ip)"
  say "Waiting for the server to finish its first boot"
  run ssh "${ssh_opts[@]}" "root@$ip" cloud-init status --wait
  say "Installing Tailscale and joining the tailnet as $NAME"
  run ssh "${ssh_opts[@]}" "root@$ip" 'command -v tailscale >/dev/null || curl -fsSL https://tailscale.com/install.sh | sh'
  # The key travels over stdin, not on the local command line.
  if [ "$DRY_RUN" = 1 ]; then
    echo "+ (auth key via stdin) ssh root@$ip tailscale up --hostname=$NAME --advertise-tags=$TS_TAGS"
  else
    # Keep the output so a failure can be shown (with the key masked).
    if ! out="$(printf '%s\n' "$TS_AUTHKEY" | ssh "${ssh_opts[@]}" "root@$ip" \
      "read -r key && tailscale up --auth-key=\"\$key\" --hostname=$NAME --advertise-tags=$TS_TAGS" 2>&1)"; then
      echo "$out" | sed -E 's/tskey-[A-Za-z0-9-]+/tskey-***/g' >&2
      die "tailscale up failed (see the message above)"
    fi
    [ -z "$out" ] || echo "$out" | sed -E 's/tskey-[A-Za-z0-9-]+/tskey-***/g'
  fi
  ts_ip="$(tailscale_ip)"
  [ -n "$ts_ip" ] || die "the server did not get a Tailscale address"
  say "Tailscale address: $ts_ip. Next: $0 deploy"
}

check_env_files() {
  for f in .env ops-service.env; do
    [ -f "$here/$f" ] || die "$here/$f is missing (copy the .example file and fill it in)"
  done
  for var in OPS_DB_PASSWORD KUMA_DB_PASSWORD KUMA_DB_ROOT_PASSWORD; do
    if ! grep -qE "^${var}=." "$here/.env" || grep -qE "^${var}=change-me$" "$here/.env"; then die "set $var in .env"; fi
  done
  grep -qE '^ALERT_TOKEN=([A-Za-z0-9._~+/=-]*)$' "$here/.env" \
    || die "ALERT_TOKEN in .env must be a plain value (no quotes, spaces or comment): compose and alert-token would read it differently"
  grep -qE "^ALERT_TOKEN=.{32,}" "$here/.env" \
    || echo "warning: ALERT_TOKEN in .env is empty or shorter than 32 characters: the alert webhook stays open to the tailnet (openssl rand -hex 32)" >&2
}

# Manual path, e.g. while Bitbucket is down. It overwrites the working tree from this machine; the next pipeline run
# checks out the pushed commit again.
cmd_deploy() {
  [ "$DRY_RUN" = 1 ] || check_env_files
  target="$(ssh_target)"
  ts_ip="$(tailscale_ip)"
  say "Copying the repo to $target:/opt/ops"
  # --no-owner/--no-group: the receiving user (root) owns the files; with the uid of this machine git refuses to
  # work in /opt/ops.
  run rsync -az --delete --no-owner --no-group -e "ssh ${ssh_opts[*]}" \
    --exclude .git --exclude .venv --exclude __pycache__ --exclude '.*_cache' \
    --exclude deploy/ops-server/.env --exclude deploy/ops-server/ops-service.env --exclude dev/ops-service.env \
    --exclude deploy/ops-server/alert-token \
    "$repo/" "$target:/opt/ops/"
  say "Writing the env files (TAILSCALE_IP=$ts_ip, image built on the server)"
  if [ "$DRY_RUN" = 1 ]; then
    echo "+ scp .env, ops-service.env and alert-token to /opt/ops/deploy/ops-server (mode 600, TAILSCALE_IP and BASE_URL set)"
  else
    sed -e "s|^TAILSCALE_IP=.*|TAILSCALE_IP=$ts_ip|" -e "s|^OPS_IMAGE=.*|OPS_IMAGE=pikett:latest|" \
      "$here/.env" | ssh "${ssh_opts[@]}" "$target" 'umask 077; cat > /opt/ops/deploy/ops-server/.env'
    sed -e "s|^BASE_URL=.*|BASE_URL=http://$ts_ip:8030|" "$here/ops-service.env" \
      | ssh "${ssh_opts[@]}" "$target" 'umask 077; cat > /opt/ops/deploy/ops-server/ops-service.env'
    # vmalert reads the webhook token from this file (compose secret); the service gets ALERT_TOKEN from .env. An
    # empty file is fine when ALERT_TOKEN is empty (no token required), but compose refuses to start without it.
    sed -n 's/^ALERT_TOKEN=//p' "$here/.env" | head -n 1 | tr -d '\n' \
      | ssh "${ssh_opts[@]}" "$target" 'umask 077; cat > /opt/ops/deploy/ops-server/alert-token'
  fi
  say "Building the image and starting the stack"
  run ssh "${ssh_opts[@]}" "$target" 'docker build -t pikett:latest /opt/ops && cd /opt/ops/deploy/ops-server && docker compose up -d --remove-orphans'
  say "Done. Check with: $0 status"
}

# One-time setup of the pipeline deploy: the deploy user, its sudoers rule, the wrapper, the restricted key and the
# repository access. Safe to run again: it replaces the wrapper, the sudoers rule and the key, and keeps the repository
# key. Run it again after every change to ops-deploy.sh, because the server holds a copy.
cmd_pipeline() {
  pubkey="${OPS_DEPLOY_PUBKEY:-}"
  [ -n "$pubkey" ] || die "set OPS_DEPLOY_PUBKEY to the public key shown under Repository settings > Pipelines > SSH keys"
  case "$pubkey" in ssh-*|ecdsa-*) ;; *) die "OPS_DEPLOY_PUBKEY does not look like a public key" ;; esac
  # No default: a default would point a new server at somebody else's repository.
  repo_url="${OPS_REPO_URL:-}"
  [ -n "$repo_url" ] || die "set OPS_REPO_URL to the SSH URL of your clone of Pikett, for example
  OPS_REPO_URL=git@github.com:pikett-dev/pikett.git $0 pipeline"
  # SSH only (the server fetches with a read-only deploy key; an https URL would ask for a password):
  # ssh://[user@]host[:port]/path or user@host:path, no spaces or quotes. The host is captured here, so the value that
  # goes into the remote command below can only hold letters, digits, dots and dashes.
  url_re="^(ssh://([^@/[:space:]]+@)?([A-Za-z0-9.-]+)(:[0-9]+)?/|[^@/:[:space:]]+@([A-Za-z0-9.-]+):)[^[:space:]\"']+\$"
  [[ "$repo_url" =~ $url_re ]] || die "OPS_REPO_URL must be an SSH URL without spaces, for example git@github.com:pikett-dev/pikett.git"
  repo_host="${BASH_REMATCH[3]:-${BASH_REMATCH[5]}}"
  target="$(ssh_target)"

  say "Installing the deploy wrapper, the sudoers rule and the restricted key on $target"
  if [ "$DRY_RUN" = 1 ]; then
    echo "+ scp ops-deploy.sh to /usr/local/bin/ops-deploy (0755), write /etc/sudoers.d/ops-deploy, add key to ~deploy/.ssh/authorized_keys"
  else
    ssh "${ssh_opts[@]}" "$target" 'cat > /usr/local/bin/ops-deploy && chmod 755 /usr/local/bin/ops-deploy' < "$here/ops-deploy.sh"
    printf '%s\n' "$pubkey" | ssh "${ssh_opts[@]}" "$target" '
      set -e
      command -v git >/dev/null || apt-get install -y git
      id deploy >/dev/null 2>&1 || useradd --create-home --shell /bin/bash deploy
      passwd -l deploy >/dev/null
      printf "%s\n" "Defaults:deploy env_keep += \"SSH_ORIGINAL_COMMAND\"" "deploy ALL=(root) NOPASSWD: /usr/local/bin/ops-deploy" > /etc/sudoers.d/ops-deploy
      chmod 440 /etc/sudoers.d/ops-deploy
      visudo -cf /etc/sudoers.d/ops-deploy
      install -d -m 700 -o deploy -g deploy /home/deploy/.ssh
      read -r key
      printf "restrict,command=\"sudo /usr/local/bin/ops-deploy\" %s\n" "$key" > /home/deploy/.ssh/authorized_keys
      chown deploy:deploy /home/deploy/.ssh/authorized_keys
      chmod 600 /home/deploy/.ssh/authorized_keys'
  fi

  say "Preparing the read-only repository key and the host key of $repo_host"
  run ssh "${ssh_opts[@]}" "$target" "repo_host='$repo_host'"'
    set -e
    install -d -m 700 /root/.ssh
    [ -f /root/.ssh/ops-repo ] || ssh-keygen -q -t ed25519 -N "" -C ops-server-readonly -f /root/.ssh/ops-repo
    ssh-keyscan -t ed25519 "$repo_host" 2>/dev/null > /root/.ssh/known_hosts_repo
    ssh-keygen -lf /root/.ssh/known_hosts_repo
    # One definition of how root reaches the repository; ops-deploy.sh and the fetch below rely on it.
    printf "%s\n" "Host $repo_host" "  IdentityFile /root/.ssh/ops-repo" "  IdentitiesOnly yes" \
      "  StrictHostKeyChecking yes" "  UserKnownHostsFile /root/.ssh/known_hosts_repo" > /root/.ssh/config
    chmod 600 /root/.ssh/config'

  say "Turning /opt/ops into a git checkout of $repo_url (env files stay)"
  run ssh "${ssh_opts[@]}" "$target" "
    set -e
    # One-time repair: a server filled by an older provision.sh deploy holds files owned by the uid of the sender,
    # and git refuses to work in such a directory.
    chown -R root:root /opt/ops
    cd /opt/ops
    [ -d .git ] || git init -q -b main
    git remote remove origin 2>/dev/null || true
    git remote add origin '$repo_url'"
  say "SSH host key of the server for the pipeline variable OPS_SERVER_HOST_KEY (known_hosts line; the pipeline replaces the name with OPS_SERVER_HOST):"
  run ssh "${ssh_opts[@]}" "$target" 'echo "ops-server $(cut -d" " -f1,2 /etc/ssh/ssh_host_ed25519_key.pub)"'

  # On a repeated run the access key is registered at the Git host already; then there is nothing to wait for.
  if [ "$DRY_RUN" != 1 ] && ssh -n "${ssh_opts[@]}" "$target" 'cd /opt/ops && git fetch -q origin main' 2>/dev/null; then
    say "Repository access works already"
    return
  fi
  say "The first fetch needs the access key at your Git host. Public key of the server:"
  run ssh "${ssh_opts[@]}" "$target" 'cat /root/.ssh/ops-repo.pub'
  echo "Add it as a read-only deploy key of the repository (Bitbucket: Repository settings > Access keys, GitHub:"
  echo "Settings > Deploy keys), compare the host key fingerprint above with the one your Git host publishes, then"
  echo "press Enter to test the fetch."
  if [ "$DRY_RUN" != 1 ]; then
    read -r _
    ssh "${ssh_opts[@]}" "$target" "
      set -e
      cd /opt/ops
      git fetch origin main
      git reset -q origin/main"
  fi
}

cmd_lockdown() {
  say "Checking that SSH over Tailscale works before closing public SSH"
  if [ "$DRY_RUN" != 1 ]; then
    ssh "${ssh_opts[@]}" -o BatchMode=yes "root@$NAME" true || die "cannot reach root@$NAME over Tailscale; not closing SSH"
  fi
  rules="$(mktemp)"
  python3 - "$here/firewall.json" "$rules" <<'PY'
import json, sys
src, dst = sys.argv[1:]
rules = [r for r in json.load(open(src)) if str(r.get("port")) != "22"]
json.dump(rules, open(dst, "w"), indent=2)
PY
  run hcloud firewall replace-rules --rules-file "$rules" "$NAME"
  rm -f "$rules"
  say "Public SSH is closed. Reach the server with: ssh root@$NAME"
}

cmd_status() {
  run hcloud server describe "$NAME"
  ts_ip="$(tailscale_ip)"
  say "Health of the ops-service at $ts_ip"
  run curl -fsS "http://$ts_ip:8030/health"
  echo
}

case "${1:-}" in
  create) cmd_create ;;
  join) cmd_join ;;
  deploy) cmd_deploy ;;
  pipeline) cmd_pipeline ;;
  lockdown) cmd_lockdown ;;
  status) cmd_status ;;
  *) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 1 ;;
esac
