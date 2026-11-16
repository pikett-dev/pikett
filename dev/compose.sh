#!/usr/bin/env bash
# Runs ops on this machine in Docker (compose project pikett-stack).
#   dev/compose.sh up -d --build     start
#   dev/compose.sh down -v           stop and delete the data
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
[ -f "$root/dev/dev.env" ] || cp "$root/dev/dev.env.example" "$root/dev/dev.env"
[ -f "$root/dev/ops-service.env" ] || cp "$root/dev/ops-service.env.example" "$root/dev/ops-service.env"
cd "$root/deploy/ops-server"
# vmalert reads the webhook token from a file (a git-ignored file next to compose.yml), written from dev.env.
token="$(sed -n 's/^ALERT_TOKEN=//p' ../../dev/dev.env | head -n 1)"
[ -z "$token" ] || { umask 077; printf '%s' "$token" > alert-token; }
[ -f alert-token ] || : > alert-token   # compose refuses to start when the secret file is missing
exec docker compose -f compose.yml -f compose.dev.yml --env-file ../../dev/dev.env "$@"
