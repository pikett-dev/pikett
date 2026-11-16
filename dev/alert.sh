#!/usr/bin/env bash
# Sends a test alert to the ops-service (default: the local one), in the format vmalert uses.
#   OPS_URL=http://100.64.0.10:8030 dev/alert.sh fire P2   to test against the real server and Slack
#   dev/alert.sh fire [P1|P2|P3]   open an incident (default P1)
#   dev/alert.sh resolve [P1|P2|P3]
# The token of the webhook is ALERT_TOKEN from the environment; for the local stack (OPS_URL unset) it is read from
# dev/dev.env when the environment has none.
set -euo pipefail
action="${1:?usage: dev/alert.sh fire|resolve [P1|P2|P3]}"
severity="${2:-P1}"
now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
if [ "$action" = fire ]; then
  ends="$(date -u -v+1M +%Y-%m-%dT%H:%M:%SZ)"   # vmalert sets the end of a firing alert slightly in the future
else
  ends="$now"
fi
if [ -z "${ALERT_TOKEN:-}" ] && [ -z "${OPS_URL:-}" ] && [ -f "$(dirname "$0")/dev.env" ]; then
  ALERT_TOKEN="$(sed -n 's/^ALERT_TOKEN=//p' "$(dirname "$0")/dev.env" | head -n 1)"
fi
auth=()
[ -z "${ALERT_TOKEN:-}" ] || auth=(-H "Authorization: Bearer $ALERT_TOKEN")
curl -fsS -X POST "${OPS_URL:-http://localhost:8030}/api/v2/alerts" -H 'Content-Type: application/json' ${auth[@]+"${auth[@]}"} -d "[{
  \"labels\": {\"alertname\": \"TestAlert\", \"severity\": \"$severity\"},
  \"annotations\": {\"summary\": \"Test alert from dev/alert.sh\"},
  \"startsAt\": \"$now\", \"endsAt\": \"$ends\"}]"
echo
