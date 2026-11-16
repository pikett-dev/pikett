#!/usr/bin/env bash
# Sends a priority 5 test push to one person's ntfy topic, read from deploy/ops-server/ops-service.env.
# The topic is never printed.
#   dev/ntfy-test.sh 0      first person in ONCALL_PEOPLE
#   dev/ntfy-test.sh 1      second person
#   dev/ntfy-test.sh 0 poll lists the messages ntfy still holds for that topic (to tell server from phone problems)
set -euo pipefail
index="${1:?usage: dev/ntfy-test.sh <0|1> [poll]}"
mode="${2:-send}"
file="$(cd "$(dirname "$0")/.." && pwd)/deploy/ops-server/ops-service.env"
payload="$(python3 - "$file" "$index" <<'PY'
import json, sys
values = {}
for line in open(sys.argv[1]):
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        key, _, value = line.partition("=")
        values[key] = value
person = json.loads(values["ONCALL_PEOPLE"])[int(sys.argv[2])]
print(json.dumps({
    "url": values.get("NTFY_URL", "https://ntfy.sh").rstrip("/"),
    "topic": person["ntfy_topic"],
    "body": {
        "topic": person["ntfy_topic"],
        "title": "Test from Pikett",
        "message": f"If you read this, the wake-up call reaches you, {person['name']}.",
        "priority": 5,
        "tags": ["rotating_light"],
    },
}))
PY
)"
url="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["url"])' <<<"$payload")"
body="$(python3 -c 'import json,sys; print(json.dumps(json.loads(sys.stdin.read())["body"]))' <<<"$payload")"
if [ "$mode" = poll ]; then
  topic="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["topic"])' <<<"$payload")"
  POLL_DATA="$(curl -sS "$url/$topic/json?poll=1&since=all")" python3 - <<'PY'
import datetime, json, os
rows = [json.loads(line) for line in os.environ["POLL_DATA"].splitlines() if line.strip()]
messages = [row for row in rows if row.get("event") == "message"]
print(f"ntfy holds {len(messages)} message(s) for this topic")
for m in messages[-5:]:
    when = datetime.datetime.fromtimestamp(m["time"]).strftime("%H:%M:%S")
    print(f"  {when}  priority {m.get('priority', 3)}  {m.get('title', '')}")
PY
  exit 0
fi
code="$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$url" -H 'Content-Type: application/json' -d "$body")"
echo "ntfy answered HTTP $code (200 means it was accepted)"
