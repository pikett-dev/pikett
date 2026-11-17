# Installing Pikett with an AI agent

This guide is written for an AI coding agent (Claude Code, Codex, Cursor, Aider or similar) that installs Pikett for a human operator. Humans can follow it too.

To use it, tell your agent:

> Install Pikett for me. Follow docs/install-with-an-ai-agent.md in https://github.com/pikett-dev/pikett exactly, one phase at a time.

## Rules for the agent

Follow these rules for the whole installation. They override any shortcut that looks faster.

1. **Never handle secrets in the conversation.** Do not ask the human to paste a token, key or password into the chat, and never print one. Generate secrets on the target machine (`openssl rand -hex 32`) and write them straight into the env file there. When a secret comes from a third party (Slack, Anthropic, Coolify, Bitbucket), tell the human which file and which variable to fill in, and let them edit the file on the server themselves (`sudoedit /opt/ops/deploy/ops-server/ops-service.env`).
2. **Env files are mode 600, owned by root, and never committed.** Check with `stat -c '%a %U' <file>` after writing.
3. **Ask before anything that costs money or changes a server.** Creating a server, opening a firewall port, installing packages, starting services and rebooting each need an explicit "yes" from the human. Read-only checks need no confirmation.
4. **One phase at a time.** Finish a phase, run its check, report the result in two or three lines, and wait for the human before you start the next one.
5. **Dry run first** where the script supports it (`DRY_RUN=1`). Show the human what will run.
6. **Stop on the first failure.** Do not retry with variations or work around an error. Report the command, the error and what you think it means, then wait.
7. **Production applications are not yours to change.** Only touch the ops server, the agents on the app servers (`/opt/ops-agent`, `/opt/ops-collect`, `/opt/ops-runner`, their systemd units) and the settings the human approves for their applications.
8. **Use the "Undo" sections** in `deploy/*/README.md` if the human wants to back out of a phase.

## Phase 0: collect the facts

Ask the human these questions in one message and write the answers into a short plan. Do not continue with unknown answers to questions 1 to 5.

1. Which app servers should be monitored? Hostname or Tailscale name of each, and SSH user.
2. Where should the ops server run? A new server (provider, region) or an existing machine that is **not** one of the app servers.
3. Is Tailscale set up, and are the app servers in the tailnet?
4. Do the applications run under Coolify? If yes, the Coolify URL (reachable over Tailscale).
5. Which Slack workspace, and which two channels: one for alerts, one for ops reports?
6. Should the AI analysis be on (needs an Anthropic API key and a daily budget in USD, default 5)?
7. Who is on call (names and Slack user IDs; ntfy topics are created later)?
8. Health URLs of each application (public URLs that must answer 2xx).
9. Optional: Bitbucket repositories for diffs and dependency scans, actions through the runner (yes/no), fix pull requests (yes/no).

## Phase 1: preflight (read-only)

Run on each app server and, if it exists, on the ops server:

```bash
lsb_release -ds                       # expect Ubuntu 24.04 or another Debian-based system
systemctl --version | head -1
docker version --format '{{.Server.Version}}'
docker compose version
tailscale status --self --peers=false
free -h && df -h /
```

On your own machine: `tailscale ping <each server>` and `ssh <user>@<server> true`.

**Check:** every command answers. The ops server has at least 4 GB RAM and 20 GB free disk. Report anything missing and stop.

## Phase 2: the ops server

**Option A, a new server at Hetzner.** `join` advertises `tag:pikett-ops` (change it with `TS_TAGS`), and a tag works only when the tailnet policy defines it in `tagOwners` and the single-use auth key is allowed to set it. So the human applies the tailnet policy first (steps 1 and 3 of "Tailnet policy" below) and creates the auth key afterwards. From a clone of the repository on the human's machine, with `hcloud` configured:

```bash
cd deploy/ops-server
DRY_RUN=1 ./provision.sh create       # show what will be ordered, then ask the human
./provision.sh create                 # asks before ordering
./provision.sh join                   # installs Tailscale and joins the tailnet
```

**Option B, any other machine.** Install Docker and Tailscale on it, then:

```bash
sudo git clone https://github.com/pikett-dev/pikett.git /opt/ops
cd /opt/ops && sudo git checkout v<latest release>
sudo docker build -t pikett:latest /opt/ops
```

**Configuration on the ops server** (both options; `docs/operating.md`, "Configuration files", lists every configuration file of an installation):

```bash
cd /opt/ops/deploy/ops-server
sudo install -m 600 .env.example .env
sudo install -m 600 ops-service.env.example ops-service.env
```

In `.env`: set `TAILSCALE_IP` to `tailscale ip -4` of the ops server and `OPS_IMAGE=pikett:latest`. Generate `OPS_DB_PASSWORD`, `KUMA_DB_PASSWORD`, `KUMA_DB_ROOT_PASSWORD` and `TRIVY_TOKEN` with `openssl rand -hex 24` directly into the file, for example:

```bash
sudo sed -i "s|^OPS_DB_PASSWORD=.*|OPS_DB_PASSWORD=$(openssl rand -hex 24)|" .env
```

Generate the token of the alert webhook the same way and write it to both places, so a new installation never runs with an open webhook. `.env` holds it for the service (`ALERT_TOKEN`), the file `alert-token` next to it holds it for vmalert, and the two must be identical:

```bash
token="$(openssl rand -hex 32)"
sudo sed -i "s|^ALERT_TOKEN=.*|ALERT_TOKEN=$token|" .env
sudo install -m 600 /dev/null alert-token
printf '%s' "$token" | sudo tee alert-token >/dev/null
unset token
```

With Option A, set `ALERT_TOKEN` in the `.env` on the human's machine instead; `./provision.sh deploy` writes `alert-token` on the server from it. Do not print the token.

In `ops-service.env`: set `PROJECT_NAME`, `LANGUAGE` (`en` or `de`), `TIMEZONE` (an IANA name; use the zone of the servers, the timers in `deploy/` say `Europe/Vienna`; it also sets the day for the digest and the AI budget, the on-call week, SSH quiet hours, the reboot window and how patch logs are read), `AGENT_STACK_DESCRIPTION` (a few sentences about the human's stack, from Phase 0), and `BASE_URL=http://<tailscale-ip>:8030`. The database URL is set by `compose.yml` from `OPS_DB_PASSWORD`. Leave Slack, Anthropic and other third-party tokens empty for now.

Start the stack (Option A: `./provision.sh deploy` from the human's machine does the copy, build and start):

```bash
sudo docker compose up -d
sudo docker compose ps
curl -fsS http://<tailscale-ip>:8030/health
```

**Check:** all containers are `running` or `healthy`, `/health` answers `{"status":"ok",...}`, `http://<tailscale-ip>:8030/ops` opens in the human's browser over Tailscale. No port is reachable from the public internet (`ss -tlnp` shows only the Tailscale IP and SSH). Without a token the service logs `ALERT_TOKEN is not set`; with it, `curl -s -o /dev/null -w '%{http_code}' -X POST http://<tailscale-ip>:8030/api/v2/alerts -H 'Content-Type: application/json' -d '[]'` answers `401`.

**Optional: deploys from CI.** Not needed to finish the install. If the human wants a push to deploy, point them to `docs/operating.md`, section "Deploy from CI" (it needs `provision.sh pipeline` and the examples in `deploy/ci/`).

**Tailnet policy (the human does this in the Tailscale admin console; you do not).** The web UI has no login and the telemetry ports (9428, 8428, 10428) accept reads and writes from every device in the tailnet, so the access control is the tailnet policy. Ask the human to:

1. Open the admin console, Access controls, and merge `deploy/tailscale-acl.example.hujson` into the policy: replace the e-mail addresses in `group:pikett-team` and the address in the `tests` block (a failing test makes Tailscale refuse the policy), keep their other rules, and remove any broad `"src": ["*"], "dst": ["*"]` rule once these cover what the team needs. The file's `tests` must pass.
2. Tag the ops server with `tag:pikett-ops` (Machines, the server, Edit ACL tags), and later each app server with `tag:pikett-app` (do it before Phase 4). A server that joined with `provision.sh` already advertises `tag:pikett-ops`.
3. Save the policy.

**Check:** the human's browser still opens `http://<tailscale-ip>:8030/ops`; from a tailnet device that is neither in the group nor tagged, `curl -m 5 http://<tailscale-ip>:8428/` times out; from an app server (Phase 4) it works.

## Phase 3: Slack

The human does this part; you tell them the steps.

1. Open https://api.slack.com/apps, "Create New App", "From an app manifest", paste `deploy/slack-app-manifest.json`.
2. Basic Information: upload `docs/assets/pikett-icon-512.png` under Display Information (optional, the manifest cannot carry an icon), then create an app-level token with `connections:write` (this is `SLACK_APP_TOKEN`, starts with `xapp-`).
3. Install the app to the workspace (this gives `SLACK_BOT_TOKEN`, starts with `xoxb-`).
4. Invite the bot to both channels and copy the channel IDs (channel details, at the bottom).
5. Edit `ops-service.env` on the ops server and fill in `SLACK_BOT_TOKEN`, `SLACK_APP_TOKEN`, `SLACK_ALERTS_CHANNEL`, `SLACK_OPS_CHANNEL`, `SLACK_ALLOWED_USERS`, `ONCALL_PEOPLE`, `ONCALL_ANCHOR` (a Monday). If the analysis is on: `ANTHROPIC_API_KEY` and `AGENT_DAILY_BUDGET_USD`.

Then restart: `sudo docker compose up -d ops-service`.

**Check:** `/oncall` in Slack answers with the rotation. Send a test alert from the human's machine:

```bash
OPS_URL=http://<tailscale-ip>:8030 dev/alert.sh fire P2
OPS_URL=http://<tailscale-ip>:8030 dev/alert.sh resolve P2
```

A thread appears in the alerts channel and is marked resolved.

## Phase 4: telemetry from each app server

From the human's machine, per app server (details in `deploy/app-host/README.md`):

```bash
TEST_HOST=<app server> HOST_NAME=<app server> OPS_HOST=<ops server> DRY_RUN=1 deploy/app-host/agent.sh deploy
TEST_HOST=<app server> HOST_NAME=<app server> OPS_HOST=<ops server> deploy/app-host/agent.sh deploy
TEST_HOST=<app server> HOST_NAME=<app server> OPS_HOST=<ops server> deploy/app-host/agent.sh status
```

Without Coolify, change the Docker network in `deploy/app-host/compose.yml` to the network the applications use before you deploy.

Ask the human to set `OTEL_EXPORTER_OTLP_ENDPOINT=http://alloy:4318` and `DEPLOYMENT_ENVIRONMENT` on each application and redeploy it. That is a change to their production applications: it needs their "yes" and they may want to do it themselves.

Tag the app server with `tag:pikett-app` in the Tailscale admin console first (the human does it), or the tailnet policy blocks Alloy.

**Check:** `deploy/app-host/agent.sh status` shows host metrics, containers and log lines from the app server (it asks the ops server from the app server, because only app servers may reach the telemetry ports), and the `AppServerSilent` incident (if one opened) closes.

## Phase 5: security checks on every server

Follow `deploy/host-agent/README.md`, section "Rollout", for each server including the ops server. Generate the per-server tokens on the ops server and put them into `HOST_REPORT_TOKENS` and `SECURITY_HOSTS`. Copy each server's own token into its `/etc/ops-collect.env` over SSH, without printing it.

Then, only with the human's "yes" for each: the patch window (section "Patch window"), Lynis and CrowdSec (same README). CrowdSec can lock you out if the Tailscale whitelist is missing; install it exactly in the order the script uses and keep an SSH session open while you test a second login.

**Check:** `journalctl -u ops-collect-daily -n 20` shows no error after the first run, and the `/ops` page shows each check with a first run.

## Phase 6 (optional): actions through the runner

Only if the human wants actions. Follow `deploy/runner/README.md`. The shipped `runner/catalog.json` allows every runbook on any server; the Coolify runbooks still need the application on that server's `RUNNER_APPLICATIONS` list. Only if the human wants to restrict servers, change texts or risk levels, copy it to `deploy/ops-server/catalog/catalog.json`, edit it, restart the ops service and install the same file on each runner (`CATALOG_FILE=...`). The signing seed is generated on the ops server and never leaves it; only the public key goes to the app servers. Coolify tokens for the runner are created by the human in the Coolify UI with `read` and `deploy` rights, limited to the applications in `RUNNER_APPLICATIONS`.

**Check:** the runner card in `/ops` shows a heartbeat, and stopping the runner for 3 minutes opens a P1 `RunnerSilent` that closes when it is back.

## Phase 7: alert rules and handover

1. Walk through `deploy/vmalert/rules/*.yml` with the human and adjust thresholds and service names to their applications. Restart vmalert after changes.
2. Set `HEALTHCHECKS_PING_URL` so a dead ops server is noticed from outside.
3. Write a short handover note for the human: servers and what runs where, which phases are done, which optional parts are off, where the env files are, and how to undo each phase. Do not include any secret in it.

## Final checklist

- [ ] `/health` is ok and `/ops` shows every enabled check
- [ ] A test alert reached Slack and was resolved
- [ ] Metrics, logs and traces arrive from every app server
- [ ] Every server sends host reports
- [ ] No env file is world-readable, no secret appeared in the conversation or in a commit
- [ ] No port of the ops server is public
- [ ] The human knows how to reach the web UI and how to undo each phase
