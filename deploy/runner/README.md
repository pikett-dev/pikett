# ops-runner on the app server

The runner executes, on one server, the runbook actions that the ops service has signed and that someone approved in Slack. It opens no port: every 10 seconds it asks the ops service for work (`POST /api/v1/runner/poll` over Tailscale), and each poll doubles as its heartbeat. The catalog, the signature scheme and the order of checks are described in `runner/README.md`.

## What the runner never does

- It runs nothing that is not signed, meant for this server, in the catalog, with valid parameters and still valid in time. Every rejection is reported to the ops service with its reason.
- It never runs an action ID twice. The ID is written (with `fsync`) to `/var/lib/ops-runner/seen/` before the start, so a restart or a duplicate delivery repeats nothing.
- It starts a job only after the ops service has confirmed the start with a 2xx (after 15 minutes the service answers 409).
- It never takes a command from a job. Runbooks have fixed argument lists and no shell.

## Permissions

- Its own user `ops-runner`: no login, no home, no groups. It cannot change anything on the server by itself.
- Code and catalog belong to root and are read-only for the runner (`/opt/ops-runner`). It only writes to `/var/lib/ops-runner`.
- The unit is hardened: no privileges (`NoNewPrivileges`, empty capabilities), a read-only file system except `/var/lib/ops-runner` (`ProtectSystem=strict`), no devices, network only to Tailscale (`100.64.0.0/10`) and localhost (Coolify). Root actions (image prune, apt, reboot) are fixed systemd units `ops-runbook-*.service` that the runner may start through polkit (rule `50-ops-runner.rules`, only these units) and that run outside its sandbox. No `sudo`, no setuid. Restarting the runner does not cut off a running action.
- The runner only reads the public signing key. The private key stays on the ops server.

## Runbooks

| Runbook | What it does | Runs as |
|---|---|---|
| `container_restart` | Coolify API `POST /api/v1/applications/<uuid>/restart` (localhost) | runner, with the Coolify token from its env file |
| `redeploy_previous` | `GET /api/v1/deployments/applications/<uuid>` (the last two finished commits, previews excluded), then `POST /api/v1/applications/<uuid>/rollback` with the previous commit | as above |
| `image_prune` | `systemctl start --wait ops-runbook-image-prune.service` (`docker image prune --all --force --filter until=168h`) | root, own unit |
| `apt_security` | `systemctl start --wait ops-runbook-apt-security.service` (`unattended-upgrade`) | root, own unit |
| `reboot_scheduled` | `systemctl start --no-block ops-runbook-reboot.service` (the unit calls `systemctl --no-block reboot`); the runner remembers the boot ID and reports the result after the reboot | root, own unit |

The Coolify token needs only the `read` and `deploy` permissions (restart and rollback are deploy operations), limited to the applications the runner may touch. `COOLIFY_APPS` in the env file is a second barrier next to the pattern in the catalog. Coolify tokens are created only in the Coolify UI (Keys & Tokens > API Tokens). Without one, the two Coolify runbooks answer "Coolify is not set up"; the other three still work.

The reboot job is created by the ops service only from a Slack approval, from the approved time on, at most once per approval. After every action the ops service checks the health URLs (`RUNNER_HEALTH_URLS`).

## Install (per server)

**Before:** no runner; the ops service has no runner token for this server.

1. On the ops server: create a token (`openssl rand -hex 32`) and the signing key (see `runner/README.md`, section "Keys"). Set `RUNNER_TOKENS={"app-1":"<token>"}` and `RUNNER_SIGNING_KEY=<seed>` in `ops-service.env` and restart the ops service.
2. Copy both folders with their paths to the server (`-R` keeps `runner/` and `deploy/runner/`; the script finds `runner/` two levels above itself):
   ```
   rsync -azR --exclude __pycache__ runner deploy/runner root@app-1:/opt/ops-runner-src/
   ```
3. Put the public key at `/etc/ops-runner/job-signing.pub` (output of `python -m runner.keys public`). `install.sh` creates `/etc/ops-runner/` itself and stops when the key is missing, so either create the folder first (`mkdir -p /etc/ops-runner`) and put the key there, or let the first run of step 4 stop at the key check, put the key in the folder it created and run the script again.
   With your own catalog (README, "Runbook catalog"), copy it to the server too and give the path to the next step: `ssh root@app-1 CATALOG_FILE=<path on the server> /opt/ops-runner-src/deploy/runner/install.sh`. The script checks the file first and keeps it in `/etc/ops-runner/catalog.json`, so a later run without `CATALOG_FILE` leaves it in place.
4. `ssh root@app-1 /opt/ops-runner-src/deploy/runner/install.sh` creates the user, directories and unit, and stops after creating `/etc/ops-runner/ops-runner.env`. Fill in `OPS_URL`, `RUNNER_TOKEN` and `HOST_NAME`, then run the script again (all configuration files at a glance: `docs/operating.md`, "Configuration files").
5. Check: `systemctl status ops-runner` and `journalctl -u ops-runner -n 20`; the runner card in the ops UI shows the heartbeat.

**Undo:** `systemctl disable --now ops-runner; rm /etc/systemd/system/ops-runner.service /etc/systemd/system/ops-runbook-*.service /etc/polkit-1/rules.d/50-ops-runner.rules; rm /etc/tmpfiles.d/ops-runbook.conf; rm -r /opt/ops-runner /opt/ops-runner-src /etc/ops-runner /var/lib/ops-runner; userdel ops-runner; systemctl daemon-reload`. Remove the server from `RUNNER_TOKENS`, or the missing heartbeat opens a P1.

**Expected result:** a poll every 10 seconds and no errors in the journal. If you stop the runner, the ops service opens a P1 `RunnerSilent` after 3 minutes, which closes again when the runner is back.
