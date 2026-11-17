# Operating Pikett

Configuration files, upgrade, back up and uninstall. Paths assume the layout of the install guide: the repository in `/opt/ops` on the ops server, the stack in `/opt/ops/deploy/ops-server`.

## Configuration files

Five files hold the configuration. None of them is in Git, all are mode 600 and owned by root, and a deploy by tag (`ops-deploy`) never touches them: it only checks out code.

| File | On | What it holds | How it gets there |
|---|---|---|---|
| `.env` | the ops server, `/opt/ops/deploy/ops-server/` | Variables that Compose itself reads: `TAILSCALE_IP`, `ALERT_NOTIFIER_URL`, `ALERT_TOKEN`, `OPS_IMAGE`, `OPS_DB_PASSWORD`, `KUMA_DB_PASSWORD`, `KUMA_DB_ROOT_PASSWORD`, `TRIVY_TOKEN`. Template: `.env.example` next to it. | `install -m 600 .env.example .env`, then fill it in (install guide, "Configuration on the ops server"). Or fill in a copy on your machine and let `provision.sh deploy` copy it. |
| `ops-service.env` | the ops server, same folder | The settings of the service itself (`app/config.py`): `PROJECT_NAME`, `LANGUAGE`, `TIMEZONE`, Slack, the Anthropic key, `RUNNER_TOKENS`, `RUNNER_SIGNING_KEY`, `HOST_REPORT_TOKENS` and more. Template: `ops-service.env.example`; the settings table in the README explains each one. Compose passes the file to the service (`env_file`). | The same way as `.env`. |
| `alert-token` | the ops server, same folder | The value of `ALERT_TOKEN` as a file, which vmalert reads. It must be identical to `ALERT_TOKEN` in `.env`. | `install -m 600 /dev/null alert-token`, then write the token to it without a newline (install guide). `provision.sh deploy` writes it from `ALERT_TOKEN` on your machine. |
| `/etc/ops-runner/ops-runner.env` | every app server that runs the runner | `OPS_URL`, `RUNNER_TOKEN`, `HOST_NAME` and, for the Coolify runbooks, the Coolify URL, token and apps. Template: `deploy/runner/ops-runner.env.example`. | `deploy/runner/install.sh` creates it from the template and stops; fill it in and run the script again (`deploy/runner/README.md`). `RUNNER_TOKEN` is this server's entry in `RUNNER_TOKENS` in `ops-service.env`. |
| `/etc/ops-collect.env` | every server that runs the collector | `OPS_URL`, the report token, `HOST_NAME`, the lists of reports per timer and the Trivy token. Template: `deploy/host-agent/ops-collect.env.example`. | `deploy/host-agent/install.sh` creates it and stops; fill it in and run the script again (`deploy/host-agent/README.md`). The token is this server's entry in `HOST_REPORT_TOKENS` in `ops-service.env`. |

What to know:

- **Tokens come in pairs.** The service holds a token per server in `ops-service.env` (`RUNNER_TOKENS`, `HOST_REPORT_TOKENS`) and each server holds its own value in its env file. Changing one side without the other makes the service answer 401 or reject the job.
- **`provision.sh deploy` overwrites** `.env`, `ops-service.env` and `alert-token` on the server with the ones from your machine. A deploy by tag does not.
- **`ops-deploy` refuses to deploy** when `TAILSCALE_IP` is missing in `.env`, when `alert-token` is missing or differs from `ALERT_TOKEN`, or when `ALERT_TOKEN` is not a plain value (no quotes, spaces or comment).
- **Restart the service after a change** to `ops-service.env` or `.env`. A change to the tokens of a runner or collector needs a restart of that unit.
- **Back them up** with the database dump (next sections): they are the only part of the installation that is not in Git or in the database, and `ops-service.env` holds the runner signing key.
- **Upgrade:** the CHANGELOG names a new variable or file; add it before you deploy (step 3 below).

## Upgrade

1. **Read the [CHANGELOG](../CHANGELOG.md)** for every version between yours and the new one. The upgrade notes come first in each entry. `/health` on the ops service shows the running version (the commit of the image).
2. **Take a backup** (next section). Migrations only go forward: going back to an older version means restoring the dump from before the upgrade.
3. **Check what the notes ask for before you deploy.** Typical items: a new variable in `.env` or `ops-service.env` (see "Configuration files" above), a file that must exist on the server (`alert-token`), a re-run of `provision.sh pipeline` after a change to `ops-deploy.sh` (the server holds a copy of it).
4. **Deploy the ops server.** `ops-deploy.sh` takes a release tag such as `v1.2.3` or the full 40-character commit hash, and only deploys a commit that is on `main`. The server resolves a tag itself, so nobody has to look up the hash.
   - From your CI or your machine, with the pipeline key (a CI runner on the tailnet needs the optional `tag:pikett-ci` rule of the tailnet policy): `ssh -i <pipeline-key> deploy@<ops-server> v1.2.3`. A pipeline that does this on every push is in the next section.
   - By hand as root on the server: `SSH_ORIGINAL_COMMAND=v1.2.3 /usr/local/bin/ops-deploy`.
   - A server that still has an `ops-deploy` from before 0.5.0 knows only hashes, and a deploy by hash does not replace that script: run `provision.sh pipeline` once to install the new one, then deploy by tag. The server follows origin for tags: a tag that origin moved points to its new commit, a deleted tag cannot be deployed, and a tag made on the server itself is ignored. Whatever the tag points to must still be on `main`.
   - Without the pipeline: `deploy/ops-server/provision.sh deploy` from your machine.

   The script checks out the commit, builds the image on the server, restarts the stack and waits for `/health`. If `/health` stays red it puts the previous image back.
5. **Update runners and the service together when the CHANGELOG says so.** Some versions change what runner and service exchange (the signing prefix of jobs, the catalog schema). A runner and a service on different sides of such a change reject each other's jobs, so deploy the service and then update every runner straight away, at a time when no action waits for approval:
   ```
   rsync -azR --exclude __pycache__ runner deploy/runner root@<app-server>:/opt/ops-runner-src/
   ssh root@<app-server> /opt/ops-runner-src/deploy/runner/install.sh
   ```
   The same pattern updates the collector (`rsync -az deploy/host-agent/ root@<server>:/opt/ops-collect-src/`, then `install.sh`) and Alloy (`deploy/app-host/agent.sh deploy`). Update them when the notes mention a change to them.
6. **Check afterwards.**
   - `docker compose ps` in `/opt/ops/deploy/ops-server`: every container `running`, the databases `healthy`.
   - `curl http://<tailscale-ip>:8030/health` shows the new version.
   - `/ops` lists every check with a recent run, and the runner card of each server shows a heartbeat with the new version.
   - `docker compose logs --since 10m ops-service vmalert` has no `rejected` lines (a wrong `ALERT_TOKEN`) and no tracebacks.
   - Send a test alert (for example with `curl` and the bearer token) and resolve it.

## Deploy from CI

Most installations keep their configuration in a repository of their own (the filled-in `ops-service.env.example`, notes) and want a push to deploy. Two files in that repository do it:

- `PIKETT_VERSION`: one line with the release to run, for example `v0.5.0`. This is the place that decides which Pikett version runs. To upgrade or roll back, change the line and push.
- a pipeline that reads the file and runs `ssh deploy@<ops-server> <that line>`: `deploy/ci/bitbucket-pipelines.example.yml` for Bitbucket Pipelines, `deploy/ci/github-actions-deploy.example.yml` for GitHub Actions. Each file starts with the setup steps (SSH key, Tailscale OAuth client, the variables).

The pipeline key can run `ops-deploy` and nothing else (`provision.sh pipeline` writes it as `restrict,command=...` for the `deploy` user, with `OPS_DEPLOY_PUBKEY` as its public key), and `ops-deploy` accepts only a release tag or a full hash that is on `main` of the repository the server fetches from (`OPS_REPO_URL`). `OPS_REPO_URL` is the URL the server fetches Pikett from. An `https://` URL of a public repository (for example `https://github.com/pikett-dev/pikett.git`) needs no key. A private repository needs an SSH URL; `provision.sh pipeline` then creates a read-only key on the server and prints it for you to add as a deploy key at your Git host. A URL with credentials (`https://user:token@...`) is refused, because the server would keep the token in its remote URL. If a server switches from an SSH to an HTTPS URL, remove the old deploy key at your Git host, and on the server delete `/root/.ssh/ops-repo` (and `.pub`), `/root/.ssh/known_hosts_repo` and the matching `Host` entry in `/root/.ssh/config`.

The pipeline holds no secret of Pikett: `.env`, `ops-service.env` and `alert-token` stay on the server. Every push to `main` runs the deploy. Pushing the same version again is harmless (the image is the same and compose recreates nothing), but it queues behind other deploys and takes a minute. The pins in the examples (actions by commit, the Tailscale image by digest) are yours to bump.

## Backup

Pikett's own Postgres (`ops-db`) is the only state that cannot be rebuilt. It holds the incidents and their timeline (including the incident memory: the key that links repeated alarms), the AI analyses and what they cost, the actions, approvals and the audit log of every approval and job, the host reports, the vulnerability findings and the state of the checks.

Not in it, and not worth backing up: logs, metrics and traces (30, 90 and 14 days of retention, filled again by Alloy), and the Trivy cache. Uptime Kuma keeps its monitors in its own MariaDB (`kuma-db`); back that up with your usual MariaDB tooling if the monitors took time to set up.

```bash
cd /opt/ops/deploy/ops-server
umask 077
mkdir -p /var/backups/pikett
docker compose exec -T ops-db pg_dump -U ops -Fc ops > /var/backups/pikett/ops-$(date +%F).dump
```

The dump contains incident texts, analyses and the audit log, so keep it at mode 600 and copy it off the server (another machine, object storage with encryption). A daily cron job with a retention of 14 days is enough: `find /var/backups/pikett -name 'ops-*.dump' -mtime +14 -delete` after the dump. Test a restore once on a spare machine.

Back up the configuration separately, because it is not in the database: `.env`, `ops-service.env` and `alert-token` in `deploy/ops-server`. `ops-service.env` holds the runner signing key. Without it you generate a new key and put its public half on every app server.

### Restore

On the same server, with the stack running:

```bash
cd /opt/ops/deploy/ops-server
docker compose stop ops-service
docker compose exec -T ops-db pg_restore -U ops -d ops --clean --if-exists --no-owner < /var/backups/pikett/ops-2026-11-16.dump
docker compose start ops-service
```

On a new server: install the stack as in the install guide, restore the three configuration files, then `docker compose up -d ops-db`, run the `pg_restore` line above (the empty database is fine) and `docker compose up -d`. Restore a dump into the same version of Pikett or a newer one; the service applies missing migrations at startup, but an older version does not understand a newer schema. Afterwards `/ops` shows the old incidents, and `docker compose logs ops-service` shows no migration errors.

## Uninstall

Order: stop the alerting, then the agents on each app server, then the ops server. Stopping the service first keeps the removal from paging anyone (`RunnerSilent`, `HostReportMissing`, `AppServerSilent`).

1. **Take a last backup** if you want to keep the history. Pause or delete the check at healthchecks.io (a stopped service stops its ping, which pages you). Then on the ops server: `docker compose stop vmalert ops-service`.
2. **On each app server, in this order:**
   1. The runner: the "Undo" in [`deploy/runner/README.md`](../deploy/runner/README.md).
   2. The collector: the "Undo" in [`deploy/host-agent/README.md`](../deploy/host-agent/README.md), and the "Undo" of the patch window, Lynis and CrowdSec there if you installed them.
   3. Alloy: the "Undo" in [`deploy/app-host/README.md`](../deploy/app-host/README.md). Remove `OTEL_EXPORTER_OTLP_ENDPOINT` from your applications and redeploy them.
3. **The ops server.** `cd /opt/ops/deploy/ops-server && docker compose down` stops and removes the containers and keeps the data. Add `-v` to delete the volumes as well (incidents, logs, metrics, Uptime Kuma); do it only after the backup. Then remove `/opt/ops`, `/usr/local/bin/ops-deploy`, `/etc/sudoers.d/ops-deploy` and the `deploy` user with its key if `provision.sh pipeline` created them, and delete the server and its firewall at your provider.

### What stays, and what you revoke

Removing the software does not remove the access you created for it:

- **Slack:** delete the Pikett app (api.slack.com/apps). That revokes the bot and app tokens.
- **Anthropic:** delete the API key used for `ANTHROPIC_API_KEY`.
- **Bitbucket:** the repository access tokens (`BITBUCKET_READ_TOKENS`, `BITBUCKET_WRITE_TOKENS`).
- **Coolify:** the API tokens of the service (read) and of the runners (read and deploy).
- **Tailscale:** remove the ops server and the agents' machines, the tags and the rules from the tailnet policy, and any auth key that is still unused.
- **ntfy:** stop using the topics; with a token, revoke it. **healthchecks.io:** delete the check.
- **Your Git host and CI:** the read-only deploy key of the ops server (SSH URL only), the SSH key of the pipeline, and the pipeline variables that call `ops-deploy`.
