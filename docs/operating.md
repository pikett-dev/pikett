# Operating Pikett

Upgrade, back up and uninstall. Paths assume the layout of the install guide: the repository in `/opt/ops` on the ops server, the stack in `/opt/ops/deploy/ops-server`.

## Upgrade

1. **Read the [CHANGELOG](../CHANGELOG.md)** for every version between yours and the new one. The upgrade notes come first in each entry. `/health` on the ops service shows the running version (the commit of the image).
2. **Take a backup** (next section). Migrations only go forward: going back to an older version means restoring the dump from before the upgrade.
3. **Check what the notes ask for before you deploy.** Typical items: a new variable in `.env` or `ops-service.env`, a file that must exist on the server (`alert-token`), a re-run of `provision.sh pipeline` after a change to `ops-deploy.sh` (the server holds a copy of it).
4. **Deploy the ops server.** `ops-deploy.sh` takes the full 40-character commit hash of a commit that is on `main`. For a release tag, get it with `git rev-parse <tag>^{commit}`.
   - From your CI or your machine, with the pipeline key (a CI runner on the tailnet needs the optional `tag:pikett-ci` rule of the tailnet policy): `ssh -i <pipeline-key> deploy@<ops-server> <full-hash>`.
   - By hand as root on the server: `SSH_ORIGINAL_COMMAND=<full-hash> /usr/local/bin/ops-deploy`.
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
- **Bitbucket:** the repository access tokens (`BITBUCKET_READ_TOKENS`, `BITBUCKET_WRITE_TOKENS`), the read-only access key of the ops server and the SSH key of the pipeline.
- **Coolify:** the API tokens of the service (read) and of the runners (read and deploy).
- **Tailscale:** remove the ops server and the agents' machines, the tags and the rules from the tailnet policy, and any auth key that is still unused.
- **ntfy:** stop using the topics; with a token, revoke it. **healthchecks.io:** delete the check.
- **Your Git history and CI:** the pipeline variables that call `ops-deploy`.
