# Operating Pikett

Configuration files, upgrade, back up and uninstall. Paths assume the layout of the install guide: the repository in `/opt/ops` on the ops server, the stack in `/opt/ops/deploy/ops-server`.

## Configuration files

Five files hold the configuration. None of them is in Git, all are mode 600 and owned by root, and a deploy by tag (`ops-deploy`) never touches them: it checks out the code, builds the image and, when you send rules, replaces `rules.local/`. A few more files belong to an installation (list below the table).

| File | On | What it holds | How it gets there |
|---|---|---|---|
| `.env` | the ops server, `/opt/ops/deploy/ops-server/` | Variables that Compose itself reads: `TAILSCALE_IP`, `ALERT_NOTIFIER_URL`, `ALERT_TOKEN`, `OPS_IMAGE`, `OPS_DB_PASSWORD`, `KUMA_DB_PASSWORD`, `KUMA_DB_ROOT_PASSWORD`, `TRIVY_TOKEN`. Template: `.env.example` next to it. | `install -m 600 .env.example .env`, then fill it in (install guide, "Configuration on the ops server"). Or fill in a copy on your machine and let `provision.sh deploy` copy it. |
| `ops-service.env` | the ops server, same folder | The settings of the service itself (`app/config.py`): `PROJECT_NAME`, `LANGUAGE`, `TIMEZONE`, Slack, the Anthropic key, `RUNNER_TOKENS`, `RUNNER_SIGNING_KEY`, `HOST_REPORT_TOKENS` and more. Template: `ops-service.env.example`; the settings table in the README explains each one. Compose passes the file to the service (`env_file`). | The same way as `.env`. |
| `alert-token` | the ops server, same folder | The value of `ALERT_TOKEN` as a file, which vmalert reads. It must be identical to `ALERT_TOKEN` in `.env`. | `install -m 600 /dev/null alert-token`, then write the token to it without a newline (install guide). `provision.sh deploy` writes it from `ALERT_TOKEN` on your machine. |
| `/etc/ops-runner/ops-runner.env` | every app server that runs the runner | `OPS_URL`, `RUNNER_TOKEN`, `HOST_NAME` and, for the Coolify runbooks, the Coolify URL, token and apps. Template: `deploy/runner/ops-runner.env.example`. | `deploy/runner/install.sh` creates it from the template and stops; fill it in and run the script again (`deploy/runner/README.md`). `RUNNER_TOKEN` is this server's entry in `RUNNER_TOKENS` in `ops-service.env`. |
| `/etc/ops-collect.env` | every server that runs the collector | `OPS_URL`, the report token, `HOST_NAME`, the lists of reports per timer and the Trivy token. Template: `deploy/host-agent/ops-collect.env.example`. | `deploy/host-agent/install.sh` creates it and stops; fill it in and run the script again (`deploy/host-agent/README.md`). The token is this server's entry in `HOST_REPORT_TOKENS` in `ops-service.env`. |

What to know:

- **Tokens come in pairs.** The service holds a token per server in `ops-service.env` (`RUNNER_TOKENS`, `HOST_REPORT_TOKENS`) and each server holds its own value in its env file. `ALERT_TOKEN` in `.env` must equal `alert-token`, and `TRIVY_TOKEN` in `.env` must equal the `TRIVY_TOKEN` in the env file of each collector (which also needs `TRIVY_SERVER`). Changing one side without the other makes the service answer 401 or reject the job, or the Trivy report fail.
- **`provision.sh deploy` overwrites** `.env`, `ops-service.env` and `alert-token` on the server with the ones from your machine. A deploy by tag does not. Pick one of the two ways and keep to it, or edits made on the server are lost.
- **`ops-deploy` stops** when `TAILSCALE_IP` is missing in `.env`, when `alert-token` is missing or differs from `ALERT_TOKEN`, or when `ALERT_TOKEN` is not a plain value (no quotes, spaces or comment). These checks run after the checkout and the rules update and before the build: the containers keep their image, but the checkout and the new rules stay in place, and vmalert loads those rules within 30 seconds.
- **Apply a change** to `ops-service.env` or `.env` with `docker compose up -d ops-service` in `/opt/ops/deploy/ops-server`. `docker compose restart` does not re-read the env files. A change to the tokens of a runner or collector needs a restart of that unit.
- **More files belong to an installation** although they are not among the five: `deploy/vmalert/rules.local/` and your own runbook catalog `deploy/ops-server/catalog/catalog.json` on the ops server; `/etc/ops-runner/catalog.json` and `/etc/ops-runner/job-signing.pub` (the public half of the signing key) on each runner; `/opt/ops-agent/.env` (written by `agent.sh deploy`), `/opt/ops-agent/alloy/local-*.alloy` and `/opt/ops-agent/secrets.env` on an app server. Rules, catalog and Alloy files come from your configuration repository; `secrets.env` is written by hand (see "Your own rules and scrape targets").
- **Back them up** with the database dump (next sections): the five files and `secrets.env` are the only part of the installation that is neither in Git nor in the database, and `ops-service.env` holds the runner signing key. Keep your configuration repository, with `rules.local/` and the catalog, as the backup of those. If you generated the key as in `runner/README.md`, the file `/root/runner-signing-seed` holds the private key a second time: delete it once the key is in `ops-service.env`.
- **Upgrade:** the CHANGELOG names a new variable or file; add it before you deploy (step 3 below).

## Upgrade

1. **Read the [CHANGELOG](../CHANGELOG.md)** for every version between yours and the new one. The upgrade notes come first in each entry. After a deploy with `ops-deploy`, `/health` on the ops service shows the running version (the commit of the image); after `provision.sh deploy` or a plain `docker build` it shows `dev`.
2. **Take a backup** (next section). Migrations only go forward: going back to an older version means restoring the dump from before the upgrade.
3. **Check what the notes ask for before you deploy.** Typical items: a new variable in `.env` or `ops-service.env` (see "Configuration files" above), a file that must exist on the server (`alert-token`), a re-run of `provision.sh pipeline` after a change to `ops-deploy.sh` (the server holds a copy of it), `agent.sh deploy` after a change to `deploy/app-host/` (with `TEST_HOST`, `HOST_NAME` and `OPS_HOST` set for that server: the defaults name `app-1` and `ops-server`, and a deploy without them would relabel the server). Docker Compose 2.24 or later is needed on every app server.
4. **Deploy the ops server.** `ops-deploy.sh` takes a release tag such as `v1.2.3` or the full 40-character commit hash, and only deploys a commit that is on `main`. The server resolves a tag itself, so nobody has to look up the hash.
   - From your CI or your machine, with the pipeline key (a CI runner on the tailnet needs the optional `tag:pikett-ci` rule of the tailnet policy): `ssh -i <pipeline-key> deploy@<ops-server> v1.2.3`. A pipeline that does this on every push is in the next section.
   - By hand as root on the server: `SSH_ORIGINAL_COMMAND=v1.2.3 /usr/local/bin/ops-deploy`.
   - The server holds its own copy of `ops-deploy`, and a deploy does not replace it. Run `provision.sh pipeline` again whenever the CHANGELOG says the script changed, before you deploy that version, for example 0.2.0, 0.5.0 (tags; an older script knows only hashes) and 0.6.0 (the rules folder; with the old script `compose up` fails). A pipeline that only raises `PIKETT_VERSION` breaks the stack in that case. `provision.sh pipeline` needs `OPS_DEPLOY_PUBKEY` and `OPS_REPO_URL` again, because it writes the `deploy` user's key anew. It reaches the server as `root@<name on the tailnet>`; for a server that is not at Hetzner set `OPS_NAME` to that name and `OPS_SSH_PUBKEY` to the public key whose private half logs in as root. The server follows origin for tags: a tag that origin moved points to its new commit, a deleted tag cannot be deployed, and a tag made on the server itself is ignored. Whatever the tag points to must still be on `main`.
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

- `PIKETT_VERSION`: one line with the release to run, for example `v0.6.1`. This is the place that decides which Pikett version runs. To upgrade, change the line and push, after you have read the upgrade notes (some versions need `provision.sh pipeline` first, see "Upgrade"). Going back to an older version works only while no migration ran in between: the service applies migrations at startup and an older version does not understand a newer schema, so a rollback across a migration means restoring the dump from before the upgrade.
- a pipeline that reads the file and runs `ssh deploy@<ops-server> <that line>`: `deploy/ci/bitbucket-pipelines.example.yml` for Bitbucket Pipelines, `deploy/ci/github-actions-deploy.example.yml` for GitHub Actions. Each file starts with the setup steps (SSH key, Tailscale OAuth client, the variables).

The pipeline key can run `ops-deploy` and nothing else (`provision.sh pipeline` writes it as `restrict,command=...` for the `deploy` user, with `OPS_DEPLOY_PUBKEY` as its public key), and `ops-deploy` accepts only a release tag or a full hash that is on `main` of the repository the server fetches from (`OPS_REPO_URL`). `OPS_REPO_URL` is the URL the server fetches Pikett from. An `https://` URL of a public repository (for example `https://github.com/pikett-dev/pikett.git`) needs no key. A private repository needs an SSH URL; `provision.sh pipeline` then creates a read-only key on the server and prints it for you to add as a deploy key at your Git host. A URL with credentials (`https://user:token@...`) is refused, because the server would keep the token in its remote URL. If a server switches from an SSH to an HTTPS URL, remove the old deploy key at your Git host, and on the server delete `/root/.ssh/ops-repo` (and `.pub`), `/root/.ssh/known_hosts_repo` and the matching `Host` entry in `/root/.ssh/config`.

The pipeline holds no secret of Pikett: `.env`, `ops-service.env` and `alert-token` stay on the server. It deploys the ops server only: the `alloy/` folder of your configuration repository still goes to each app server with `agent.sh deploy` from a machine. Every push to `main` runs the deploy. Pushing the same version again is harmless (the image is the same and compose recreates nothing), but it queues behind other deploys and takes a minute. The pins in the examples (actions by commit, the Tailscale image by digest) are yours to bump.

## Your own rules and scrape targets

Everything an installation adds lives in its own configuration repository, not in tracked Pikett files. A deploy never overwrites or deletes it, except that `rules.local/` is replaced when you send rules (below).

### Alert rules

vmalert loads the rules from `deploy/vmalert/rules.live/`. `ops-deploy` builds that folder on every deploy: the shipped files of the release, and over them the files of your own folder `deploy/vmalert/rules.local/` (git-ignored). Both are plain rule files (`*.yml`, `groups:` at the top).

- **Add rules:** put a file with a new name into `rules.local/`.
- **Change or switch off a shipped file:** put a file with the same name there. `rules.local/apps.yml` replaces `apps.yml` as a whole; with the content `groups: []` it switches that file off. New shipped files of later releases are loaded as before.
- **Check:** `vmalert -dryRun` runs on the shipped rules of the release you deploy together with yours, before the checkout. If it refuses them, `ops-deploy` exits with 1 and changes nothing: no checkout, no build, no restart, and `rules.local/` stays as it was.

To get the files from your configuration repository onto the server, send the folder as a tar on stdin and add the word `rules` to the command:

```
tar -C rules -cf - . | ssh deploy@<ops-server> "v1.2.3 rules"
```

`ssh deploy@<ops-server> v1.2.3` without the word deploys the release and leaves `rules.local/` alone. With it, the tar replaces the folder: a file that is no longer in the tar is removed. To remove all own rules, send a tar that holds only `./`; an empty stream is refused, so a failed `tar` on the client cannot wipe the rules. The server accepts at most 1 MiB and 100 entries, an uncompressed tar, and only plain `*.yml` files at the top level (no folders, links or other names) of at most 1 MiB each, and refuses the whole tar otherwise. The pipeline key still runs only `ops-deploy`; the only thing it can change besides the release is `rules.local/`, and a rule file cannot run anything on the server. It can, however, silence alerts: a file named like a shipped one with `groups: []` switches that file off, and unlike code, rules are not tied to `main`. Whoever holds the pipeline key can therefore switch off alerts (a missing Watchdog still raises a P1). If a later step of a deploy fails (image build, health check), the new rules stay in place while the image rolls back; only a refusal by `vmalert -dryRun` changes nothing at all. The examples in `deploy/ci/` send `rules/` when that folder exists in your repository. A tar made on macOS needs `COPYFILE_DISABLE=1` in front of `tar`, or it adds `._*` entries that the server refuses.

By hand on the server: put the files into `/opt/ops/deploy/vmalert/rules.local/` and run `SSH_ORIGINAL_COMMAND=v1.2.3 /usr/local/bin/ops-deploy` (the check runs, vmalert picks the change up within 30 seconds after the deploy; `/usr/local/bin/ops-deploy` exists only after `provision.sh pipeline`). `provision.sh deploy` keeps `rules.local/` and rebuilds `rules.live/` from it, but runs no `vmalert -dryRun`: a broken file then shows up as a vmalert that does not start.

### Scrape targets and Postgres on the app server

Alloy loads every `*.alloy` file of `/opt/ops-agent/alloy/` as one configuration, so your files can use components of `config.alloy` such as `prometheus.remote_write.ops.receiver`. Your files are named `local-*.alloy`, and the component names must be unique across all files, so use a `local_` prefix.

- **Secrets** (a Bearer token of an app, the DSN of a database) go into `/opt/ops-agent/secrets.env` on the app server (mode 600, never in Git, `agent.sh` never writes or deletes it) and are read in the Alloy file with `sys.env("NAME")`. Restart Alloy after a change: `cd /opt/ops-agent && docker compose up -d --force-recreate`.
- **Copy the files** with `ALLOY_LOCAL_DIR=../<your-repo>/alloy deploy/app-host/agent.sh deploy`. The folder may hold only `local-*.alloy` files; anything else stops the script before it copies. A file you delete from the folder is deleted on the server. Without the variable `deploy` keeps what is there. Set `TEST_HOST`, `HOST_NAME` and `OPS_HOST` for the server as well (`agent.sh` defaults to `app-1` and `ops-server`, and writes `/opt/ops-agent/.env` from them on every deploy).
- **Examples** to copy and adapt are in `deploy/app-host/alloy/examples/`: `local-app-metrics.alloy` (the `/metrics` endpoint of an app behind a Bearer token, found by its Coolify resource name in the Docker network `coolify`, with the labels `job`, `service` and `host`) and `local-postgres.alloy` (one database server; the exporter reports every database on it).

### Postgres monitoring

`deploy/vmalert/rules/postgres.yml` has five rules: `PostgresDown` (`pg_up == 0`), `PostgresConnectionsHigh` (backends above 80 % of `max_connections` for 10 minutes), `PostgresDeadlocks`, `PostgresLongTransaction` (a transaction open longer than 10 minutes) and `PostgresExporterFailing` (the exporter's scrape fails). They need no setting: without the Postgres example in use there are no `pg_*` series and they stay silent. `PostgresExporterFailing` looks for `job="postgres"`, which the relabel block of `examples/local-postgres.alloy` sets; keep that block if you write your own exporter file.

1. **Create a monitoring role** in each database server. It gets `pg_monitor` and nothing else:
   ```sql
   CREATE ROLE pikett_monitor LOGIN PASSWORD '<password>';
   GRANT pg_monitor TO pikett_monitor;
   ```
   In a Coolify-managed Postgres open the terminal of the database resource (Coolify, resource, Terminal) and run `psql -U <superuser> -d <database>` first. The role belongs to the database server, so one role covers every database on it; the DSN of a server names one database to connect to, and the exporter reports all databases of that server.
2. **Put the connection string** into `secrets.env`: `PG_ACME_DSN=postgresql://pikett_monitor:<password>@<database-container>:5432/<database>?sslmode=disable`. The host is the container name of the database in the Docker network `coolify` (`docker ps` on the app server), and `sslmode=disable` is acceptable only inside that network. Special characters in the password have to be URL-encoded, and a value with a `$` goes in single quotes (Compose would read `$name` as a variable).
3. **Copy `examples/local-postgres.alloy`** to your repository as `local-postgres.alloy`, adapt the names (one component pair per database server: the exporter reports all databases of the server it connects to) and run `agent.sh deploy`. Docker Compose 2.24 or later is needed on the app server (`env_file` with `required: false`).

The analyst needs no change: its metric tools take any query, so it can ask for `pg_stat_database_*`, `pg_locks_count` or `pg_settings_max_connections` on its own.

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

Back up the configuration separately, because it is not in the database: `.env`, `ops-service.env` and `alert-token` in `deploy/ops-server`, plus `deploy/vmalert/rules.local/` and `deploy/ops-server/catalog/` if you do not keep them in your configuration repository. `ops-service.env` holds the runner signing key. Without it you generate a new key and put its public half on every app server.

### Restore

On the same server, with the stack running:

```bash
cd /opt/ops/deploy/ops-server
docker compose stop ops-service
docker compose exec -T ops-db pg_restore -U ops -d ops --clean --if-exists --no-owner < /var/backups/pikett/ops-2026-11-16.dump
docker compose start ops-service
```

On a new server: install the stack as in the install guide, restore the three configuration files (and `rules.local/` and `catalog/` if you use them), then `docker compose up -d ops-db`, run the `pg_restore` line above (the empty database is fine) and `docker compose up -d`. Restore a dump into the same version of Pikett or a newer one; the service applies missing migrations at startup, but an older version does not understand a newer schema. Afterwards `/ops` shows the old incidents, and `docker compose logs ops-service` shows no migration errors.

## Uninstall

Order: stop the alerting, then the agents on each app server, then the ops server. Stopping the service first keeps the removal from paging anyone (`RunnerSilent`, `HostReportMissing`, `AppServerSilent`, `AppHostSilent`). A server you remove on purpose keeps raising `AppHostSilent` for up to 24 hours. To stop it sooner, mute the incident for 24 hours with the Slack button. A copy of `host.yml` without that rule in `rules.local/` also works, but it replaces the shipped file as a whole: `groups: []` would switch off the disk, memory and container rules, and a copy freezes them at today's version, so remove it again after 24 hours.

1. **Take a last backup** if you want to keep the history. Pause or delete the heartbeat check (healthchecks.io or your push monitor): a stopped service stops its ping, which pages you. Then on the ops server: `docker compose stop vmalert ops-service`.
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
- **ntfy:** stop using the topics; with a token, revoke it. **Heartbeat monitor:** delete the check.
- **Your Git host and CI:** the read-only deploy key of the ops server (SSH URL only), the SSH key of the pipeline, and the pipeline variables that call `ops-deploy`.
