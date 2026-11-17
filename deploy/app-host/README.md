# Alloy on the app server

Alloy collects Docker logs, host and container metrics, and OTLP from your applications on the app server, and ships everything over Tailscale to the ops server. It runs as a container in the Docker network `coolify`, the network all Coolify resources share, so your applications reach it at `http://alloy:4318` without any change to their network settings. Without Coolify, attach it to the network your applications use and change `networks` in `compose.yml`.

## Install

From your own machine, with SSH access to the app server over Tailscale (key `~/.ssh/app_server` by default, override with `TEST_SSH_KEY=...`):

```
deploy/app-host/agent.sh deploy
deploy/app-host/agent.sh status
```

`deploy` copies this folder to `/opt/ops-agent`, writes `.env` (the Tailscale address of the ops server and `HOST_NAME`) and starts Alloy. `status` shows the container, warnings from the Alloy log, and whether host metrics and logs arrive on the ops server. Prefix either command with `DRY_RUN=1` to print the commands without running them.

## Your own Alloy files

Alloy runs on the folder `/opt/ops-agent/alloy/`: it loads every `*.alloy` file in it as one configuration (subfolders such as `examples/` are not read). Add your own as `local-*.alloy` and reference the components of `config.alloy`, for example `prometheus.remote_write.ops.receiver`; component names must be unique across files, so use a `local_` prefix.

```
ALLOY_LOCAL_DIR=../<your-repo>/alloy deploy/app-host/agent.sh deploy
```

The folder may hold only `local-*.alloy` files (anything else stops the script before it copies), and a file removed from the folder is removed on the server. Without the variable `deploy` leaves the server's files alone. Secrets for these files go into `/opt/ops-agent/secrets.env` (mode 600, created by hand, never written or deleted by `agent.sh`) and are read with `sys.env("NAME")`. `examples/` has a Bearer-token scrape of an app's `/metrics` and a Postgres exporter; the rules for Postgres are in `deploy/vmalert/rules/postgres.yml`. Details: `docs/operating.md`, "Your own rules and scrape targets". `agent.sh status` shows Alloy's warnings; a file Alloy cannot load stops it from starting, so look at `docker compose logs alloy` after a deploy.

## Application settings

Set these as runtime environment variables of each application (in Coolify: normal variables, not build variables):

| Variable | Value |
|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://alloy:4318` |
| `DEPLOYMENT_ENVIRONMENT` | `production`, `test`, ... |

Redeploy afterwards. Check that the commit SHA reaches the application (Coolify passes `SOURCE_COMMIT` as a build argument): its health endpoint should report the commit as its version, not `dev`. `service.version` = commit SHA is what ties an incident to a deploy.

## What you see afterwards

- `AppServerSilent` closes on its own as soon as host metrics arrive.
- Logs, metrics and traces of your applications on the ops server (ports 9428, 8428 and 10428, Tailscale only).
- Logs of every container on the app server, including Coolify's own.

## Undo

On the app server: `cd /opt/ops-agent && docker compose down -v` stops Alloy and deletes its data volume (the persistent queue; logs and metrics already sent stay on the ops server). Then remove `/opt/ops-agent`. Remove `OTEL_EXPORTER_OTLP_ENDPOINT` from your applications and redeploy them, or their exporters log errors. Do not remove the Docker network `coolify`; it belongs to Coolify. The ops server raises `AppServerSilent` (P1) when the metrics stop, so stop vmalert or take the alert rule out first (`deploy/vmalert/rules/`).

## Known limits

- **Alloy has root-equivalent access to the app server.** It runs `privileged` with `pid: host` and `cgroup: host`, mounts the whole root file system read-only and the Docker socket. A read-only socket mount does not make the Docker API read-only: whoever controls the Alloy container (or its config, or a vulnerability in it) can start containers and take over the host. Keep `config.alloy`, your `local-*.alloy` files, `secrets.env` and this directory writable by root only, keep the image pinned by digest (Renovate proposes updates), and keep port 12345 on localhost (it already is).
  Why it is not narrower: Grafana's documentation for `prometheus.exporter.cadvisor` says that to collect container metrics with Alloy in Docker you "must mount the necessary host directories and run the container in privileged mode", and its own Compose example uses `privileged: true`. The page for `prometheus.exporter.unix` only says that some collectors need "elevated privileges" (it names `SYS_TIME` as one capability you may need) and documents no set of capabilities. There is no documented setup with `cap_add` and read-only mounts that replaces `privileged`, and this repository has not tested one. If you try it, check that every container still shows up in cAdvisor metrics and that the host metrics are complete before you drop `privileged: true`.
  If you do not want this, run the node exporter and cAdvisor as separate containers with the narrowest rights each needs and let Alloy scrape them; that changes `config.alloy` and is not part of this repository.
- Log lines are expected on stdout. JSON logs (ECS or similar) with `trace_id` and `span_id` give the analyst the link between a log line and its trace.
