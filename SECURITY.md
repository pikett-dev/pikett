# Security policy

Pikett signs and runs actions on servers and handles alert data, logs and access tokens. We take reports seriously.

## Reporting a vulnerability

Please do **not** open a public issue. Report it privately through GitHub: **Security > Report a vulnerability** in this repository (private vulnerability reporting).

Include what you found, how to reproduce it and the version or commit. We confirm receipt within 5 working days and keep you informed until it is fixed. We credit reporters in the release notes unless you prefer otherwise.

## Supported versions

Only the latest minor release gets security fixes while the project is at 0.x.

## Scope

Especially relevant:

- forging or replaying runner jobs, bypassing the catalog or the host binding
- approving actions without being on the Slack allowlist
- getting the analyst to change anything, or to leak unmasked PII to the model
- reading secrets from the ops service, its logs, the web UI or the error messages it posts
- secrets committed to this repository

## For operators

- Keep `ops-service.env`, `.env`, `/etc/ops-collect.env` and `/etc/ops-runner/ops-runner.env` at mode 600, owned by root, and never commit them.
- Bind every port of the ops server to its Tailscale address. The web UI has no login of its own, and VictoriaLogs, VictoriaMetrics and VictoriaTraces accept reads and writes from every device that can reach them. The access control for the web UI and the telemetry ports is your tailnet policy: apply [`deploy/tailscale-acl.example.hujson`](deploy/tailscale-acl.example.hujson) (or an equivalent) so that only app servers reach the telemetry ports and only your team reaches the web UI.
- Set `ALERT_TOKEN` (and the same value for vmalert). Without it every device in the tailnet can post alerts, which opens incidents, pages people, spends AI budget and puts text into the analysis prompt.
- Give tokens the smallest scope: read-only repository tokens for diffs and OSV, write tokens only for repositories where you want fix pull requests, Coolify tokens limited to `read` (and `deploy` for the runner).
- Protect your main branches against direct pushes, so a fix pull request can never reach production without review.
