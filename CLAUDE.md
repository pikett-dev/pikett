# CLAUDE.md (Pikett)

Open-source, self-hosted incident analysis, alerting and patch management for small teams on Docker servers. Public repository under the Apache License 2.0. See README.md for what it does and CONTRIBUTING.md for the rules.

## Stack

Python 3.12+, FastAPI, pydantic-settings, SQLAlchemy async on Postgres 18, Slack Bolt (Socket Mode), uv. Versions are pinned in `pyproject.toml` / `uv.lock`. Port 8030.

## Commands

- `uv sync` install
- `uv run uvicorn app.main:create_app --factory --port 8030 --reload` run
- `uv run ruff check . && uv run ruff format --check . && uv run mypy app runner && uv run pytest` gate: a task is done only when all pass; the tests start a real Postgres with Testcontainers, so Docker must run
- `docker compose up -d` local Postgres on 5436 (compose project `pikett`)
- `dev/compose.sh up -d --build` local all-in-one stack (compose project `pikett-stack`)

## Rules

- **This repository is public.** Never write secrets, tokens, keys, passwords, real hostnames, IP addresses, Tailscale names, Slack IDs, Coolify UUIDs, company or customer names, people's names or internal ticket keys into code, tests, comments, docs or commit messages. Use placeholders (`<token>`, `app-1`, `ops-server`, `acme/api`, `alice@example.com`). Before proposing a commit, search the diff for them.
- **No project-specific code.** Several teams use Pikett. What differs goes into settings (`app/config.py`) or behind a port, never into a branch on a project name.
- **English** for code, comments, docstrings, docs and commit messages. Every text a person reads (web UI, Slack, ntfy, reports, alert summaries, runbook titles) goes into `app/i18n/locales/en.json` and `de.json` and is read through `locale.t(key)`; the `Locale` (language and time zone) is passed in from `Settings`, never read from a global. English is the source text, German stays as it is. Tests fail on a German umlaut in code, on missing keys and on different placeholders.
- **Migrations** are numbered SQL files in `app/migrations`, applied once at startup. Never edit a released file; add the next number.
- **Incident logic goes through `IncidentService`**; Slack and ntfy sit behind the ports in `app/notify/base.py`, so tests use fakes. Notification steps record that they happened and are retried by the tick.
- Alerts arrive in the Alertmanager v2 format: firing alerts carry an `endsAt` in the future, resolved ones in the past, and `0001-01-01` means no end.
- The ops service runs on its own server, never on the app server. The app server only runs Alloy, the runner, the collector and patch tools.
- The AI agent is read-only. Actions run only through the signed runbook catalog in `runner/`, after a Slack approval.
- Mask PII (emails, tokens, IBANs, JWTs) before any text goes to an LLM.
- Fetch live docs before using the Anthropic API, Slack Bolt, VictoriaLogs/Traces, Alloy, Coolify or Bitbucket APIs.
- Keep modules small; maintain modularity even for small features.
- Every container setup has its own `COMPOSE_PROJECT_NAME` / compose `name:`.
- Never deploy and never publish a release. Propose a commit message (Conventional Commits) and stop.
- After every implementation, run `/simplify`, then `/code-review`, and fix what they find before you propose the commit message. Add a line to `CHANGELOG.md` under "Unreleased".
