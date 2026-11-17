# Contributing to Pikett

Thanks for taking the time. Bug reports, fixes, adapters for other platforms and translations are all welcome.

## Before you start

- For anything larger than a small fix, open an issue first and describe what you want to change and why. That saves you from building something that does not fit.
- Security problems go to [SECURITY.md](SECURITY.md), not into a public issue.

## Set up

```bash
git clone https://github.com/pikett-dev/pikett.git
cd pikett
uv sync
pre-commit install            # optional: runs ruff and gitleaks before each commit
```

Docker must be running for the tests: Testcontainers starts a real Postgres, and some tests run the pinned vmalert and Alloy images over the shipped rules and configuration (the first run pulls them).

## The gate

A change is ready when all of these pass locally. CI runs the same checks, plus gitleaks and a `docker build`.

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy app runner
uv run pytest
```

## Rules for code in this repository

- **No secrets, ever.** No tokens, keys, passwords, real hostnames, IP addresses, Slack IDs or customer data, not even in tests. Use placeholders (`<token>`, `app-1`, `acme/api`, `alice@example.com`). CI runs gitleaks and will fail.
- **No project-specific code.** Pikett is used by several teams. What differs between them goes into settings or behind a port, never into `if project == ...`.
- **English** for code, comments, docstrings, commit messages and documentation.
- **Migrations** are numbered SQL files in `app/migrations`. Never edit one that is in a release; add the next number.
- **Incident logic goes through `IncidentService`.** Slack, ntfy, the model and external APIs sit behind ports, so tests use fakes.
- **The agent stays read-only.** A new agent tool must not change anything. Anything that acts goes into the runbook catalog in `runner/` and needs an approval.
- **Mask before the model.** Text that can reach the model goes through `app/agent/masking.py`. A new kind of sensitive value gets a pattern and a test.
- Tests for every behaviour change. Name them after what they prove (`test_a_known_alarm_gets_its_solution_without_a_model_call`).
- Keep modules small and focused; prefer a new module over a long one.

## Pull requests

- One topic per pull request. Describe what changes for an operator: new settings, new migrations, changed alerts.
- Add a line to `CHANGELOG.md` under "Unreleased".
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `chore:`).
- By submitting a pull request you agree that your contribution is licensed under the Apache License 2.0.

## Good first contributions

- More languages for the web UI, Slack messages and runbook descriptions (English and German today).
- A GitHub or GitLab adapter for diffs, OSV scans and fix pull requests (today Bitbucket only).
- A deploy source without Coolify (plain `docker compose`, Dokploy, CapRover).
- Documentation from your own installation: what was unclear, what was missing.

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
