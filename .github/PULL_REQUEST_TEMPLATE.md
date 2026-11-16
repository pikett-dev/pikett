## What changes

<!-- What does this change for someone who runs Pikett? New settings, migrations, alerts, UI? -->

## Why

<!-- Link the issue if there is one. -->

## Checklist

- [ ] `ruff check`, `ruff format --check`, `mypy app runner` and `pytest` pass locally
- [ ] Tests cover the new behaviour
- [ ] No secrets, real hostnames, IP addresses, Slack IDs or customer data, also not in tests
- [ ] No project-specific code (settings or ports instead)
- [ ] New migration is a new numbered file, no released migration edited
- [ ] `CHANGELOG.md` has a line under "Unreleased"
