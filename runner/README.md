# ops-runner: catalog and signing

The runner executes only actions that are in the catalog and that the ops service has signed. The AI agent only reads; actions run through this path only, after an approval in Slack.

## Catalog

`catalog.json` is a checked-in file that the ops service and the runner load the same way (`catalog.py`). An installation can use its own file of the same schema (README, "Runbook catalog"). Per runbook:

| Field | Meaning |
|---|---|
| `title`, `description`, `rollback` | Text for Slack and the ops UI, as an object per language: `{"en": "...", "de": "..."}`. English is required, a language without a text falls back to it. Display text only: it is not part of the catalog digest, so changing it keeps signed jobs valid |
| `risk` | `low`, `medium`, `high` |
| `hosts` | servers it may run on (`*` = any) |
| `verify` | `health`: the ops service checks the health URLs afterwards; `reboot`: it waits until the runner reports again |
| `params` | allowed parameters: `type` (`string`, `integer`, `boolean`), `pattern` (must match the whole value), `enum`, `min`, `max`, `max_length` |

A parameter that is not in the schema, is missing or does not fit is rejected. A runbook without `params` takes none. A malformed catalog is refused at load, including unknown keys (a typo such as `patern` would otherwise drop a rule silently) and keys that do not fit a parameter type. Patterns match ASCII only.

| Runbook | Effect | Risk | Servers |
|---|---|---|---|
| `container_restart` | restart an application through the Coolify API | medium | any server whose `RUNNER_APPLICATIONS` list has the application |
| `redeploy_previous` | deploy the commit of the last successful deployment before the current one, through Coolify | high | any server whose `RUNNER_APPLICATIONS` list has the application |
| `image_prune` | `docker image prune --all --force --filter until=168h` | low | all |
| `apt_security` | `unattended-upgrade` now (security archives only, per the patch configuration) | medium | all |
| `reboot_scheduled` | reboot; the ops service creates it only from an approval in Slack (`reboot_request`) | high | all |

The runner never takes a command from a job. It has fixed argument lists per runbook in its code (no shell); parameters only enter a Coolify URL as validated values.

## Signing: Ed25519

Decision (instead of the HMAC in the first plan): the ops service holds the **private** key, the runner only the **public** one. The runner runs on the internet-facing app server. With a shared HMAC secret, whoever takes over that server could sign jobs and have the runner run commands as root. With Ed25519 they can only verify. The runner verifies with `python3-cryptography` (apt, Ubuntu 24.04 ships 41.x, which has everything used here); the service uses the `cryptography` package.

A job is `{"job": {...}, "signature": "<base64>"}`. The signature covers the canonical JSON bytes (sorted keys, no whitespace) with the prefix `pikett-job-v1\n`, so a signature made for something else with the same key never counts as a job. The job has exactly these fields:

`action_id`, `runbook`, `params`, `host`, `issued_at`, `expires_at`, `catalog`.

`catalog` is the SHA-256 over risk, hosts, verify mode and parameter rules of every runbook. Titles and descriptions are not part of it, so fixing a wording does not invalidate jobs.

`jobs.verify_job` checks in this order and rejects at the first failure:

1. shape and signature (unsigned, wrongly signed or altered: rejected)
2. only the expected fields
3. `host` is this server
4. `catalog` equals the digest of the runner's own catalog (an altered `catalog.json` on the server rejects every job)
5. lifetime valid (at most 1 hour, `expires_at` after `issued_at`), not expired, not from the future (60 s clock skew)
6. well-formed action id, runbook in the catalog, allowed on this server, parameters fit the schema

Replay protection (an action id runs once) needs state and lives in the runner. The runner must write the action id to disk (fsync) before it runs the action and key the store on `action_id`, not on the signature; otherwise a re-delivered reboot job could reboot the server again within its 15 minutes. The runner also caps the size of a job before parsing it.

## Keys

Generate on the ops server (the private key never leaves it):

```
umask 077; openssl genpkey -algorithm ed25519 -outform DER | tail -c 32 | base64 > /root/runner-signing-seed   # RUNNER_SIGNING_KEY (seed)
```

The ops service reads the seed from `RUNNER_SIGNING_KEY` in its env file; the runner never holds it. Derive the public key with `RUNNER_SIGNING_KEY=$(cat /root/runner-signing-seed) python -m runner.keys public`; it goes to the app server as `/etc/ops-runner/job-signing.pub`.

## Protocol with the ops service

The runner polls with `POST /api/v1/runner/poll` (Bearer token of its server). Before it runs a job it verifies it (above), stores the action id, then calls `POST /api/v1/runner/jobs/<id>/started` and runs the job **only if that call answers 2xx** (the service refuses a start after the 15 minutes; a repeated call is fine). It reports with `POST .../result` (`succeeded`, `failed`, or `rejected` for a job it refused to run).
