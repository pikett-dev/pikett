"""Signed jobs: what the ops service sends and the runner verifies before it does anything.

A job is signed with Ed25519. The ops service holds the private key, the runner only the public one, so whoever takes
over the app server cannot forge a job (a shared HMAC secret would allow that). The signature covers the action id,
the runbook, the parameters, the target server, the times and the digest of the catalog; the runner checks all of it
and rejects, never guesses. Replay protection (an action id runs once) needs state and lives in the runner.
"""

import base64
import binascii
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from runner.catalog import Catalog, CatalogError, Runbook, canonical_json

# Domain separation: a signature made for something else with the same key never validates as a job.
SIGNING_PREFIX = b"pikett-job-v1\n"
JOB_FIELDS = frozenset({"action_id", "runbook", "params", "host", "issued_at", "expires_at", "catalog"})
_REASON_LIMIT = 200
MAX_CLOCK_SKEW = timedelta(seconds=60)
MAX_LIFETIME = timedelta(hours=1)  # jobs live 15 minutes; a wrong TTL in the service must not make a long-lived job
_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", re.ASCII)
_ACTION_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")


def is_safe_id(value: object) -> bool:
    """An action id that is safe as a file name and in a URL path."""
    return isinstance(value, str) and _ACTION_ID.fullmatch(value) is not None


class JobRejected(Exception):
    """The job must not run. The message is safe to report back (no secrets, bounded length)."""

    def __init__(self, reason: str) -> None:
        reason = reason[:_REASON_LIMIT]
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Job:
    action_id: str
    runbook: Runbook
    params: dict[str, Any]
    host: str
    expires_at: datetime


def format_time(moment: datetime) -> str:
    if moment.tzinfo is None:
        raise ValueError("moment must be timezone-aware")
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_time(value: object) -> datetime:
    if not isinstance(value, str) or not _TIME.fullmatch(value):
        raise JobRejected("time has the wrong format")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        raise JobRejected("time has the wrong format") from None


def sign_job(private_key: Ed25519PrivateKey, payload: dict[str, Any]) -> dict[str, Any]:
    """The envelope `{"job": payload, "signature": base64}` for the runner."""
    signature = private_key.sign(SIGNING_PREFIX + canonical_json(payload))
    return {"job": payload, "signature": base64.b64encode(signature).decode("ascii")}


def public_key_from_b64(text: str) -> Ed25519PublicKey:
    try:
        return Ed25519PublicKey.from_public_bytes(base64.b64decode(text.strip(), validate=True))
    except (binascii.Error, ValueError) as error:
        raise ValueError("the public key must be 32 raw bytes in base64") from error


def verify_job(
    envelope: object,
    *,
    public_key: Ed25519PublicKey,
    catalog: Catalog,
    host: str,
    now: datetime,
) -> Job:
    """The job when everything checks out; otherwise JobRejected with the reason. Order: signature first."""
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    if not isinstance(envelope, dict) or set(envelope) != {"job", "signature"}:
        raise JobRejected("not a signed job")
    payload, signature = envelope["job"], envelope["signature"]
    if not isinstance(payload, dict) or not isinstance(signature, str):
        raise JobRejected("not a signed job")
    try:
        public_key.verify(base64.b64decode(signature, validate=True), SIGNING_PREFIX + canonical_json(payload))
    except (InvalidSignature, ValueError, TypeError, RecursionError):
        raise JobRejected("the signature is not valid") from None
    if set(payload) != JOB_FIELDS:
        raise JobRejected("the job has unexpected fields")
    if payload["host"] != host:
        raise JobRejected("the job is for another server")
    if payload["catalog"] != catalog.digest:
        raise JobRejected("the job was made for another catalog")
    expires_at, issued_at = _parse_time(payload["expires_at"]), _parse_time(payload["issued_at"])
    if expires_at <= issued_at or expires_at - issued_at > MAX_LIFETIME:
        raise JobRejected("the job has an invalid lifetime")
    if now >= expires_at:
        raise JobRejected("the job has expired")
    if issued_at - now > MAX_CLOCK_SKEW:
        raise JobRejected("the job was issued in the future")
    action_id = payload["action_id"]
    if not is_safe_id(action_id):
        raise JobRejected("the action id is malformed")
    try:
        runbook = catalog.get(payload["runbook"])
        if not runbook.allows_host(host):
            raise JobRejected("the runbook is not allowed on this server")
        params = runbook.validate_params(payload["params"])
    except CatalogError as error:
        raise JobRejected(str(error)) from None
    return Job(action_id, runbook, params, host, expires_at)
