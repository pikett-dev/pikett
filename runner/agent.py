"""The ops-runner loop: poll the ops service, verify a job, run it once, report.

It runs on an app server without an open port: it asks the ops service for work (every poll is also its heartbeat).
It never runs anything it has not verified, never runs an action id twice (the id is written to disk and synced before
the job starts, so a restart or a re-delivery cannot repeat it) and never takes a command from the job: the runbooks
(runner/runbooks.py) hold fixed argument lists. Standard library plus `cryptography` only.
"""

import json
import logging
import os
import signal
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from runner import __version__
from runner.catalog import Catalog, load_installed_catalog
from runner.jobs import JobRejected, is_safe_id, public_key_from_b64, verify_job
from runner.runbooks import Executor, Outcome, build_executor

log = logging.getLogger("ops-runner")

MAX_JOB_BYTES = 16 * 1024  # a job is a few hundred bytes; anything bigger is not read
SEEN_RETENTION_SECONDS = 24 * 3600  # far beyond the 1 hour a signed job can live
SUMMARY_LIMIT = 4000
POLL_TIMEOUT = 20
RESULT_ATTEMPTS = 5
START_ATTEMPTS = 3
RESULT_RETRY_SECONDS = 3.0
MIN_POLL_SECONDS, MAX_POLL_SECONDS = 1.0, 60.0  # the heartbeat alarm fires after 3 minutes of silence


class Api(Protocol):
    def poll(self, version: str, catalog: str) -> bytes | None: ...
    def started(self, action_id: str) -> bool: ...
    def result(self, action_id: str, status: str, summary: str) -> bool:
        """True when the result is settled: the service took it, or refused it for good (4xx)."""
        ...


class SeenStore:
    """Action ids that were taken. An id is recorded (file created exclusively, file and directory synced) before its
    job starts, so a crash in between loses the job but never runs it twice."""

    def __init__(self, directory: Path) -> None:
        self._dir = directory
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)

    def add(self, action_id: str) -> bool:
        """True when this id is new. A malformed id is never new."""
        if not is_safe_id(action_id):
            return False
        try:
            fd = os.open(self._dir / action_id, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            return False
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        dir_fd = os.open(self._dir, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        return True

    def prune(self, now: float) -> None:
        for path in self._dir.iterdir():
            if now - path.stat().st_mtime > SEEN_RETENTION_SECONDS:
                path.unlink(missing_ok=True)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """The token must go to the configured URL only: a redirect is an error, not something to follow."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class HttpApi:
    def __init__(self, base_url: str, token: str) -> None:
        self._base = base_url.rstrip("/")
        self._headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        # No proxy from the environment, no redirects.
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)
        self._last_problem = ""

    def _request(self, path: str, body: dict[str, Any]) -> tuple[int, bytes]:
        request = urllib.request.Request(  # noqa: S310 (http(s) only, checked in load_config)
            f"{self._base}{path}", data=json.dumps(body).encode(), headers=self._headers, method="POST"
        )
        try:
            with self._opener.open(request, timeout=POLL_TIMEOUT) as response:
                self._last_problem = ""
                return response.status, response.read(MAX_JOB_BYTES + 1)
        except urllib.error.HTTPError as error:
            with error:
                self._note(f"{path} answered {error.code}" + (" (check RUNNER_TOKEN)" if error.code == 401 else ""))
                return error.code, b""
        except OSError as error:  # URLError, timeouts and resets: the ops service is not reachable right now
            self._note(f"{path} failed: {error}")
            return 0, b""

    def _note(self, problem: str) -> None:
        """Log a problem once, not on every poll (one line every 10 s would be 8,600 a day)."""
        if problem != self._last_problem:
            log.warning("%s", problem)
            self._last_problem = problem

    def poll(self, version: str, catalog: str) -> bytes | None:
        status, body = self._request("/api/v1/runner/poll", {"version": version, "catalog": catalog})
        return body if status == 200 else None

    def started(self, action_id: str) -> bool:
        """True when the service accepted the start. A lost answer is retried (the service allows a repeated start);
        a refusal (409: expired) is final."""
        for attempt in range(START_ATTEMPTS):
            status, _ = self._request(f"/api/v1/runner/jobs/{action_id}/started", {})
            if 200 <= status < 300:
                return True
            if status and status < 500:
                return False
            if attempt + 1 < START_ATTEMPTS:
                time.sleep(RESULT_RETRY_SECONDS * (attempt + 1))
        return False

    def result(self, action_id: str, status: str, summary: str) -> bool:
        """The outcome must not be lost to a short outage: retry a few times, then leave it to the service's sweep.
        True when it is settled: taken, or refused for good (a 4xx does not change by asking again)."""
        for attempt in range(RESULT_ATTEMPTS):
            code, _ = self._request(
                f"/api/v1/runner/jobs/{action_id}/result", {"status": status, "summary": summary[:SUMMARY_LIMIT]}
            )
            if 200 <= code < 300:
                return True
            if code and code < 500:  # the service understood and said no: asking again will not change that
                log.error("the result of %s was refused (%s)", action_id, code)
                return True
            if attempt + 1 < RESULT_ATTEMPTS:
                time.sleep(RESULT_RETRY_SECONDS * (attempt + 1))
        log.error("the result of %s could not be delivered", action_id)
        return False


class Runner:
    def __init__(
        self,
        api: Api,
        public_key: Ed25519PublicKey,
        catalog: Catalog,
        host: str,
        seen: SeenStore,
        execute: Executor,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._api, self._key, self._catalog, self._host = api, public_key, catalog, host
        self._seen, self._execute, self._clock = seen, execute, clock

    def run_once(self) -> bool:
        """One poll. True when a job came in (run or rejected), False when there was nothing."""
        raw = self._api.poll(__version__, self._catalog.digest)
        if raw is None:
            return False
        envelope = self._parse(raw)
        action_id = self._claimed_id(envelope)
        try:
            job = verify_job(envelope, public_key=self._key, catalog=self._catalog, host=self._host, now=self._clock())
        except JobRejected as error:
            self._reject(action_id, error.reason)
            return True
        if not self._seen.add(job.action_id):
            # Not reported: a result under this id would be taken for the result of the job that ran it before.
            log.warning("dropped job %s: this action id was taken before (replay)", job.action_id)
            return True
        if not self._api.started(job.action_id):
            log.warning("the ops service did not accept the start of %s, not running it", job.action_id)
            return True
        try:
            outcome = self._execute(job)
        except Exception as error:  # a runbook bug must not stop the runner or leave the job running
            log.exception("runbook %s failed", job.runbook.id)
            outcome = Outcome(False, f"{type(error).__name__}: {error}")
        if not outcome.deferred:
            self._api.result(job.action_id, "succeeded" if outcome.ok else "failed", outcome.summary)
        return True

    @staticmethod
    def _parse(raw: bytes) -> object:
        if len(raw) > MAX_JOB_BYTES:
            return None
        try:
            return json.loads(raw)
        except (ValueError, RecursionError):
            return None

    @staticmethod
    def _claimed_id(envelope: object) -> str | None:
        """The id a job names, only to report its rejection. The transport is Tailscale (authenticated and encrypted),
        and the service takes a rejection only for a job it delivered to this server."""
        job = envelope.get("job") if isinstance(envelope, dict) else None
        action_id = job.get("action_id") if isinstance(job, dict) else None
        return action_id if isinstance(action_id, str) and is_safe_id(action_id) else None

    def _reject(self, action_id: str | None, reason: str) -> None:
        log.warning("rejected job %s: %s", action_id, reason)
        if action_id is not None:
            self._api.result(action_id, "rejected", reason)


def load_config(env: dict[str, str]) -> tuple[str, str, str, Path, Path, float]:
    """(ops url, token, host, public key file, state dir, poll seconds) from the environment of the systemd unit."""
    try:
        url, token, host = env["OPS_URL"], env["RUNNER_TOKEN"], env["HOST_NAME"]
    except KeyError as error:
        raise SystemExit(f"missing setting {error} in /etc/ops-runner/ops-runner.env") from error
    if not url.startswith(("http://", "https://")) or "<" in url:
        raise SystemExit("OPS_URL must be an http(s) URL")
    if not token or not host:
        raise SystemExit("RUNNER_TOKEN and HOST_NAME must not be empty")
    try:
        interval = float(env.get("POLL_SECONDS", "10"))
    except ValueError:
        raise SystemExit("POLL_SECONDS must be a number") from None
    if not MIN_POLL_SECONDS <= interval <= MAX_POLL_SECONDS:  # also rules out nan and inf
        raise SystemExit(f"POLL_SECONDS must be between {MIN_POLL_SECONDS:g} and {MAX_POLL_SECONDS:g}")
    key_file = Path(env.get("JOB_PUBLIC_KEY_FILE", "/etc/ops-runner/job-signing.pub"))
    return url, token, host, key_file, Path(env.get("STATE_DIR", "/var/lib/ops-runner")), interval


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    url, token, host, key_file, state_dir, interval = load_config(dict(os.environ))
    public_key = public_key_from_b64(key_file.read_text())
    seen = SeenStore(state_dir / "seen")
    runbooks = build_executor(dict(os.environ), state_dir)
    api = HttpApi(url, token)
    # The same file as the service uses (install.sh puts it here), else the shipped catalog.
    catalog = load_installed_catalog(
        Path(os.environ.get("CATALOG_FILE", "/etc/ops-runner/catalog.json")), required="CATALOG_FILE" in os.environ
    )
    runner = Runner(api, public_key, catalog, host, seen, runbooks)
    stop = False

    def request_stop(*_: object) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, request_stop)
    log.info("ops-runner %s for %s polling %s every %ss", __version__, host, url, interval)
    last_prune = 0.0
    while not stop:
        try:
            if runbooks.recover_pending(api.result, time.time()):  # a reboot this runner asked for before it went down
                log.info("reported the result of a reboot")
            busy = runner.run_once()
            if (now := time.time()) - last_prune > 3600:
                seen.prune(now)
                last_prune = now
        except Exception:  # network trouble, a full disk: keep polling, the ops service alarms when it goes quiet
            log.exception("poll round failed")
            busy = False
        if not busy:
            time.sleep(interval)


if __name__ == "__main__":
    main()
