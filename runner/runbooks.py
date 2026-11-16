"""What the runner does for each runbook of the catalog.

A runbook is code with fixed argument lists, never a command taken from a job. Parameters have been validated against
the catalog before they get here; they only ever enter a Coolify URL path (and only after a second check against the
runner's own allowlist of applications), never a command line. Root actions are fixed systemd units
(`ops-runbook-*.service`) that the runner may start through a polkit rule; they run outside its sandbox.
Standard library only.
"""

import json
import logging
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from runner.jobs import Job

log = logging.getLogger("ops-runner")

# Minimal environment for child processes: nothing of the runner's own (the token in particular) reaches them.
CHILD_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}
UNIT_OUTPUT_DIR = Path("/run/ops-runbook")  # the units write their output here (tmpfiles.d, readable by the runner)
OUTPUT_TAIL = 1500
BOOT_ID_FILE = Path("/proc/sys/kernel/random/boot_id")
REBOOT_WAIT_SECONDS = 15 * 60  # how long a reboot may take before the runner calls it failed
COOLIFY_TIMEOUT = 30

# Root actions: runbook id -> its fixed unit.
# (unit, seconds the runner waits, file with the unit's output)
UNITS: dict[str, tuple[str, int, str]] = {
    "image_prune": ("ops-runbook-image-prune.service", 15 * 60, "image-prune.log"),
    "apt_security": ("ops-runbook-apt-security.service", 28 * 60, "apt-security.log"),
}
REBOOT_UNIT = "ops-runbook-reboot.service"


@dataclass(frozen=True)
class Outcome:
    ok: bool
    summary: str
    # A reboot cannot report: the runner is gone before. The result is sent by the next start (recover_pending).
    deferred: bool = False


Executor = Callable[[Job], Outcome]


class Coolify(Protocol):
    def restart(self, application: str) -> str: ...
    def deployments(self, application: str) -> list[dict[str, Any]]: ...
    def rollback(self, application: str, commit: str) -> str: ...


class Systemd(Protocol):
    def run_unit(self, unit: str, timeout: int, *, wait: bool = True) -> tuple[bool, str]:
        """Start a fixed unit. (ok, what it said)."""
        ...


class CoolifyError(Exception):
    pass


def _message(answer: Any) -> str:
    return str(answer.get("message", "queued")) if isinstance(answer, dict) else "queued"


class RunnerCoolify:
    """The Coolify API on this server (localhost). The token needs `deploy` (restart, rollback) and `read`."""

    def __init__(self, base_url: str, token: str) -> None:
        self._base = base_url.rstrip("/")
        self._headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def _call(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        request = urllib.request.Request(  # noqa: S310 (http(s) only, checked in the runner's config)
            f"{self._base}{path}",
            data=json.dumps(body).encode() if body is not None else None,
            headers=self._headers,
            method=method,
        )
        try:
            with self._opener.open(request, timeout=COOLIFY_TIMEOUT) as response:
                return json.loads(response.read(1_000_000) or b"{}")
        except urllib.error.HTTPError as error:
            with error:  # the answer body can carry secrets; only the status goes into the message
                raise CoolifyError(f"Coolify answered {error.code} for {method} {path.split('?')[0]}") from None
        except (OSError, ValueError) as error:
            raise CoolifyError(f"Coolify request failed: {type(error).__name__}") from None

    def restart(self, application: str) -> str:
        return _message(self._call("POST", f"/api/v1/applications/{application}/restart"))

    def deployments(self, application: str) -> list[dict[str, Any]]:
        body = self._call("GET", f"/api/v1/deployments/applications/{application}?take=20")
        rows = body.get("deployments") if isinstance(body, dict) else body
        return [row for row in rows or [] if isinstance(row, dict)]

    def rollback(self, application: str, commit: str) -> str:
        return str(
            self._call("POST", f"/api/v1/applications/{application}/rollback", {"commit": commit}).get(
                "message", "queued"
            )
        )


class SystemctlUnits:
    def run_unit(self, unit: str, timeout: int, *, wait: bool = True) -> tuple[bool, str]:
        argv = ["/usr/bin/systemctl", "start", "--wait" if wait else "--no-block", unit]
        try:
            done = subprocess.run(argv, env=CHILD_ENV, capture_output=True, text=True, timeout=timeout, check=False)  # noqa: S603
        except subprocess.TimeoutExpired:
            return False, f"{unit} did not finish in {timeout // 60} minutes"
        said = (done.stderr or done.stdout).strip()[-OUTPUT_TAIL:]
        return done.returncode == 0, said or f"{unit} finished with exit code {done.returncode}"


def previous_commit(deployments: list[dict[str, Any]]) -> tuple[str, str] | None:
    """(current, previous) commits of the production deployments (newest first): the last two finished deployments
    with a real and different commit. Previews (a pull request id) and failed deployments do not count."""
    commits: list[str] = []
    for row in deployments:
        commit = str(row.get("commit") or "")
        if row.get("status") != "finished" or row.get("pull_request_id") or not commit or commit == "HEAD":
            continue
        if not commits or commit != commits[-1]:
            commits.append(commit)
        if len(commits) == 2:
            return commits[0], commits[1]
    return None


def _tail(path: Path, since: float) -> str:
    """The end of a unit's output file, but only if this run wrote it (a failure before the first write leaves the
    file of an earlier run)."""
    try:
        if path.stat().st_mtime < since:
            return ""
        return path.read_text(errors="replace")[-OUTPUT_TAIL:].strip()
    except OSError:
        return ""


class Runbooks:
    def __init__(
        self,
        systemd: Systemd,
        state_dir: Path,
        *,
        coolify: Coolify | None = None,
        applications: frozenset[str] = frozenset(),
        output_dir: Path = UNIT_OUTPUT_DIR,
        boot_id: Callable[[], str] = lambda: BOOT_ID_FILE.read_text().strip(),
    ) -> None:
        self._systemd, self._state, self._coolify = systemd, state_dir, coolify
        self._applications, self._output, self._boot_id = applications, output_dir, boot_id

    def __call__(self, job: Job) -> Outcome:
        handler: Callable[[Job], Outcome] | None = {
            "container_restart": self._restart,
            "redeploy_previous": self._redeploy_previous,
            "image_prune": self._unit,
            "apt_security": self._unit,
            "reboot_scheduled": self._reboot,
        }.get(job.runbook.id)
        if handler is None:  # the catalog knows a runbook this runner has no code for
            return Outcome(False, f"runbook {job.runbook.id} is not implemented on this runner")
        return handler(job)

    def _coolify_for(self, job: Job) -> tuple[Coolify, str] | Outcome:
        """The Coolify client and the application of a job, or the failure when this runner may not touch it."""
        application = str(job.params["application"])
        if self._coolify is None or application not in self._applications:
            return Outcome(False, "Coolify is not set up on this runner or the application is not on its allowlist")
        return self._coolify, application

    def _restart(self, job: Job) -> Outcome:
        target = self._coolify_for(job)
        if isinstance(target, Outcome):
            return target
        coolify, application = target
        try:
            return Outcome(True, f"restart queued: {coolify.restart(application)}")
        except CoolifyError as error:
            return Outcome(False, str(error))

    def _redeploy_previous(self, job: Job) -> Outcome:
        target = self._coolify_for(job)
        if isinstance(target, Outcome):
            return target
        coolify, application = target
        try:
            found = previous_commit(coolify.deployments(application))
            if found is None:
                return Outcome(False, "there is no earlier finished deployment to go back to")
            current, previous = found
            message = coolify.rollback(application, previous)
        except CoolifyError as error:
            return Outcome(False, str(error))
        return Outcome(True, f"rollback from {current[:12]} to {previous[:12]} queued: {message}")

    def _unit(self, job: Job) -> Outcome:
        unit, timeout, output_file = UNITS[job.runbook.id]
        started = time.time() - 2  # file times have a coarse resolution
        ok, said = self._systemd.run_unit(unit, timeout)
        output = _tail(self._output / output_file, started)
        return Outcome(ok, f"{said}\n{output}".strip() if output else said)

    def _reboot(self, job: Job) -> Outcome:
        # Remember this boot before asking for the reboot: the next start of the runner reports the result.
        pending = {"action_id": job.action_id, "boot_id": self._boot_id()}
        self._state.mkdir(parents=True, exist_ok=True)
        (self._state / "pending-reboot.json").write_text(json.dumps(pending))
        ok, said = self._systemd.run_unit(REBOOT_UNIT, 60, wait=False)
        # Even when the start call looks failed the server may be going down (the shutdown kills the caller), so the
        # marker stays and the next start decides by the boot id; a reboot that did not happen is reported as failed.
        return Outcome(True, "reboot requested" if ok else f"reboot requested, start call said: {said}", deferred=True)

    def recover_pending(self, report: Callable[[str, str, str], bool], now: float) -> bool:
        """After a start: report the result of a reboot this runner asked for. True when there was one.

        A new boot id means the reboot happened. The same boot id for REBOOT_WAIT_SECONDS means it did not."""
        path = self._state / "pending-reboot.json"
        try:
            pending = json.loads(path.read_text())
            action_id, old_boot = str(pending["action_id"]), str(pending["boot_id"])
        except (OSError, ValueError, KeyError):
            return False
        if self._boot_id() != old_boot:
            reported = report(action_id, "succeeded", "the server restarted")
        elif now - path.stat().st_mtime > REBOOT_WAIT_SECONDS:
            reported = report(action_id, "failed", "the server did not restart")
        else:
            return False  # the runner restarted for another reason while the reboot is still coming
        if reported:  # a result the service did not take is kept and sent again by the next round
            path.unlink(missing_ok=True)
        return reported


def build_executor(env: dict[str, str], state_dir: Path) -> Runbooks:
    """The runbooks with the settings of this server. Coolify is optional: without it only the root actions work."""
    coolify = None
    url, token = env.get("COOLIFY_URL", ""), env.get("COOLIFY_TOKEN", "")
    if url and token:
        if not url.startswith(("http://", "https://")):
            raise SystemExit("COOLIFY_URL must be an http(s) URL")
        coolify = RunnerCoolify(url, token)
    applications = frozenset(a.strip() for a in env.get("COOLIFY_APPS", "").split(",") if a.strip())
    return Runbooks(SystemctlUnits(), state_dir, coolify=coolify, applications=applications)
