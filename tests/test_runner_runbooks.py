import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from runner.catalog import load_catalog
from runner.jobs import Job
from runner.runbooks import (
    REBOOT_UNIT,
    REBOOT_WAIT_SECONDS,
    UNITS,
    CoolifyError,
    Runbooks,
    SystemctlUnits,
    build_executor,
    previous_commit,
)

HOST = "app-1"
APP = "abcdefghijklmnop12345678"
OTHER = "zzzzzzzzzzzzzzzzzzzzzzzz"
CATALOG = load_catalog()


def job(runbook: str, **params: Any) -> Job:
    return Job("act-1", CATALOG.get(runbook), params, HOST, datetime(2026, 11, 15, tzinfo=UTC))


class FakeCoolify:
    def __init__(self, deployments: list[dict[str, Any]] | None = None, fail: bool = False) -> None:
        self.calls: list[tuple[str, ...]] = []
        self._deployments = deployments or []
        self._fail = fail

    def restart(self, application: str) -> str:
        self.calls.append(("restart", application))
        if self._fail:
            raise CoolifyError("Coolify answered 403 for POST /api/v1/applications/x/restart")
        return "Restart request queued."

    def deployments(self, application: str) -> list[dict[str, Any]]:
        self.calls.append(("deployments", application))
        return self._deployments

    def rollback(self, application: str, commit: str) -> str:
        self.calls.append(("rollback", application, commit))
        return "Rollback queued."


class FakeSystemd:
    def __init__(self, ok: bool = True, said: str = "") -> None:
        self.started: list[tuple[str, int, bool]] = []
        self._ok, self._said = ok, said

    def run_unit(self, unit: str, timeout: int, *, wait: bool = True) -> tuple[bool, str]:
        self.started.append((unit, timeout, wait))
        return self._ok, self._said or f"{unit} finished"


def runbooks(
    tmp_path: Path, systemd: FakeSystemd | None = None, coolify: FakeCoolify | None = None, boot: str = "boot-1"
):
    return Runbooks(
        systemd or FakeSystemd(),
        tmp_path / "state",
        coolify=coolify,
        applications=frozenset({APP}),
        output_dir=tmp_path / "out",
        boot_id=lambda: boot,
    )


def deployment(commit: str, status: str = "finished", pr: int = 0) -> dict[str, Any]:
    return {"commit": commit, "status": status, "pull_request_id": pr}


# --- Coolify --------------------------------------------------------------------------------------------------------


def test_container_restart_calls_coolify_for_an_allowed_application(tmp_path) -> None:
    coolify = FakeCoolify()
    outcome = runbooks(tmp_path, coolify=coolify)(job("container_restart", application=APP))
    assert outcome.ok and "queued" in outcome.summary
    assert coolify.calls == [("restart", APP)]


@pytest.mark.parametrize("runbook", ["container_restart", "redeploy_previous"])
def test_an_application_outside_the_runners_allowlist_is_refused(tmp_path, runbook) -> None:
    coolify = FakeCoolify()
    outcome = runbooks(tmp_path, coolify=coolify)(job(runbook, application=OTHER))
    assert not outcome.ok and "allowlist" in outcome.summary
    assert coolify.calls == []


@pytest.mark.parametrize("runbook", ["container_restart", "redeploy_previous"])
def test_without_coolify_the_coolify_runbooks_fail_clearly(tmp_path, runbook) -> None:
    outcome = runbooks(tmp_path)(job(runbook, application=APP))
    assert not outcome.ok and "not set up" in outcome.summary


def test_a_coolify_error_is_reported_without_a_body(tmp_path) -> None:
    outcome = runbooks(tmp_path, coolify=FakeCoolify(fail=True))(job("container_restart", application=APP))
    assert not outcome.ok and "403" in outcome.summary


def test_redeploy_rolls_back_to_the_commit_before_the_current_one(tmp_path) -> None:
    rows = [deployment("c3"), deployment("c2", pr=7), deployment("c2f", "failed"), deployment("c3"), deployment("c1")]
    coolify = FakeCoolify(rows)
    outcome = runbooks(tmp_path, coolify=coolify)(job("redeploy_previous", application=APP))
    assert outcome.ok
    assert coolify.calls == [("deployments", APP), ("rollback", APP, "c1")]
    assert "c3" in outcome.summary and "c1" in outcome.summary


def test_redeploy_without_an_earlier_deployment_fails_and_changes_nothing(tmp_path) -> None:
    coolify = FakeCoolify([deployment("only")])
    outcome = runbooks(tmp_path, coolify=coolify)(job("redeploy_previous", application=APP))
    assert not outcome.ok and "no earlier" in outcome.summary
    assert ("rollback", APP, "only") not in coolify.calls and len(coolify.calls) == 1


@pytest.mark.parametrize(
    ("rows", "expected"),
    [
        ([], None),
        ([deployment("a"), deployment("b")], ("a", "b")),
        ([deployment("a"), deployment("a"), deployment("b")], ("a", "b")),  # the same commit twice is one state
        ([deployment("HEAD"), deployment("a"), deployment("b")], ("a", "b")),  # an unresolved commit is no state
        ([deployment("a"), deployment("x", "in_progress"), deployment("b")], ("a", "b")),
        ([deployment("a"), deployment("p", pr=3), deployment("b")], ("a", "b")),
        ([deployment("a", "failed"), deployment("b", "failed")], None),
        ([{"commit": None, "status": "finished"}, deployment("a")], None),
    ],
)
def test_previous_commit(rows, expected) -> None:
    assert previous_commit(rows) == expected


# --- root actions ---------------------------------------------------------------------------------------------------


def test_image_prune_starts_its_fixed_unit_and_reports_the_output(tmp_path) -> None:
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "image-prune.log").write_text("Total reclaimed space: 1.2GB\n")
    systemd = FakeSystemd()
    outcome = runbooks(tmp_path, systemd)(job("image_prune"))
    assert outcome.ok and "1.2GB" in outcome.summary
    assert systemd.started == [("ops-runbook-image-prune.service", 15 * 60, True)]


def test_apt_security_starts_its_fixed_unit_and_a_failure_is_reported(tmp_path) -> None:
    systemd = FakeSystemd(ok=False, said="Failed to start: unit failed")
    outcome = runbooks(tmp_path, systemd)(job("apt_security"))
    assert not outcome.ok and "failed" in outcome.summary
    assert systemd.started == [("ops-runbook-apt-security.service", 28 * 60, True)]


def test_the_output_of_an_earlier_run_is_not_reported(tmp_path) -> None:
    (tmp_path / "out").mkdir()
    old = tmp_path / "out" / "image-prune.log"
    old.write_text("Total reclaimed space: 9GB\n")
    import os

    os.utime(old, (1.0, 1.0))
    outcome = runbooks(tmp_path, FakeSystemd(ok=False, said="denied"))(job("image_prune"))
    assert "9GB" not in outcome.summary


def test_the_runner_never_builds_a_unit_name_from_a_job(tmp_path) -> None:
    systemd = FakeSystemd()
    runbooks(tmp_path, systemd)(job("image_prune"))
    runbooks(tmp_path, systemd)(job("apt_security"))
    assert {u for u, _, _ in systemd.started} == {unit for unit, _, _ in UNITS.values()}


def test_a_runbook_the_runner_has_no_code_for_fails(tmp_path) -> None:
    unknown = job("image_prune")
    object.__setattr__(unknown.runbook, "id", "something_new")
    assert "not implemented" in runbooks(tmp_path)(unknown).summary


# --- the reboot -----------------------------------------------------------------------------------------------------


def test_a_reboot_is_requested_and_its_result_is_deferred_to_the_next_start(tmp_path) -> None:
    systemd = FakeSystemd()
    book = runbooks(tmp_path, systemd, boot="boot-1")
    outcome = book(job("reboot_scheduled", reboot_request=5))
    assert outcome.ok and outcome.deferred
    assert systemd.started == [(REBOOT_UNIT, 60, False)]  # does not wait: the server goes down

    reported: list[tuple[str, str, str]] = []

    def report(*args: str) -> bool:
        reported.append(args)
        return True

    now = datetime(2026, 11, 15, 4, 5, tzinfo=UTC).timestamp()
    # Still the same boot, a moment later: nothing to report yet.
    assert runbooks(tmp_path, boot="boot-1").recover_pending(report, now) is False and reported == []
    # After the reboot (new boot id) the result goes out and the marker is gone.
    assert runbooks(tmp_path, boot="boot-2").recover_pending(report, now) is True
    assert reported == [("act-1", "succeeded", "the server restarted")]
    assert runbooks(tmp_path, boot="boot-2").recover_pending(report, now) is False


def test_a_reboot_that_did_not_happen_is_reported_failed_after_the_wait(tmp_path) -> None:
    runbooks(tmp_path, boot="boot-1")(job("reboot_scheduled", reboot_request=5))
    marker = tmp_path / "state" / "pending-reboot.json"
    reported: list[tuple[str, str, str]] = []
    late = marker.stat().st_mtime + REBOOT_WAIT_SECONDS + 1
    assert runbooks(tmp_path, boot="boot-1").recover_pending(lambda *a: reported.append(a) or True, late) is True
    assert reported[0][:2] == ("act-1", "failed")


def test_a_result_the_service_did_not_take_is_kept_for_the_next_round(tmp_path) -> None:
    runbooks(tmp_path, boot="boot-1")(job("reboot_scheduled", reboot_request=5))
    book = runbooks(tmp_path, boot="boot-2")
    assert book.recover_pending(lambda *a: False, 0.0) is False
    assert (tmp_path / "state" / "pending-reboot.json").exists()
    assert book.recover_pending(lambda *a: True, 0.0) is True


def test_a_reboot_whose_start_call_looks_failed_keeps_the_marker_and_the_boot_id_decides(tmp_path) -> None:
    # The shutdown can kill the caller of the start, so a non-zero exit does not mean the server stays up.
    outcome = runbooks(tmp_path, FakeSystemd(ok=False, said="canceled"))(job("reboot_scheduled", reboot_request=5))
    assert outcome.ok and outcome.deferred and "canceled" in outcome.summary
    assert (tmp_path / "state" / "pending-reboot.json").exists()


# --- the real boundaries --------------------------------------------------------------------------------------------


def test_the_real_systemctl_wrapper_uses_a_fixed_command_and_no_runner_environment(monkeypatch) -> None:
    seen: dict[str, Any] = {}

    class Done:
        returncode, stdout, stderr = 0, "", ""

    def fake_run(argv, **kwargs):
        seen["argv"], seen["env"], seen["shell"] = argv, kwargs["env"], kwargs.get("shell", False)
        return Done()

    monkeypatch.setattr("runner.runbooks.subprocess.run", fake_run)
    monkeypatch.setenv("RUNNER_TOKEN", "must-not-leak")
    assert SystemctlUnits().run_unit("ops-runbook-image-prune.service", 60) == (
        True,
        "ops-runbook-image-prune.service finished with exit code 0",
    )
    assert seen["argv"] == ["/usr/bin/systemctl", "start", "--wait", "ops-runbook-image-prune.service"]
    SystemctlUnits().run_unit("ops-runbook-reboot.service", 60, wait=False)
    assert seen["argv"] == ["/usr/bin/systemctl", "start", "--no-block", "ops-runbook-reboot.service"]
    assert "RUNNER_TOKEN" not in seen["env"] and seen["shell"] is False


def test_build_executor_reads_the_coolify_settings_and_the_allowlist(tmp_path) -> None:
    book = build_executor(
        {"COOLIFY_URL": "http://localhost:8000", "COOLIFY_TOKEN": "t", "COOLIFY_APPS": f"{APP}, {OTHER}"}, tmp_path
    )
    assert book._applications == {APP, OTHER}
    with pytest.raises(SystemExit):
        build_executor({"COOLIFY_URL": "ftp://x", "COOLIFY_TOKEN": "t"}, tmp_path)


def test_the_polkit_rule_and_the_units_match_what_the_runner_starts() -> None:
    folder = Path(__file__).parent.parent / "deploy" / "runner"
    rule = (folder / "50-ops-runner.rules").read_text()
    allowed = set(re.findall(r'"(ops-runbook-[a-z-]+\.service)"', rule))
    assert allowed == {unit for unit, _, _ in UNITS.values()} | {REBOOT_UNIT}
    for unit in allowed:
        assert (folder / unit).exists()
    assert 'subject.user !== "ops-runner"' in rule
    assert (
        'verb === "start"' in rule
        and 'verb === "ref"' in rule
        and "stop" not in rule.lower().replace("ops-runbook", "")
    )
    # Every root unit has a fixed ExecStart and no Environment or ExecStartPre that could carry a parameter.
    for unit in allowed:
        text = (folder / unit).read_text()
        assert text.count("ExecStart=") == 1 and "ExecStartPre" not in text and "%" not in text
    assert "--filter until=168h" in (folder / "ops-runbook-image-prune.service").read_text()


def test_every_catalog_runbook_has_code_or_is_a_coolify_runbook() -> None:
    handled = set(UNITS) | {"container_restart", "redeploy_previous", "reboot_scheduled"}
    assert set(CATALOG.runbooks) == handled


def test_the_catalog_rollback_hints_exist_for_every_runbook() -> None:
    assert all(book.rollback for book in CATALOG.runbooks.values())
    assert json.loads((Path(__file__).parent.parent / "runner" / "catalog.json").read_text())["version"] == 1
