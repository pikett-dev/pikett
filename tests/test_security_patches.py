from datetime import UTC, datetime, timedelta

import pytest

from app.models import HostReport
from app.security import overview
from app.security.patches import PatchCheck, parse_run, pending_services, restarted_services
from app.security.service import SecurityService
from app.security.signals import Signals
from tests.fakes import EN, TZ
from tests.security_helpers import open_incidents, report

HOST = "app-1"
# 03:40 Vienna (winter time) on 2026-11-14, when the collector reports.
COLLECTED = datetime(2026, 11, 14, 2, 40, tzinfo=UTC)

UU_LOG = """\
2026-11-13 03:00:11,101 INFO Starting unattended upgrades script
2026-11-13 03:00:11,102 INFO Allowed origins are: o=Ubuntu,a=noble-security
2026-11-13 03:00:15,000 INFO No packages found that can be upgraded unattended and no pending auto-removals
2026-11-14 03:00:12,345 INFO Starting unattended upgrades script
2026-11-14 03:00:12,346 INFO Allowed origins are: o=Ubuntu,a=noble-security, o=UbuntuESMApps,a=noble-apps-security
2026-11-14 03:00:20,000 INFO Packages that will be upgraded: libssl3t64 openssl linux-image-6.8.0-49-generic
2026-11-14 03:00:20,001 INFO Writing dpkg log to /var/log/unattended-upgrades/unattended-upgrades-dpkg.log
2026-11-14 03:02:01,000 INFO All upgrades installed
"""

DPKG_LOG = """\
Log started: 2026-11-13  03:00:15
Restarting services...
 systemctl restart cron.service
Log ended: 2026-11-13  03:00:30

Log started: 2026-11-14  03:00:21
Unpacking openssl (3.0.13-0ubuntu3.5) over (3.0.13-0ubuntu3.4) ...
Restarting services...
 systemctl restart ssh.service systemd-journald.service
Service restarts being deferred:
 systemctl restart docker.service
Log ended: 2026-11-14  03:02:00
"""

NEEDRESTART = """\
NEEDRESTART-VER: 3.6
NEEDRESTART-KCUR: 6.8.0-47-generic
NEEDRESTART-KEXP: 6.8.0-49-generic
NEEDRESTART-KSTA: 3
NEEDRESTART-SVC: docker.service
"""

FAILED_LOG = UU_LOG.replace(
    "2026-11-14 03:02:01,000 INFO All upgrades installed",
    "2026-11-14 03:02:01,000 ERROR Installing the upgrades failed!\n"
    "2026-11-14 03:02:01,001 ERROR error message: 'E:Sub-process /usr/bin/dpkg returned an error code (1)'",
)


def data(**overrides):
    base = {
        "log": UU_LOG,
        "dpkg_log": DPKG_LOG,
        "needrestart": NEEDRESTART,
        "reboot_required": True,
        "reboot_packages": ["linux-image-6.8.0-49-generic"],
        "health": [{"url": "https://api.example/health", "status": 200}],
    }
    return {**base, **overrides}


@pytest.fixture
def security(sessions, service, clock):
    signals = Signals(sessions, service, clock)
    return SecurityService(
        sessions,
        signals,
        clock,
        [PatchCheck(sessions, signals, clock, [HOST], self_rebooting=[], locale=EN)],
        locale=EN,
    )


def test_the_last_run_is_read_from_the_log():
    run = parse_run(UU_LOG, TZ)

    assert run.started_at == datetime(2026, 11, 14, 2, 0, 12, tzinfo=UTC)
    assert run.packages == ["libssl3t64", "openssl", "linux-image-6.8.0-49-generic"]
    assert run.errors == []
    assert restarted_services(DPKG_LOG, run.started_at, TZ) == [
        "ssh.service",
        "systemd-journald.service",
        "docker.service",
    ]
    assert pending_services(NEEDRESTART) == ["docker.service"]


async def test_the_digest_says_what_was_patched_and_restarted(security, clock):
    clock.now = COLLECTED
    await security.ingest(report(HOST, "patches", COLLECTED, **data()))

    [line] = await security.daily_lines(COLLECTED + timedelta(hours=5))

    assert line.startswith("Patches (app-1): 3 package(s): libssl3t64, openssl, linux-image-6.8.0-49-generic")
    assert "restarted: ssh.service, systemd-journald.service" in line
    assert "needs a manual restart: docker.service" in line
    assert "server reboot needed" in line


async def test_a_pending_reboot_or_service_restart_makes_the_overview_warn(security, clock):
    clock.now = COLLECTED
    await security.ingest(report(HOST, "patches", COLLECTED, **data()))
    assert overview._line_state(await security.daily_lines(COLLECTED)) == overview.WARN

    await security.ingest(report(HOST, "patches", COLLECTED, **data(reboot_required=False, needrestart="")))
    assert overview._line_state(await security.daily_lines(COLLECTED)) == overview.OK

    await security.ingest(report(HOST, "patches", COLLECTED, **data(reboot_required=False)))  # docker still pending
    assert overview._line_state(await security.daily_lines(COLLECTED)) == overview.WARN


async def test_a_red_health_check_after_the_patch_window_makes_the_card_a_problem(security, clock):
    clock.now = COLLECTED
    health = [{"url": "https://api.example/health", "status": 500}]
    await security.ingest(report(HOST, "patches", COLLECTED, **data(health=health)))  # a reboot is pending as well
    assert overview._line_state(await security.daily_lines(COLLECTED)) == overview.PROBLEM


@pytest.fixture
def self_rebooting(sessions, service, clock):
    signals = Signals(sessions, service, clock)
    check = PatchCheck(sessions, signals, clock, [HOST], self_rebooting=[HOST], locale=EN)
    return SecurityService(sessions, signals, clock, [check], locale=EN)


SUNDAY_BEFORE_REBOOT = COLLECTED + timedelta(hours=24)  # Sunday 03:40 Vienna, the reboot is at 05:00
SUNDAY_AFTER_REBOOT = datetime(2026, 11, 15, 4, 30, tzinfo=UTC)  # 05:30 Vienna, 30 minutes after the reboot time


async def test_a_self_rebooting_server_is_not_shown_as_waiting_after_its_sunday_reboot(self_rebooting, clock):
    clock.now = COLLECTED
    await self_rebooting.ingest(report(HOST, "patches", COLLECTED, **data()))

    [before] = await self_rebooting.daily_lines(SUNDAY_BEFORE_REBOOT)
    [after] = await self_rebooting.daily_lines(SUNDAY_AFTER_REBOOT)

    assert "server reboot needed" in before and "needs a manual restart" in before
    assert overview._line_state([before]) == overview.WARN
    assert "server reboot needed" not in after and "needs a manual restart" not in after
    assert "the reboot on Sunday at 05:00 was scheduled" in after
    assert overview._line_state([after]) == overview.OK


async def test_the_sunday_reboot_window_is_judged_from_the_report_and_has_a_boundary(self_rebooting, clock):
    clock.now = COLLECTED
    await self_rebooting.ingest(report(HOST, "patches", COLLECTED, **data()))

    [just_before] = await self_rebooting.daily_lines(SUNDAY_AFTER_REBOOT - timedelta(seconds=1))
    [at_boundary] = await self_rebooting.daily_lines(SUNDAY_AFTER_REBOOT)
    assert "server reboot needed" in just_before and "server reboot needed" not in at_boundary


def test_a_report_collected_after_the_sunday_reboot_time_waits_for_the_next_one(sessions, service, clock):
    check = PatchCheck(sessions, Signals(sessions, service, clock), clock, [HOST], self_rebooting=[HOST], locale=EN)
    sunday_report = datetime(2026, 11, 15, 8, 0, tzinfo=UTC)  # after the 05:00 reboot: its flag is current
    row = HostReport(
        host=HOST, kind="patches", collected_at=sunday_report, received_at=sunday_report, data={"reboot_required": True}
    )

    assert not check._reboot_overtaken(HOST, row, sunday_report + timedelta(hours=20))
    assert not check._reboot_overtaken(HOST, row, datetime(2026, 11, 22, 4, 29, tzinfo=UTC))  # 05:29 a week later
    assert check._reboot_overtaken(HOST, row, datetime(2026, 11, 22, 4, 30, tzinfo=UTC))  # 05:30 a week later

    # Summer time starts on 2027-03-28 (02:00 -> 03:00): 05:00 CEST is 03:00 UTC, so 05:30 CEST is 03:30 UTC.
    before_change = datetime(2027, 3, 27, 2, 40, tzinfo=UTC)
    row = HostReport(
        host=HOST, kind="patches", collected_at=before_change, received_at=before_change, data={"reboot_required": True}
    )
    assert not check._reboot_overtaken(HOST, row, datetime(2027, 3, 28, 3, 29, tzinfo=UTC))
    assert check._reboot_overtaken(HOST, row, datetime(2027, 3, 28, 3, 30, tzinfo=UTC))


async def test_the_sunday_reboot_only_settles_reports_that_asked_for_it(self_rebooting, security, clock):
    clock.now = COLLECTED
    await self_rebooting.ingest(report(HOST, "patches", COLLECTED, **data(reboot_required=False)))
    [line] = await self_rebooting.daily_lines(SUNDAY_AFTER_REBOOT)
    assert "needs a manual restart: docker.service" in line  # no reboot ran, so the service still waits

    await security.ingest(report(HOST, "patches", COLLECTED, **data()))  # a server with the Slack question
    [asked] = await security.daily_lines(SUNDAY_AFTER_REBOOT)
    assert "server reboot needed" in asked


async def test_a_failed_patch_opens_a_p1(security, sessions, clock, pager):
    clock.now = COLLECTED
    await security.ingest(report(HOST, "patches", COLLECTED, **data(log=FAILED_LOG)))

    [incident] = await open_incidents(sessions)
    assert (incident.title, incident.severity) == ("PatchFailed", "P1")
    assert "Installing the upgrades failed" in incident.annotations["summary"]
    assert len(pager.pages) == 1  # P1 pages whoever is on call that week
    assert ":red_circle:" in (await security.daily_lines(COLLECTED))[0]

    await security.ingest(
        report(HOST, "patches", COLLECTED + timedelta(days=1), **data(log=UU_LOG.replace("14 ", "15 ")))
    )
    assert await open_incidents(sessions) == []


async def test_a_red_health_check_after_the_window_opens_a_p1(security, sessions, clock):
    clock.now = COLLECTED
    health = [
        {"url": "https://api.example/health", "status": 502},
        {"url": "https://admin.example", "error": "timed out"},
    ]
    await security.ingest(report(HOST, "patches", COLLECTED, **data(health=health)))

    [incident] = await open_incidents(sessions)
    assert (incident.title, incident.severity) == ("PatchHealthRed", "P1")
    assert "api.example/health (502)" in incident.annotations["summary"]
    assert "admin.example (timed out)" in incident.annotations["summary"]


async def test_a_window_that_did_not_run_is_a_p2(security, sessions, clock):
    clock.now = COLLECTED + timedelta(days=2)
    await security.ingest(report(HOST, "patches", clock.now, **data()))

    [incident] = await open_incidents(sessions)
    assert (incident.title, incident.severity) == ("PatchWindowMissed", "P2")
    assert "the window did not run last night" in (await security.daily_lines(clock.now))[0]


async def test_a_report_without_the_log_is_a_p2_and_named(security, sessions, clock):
    await security.ingest(report(HOST, "patches", clock.now, error="/var/log/unattended-upgrades/... is missing"))

    [incident] = await open_incidents(sessions)
    assert incident.title == "PatchReportFailed"


async def test_no_report_last_night_is_named(security, clock):
    assert "no report from last night" in (await security.daily_lines(clock.now))[0]
