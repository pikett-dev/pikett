from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from app.security.intrusion import CrowdSecCheck, SshLoginCheck, in_tailscale, parse_logins
from app.security.service import SecurityService
from app.security.signals import Signals
from tests.fakes import EN
from tests.security_helpers import open_incidents, report

HOST = "app-1"
NOON = datetime(2026, 11, 14, 11, 0, tzinfo=UTC)  # 12:00 Vienna


def login(at: datetime, user: str = "root", source: str = "100.101.1.2") -> dict:
    return {
        "at": at.isoformat(),
        "message": f"Accepted publickey for {user} from {source} port 52144 ssh2: ED25519 SHA256:x",
    }


@pytest.fixture
def security(sessions, service, chat, clock):
    clock.now = NOON
    signals = Signals(sessions, service, clock)
    checks = [
        CrowdSecCheck(sessions, signals, clock, [HOST], locale=EN),
        SshLoginCheck(
            sessions, signals, chat, clock, [HOST], known_users=["root", "deploy"], any_time_users=["deploy"], locale=EN
        ),
    ]
    return SecurityService(sessions, signals, clock, checks, locale=EN)


def test_login_lines_are_parsed():
    data = {"logins": [login(NOON), {"at": NOON.isoformat(), "message": "Failed password for x"}]}

    [parsed] = parse_logins(HOST, data)

    assert (parsed.user, parsed.source, parsed.method, parsed.at) == ("root", "100.101.1.2", "publickey", NOON)


def test_tailscale_ranges():
    assert in_tailscale("100.64.0.1") and in_tailscale("100.127.255.254") and in_tailscale("fd7a:115c:a1e0::1")
    assert not in_tailscale("100.128.0.1") and not in_tailscale("203.0.113.7") and not in_tailscale("nonsense")


async def test_an_unusual_login_is_posted_once(security, chat, clock):
    night = datetime(2026, 11, 14, 1, 30, tzinfo=UTC)  # 02:30 Vienna
    logins = [
        login(NOON),  # usual
        login(night, user="deploy"),  # the pipeline may deploy at night
        login(night),  # root at night
        login(NOON, source="203.0.113.7"),  # outside Tailscale
        login(NOON, user="mallory"),  # unknown user
    ]
    await security.ingest(report(HOST, "ssh", clock.now, logins=logins))

    assert len(chat.ops) == 3
    assert "root from 100.101.1.2 (publickey) at Nov 14 02:30, at night" in chat.ops[0]
    assert "from outside Tailscale" in chat.ops[1]
    assert "unknown user mallory" in chat.ops[2]

    clock.advance(timedelta(hours=24))  # the next report covers an hour of the same logins
    await security.ingest(report(HOST, "ssh", clock.now, logins=logins))
    assert len(chat.ops) == 3


async def test_the_weekly_report_counts_logins_and_unusual_ones(security, clock):
    await security.ingest(report(HOST, "ssh", clock.now, logins=[login(NOON), login(NOON, user="mallory")]))

    lines = await security.weekly_lines(clock.now)

    assert "SSH (app-1): 2 login(s) (root 1x, mallory 1x), 1 of them unusual" in lines


async def test_crowdsec_bans_and_detections_are_in_the_weekly_report(security, clock):
    alerts = [
        {
            "scenario": "crowdsecurity/ssh-bf",
            "ip": "203.0.113.7",
            "country": "CN",
            "at": "2026-11-13T10:00:00Z",
            "banned": True,
        },
        {
            "scenario": "crowdsecurity/http-probing",
            "ip": "198.51.100.2",
            "country": "US",
            "at": "2026-11-13T11:00:00Z",
            "banned": True,
        },
        {
            "scenario": "crowdsecurity/http-probing",
            "ip": "198.51.100.3",
            "country": "US",
            "at": "2026-11-13T12:00:00Z",
            "banned": False,
        },
    ]
    await security.ingest(report(HOST, "crowdsec", clock.now, alerts=alerts, active_bans=2))
    await security.ingest(report(HOST, "crowdsec", clock.now, alerts=alerts[:1], active_bans=1))  # overlap

    lines = await security.weekly_lines(clock.now)

    assert (
        "CrowdSec (app-1): 3 detection(s) from 3 address(es), 2 banned, currently 1 ban(s); http-probing 2x, ssh-bf 1x"
    ) in lines


async def test_crowdsec_not_answering_is_a_p2(security, sessions, clock):
    await security.ingest(report(HOST, "crowdsec", clock.now, error="cscli fehlt (ist CrowdSec installiert?)"))

    [incident] = await open_incidents(sessions)
    assert (incident.title, incident.severity) == ("CrowdSecDown", "P2")
    assert ":warning: CrowdSec (app-1): no data from the last week." in await security.weekly_lines(clock.now)


def test_the_tailscale_network_can_never_be_banned():
    whitelist = Path(__file__).parent.parent / "deploy/host-agent/crowdsec/tailscale-whitelist.yaml"
    document = yaml.safe_load(whitelist.read_text())

    assert set(document["whitelist"]["cidr"]) == {"100.64.0.0/10", "fd7a:115c:a1e0::/48"}


async def test_two_servers_reporting_together_keep_their_own_posted_logins(sessions, service, chat, clock):
    import asyncio

    clock.now = NOON
    signals = Signals(sessions, service, clock)
    check = SshLoginCheck(
        sessions, signals, chat, clock, [HOST, "ops-server"], known_users=["root"], any_time_users=[], locale=EN
    )
    security = SecurityService(sessions, signals, clock, [check], locale=EN)
    odd = [login(NOON, user="mallory")]

    await asyncio.gather(
        security.ingest(report(HOST, "ssh", clock.now, logins=odd)),
        security.ingest(report("ops-server", "ssh", clock.now, logins=odd)),
    )
    await security.ingest(report(HOST, "ssh", clock.now, logins=odd))
    await security.ingest(report("ops-server", "ssh", clock.now, logins=odd))

    assert len(chat.ops) == 2  # one per server, none twice
