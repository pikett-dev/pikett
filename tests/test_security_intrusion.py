from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from app.config import KnownSshKey, Settings
from app.security.intrusion import CrowdSecCheck, SshLoginCheck, in_tailscale, parse_logins
from app.security.service import SecurityService
from app.security.signals import Signals
from tests.fakes import DE, EN
from tests.security_helpers import open_incidents, report

HOST = "app-1"
NOON = datetime(2026, 11, 14, 11, 0, tzinfo=UTC)  # 12:00 Vienna


BACKUP, ADMIN, PIPELINE = "SHA256:backupkey", "SHA256:adminkey", "SHA256:pipelinekey"
KEYS = [
    KnownSshKey(label="backup", fingerprint=BACKUP, user="root", networks=["10.0.1.0/24"]),
    KnownSshKey(label="admin", fingerprint=ADMIN, user="root", networks=["100.64.0.0/10"]),
    KnownSshKey(label="pipeline", fingerprint=PIPELINE, user="deploy", networks=["198.51.100.10/32"]),
]


def login(at: datetime, user: str = "root", source: str = "100.101.1.2", key: str = "SHA256:x") -> dict:
    return {
        "at": at.isoformat(),
        "message": f"Accepted publickey for {user} from {source} port 52144 ssh2: ED25519 {key}",
    }


def build(sessions, service, chat, clock, locale=EN, keys=(), hosts=(HOST,)):
    clock.now = NOON
    signals = Signals(sessions, service, clock)
    check = SshLoginCheck(
        sessions, signals, chat, clock, list(hosts),
        known_users=["root", "deploy"], any_time_users=["deploy"], known_keys=keys, locale=locale,
    )  # fmt: skip
    return SecurityService(sessions, signals, clock, [check], locale=locale)


@pytest.fixture
def keyed(sessions, service, chat, clock):
    return build(sessions, service, chat, clock, keys=KEYS)


@pytest.fixture
def keyed_de(sessions, service, chat, clock):
    return build(sessions, service, chat, clock, locale=DE, keys=KEYS)


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
    assert parsed.fingerprint == "SHA256:x"


def test_a_password_login_has_no_fingerprint():
    entry = {"at": NOON.isoformat(), "message": "Accepted password for root from 203.0.113.7 port 22 ssh2"}

    [parsed] = parse_logins(HOST, {"logins": [entry]})

    assert parsed.fingerprint is None


def test_tailscale_ranges():
    assert in_tailscale("100.64.0.1") and in_tailscale("100.127.255.254") and in_tailscale("fd7a:115c:a1e0::1")
    assert not in_tailscale("100.128.0.1") and not in_tailscale("203.0.113.7") and not in_tailscale("nonsense")


async def test_unusual_logins_are_one_message_per_report_and_posted_once(security, chat, clock):
    night = datetime(2026, 11, 14, 1, 30, tzinfo=UTC)  # 02:30 Vienna
    logins = [
        login(NOON),  # usual
        login(night, user="deploy"),  # the pipeline may deploy at night
        login(night),  # root at night
        login(NOON, source="203.0.113.7"),  # outside Tailscale
        login(NOON, user="mallory"),  # unknown user
    ]
    await security.ingest(report(HOST, "ssh", clock.now, logins=logins))

    [text] = chat.ops
    assert "Unusual SSH logins on *app-1* (3)" in text
    assert "root from 100.101.1.2 (publickey, `SHA256:x`): 1x, Nov 14 02:30; at night" in text
    assert "from outside Tailscale" in text
    assert "unknown user mallory" in text

    clock.advance(timedelta(hours=24))  # the next report covers an hour of the same logins
    await security.ingest(report(HOST, "ssh", clock.now, logins=logins))
    assert len(chat.ops) == 1


async def test_sixteen_admin_logins_from_outside_are_one_message(security, chat, clock):
    logins = [login(NOON + timedelta(minutes=i), source="203.0.113.66", key=ADMIN) for i in range(16)]

    await security.ingest(report(HOST, "ssh", clock.now, logins=logins))

    [text] = chat.ops
    assert "(16)" in text
    assert "root from 203.0.113.66 (publickey, `SHA256:adminkey`): 16x, Nov 14 12:00 to Nov 14 12:15" in text


async def test_known_keys_from_their_own_network_are_not_reported(keyed, chat, clock):
    night = datetime(2026, 11, 14, 1, 30, tzinfo=UTC)
    logins = [
        login(night, source="10.0.1.4", key=BACKUP),  # backup job at 04:00 in the Docker network
        login(night, source="10.0.1.10", key=BACKUP),
        login(night, user="deploy", source="198.51.100.10", key=PIPELINE),  # the pipeline
        login(NOON, key=ADMIN),  # the admin over Tailscale
    ]

    await keyed.ingest(report(HOST, "ssh", clock.now, logins=logins))

    assert chat.ops == []


async def test_an_unknown_key_is_reported_on_its_own(keyed, chat, clock):
    logins = [login(NOON, key="SHA256:stranger"), login(NOON + timedelta(minutes=1), key="SHA256:stranger")]
    logins.append(login(NOON, source="100.101.1.9", key="SHA256:other"))

    await keyed.ingest(report(HOST, "ssh", clock.now, logins=logins))

    assert len(chat.ops) == 2  # one per source and key, not per login
    assert all(":rotating_light:" in text and "unknown key" in text for text in chat.ops)
    assert "2x" in chat.ops[0]


async def test_a_known_key_from_the_wrong_network_or_user_is_reported_on_its_own(keyed, chat, clock):
    logins = [
        login(NOON, source="203.0.113.7", key=BACKUP),  # the backup key from the internet
        login(NOON, user="deploy", key=ADMIN),  # the admin key as another user
    ]

    await keyed.ingest(report(HOST, "ssh", clock.now, logins=logins))

    assert len(chat.ops) == 2
    assert "key backup is only allowed for root from 10.0.1.0/24" in chat.ops[0]
    assert "key admin is only allowed for root from 100.64.0.0/10" in chat.ops[1]


async def test_a_login_without_a_key_is_unknown_once_keys_are_configured(keyed, chat, clock):
    entry = {"at": NOON.isoformat(), "message": "Accepted password for root from 100.101.1.2 port 22 ssh2"}

    await keyed.ingest(report(HOST, "ssh", clock.now, logins=[entry]))

    assert "unknown key (no key)" in chat.ops[0]


async def test_the_weekly_report_names_known_keys(keyed, clock):
    logins = [login(NOON, source="10.0.1.4", key=BACKUP), login(NOON, source="10.0.1.4", key=BACKUP)]
    await keyed.ingest(report(HOST, "ssh", clock.now, logins=[*logins, login(NOON, key="SHA256:stranger")]))

    lines = await keyed.weekly_lines(clock.now)

    assert any("root (backup) 1x" in line and "1 of them unusual" in line for line in lines)


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


def test_a_bad_known_key_entry_is_rejected_at_startup():
    with pytest.raises(ValueError):
        KnownSshKey(label="x", fingerprint="kBzfZTZR", user="root", networks=["100.64.0.0/10"])
    with pytest.raises(ValueError):
        KnownSshKey(label="x", fingerprint="SHA256:abc", user="root", networks=["not-a-network"])


def test_the_same_fingerprint_twice_is_rejected():
    key = {"label": "a", "fingerprint": "SHA256:abc", "user": "root", "networks": ["100.64.0.0/10"]}
    with pytest.raises(ValueError, match="every fingerprint"):
        Settings(ssh_known_keys=[key, key], _env_file=None)


async def test_two_logins_of_one_second_with_different_keys_are_both_judged(keyed, chat, clock):
    logins = [login(NOON, key=ADMIN), login(NOON, key="SHA256:stranger")]

    await keyed.ingest(report(HOST, "ssh", clock.now, logins=logins))

    [text] = chat.ops
    assert "stranger" in text


async def test_a_group_lists_the_reasons_of_all_its_logins(security, chat, clock):
    night = datetime(2026, 11, 14, 1, 30, tzinfo=UTC)
    logins = [login(NOON, source="203.0.113.7"), login(night, source="203.0.113.7")]

    await security.ingest(report(HOST, "ssh", clock.now, logins=logins))

    assert "from outside Tailscale, at night" in chat.ops[0]


async def test_keys_of_another_server_do_not_make_this_server_strict(sessions, service, chat, clock):
    only_test = [KnownSshKey(label="admin", fingerprint=ADMIN, user="root", networks=["100.64.0.0/10"], hosts=[HOST])]
    security = build(sessions, service, chat, clock, keys=only_test, hosts=(HOST, "ops-server"))

    await security.ingest(report("ops-server", "ssh", clock.now, logins=[login(NOON, key="SHA256:other")]))
    assert chat.ops == []  # no keys listed for ops-server: judged by network, user and time
    await security.ingest(report(HOST, "ssh", clock.now, logins=[login(NOON, key="SHA256:other")]))
    assert len(chat.ops) == 1


async def test_many_unknown_sources_do_not_flood_the_channel(keyed, chat, clock):
    logins = [login(NOON, source=f"203.0.113.{i}", key=f"SHA256:k{i}") for i in range(1, 21)]

    await keyed.ingest(report(HOST, "ssh", clock.now, logins=logins))

    assert len(chat.ops) == 6  # five on their own, the rest in one message of at most ten groups
    assert "and 5 more groups" in chat.ops[5]


async def test_a_german_deployment_gets_german_messages(keyed_de, chat, clock):
    logins = [
        login(NOON, source="203.0.113.7", key=BACKUP),
        login(NOON, source="203.0.113.8", key="SHA256:stranger"),
        login(NOON + timedelta(minutes=5), source="203.0.113.8", key="SHA256:stranger"),
        login(NOON, user="mallory", source="100.101.1.2", key=ADMIN),
    ]

    await keyed_de.ingest(report(HOST, "ssh", clock.now, logins=logins))

    assert "Schlüssel backup nur für root aus 10.0.1.0/24 erlaubt" in chat.ops[0]
    assert "unbekannter Schlüssel SHA256:stranger" in chat.ops[1]
    assert "2x, 14.11. 12:00 bis 14.11. 12:05" in chat.ops[1]
    assert chat.ops[1].endswith("Das sollte jemand prüfen.")


async def test_german_grouped_message_and_overflow(sessions, service, chat, clock):
    security = build(sessions, service, chat, clock, locale=DE)
    logins = [login(NOON, source=f"203.0.113.{i}") for i in range(1, 13)]

    await security.ingest(report(HOST, "ssh", clock.now, logins=logins))

    [text] = chat.ops
    assert text.startswith(":eyes: Ungewöhnliche SSH-Anmeldungen auf *app-1* (12):")
    assert "• und 2 weitere Gruppen" in text
    assert text.endswith("Wart ihr das?")


async def test_a_german_login_without_a_key_names_it(keyed_de, chat, clock):
    entry = {"at": NOON.isoformat(), "message": "Accepted password for root from 100.101.1.2 port 22 ssh2"}

    await keyed_de.ingest(report(HOST, "ssh", clock.now, logins=[entry]))

    assert "unbekannter Schlüssel (ohne Schlüssel)" in chat.ops[0]


async def test_a_failed_post_is_retried_with_the_next_report_without_reposting_the_rest(keyed, chat, clock):
    logins = [login(NOON, source="203.0.113.7", key="SHA256:a"), login(NOON, source="203.0.113.8", key="SHA256:b")]
    real, calls = chat.post_ops, []

    async def flaky(text: str) -> None:
        calls.append(text)
        if len(calls) == 1:
            raise RuntimeError("slack is down")
        await real(text)

    chat.post_ops = flaky
    await keyed.ingest(report(HOST, "ssh", clock.now, logins=logins))
    assert len(chat.ops) == 1  # the first group failed, the second went out

    await keyed.ingest(report(HOST, "ssh", clock.now, logins=logins))
    assert len(chat.ops) == 2  # the failed one is posted now, the other not again
    assert "203.0.113.7" in chat.ops[1]


def test_a_known_key_naming_an_unlisted_server_is_rejected():
    key = {"label": "a", "fingerprint": "SHA256:abc", "user": "root", "networks": ["100.64.0.0/10"], "hosts": ["app1"]}
    with pytest.raises(ValueError, match="not in security_hosts"):
        Settings(ssh_known_keys=[key], security_hosts=["app-1"], _env_file=None)


async def test_the_weekly_report_does_not_label_a_known_key_from_the_wrong_network(keyed, clock):
    await keyed.ingest(report(HOST, "ssh", clock.now, logins=[login(NOON, source="203.0.113.7", key=BACKUP)]))

    lines = await keyed.weekly_lines(clock.now)

    assert any("root 1x" in line and "(backup)" not in line for line in lines)
