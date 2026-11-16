"""CrowdSec bans and the review of SSH logins.

Kind `crowdsec` (daily): {"alerts": [{"scenario", "ip", "country", "at", "banned"}], "active_bans": n}.
Kind `ssh` (daily): {"logins": [{"at", "message": "Accepted publickey for root from 100.101.1.2 port 52144 ssh2..."}]}.

SSH is open only over Tailscale on both servers. A login is unusual when it comes from outside the Tailscale
network, by a user nobody expects, or at night (23:00 to 07:00 in the configured time zone) by anyone but the
pipeline's deploy user.
Each unusual login is posted once to the ops channel.
"""

import ipaddress
import logging
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, time, timedelta, tzinfo
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.i18n import Locale
from app.models import HostReport
from app.notify.base import ChatNotifier
from app.security import hostreports
from app.security.base import CheckBase, ReportKind
from app.security.signals import Signal, Signals
from app.security.state import load_state, save_state

log = logging.getLogger(__name__)

CROWDSEC = "crowdsec"
SSH = "ssh"
CROWDSEC_DOWN = "CrowdSecDown"
SSH_FAILED = "SshLogReadFailed"
REPORT_EVERY = timedelta(hours=26)
TAILSCALE = (ipaddress.ip_network("100.64.0.0/10"), ipaddress.ip_network("fd7a:115c:a1e0::/48"))
QUIET_FROM, QUIET_UNTIL = time(23, 0), time(7, 0)
POSTED_STATE = "ssh_posted"
POSTED_KEEP = timedelta(days=3)  # longer than the 25 h a report covers, so overlapping reports post nothing twice

_ACCEPTED = re.compile(r"^Accepted (\S+) for (\S+) from (\S+) port (\d+)")


@dataclass(frozen=True)
class Login:
    host: str
    at: datetime
    user: str
    source: str
    method: str

    @property
    def key(self) -> str:
        return f"{self.host}|{self.at.isoformat()}|{self.user}|{self.source}"


def parse_logins(host: str, data: dict[str, Any]) -> list[Login]:
    logins = []
    for entry in data.get("logins") or []:
        match = _ACCEPTED.match(str(entry.get("message", "")))
        if not match:
            continue
        try:
            at = datetime.fromisoformat(str(entry["at"]))
        except (KeyError, ValueError):
            continue
        method, user, source, _ = match.groups()
        logins.append(Login(host=host, at=at, user=user, source=source, method=method))
    return logins


def in_tailscale(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip in network for network in TAILSCALE)


def at_night(moment: datetime, tz: tzinfo) -> bool:
    local = moment.astimezone(tz).time()
    return local >= QUIET_FROM or local < QUIET_UNTIL


def why_unusual(locale: Locale, login: Login, known_users: set[str], any_time_users: set[str]) -> list[str]:
    reasons = []
    if not in_tailscale(login.source):
        reasons.append(locale.t("security.ssh.reason.outside"))
    if login.user not in known_users:
        reasons.append(locale.t("security.ssh.reason.unknown_user", user=login.user))
    if at_night(login.at, locale.tz) and login.user not in any_time_users:
        reasons.append(locale.t("security.ssh.reason.night"))
    return reasons


class SshLoginCheck(CheckBase):
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        signals: Signals,
        chat: ChatNotifier,
        clock: Callable[[], datetime],
        hosts: list[str],
        *,
        known_users: list[str],
        any_time_users: list[str],
        locale: Locale,
    ) -> None:
        self._locale = locale
        self._sessions = sessions
        self._signals = signals
        self._chat = chat
        self._clock = clock
        self._hosts = tuple(hosts)
        self._known = set(known_users)
        self._any_time = set(any_time_users)

    def report_kinds(self) -> list[ReportKind]:
        return [ReportKind(SSH, self._hosts, REPORT_EVERY)]

    async def on_report(self, report: HostReport) -> None:
        scope = {"host": report.host}
        if error := hostreports.error_of(report.data):
            summary = self._locale.t("security.ssh.failed", host=report.host, error=error)
            await self._signals.set(SSH_FAILED, "P2", scope, Signal(labels=scope, summary=summary))
            return
        await self._signals.set(SSH_FAILED, "P2", scope, None)

        now = self._clock()
        state_name = f"{POSTED_STATE}:{report.host}"  # one row per server: reports of two servers arrive together
        async with self._sessions() as session:
            state = await load_state(session, state_name)
        posted: dict[str, str] = dict(state.data) if state else {}
        for login in parse_logins(report.host, report.data):
            reasons = why_unusual(self._locale, login, self._known, self._any_time)
            if not reasons or login.key in posted:
                continue
            text = self._locale.t(
                "security.ssh.post",
                host=login.host,
                user=login.user,
                source=login.source,
                method=login.method,
                at=self._locale.day_time(login.at),
                reasons=", ".join(reasons),
            )
            try:
                await self._chat.post_ops(text)
            except Exception:
                log.exception("posting an unusual SSH login failed, retrying with the next report")
                continue
            posted[login.key] = now.isoformat()
        cutoff = now - POSTED_KEEP
        posted = {key: at for key, at in posted.items() if datetime.fromisoformat(at) >= cutoff}
        async with self._sessions() as session, session.begin():
            await save_state(session, state_name, posted, now)

    async def weekly_lines(self, now: datetime) -> list[str]:
        if not self._hosts:
            return []
        async with self._sessions() as session:
            rows = await hostreports.history(session, SSH, now - timedelta(days=7))
        lines = []
        for host in self._hosts:
            reports = [row for row in rows if row.host == host and not hostreports.error_of(row.data)]
            if not reports:
                lines.append(self._locale.t("security.ssh.line.no_data", host=host))
                continue
            logins = {login.key: login for row in reports for login in parse_logins(host, row.data)}.values()
            unusual = [login for login in logins if why_unusual(self._locale, login, self._known, self._any_time)]
            users = Counter(login.user for login in logins)
            who = ", ".join(f"{user} {count}x" for user, count in users.most_common()) or self._locale.t(
                "security.ssh.line.none"
            )
            lines.append(
                self._locale.t("security.ssh.line.summary", host=host, n=len(logins), who=who, unusual=len(unusual))
            )
        return lines


class CrowdSecCheck(CheckBase):
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        signals: Signals,
        clock: Callable[[], datetime],
        hosts: list[str],
        *,
        locale: Locale,
    ) -> None:
        self._locale = locale
        self._sessions = sessions
        self._signals = signals
        self._clock = clock
        self._hosts = tuple(hosts)

    def report_kinds(self) -> list[ReportKind]:
        return [ReportKind(CROWDSEC, self._hosts, REPORT_EVERY)]

    async def on_report(self, report: HostReport) -> None:
        scope = {"host": report.host}
        signal = None
        if error := hostreports.error_of(report.data):
            signal = Signal(
                labels=scope, summary=self._locale.t("security.crowdsec.failed", host=report.host, error=error)
            )
        await self._signals.set(CROWDSEC_DOWN, "P2", scope, signal)

    async def weekly_lines(self, now: datetime) -> list[str]:
        if not self._hosts:
            return [self._locale.t("security.crowdsec.line.no_hosts")]
        async with self._sessions() as session:
            rows = await hostreports.history(session, CROWDSEC, now - timedelta(days=7))
        lines = []
        for host in self._hosts:
            reports = [row for row in rows if row.host == host]
            good = [row for row in reports if not hostreports.error_of(row.data)]
            if not good:
                lines.append(self._locale.t("security.crowdsec.line.no_data", host=host))
                continue
            if len(good) < len(reports):
                lines.append(
                    self._locale.t("security.crowdsec.line.unreachable", host=host, n=len(reports) - len(good))
                )
            seen: dict[tuple[str, str, str], dict[str, Any]] = {}
            for row in good:
                for alert in row.data.get("alerts") or []:
                    seen[(alert.get("scenario", ""), alert.get("ip", ""), alert.get("at", ""))] = alert
            alerts = list(seen.values())
            banned = sum(1 for a in alerts if a.get("banned"))
            ips = len({a.get("ip") for a in alerts})
            scenarios = Counter(str(a.get("scenario", "")).split("/")[-1] for a in alerts)
            top = ", ".join(f"{name} {count}x" for name, count in scenarios.most_common(5))
            active = good[-1].data.get("active_bans", 0)
            text = self._locale.t("security.crowdsec.line.summary", host=host, n=len(alerts), ips=ips, banned=banned)
            text += self._locale.t("security.crowdsec.line.active", n=active)
            lines.append(text + (f"; {top}" if top else ""))
        return lines
