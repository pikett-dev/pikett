"""CrowdSec bans and the review of SSH logins.

Kind `crowdsec` (daily): {"alerts": [{"scenario", "ip", "country", "at", "banned"}], "active_bans": n}.
Kind `ssh` (daily): {"logins": [{"at", "message": "Accepted publickey for root from 100.101.1.2 port 52144 ssh2..."}]}.

For a server without known keys a login is unusual when it comes from outside the Tailscale network, by a user
nobody expects, or at night (23:00 to 07:00 in the configured time zone) by anyone but the pipeline's deploy user.
For a server with known keys (fingerprint, user, source networks) a login is usual exactly when it matches one, at
any time of day, and unusual otherwise. Unusual logins are posted once per report and server as one message, grouped
by source, user and key. A login with an unknown key, or with a known key from the wrong user or network, is posted
as its own message per group (at most five, the rest in one more).
"""

import ipaddress
import logging
import re
from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, time, timedelta, tzinfo
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.config import KnownSshKey
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
MAX_LINES = 10  # groups listed in one message; a scan from many addresses must not flood the channel
MAX_KEY_MESSAGES = 5  # key problems posted on their own per report; the rest go into one message
POSTED_STATE = "ssh_posted"
POSTED_KEEP = timedelta(days=3)  # longer than the 25 h a report covers, so overlapping reports post nothing twice

# "Accepted publickey for root from 10.0.1.4 port 52144 ssh2: ED25519 SHA256:abc"; password logins have no key.
_ACCEPTED = re.compile(r"^Accepted (\S+) for (\S+) from (\S+) port (\d+)(?: ssh2: \S+ (SHA256:\S+))?")


@dataclass(frozen=True)
class Login:
    host: str
    at: datetime
    user: str
    source: str
    method: str
    fingerprint: str | None = None

    @property
    def key(self) -> str:
        return f"{self.host}|{self.at.isoformat()}|{self.user}|{self.source}|{self.fingerprint or ''}"


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
        method, user, source, _, fingerprint = match.groups()
        logins.append(Login(host=host, at=at, user=user, source=source, method=method, fingerprint=fingerprint))
    return logins


def in_networks(address: str, networks: Iterable[ipaddress.IPv4Network | ipaddress.IPv6Network]) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip in network for network in networks)


def in_tailscale(address: str) -> bool:
    return in_networks(address, TAILSCALE)


def at_night(moment: datetime, tz: tzinfo) -> bool:
    local = moment.astimezone(tz).time()
    return local >= QUIET_FROM or local < QUIET_UNTIL


@dataclass(frozen=True)
class Verdict:
    reasons: tuple[str, ...]
    key_problem: bool  # an unknown key, or a known key used by the wrong user or from the wrong network

    @property
    def unusual(self) -> bool:
        return bool(self.reasons)


def judge(
    locale: Locale,
    login: Login,
    known_keys: dict[str, KnownSshKey],
    known_users: set[str],
    any_time_users: set[str],
) -> Verdict:
    reasons = []
    key_problem = False
    if known_keys:
        key = known_keys.get(login.fingerprint or "")
        if key is None:
            key_problem = True
            fingerprint = login.fingerprint or locale.t("security.ssh.key.none")
            reasons.append(locale.t("security.ssh.reason.unknown_key", fingerprint=fingerprint))
        elif login.user != key.user or not in_networks(login.source, key.networks):
            key_problem = True
            networks = ", ".join(str(n) for n in key.networks)
            reasons.append(
                locale.t("security.ssh.reason.key_misused", label=key.label, user=key.user, networks=networks)
            )
        else:
            return Verdict((), False)
    if not in_tailscale(login.source):
        reasons.append(locale.t("security.ssh.reason.outside"))
    if login.user not in known_users:
        reasons.append(locale.t("security.ssh.reason.unknown_user", user=login.user))
    if at_night(login.at, locale.tz) and login.user not in any_time_users:
        reasons.append(locale.t("security.ssh.reason.night"))
    return Verdict(tuple(reasons), key_problem)


def describe_groups(locale: Locale, logins: list[Login], verdicts: dict[str, Verdict]) -> str:
    """One line per source, user and key with the number of logins and the period they cover."""
    groups: dict[tuple[str, str, str, str], list[Login]] = {}
    for login in logins:
        groups.setdefault(
            (login.source, login.user, login.fingerprint or locale.t("security.ssh.key.none"), login.method), []
        ).append(login)
    lines = []
    for (source, user, fingerprint, method), members in groups.items():
        first, last = min(m.at for m in members), max(m.at for m in members)
        period = locale.day_time(first)
        if last != first:
            period = locale.t("security.ssh.group.range", first=period, last=locale.day_time(last))
        reasons = ", ".join(dict.fromkeys(r for m in members for r in verdicts[m.key].reasons))
        lines.append(
            locale.t(
                "security.ssh.group.line",
                user=user,
                source=source,
                method=method,
                fingerprint=fingerprint,
                n=len(members),
                period=period,
                reasons=reasons,
            )
        )
    if len(lines) > MAX_LINES:
        lines = [*lines[:MAX_LINES], locale.t("security.ssh.group.more", n=len(lines) - MAX_LINES)]
    return "\n".join(lines)


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
        known_keys: Sequence[KnownSshKey] = (),
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
        self._known_keys = tuple(known_keys)

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
        keys = self._keys_for(report.host)
        verdicts: dict[str, Verdict] = {}
        fresh: list[Login] = []
        for login in parse_logins(report.host, report.data):
            verdict = judge(self._locale, login, keys, self._known, self._any_time)
            if verdict.unusual and login.key not in posted:
                verdicts[login.key] = verdict
                fresh.append(login)
        for text, logins in self._messages(report.host, fresh, verdicts):
            try:
                await self._chat.post_ops(text)
            except Exception:
                log.exception("posting unusual SSH logins failed, retrying with the next report")
                continue
            posted.update({login.key: now.isoformat() for login in logins})
        cutoff = now - POSTED_KEEP
        posted = {key: at for key, at in posted.items() if datetime.fromisoformat(at) >= cutoff}
        async with self._sessions() as session, session.begin():
            await save_state(session, state_name, posted, now)

    def _messages(self, host: str, fresh: list[Login], verdicts: dict[str, Verdict]) -> list[tuple[str, list[Login]]]:
        """Key problems go out per source, user and key; everything else unusual is one message per server."""
        by_key: dict[tuple[str, str, str | None], list[Login]] = {}
        for login in fresh:
            if verdicts[login.key].key_problem:
                by_key.setdefault((login.source, login.user, login.fingerprint), []).append(login)
        groups = list(by_key.values())
        overflow = [login for members in groups[MAX_KEY_MESSAGES:] for login in members]
        messages = [
            (self._locale.t("security.ssh.post.key", host=host, lines=describe_groups(self._locale, m, verdicts)), m)
            for m in groups[:MAX_KEY_MESSAGES]
        ]
        if overflow:
            lines = describe_groups(self._locale, overflow, verdicts)
            messages.append((self._locale.t("security.ssh.post.key_more", host=host, lines=lines), overflow))
        rest = [login for login in fresh if not verdicts[login.key].key_problem]
        if rest:
            lines = describe_groups(self._locale, rest, verdicts)
            messages.append((self._locale.t("security.ssh.post.unusual", host=host, n=len(rest), lines=lines), rest))
        return messages

    def _keys_for(self, host: str) -> dict[str, KnownSshKey]:
        """The keys that apply to this server; none means the judgement by network, user and time."""
        return {key.fingerprint: key for key in self._known_keys if not key.hosts or host in key.hosts}

    @staticmethod
    def _who(login: Login, keys: dict[str, KnownSshKey]) -> str:
        key = keys.get(login.fingerprint or "")
        if key and key.user == login.user and in_networks(login.source, key.networks):
            return f"{login.user} ({key.label})"
        return login.user

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
            keys = self._keys_for(host)
            unusual = [
                login for login in logins if judge(self._locale, login, keys, self._known, self._any_time).unusual
            ]
            users = Counter(self._who(login, keys) for login in logins)
            who = ", ".join(f"{name} {count}x" for name, count in users.most_common()) or self._locale.t(
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
