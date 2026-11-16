"""Backup check: the Postgres backups that Coolify makes, read from the Coolify API.

Coolify runs the dumps on its schedule and uploads them to S3; the local copies are pruned, so counting files on the
server says little. The API lists every run with status, size, time and whether it reached S3. Per database in
BACKUP_DATABASES (Coolify database UUIDs), every 30 minutes:

- no successful run for 26 hours, or no enabled schedule at all: P1 BackupTooOld
- the newest run failed: P2 BackupFailed
- the newest successful dump is under half the size of the one before: P2 BackupShrunk
- the newest successful dump did not reach S3: P2 BackupNotInS3
- the Coolify API cannot be read: P2 BackupCheckFailed, and the verdicts of the last good read stay
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Protocol

import httpx
from pydantic import AwareDatetime, BaseModel, SecretStr, ValidationError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.i18n import Locale
from app.security.base import CheckBase
from app.security.signals import Signal, Signals
from app.security.state import load_state, save_state

TOO_OLD = "BackupTooOld"
FAILED_RUN = "BackupFailed"
SHRUNK = "BackupShrunk"
NOT_IN_S3 = "BackupNotInS3"
CHECK_FAILED = "BackupCheckFailed"
STATE = "backups"
MAX_AGE = timedelta(hours=26)
# A dump at less than half the size of the one before is suspicious (a table missing, a dump cut short).
SHRINK_RATIO = 0.5
CHECK_EVERY = timedelta(minutes=30)


class Run(BaseModel):
    status: str
    size: int = 0
    created_at: AwareDatetime
    s3_uploaded: bool | None = None


@dataclass(frozen=True)
class Database:
    uuid: str
    name: str
    schedules: list[str]  # cron expressions of the enabled schedules
    runs: list[Run]  # newest first


class BackupError(Exception):
    pass


class BackupSource(Protocol):
    async def database(self, uuid: str) -> Database: ...


class CoolifyBackups:
    def __init__(self, client: httpx.AsyncClient, base_url: str, token: SecretStr, locale: Locale) -> None:
        self._locale = locale
        self._client = client
        self._base_url = base_url.rstrip("/")
        self._token = token

    async def _get(self, path: str) -> Any:
        try:
            response = await self._client.get(
                f"{self._base_url}/api/v1/{path}",
                headers={"Authorization": f"Bearer {self._token.get_secret_value()}"},
                timeout=20,
            )
            response.raise_for_status()
            return response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise BackupError(self._locale.t("security.backup.api_error", path=path, error=exc)) from exc

    async def database(self, uuid: str) -> Database:
        info = await self._get(f"databases/{uuid}")
        schedules = await self._get(f"databases/{uuid}/backups")
        if not isinstance(info, dict) or not isinstance(schedules, list):
            raise BackupError(self._locale.t("security.backup.api_unexpected"))
        enabled = [s for s in schedules if isinstance(s, dict) and s.get("enabled")]
        try:
            runs = [Run.model_validate(run) for s in enabled for run in s.get("executions") or []]
        except ValidationError as exc:
            raise BackupError(self._locale.t("security.backup.api_unreadable", n=exc.error_count())) from exc
        return Database(
            uuid=uuid,
            name=str(info.get("name") or uuid),
            schedules=[str(s.get("frequency", "")) for s in enabled],
            runs=sorted(runs, key=lambda r: r.created_at, reverse=True),
        )


def verdicts(locale: Locale, db: Database, now: datetime) -> dict[str, str]:
    """Alert name -> summary for everything that is wrong with this database's backups."""
    found: dict[str, str] = {}
    good = [run for run in db.runs if run.status == "success"]
    if not db.schedules:
        found[TOO_OLD] = locale.t("security.backup.no_schedule", name=db.name)
    elif not good:
        found[TOO_OLD] = locale.t("security.backup.no_success", name=db.name)
    elif now - good[0].created_at > MAX_AGE:
        found[TOO_OLD] = locale.t(
            "security.backup.too_old",
            name=db.name,
            age=locale.hours(now - good[0].created_at),
            limit=locale.hours(MAX_AGE),
        )
    if db.runs and db.runs[0].status != "success":
        found[FAILED_RUN] = locale.t("security.backup.failed_run", name=db.name, status=db.runs[0].status)
    if len(good) > 1 and good[0].size < good[1].size * SHRINK_RATIO:
        found[SHRUNK] = locale.t(
            "security.backup.shrunk", name=db.name, new=locale.size(good[0].size), old=locale.size(good[1].size)
        )
    if good and good[0].s3_uploaded is False:
        found[NOT_IN_S3] = locale.t("security.backup.not_in_s3", name=db.name)
    return found


SEVERITY = {TOO_OLD: "P1", FAILED_RUN: "P2", SHRUNK: "P2", NOT_IN_S3: "P2"}


class BackupCheck(CheckBase):
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        signals: Signals,
        clock: Callable[[], datetime],
        source: BackupSource | None,
        databases: list[str],
        *,
        locale: Locale,
        link: str = "",
    ) -> None:
        self._locale = locale
        self._sessions = sessions
        self._signals = signals
        self._clock = clock
        self._source = source
        self._databases = databases
        self._link = link
        self._checked_at: datetime | None = None

    async def periodic(self, now: datetime) -> None:
        if self._source is None or not self._databases:
            return
        if self._checked_at is not None and now - self._checked_at < CHECK_EVERY:
            return
        self._checked_at = now
        state: dict[str, Any] = {}
        for uuid in self._databases:
            scope = {"database": uuid}
            try:
                db = await self._source.database(uuid)
            except BackupError as exc:
                summary = self._locale.t("security.backup.check_failed", uuid=uuid, error=exc)
                await self._signals.set(CHECK_FAILED, "P2", scope, Signal(labels=scope, summary=summary[:500]))
                state[uuid] = {"error": str(exc)[:300]}
                continue
            await self._signals.set(CHECK_FAILED, "P2", scope, None)
            found = verdicts(self._locale, db, now)
            for name, severity in SEVERITY.items():
                signal = Signal(labels=scope, summary=found[name], link=self._link) if name in found else None
                await self._signals.set(name, severity, scope, signal)
            good = [run for run in db.runs if run.status == "success"]
            state[uuid] = {
                "name": db.name,
                "schedules": db.schedules,
                "newest": good[0].model_dump(mode="json") if good else None,
                "problems": sorted(found.values()),
            }
        async with self._sessions() as session, session.begin():
            await save_state(session, STATE, state, now)

    async def daily_lines(self, now: datetime) -> list[str]:
        if self._source is None or not self._databases:
            return [self._locale.t("security.backup.line.disabled")]
        async with self._sessions() as session:
            saved = await load_state(session, STATE)
        if saved is None or now - saved.updated_at > timedelta(hours=2):
            return [self._locale.t("security.backup.line.stale")]
        lines = []
        for uuid in self._databases:
            entry = saved.data.get(uuid)
            if entry is None:
                lines.append(self._locale.t("security.backup.line.unchecked", uuid=uuid))
            elif "error" in entry:
                lines.append(self._locale.t("security.backup.line.unreadable", uuid=uuid, error=entry["error"]))
            elif entry["newest"] is None:
                lines.append(self._locale.t("security.backup.line.no_success", name=entry["name"]))
            else:
                newest = Run.model_validate(entry["newest"])
                mark = ":red_circle: " if entry["problems"] else ""
                s3 = self._locale.t("security.backup.line.in_s3") if newest.s3_uploaded else ""
                lines.append(
                    self._locale.t(
                        "security.backup.line.ok",
                        mark=mark,
                        name=entry["name"],
                        size=self._locale.size(newest.size),
                        age=self._locale.hours(now - newest.created_at),
                        at=self._locale.day_time(newest.created_at),
                        s3=s3,
                    )
                )
                lines += [f"• {problem}" for problem in entry["problems"]]
        return lines
