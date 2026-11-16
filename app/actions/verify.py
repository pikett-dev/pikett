"""The health check after an action.

After every finished job the ops service checks the health URLs of its server. Green: done. Red for longer than the
grace period of the runbook (5 minutes, 10 for a reboot): a P1 `ActionHealthRed` with the rollback hint of the runbook,
which closes again when the URLs answer. A server without URLs is not checked and the history says so.
"""

import asyncio
import logging
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Protocol

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.actions.service import ActionService
from app.agent.masking import Masker
from app.i18n import Locale
from app.models import ActionJob
from app.security.signals import Signal, Signals
from runner.catalog import CatalogError

log = logging.getLogger(__name__)

ALERT = "ActionHealthRed"
SYSTEM = "system"
DETAIL_MAX = 500
# A restart or rollback is only queued when the runner reports it: the old container may still answer. A green check
# counts only this long after the result (a rollback needs longer than a restart).
SETTLE = timedelta(seconds=90)
SETTLE_BY_RUNBOOK = {"redeploy_previous": timedelta(minutes=4)}


class Health(Protocol):
    async def failures(self, urls: list[str]) -> list[str]:
        """What is not healthy: one text per URL that did not answer 2xx (empty: all green)."""
        ...


class HttpHealth:
    def __init__(self, client: httpx.AsyncClient) -> None:
        self._client = client

    async def _one(self, url: str) -> str | None:
        try:
            response = await self._client.get(url, timeout=10, follow_redirects=False)
        except httpx.HTTPError as error:
            return f"{url}: {type(error).__name__}"
        return None if 200 <= response.status_code < 300 else f"{url}: {response.status_code}"

    async def failures(self, urls: list[str]) -> list[str]:
        return [text for text in await asyncio.gather(*(self._one(u) for u in urls)) if text]


class ActionVerifier:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        jobs: ActionService,
        signals: Signals,
        health: Health,
        urls: dict[str, list[str]],
        clock: Callable[[], datetime],
        *,
        locale: Locale,
    ) -> None:
        self._locale = locale
        self._sessions, self._jobs, self._signals = sessions, jobs, signals
        self._health, self._urls, self._clock = health, urls, clock

    async def tick(self) -> None:
        async with self._sessions() as session:
            ids = list(
                await session.scalars(
                    select(ActionJob.id).where(ActionJob.verify_status.in_(("pending", "red"))).order_by(ActionJob.id)
                )
            )
        # Concurrently: slow health URLs of one server must not hold up the others (or the rest of the tick).
        await asyncio.gather(*(self._guarded(job_id) for job_id in ids))

    async def _guarded(self, job_id: int) -> None:
        try:
            await self._verify(job_id)
        except Exception:
            log.exception("verifying job %s failed", job_id)

    async def _verify(self, job_id: int) -> None:
        now = self._clock()
        async with self._sessions() as session:
            job = await session.get(ActionJob, job_id)
            if job is None or job.verify_status not in ("pending", "red"):
                return
        # The row is detached but loaded (the session factory keeps values after the block), so it is read below.
        host, status, until = job.host, job.verify_status, job.verify_until
        if (
            status == "pending"
            and job.finished_at is not None
            and now < job.finished_at + SETTLE_BY_RUNBOOK.get(job.runbook, SETTLE)
        ):
            return
        urls = self._urls.get(host, [])
        failures = await self._health.failures(urls) if urls else []
        detail = Masker().mask("; ".join(failures))[:DETAIL_MAX]
        scope = {"host": host}  # one incident per server, whichever action it followed
        if not urls:
            await self._set(job_id, "skipped", self._locale.t("actions.verify_detail.skipped"), status)
            if status == "red":
                await self._signals.set(ALERT, "P1", scope, None)
        elif not failures:
            new = "ok" if status == "pending" else "recovered"
            await self._set(job_id, new, self._locale.t("actions.verify_detail.ok"), status)
            if status == "red":
                await self._signals.set(ALERT, "P1", scope, None)
        elif status == "pending" and (until is None or now >= until):
            hint = self._rollback_hint(job.runbook)
            summary = self._locale.t(
                "actions.verify_red_summary", runbook=job.runbook, host=host, detail=detail, hint=hint
            )
            await self._set(job_id, "red", detail, "pending")
            await self._signals.set(ALERT, "P1", scope, Signal(labels=scope, summary=summary))
        elif status == "pending":
            await self._set(job_id, "pending", detail, "pending")  # not yet green, still inside the grace period

    def _rollback_hint(self, runbook: str) -> str:
        try:
            return self._jobs.catalog.get(runbook).text("rollback", self._locale.language)
        except CatalogError:  # no longer in the catalog
            return self._locale.t("actions.rollback_fallback")

    async def _set(self, job_id: int, new: str, detail: str, expected: str) -> None:
        async with self._sessions() as session, session.begin():
            job = await session.get(ActionJob, job_id, with_for_update=True)
            if job is None or job.verify_status != expected:
                return
            changed = job.verify_status != new
            job.verify_status, job.verify_detail = new, detail
            if changed:
                self._jobs.audit(session, job, self._clock(), f"verify_{new}", SYSTEM, detail)
