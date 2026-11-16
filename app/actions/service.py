"""Jobs for the ops-runner: proposal, approval, one-time delivery, result and the audit log.

Rules that hold here, not in the callers:
- A job reaches a runner at most once: delivery is one `FOR UPDATE SKIP LOCKED` claim inside a transaction.
- Only an approved job that has not expired is delivered. A job is valid for 15 minutes from its creation; the
  approval, the delivery and the start all have to happen in that time.
- Every state change writes a row to the audit log in the same transaction.
- A runner may only claim, start and finish jobs of its own server.
"""

import logging
import secrets
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import exists, func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import aliased

from app.agent.masking import Masker
from app.i18n import Locale
from app.models import ActionAudit, ActionJob, RebootRequest, RunnerHeartbeat
from runner.catalog import Catalog, CatalogError
from runner.jobs import format_time, sign_job

log = logging.getLogger(__name__)

VALID_FOR = timedelta(minutes=15)
SUMMARY_MAX = 2000
RUN_LIMIT = timedelta(minutes=45)  # a started job without a result after this long is lost (the runner died)
SYSTEM = "system"
MIN_TIME_TO_RUN = timedelta(minutes=1)  # an approval later than this before the expiry would leave no time to run
BEFORE_START = ("proposed", "approved", "delivered")
RESULTS = ("succeeded", "failed", "rejected")
# How long a red health check after an action may last before it is a P1: a restart or a deploy needs a moment, a
# reboot a few minutes.
VERIFY_GRACE = {"health": timedelta(minutes=5), "reboot": timedelta(minutes=10)}


class ActionError(Exception):
    """A request that cannot be carried out; the message is meant for the person or runner who asked."""


class DuplicateJob(ActionError):
    """This reboot request has a job already (one job per approval)."""


class ActionService:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        clock: Callable[[], datetime],
        catalog: Catalog,
        signing_key: Ed25519PrivateKey | None,
        hosts: set[str],
        applications: dict[str, dict[str, str]] | None = None,
        *,
        locale: Locale,
    ) -> None:
        self._locale = locale
        self.applications = applications or {}  # host -> {Coolify application UUID: name}
        self._sessions = sessions
        self._clock = clock
        self.catalog = catalog
        self._key = signing_key
        self.hosts = hosts  # servers that have a runner token; jobs for any other server are refused

    @staticmethod
    def audit(session: AsyncSession, job: ActionJob, at: datetime, event: str, actor: str, detail: str = "") -> None:
        session.add(ActionAudit(job_id=job.id, at=at, event=event, actor=actor, detail=detail[:500]))

    async def propose(
        self,
        runbook: str,
        params: dict[str, Any],
        host: str,
        requested_by: str,
        *,
        incident_id: int | None = None,
        reboot_request_id: int | None = None,
        analysis_id: int | None = None,
        approved_by: str | None = None,
    ) -> ActionJob:
        """A new job. With `approved_by` (the reboot that was approved in Slack) it starts approved."""
        try:
            book = self.catalog.get(runbook)
            params = book.validate_params(params)
        except CatalogError as error:
            raise ActionError(str(error)) from error
        if host not in self.hosts or not book.allows_host(host):
            raise ActionError(f"{runbook} cannot run on {host}")
        if "application" in params and str(params["application"]) not in self.applications.get(host, {}):
            raise ActionError("this application is not on the list of applications for that server")
        if not book.proposable and requested_by != SYSTEM:  # the reboot exists only from its Slack approval
            raise ActionError(f"{runbook} is created by the ops service itself, not proposed")
        now = self._clock()
        job = ActionJob(
            action_id=secrets.token_urlsafe(24),
            runbook=runbook,
            params=params,
            host=host,
            status="approved" if approved_by else "proposed",
            requested_by=requested_by,
            created_at=now,
            expires_at=now + VALID_FOR,
            approved_by=approved_by,
            approved_at=now if approved_by else None,
            incident_id=incident_id,
            reboot_request_id=reboot_request_id,
            analysis_id=analysis_id,
        )
        try:
            async with self._sessions() as session, session.begin():
                session.add(job)
                await session.flush()
                self.audit(session, job, now, "created", requested_by, f"{runbook} {params} on {host}")
                if approved_by:
                    self.audit(session, job, now, "approved", approved_by, "approved when the job was created")
        except IntegrityError as error:
            if not any(name in str(error.orig) for name in ("ux_action_job_reboot", "ux_action_job_analysis")):
                raise
            raise DuplicateJob("there is already a job for this reboot request or analysis") from error
        return job

    async def approve(self, action_id: str, user_id: str) -> str | None:
        """An approval. The caller checks the allow-list first. Returns an error text, or None when it worked."""
        now = self._clock()
        async with self._sessions() as session, session.begin():
            job = await session.scalar(select(ActionJob).where(ActionJob.action_id == action_id).with_for_update())
            if job is None:
                return self._locale.t("errors.approval_unknown")
            if job.status != "proposed":
                return self._locale.t("errors.approval_done")
            if now >= job.expires_at - MIN_TIME_TO_RUN:
                job.status = "expired"
                self.audit(session, job, now, "expired", SYSTEM, "too late to approve")
                return self._locale.t("errors.approval_expired")
            job.status, job.approved_by, job.approved_at = "approved", user_id, now
            self.audit(session, job, now, "approved", user_id)
        return None

    async def heartbeat(self, host: str, version: str = "", catalog: str = "") -> None:
        values = {"last_seen_at": self._clock(), "version": version, "catalog": catalog}
        async with self._sessions() as session, session.begin():
            await session.execute(
                insert(RunnerHeartbeat)
                .values(host=host, **values)
                .on_conflict_do_update(index_elements=[RunnerHeartbeat.host], set_=values)
            )

    async def _touch(self, host: str) -> None:
        """A started job or a result is a sign of life of the runner too: it does not poll while it works."""
        async with self._sessions() as session, session.begin():
            await session.execute(
                update(RunnerHeartbeat).where(RunnerHeartbeat.host == host).values(last_seen_at=self._clock())
            )

    async def claim(self, host: str) -> dict[str, Any] | None:
        """The next approved job of this server as a signed envelope, or None. Each job is delivered once."""
        if self._key is None:
            raise ActionError("signing is not configured (RUNNER_SIGNING_KEY)")
        now = self._clock()
        async with self._sessions() as session, session.begin():
            # One claim per server at a time, so "nothing else runs on this server" below cannot race.
            await session.execute(select(func.pg_advisory_xact_lock(func.hashtext(f"action_claim:{host}"))))
            busy = aliased(ActionJob)
            job = await session.scalar(
                select(ActionJob)
                .where(
                    ActionJob.host == host,
                    ActionJob.status == "approved",
                    ActionJob.expires_at > now,
                    # Two runbooks on one server at the same time (a reboot during a restart) are never wanted.
                    ~exists().where(busy.host == host, busy.status.in_(("delivered", "running"))),
                )
                .order_by(ActionJob.id)
                .limit(1)
                .with_for_update(skip_locked=True)
            )
            if job is None:
                return None
            try:  # the catalog may have changed since the job was proposed
                self.catalog.get(job.runbook).validate_params(job.params)
            except CatalogError as error:
                job.status = "expired"
                self.audit(session, job, now, "expired", SYSTEM, f"no longer valid: {error}")
                return None
            job.status, job.delivered_at = "delivered", now
            self.audit(session, job, now, "delivered", f"runner:{host}")
            payload = {
                "action_id": job.action_id,
                "runbook": job.runbook,
                "params": job.params,
                "host": job.host,
                "issued_at": format_time(job.created_at),
                "expires_at": format_time(job.expires_at),
                "catalog": self.catalog.digest,
            }
            return sign_job(self._key, payload)

    def _start_verification(self, job: ActionJob, now: datetime) -> None:
        try:
            kind = self.catalog.get(job.runbook).verify
        except CatalogError:  # a runbook that is no longer in the catalog still gets the ordinary check
            kind = "health"
        job.verify_status = "pending"
        job.verify_until = now + VERIFY_GRACE[kind]

    async def _own_job(self, session: AsyncSession, host: str, action_id: str) -> ActionJob:
        job = await session.scalar(select(ActionJob).where(ActionJob.action_id == action_id).with_for_update())
        if job is None or job.host != host:  # the same answer for "unknown" and "another server's"
            raise ActionError("unknown job")
        return job

    async def started(self, host: str, action_id: str) -> None:
        now = self._clock()
        async with self._sessions() as session, session.begin():
            job = await self._own_job(session, host, action_id)
            if job.status == "running":
                return  # a retry after a lost answer: the runner may carry on, the job was started in time
            if job.status != "delivered":
                raise ActionError(f"the job is {job.status}, not delivered")
            late = now >= job.expires_at  # valid for 15 minutes: the start counts too, not only the delivery
            if late:
                job.status = "expired"
                self.audit(session, job, now, "expired", SYSTEM, "delivered but not started in time")
            else:
                job.status, job.started_at = "running", now
                self.audit(session, job, now, "started", f"runner:{host}")
        await self._touch(host)
        if late:
            raise ActionError("the job has expired")

    async def finished(self, host: str, action_id: str, status: str, summary: str) -> ActionJob:
        """The runner's result: succeeded, failed, or rejected (it refused to run the job)."""
        if status not in RESULTS:
            raise ActionError("status must be succeeded, failed or rejected")
        now = self._clock()
        async with self._sessions() as session, session.begin():
            job = await self._own_job(session, host, action_id)
            # A rejection arrives before a start; a result of a run arrives after it.
            expected = "delivered" if status == "rejected" else "running"
            lost = job.lost_at is not None and status != "rejected"
            if job.status != expected and not lost:  # one result that came after the 45 minute limit still counts
                raise ActionError(f"the job is {job.status}, not {expected}")
            job.status, job.finished_at, job.lost_at = status, now, None
            job.summary = Masker().mask(summary)[:SUMMARY_MAX]
            self.audit(session, job, now, status, f"runner:{host}", job.summary)
            if status != "rejected":  # the action ran, so the server has to be checked afterwards
                self._start_verification(job, now)
            if status == "succeeded" and job.reboot_request_id is not None:
                request = await session.get(RebootRequest, job.reboot_request_id, with_for_update=True)
                if request is not None and request.status == "approved":
                    request.status, request.done_at = "done", now
        await self._touch(host)
        return job

    async def expire(self) -> int:
        """Retire jobs that were not delivered and started in time, and fail started ones that never reported."""
        now = self._clock()
        async with self._sessions() as session, session.begin():
            jobs = (
                await session.scalars(
                    select(ActionJob)
                    .where(ActionJob.status.in_(BEFORE_START), ActionJob.expires_at <= now)
                    .with_for_update(skip_locked=True)
                )
            ).all()
            for job in jobs:
                previous, job.status = job.status, "expired"
                self.audit(session, job, now, "expired", SYSTEM, f"was {previous}")
            lost = (
                await session.scalars(
                    select(ActionJob)
                    .where(ActionJob.status == "running", ActionJob.started_at <= now - RUN_LIMIT)
                    .with_for_update(skip_locked=True)
                )
            ).all()
            for job in lost:
                job.status, job.finished_at, job.lost_at, job.summary = (
                    "failed",
                    now,
                    now,
                    self._locale.t("actions.lost"),
                )
                self.audit(session, job, now, "failed", SYSTEM, "no result from the runner")
                self._start_verification(job, now)
            return len(jobs) + len(lost)

    async def cancel(self, action_id: str, reason: str) -> None:
        """Retire a job that was proposed but not yet approved (it is no longer wanted)."""
        now = self._clock()
        async with self._sessions() as session, session.begin():
            job = await session.scalar(select(ActionJob).where(ActionJob.action_id == action_id).with_for_update())
            if job is not None and job.status == "proposed":
                job.status = "expired"
                self.audit(session, job, now, "expired", SYSTEM, reason)

    async def cancel_proposals(self, incident_id: int, reason: str) -> None:
        """Retire the unapproved proposals of an incident: only the newest analysis' proposal may be approved."""
        async with self._sessions() as session:
            ids = list(
                await session.scalars(
                    select(ActionJob.action_id).where(
                        ActionJob.incident_id == incident_id, ActionJob.status == "proposed"
                    )
                )
            )
        for action_id in ids:
            await self.cancel(action_id, reason)

    async def reboot_job_exists(self, reboot_request_id: int) -> bool:
        async with self._sessions() as session:
            found = await session.scalar(select(ActionJob.id).where(ActionJob.reboot_request_id == reboot_request_id))
        return found is not None

    async def audit_log(self, job_id: int) -> list[ActionAudit]:
        async with self._sessions() as session:
            return list(
                await session.scalars(select(ActionAudit).where(ActionAudit.job_id == job_id).order_by(ActionAudit.id))
            )
