"""The Slack approval of a runbook: from the analysis' proposal to a button, an approval, and the result.

An analysis may name a runbook. The service checks the proposal against the catalog and the servers that have a
runner, creates the job (state `proposed`) and posts it in the incident thread with an approval button and a
confirmation dialog. Only people on the allowlist may approve (checked in ButtonActions); the approval is the one
transition `proposed -> approved` of that job, so a second click cannot start a second run. The message is updated
as the job moves on and shows the result at the end.
"""

import logging
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.actions.service import ActionError, ActionService
from app.i18n import Locale
from app.models import ActionJob, Incident, IncidentAnalysis
from app.notify.base import ChatNotifier
from app.notify.blocks import approval_blocks, escape
from runner.catalog import Catalog, CatalogError, Runbook

log = logging.getLogger(__name__)

ACTION_ID = "runbook_approve"
REFRESH_WINDOW = timedelta(days=1)
RESULT_MAX = 500
_VERIFY = ("pending", "ok", "red", "recovered", "skipped")


def runbook_prompt(catalog: Catalog, hosts: set[str], applications: dict[str, dict[str, str]] | None = None) -> str:
    """The part of the analyst's system prompt about runbooks (empty when no server has a runner)."""
    if not hosts:
        return ""
    lines = [
        "\n\nRunbooks: if one of these would fix the problem right now, name it in `runbook` (with `runbook_host`",
        "and, where listed, `runbook_application`), otherwise leave the three fields empty. Propose one only when the",
        "evidence supports it. A person approves it in Slack first; you cannot run anything yourself.",
        f"Servers with a runner: {', '.join(sorted(hosts))}.",
    ]
    for book in catalog.runbooks.values():
        if not book.proposable:
            continue
        needs = " (needs `runbook_application`)" if "application" in book.params else ""
        servers = book.hosts
        if needs and applications:  # only a server with an application list can take it, whatever the catalog says
            servers = tuple(sorted(host for host in applications if book.allows_host(host)))
        lines.append(f"- {book.id}{needs}: {book.text('description', 'en')} Servers: {', '.join(servers)}.")
    for host, names in sorted((applications or {}).items()):
        listed = ", ".join(f"{name} = {uuid}" for uuid, name in sorted(names.items(), key=lambda kv: kv[1]))
        lines.append(f"Applications on {host} (name = UUID for `runbook_application`): {listed}.")
    return "\n".join(lines)


def message(
    locale: Locale, job: ActionJob, book: Runbook | None, applications: dict[str, str] | None = None
) -> tuple[str, list[dict[str, Any]]]:
    """The Slack message of a job in its current state.

    `applications` maps a Coolify UUID to its name: the person approving has to see which application it is."""
    title = book.text("title", locale.language) if book else job.runbook
    risk = locale.label("actions.risk", book.risk) if book else ""
    shown = []
    for key, value in sorted(job.params.items()):
        name = (applications or {}).get(str(value)) if key == "application" else None
        shown.append(f"{key}={name} ({value})" if name else f"{key}={value}")
    params = ", ".join(shown)
    head = locale.t("actions.head", title=title, host=job.host) + (f" ({params})" if params else "")
    head += f", {risk}" if risk else ""
    if job.status == "proposed":
        text = locale.t("actions.proposed", head=head, at=locale.clock(job.expires_at))
        subject = locale.t("actions.confirm_subject", title=title, host=job.host)
        return text, approval_blocks(
            locale,
            text,
            locale.t("slack.approve"),
            ACTION_ID,
            job.action_id,
            locale.t("actions.confirm_title"),
            subject + (f" ({params})" if params else "") + (f", {risk}" if risk else "") + ".",
        )
    approved = job.approved_at is not None
    by = (
        locale.t("actions.approved_by", id=job.approved_by, at=locale.clock(job.approved_at)) if job.approved_at else ""
    )
    result = escape(job.summary.strip()[:RESULT_MAX])
    if job.status == "expired":
        state = locale.t("actions.state.expired" if approved else "actions.state.expired_unapproved")
    elif job.status in ("approved", "delivered", "running"):
        state = locale.t(f"actions.state.{job.status}")
    elif job.status in ("succeeded", "rejected"):
        state = locale.t(f"actions.state.{job.status}", result=result)
    else:
        state = locale.t("actions.state.failed", result=result)
    verify = f"\n{locale.t(f'actions.verify.{job.verify_status}')}" if job.verify_status in _VERIFY else ""
    text = f"{head}.{by}\n{state}{verify}"
    return text, [{"type": "section", "text": {"type": "mrkdwn", "text": text}}]


class RunbookApprovals:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        jobs: ActionService,
        chat: ChatNotifier,
        clock: Callable[[], datetime],
        *,
        locale: Locale,
    ) -> None:
        self._sessions, self._jobs, self._chat, self._clock = sessions, jobs, chat, clock
        self._locale = locale

    async def offer(self, analysis: IncidentAnalysis, channel: str, thread_ts: str) -> None:
        """Turn the analysis' proposal into a job and a button in the incident thread. Never raises."""
        data = analysis.analysis or {}
        runbook = str(data.get("runbook") or "")
        # "verified" only says the quotes exist in tool results (log lines can be written by an attacker), so a
        # low-confidence analysis offers nothing; a person still approves whatever is offered.
        if not runbook or data.get("confidence") == "low":
            return
        async with self._sessions() as session:
            incident = await session.get(Incident, analysis.incident_id)
        if incident is None or incident.status != "open":
            return  # resolved while the analysis ran: nothing left to fix
        await self._jobs.cancel_proposals(analysis.incident_id, "a newer proposal replaced it")
        try:
            book = self._jobs.catalog.get(runbook)
            params: dict[str, Any] = {}
            if "application" in book.params:
                params["application"] = str(data.get("runbook_application") or "")
            job = await self._jobs.propose(
                runbook,
                params,
                str(data.get("runbook_host") or ""),
                "analysis",
                incident_id=analysis.incident_id,
                analysis_id=analysis.id,
            )
        except ActionError as error:  # a proposal the catalog does not allow gets no button, only a log line
            log.info("proposal of analysis %s not offered: %s", analysis.id, error)
            return
        except Exception:
            log.exception("could not create the job for analysis %s", analysis.id)
            return
        await self._post(job, book, channel, thread_ts)

    async def _post(self, job: ActionJob, book: Runbook, channel: str, thread_ts: str) -> None:
        text, blocks = message(self._locale, job, book, self._jobs.applications.get(job.host))
        try:
            ts = await self._chat.reply_message(channel, thread_ts, text, blocks)
        except Exception:
            log.exception("posting the approval button of job %s failed", job.id)
            return  # the job expires after 15 minutes without a button, nothing runs
        try:
            await self._remember(job.id, self._state(job), channel, ts)
        except Exception:  # the button is out; without the ts the message just is not updated
            log.exception("could not record the message of job %s", job.id)

    async def _remember(self, job_id: int, state: str, channel: str | None = None, ts: str | None = None) -> None:
        """Record what the message shows (the state it was rendered from, not the one the row has by now) and, the
        first time, where it is."""
        async with self._sessions() as session, session.begin():
            row = await session.get(ActionJob, job_id)
            if row is None:
                return
            if channel is not None:
                row.slack_channel, row.slack_ts = channel, ts
            row.slack_state = state

    @staticmethod
    def _state(job: ActionJob) -> str:
        return f"{job.status}/{job.verify_status or '-'}"

    async def approve(self, value: str, user_id: str) -> str | None:
        """The button press of an allowed user. Returns an error text for them, or None when approved."""
        async with self._sessions() as session:
            job = await session.scalar(select(ActionJob).where(ActionJob.action_id == value))
            incident = await session.get(Incident, job.incident_id) if job and job.incident_id else None
        if job is not None and job.status == "proposed" and incident is not None and incident.status != "open":
            await self._jobs.cancel(value, "the incident was resolved before the approval")
            await self._safe_refresh(value)
            return self._locale.t("errors.incident_closed")
        error = await self._jobs.approve(value, user_id)
        if error is None:
            await self._safe_refresh(value)
        return error

    async def _safe_refresh(self, action_id: str) -> None:
        try:
            await self.refresh(action_id)
        except Exception:  # the change stands; the tick brings the message up to date
            log.exception("refreshing the message of %s failed", action_id)

    async def refresh(self, action_id: str) -> None:
        async with self._sessions() as session:
            job = await session.scalar(select(ActionJob).where(ActionJob.action_id == action_id))
        if job is not None:
            await self._update(job)

    async def tick(self) -> None:
        """Bring the messages up to date: a job that moved on shows its new state and, at the end, its result."""
        now = self._clock()
        async with self._sessions() as session:
            jobs = (
                await session.scalars(
                    select(ActionJob).where(
                        ActionJob.slack_ts.is_not(None),
                        ActionJob.created_at > now - REFRESH_WINDOW,
                        # only what changed since the message was written
                        ActionJob.slack_state.is_distinct_from(
                            func.concat(ActionJob.status, "/", func.coalesce(ActionJob.verify_status, "-"))
                        ),
                    )
                )
            ).all()
        for job in jobs:
            await self._update(job)

    async def _update(self, job: ActionJob) -> None:
        if job.slack_channel is None or job.slack_ts is None:
            return
        try:
            book = self._jobs.catalog.get(job.runbook)
        except CatalogError:  # no longer in the catalog: the message still shows the id
            book = None
        text, blocks = message(self._locale, job, book, self._jobs.applications.get(job.host))
        try:
            await self._chat.update_message(job.slack_channel, job.slack_ts, text, blocks)
        except Exception:
            log.exception("updating the message of job %s failed", job.id)
            return
        await self._remember(job.id, self._state(job))
