"""Runs the analyst for incidents and keeps the result where people look for it.

Like the other steps of the incident service, this one is driven by recorded facts and retried by the tick: an open P1
or P2 incident without a finished analysis gets one started (a failed automatic one is retried a few times, with a
pause), and a finished analysis whose result was not yet handled in the Slack thread is posted. So a budget that was
used up, a database blip, a restart in the middle of a run or a failed Slack call delay the result, they do not lose
it. The automatic run uses the cheap model (Haiku); the buttons "Tiefer analysieren" (Sonnet) and "Mit Opus analysieren"
start a stronger one. Over the daily budget every stage falls back to the cheap model.

Analyses run in the background, so opening and paging an incident never waits for them, and whatever goes wrong inside
only ends up as a failed analysis. At most `max_parallel` run at the same time per process (one process serves this
box); the daily budget is checked per call, so this bounds how far parallel runs can overshoot it.
"""

import asyncio
import logging
from collections import defaultdict
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import aliased

from app.agent.analyst import AnalysisOutcome, Analyst, IncidentContext
from app.agent.budget import Budget, BudgetStatus
from app.agent.pricing import money
from app.i18n import Locale
from app.incidents.memory import latest_backed_analysis
from app.models import Incident, IncidentAnalysis
from app.notify.base import ChatNotifier
from app.notify.blocks import analysis_text, feedback_blocks, feedback_question, known_solution_text

log = logging.getLogger(__name__)

AUTO = "auto"
AUTO_SEVERITIES = {"P1", "P2"}  # P3 only shows up in the digest, so it is not worth a model call
MAX_AUTO_ATTEMPTS = 3
RETRY_AFTER = timedelta(minutes=5)  # between two automatic attempts for the same incident
ANNOUNCE_WINDOW = timedelta(hours=6)  # a result older than this is not posted any more


async def fail_interrupted_analyses(
    sessions: async_sessionmaker[AsyncSession], clock: Callable[[], datetime], locale: Locale
) -> None:
    """At start: analyses that were running when the service stopped will never finish.

    This needs no agent, so it also clears rows if the agent was switched off in the meantime. It assumes that no
    second process is still working on them (the box runs one service; a deploy stops the old one first).
    """
    async with sessions() as session, session.begin():
        await session.execute(
            update(IncidentAnalysis)
            .where(IncidentAnalysis.status == "running")
            .values(status="failed", finished_at=clock(), error=locale.t("analysis.interrupted"), interrupted=True)
        )


def _attempts_used(runs: list[IncidentAnalysis]) -> bool:
    """Whether the automatic attempts are used up. A restart is not a failed attempt, but it has its own cap, so
    a run that takes the process down (out of memory) is not retried for ever."""
    automatic = [r for r in runs if r.requested_by == AUTO]
    interrupted = sum(r.interrupted for r in automatic)
    return len(automatic) - interrupted >= MAX_AUTO_ATTEMPTS or interrupted >= MAX_AUTO_ATTEMPTS


class AnalysisService:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        analyst: Analyst,
        budget: Budget,
        chat: ChatNotifier,
        clock: Callable[[], datetime],
        base_url: str,
        *,
        locale: Locale,
        auto: bool = True,
        auto_model: str | None = None,
        deep_model: str | None = None,
        max_parallel: int = 2,
    ) -> None:
        self._locale = locale
        self._sessions = sessions
        self._analyst = analyst
        self._budget = budget
        self._chat = chat
        self._clock = clock
        self._base_url = base_url.rstrip("/")
        self._auto = auto
        self._auto_model = auto_model  # the cheap model of the automatic run; None: the analyst's default
        self._deep_model = deep_model  # the model of the deeper button; None: the analyst's default
        self._max_parallel = max_parallel
        self._slots = asyncio.Semaphore(max_parallel)
        self._tasks: set[asyncio.Task[None]] = set()  # the event loop only holds tasks weakly: keep them alive
        self._known_replied: set[int] = set()  # known solutions already sent to Slack, like `_replied`
        self._replied: set[int] = set()  # results already sent to Slack, whether or not `posted_at` was recorded
        # Called with a result that was just posted (analysis, channel, thread ts): the runbook approval hangs here.
        self.on_posted: Callable[[IncidentAnalysis, str, str], Awaitable[None]] | None = None

    async def budget_status(self) -> BudgetStatus:
        return await self._budget.status()

    async def record_feedback(self, analysis_id: int, user_id: str, feedback: str) -> str | None:
        """Stores a person's verdict on a finished analysis (the latest click wins). Returns a reason (in the configured
        language) on failure, else None."""
        async with self._sessions() as session, session.begin():
            found = await session.scalar(
                update(IncidentAnalysis)
                .where(
                    IncidentAnalysis.id == analysis_id,
                    IncidentAnalysis.status == "done",
                    IncidentAnalysis.verified.is_(True),
                )
                .values(feedback=feedback, feedback_by=user_id, feedback_at=self._clock())
                .returning(IncidentAnalysis.id)
            )
        return None if found is not None else self._locale.t("errors.analysis_not_found")

    async def fail_interrupted(self) -> None:
        await fail_interrupted_analyses(self._sessions, self._clock, self._locale)

    async def tick(self) -> None:
        await self._start_automatic()  # marks the incidents whose problem is known ...
        await self._post_known()  # ... and the thread hears of it in the same tick
        await self._post_results()
        try:  # the question is a nicety: a failing database must not look like a failed analysis tick
            await self._ask_feedback()
        except Exception:
            log.exception("asking for feedback failed, retrying on the next tick")

    async def request(self, incident_id: int, requested_by: str, *, deep: bool = False) -> str | None:
        """Starts an analysis in the background, on the deep model when `deep`, else on the analyst's default.

        Returns a reason (in the configured language) when none was started, else None.

        This also serves old Slack messages and resolved incidents: an analysis after the fact is allowed.
        """
        if (await self._budget.status()).exhausted:
            return self._locale.t("errors.budget_used")
        return await self._start(incident_id, requested_by, self._deep_model if deep else None)

    async def _start(self, incident_id: int, requested_by: str, model: str | None) -> str | None:
        async with self._sessions() as session:
            incident = await session.get(Incident, incident_id)
            if incident is None:
                return self._locale.t("errors.incident_not_found")
            context = IncidentContext(
                title=incident.title,
                severity=incident.severity,
                summary=incident.annotations.get("summary", ""),
                started_at=incident.started_at,
                labels=dict(incident.labels),
                annotations=dict(incident.annotations),
            )
            row = IncidentAnalysis(
                incident_id=incident_id, requested_by=requested_by, status="running", started_at=self._clock()
            )
            session.add(row)
            try:
                await session.commit()
            except IntegrityError as exc:
                if "ux_incident_analysis_running" in str(exc.orig):  # one running analysis per incident
                    return self._locale.t("errors.analysis_running")
                return self._locale.t("errors.incident_not_found")  # the incident was deleted in the meantime
            analysis_id = row.id
        task = asyncio.create_task(self._run(analysis_id, context, model))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return None

    async def wait_idle(self, timeout: float | None = None) -> None:
        """Waits for the running analyses (tests and shutdown). After `timeout` the rest is cancelled: their rows stay
        `running` and the next start marks them as interrupted."""
        while self._tasks:
            tasks = list(self._tasks)
            if timeout is None:
                await asyncio.gather(*tasks, return_exceptions=True)
            else:
                _, pending = await asyncio.wait(tasks, timeout=timeout)
                for task in pending:
                    task.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
            # Do not rely on the done-callbacks having run: a finished task left in the set would spin this loop.
            self._tasks.difference_update(task for task in tasks if task.done())
            if timeout is not None:
                return

    async def _ask_feedback(self) -> None:
        """The question under the newest backed analysis of an incident once its text is posted. A recorded
        step: a failed post is retried by the next tick, within the announce window."""
        newer = aliased(IncidentAnalysis)
        async with self._sessions() as session:
            rows = (
                await session.execute(
                    select(IncidentAnalysis.id, Incident.slack_channel, Incident.slack_ts)
                    .join(Incident, Incident.id == IncidentAnalysis.incident_id)
                    .where(
                        IncidentAnalysis.status == "done",
                        IncidentAnalysis.verified.is_(True),
                        IncidentAnalysis.posted_at.is_not(None),
                        IncidentAnalysis.feedback_asked_at.is_(None),
                        IncidentAnalysis.finished_at > self._clock() - ANNOUNCE_WINDOW,
                        Incident.slack_channel.is_not(None),
                        Incident.slack_ts.is_not(None),
                        ~select(newer.id)
                        .where(newer.incident_id == IncidentAnalysis.incident_id, newer.id > IncidentAnalysis.id)
                        .exists(),  # an older, superseded analysis is not worth a verdict
                    )
                )
            ).all()
        for analysis_id, channel, ts in rows:
            if channel is None or ts is None:
                continue
            try:
                await self._chat.reply_message(
                    channel, ts, feedback_question(self._locale), feedback_blocks(self._locale, analysis_id)
                )
            except Exception:
                log.exception("the feedback question of analysis %s was not posted, retrying next tick", analysis_id)
                continue
            try:
                async with self._sessions() as session, session.begin():
                    await session.execute(
                        update(IncidentAnalysis)
                        .where(IncidentAnalysis.id == analysis_id)
                        .values(feedback_asked_at=self._clock())
                    )
            except Exception:
                log.exception("could not record that the feedback question of analysis %s was asked", analysis_id)

    # ---- known solutions ------------------------------------------------------------

    async def _mark_known(self, incident_id: int) -> bool:
        """An incident that has happened before, with a solution people rated helpful, gets that solution and no
        model call. The mark is the fact; telling the thread is the next step and is retried."""
        async with self._sessions() as session, session.begin():
            incident = await session.get(Incident, incident_id)
            if incident is None or incident.memory_key is None:
                return False
            known = await latest_backed_analysis(session, incident, helpful_only=True)
            if known is None:
                return False
            incident.known_from_incident_id = known.incident_id
            return True

    async def _post_known(self) -> None:
        async with self._sessions() as session:
            waiting = (
                await session.scalars(
                    select(Incident).where(
                        Incident.status == "open",  # a thread of a closed incident needs no hint any more
                        Incident.known_from_incident_id.is_not(None),
                        Incident.known_posted_at.is_(None),
                        Incident.slack_channel.is_not(None),  # no thread yet: the next tick tries again
                        Incident.slack_ts.is_not(None),
                    )
                )
            ).all()
            replies: list[tuple[int, str, str, str]] = []  # incident, channel, ts, text
            analysis_ids: dict[int, int] = {}  # incident -> the earlier analysis the question is about
            lost: list[int] = []
            for incident in waiting:
                if incident.id in self._known_replied or incident.slack_channel is None or incident.slack_ts is None:
                    continue
                known = await latest_backed_analysis(session, incident, helpful_only=True)
                if known is None:  # rated "not helpful" since, or gone: the incident gets a normal analysis after all
                    lost.append(incident.id)
                    continue
                base = self._base_url
                text = known_solution_text(
                    self._locale,
                    known,
                    f"{base}/incidents/{incident.id}",
                    f"{base}/incidents/{known.incident_id}",
                    self._locale.full_date(known.finished_at),
                )
                replies.append((incident.id, incident.slack_channel, incident.slack_ts, text))
                analysis_ids[incident.id] = known.analysis_id
        if lost:
            async with self._sessions() as session, session.begin():
                await session.execute(update(Incident).where(Incident.id.in_(lost)).values(known_from_incident_id=None))
        for incident_id, channel, ts, text in replies:
            try:
                await self._chat.reply(channel, ts, text)
            except Exception:
                log.exception(
                    "posting the known solution of incident %s failed, retrying on the next tick", incident_id
                )
                continue
            self._known_replied.add(incident_id)  # if recording it fails below, the reply is not sent again
            try:  # so a wrong "helpful" of the earlier analysis can be taken back: the buttons rate that analysis
                await self._chat.reply_message(
                    channel,
                    ts,
                    feedback_question(self._locale),
                    feedback_blocks(self._locale, analysis_ids[incident_id]),
                )
            except Exception:
                log.exception("the feedback question of the known solution of incident %s was not posted", incident_id)
            try:
                async with self._sessions() as session, session.begin():
                    await session.execute(
                        update(Incident).where(Incident.id == incident_id).values(known_posted_at=self._clock())
                    )
            except Exception:
                log.exception("could not record that the known solution of incident %s was posted", incident_id)

    # ---- starting ----------------------------------------------------------------------------

    async def _start_automatic(self) -> None:
        if not self._auto:
            return
        capacity = self._max_parallel * 2 - len(self._tasks)  # a burst of incidents must not queue unbounded work
        if capacity <= 0:
            return
        now = self._clock()
        async with self._sessions() as session:
            open_ids = (
                await session.scalars(
                    select(Incident.id).where(
                        Incident.status == "open",
                        Incident.severity.in_(AUTO_SEVERITIES),
                        Incident.known_from_incident_id.is_(None),  # its solution is known: no new analysis
                    )
                )
            ).all()
            if not open_ids:
                return
            runs: dict[int, list[IncidentAnalysis]] = defaultdict(list)
            found = await session.scalars(select(IncidentAnalysis).where(IncidentAnalysis.incident_id.in_(open_ids)))
            for run in found:
                runs[run.incident_id].append(run)
        # Decided here, in the step that would start the run, so no run slips through for a known problem. A known
        # solution costs no budget, so this comes before the budget check.
        known = {i for i in open_ids if not runs[i] and await self._mark_known(i)}
        if (await self._budget.status()).exhausted:
            return
        for incident_id in open_ids:
            if incident_id in known:
                continue
            mine = runs[incident_id]
            if any(r.status in ("running", "done") for r in mine):
                continue
            if _attempts_used(mine):
                continue
            if mine and now - max(r.started_at for r in mine) < RETRY_AFTER:
                continue
            if reason := await self._start(incident_id, AUTO, self._auto_model):
                log.info("no automatic analysis for incident %s: %s", incident_id, reason)
            else:
                capacity -= 1
                if capacity <= 0:
                    return

    async def _run(self, analysis_id: int, context: IncidentContext, model: str | None) -> None:
        try:
            async with self._slots:
                outcome = await self._analyst.run(context, model)
            await self._store(analysis_id, outcome)
        except Exception:
            log.exception("analysis %s failed unexpectedly", analysis_id)
            await self._fail(analysis_id, self._locale.t("analysis.unexpected"))

    async def _store(self, analysis_id: int, outcome: AnalysisOutcome) -> None:
        if len(outcome.models) > 1:
            log.info("analysis %s moved from %s to %s: the budget", analysis_id, outcome.models[0], outcome.model)
        async with self._sessions() as session, session.begin():
            await session.execute(
                update(IncidentAnalysis)
                .where(IncidentAnalysis.id == analysis_id, IncidentAnalysis.status == "running")
                .values(
                    status="done" if outcome.analysis is not None else "failed",
                    finished_at=self._clock(),
                    model=outcome.model,
                    analysis=outcome.analysis.model_dump(mode="json") if outcome.analysis else None,
                    error=outcome.error,
                    verified=outcome.verified,
                    dropped_evidence=outcome.dropped_evidence,
                    cost_usd=money(outcome.cost_usd),
                    iterations=outcome.iterations,
                    tool_calls=outcome.tool_calls,
                )
            )

    async def _fail(self, analysis_id: int, reason: str) -> None:
        try:
            async with self._sessions() as session, session.begin():
                await session.execute(
                    update(IncidentAnalysis)
                    .where(IncidentAnalysis.id == analysis_id, IncidentAnalysis.status == "running")
                    .values(status="failed", finished_at=self._clock(), error=reason)
                )
        except Exception:
            log.exception("could not mark analysis %s as failed", analysis_id)

    # ---- posting -----------------------------------------------------------------------------

    async def _post_results(self) -> None:
        """Posts the newest finished analysis of each incident to its thread; older unposted ones are superseded."""
        now = self._clock()
        budget_left = not (await self._budget.status()).exhausted  # before the session: the snapshot starts below
        async with self._sessions() as session:
            # One snapshot for all the reads below: an analysis that finishes in between must not be seen as
            # running by one query and as finished by the next, or its result would be posted twice.
            await session.connection(execution_options={"isolation_level": "REPEATABLE READ"})
            pending = (
                await session.scalars(
                    select(IncidentAnalysis)
                    .where(
                        IncidentAnalysis.status != "running",
                        IncidentAnalysis.posted_at.is_(None),
                        IncidentAnalysis.finished_at > now - ANNOUNCE_WINDOW,
                    )
                    .order_by(IncidentAnalysis.started_at)
                )
            ).all()
            if not pending:
                return
            retry_possible = self._auto and budget_left
            running_now = select(IncidentAnalysis.incident_id).where(IncidentAnalysis.status == "running")
            running = set(await session.scalars(running_now))
            by_incident: dict[int, list[IncidentAnalysis]] = defaultdict(list)
            for run in pending:
                by_incident[run.incident_id].append(run)
            replies: list[
                tuple[str, str, str, IncidentAnalysis, list[int]]
            ] = []  # channel, ts, text, newest, rows handled
            for incident_id, group in by_incident.items():
                if incident_id in running:
                    continue  # a newer attempt is on its way: its result will be the one to post
                incident = await session.get(Incident, incident_id)
                if incident is None or incident.slack_channel is None or incident.slack_ts is None:
                    continue  # no thread yet: the next tick tries again, within the window
                newest = group[-1]
                every_run = (
                    await session.scalars(select(IncidentAnalysis).where(IncidentAnalysis.incident_id == incident_id))
                ).all()
                if retry_possible and self._retry_pending(incident, newest, list(every_run)):
                    continue  # a failed automatic attempt that will be tried again is not worth a message
                url = f"{self._base_url}/incidents/{incident.id}"
                text = analysis_text(self._locale, newest, url)
                replies.append((incident.slack_channel, incident.slack_ts, text, newest, [r.id for r in group]))
        # The session is closed: a slow chat must not hold a database connection.
        for channel, ts, text, newest, ids in replies:
            await self._post(channel, ts, text, newest, ids)

    @staticmethod
    def _retry_pending(incident: Incident, run: IncidentAnalysis, every_run: list[IncidentAnalysis]) -> bool:
        return (
            run.status == "failed"
            and run.requested_by == AUTO
            and incident.status == "open"
            and incident.severity in AUTO_SEVERITIES
            and not _attempts_used(every_run)
        )

    async def _post(self, channel: str, ts: str, text: str, newest: IncidentAnalysis, analysis_ids: list[int]) -> None:
        newest_id = newest.id
        if newest_id not in self._replied:
            try:
                await self._chat.reply(channel, ts, text)
            except Exception:
                log.exception("posting analyses %s to chat failed, retrying on the next tick", analysis_ids)
                return
            self._replied.add(newest_id)  # if recording it fails below, the reply is not sent again
            if self.on_posted is not None and newest.status == "done" and newest.verified:  # only a backed analysis
                try:  # an offer that fails must not stop the analysis from being recorded as posted
                    await self.on_posted(newest, channel, ts)
                except Exception:
                    log.exception("the follow-up of analysis %s failed", newest_id)
        try:
            async with self._sessions() as session, session.begin():
                await session.execute(
                    update(IncidentAnalysis)
                    .where(IncidentAnalysis.id.in_(analysis_ids))
                    .values(posted_at=self._clock())
                )
        except Exception:
            log.exception("could not record that analyses %s were posted, retrying on the next tick", analysis_ids)
