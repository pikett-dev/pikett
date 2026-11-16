import asyncio
import hashlib
import json
import logging
import weakref
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db import last_run, mark_run
from app.i18n import Locale
from app.incidents import decide
from app.incidents.memory import INTERNAL_ORIGIN, memory_key
from app.incidents.schemas import AlertIn
from app.models import Incident, IncidentEvent
from app.notify.base import ChatNotifier, IncidentView, Pager
from app.oncall import OnCall
from app.timefmt import minutes

log = logging.getLogger(__name__)

SEVERITIES = {"P1", "P2", "P3"}
DEFAULT_SEVERITY = "P2"

# vmalert has a rule that always fires. If it stops arriving, the alerting pipeline itself is broken.
WATCHDOG = "Watchdog"
PIPELINE_ALERT = "AlertingPipelineSilent"
WATCHDOG_SILENT_AFTER = timedelta(minutes=5)
# vmalert resends firing alerts on every evaluation. An open incident that was not renewed for this long has
# stopped firing without a "resolved" (rule edited or removed, vmalert restarted).
STALE_AFTER = timedelta(minutes=10)


def fingerprint(labels: dict[str, str]) -> str:
    return hashlib.sha256(json.dumps(labels, sort_keys=True).encode()).hexdigest()[:32]


class IncidentService:
    """Turns alerts into incidents and tells people about them.

    State is written first and notifications follow. Every notification step records that it happened,
    so a failed Slack or ntfy call is retried by the next tick instead of being lost.
    """

    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        chat: ChatNotifier,
        pager: Pager,
        oncall: OnCall,
        clock: Callable[[], datetime],
        base_url: str,
        *,
        locale: Locale,
    ) -> None:
        self._locale = locale
        self._sessions = sessions
        self._chat = chat
        self._pager = pager
        self._oncall = oncall
        self._clock = clock
        self._base_url = base_url.rstrip("/")
        self._started = clock()
        # Requests and the scheduler both deliver; without a lock per incident they page it twice. A lock is
        # dropped as soon as nobody holds or awaits it.
        self._locks: weakref.WeakValueDictionary[int, asyncio.Lock] = weakref.WeakValueDictionary()

    # ---- alerts in -------------------------------------------------------------------------

    async def handle_alerts(self, alerts: list[AlertIn]) -> None:
        now = self._clock()
        touched: list[int] = []
        async with self._sessions() as session, session.begin():
            for alert in alerts:
                if alert.labels.get("alertname") == WATCHDOG:
                    await mark_run(session, "watchdog", now)
                    continue
                incident = await self._apply_alert(session, alert, now)
                if incident is not None:
                    touched.append(incident.id)
        for incident_id in touched:
            await self.deliver(incident_id)

    async def _apply_alert(self, session: AsyncSession, alert: AlertIn, now: datetime) -> Incident | None:
        fp = fingerprint(alert.labels)
        open_incident = await session.scalar(
            select(Incident).where(Incident.fingerprint == fp, Incident.status == "open")
        )
        if alert.is_resolved(now):
            if open_incident is None:
                return None
            open_incident.status = "resolved"
            open_incident.resolved_at = now
            self._event(session, open_incident, now, "resolved")
            return open_incident

        if open_incident is not None:
            open_incident.last_seen_at = now
            if open_incident.annotations != alert.annotations:
                open_incident.annotations = alert.annotations
            return None

        severity = alert.labels.get("severity", DEFAULT_SEVERITY)
        title = alert.labels.get("alertname", self._locale.t("incident.unnamed"))
        incident = Incident(
            fingerprint=fp,
            title=title,
            severity=severity if severity in SEVERITIES else DEFAULT_SEVERITY,
            status="open",
            labels=alert.labels,
            annotations=alert.annotations,
            generator_url=alert.generatorURL,
            memory_key=memory_key(alert.labels, title),
            started_at=alert.startsAt or now,
            last_seen_at=now,
            last_notified_at=now,
        )
        session.add(incident)
        await session.flush()
        self._event(session, incident, now, "opened")
        return incident

    @staticmethod
    def _event(session: AsyncSession, incident: Incident, at: datetime, kind: str, detail: str = "") -> None:
        session.add(IncidentEvent(incident_id=incident.id, at=at, kind=kind, detail=detail))

    # ---- notifications -----------------------------------------------------------------------

    def _lock_for(self, incident_id: int) -> asyncio.Lock:
        lock = self._locks.get(incident_id)
        if lock is None:
            lock = self._locks[incident_id] = asyncio.Lock()
        return lock

    def _view(self, incident: Incident, now: datetime) -> IncidentView:
        person = self._oncall.primary(now)
        return IncidentView(
            id=incident.id,
            title=incident.title,
            severity=incident.severity,
            status=incident.status,
            summary=incident.annotations.get("summary", ""),
            started_at=incident.started_at,
            resolved_at=incident.resolved_at,
            acked_by=incident.acked_by,
            silenced_until=incident.silenced_until,
            url=f"{self._base_url}/incidents/{incident.id}",
            oncall_slack_id=person.slack_user_id if person else None,
        )

    async def deliver(self, incident_id: int) -> None:
        """Bring Slack and the pager up to date with the incident. Safe to call repeatedly."""
        async with self._lock_for(incident_id):
            now = self._clock()
            async with self._sessions() as session:
                incident = await session.get(Incident, incident_id)
                if incident is None:
                    return
                view = self._view(incident, now)
                await self._post(session, incident, view, now)
                await self._page(session, incident, view, now)
                await self._announce_resolution(session, incident, view, now)

    async def _post(self, session: AsyncSession, incident: Incident, view: IncidentView, now: datetime) -> None:
        if incident.slack_ts is not None or incident.status != "open" or incident.severity == "P3":
            return
        try:
            channel, ts = await self._chat.post_incident(view)
        except Exception:
            log.exception("posting incident %s to chat failed, retrying on the next tick", incident.id)
            return
        incident.slack_channel, incident.slack_ts = channel, ts
        self._event(session, incident, now, "posted")
        await session.commit()

    async def _page(self, session: AsyncSession, incident: Incident, view: IncidentView, now: datetime) -> None:
        if (
            incident.status != "open"
            or incident.paged_at is not None
            or not decide.should_page(incident.severity)
            or decide.is_silenced(incident.silenced_until, now)
        ):
            return
        person = self._oncall.primary(now)
        if person is None:
            log.warning("P1 incident %s but nobody is on call", incident.id)
            return
        try:
            await self._pager.page(person, view, escalated=False)
        except Exception:
            log.exception("paging for incident %s failed, retrying on the next tick", incident.id)
            return
        incident.paged_at = now
        self._event(session, incident, now, "paged", person.name)
        await session.commit()

    async def _announce_resolution(
        self, session: AsyncSession, incident: Incident, view: IncidentView, now: datetime
    ) -> None:
        if incident.status != "resolved" or incident.resolution_posted_at is not None:
            return
        if incident.slack_ts is not None and incident.slack_channel is not None:
            # Without a posted message (resolved before anyone was told) there is nothing to correct in chat.
            took = minutes((incident.resolved_at or now) - incident.started_at)
            try:
                await self._chat.update_incident(view, incident.slack_channel, incident.slack_ts)
                await self._chat.reply(
                    incident.slack_channel, incident.slack_ts, self._locale.t("incident.resolved_after", n=took)
                )
            except Exception:
                log.exception("posting resolution of incident %s failed", incident.id)
                return
        incident.resolution_posted_at = now
        await session.commit()

    async def _pipeline_silent(self, now: datetime) -> bool:
        async with self._sessions() as session:
            seen = await last_run(session, "watchdog")
        return now - (seen or self._started) > WATCHDOG_SILENT_AFTER

    async def _check_pipeline(self, silent: bool, now: datetime) -> None:
        """Open an incident when the watchdog stops arriving, and close it when it is back."""
        await self.handle_alerts(
            [
                AlertIn(
                    labels={"alertname": PIPELINE_ALERT, "severity": "P1"},
                    annotations={"summary": self._locale.t("incident.pipeline_silent")},
                    endsAt=None if silent else now,
                )
            ]
        )

    async def _close_stale(self, now: datetime) -> None:
        closed: list[int] = []
        async with self._sessions() as session, session.begin():
            stale = await session.scalars(
                select(Incident).where(
                    Incident.status == "open",
                    Incident.last_seen_at < now - STALE_AFTER,
                    Incident.title != PIPELINE_ALERT,
                    ~Incident.labels.contains(INTERNAL_ORIGIN),
                )
            )
            for incident in stale:
                incident.status, incident.resolved_at = "resolved", now
                self._event(session, incident, now, "resolved", "no longer reported by vmalert")
                closed.append(incident.id)
        for incident_id in closed:
            await self.deliver(incident_id)

    async def tick(self) -> None:
        """Check the pipeline, retry missed notifications, then send reminders and escalations."""
        now = self._clock()
        silent = await self._pipeline_silent(now)
        await self._check_pipeline(silent, now)
        if not silent:  # While vmalert is silent no renewals can be expected, so nothing is known to be stale.
            await self._close_stale(now)
        async with self._sessions() as session:
            pending = (
                await session.scalars(
                    select(Incident.id).where(
                        (Incident.status == "open")
                        | ((Incident.status == "resolved") & Incident.resolution_posted_at.is_(None))
                    )
                )
            ).all()
        for incident_id in pending:
            await self.deliver(incident_id)
            await self._remind_or_escalate(incident_id, now)

    async def _remind_or_escalate(self, incident_id: int, now: datetime) -> None:
        async with self._lock_for(incident_id), self._sessions() as session:
            incident = await session.get(Incident, incident_id)
            if incident is None or incident.status != "open":
                return
            channel, ts = incident.slack_channel, incident.slack_ts
            if channel is None or ts is None:
                return
            view = self._view(incident, now)

            if decide.escalation_due(
                severity=incident.severity,
                started_at=incident.started_at,
                acked_at=incident.acked_at,
                escalated_at=incident.escalated_at,
                silenced_until=incident.silenced_until,
                now=now,
            ):
                person = self._oncall.secondary(now)
                if person is None:
                    return
                try:
                    await self._pager.page(person, view, escalated=True)
                    await self._chat.reply(
                        channel,
                        ts,
                        self._locale.t("incident.escalated", id=person.slack_user_id),
                    )
                except Exception:
                    log.exception("escalating incident %s failed", incident.id)
                    return
                incident.escalated_at = now
                self._event(session, incident, now, "escalated", person.name)
                await session.commit()
            elif decide.reminder_due(
                severity=incident.severity,
                reminder_count=incident.reminder_count,
                last_notified_at=incident.last_notified_at,
                silenced_until=incident.silenced_until,
                now=now,
            ):
                try:
                    await self._chat.reply(
                        channel, ts, self._locale.t("incident.reminder", n=minutes(now - incident.started_at))
                    )
                except Exception:
                    log.exception("posting reminder for incident %s failed", incident.id)
                    return
                incident.reminder_count += 1
                incident.last_notified_at = now
                self._event(session, incident, now, "reminder")
                await session.commit()

    # ---- actions from chat -------------------------------------------------------------------

    async def _act_on_open(
        self, incident_id: int, change: Callable[[Incident, AsyncSession, datetime], Awaitable[None]]
    ) -> bool:
        """Apply a change to an open incident, then refresh its chat message. False if it is not open."""
        now = self._clock()
        async with self._sessions() as session:
            incident = await session.get(Incident, incident_id)
            if incident is None or incident.status != "open":
                return False
            await change(incident, session, now)
            await session.commit()
            await self._refresh_message(incident, now)
            return True

    async def acknowledge(self, incident_id: int, user_id: str) -> bool:
        async def change(incident: Incident, session: AsyncSession, now: datetime) -> None:
            if incident.acked_at is None:
                incident.acked_by, incident.acked_at = user_id, now
                self._event(session, incident, now, "acked", user_id)

        return await self._act_on_open(incident_id, change)

    async def silence(self, incident_id: int, user_id: str, duration: timedelta) -> bool:
        async def change(incident: Incident, session: AsyncSession, now: datetime) -> None:
            incident.silenced_until = now + duration
            self._event(session, incident, now, "silenced", f"{user_id} for {minutes(duration)} min")

        return await self._act_on_open(incident_id, change)

    async def _refresh_message(self, incident: Incident, now: datetime) -> None:
        if incident.slack_channel is None or incident.slack_ts is None:
            return
        try:
            await self._chat.update_incident(self._view(incident, now), incident.slack_channel, incident.slack_ts)
        except Exception:
            log.exception("updating the chat message of incident %s failed", incident.id)
