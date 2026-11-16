"""Incidents raised by the ops service's own checks (backups, scans, missing reports), not by vmalert.

They go through the same alert path as vmalert alerts, so dedup, Slack, paging, reminders and the resolution
message work unchanged. They carry the label origin=ops: such an incident is renewed only when its check runs
(hourly or nightly), so the stale-alert cleanup for vmalert must leave it alone.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.incidents.memory import INTERNAL_ORIGIN
from app.incidents.schemas import AlertIn
from app.incidents.service import IncidentService, fingerprint
from app.models import Incident


@dataclass(frozen=True)
class Signal:
    """One firing condition. `labels` identify it (one incident per distinct label set), annotations describe it."""

    labels: dict[str, str]
    summary: str
    link: str = ""
    details: dict[str, str] = field(default_factory=dict)


class Signals:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        incidents: IncidentService,
        clock: Callable[[], datetime],
    ) -> None:
        self._sessions = sessions
        self._incidents = incidents
        self._clock = clock

    @staticmethod
    def _labels(name: str, severity: str, labels: dict[str, str]) -> dict[str, str]:
        return {**labels, "alertname": name, "severity": severity, **INTERNAL_ORIGIN}

    async def reconcile(self, name: str, severity: str, scope: dict[str, str], firing: list[Signal]) -> None:
        """Make the open incidents named `name` within `scope` match `firing`: open or renew those, resolve the rest.

        `scope` is the part of the labels this check is responsible for (for example the host), so a check that
        saw one host does not resolve the incidents of another. Every signal must carry the scope labels.
        """
        now = self._clock()
        alerts: list[AlertIn] = []
        wanted: set[str] = set()
        for signal in firing:
            if any(signal.labels.get(key) != value for key, value in scope.items()):
                raise ValueError(f"signal {signal.labels} is outside the scope {scope}")
            labels = self._labels(name, severity, signal.labels)
            wanted.add(fingerprint(labels))
            annotations = {"summary": signal.summary, **signal.details}
            if signal.link:
                annotations["link"] = signal.link
            alerts.append(AlertIn(labels=labels, annotations=annotations))

        async with self._sessions() as session:
            open_incidents = (
                await session.scalars(
                    select(Incident).where(
                        Incident.status == "open",
                        Incident.title == name,
                        Incident.labels.contains({**scope, **INTERNAL_ORIGIN}),
                    )
                )
            ).all()
        for incident in open_incidents:
            if incident.fingerprint not in wanted:
                alerts.append(AlertIn(labels=incident.labels, endsAt=now))
        if alerts:
            await self._incidents.handle_alerts(alerts)

    async def set(self, name: str, severity: str, scope: dict[str, str], signal: Signal | None) -> None:
        """A check with a single outcome: firing with this signal, or not firing (None)."""
        await self.reconcile(name, severity, scope, [signal] if signal else [])
