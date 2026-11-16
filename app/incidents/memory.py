"""The incident memory: the same alarm with the same labels is the same problem again.

An incident gets a key when it opens: the alarm name plus its labels, see `memory_key`. The known solution of a key is
the latest analysis of an earlier incident with that key that finished and whose evidence checked out. Nothing here
calls a model.
"""

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Incident, IncidentAnalysis

# Incidents raised by the ops service itself (app/security/signals.py) carry this label; the stale cleanup, the alarm
# review and the memory leave them alone. It lives here because incidents/service.py imports this module.
INTERNAL_ORIGIN = {"origin": "ops"}


def memory_key(labels: dict[str, str], title: str) -> str | None:
    """The alarm name and every other label but the severity: the labels of an alert are what its rule grouped by
    (`service.name`, `app`, `mountpoint`, `host`, ...), so the same labels are the same problem again. None for
    incidents the ops service raised itself: they have no recurring rule."""
    if INTERNAL_ORIGIN.items() <= labels.items():
        return None
    identity = {k: v for k, v in labels.items() if k not in ("alertname", "severity")}
    return json.dumps([labels.get("alertname") or title, sorted(identity.items())], ensure_ascii=False)


@dataclass(frozen=True)
class KnownSolution:
    incident_id: int  # the earlier incident
    analysis_id: int
    finished_at: datetime
    analysis: dict[str, Any]  # the stored analysis (summary, cause, immediate_action, ...)


async def latest_backed_analysis(
    session: AsyncSession, incident: Incident, *, helpful_only: bool = False
) -> KnownSolution | None:
    """The latest analysis of an earlier incident with the same key: finished, with every quote found in the data.
    With `helpful_only` it is the latest analysis a person rated, and only if they rated it helpful."""
    if incident.memory_key is None:
        return None
    query = (
        select(IncidentAnalysis, Incident.id)
        .join(Incident, Incident.id == IncidentAnalysis.incident_id)
        .where(
            Incident.memory_key == incident.memory_key,
            Incident.id != incident.id,
            IncidentAnalysis.status == "done",
            IncidentAnalysis.verified.is_(True),
            IncidentAnalysis.analysis.is_not(None),
        )
        .order_by(IncidentAnalysis.finished_at.desc())
        .limit(1)
    )
    if helpful_only:  # the latest verdict decides: a newer "not helpful" retires an older "helpful"
        query = query.where(IncidentAnalysis.feedback.is_not(None))
    row = (await session.execute(query)).first()
    if row is None:
        return None
    analysis, incident_id = row
    if helpful_only and analysis.feedback != "helpful":
        return None
    assert analysis.finished_at is not None and analysis.analysis is not None  # noqa: S101 (the query ensures both)
    return KnownSolution(incident_id, analysis.id, analysis.finished_at, analysis.analysis)
