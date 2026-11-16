from datetime import datetime
from typing import Any

from sqlalchemy import select

from app.models import Incident
from app.security.hostreports import HostReportIn


def report(host: str, kind: str, at: datetime, **data: Any) -> HostReportIn:
    return HostReportIn(host=host, kind=kind, collected_at=at, data=data)


async def open_incidents(sessions, title: str | None = None) -> list[Incident]:
    async with sessions() as session:
        query = select(Incident).where(Incident.status == "open").order_by(Incident.id)
        if title is not None:
            query = query.where(Incident.title == title)
        return list((await session.scalars(query)).all())
