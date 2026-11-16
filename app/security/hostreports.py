"""Reports pushed by the collector on each server (deploy/host-agent/ops-collect.py)."""

from datetime import datetime
from typing import Any

from pydantic import AwareDatetime, BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import distinct_on
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import HostReport

HOST_PATTERN = r"^[a-z0-9][a-z0-9-]{0,62}$"
KIND_PATTERN = r"^[a-z][a-z0-9_]{0,31}$"


class HostReportIn(BaseModel):
    host: str = Field(pattern=HOST_PATTERN)
    kind: str = Field(pattern=KIND_PATTERN)
    collected_at: AwareDatetime
    # What the collector read, raw. Its own failure arrives as {"error": "..."} so a broken run is not silent.
    data: dict[str, Any]


async def store(session: AsyncSession, report: HostReportIn, received_at: datetime) -> HostReport:
    row = HostReport(
        host=report.host,
        kind=report.kind,
        collected_at=report.collected_at,
        received_at=received_at,
        data=report.data,
    )
    session.add(row)
    await session.flush()
    return row


async def latest(session: AsyncSession, kind: str) -> dict[str, HostReport]:
    """The newest report of this kind per host."""
    rows = await session.scalars(
        select(HostReport)
        .where(HostReport.kind == kind)
        .order_by(HostReport.host, HostReport.received_at.desc(), HostReport.id.desc())
        .ext(distinct_on(HostReport.host))
    )
    return {row.host: row for row in rows}


async def history(session: AsyncSession, kind: str, since: datetime) -> list[HostReport]:
    """All reports of this kind since `since`, oldest first."""
    rows = await session.scalars(
        select(HostReport)
        .where(HostReport.kind == kind, HostReport.received_at >= since)
        .order_by(HostReport.received_at, HostReport.id)
    )
    return list(rows)


async def previous(session: AsyncSession, report: HostReport) -> HostReport | None:
    """The report of the same host and kind before this one."""
    return await session.scalar(
        select(HostReport)
        .where(HostReport.host == report.host, HostReport.kind == report.kind, HostReport.id < report.id)
        .order_by(HostReport.id.desc())
        .limit(1)
    )


async def prune(session: AsyncSession, before: datetime) -> None:
    await session.execute(delete(HostReport).where(HostReport.received_at < before))


def error_of(data: dict[str, Any]) -> str | None:
    """The collector's own failure for this report, if any."""
    error = data.get("error")
    return str(error) if error else None
