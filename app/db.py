import logging
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path

from sqlalchemy import func, select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from app.models import AgentSpend, JobRun

log = logging.getLogger(__name__)

MIGRATIONS_DIR = Path(__file__).parent / "migrations"


def create_engine(url: str) -> AsyncEngine:
    return create_async_engine(url, pool_pre_ping=True)


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


async def migrate(engine: AsyncEngine) -> None:
    """Apply numbered SQL files from app/migrations once, in order."""
    async with engine.begin() as conn:
        # Serialize concurrent starts.
        await conn.execute(text("SELECT pg_advisory_xact_lock(727001)"))
        await conn.execute(
            text(
                "CREATE TABLE IF NOT EXISTS schema_migration ("
                "version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"
            )
        )
        applied = {row[0] for row in await conn.execute(text("SELECT version FROM schema_migration"))}
        for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
            if path.name in applied:
                continue
            log.info("applying migration %s", path.name)
            # The raw asyncpg connection runs a whole script (several statements, function bodies), inside the
            # transaction SQLAlchemy has already opened on it.
            driver = (await conn.get_raw_connection()).driver_connection
            if driver is None:
                raise RuntimeError("the database connection has no driver connection")
            await driver.execute(path.read_text())
            await conn.execute(text("INSERT INTO schema_migration (version) VALUES (:v)"), {"v": path.name})


async def last_run(session: AsyncSession, name: str) -> datetime | None:
    row = await session.get(JobRun, name)
    return row.last_run_at if row else None


async def mark_run(session: AsyncSession, name: str, at: datetime) -> None:
    await session.execute(
        insert(JobRun)
        .values(name=name, last_run_at=at)
        .on_conflict_do_update(index_elements=[JobRun.name], set_={"last_run_at": at})
    )


async def spent_on(session: AsyncSession, day: date) -> Decimal:
    total = await session.scalar(select(func.coalesce(func.sum(AgentSpend.cost_usd), 0)).where(AgentSpend.day == day))
    return Decimal(total or 0)


async def add_spend(session: AsyncSession, day: date, model: str, cost_usd: Decimal) -> None:
    await session.execute(
        insert(AgentSpend)
        .values(day=day, model=model, cost_usd=cost_usd, requests=1)
        .on_conflict_do_update(
            index_elements=[AgentSpend.day, AgentSpend.model],
            set_={"cost_usd": AgentSpend.cost_usd + cost_usd, "requests": AgentSpend.requests + 1},
        )
    )
