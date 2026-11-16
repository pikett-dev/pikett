from collections.abc import AsyncIterator, Iterator
from datetime import date

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from testcontainers.community.postgres import PostgresContainer

from app.db import create_engine, create_session_factory, migrate
from app.i18n import set_strict
from app.incidents.service import IncidentService
from app.notify.slack import ButtonActions
from app.oncall import OnCall
from tests.fakes import ALICE, BOB, EN, START, Clock, FakeChat, FakePager

# Every table the tests write to; each test starts from empty tables.
TABLES = [
    "fix_pr",
    "action_job",
    "action_audit",
    "runner_heartbeat",
    "incident",
    "incident_event",
    "job_run",
    "agent_spend",
    "host_report",
    "vulnerability_finding",
    "kev_entry",
    "epss_score",
    "check_state",
    "reboot_request",
    "ops_run",
]


@pytest.fixture(autouse=True)
def _strict_messages() -> None:
    """A missing message key fails the test; in production it falls back to English."""
    set_strict(True)


@pytest.fixture(scope="session")
def database_url() -> Iterator[str]:
    with PostgresContainer("postgres:18", driver="asyncpg") as postgres:
        yield postgres.get_connection_url()


@pytest.fixture
async def sessions(database_url: str) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_engine(database_url)
    await migrate(engine)
    async with engine.begin() as conn:
        await conn.execute(text(f"TRUNCATE {', '.join(TABLES)} RESTART IDENTITY CASCADE"))
    yield create_session_factory(engine)
    await engine.dispose()


@pytest.fixture
def clock() -> Clock:
    return Clock(START)


@pytest.fixture
def chat() -> FakeChat:
    return FakeChat()


@pytest.fixture
def pager() -> FakePager:
    return FakePager()


@pytest.fixture
def service(
    sessions: async_sessionmaker[AsyncSession], chat: FakeChat, pager: FakePager, clock: Clock
) -> IncidentService:
    return IncidentService(
        sessions, chat, pager, OnCall([ALICE, BOB], date(2026, 10, 19), EN), clock, "http://ops.test", locale=EN
    )


@pytest.fixture
def actions(service: IncidentService) -> ButtonActions:
    actions = ButtonActions(["U_ALICE"], EN)
    actions.service = service
    return actions
