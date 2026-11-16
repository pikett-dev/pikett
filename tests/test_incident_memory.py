from datetime import timedelta

from sqlalchemy import text

from app.incidents.memory import latest_backed_analysis, memory_key
from app.incidents.schemas import AlertIn
from app.models import IncidentAnalysis
from tests.test_service import incidents


def alert(name="DiskAlmostFull", ends=None, **labels) -> AlertIn:
    return AlertIn(labels={"alertname": name, "severity": "P2", **labels}, endsAt=ends)


def test_the_key_is_the_alarm_and_all_its_labels_but_the_severity_and_internal_incidents_have_none():
    core = {"alertname": "HighErrorRate", "severity": "P1", "service.name": "core", "host": "app-1"}
    admin = {**core, "service.name": "admin-frontend"}
    assert memory_key(core, "HighErrorRate") != memory_key(admin, "HighErrorRate")  # two services, two problems
    assert memory_key(core, "x") == memory_key({**core, "severity": "P2"}, "x")  # the severity is no identity
    assert memory_key({"alertname": "A"}, "A") == memory_key({}, "A")  # the title stands in for a missing name
    assert memory_key({"alertname": "A", "app": "core"}, "A") != memory_key({"alertname": "A", "app": "admin"}, "A")
    assert memory_key({"alertname": "ScheduledJobFailed", "origin": "ops"}, "ScheduledJobFailed") is None


async def add_analysis(sessions, incident_id, clock, *, status="done", verified=True, analysis=None):
    async with sessions() as session, session.begin():
        session.add(
            IncidentAnalysis(
                incident_id=incident_id,
                requested_by="auto",
                status=status,
                started_at=clock.now,
                finished_at=clock.now,
                verified=verified,
                analysis={"cause": "Disk full", "immediate_action": "prune"} if analysis is None else analysis,
            )
        )


async def reopen(service, clock, **labels):
    """The alarm fires, ends, and fires again: the second incident is the same problem."""
    await service.handle_alerts([alert(**labels)])
    clock.advance(timedelta(minutes=5))
    await service.handle_alerts([alert(**labels, ends=clock.now)])
    clock.advance(timedelta(hours=1))
    await service.handle_alerts([alert(**labels)])


async def test_an_incident_gets_its_key_when_it_opens(service, sessions):
    await service.handle_alerts([alert(service="core", host="app-1")])
    [incident] = await incidents(sessions)
    assert incident.memory_key == memory_key({"alertname": "DiskAlmostFull", "service": "core", "host": "app-1"}, "")


async def test_the_known_solution_is_the_latest_backed_analysis_of_an_earlier_incident(service, sessions, clock):
    await reopen(service, clock, host="app-1")
    await add_analysis(sessions, 1, clock)
    first, second = await incidents(sessions)

    async with sessions() as session:
        known = await latest_backed_analysis(session, second)
        assert known is not None and (known.incident_id, known.analysis["cause"]) == (first.id, "Disk full")
        assert await latest_backed_analysis(session, first) is None  # its own analysis is not "earlier"


async def test_unbacked_failed_or_other_alarms_are_not_a_known_solution(service, sessions, clock):
    await reopen(service, clock, host="app-1")
    await add_analysis(sessions, 1, clock, verified=False)
    await add_analysis(sessions, 1, clock, status="failed")
    await service.handle_alerts([alert("OtherAlarm", host="app-1")])
    await add_analysis(sessions, 3, clock)
    first, second, other = await incidents(sessions)

    async with sessions() as session:
        assert await latest_backed_analysis(session, second) is None
        assert await latest_backed_analysis(session, other) is None


async def test_the_same_alarm_on_another_host_is_another_problem(service, sessions, clock):
    await service.handle_alerts([alert(host="app-1")])
    await add_analysis(sessions, 1, clock)
    await service.handle_alerts([alert(host="app-2")])
    _, other_host = await incidents(sessions)

    async with sessions() as session:
        assert await latest_backed_analysis(session, other_host) is None


async def test_the_migration_drops_the_old_keys(service, sessions):
    await service.handle_alerts([alert(service="core", host="app-1")])
    async with sessions() as session, session.begin():
        await session.execute(text("UPDATE incident SET memory_key = 'old|core|app-1'"))
    async with sessions() as session, session.begin():
        await session.execute(text("UPDATE incident SET memory_key = NULL WHERE memory_key IS NOT NULL"))  # 017
    assert [i.memory_key for i in await incidents(sessions)] == [None]
