import asyncio
from datetime import timedelta

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.incidents.schemas import AlertIn
from app.incidents.service import IncidentService
from app.models import Incident
from tests.fakes import Clock


def firing(name="DiskAlmostFull", severity="P2", **labels) -> AlertIn:
    return AlertIn(labels={"alertname": name, "severity": severity, **labels}, annotations={"summary": "Disk is full"})


def resolved(clock: Clock, name="DiskAlmostFull", severity="P2", **labels) -> AlertIn:
    return AlertIn(labels={"alertname": name, "severity": severity, **labels}, endsAt=clock.now)


WATCHDOG = AlertIn(labels={"alertname": "Watchdog", "severity": "none"})


async def tick(service: IncidentService, *still_firing: AlertIn) -> None:
    """One scheduler tick as it happens with a live vmalert: the watchdog and still-firing alerts are renewed."""
    await service.handle_alerts([WATCHDOG, *still_firing])
    await service.tick()


async def incidents(sessions: async_sessionmaker[AsyncSession]) -> list[Incident]:
    async with sessions() as session:
        return list((await session.scalars(select(Incident).order_by(Incident.id))).all())


async def test_repeated_firing_alert_opens_one_incident_and_posts_once(service, sessions, chat):
    await service.handle_alerts([firing()])
    await service.handle_alerts([firing()])

    assert len(await incidents(sessions)) == 1
    assert len(chat.posted) == 1
    assert chat.posted[0].title == "DiskAlmostFull"
    assert chat.posted[0].oncall_slack_id == "U_ALICE"


async def test_different_label_sets_are_different_incidents(service, sessions):
    await service.handle_alerts([firing(mountpoint="/"), firing(mountpoint="/data")])

    assert len(await incidents(sessions)) == 2


async def test_p1_pages_the_current_oncall_person(service, pager):
    await service.handle_alerts([firing("AppServerSilent", "P1")])

    assert pager.pages == [("Alice", False)]


async def test_p2_does_not_page_and_p3_is_not_posted(service, pager, chat):
    await service.handle_alerts([firing(severity="P2"), firing("Minor", "P3")])

    assert pager.pages == []
    assert [view.title for view in chat.posted] == ["DiskAlmostFull"]


async def test_unknown_severity_falls_back_to_p2(service, sessions):
    await service.handle_alerts([firing(severity="critical")])

    assert (await incidents(sessions))[0].severity == "P2"


async def test_resolved_alert_closes_the_incident_and_announces_it(service, sessions, chat, clock):
    await service.handle_alerts([firing()])
    clock.advance(timedelta(minutes=12))
    await service.handle_alerts([resolved(clock)])

    incident = (await incidents(sessions))[0]
    assert incident.status == "resolved"
    assert chat.updates[-1].status == "resolved"
    assert chat.replies == ["Resolved after 12 min."]


async def test_resolved_alert_without_open_incident_is_ignored(service, sessions, chat, clock):
    await service.handle_alerts([resolved(clock)])

    assert await incidents(sessions) == []
    assert chat.updates == []


async def test_the_same_alert_after_resolution_opens_a_new_incident(service, sessions, clock):
    await service.handle_alerts([firing()])
    await service.handle_alerts([resolved(clock)])
    clock.advance(timedelta(minutes=5))
    await service.handle_alerts([firing()])

    assert [i.status for i in await incidents(sessions)] == ["resolved", "open"]


async def test_incident_resolved_before_it_was_posted_is_not_announced(service, sessions, chat, clock):
    chat.fail_next_post = True
    await service.handle_alerts([firing()])
    await service.handle_alerts([resolved(clock)])
    await tick(service)

    assert chat.posted == [] and chat.updates == [] and chat.replies == []
    assert (await incidents(sessions))[0].resolution_posted_at is not None


async def test_failed_chat_post_is_retried_on_the_next_tick(service, sessions, chat):
    chat.fail_next_post = True
    await service.handle_alerts([firing()])
    assert (await incidents(sessions))[0].slack_ts is None

    await tick(service, firing())

    assert len(chat.posted) == 1
    assert (await incidents(sessions))[0].slack_ts is not None


async def test_failed_page_is_retried_on_the_next_tick(service, pager):
    pager.fail_next = True
    await service.handle_alerts([firing("AppServerSilent", "P1")])
    assert pager.pages == []

    await tick(service, firing("AppServerSilent", "P1"))

    assert pager.pages == [("Alice", False)]


async def test_unacknowledged_p1_escalates_once_to_the_second_person(service, pager, chat, clock):
    await service.handle_alerts([firing("AppServerSilent", "P1")])
    clock.advance(timedelta(minutes=11))
    await tick(service, firing("AppServerSilent", "P1"))
    await tick(service, firing("AppServerSilent", "P1"))

    assert pager.pages == [("Alice", False), ("Bob", True)]
    assert "U_BOB" in chat.replies[0]


async def test_acknowledging_stops_the_escalation(service, pager, clock):
    await service.handle_alerts([firing("AppServerSilent", "P1")])
    assert await service.acknowledge(1, "U_ALICE")
    clock.advance(timedelta(minutes=30))
    await tick(service, firing("AppServerSilent", "P1"))

    assert pager.pages == [("Alice", False)]


async def test_acknowledging_updates_the_message_with_the_name(service, chat):
    await service.handle_alerts([firing()])
    await service.acknowledge(1, "U_ALICE")

    assert chat.updates[-1].acked_by == "U_ALICE"


async def test_acknowledging_a_resolved_incident_is_refused(service, clock):
    await service.handle_alerts([firing()])
    await service.handle_alerts([resolved(clock)])

    assert not await service.acknowledge(1, "U_ALICE")
    assert not await service.acknowledge(999, "U_ALICE")


async def test_silence_suppresses_escalation_until_it_expires(service, pager, clock):
    await service.handle_alerts([firing("AppServerSilent", "P1")])
    await service.silence(1, "U_ALICE", timedelta(hours=1))
    clock.advance(timedelta(minutes=30))
    await tick(service, firing("AppServerSilent", "P1"))
    assert pager.pages == [("Alice", False)]

    clock.advance(timedelta(minutes=31))
    await tick(service, firing("AppServerSilent", "P1"))
    assert pager.pages == [("Alice", False), ("Bob", True)]


async def test_p2_reminder_after_four_hours_and_then_not_again_right_away(service, chat, clock):
    await service.handle_alerts([firing()])
    clock.advance(timedelta(hours=4, minutes=1))
    await tick(service, firing())
    await tick(service, firing())

    assert chat.replies == ["Running for 241 min and still open."]


async def test_reminders_stop_after_the_maximum(service, chat, clock):
    await service.handle_alerts([firing()])
    for _ in range(5):
        clock.advance(timedelta(hours=4, minutes=1))
        await tick(service, firing())

    assert len(chat.replies) == 3


async def test_events_form_a_timeline(service, sessions, clock):
    await service.handle_alerts([firing("AppServerSilent", "P1")])
    await service.acknowledge(1, "U_ALICE")
    await service.handle_alerts([resolved(clock, "AppServerSilent", "P1")])

    async with sessions() as session:
        events = (await session.execute(text("SELECT kind FROM incident_event ORDER BY id"))).all()
    assert [e[0] for e in events] == ["opened", "posted", "paged", "acked", "resolved"]


async def test_missing_watchdog_opens_a_p1_for_the_alerting_pipeline_and_pages(service, pager, clock):
    await service.tick()
    assert pager.pages == []

    clock.advance(timedelta(minutes=6))
    await service.tick()

    assert pager.pages == [("Alice", False)]


async def test_returning_watchdog_closes_the_pipeline_incident(service, sessions, clock):
    clock.advance(timedelta(minutes=6))
    await service.tick()
    await tick(service)

    incident = (await incidents(sessions))[0]
    assert incident.title == "AlertingPipelineSilent" and incident.status == "resolved"


async def test_watchdog_never_becomes_an_incident(service, sessions):
    await service.handle_alerts([WATCHDOG])

    assert await incidents(sessions) == []


async def test_incident_that_vmalert_stopped_renewing_is_closed_as_stale(service, sessions, chat, clock):
    await service.handle_alerts([firing()])
    clock.advance(timedelta(minutes=11))
    await tick(service)

    assert (await incidents(sessions))[0].status == "resolved"
    assert chat.replies == ["Resolved after 11 min."]


async def test_renewed_incident_is_not_stale(service, sessions, clock):
    await service.handle_alerts([firing()])
    for _ in range(3):
        clock.advance(timedelta(minutes=5))
        await tick(service, firing())

    assert (await incidents(sessions))[0].status == "open"


async def test_nothing_is_closed_as_stale_while_the_pipeline_is_silent(service, sessions, clock):
    await service.handle_alerts([firing()])
    clock.advance(timedelta(minutes=20))
    await service.tick()  # no watchdog arrived

    by_title = {i.title: i.status for i in await incidents(sessions)}
    assert by_title["DiskAlmostFull"] == "open"
    assert by_title["AlertingPipelineSilent"] == "open"


async def test_concurrent_deliveries_page_only_once(service, pager):
    pager.fail_next = True
    await service.handle_alerts([firing("AppServerSilent", "P1")])
    pager.delay = 0.05

    await asyncio.gather(service.deliver(1), service.deliver(1), service.deliver(1))

    assert pager.pages == [("Alice", False)]
