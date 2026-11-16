from datetime import UTC, datetime, timedelta

import httpx

from app.incidents.review import alarm_stats, candidates, review_lines, suggestion
from app.incidents.schemas import AlertIn
from app.jobs import Jobs
from app.models import ActionJob
from tests.fakes import EN


def alert(name: str, ends=None, severity: str = "P2") -> AlertIn:
    return AlertIn(labels={"alertname": name, "severity": severity}, endsAt=ends)


async def blip(service, clock, name: str, minutes: int = 3) -> None:
    """The alarm fires and ends by itself after `minutes`."""
    await service.handle_alerts([alert(name)])
    clock.advance(timedelta(minutes=minutes))
    await service.handle_alerts([alert(name, ends=clock.now)])
    clock.advance(timedelta(hours=1))


async def test_no_alarms_in_the_week(sessions, clock):
    assert await review_lines(EN, sessions, clock.now) == ["No alerts in the last 7 days."]


async def test_a_short_untouched_alarm_that_repeats_is_a_false_alarm_candidate(service, sessions, clock):
    for _ in range(3):
        await blip(service, clock, "DiskBlip")

    [stat] = await alarm_stats(sessions, clock.now)
    lines = await review_lines(EN, sessions, clock.now)

    assert (stat.name, stat.count, stat.median, stat.touched) == ("DiskBlip", 3, timedelta(minutes=3), 0)
    assert candidates([stat]) == [stat]
    assert "• DiskBlip: 3x, median 3 min, taken over or handled 0" in lines
    assert any(line.startswith("• DiskBlip: for: usually set it to at least 5 min") for line in lines)


async def test_the_suggested_wait_is_at_least_five_minutes(service, sessions, clock):
    for _ in range(3):
        await blip(service, clock, "Flap", minutes=1)
    assert any("at least 5 min" in line for line in await review_lines(EN, sessions, clock.now))


async def test_a_taken_over_alarm_is_not_a_candidate(service, sessions, clock):
    for _ in range(2):
        await blip(service, clock, "Real")
    await service.handle_alerts([alert("Real")])
    assert await service.acknowledge(3, "U_ALICE")  # the third one was taken over while it fired
    await service.handle_alerts([alert("Real", ends=clock.now)])

    [stat] = await alarm_stats(sessions, clock.now)

    assert stat.touched == 1 and candidates([stat]) == []
    assert "No false-alarm candidates." in await review_lines(EN, sessions, clock.now)


async def test_long_or_rare_alarms_are_not_candidates(service, sessions, clock):
    await blip(service, clock, "Rare")
    await blip(service, clock, "Rare")  # only twice
    for _ in range(3):
        await blip(service, clock, "Slow", minutes=30)  # median too long
    assert candidates(await alarm_stats(sessions, clock.now)) == []


async def test_alarms_older_than_a_week_are_left_out(service, sessions, clock):
    await blip(service, clock, "Old")
    clock.advance(timedelta(days=8))
    assert await alarm_stats(sessions, clock.now) == []


async def test_the_weekly_report_has_the_alarm_review_even_without_security(service, sessions, chat, clock):
    clock.now = datetime(2026, 10, 18, 20, 0, tzinfo=UTC)  # the blips happen on the Sunday before
    for _ in range(3):
        await blip(service, clock, "DiskBlip")
    clock.now = datetime(2026, 10, 19, 7, 0, tzinfo=UTC)  # Monday 09:00 Vienna
    jobs = Jobs(service, chat, sessions, clock, "http://ops.test", None, httpx.AsyncClient(), locale=EN)

    await jobs.run_scheduled()

    weekly = [text for text in chat.ops if text.startswith("*Weekly report*")]
    assert len(weekly) == 1
    assert "*Alerts of the week*" in weekly[0] and "*Security*" not in weekly[0]
    assert "• DiskBlip: for:" in weekly[0]  # listed as a candidate with its suggestion


async def test_an_alarm_that_still_fires_is_not_a_candidate(service, sessions, clock):
    for _ in range(2):
        await blip(service, clock, "Still")
    await service.handle_alerts([alert("Still")])  # the third one has not ended

    [stat] = await alarm_stats(sessions, clock.now)

    assert stat.open == 1 and candidates([stat]) == []


async def test_the_same_alarm_on_two_hosts_is_two_entries(service, sessions, clock):
    for host in ("app-1", "app-2"):
        await service.handle_alerts([AlertIn(labels={"alertname": "DiskBlip", "severity": "P2", "host": host})])

    assert [s.name for s in await alarm_stats(sessions, clock.now)] == ["DiskBlip (app-1)", "DiskBlip (app-2)"]


async def test_ops_internal_incidents_are_left_out(service, sessions, clock):
    await service.handle_alerts(
        [AlertIn(labels={"alertname": "ScheduledJobFailed", "severity": "P2", "origin": "ops"})]
    )
    assert await alarm_stats(sessions, clock.now) == []


async def test_an_alarm_name_cannot_become_a_slack_mention(service, sessions, clock):
    await service.handle_alerts([alert("<!channel> & <@U1>")])
    text = "\n".join(await review_lines(EN, sessions, clock.now))
    assert "&lt;!channel&gt; &amp; &lt;@U1&gt;" in text and "<!channel>" not in text


async def test_an_expired_proposal_of_the_analysis_is_no_attention_but_an_approved_job_is(service, sessions, clock):
    for _ in range(3):
        await blip(service, clock, "Proposed")
    async with sessions() as session, session.begin():
        session.add(_job("a1", "analysis", None, clock.now))  # nobody approved it, it expired

    assert candidates(await alarm_stats(sessions, clock.now)) != []
    async with sessions() as session, session.begin():
        session.add(_job("a2", "U_ALICE", "U_ALICE", clock.now))
    assert candidates(await alarm_stats(sessions, clock.now)) == []


def _job(action_id, requested_by, approved_by, now):
    return ActionJob(
        action_id=action_id,
        runbook="image_prune",
        params={},
        host="app-1",
        status="expired" if approved_by is None else "succeeded",
        requested_by=requested_by,
        created_at=now,
        expires_at=now,
        approved_by=approved_by,
        incident_id=1,
    )


async def test_the_ops_pipeline_alarm_is_left_out(service, sessions, clock):
    await service.handle_alerts([alert("AlertingPipelineSilent", severity="P1")])
    assert await alarm_stats(sessions, clock.now) == []


async def test_one_long_run_does_not_stretch_the_suggestion_and_an_open_alarm_says_so(service, sessions, clock):
    for _ in range(3):
        await blip(service, clock, "Mixed", minutes=2)
    await blip(service, clock, "Mixed", minutes=180)
    [stat] = await alarm_stats(sessions, clock.now)
    assert "at least 11 min" in suggestion(EN, stat)
    await service.handle_alerts([alert("OnlyOpen")])
    assert any(line.startswith("• OnlyOpen: 1x, still open") for line in await review_lines(EN, sessions, clock.now))
