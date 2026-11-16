"""German stays available: the same behaviour with `language="de"`, next to the English default."""

from datetime import date, timedelta

import httpx
import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.incidents.digest import build_digest
from app.incidents.schemas import AlertIn
from app.incidents.service import IncidentService
from app.jobs import Jobs
from app.main import create_app
from app.models import IncidentAnalysis
from app.notify.blocks import analysis_text, fallback_text, incident_blocks
from app.notify.slack import ButtonActions
from app.oncall import OnCall
from app.security.backup import BackupCheck, Database, Run
from app.security.service import SecurityService
from app.security.signals import Signals
from tests.fakes import ALICE, BOB, DE, EN, START, Clock, FakeChat, FakePager, view
from tests.security_helpers import open_incidents


@pytest.fixture
def german(sessions, chat, pager, clock) -> IncidentService:
    return IncidentService(
        sessions, chat, pager, OnCall([ALICE, BOB], date(2026, 10, 19), DE), clock, "http://ops.test", locale=DE
    )


def alert(name: str, severity: str = "P2", ends=None) -> AlertIn:
    return AlertIn(labels={"alertname": name, "severity": severity}, endsAt=ends)


def buttons(blocks) -> list[str]:
    return [element["text"]["text"] for element in blocks[1]["elements"]]


def test_a_web_page_is_german(database_url, sessions):
    settings = Settings(database_url=database_url, language="de", timezone="Europe/Vienna")
    with TestClient(create_app(settings, chat=FakeChat(), pager=FakePager(), clock=Clock(START))) as client:
        page = client.get("/ops").text
        history = client.get("/ops/history").text

        assert '<html lang="de">' in page
        assert "Übersicht" in page and "Verlauf" in page and "Hilfe" in page and "Alarme" in page
        assert "Alles in Ordnung" in page or "Prüfungen" in page
        assert "Verlauf" in history and "Läufe" in history and "Zeitraum" in history
        assert "7 Tage" in history and "Overview" not in page


def test_the_incident_message_in_slack_is_german():
    blocks = incident_blocks(DE, view(), analyze_button=True)

    assert buttons(blocks) == [
        "Übernehmen",
        "1 h stumm",
        "24 h stumm",
        "Tiefer analysieren",
        "Mit Opus analysieren",
        "Details",
    ]
    text = blocks[0]["text"]["text"]
    assert "Seit 12:00" in text and "Bereitschaft: <@U_ALICE>" in text
    assert fallback_text(DE, view(status="resolved")) == "P1 AppServerSilent (behoben)"
    assert "Übernommen von <@U_BOB>" in incident_blocks(DE, view(acked_by="U_BOB"))[0]["text"]["text"]


async def test_the_replies_in_the_incident_thread_are_german(german, chat, clock):
    await german.handle_alerts([alert("Fixed")])
    clock.advance(timedelta(minutes=5))
    await german.handle_alerts([alert("Fixed", ends=clock.now)])
    await german.tick()

    assert "Behoben nach 5 min." in chat.replies


async def test_a_button_answer_is_german(german):
    actions = ButtonActions(["U_ALICE"], DE)
    actions.service = german

    assert await actions.handle("U_MALLORY", "incident_ack", 1) == "Dafür fehlt dir die Berechtigung."
    assert await actions.handle("U_ALICE", "incident_ack", 999) == "Der Alarm ist nicht mehr offen."


def test_the_analysis_text_is_german():
    analysis = {
        "summary": "Login schlägt fehl",
        "cause": "Pool voll",
        "confidence": "low",
        "evidence": [],
        "affected": "core",
        "immediate_action": "Neustart",
        "fix_suggestion": "Pool vergrößern",
        "risk": "kurz",
    }
    run = IncidentAnalysis(
        status="done", model="claude-opus-5-5", cost_usd=0.123, verified=False, dropped_evidence=2, analysis=analysis
    )

    text = analysis_text(DE, run, "http://ops.test/incidents/7")

    assert "*KI-Analyse* (claude-opus-5-5, 0,12 USD)" in text and "*Zusammenfassung:* Login schlägt fehl" in text
    assert "Konfidenz niedrig" in text and "*Sofort:* Neustart" in text and "*Dauerhaft:* Pool vergrößern" in text
    assert "Kein Zitat konnte in den Abfrageergebnissen gefunden werden" in text
    failed = analysis_text(DE, IncidentAnalysis(status="failed", error=None), "u")
    assert failed == ":warning: Die KI-Analyse ist fehlgeschlagen: unbekannter Fehler\nDetails: u"


async def test_the_daily_digest_is_german(german, sessions, clock):
    assert "Keine Alarme in den letzten 24 Stunden." in await build_digest(DE, sessions, clock.now, "http://ops.test")
    await german.handle_alerts([alert("StillBroken", "P1"), alert("Fixed")])
    clock.advance(timedelta(minutes=30))
    await german.handle_alerts([alert("Fixed", ends=clock.now)])
    clock.advance(timedelta(hours=1))

    text = await build_digest(DE, sessions, clock.now, "http://ops.test/")

    assert text.startswith("*Tagesbericht*")
    assert "*Offen (1)*" in text and "P1 <http://ops.test/incidents/1|StillBroken>, seit 90 min" in text
    assert "*Behoben in den letzten 24 h (1)*" in text and "P2 Fixed, Dauer 30 min" in text


async def test_the_posted_digest_is_german(german, chat, sessions):
    jobs = Jobs(german, chat, sessions, Clock(START), "http://ops.test", None, httpx.AsyncClient(), locale=DE)

    await jobs._post_digest(START)

    assert chat.ops[-1].startswith("*Tagesbericht*") and "Keine Alarme in den letzten 24 Stunden." in chat.ops[-1]


async def test_a_security_alert_is_german(sessions, german, clock):
    class Source:
        async def database(self, uuid: str) -> Database:
            return Database(
                uuid=uuid, name="app-db", schedules=[], runs=[Run(status="success", size=1, created_at=START)]
            )

    signals = Signals(sessions, german, clock)
    check = BackupCheck(sessions, signals, clock, Source(), ["db-1"], locale=DE)
    security = SecurityService(sessions, signals, clock, [check], locale=DE)

    await check.periodic(clock.now)

    [incident] = await open_incidents(sessions)
    assert incident.annotations["summary"] == "app-db hat in Coolify keinen aktiven Backup-Zeitplan."
    assert (await security.daily_lines(clock.now))[0].startswith(":red_circle: Backup (app-db): ")


async def test_an_english_and_a_german_service_run_side_by_side(service, german, sessions, clock):
    await service.handle_alerts([alert("OnlyEnglish")])
    await german.handle_alerts([alert("OnlyGerman")])
    clock.advance(timedelta(minutes=90))

    english = await build_digest(EN, sessions, clock.now, "http://ops.test")
    deutsch = await build_digest(DE, sessions, clock.now, "http://ops.test")

    assert "*Daily report*" in english and "*Open (2)*" in english and "for 90 min" in english
    assert "*Tagesbericht*" in deutsch and "*Offen (2)*" in deutsch and "seit 90 min" in deutsch
    assert "Open" not in deutsch and "Offen" not in english
