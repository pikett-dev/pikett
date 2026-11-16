import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.config import Settings
from app.db import create_engine
from app.main import create_app
from tests.fakes import ALICE, BOB, START, Clock, FakeChat, FakePager

ALERT = {
    "labels": {"alertname": "AppServerSilent", "severity": "P1"},
    "annotations": {"summary": "Keine Metriken vom App-Server"},
    "startsAt": "2026-10-19T09:55:00Z",
    "endsAt": "0001-01-01T00:00:00Z",
    "generatorURL": "http://vmalert/rule",
}


@pytest.fixture
def client(database_url, sessions):  # `sessions` migrates and truncates the shared database first
    settings = Settings(database_url=database_url, base_url="http://ops.test", oncall_people=[ALICE, BOB])
    chat, pager = FakeChat(), FakePager()
    with TestClient(create_app(settings, chat=chat, pager=pager, clock=Clock(START))) as client:
        client.chat, client.pager = chat, pager
        yield client


def test_vmalert_payload_opens_an_incident_that_has_a_page(client):
    response = client.post("/api/v2/alerts", json=[ALERT])

    assert response.status_code == 200
    assert client.chat.posted[0].title == "AppServerSilent"
    assert client.pager.pages == [("Alice", False)]

    page = client.get("/incidents/1")
    assert page.status_code == 200
    assert "AppServerSilent" in page.text and "Keine Metriken vom App-Server" in page.text
    assert "opened" in page.text


def test_incident_list_and_missing_incident(client):
    assert "No alerts yet" in client.get("/incidents").text
    client.post("/api/v2/alerts", json=[ALERT])
    assert "AppServerSilent" in client.get("/incidents").text
    assert client.get("/incidents/999").status_code == 404


def test_resolved_payload_closes_the_incident(client):
    client.post("/api/v2/alerts", json=[ALERT])
    client.post("/api/v2/alerts", json=[{**ALERT, "endsAt": "2026-10-19T10:00:00Z"}])

    assert "Resolved" in client.get("/incidents/1").text


def test_labels_in_the_page_are_escaped(client):
    client.post("/api/v2/alerts", json=[{**ALERT, "labels": {**ALERT["labels"], "x": "<script>alert(1)</script>"}}])

    page = client.get("/incidents/1").text
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page


def test_garbage_payload_is_rejected(client):
    assert client.post("/api/v2/alerts", json={"not": "a list"}).status_code == 422


async def test_migrations_can_run_twice(database_url):
    engine = create_engine(database_url)
    from app.db import MIGRATIONS_DIR, migrate

    await migrate(engine)
    await migrate(engine)
    async with engine.connect() as conn:
        count = (await conn.execute(text("SELECT count(*) FROM schema_migration"))).scalar_one()
    await engine.dispose()
    assert count == len(list(MIGRATIONS_DIR.glob("*.sql")))  # each file applied once, however often migrate runs


def _store_analysis(database_url):
    import asyncio
    from datetime import UTC, datetime

    from app.db import create_session_factory
    from app.models import IncidentAnalysis

    async def go():
        engine = create_engine(database_url)
        async with create_session_factory(engine)() as session, session.begin():
            session.add(
                IncidentAnalysis(
                    incident_id=1,
                    requested_by="U_ALICE",
                    status="done",
                    started_at=datetime(2026, 10, 19, 10, 0, tzinfo=UTC),
                    model="claude-opus-5-5",
                    verified=True,
                    dropped_evidence=0,
                    cost_usd=0.1,
                    feedback="helpful",
                    feedback_by="U_BOB",
                    analysis={
                        "summary": "Der Pool ist erschöpft",
                        "cause": "Alle Verbindungen belegt",
                        "evidence": [{"quote": "Connection is not available", "source": "query_logs"}],
                        "confidence": "medium",
                        "affected": "core",
                        "immediate_action": "Neustart",
                        "fix_suggestion": "Pool prüfen",
                        "risk": "kurz",
                    },
                )
            )
        await engine.dispose()

    asyncio.run(go())


def test_without_an_api_key_the_page_has_no_analysis_section_and_no_button(client):
    client.post("/api/v2/alerts", json=[ALERT])
    assert "KI-Analyse" not in client.get("/incidents/1").text


def test_with_an_api_key_the_page_shows_the_analysis_and_the_budget(database_url, sessions):
    from pydantic import SecretStr

    settings = Settings(
        database_url=database_url,
        base_url="http://ops.test",
        oncall_people=[ALICE, BOB],
        anthropic_api_key=SecretStr("sk-test"),
        agent_auto_analyze=False,  # no model call in this test
    )
    with TestClient(create_app(settings, chat=FakeChat(), pager=FakePager(), clock=Clock(START))) as client:
        client.post("/api/v2/alerts", json=[ALERT])
        assert "No analysis yet" in client.get("/incidents/1").text
        _store_analysis(database_url)
        page = client.get("/incidents/1").text
    assert "AI analysis" in page and "Der Pool ist erschöpft" in page and "Connection is not available" in page
    assert "Daily budget" in page and "of 5.00 USD" in page and "U_ALICE" in page
    assert "Rated as helpful by U_BOB" in page
