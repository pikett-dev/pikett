import json

import httpx
from pydantic import SecretStr

from app.notify.ntfy import NtfyPager
from tests.fakes import ALICE, EN, view


async def test_page_posts_json_with_topic_priority_and_auth():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await NtfyPager("https://ntfy.example/", SecretStr("tk_secret"), client, EN).page(
            ALICE, view(), escalated=False
        )

    request = seen[0]
    assert str(request.url) == "https://ntfy.example"
    assert request.headers["Authorization"] == "Bearer tk_secret"
    body = json.loads(request.content)
    assert body["topic"] == "topic-alice"
    assert body["priority"] == 5
    assert body["title"] == "P1 AppServerSilent"
    assert body["click"] == "http://ops.test/incidents/7"


async def test_escalation_is_marked_in_the_title():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await NtfyPager("https://ntfy.example", None, client, EN).page(ALICE, view(), escalated=True)

    assert json.loads(seen[0].content)["title"].startswith("Escalated: ")
    assert "Authorization" not in seen[0].headers


async def test_a_rejected_page_raises_so_the_service_retries():
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(403))) as client:
        try:
            await NtfyPager("https://ntfy.example", None, client, EN).page(ALICE, view(), escalated=False)
        except httpx.HTTPStatusError:
            return
    raise AssertionError("expected HTTPStatusError")
