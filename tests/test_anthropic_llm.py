from typing import Any

import anthropic
import httpx2
import pytest
from anthropic.types import Message

from app.agent.llm import AnthropicLlm, LlmError


def message() -> Message:
    return Message.model_validate(
        {
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "model": "claude-opus-5-5",
            "stop_reason": "tool_use",
            "stop_sequence": None,
            "content": [
                {"type": "text", "text": "Looking at the logs."},
                {"type": "tool_use", "id": "toolu_1", "name": "query_logs", "input": {"query": "error"}},
            ],
            "usage": {
                "input_tokens": 120,
                "output_tokens": 45,
                "cache_creation_input_tokens": 3000,
                "cache_read_input_tokens": None,
            },
        }
    )


class StubClient:
    def __init__(self, result: Any) -> None:
        self.result = result
        self.params: dict[str, Any] = {}
        self.messages = self

    async def create(self, **params: Any) -> Any:
        self.params = params
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


async def test_request_turns_on_automatic_caching_and_maps_the_reply():
    client = StubClient(message())
    reply = await AnthropicLlm(client).complete(  # type: ignore[arg-type]
        model="claude-opus-5-5",
        system="be careful",
        tools=[{"name": "t", "description": "d", "input_schema": {"type": "object"}}],
        messages=[{"role": "user", "content": "hi"}],
        max_tokens=100,
    )
    # automatic caching: the breakpoint follows the conversation, so earlier turns and tool results are cached too
    assert client.params["system"] == "be careful" and client.params["cache_control"] == {"type": "ephemeral"}
    assert client.params["model"] == "claude-opus-5-5" and client.params["timeout"] > 0
    assert reply.stop_reason == "tool_use"
    assert [(c.id, c.name, c.input) for c in reply.tool_calls] == [("toolu_1", "query_logs", {"query": "error"})]
    assert (reply.usage.input_tokens, reply.usage.output_tokens) == (120, 45)
    assert (reply.usage.cache_write_tokens, reply.usage.cache_read_tokens) == (3000, 0)
    assert reply.raw[1] == {"type": "tool_use", "id": "toolu_1", "name": "query_logs", "input": {"query": "error"}}


async def test_api_errors_become_llm_errors_without_request_content():
    error = anthropic.APIConnectionError(request=httpx2.Request("POST", "https://api.anthropic.com/v1/messages"))
    client = StubClient(error)
    with pytest.raises(LlmError, match="APIConnectionError"):
        await AnthropicLlm(client).complete(  # type: ignore[arg-type]
            model="m", system="s", tools=[], messages=[{"role": "user", "content": "anna@example.at"}], max_tokens=10
        )


async def test_the_models_reply_survives_the_round_trip_through_the_real_sdk_unchanged():
    """The adapter hands SDK block objects back as the assistant turn; check what the SDK puts on the wire."""
    import json

    from anthropic import AsyncAnthropic, DefaultAsyncHttpxClient

    bodies: list[dict[str, Any]] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        bodies.append(json.loads(request.content))
        return httpx2.Response(200, json=message().model_dump(mode="json"))

    http = DefaultAsyncHttpxClient(transport=httpx2.MockTransport(handler))
    llm = AnthropicLlm(AsyncAnthropic(api_key="test", http_client=http, max_retries=0))
    first = await llm.complete(
        model="m", system="s", tools=[], messages=[{"role": "user", "content": "hi"}], max_tokens=10
    )
    turns = [
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": first.raw},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_1", "content": "ok"}]},
    ]
    await llm.complete(model="m", system="s", tools=[], messages=turns, max_tokens=10)

    assistant = bodies[1]["messages"][1]["content"]
    assert assistant[1] == {"type": "tool_use", "id": "toolu_1", "name": "query_logs", "input": {"query": "error"}}
    assert assistant[0]["type"] == "text"
    assert bodies[1]["cache_control"] == {"type": "ephemeral"} and bodies[1]["system"] == "s"


def test_the_factory_sets_one_retry():
    assert AnthropicLlm.from_api_key("sk-test")._client.max_retries == 1  # type: ignore[attr-defined]
