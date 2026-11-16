"""The LLM behind a port, so the agent loop runs against a scripted fake in tests (same idea as app/notify/base.py).

`AnthropicLlm` is the adapter for the Anthropic Messages API. It turns on automatic prompt caching: the cache
breakpoint moves to the last block as the conversation grows, so the tools, the system prompt and every earlier turn
(including large tool results) are read from the cache on the next call instead of being billed again.

`MaskedLlm` is the choke point for PII: it masks every string the model is sent, so a message added anywhere in the
loop (a nudge, a validation error) cannot skip the masker.
"""

from dataclasses import dataclass
from typing import Any, Protocol

import anthropic

from app.agent.masking import Masker
from app.agent.pricing import cost_usd
from app.agent.usage import LlmUsage

_REQUEST_TIMEOUT_SECONDS = 120


class LlmError(Exception):
    """The model API failed (network, rate limit, bad request). The message is safe to log."""


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    input: dict[str, Any]


@dataclass(frozen=True)
class LlmReply:
    tool_calls: list[ToolCall]
    stop_reason: str | None
    usage: LlmUsage
    raw: Any  # the assistant content exactly as received: it must be sent back unchanged in the next turn
    model: str  # the model that answered, which can differ from the one asked for (see app/agent/budget.py)
    cost_usd: float  # what this call cost: priced once, in the adapter. No default: a missing price would book 0 USD


class Llm(Protocol):
    async def complete(
        self, *, model: str, system: str, tools: list[dict[str, Any]], messages: list[dict[str, Any]], max_tokens: int
    ) -> LlmReply: ...


class AnthropicLlm:
    def __init__(self, client: anthropic.AsyncAnthropic) -> None:
        self._client = client

    @classmethod
    def from_api_key(cls, api_key: str) -> "AnthropicLlm":
        """One retry (the SDK default is two): a call can take up to two request timeouts, which has to fit well
        inside the timeout of a whole analysis (`agent_timeout_seconds`)."""
        return cls(anthropic.AsyncAnthropic(api_key=api_key, max_retries=1))

    async def complete(
        self, *, model: str, system: str, tools: list[dict[str, Any]], messages: list[dict[str, Any]], max_tokens: int
    ) -> LlmReply:
        params: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "system": system,
            "cache_control": {"type": "ephemeral"},
            "tools": tools,
            "messages": messages,
            "timeout": _REQUEST_TIMEOUT_SECONDS,
        }
        try:
            response = await self._client.messages.create(**params)
        except anthropic.AnthropicError as exc:
            # The exception text can echo request content; log the type and status only.
            raise LlmError(f"model API call failed ({type(exc).__name__}, {getattr(exc, 'status_code', '-')})") from exc
        usage = response.usage
        counted = LlmUsage(
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            cache_write_tokens=usage.cache_creation_input_tokens or 0,
            cache_read_tokens=usage.cache_read_input_tokens or 0,
        )
        return LlmReply(
            tool_calls=[
                ToolCall(block.id, block.name, dict(block.input))
                for block in response.content
                if block.type == "tool_use"
            ],
            stop_reason=response.stop_reason,
            usage=counted,
            model=model,
            cost_usd=cost_usd(model, counted),
            # Plain dicts without empty fields: the SDK objects would also send `caller: null` and the like back.
            raw=[block.model_dump(exclude_none=True) for block in response.content],
        )


class MaskedLlm:
    """Wraps an `Llm` and masks the user turns (the alert text and every tool result) before each call.

    Assistant turns are passed through untouched: they come from the model and must be sent back unchanged. The
    system prompt and tool definitions are ours and static.
    """

    def __init__(self, inner: Llm, masker: Masker) -> None:
        self._inner = inner
        self._masker = masker

    async def complete(
        self, *, model: str, system: str, tools: list[dict[str, Any]], messages: list[dict[str, Any]], max_tokens: int
    ) -> LlmReply:
        masked = [self._mask_turn(m) for m in messages]
        return await self._inner.complete(
            model=model, system=system, tools=tools, messages=masked, max_tokens=max_tokens
        )

    def _mask_turn(self, message: dict[str, Any]) -> dict[str, Any]:
        if message["role"] != "user":
            return message
        content = message["content"]
        if isinstance(content, str):
            return {**message, "content": self._masker.mask(content)}
        return {**message, "content": [self._mask_block(block) for block in content]}

    def _mask_block(self, block: dict[str, Any]) -> dict[str, Any]:
        """Masks the text of a user block. The ids that pair a result with its call are left alone."""
        kind = block.get("type")
        if kind == "text":
            return {**block, "text": self._masker.mask(block["text"])}
        if kind == "tool_result":
            content = block.get("content")
            if isinstance(content, str):
                return {**block, "content": self._masker.mask(content)}
            if isinstance(content, list):
                return {**block, "content": [self._mask_block(b) for b in content]}
            return block
        raise ValueError(f"unsupported block type in a user turn: {kind!r}")  # a new shape must be masked on purpose
