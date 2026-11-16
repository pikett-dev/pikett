"""The one place every tool result passes through before the agent sees it.

`ToolRegistry.call` masks the result (PII and secrets) first and only then clips strings and trims lists to a size
budget. Clipping after masking matters: cutting a value in half before the masker sees it can leave a fragment that
no longer matches any pattern. Tools never return text to the agent directly, so a new tool cannot skip either step.

Use one registry (and one `Masker`) per analysis: the masker remembers every value it replaced.
"""

import json
import logging
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Any

from app.agent.errors import SourceError, ToolInputError
from app.agent.masking import Masker

log = logging.getLogger(__name__)

Handler = Callable[[dict[str, Any]], Awaitable[Any]]


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Handler


@dataclass(frozen=True)
class ToolResult:
    text: str
    is_error: bool = False


def _clip(value: Any, limit: int) -> Any:
    if isinstance(value, str):
        return value if len(value) <= limit else value[:limit] + "..."
    if isinstance(value, dict):
        return {k: _clip(v, limit) for k, v in value.items()}
    if isinstance(value, list):
        return [_clip(v, limit) for v in value]
    return value


def _longest_list(node: Any) -> list[Any] | None:
    """The longest list of records (dicts), else the longest list at all.

    Trimming records (rows, series, spans) keeps every series over the same time range; cutting one series' own
    points would look like a gap in the metric.
    """
    records: list[Any] | None = None
    anything: list[Any] | None = None
    stack = [node]
    while stack:
        current = stack.pop()
        if isinstance(current, list):
            if anything is None or len(current) > len(anything):
                anything = current
            if current and isinstance(current[0], dict) and (records is None or len(current) > len(records)):
                records = current
            stack.extend(current)
        elif isinstance(current, dict):
            stack.extend(current.values())
    return records if records is not None and len(records) > 1 else anything


class ToolRegistry:
    def __init__(
        self, tools: Sequence[Tool], masker: Masker, *, max_chars: int = 20_000, max_string: int = 500
    ) -> None:
        self._tools = {tool.name: tool for tool in tools}
        self._masker = masker
        self._max_chars = max_chars
        self._max_string = max_string

    def definitions(self) -> list[dict[str, Any]]:
        return [
            {"name": t.name, "description": t.description, "input_schema": t.input_schema} for t in self._tools.values()
        ]

    async def call(self, name: str, arguments: dict[str, Any]) -> ToolResult:
        tool = self._tools.get(name)
        if tool is None:
            return self._error(f"unknown tool {name!r}")
        try:
            value = await tool.handler(arguments)
        except ToolInputError as exc:
            return self._error(f"invalid input: {exc}")
        except SourceError as exc:
            return self._error(str(exc))
        except Exception:
            # A malformed backend payload must not abort the agent loop or reach it unmasked.
            log.exception("tool %s failed unexpectedly", name)
            return self._error("the tool failed unexpectedly; try a different query")
        # Convert to JSON-native types first: anything the masker does not recognise (a set, a datetime, an object)
        # would otherwise be turned into text by json.dumps only after masking.
        native = json.loads(json.dumps(value, ensure_ascii=False, default=str))
        return ToolResult(self._fit(self._masker.mask_obj(native)))

    def _error(self, message: str) -> ToolResult:
        return ToolResult(self._hard_cut(self._masker.mask(message)), is_error=True)

    def _fit(self, payload: Any) -> str:
        """Clips long strings, then halves the longest record list until the JSON fits. Always returns valid JSON."""
        payload = _clip(payload, self._max_string)
        text = json.dumps(payload, ensure_ascii=False, default=str)
        trimmed = False
        while len(text) > self._max_chars:
            longest = _longest_list(payload)
            if longest is None or len(longest) <= 1:
                break
            del longest[len(longest) // 2 :]
            trimmed = True
            text = json.dumps(payload, ensure_ascii=False, default=str)
        if trimmed and isinstance(payload, dict):
            payload["truncated_for_size"] = True
            payload["note"] = "lists were cut to fit; counts such as returned or series_total describe the full data"
            text = json.dumps(payload, ensure_ascii=False, default=str)
        return text if len(text) <= self._max_chars else self._partial(text)

    def _partial(self, text: str) -> str:
        """Nothing left to trim: wrap the start of the text so the result is still valid JSON within the budget."""
        keep = self._max_chars - 100
        while keep > 0:
            wrapped = json.dumps({"truncated_for_size": True, "partial_json": text[:keep]}, ensure_ascii=False)
            if len(wrapped) <= self._max_chars:
                return wrapped
            keep = int(keep * self._max_chars / len(wrapped)) - 1  # escaping quotes made it longer
        return json.dumps({"truncated_for_size": True})

    def _hard_cut(self, text: str) -> str:
        if len(text) <= self._max_chars:
            return text
        return f"{text[: self._max_chars]}\n... cut off, {len(text) - self._max_chars} more characters."
