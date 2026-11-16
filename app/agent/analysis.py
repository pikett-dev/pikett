"""The result an analysis must produce, and the check that a claim is backed by what the tools returned."""

import json
from collections.abc import Iterator, Sequence
from typing import Any, Literal

from pydantic import BaseModel, Field

SUBMIT_TOOL_NAME = "submit_analysis"


class Evidence(BaseModel):
    quote: str = Field(min_length=12, max_length=400)  # copied verbatim from a tool result
    source: str = Field(min_length=1, max_length=100)  # the tool that returned it


class Analysis(BaseModel):
    summary: str = Field(min_length=1, max_length=300)
    cause: str = Field(min_length=1, max_length=1500)
    evidence: list[Evidence] = Field(max_length=6)
    confidence: Literal["low", "medium", "high"]
    affected: str = Field(max_length=600)
    immediate_action: str = Field(max_length=600)  # in words
    # A runbook that would fix it now, or empty. Only a proposal: a person has to approve it in Slack, and the service
    # checks it against the catalog before it offers a button.
    runbook: str = Field(default="", max_length=40)
    runbook_host: str = Field(default="", max_length=63)
    runbook_application: str = Field(
        default="", max_length=40
    )  # the Coolify application UUID, where a runbook takes one
    # A lasting fix as a diff for one repository, or empty. A person approves a pull request for it in Slack.
    fix_repo: str = Field(default="", max_length=100)
    fix_title: str = Field(default="", max_length=90)
    fix_diff: str = Field(default="", max_length=2000)
    fix_suggestion: str = Field(max_length=1500)
    risk: str = Field(max_length=600)


def _text(description: str, limit: int, minimum: int = 0) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "string", "maxLength": limit, "description": description}
    if minimum:
        schema["minLength"] = minimum
    return schema


# Written by hand instead of `Analysis.model_json_schema()`: that one uses $defs and $ref, which a tool input schema
# should avoid. A test keeps the two in sync.
SUBMIT_TOOL: dict[str, Any] = {
    "name": SUBMIT_TOOL_NAME,
    "description": (
        "Submit the final analysis. Call it exactly once, when you are done. Every claim in `cause` must be backed "
        "by an evidence item whose `quote` is copied verbatim from a tool result."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "summary": _text("One or two sentences: what happened.", 300, 1),
            "cause": _text(
                "The root cause, or what is known and what is not. Only claims you can back with evidence.", 1500, 1
            ),
            "evidence": {
                "type": "array",
                "maxItems": 6,
                "description": "Quotes from tool results that support the cause. Verbatim, not paraphrased.",
                "items": {
                    "type": "object",
                    "properties": {
                        "quote": _text(
                            "Verbatim text from a tool result (a log line, a metric value, a span).", 400, 12
                        ),
                        "source": _text("The tool the quote came from.", 100, 1),
                    },
                    "required": ["quote", "source"],
                },
            },
            "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
            "affected": _text("Who or what is affected: services, endpoints, how many users if known.", 600),
            "immediate_action": _text("What the person on call should do first, in words.", 600),
            "runbook": _text(
                "The id of one runbook that would fix the problem now, or an empty string. Only when the evidence "
                "supports it; a person approves it in Slack before it runs.",
                40,
            ),
            "runbook_host": _text("The server the runbook is for (as listed under the runbooks), or empty.", 63),
            "runbook_application": _text(
                "The Coolify application UUID for runbooks that take an application, or empty.", 40
            ),
            "fix_repo": _text(
                "workspace/slug of the repository the fix is for (as listed in the prompt), or empty.", 100
            ),
            "fix_title": _text("A short title for the fix pull request, or empty.", 90),
            "fix_diff": _text(
                "The fix as a unified diff (--- a/path, +++ b/path, @@ hunks) that changes existing files only, with "
                "enough context lines, or empty. It is applied to the main branch with exact line numbers, so only "
                "when you know the code there. At most 2000 characters; no CI, build, test or shell files.",
                2000,
            ),
            "fix_suggestion": _text("The lasting fix, if the cause is known. Otherwise what to check next.", 1500),
            "risk": _text("What could go wrong with the immediate action or the fix.", 600),
        },
        "required": [
            "summary",
            "cause",
            "evidence",
            "confidence",
            "affected",
            "immediate_action",
            "runbook",
            "runbook_host",
            "runbook_application",
            "fix_repo",
            "fix_title",
            "fix_diff",
            "fix_suggestion",
            "risk",
        ],
    },
}


def _normalise(text: str) -> str:
    return " ".join(text.split())


def _strings(node: Any) -> Iterator[str]:
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield str(key)
            yield from _strings(value)
    elif isinstance(node, list):
        for item in node:
            yield from _strings(item)


def _searchable(result: str) -> list[str]:
    """What a quote may match: the text as returned and, for JSON, the decoded strings (no escapes like \\u00e4)."""
    texts = [_normalise(result)]
    try:
        texts += [_normalise(s) for s in _strings(json.loads(result))]
    except ValueError:
        pass
    return texts


def verify_evidence(analysis: Analysis, tool_results: Sequence[tuple[str, str]]) -> tuple[Analysis, int]:
    """Keeps only evidence whose quote appears in a result of the tool named as its source.

    `tool_results` are (tool name, masked text) pairs of successful calls. Returns the analysis and the dropped count.
    With nothing left the cause is unsupported, so the confidence is forced to low. This covers the quotes only: the
    prose around them is not tied to a quote, which is why the UI must show the evidence next to the cause.
    """
    pool: dict[str, list[str]] = {}
    for tool, text in tool_results:
        pool.setdefault(tool, []).extend(_searchable(text))
    kept = [e for e in analysis.evidence if any(_normalise(e.quote) in text for text in pool.get(e.source, []))]
    dropped = len(analysis.evidence) - len(kept)
    update: dict[str, Any] = {"evidence": kept}
    if not kept:
        update["confidence"] = "low"
    return analysis.model_copy(update=update), dropped
