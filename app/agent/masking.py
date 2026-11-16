"""Masks PII and secrets before any text reaches an LLM.

Placeholders are keyed on the value, so the same secret gets the same placeholder whichever rule found it, and the
agent can still see that two lines mention the same user (`<EMAIL_1>`) without seeing the value. Use one `Masker` per
analysis. The read tools (Phase 4, step 2) must route every result through `mask` or `mask_obj` in one shared place,
so no single tool can forget it.

Known limit: base64 secrets that contain `+` or `/` are not recognised as one token; use key context
(`token=...`) for those.
"""

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

_PLACEHOLDER = re.compile(r"<[A-Z]+_\d+>")
_HEX = r"[0-9a-fA-F]"
# Shapes that stay readable because the agent needs them to follow a request: trace ids, commit SHAs, UUIDs,
# container names.
_ID_SHAPE = re.compile(
    rf"{_HEX}{{32}}|{_HEX}{{40}}|{_HEX}{{8}}-{_HEX}{{4}}-{_HEX}{{4}}-{_HEX}{{4}}-{_HEX}{{12}}"
    r"|[a-z0-9]{24}-\d{8}T\d{6}"  # a Coolify container name: resource id and deploy time
)
_ANY_HEX = re.compile(r"[0-9a-fA-F]+")
_SENSITIVE_NAMES = r"(?:password|passwd|secret|token|api[_-]?key|authorization)"
_SECRET_KEY = re.compile(_SENSITIVE_NAMES, re.IGNORECASE)
# Keyword, optional suffix (`_token`, `access_token`, `keys`) and a closing quote of a JSON key, then `:` or `=`.
_SECRET_PREFIX = rf'(?i){_SENSITIVE_NAMES}[\w-]*"?\s*[:=]\s*'

Select = Callable[[str], str | None]  # returns the part of the match to mask (a prefix), or None to leave it


def _when(predicate: Callable[[str], bool]) -> Select:
    return lambda value: value if predicate(value) else None


def _iban_checksum_ok(candidate: str) -> bool:
    """ISO 13616 mod-97 check; it keeps ordinary identifiers that look like an IBAN from being masked."""
    compact = candidate.replace(" ", "")
    if not 15 <= len(compact) <= 34:
        return False
    rearranged = compact[4:] + compact[:4]
    return int("".join(str(int(ch, 36)) for ch in rearranged)) % 97 == 1


def _iban_prefix(candidate: str) -> str | None:
    """The pattern may swallow trailing words (`... 3201 EUR`); drop them until the checksum holds."""
    while not _iban_checksum_ok(candidate):
        if " " not in candidate:
            return None
        candidate = candidate.rsplit(" ", 1)[0]
    return candidate


def _looks_like_secret(candidate: str) -> bool:
    """Long hex (other than the id shapes) or mixed upper/lower/digit strings are tokens.

    Lower-case names such as metric names, container names and image tags stay readable.
    """
    if _ID_SHAPE.fullmatch(candidate):
        return False
    if _ANY_HEX.fullmatch(candidate):
        return True
    return (
        any(c.isdigit() for c in candidate)
        and any(c.isupper() for c in candidate)
        and any(c.islower() for c in candidate)
    )


@dataclass(frozen=True)
class Rule:
    kind: str
    pattern: re.Pattern[str]
    group: int = 0  # the part of the match that is replaced; the rest (for example the key) stays readable
    select: Select | None = None


# Order matters: a JWT is replaced before the assignment rule sees `token=<JWT>`, an e-mail before the token rule.
_RULES = (
    Rule("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")),
    # Real tokens contain a digit; this keeps prose such as "basic validation failed" readable.
    Rule(
        "TOKEN",
        re.compile(r"(?i)\b(?:Bearer|Basic)\s+([A-Za-z0-9._~+/=-]{8,})"),
        group=1,
        select=_when(lambda v: any(c.isdigit() for c in v)),
    ),
    Rule("SECRET", re.compile(_SECRET_PREFIX + r'"([^"\n]*)"'), group=1),
    # `Authorization: Bearer x` is the TOKEN rule's job, so the scheme word is not taken as the value.
    Rule("SECRET", re.compile(_SECRET_PREFIX + r"(?!(?:Bearer|Basic)\s)([^\s\"',;&\[\]{}]+)"), group=1),
    Rule("IBAN", re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b"), select=_iban_prefix),
    # The lookbehinds keep long runs (base64 blobs, `-----`) linear; without them failing starts are quadratic.
    Rule(
        "EMAIL",
        re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"),
    ),
    Rule(
        "TOKEN",
        re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{32,}(?![A-Za-z0-9_-])"),
        select=_when(_looks_like_secret),
    ),
)


class Masker:
    def __init__(self) -> None:
        self._seen: dict[str, str] = {}
        self._counts: dict[str, int] = {}

    def _placeholder(self, kind: str, value: str) -> str:
        if value not in self._seen:
            self._counts[kind] = self._counts.get(kind, 0) + 1
            self._seen[value] = f"<{kind}_{self._counts[kind]}>"
        return self._seen[value]

    def _apply(self, rule: Rule, text: str) -> str:
        def replace(match: re.Match[str]) -> str:
            whole = match.group(0)
            value = match.group(rule.group)
            if _PLACEHOLDER.fullmatch(value):
                return whole
            masked = value if rule.select is None else rule.select(value)
            if masked is None:
                return whole
            start = match.start(rule.group) - match.start()
            return whole[:start] + self._placeholder(rule.kind, masked) + whole[start + len(masked) :]

        return rule.pattern.sub(replace, text)

    def mask(self, text: str) -> str:
        for rule in _RULES:
            text = self._apply(rule, text)
        return text

    def mask_obj(self, value: Any) -> Any:
        """Masks every string in nested dicts, lists and tuples (span attributes, metric labels, tool results).

        Dict keys are masked too. Everything under a secret-looking key is replaced whatever its type.
        """
        if isinstance(value, str):
            return self.mask(value)
        if isinstance(value, bytes):
            return self.mask(value.decode("utf-8", errors="replace"))
        if isinstance(value, dict):
            return {self._mask_key(k): self._mask_entry(k, v) for k, v in value.items()}
        if isinstance(value, list | tuple):
            return [self.mask_obj(v) for v in value]
        return value

    def _mask_key(self, key: Any) -> Any:
        return self.mask(key) if isinstance(key, str) else key

    def _mask_entry(self, key: Any, value: Any) -> Any:
        if isinstance(key, str) and _SECRET_KEY.search(key):
            return self._hide(value)
        return self.mask_obj(value)

    def _hide(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {self._mask_key(k): self._hide(v) for k, v in value.items()}
        if isinstance(value, list | tuple):
            return [self._hide(v) for v in value]
        return self._placeholder("SECRET", str(value))
