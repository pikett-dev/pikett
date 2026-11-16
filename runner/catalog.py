"""The runbook catalog: which actions exist, which parameters they take and where they may run.

The catalog is a checked-in file (`catalog.json`). The ops service and the runner load the same file. Every signed job
carries the digest of the catalog it was made against, so a runner whose catalog differs rejects it (see jobs.py).
Standard library only.
"""

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CATALOG_PATH = Path(__file__).with_name("catalog.json")
log = logging.getLogger(__name__)
SUPPORTED_VERSION = 1
RISKS = ("low", "medium", "high")
VERIFY_MODES = ("health", "reboot")
ANY_HOST = "*"
DEFAULT_MAX_LENGTH = 200
TOP_KEYS = frozenset({"version", "runbooks"})
RUNBOOK_KEYS = frozenset({"title", "description", "rollback", "proposable", "risk", "hosts", "verify", "params"})
PARAM_KEYS = {
    "string": frozenset({"type", "description", "pattern", "enum", "max_length"}),
    "integer": frozenset({"type", "description", "enum", "min", "max"}),
    "boolean": frozenset({"type", "description"}),
}
_RUNBOOK_ID = re.compile(r"[a-z][a-z0-9_]{0,39}")
PARAM_TYPES = ("string", "integer", "boolean")


class CatalogError(ValueError):
    """The catalog file is malformed, or parameters do not fit a runbook."""


@dataclass(frozen=True)
class Param:
    name: str
    type: str
    description: str = ""
    pattern: str | None = None
    enum: tuple[str | int, ...] | None = None
    min: int | None = None
    max: int | None = None
    max_length: int = DEFAULT_MAX_LENGTH

    def check(self, value: object) -> None:
        # bool is a subclass of int in Python: a JSON `true` must not pass as an integer.
        if self.type == "integer":
            if isinstance(value, bool) or not isinstance(value, int):
                raise CatalogError(f"parameter {self.name} must be an integer")
            if self.min is not None and value < self.min or self.max is not None and value > self.max:
                raise CatalogError(f"parameter {self.name} is out of range")
        elif self.type == "boolean":
            if not isinstance(value, bool):
                raise CatalogError(f"parameter {self.name} must be a boolean")
        else:
            if not isinstance(value, str):
                raise CatalogError(f"parameter {self.name} must be a string")
            if len(value) > self.max_length:
                raise CatalogError(f"parameter {self.name} is too long")
            if self.pattern is not None and not re.fullmatch(self.pattern, value, re.ASCII):
                raise CatalogError(f"parameter {self.name} has the wrong format")
        if self.enum is not None and value not in self.enum:
            raise CatalogError(f"parameter {self.name} is not an allowed value")


SOURCE_LANGUAGE = "en"


def text_in(texts: dict[str, str], language: str) -> str:
    """A display text in `language`, in the source language (English) when it has no translation."""
    return texts.get(language) or texts.get(SOURCE_LANGUAGE, "")


@dataclass(frozen=True)
class Runbook:
    id: str
    title: dict[str, str]  # display text per language, English always present
    description: dict[str, str]
    risk: str
    hosts: tuple[str, ...]
    verify: str
    params: dict[str, Param]
    proposable: bool = True  # False: the ops service creates it itself (the reboot), an analysis may not propose it
    # what to do when the health check is red afterwards (display text per language, not part of the digest)
    rollback: dict[str, str] = field(default_factory=dict)

    def text(self, name: str, language: str) -> str:
        """`title`, `description` or `rollback` in `language`."""
        return text_in(getattr(self, name), language)

    def allows_host(self, host: str) -> bool:
        return ANY_HOST in self.hosts or host in self.hosts

    def validate_params(self, params: object) -> dict[str, Any]:
        """The params when they match the schema exactly: every parameter present, none unknown. Else CatalogError."""
        if not isinstance(params, dict):
            raise CatalogError("parameters must be an object")
        unknown = sorted(set(params) - set(self.params))
        if unknown:
            raise CatalogError(f"unknown parameter {unknown[0]!r}")
        for name, spec in self.params.items():
            if name not in params:
                raise CatalogError(f"parameter {name} is missing")
            spec.check(params[name])
        return dict(params)


@dataclass(frozen=True)
class Catalog:
    runbooks: dict[str, Runbook]
    digest: str  # see _digest; signed into every job

    def get(self, runbook_id: object) -> Runbook:
        if not isinstance(runbook_id, str) or runbook_id not in self.runbooks:
            raise CatalogError("unknown runbook")
        return self.runbooks[runbook_id]


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _texts(runbook_id: str, key: str, raw: object, *, required: bool) -> dict[str, str]:
    """A display text as an object {"en": "...", "de": "..."}: English is the source language and must be there."""
    if raw is None and not required:
        return {}
    if (
        not isinstance(raw, dict)
        or not all(isinstance(lang, str) and isinstance(text, str) for lang, text in raw.items())
        or not raw.get(SOURCE_LANGUAGE)
    ):
        raise CatalogError(f'runbook {runbook_id}: {key} must be an object of texts per language with an "en" text')
    return dict(raw)


def _param(name: str, raw: object) -> Param:
    if not isinstance(raw, dict) or raw.get("type") not in PARAM_TYPES:
        raise CatalogError(f"parameter {name}: needs an object with a known type")
    # An unknown key is a typo that would silently drop a rule (`patern`), so it is an error.
    if unknown := set(raw) - PARAM_KEYS[raw["type"]]:
        raise CatalogError(f"parameter {name}: unexpected key {sorted(unknown)[0]!r} for type {raw['type']}")
    pattern, enum = raw.get("pattern"), raw.get("enum")
    if pattern is not None:
        if not isinstance(pattern, str):
            raise CatalogError(f"parameter {name}: pattern must be a string")
        re.compile(pattern, re.ASCII)
    member = str if raw["type"] == "string" else int
    if enum is not None and not (
        isinstance(enum, list) and enum and all(type(v) is member for v in enum)  # type(): a bool is no int here
    ):
        raise CatalogError(f"parameter {name}: enum must be a non-empty list matching the type")
    bounds = {key: raw.get(key) for key in ("min", "max", "max_length")}
    for key, bound in bounds.items():
        if bound is not None and (isinstance(bound, bool) or not isinstance(bound, int)):
            raise CatalogError(f"parameter {name}: {key} must be an integer")
    max_length = bounds["max_length"]
    if bounds["min"] is not None and bounds["max"] is not None and bounds["min"] > bounds["max"]:
        raise CatalogError(f"parameter {name}: min is above max")
    return Param(
        name=name,
        type=raw["type"],
        description=str(raw.get("description", "")),
        pattern=pattern,
        enum=tuple(enum) if enum is not None else None,
        min=bounds["min"],
        max=bounds["max"],
        max_length=max_length if max_length is not None else DEFAULT_MAX_LENGTH,
    )


def _digest(runbooks: dict[str, Runbook]) -> str:
    """Hash of what decides what may run (risk, hosts, verify, parameter rules), from the parsed values: a wording fix
    in a title or description must not invalidate every signed job."""
    security = {
        runbook.id: {
            "risk": runbook.risk,
            "hosts": list(runbook.hosts),
            "verify": runbook.verify,
            "params": {
                name: [p.type, p.pattern, list(p.enum) if p.enum else None, p.min, p.max, p.max_length]
                for name, p in runbook.params.items()
            },
        }
        for runbook in runbooks.values()
    }
    return hashlib.sha256(canonical_json({"version": SUPPORTED_VERSION, "runbooks": security})).hexdigest()


def parse_catalog(data: object) -> Catalog:
    if (
        not isinstance(data, dict)
        or data.get("version") != SUPPORTED_VERSION
        or not isinstance(data.get("runbooks"), dict)
        or set(data) - TOP_KEYS
    ):
        raise CatalogError("the catalog needs version 1 and a runbooks object, nothing else")
    runbooks: dict[str, Runbook] = {}
    for runbook_id, raw in data["runbooks"].items():
        if not _RUNBOOK_ID.fullmatch(runbook_id) or not isinstance(raw, dict):
            raise CatalogError(f"bad runbook {runbook_id!r}")
        if set(raw) - RUNBOOK_KEYS:
            raise CatalogError(f"runbook {runbook_id}: unexpected key {sorted(set(raw) - RUNBOOK_KEYS)[0]!r}")
        if raw.get("risk") not in RISKS or raw.get("verify") not in VERIFY_MODES:
            raise CatalogError(f"runbook {runbook_id}: bad risk or verify mode")
        hosts = raw.get("hosts")
        if not isinstance(hosts, list) or not hosts or not all(isinstance(h, str) and h for h in hosts):
            raise CatalogError(f"runbook {runbook_id}: hosts must be a non-empty list of names")
        raw_params = raw.get("params", {})
        if not isinstance(raw_params, dict):
            raise CatalogError(f"runbook {runbook_id}: params must be an object")
        runbooks[runbook_id] = Runbook(
            id=runbook_id,
            title=_texts(runbook_id, "title", raw.get("title"), required=True),
            description=_texts(runbook_id, "description", raw.get("description"), required=True),
            risk=raw["risk"],
            hosts=tuple(hosts),
            verify=raw["verify"],
            rollback=_texts(runbook_id, "rollback", raw.get("rollback"), required=False),
            proposable=raw.get("proposable", True) is True,
            params={name: _param(name, spec) for name, spec in raw_params.items()},
        )
    return Catalog(runbooks, _digest(runbooks))


def load_catalog(path: Path = CATALOG_PATH) -> Catalog:
    return parse_catalog(json.loads(path.read_text(encoding="utf-8")))


def load_installed_catalog(custom: Path, *, required: bool = False) -> Catalog:
    """The installation's own catalog (`custom`) when it is a file, otherwise the one shipped in this folder.

    The ops service (CATALOG_FILE) and the runner use this one rule. `required` is true when the path was set on
    purpose: a missing file is then an error, because the shipped catalog names example servers. A file that cannot
    be read or parsed raises CatalogError naming the path instead of falling back, because the other side would then
    work with a different catalog and reject every job.
    """
    if required or custom.is_file():
        try:
            catalog = load_catalog(custom)
        except (OSError, ValueError) as exc:  # unreadable, not UTF-8, not JSON, or CatalogError itself
            raise CatalogError(f"catalog {custom}: {exc}") from exc
        log.info("runbook catalog from %s (digest %s)", custom, catalog.digest[:12])
        return catalog
    if custom.parent.is_dir() and any(custom.parent.iterdir()):
        log.warning("%s is missing but its folder has other files: is the catalog named differently?", custom)
    catalog = load_catalog()
    log.info("runbook catalog shipped with Pikett, no file at %s (digest %s)", custom, catalog.digest[:12])
    return catalog
