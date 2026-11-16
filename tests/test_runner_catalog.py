import base64
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from runner.catalog import CATALOG_PATH, Catalog, CatalogError, canonical_json, load_catalog, parse_catalog
from runner.jobs import JobRejected, format_time, public_key_from_b64, sign_job, verify_job
from runner.keys import private_key_from_b64, public_b64

NOW = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)
HOST = "app-1"
APP = "abcdefghijklmnop12345678"
T = {"en": "t"}  # a valid display text
# The digest of the checked-in catalog. Jobs that are already signed carry it, so it must not change when only
# display text changes (see test_the_checked_in_catalog_keeps_its_digest).
CATALOG_DIGEST = "76932117d77a8b15fa6ebd6c9c3c6fa1d9bd02ad2ddfbe93367e6f9480972b87"


@pytest.fixture(scope="module")
def catalog() -> Catalog:
    return load_catalog()


@pytest.fixture(scope="module")
def key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def payload(known: Catalog, **changes: Any) -> dict[str, Any]:
    base = {
        "action_id": "act-1",
        "runbook": "image_prune",
        "params": {},
        "host": HOST,
        "issued_at": format_time(NOW),
        "expires_at": format_time(NOW + timedelta(minutes=15)),
        "catalog": known.digest,
    }
    return {**base, **changes}


def check(catalog: Catalog, key: Ed25519PrivateKey, envelope: object, *, now: datetime = NOW, host: str = HOST):
    return verify_job(envelope, public_key=key.public_key(), catalog=catalog, host=host, now=now)


def test_the_checked_in_catalog_loads_and_covers_the_five_runbooks(catalog: Catalog) -> None:
    assert set(catalog.runbooks) == {
        "container_restart",
        "redeploy_previous",
        "image_prune",
        "apt_security",
        "reboot_scheduled",
    }
    assert len(catalog.digest) == 64


def test_the_checked_in_catalog_keeps_its_digest(catalog: Catalog) -> None:
    assert catalog.digest == CATALOG_DIGEST


def test_a_valid_job_is_accepted(catalog: Catalog, key: Ed25519PrivateKey) -> None:
    job = check(catalog, key, sign_job(key, payload(catalog)))
    assert job.runbook.id == "image_prune"
    assert job.action_id == "act-1"


def test_a_job_with_valid_params_is_accepted(catalog: Catalog, key: Ed25519PrivateKey) -> None:
    job = check(catalog, key, sign_job(key, payload(catalog, runbook="container_restart", params={"application": APP})))
    assert job.params == {"application": APP}


@pytest.mark.parametrize(
    "envelope",
    [None, "job", [], {}, {"job": {}}, {"job": {}, "signature": 1}, {"job": "x", "signature": "x"}],
)
def test_something_that_is_not_a_signed_job_is_rejected(
    catalog: Catalog, key: Ed25519PrivateKey, envelope: object
) -> None:
    with pytest.raises(JobRejected):
        check(catalog, key, envelope)


def test_an_unsigned_job_is_rejected(catalog: Catalog, key: Ed25519PrivateKey) -> None:
    with pytest.raises(JobRejected, match="not a signed job"):
        check(catalog, key, payload(catalog))
    with pytest.raises(JobRejected, match="signature"):
        check(catalog, key, {"job": payload(catalog), "signature": ""})


def test_a_job_signed_with_another_key_is_rejected(catalog: Catalog, key: Ed25519PrivateKey) -> None:
    other = Ed25519PrivateKey.generate()
    with pytest.raises(JobRejected, match="signature"):
        check(catalog, key, sign_job(other, payload(catalog)))


def test_a_changed_job_is_rejected(catalog: Catalog, key: Ed25519PrivateKey) -> None:
    envelope = sign_job(key, payload(catalog, runbook="container_restart", params={"application": APP}))
    envelope["job"]["params"] = {"application": "zzzzzzzzzzzzzzzzzzzzzzzz"}
    with pytest.raises(JobRejected, match="signature"):
        check(catalog, key, envelope)


def test_a_signature_over_something_else_is_rejected(catalog: Catalog, key: Ed25519PrivateKey) -> None:
    # Signed without the domain prefix, as another protocol with the same key would do.
    data = payload(catalog)
    envelope = {"job": data, "signature": base64.b64encode(key.sign(canonical_json(data))).decode()}
    with pytest.raises(JobRejected, match="signature"):
        check(catalog, key, envelope)


def test_an_unknown_runbook_is_rejected_even_when_signed(catalog: Catalog, key: Ed25519PrivateKey) -> None:
    with pytest.raises(JobRejected, match="unknown runbook"):
        check(catalog, key, sign_job(key, payload(catalog, runbook="shell")))
    with pytest.raises(JobRejected, match="unknown runbook"):
        check(catalog, key, sign_job(key, payload(catalog, runbook=["image_prune"])))


@pytest.mark.parametrize(
    ("runbook", "params"),
    [
        ("container_restart", {}),  # missing
        ("container_restart", {"application": APP, "cmd": "rm -rf /"}),  # unknown
        ("container_restart", {"application": "../../etc/passwd"}),  # wrong format
        ("container_restart", {"application": APP + "\n"}),  # trailing newline must not slip through fullmatch
        ("container_restart", {"application": 5}),
        ("container_restart", {"application": "a" * 300}),
        ("image_prune", {"all": True}),  # takes none
        ("reboot_scheduled", {"reboot_request": "7"}),
        ("reboot_scheduled", {"reboot_request": True}),  # a JSON true is not an integer
        ("reboot_scheduled", {"reboot_request": 0}),
        ("reboot_scheduled", {"reboot_request": 2**40}),
        ("image_prune", ["x"]),
    ],
)
def test_params_outside_the_schema_are_rejected(
    catalog: Catalog, key: Ed25519PrivateKey, runbook: str, params: object
) -> None:
    with pytest.raises(JobRejected):
        check(catalog, key, sign_job(key, payload(catalog, runbook=runbook, params=params)))


def test_a_job_for_another_server_is_rejected(catalog: Catalog, key: Ed25519PrivateKey) -> None:
    with pytest.raises(JobRejected, match="another server"):
        check(catalog, key, sign_job(key, payload(catalog, host="ops-server")))


def test_a_runbook_is_limited_to_its_servers(key: Ed25519PrivateKey) -> None:
    data = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    data["runbooks"]["container_restart"]["hosts"] = [HOST]  # the shipped catalog allows it on any server
    limited = parse_catalog(data)
    envelope = sign_job(
        key, payload(limited, runbook="container_restart", host="ops-server", params={"application": APP})
    )
    with pytest.raises(JobRejected, match="not allowed on this server"):
        check(limited, key, envelope, host="ops-server")


def test_an_expired_job_is_rejected(catalog: Catalog, key: Ed25519PrivateKey) -> None:
    envelope = sign_job(key, payload(catalog))
    with pytest.raises(JobRejected, match="expired"):
        check(catalog, key, envelope, now=NOW + timedelta(minutes=15))


def test_a_job_from_the_future_is_rejected(catalog: Catalog, key: Ed25519PrivateKey) -> None:
    envelope = sign_job(key, payload(catalog, issued_at=format_time(NOW + timedelta(minutes=5))))
    with pytest.raises(JobRejected, match="future"):
        check(catalog, key, envelope)


def test_a_job_for_another_catalog_is_rejected(catalog: Catalog, key: Ed25519PrivateKey) -> None:
    with pytest.raises(JobRejected, match="catalog"):
        check(catalog, key, sign_job(key, payload(catalog, catalog="0" * 64)))


def test_a_changed_catalog_on_the_server_rejects_every_job(catalog: Catalog, key: Ed25519PrivateKey) -> None:
    # Someone adds a runbook to the runner's catalog file: the digest differs from the one in the jobs.
    tampered = parse_catalog({"version": 1, "runbooks": {}})
    with pytest.raises(JobRejected, match="catalog"):
        check(tampered, key, sign_job(key, payload(catalog)))


def test_unexpected_fields_in_a_signed_job_are_rejected(catalog: Catalog, key: Ed25519PrivateKey) -> None:
    with pytest.raises(JobRejected, match="unexpected fields"):
        check(catalog, key, sign_job(key, {**payload(catalog), "command": "id"}))


def test_a_reason_is_bounded() -> None:
    assert len(JobRejected("x" * 5000).reason) == 200


@pytest.mark.parametrize(
    "bad",
    [
        {"version": 2, "runbooks": {}},
        {"version": 1},
        {"version": 1, "runbooks": {"Bad-Id": {}}},
        {"version": 1, "runbooks": {"x": "text"}},
        {"version": 1, "runbooks": {"x": {"risk": "low", "verify": "health", "hosts": ["*"]}}},  # no title
        {
            "version": 1,
            "runbooks": {"x": {"title": T, "description": T, "risk": "none", "verify": "health", "hosts": ["*"]}},
        },
        {
            "version": 1,
            "runbooks": {"x": {"title": T, "description": T, "risk": "low", "verify": "health", "hosts": []}},
        },
        {
            "version": 1,
            "runbooks": {
                "x": {
                    "title": T,
                    "description": T,
                    "risk": "low",
                    "verify": "health",
                    "hosts": ["*"],
                    "params": {"a": {"type": "object"}},
                }
            },
        },
    ],
)
def test_a_malformed_catalog_is_refused(bad: object) -> None:
    with pytest.raises(CatalogError):
        parse_catalog(bad)


def test_the_digest_follows_the_content(catalog: Catalog) -> None:
    assert load_catalog().digest == catalog.digest
    changed = {"version": 1, "runbooks": {}}
    assert parse_catalog(changed).digest != catalog.digest


def test_a_public_key_must_be_32_bytes_in_base64(key: Ed25519PrivateKey) -> None:
    raw = key.public_key().public_bytes_raw()
    assert public_key_from_b64(base64.b64encode(raw).decode()).public_bytes_raw() == raw
    with pytest.raises(ValueError, match="32 raw bytes"):
        public_key_from_b64("not base64!")
    with pytest.raises(ValueError, match="32 raw bytes"):
        public_key_from_b64(base64.b64encode(b"short").decode())


def test_the_public_key_can_be_derived_from_the_seed(key: Ed25519PrivateKey) -> None:
    seed = base64.b64encode(key.private_bytes_raw()).decode()
    derived = private_key_from_b64(seed)
    assert public_b64(derived) == base64.b64encode(key.public_key().public_bytes_raw()).decode()
    with pytest.raises(ValueError, match="32 byte seed"):
        private_key_from_b64("nope")


def test_display_text_does_not_change_the_digest(catalog: Catalog) -> None:
    data = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    prune = data["runbooks"]["image_prune"]
    prune["title"]["de"] = "Anderer Titel"
    assert parse_catalog(data).digest == catalog.digest
    prune["title"]["en"] = "Another title"
    prune["description"]["en"] = "Another description"
    prune["rollback"]["en"] = "Another rollback"
    assert parse_catalog(data).digest == catalog.digest
    data["runbooks"]["image_prune"]["hosts"] = ["app-1"]
    assert parse_catalog(data).digest != catalog.digest


@pytest.mark.parametrize("key", ["title", "description", "rollback"])
@pytest.mark.parametrize(
    "bad",
    ["plain string", {"de": "nur deutsch"}, {"en": ""}, {"en": 5}, {"en": "ok", "de": 5}, ["en"], 5],
)
def test_a_display_text_needs_an_english_text_per_language_object(key: str, bad: object) -> None:
    data = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    data["runbooks"]["image_prune"][key] = bad
    with pytest.raises(CatalogError, match=f"runbook image_prune: {key} must be an object of texts per language"):
        parse_catalog(data)


def test_a_missing_title_or_description_is_refused_but_the_rollback_is_optional() -> None:
    for key in ("title", "description"):
        data = book()
        del data["runbooks"]["x"][key]  # type: ignore[attr-defined]
        with pytest.raises(CatalogError, match="object of texts per language"):
            parse_catalog(data)
    assert parse_catalog(book()).get("x").rollback == {}


def test_a_text_falls_back_to_english_for_a_language_without_a_translation() -> None:
    runbook = parse_catalog(
        book(title={"en": "Prune", "de": "Aufraeumen"}, description={"en": "Only English"}, rollback={"en": "Redeploy"})
    ).get("x")
    assert runbook.text("title", "de") == "Aufraeumen"
    assert runbook.text("title", "en") == "Prune"
    assert runbook.text("title", "fr") == "Prune"
    assert runbook.text("description", "de") == "Only English"
    assert runbook.text("rollback", "de") == "Redeploy"
    assert parse_catalog(book()).get("x").text("rollback", "de") == ""


def test_a_job_with_a_long_or_inverted_lifetime_is_rejected(catalog: Catalog, key: Ed25519PrivateKey) -> None:
    for expires in (NOW + timedelta(days=365), NOW - timedelta(minutes=1)):
        with pytest.raises(JobRejected, match="lifetime"):
            check(catalog, key, sign_job(key, payload(catalog, expires_at=format_time(expires))))


@pytest.mark.parametrize("action_id", ["", "a b", "x" * 65, "a\nb", 5])
def test_a_malformed_action_id_is_rejected(catalog: Catalog, key: Ed25519PrivateKey, action_id: object) -> None:
    with pytest.raises(JobRejected, match="action id"):
        check(catalog, key, sign_job(key, payload(catalog, action_id=action_id)))


def test_the_catalog_refuses_unknown_top_level_keys() -> None:
    with pytest.raises(CatalogError):
        parse_catalog({**book(), "extra": 1})


def test_patterns_match_ascii_only() -> None:
    catalog = parse_catalog(book(params={"a": {"type": "string", "pattern": "\\d+"}}))
    runbook = catalog.get("x")
    assert runbook.validate_params({"a": "34"})
    with pytest.raises(CatalogError):
        runbook.validate_params({"a": "\u0663\u0664"})  # Arabic-Indic digits


def test_loose_time_formats_are_rejected(catalog: Catalog, key: Ed25519PrivateKey) -> None:
    for bad in ("2026-1-1T1:1:1Z", "\uff12\uff10\uff12\uff16-11-15T12:00:00Z", "2026-11-15 12:00:00"):
        with pytest.raises(JobRejected, match="time"):
            check(catalog, key, sign_job(key, payload(catalog, issued_at=bad)))


def test_a_deeply_nested_job_is_a_rejection_not_a_crash(catalog: Catalog, key: Ed25519PrivateKey) -> None:
    nested: Any = []
    for _ in range(5000):
        nested = [nested]
    with pytest.raises(JobRejected):
        check(catalog, key, {"job": {"params": nested}, "signature": "AAAA"})


def test_format_time_needs_an_aware_datetime() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        format_time(NOW.replace(tzinfo=None))


def test_a_naive_clock_is_a_programming_error(catalog: Catalog, key: Ed25519PrivateKey) -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        check(catalog, key, sign_job(key, payload(catalog)), now=NOW.replace(tzinfo=None))


def test_param_descriptions_do_not_change_the_digest(catalog: Catalog) -> None:
    data = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    data["runbooks"]["container_restart"]["params"]["application"]["description"] = "reworded"
    del data["runbooks"]["image_prune"]["params"]  # missing and empty mean the same
    assert parse_catalog(data).digest == catalog.digest


def book(**changes: object) -> dict[str, object]:
    return {
        "version": 1,
        "runbooks": {
            "x": {
                "title": {"en": "t"},
                "description": {"en": "d"},
                "risk": "low",
                "verify": "health",
                "hosts": ["*"],
                **changes,
            }
        },
    }


@pytest.mark.parametrize(
    "changes",
    [
        {"hosts": "*"},
        {"hosts": [1]},
        {"params": []},
        {"params": {"a": "string"}},
        {"params": {"a": {"type": "string", "enum": "abc"}}},
        {"params": {"a": {"type": "integer", "min": "1"}}},
        {"params": {"a": {"type": "integer", "max": True}}},
        {"params": {"a": {"type": "string", "pattern": 5}}},
        {"params": {"a": {"type": "string", "patern": "[a-z]+"}}},  # a typo must not drop the rule
        {"params": {"a": {"type": "string", "min": 1}}},
        {"params": {"a": {"type": "integer", "pattern": "x"}}},
        {"params": {"a": {"type": "integer", "min": 5, "max": 1}}},
        {"params": {"a": {"type": "string", "enum": []}}},  # empty would differ from none
        {"params": {"a": {"type": "boolean", "enum": [1]}}},
        {"params": {"a": {"type": "integer", "enum": [True]}}},
        {"command": "id"},
    ],
)
def test_catalog_values_of_the_wrong_type_are_refused_at_load(changes: dict[str, object]) -> None:
    with pytest.raises(CatalogError):
        parse_catalog(book(**changes))
