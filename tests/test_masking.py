import time

import pytest

from app.agent.masking import Masker

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
IBAN = "AT611904300234573201"


def test_email_is_replaced_and_stable():
    m = Masker()
    out = m.mask("login failed for anna@example.at, retry for anna@example.at and ben@example.at")
    assert "example.at" not in out
    assert out == "login failed for <EMAIL_1>, retry for <EMAIL_1> and <EMAIL_2>"


def test_jwt_in_plain_text_gets_jwt_placeholder():
    assert Masker().mask(f"got {JWT} here") == "got <JWT_1> here"


def test_bearer_token_keeps_scheme_and_hides_value():
    out = Masker().mask("Authorization header: Bearer abcdef1234567890xyz")
    assert "abcdef1234567890xyz" not in out
    assert "Bearer" in out


def test_secret_assignments_hide_the_value_but_keep_the_key():
    out = Masker().mask('password=hunter2hunter2 api_key: "k-12345" secret=abc')
    assert "hunter2" not in out
    assert "k-12345" not in out
    assert "password=" in out
    assert "api_key" in out


def test_valid_iban_is_replaced_with_and_without_spaces():
    out = Masker().mask(f"refund to {IBAN} and AT61 1904 3002 3457 3201")
    assert "1904" not in out
    assert out == "refund to <IBAN_1> and <IBAN_2>"


def test_invalid_iban_lookalike_is_left_alone():
    assert Masker().mask("ref AT00 1904 3002 3457 3201") == "ref AT00 1904 3002 3457 3201"


def test_jwt_inside_an_assignment_keeps_its_jwt_placeholder():
    assert Masker().mask(f"token={JWT} seen") == "token=<JWT_1> seen"


def test_same_secret_gets_the_same_placeholder_whichever_rule_finds_it():
    value = "abcdef1234567890xyz"
    out = Masker().mask(f"Bearer {value} then token={value}")
    assert out == "Bearer <TOKEN_1> then token=<TOKEN_1>"


def test_uuids_stay_readable_but_long_hex_secrets_are_masked():
    uuid = "123e4567-e89b-12d3-a456-426614174000"
    sha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    assert Masker().mask(f"id {uuid}") == f"id {uuid}"
    assert Masker().mask(f"key {sha256}") == "key <TOKEN_1>"


def test_mask_obj_walks_nested_structures_and_hides_values_under_secret_keys():
    out = Masker().mask_obj({"attrs": [{"user": "anna@example.at", "api_key": "short"}], "count": 3, "note": "ok"})
    assert out == {"attrs": [{"user": "<EMAIL_1>", "api_key": "<SECRET_1>"}], "count": 3, "note": "ok"}


def test_long_mixed_token_is_replaced():
    out = Masker().mask("key AbCdEfGh1234567890AbCdEfGh1234567890 used")
    assert out == "key <TOKEN_1> used"


def test_trace_ids_span_ids_and_commit_shas_stay_readable():
    text = "trace 4bf92f3577b34da6a3ce929d0e0e4736 span 00f067aa0ba902b7 sha dd426d58f11e0a1b2c3d4e5f60718293a4b5c6d7"
    assert Masker().mask(text) == text


def test_plain_text_is_unchanged():
    text = "GET /api/v1/me 500 in 12ms, pool exhausted"
    assert Masker().mask(text) == text


def test_placeholders_do_not_leak_across_maskers():
    assert Masker().mask("a@b.at") == Masker().mask("c@d.at") == "<EMAIL_1>"


@pytest.mark.parametrize("filler", ["a", "-", "ab-", "a.", "a@", "a.a@", "AT61 ", "password=", "Bearer "])
def test_long_inputs_do_not_blow_up(filler):
    # A quadratic pattern needs about 15 s for 100k characters, so the generous limit stays reliable on slow runners.
    start = time.perf_counter()
    Masker().mask(filler * 50_000)
    assert time.perf_counter() - start < 5.0


@pytest.mark.parametrize("line", ["access_token=abc123", "refresh_token=short", "DB_PASSWORD=hunter2", "x_api_key=k1"])
def test_secret_keywords_inside_longer_names_are_masked(line):
    key = line.split("=")[0]
    assert Masker().mask(line) == f"{key}=<SECRET_1>"


def test_quoted_secret_with_spaces_is_masked_completely():
    assert Masker().mask('password: "my secret phrase" ok') == 'password: "<SECRET_1>" ok'


def test_authorization_header_masks_only_the_token():
    assert Masker().mask("Authorization: Bearer abcdef123456") == "Authorization: Bearer <TOKEN_1>"


def test_prose_after_basic_or_bearer_is_left_alone():
    text = "basic validation failed, Bearer missing"
    assert Masker().mask(text) == text


def test_iban_followed_by_a_short_word_is_still_masked():
    assert Masker().mask(f"refund {IBAN} EUR") == "refund <IBAN_1> EUR"
    assert Masker().mask("refund AT61 1904 3002 3457 3201 OK") == "refund <IBAN_1> OK"


def test_metric_and_container_names_stay_readable():
    text = "ops_core_hikaricp_connections_active_v2 http_server_request_duration_seconds_bucket_p99"
    assert Masker().mask(text) == text


def test_mask_obj_handles_non_string_secrets_keys_tuples_and_bytes():
    out = Masker().mask_obj(
        {"password": 123456, "token": {"value": "short"}, "anna@example.at": 3, "raw": b"a@b.at", "t": ("c@d.at",)}
    )
    assert out == {
        "password": "<SECRET_1>",
        "token": {"value": "<SECRET_2>"},
        "<EMAIL_1>": 3,
        "raw": "<EMAIL_2>",
        "t": ["<EMAIL_3>"],
    }


def test_a_secret_named_key_followed_by_a_json_container_is_not_mangled():
    # JSON from the tool registry is masked a second time on its way to the model: it must stay valid
    import json

    value = {"authorization": ["Bearer abc12345", "x"], "tokens": {"in": "k"}, "note": "ok"}
    once = json.dumps(Masker().mask_obj(value))
    twice = Masker().mask(once)
    assert twice == once
    assert json.loads(twice)["note"] == "ok"


def test_a_coolify_container_name_stays_readable_so_a_filter_can_use_it():
    text = "container q1w2e3r4t5y6u7i8o9p0a1s2-20261110T123039 restarted, token Abc123def456Ghi789Jkl012Mno345Pqr678"
    out = Masker().mask(text)
    assert "q1w2e3r4t5y6u7i8o9p0a1s2-20261110T123039" in out
    assert "Abc123def456" not in out  # a real token next to it is still masked
