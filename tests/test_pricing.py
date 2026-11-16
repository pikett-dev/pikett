import pytest

from app.agent.pricing import cost_usd
from app.agent.usage import LlmUsage


def test_costs_follow_the_price_table():
    usage = LlmUsage(
        input_tokens=1_000_000, output_tokens=1_000_000, cache_write_tokens=1_000_000, cache_read_tokens=1_000_000
    )
    assert cost_usd("claude-opus-5-5", usage) == pytest.approx(4 + 20 + 5 + 0.20)
    assert cost_usd("claude-sonnet-5-5", usage) == pytest.approx(2 + 10 + 2.50 + 0.10)
    assert cost_usd("claude-haiku-5-5", LlmUsage(input_tokens=1000, output_tokens=1000)) == pytest.approx(0.0006)


def test_haiku_pays_the_long_prompt_price_above_100k_tokens():
    long_prompt = LlmUsage(input_tokens=200_000, output_tokens=1_000_000)
    assert cost_usd("claude-haiku-5-5", long_prompt) == pytest.approx(0.2 * 0.5 + 2.5)


def test_an_unknown_model_is_priced_like_opus_so_a_budget_never_undercounts():
    assert cost_usd("some-new-model", LlmUsage(output_tokens=1_000_000)) == pytest.approx(20)


def test_the_opus_cache_read_is_five_percent_and_the_cache_write_is_125_percent_of_input():
    # Per the pricing page (checked 2026-11-12): Opus 5.5 reads the cache at 0.05x, Haiku 5.5 at 0.1x
    assert cost_usd("claude-opus-5-5", LlmUsage(cache_read_tokens=1_000_000)) == pytest.approx(0.05 * 4)
    assert cost_usd("claude-opus-5-5", LlmUsage(cache_write_tokens=1_000_000)) == pytest.approx(1.25 * 4)
    # 50k tokens stay under the 100k-token threshold of the long-prompt tier
    assert cost_usd("claude-haiku-5-5", LlmUsage(cache_read_tokens=50_000)) == pytest.approx(0.05 * 0.01)
