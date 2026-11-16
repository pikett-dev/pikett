"""What a model call costs, from the usage fields. Prices are USD per million tokens (Anthropic pricing page,
checked 2026-11-14). Update them here when the pricing changes; the daily budget counts these numbers."""

from dataclasses import dataclass
from decimal import Decimal

from app.agent.usage import LlmUsage


@dataclass(frozen=True)
class Price:
    input: float
    cache_write: float  # 5 minute cache
    cache_read: float
    output: float
    long_prompt: "tuple[int, Price] | None" = None  # above this many prompt tokens a request pays the other price


_OPUS = Price(input=4.0, cache_write=5.0, cache_read=0.20, output=20.0)  # Opus 5.5 reads the cache at 0.05x
_SONNET = Price(input=2.0, cache_write=2.50, cache_read=0.10, output=10.0)
_HAIKU_LONG = Price(input=0.50, cache_write=0.625, cache_read=0.05, output=2.50)
_HAIKU = Price(input=0.10, cache_write=0.125, cache_read=0.01, output=0.50, long_prompt=(100_000, _HAIKU_LONG))

_PRICES = {"claude-opus-5-5": _OPUS, "claude-sonnet-5-5": _SONNET, "claude-haiku-5-5": _HAIKU}
PRICED_MODELS = frozenset(_PRICES)  # a model without a price here would be billed at Opus rates: settings refuse it


def cost_usd(model: str, usage: LlmUsage) -> float:
    """An unknown model is priced like Opus, so a budget never undercounts."""
    price = _PRICES.get(model, _OPUS)
    prompt = usage.input_tokens + usage.cache_write_tokens + usage.cache_read_tokens
    if price.long_prompt is not None and prompt > price.long_prompt[0]:
        price = price.long_prompt[1]
    return (
        usage.input_tokens * price.input
        + usage.cache_write_tokens * price.cache_write
        + usage.cache_read_tokens * price.cache_read
        + usage.output_tokens * price.output
    ) / 1_000_000


def money(cost_usd: float) -> Decimal:
    """A cost as the value of a NUMERIC(12, 6) column."""
    return Decimal(str(round(cost_usd, 6)))
