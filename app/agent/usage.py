"""Token counts of a model call, as the API reports them."""

from dataclasses import dataclass


@dataclass(frozen=True)
class LlmUsage:
    input_tokens: int = 0  # tokens after the last cache breakpoint, billed at the normal input price
    output_tokens: int = 0
    cache_write_tokens: int = 0
    cache_read_tokens: int = 0

    def __add__(self, other: "LlmUsage") -> "LlmUsage":
        return LlmUsage(
            self.input_tokens + other.input_tokens,
            self.output_tokens + other.output_tokens,
            self.cache_write_tokens + other.cache_write_tokens,
            self.cache_read_tokens + other.cache_read_tokens,
        )
