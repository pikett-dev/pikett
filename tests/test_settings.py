import pytest
from pydantic import ValidationError

from app.config import Settings


@pytest.mark.parametrize("name", ["agent_max_iterations", "agent_max_tokens", "agent_timeout_seconds"])
def test_agent_limits_must_be_positive(name):
    with pytest.raises(ValidationError):
        Settings(**{name: 0})  # type: ignore[arg-type]


def test_the_agent_is_off_without_a_key():
    assert Settings().anthropic_api_key is None


def test_the_agent_models_must_be_priced_and_different():
    with pytest.raises(ValidationError, match="add a price"):
        Settings(agent_fallback_model="some-unpriced-model")
    with pytest.raises(ValidationError, match="must differ"):
        Settings(agent_model="claude-haiku-5-5", agent_fallback_model="claude-haiku-5-5")
    with pytest.raises(ValidationError, match="must differ"):
        Settings(agent_deep_model="claude-sonnet-5-5")


def test_the_analysis_runs_on_sonnet_by_default():
    # Sonnet costs half of Opus; Opus stays selectable through AGENT_MODEL
    settings = Settings()
    assert settings.agent_model == "claude-sonnet-5-5"
    assert settings.agent_fallback_model == "claude-haiku-5-5"
    assert settings.agent_deep_model == "claude-opus-5-5"  # the button "Mit Opus analysieren"
