import re
from functools import cached_property, lru_cache
from typing import Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.agent.pricing import PRICED_MODELS
from app.i18n import Locale

MIN_TOKEN_LENGTH = 32  # openssl rand -hex 32 gives 64


class Person(BaseModel):
    name: str
    slack_user_id: str
    ntfy_topic: str


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Shown in the web UI and in the analyst prompt, e.g. "Acme". Empty: just "Pikett".
    project_name: str = ""
    # Language of the web UI, Slack messages, ntfy pushes, reports and the analysis.
    language: Literal["en", "de"] = "en"
    # IANA time zone name. Times are shown in it, and it also sets the day boundary of the schedule (digest time),
    # the agent budget day, the on-call week, SSH quiet hours and the reboot window.
    timezone: str = "UTC"
    # A few sentences about your stack for the analyst: services, frameworks, how you deploy. Plain text.
    agent_stack_description: str = ""

    environment: str = "local"
    log_level: str = "INFO"
    # Commit SHA of the running image, injected at build time.
    service_version: str = "dev"

    database_url: str = "postgresql+asyncpg://ops:ops@localhost:5436/ops"
    # Public base URL of this service as seen by the team (Tailscale name); used for links in messages.
    base_url: str = "http://localhost:8030"

    # Slack runs in Socket Mode (outbound only). Without both tokens, messages are only logged.
    slack_bot_token: SecretStr | None = None
    slack_app_token: SecretStr | None = None
    slack_alerts_channel: str = ""
    slack_ops_channel: str = ""
    # Only these Slack user ids may press buttons.
    slack_allowed_users: list[str] = []

    ntfy_url: str = "https://ntfy.sh"
    ntfy_token: SecretStr | None = None

    # JSON list of {name, slack_user_id, ntfy_topic}. The first entry is on call in the week of oncall_anchor.
    oncall_people: list[Person] = []
    # Monday that starts rotation week 0 (ISO date).
    oncall_anchor: str = "2026-10-19"

    # Shared secret of the alert webhook (POST /api/v2/alerts): vmalert sends it as `Authorization: Bearer <token>`
    # (deploy/ops-server/alert-token). Unset: the webhook accepts every caller in the tailnet and the service warns.
    alert_token: SecretStr | None = None

    # Telemetry backends the agent tools read from. On the ops server these are the compose service names.
    victoria_logs_url: str = "http://localhost:9428"
    victoria_metrics_url: str = "http://localhost:8428"
    victoria_traces_url: str = "http://localhost:10428"

    # The analysis agent. Without a key the agent is off and incidents work as before.
    anthropic_api_key: SecretStr | None = None
    # Three stages: the automatic run uses the fallback model (Haiku), the button "Analyze deeper" uses
    # `agent_model` (Sonnet), the button "Analyze with Opus" uses `agent_deep_model`.
    agent_model: str = "claude-sonnet-5-5"
    agent_deep_model: str = "claude-opus-5-5"
    agent_max_iterations: int = Field(default=12, gt=0)
    agent_max_tokens: int = Field(default=8000, gt=0)
    agent_timeout_seconds: int = Field(default=300, gt=0)  # one whole analysis: all model and tool calls together
    # Daily limit in USD (a day in `timezone`). Over it only the fallback model runs, up to twice the budget.
    agent_daily_budget_usd: float = Field(default=5.0, gt=0)
    agent_fallback_model: str = "claude-haiku-5-5"
    agent_auto_analyze: bool = True  # analyse P1 and P2 incidents when they open; off: only the button
    agent_max_parallel: int = Field(default=2, gt=0)  # analyses running at the same time, which bounds the overshoot

    # Security checks (app/security). One token per server (HOST_NAME there -> token); a report is accepted only with
    # the token of the server it names, so one server cannot report for the other. Empty: reports are refused.
    host_report_tokens: dict[str, SecretStr] = {}
    # Servers that run the collector (HOST_NAME there). An expected report that stops arriving opens a P2.
    security_hosts: list[str] = []
    # Servers that reboot themselves after updates (the ops server, Sunday 05:00); the others get a question in Slack.
    self_rebooting_hosts: list[str] = []
    # SSH login review: users that are expected at all, and those that may log in at night (the pipeline).
    ssh_known_users: list[str] = ["root", "deploy"]
    ssh_any_time_users: list[str] = ["deploy"]
    # Coolify database UUIDs whose backups are checked through the Coolify API (COOLIFY_URL, COOLIFY_TOKEN).
    # Empty: the backup check is off and the digest says so.
    backup_databases: list[str] = []

    # OSV scan of the dependencies and the agent's change tools (commits and diffs between deploys): repository
    # (workspace/slug) -> its Bitbucket repository access token with the `repository` (read) scope only; workspace
    # tokens need Bitbucket Premium. Empty: the scan is off and the digest says so.
    bitbucket_read_tokens: dict[str, SecretStr] = {}
    # Fix pull requests: repository -> a Bitbucket repository access token with the scopes repository:write
    # and pullrequest:write. The ops service only ever writes branches named ops-fix/... and opens pull requests; it
    # never merges. Empty: no fix pull requests are offered.
    bitbucket_write_tokens: dict[str, SecretStr] = {}

    # Coolify version check and the agent's change tools (deploys): base URL of the Coolify instance and an API token
    # with read rights only. Without both the agent has no `recent_changes`.
    coolify_url: str | None = None
    coolify_token: SecretStr | None = None

    # The ops-runner (runner/). One token per server (RUNNER_TOKENS: HOST_NAME there -> token); the runner
    # of a server can fetch and report only jobs of that server. The signing key is the 32 byte seed of the Ed25519
    # key in base64; its public half is on the app servers. Without the key no job is ever delivered.
    runner_tokens: dict[str, SecretStr] = {}
    runner_signing_key: SecretStr | None = None
    # Health URLs per server (HOST_NAME -> URLs): after every action the ops service checks that they answer 2xx.
    # A server without URLs gets no health check after an action (and says so in the history).
    runner_health_urls: dict[str, list[str]] = {}
    # The Coolify applications an action may touch, per server: UUID -> name. A runbook that takes an application is
    # created only for a UUID listed here, and the approval message shows the name. Empty: those runbooks are off.
    runner_applications: dict[str, dict[str, str]] = {}

    # healthchecks.io ping URL; unset disables the heartbeat.
    healthchecks_ping_url: str | None = None

    @field_validator("language", mode="before")
    @classmethod
    def _language_from_a_locale_name(cls, value: object) -> object:
        """Many systems set LANGUAGE to a locale list such as `de_AT:de`: the first entry's language part counts."""
        if isinstance(value, str):
            return re.split(r"[:_.@-]", value.strip().lower(), maxsplit=1)[0]
        return value

    @field_validator("alert_token", mode="before")
    @classmethod
    def _empty_alert_token_is_unset(cls, value: object) -> object:
        """Compose passes `ALERT_TOKEN=` as an empty string when .env leaves it blank."""
        return None if isinstance(value, str) and not value.strip() else value

    @field_validator("timezone")
    @classmethod
    def _timezone_exists(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError, OSError) as error:
            raise ValueError(f"unknown time zone {value!r}, use an IANA name like Europe/Vienna") from error
        return value

    @model_validator(mode="after")
    def _agent_models_are_priced_and_different(self) -> "Settings":
        for name in ("agent_model", "agent_deep_model", "agent_fallback_model"):
            if getattr(self, name) not in PRICED_MODELS:
                raise ValueError(
                    f"{name} must be one of {sorted(PRICED_MODELS)}: add a price in app/agent/pricing.py first"
                )
        tokens = [t.get_secret_value() for t in self.runner_tokens.values()]
        if len(set(tokens)) != len(tokens):
            raise ValueError("runner_tokens: every server needs its own token")
        if any(len(token) < MIN_TOKEN_LENGTH for token in tokens):
            raise ValueError(f"runner_tokens: a token needs at least {MIN_TOKEN_LENGTH} characters")
        if set(tokens) & {t.get_secret_value() for t in self.host_report_tokens.values()}:
            raise ValueError(
                "runner_tokens must differ from host_report_tokens: the collector token is not a runner token"
            )
        if self.alert_token is not None:
            alert_token = self.alert_token.get_secret_value()
            if len(alert_token) < MIN_TOKEN_LENGTH:
                raise ValueError(f"alert_token needs at least {MIN_TOKEN_LENGTH} characters")
            if alert_token in set(tokens) | {t.get_secret_value() for t in self.host_report_tokens.values()}:
                raise ValueError("alert_token must differ from runner_tokens and host_report_tokens")
        if len({self.agent_model, self.agent_deep_model, self.agent_fallback_model}) != 3:
            raise ValueError("agent_model, agent_deep_model and agent_fallback_model must differ: they are three tiers")
        return self

    @property
    def brand(self) -> str:
        return f"Pikett · {self.project_name}" if self.project_name else "Pikett"

    @cached_property
    def locale(self) -> Locale:
        return Locale(self.language, ZoneInfo(self.timezone))


@lru_cache
def get_settings() -> Settings:
    return Settings()
