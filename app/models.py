from datetime import date, datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import BigInteger, Boolean, Date, DateTime, ForeignKey, Integer, Numeric, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def _ts() -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True))


class Incident(Base):
    """Schema lives in app/migrations; this only maps it."""

    __tablename__ = "incident"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    fingerprint: Mapped[str] = mapped_column(Text)
    title: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text)
    labels: Mapped[dict[str, str]] = mapped_column(JSONB)
    annotations: Mapped[dict[str, str]] = mapped_column(JSONB)
    generator_url: Mapped[str | None] = mapped_column(Text)
    memory_key: Mapped[str | None] = mapped_column(Text)  # alarm|service|host, see app/incidents/memory.py
    # the earlier incident whose solution applies
    known_from_incident_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("incident.id", ondelete="SET NULL")
    )
    known_posted_at: Mapped[datetime | None] = _ts()
    started_at: Mapped[datetime] = _ts()
    resolved_at: Mapped[datetime | None] = _ts()
    last_seen_at: Mapped[datetime] = _ts()
    acked_by: Mapped[str | None] = mapped_column(Text)
    acked_at: Mapped[datetime | None] = _ts()
    silenced_until: Mapped[datetime | None] = _ts()
    slack_channel: Mapped[str | None] = mapped_column(Text)
    slack_ts: Mapped[str | None] = mapped_column(Text)
    paged_at: Mapped[datetime | None] = _ts()
    escalated_at: Mapped[datetime | None] = _ts()
    reminder_count: Mapped[int] = mapped_column(Integer, default=0)
    last_notified_at: Mapped[datetime] = _ts()
    resolution_posted_at: Mapped[datetime | None] = _ts()


class IncidentEvent(Base):
    __tablename__ = "incident_event"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    incident_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("incident.id", ondelete="CASCADE"))
    at: Mapped[datetime] = _ts()
    kind: Mapped[str] = mapped_column(Text)
    detail: Mapped[str] = mapped_column(Text, default="")


class JobRun(Base):
    __tablename__ = "job_run"

    name: Mapped[str] = mapped_column(Text, primary_key=True)
    last_run_at: Mapped[datetime] = _ts()


class OpsRun(Base):
    """One run of a scheduled job or report of the ops service itself. Schema lives in app/migrations."""

    __tablename__ = "ops_run"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    name: Mapped[str] = mapped_column(Text)
    kind: Mapped[str] = mapped_column(Text)
    started_at: Mapped[datetime] = _ts()
    finished_at: Mapped[datetime] = _ts()
    status: Mapped[str] = mapped_column(Text)
    summary: Mapped[str] = mapped_column(Text, default="")


class AgentSpend(Base):
    """What the analysis agent cost per day (in the configured time zone) and model. Schema lives in app/migrations."""

    __tablename__ = "agent_spend"

    day: Mapped[date] = mapped_column(Date, primary_key=True)
    model: Mapped[str] = mapped_column(Text, primary_key=True)
    cost_usd: Mapped[Decimal] = mapped_column(Numeric(12, 6))
    requests: Mapped[int] = mapped_column(Integer)


class IncidentAnalysis(Base):
    """Schema lives in app/migrations; this only maps it."""

    __tablename__ = "incident_analysis"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    incident_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("incident.id"))
    requested_by: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text)
    started_at: Mapped[datetime] = _ts()
    finished_at: Mapped[datetime | None] = _ts()
    model: Mapped[str | None] = mapped_column(Text)
    analysis: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    error: Mapped[str | None] = mapped_column(Text)
    interrupted: Mapped[bool] = mapped_column(Boolean, default=False)
    verified: Mapped[bool | None] = mapped_column(Boolean)
    dropped_evidence: Mapped[int | None] = mapped_column(Integer)
    cost_usd: Mapped[Decimal | None] = mapped_column(Numeric(12, 6))
    iterations: Mapped[int | None] = mapped_column(Integer)
    tool_calls: Mapped[int | None] = mapped_column(Integer)
    posted_at: Mapped[datetime | None] = _ts()
    feedback: Mapped[str | None] = mapped_column(Text)  # helpful, not_helpful: a person's verdict
    feedback_by: Mapped[str | None] = mapped_column(Text)
    feedback_at: Mapped[datetime | None] = _ts()
    feedback_asked_at: Mapped[datetime | None] = _ts()  # the question under the analysis was posted


class HostReport(Base):
    """A report pushed by the collector on a server. Schema lives in app/migrations."""

    __tablename__ = "host_report"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    host: Mapped[str] = mapped_column(Text)
    kind: Mapped[str] = mapped_column(Text)
    collected_at: Mapped[datetime] = _ts()
    received_at: Mapped[datetime] = _ts()
    data: Mapped[dict[str, Any]] = mapped_column(JSONB)


class VulnerabilityFinding(Base):
    """A known vulnerability seen by the last scan of its source and scope. Schema lives in app/migrations."""

    __tablename__ = "vulnerability_finding"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    source: Mapped[str] = mapped_column(Text)
    scope: Mapped[str] = mapped_column(Text)
    target: Mapped[str] = mapped_column(Text)
    services: Mapped[str] = mapped_column(Text, default="")
    package: Mapped[str] = mapped_column(Text)
    installed_version: Mapped[str] = mapped_column(Text)
    vuln_id: Mapped[str] = mapped_column(Text)
    cve: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(Text)
    fixed_version: Mapped[str] = mapped_column(Text, default="")
    title: Mapped[str] = mapped_column(Text, default="")
    first_seen_at: Mapped[datetime] = _ts()
    last_seen_at: Mapped[datetime] = _ts()


class KevEntry(Base):
    """A CVE in the CISA catalog of known exploited vulnerabilities. Schema lives in app/migrations."""

    __tablename__ = "kev_entry"

    cve: Mapped[str] = mapped_column(Text, primary_key=True)
    vendor: Mapped[str] = mapped_column(Text, default="")
    product: Mapped[str] = mapped_column(Text, default="")
    name: Mapped[str] = mapped_column(Text, default="")
    date_added: Mapped[date | None] = mapped_column(Date)
    due_date: Mapped[date | None] = mapped_column(Date)
    ransomware: Mapped[str] = mapped_column(Text, default="")


class EpssScore(Base):
    """The EPSS score of a CVE. Schema lives in app/migrations."""

    __tablename__ = "epss_score"

    cve: Mapped[str] = mapped_column(Text, primary_key=True)
    epss: Mapped[Decimal] = mapped_column(Numeric(6, 5))
    percentile: Mapped[Decimal] = mapped_column(Numeric(6, 5))
    score_date: Mapped[date | None] = mapped_column(Date)
    fetched_at: Mapped[datetime] = _ts()


class CheckState(Base):
    """The latest result of a scheduled security check. Schema lives in app/migrations."""

    __tablename__ = "check_state"

    name: Mapped[str] = mapped_column(Text, primary_key=True)
    data: Mapped[dict[str, Any]] = mapped_column(JSONB)
    updated_at: Mapped[datetime] = _ts()


class RebootRequest(Base):
    """A reboot question in Slack and its approval. Schema lives in app/migrations."""

    __tablename__ = "reboot_request"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    host: Mapped[str] = mapped_column(Text)
    reason: Mapped[str] = mapped_column(Text, default="")
    requested_at: Mapped[datetime] = _ts()
    status: Mapped[str] = mapped_column(Text)
    token: Mapped[str] = mapped_column(Text)
    slack_channel: Mapped[str | None] = mapped_column(Text)
    slack_ts: Mapped[str | None] = mapped_column(Text)
    expires_at: Mapped[datetime | None] = _ts()
    approved_by: Mapped[str | None] = mapped_column(Text)
    approved_at: Mapped[datetime | None] = _ts()
    scheduled_for: Mapped[datetime | None] = _ts()
    done_at: Mapped[datetime | None] = _ts()


class ActionJob(Base):
    """A job for the ops-runner. Schema lives in app/migrations."""

    __tablename__ = "action_job"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    action_id: Mapped[str] = mapped_column(Text)
    runbook: Mapped[str] = mapped_column(Text)
    params: Mapped[dict[str, Any]] = mapped_column(JSONB)
    host: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text)
    requested_by: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = _ts()
    expires_at: Mapped[datetime] = _ts()
    approved_by: Mapped[str | None] = mapped_column(Text)
    approved_at: Mapped[datetime | None] = _ts()
    delivered_at: Mapped[datetime | None] = _ts()
    started_at: Mapped[datetime | None] = _ts()
    finished_at: Mapped[datetime | None] = _ts()
    lost_at: Mapped[datetime | None] = _ts()
    summary: Mapped[str] = mapped_column(Text, default="")
    incident_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("incident.id"))
    reboot_request_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("reboot_request.id"))
    verify_status: Mapped[str | None] = mapped_column(Text)
    verify_detail: Mapped[str] = mapped_column(Text, default="")
    verify_until: Mapped[datetime | None] = _ts()
    analysis_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("incident_analysis.id"))
    slack_channel: Mapped[str | None] = mapped_column(Text)
    slack_ts: Mapped[str | None] = mapped_column(Text)
    slack_state: Mapped[str | None] = mapped_column(Text)


class ActionAudit(Base):
    """One step in the life of a job. Schema lives in app/migrations."""

    __tablename__ = "action_audit"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    job_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("action_job.id"))
    fix_pr_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("fix_pr.id"))
    at: Mapped[datetime] = _ts()
    event: Mapped[str] = mapped_column(Text)
    actor: Mapped[str] = mapped_column(Text)
    detail: Mapped[str] = mapped_column(Text, default="")


class RunnerHeartbeat(Base):
    """The last poll of the runner on a server. Schema lives in app/migrations."""

    __tablename__ = "runner_heartbeat"

    host: Mapped[str] = mapped_column(Text, primary_key=True)
    last_seen_at: Mapped[datetime] = _ts()
    version: Mapped[str] = mapped_column(Text, default="")
    catalog: Mapped[str] = mapped_column(Text, default="")


class FixPr(Base):
    """A fix pull request proposed by an analysis. Schema lives in app/migrations."""

    __tablename__ = "fix_pr"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    token: Mapped[str] = mapped_column(Text)
    analysis_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("incident_analysis.id"))
    incident_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("incident.id"))
    repo: Mapped[str] = mapped_column(Text)
    title: Mapped[str] = mapped_column(Text)
    diff: Mapped[str] = mapped_column(Text)
    branch: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = _ts()
    expires_at: Mapped[datetime] = _ts()
    approved_by: Mapped[str | None] = mapped_column(Text)
    approved_at: Mapped[datetime | None] = _ts()
    finished_at: Mapped[datetime | None] = _ts()
    pr_url: Mapped[str | None] = mapped_column(Text)
    error: Mapped[str] = mapped_column(Text, default="")
    slack_channel: Mapped[str | None] = mapped_column(Text)
    slack_ts: Mapped[str | None] = mapped_column(Text)
    slack_state: Mapped[str | None] = mapped_column(Text)
