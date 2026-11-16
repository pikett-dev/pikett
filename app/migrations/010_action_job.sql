-- Jobs for the ops-runner and their audit log. A job is created, approved by an allowed person in Slack,
-- delivered once to the runner of its server, started and finished. Every step is a row in action_audit.
CREATE TABLE IF NOT EXISTS action_job (
    id BIGSERIAL PRIMARY KEY,
    action_id TEXT NOT NULL UNIQUE, -- the one-time id the runner sees and the Slack button carries
    runbook TEXT NOT NULL,
    params JSONB NOT NULL DEFAULT '{}',
    host TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('proposed', 'approved', 'delivered', 'running', 'succeeded', 'failed', 'rejected', 'expired')
    ),
    requested_by TEXT NOT NULL, -- Slack user id, or 'system' for the approved reboot
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL, -- created_at + 15 minutes: the job must be approved, delivered and started by then
    approved_by TEXT,
    approved_at TIMESTAMPTZ,
    delivered_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    lost_at TIMESTAMPTZ, -- set only by the sweep: a started job without a result; one late result is still accepted
    summary TEXT NOT NULL DEFAULT '', -- what the runner reported (masked, shortened)
    incident_id BIGINT REFERENCES incident (id) ON DELETE SET NULL,
    reboot_request_id BIGINT REFERENCES reboot_request (id) ON DELETE SET NULL
);

-- The runner asks for the oldest approved job of its server.
CREATE INDEX IF NOT EXISTS ix_action_job_approved ON action_job (host, id) WHERE status = 'approved';
CREATE INDEX IF NOT EXISTS ix_action_job_incident ON action_job (incident_id);

-- One approved reboot request leads to at most one job.
CREATE UNIQUE INDEX IF NOT EXISTS ux_action_job_reboot ON action_job (reboot_request_id) WHERE reboot_request_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS action_audit (
    id BIGSERIAL PRIMARY KEY,
    job_id BIGINT NOT NULL REFERENCES action_job (id), -- no cascade: the audit log outlives a careless delete
    at TIMESTAMPTZ NOT NULL,
    event TEXT NOT NULL, -- created, approved, delivered, started, succeeded, failed, rejected, expired
    actor TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ix_action_audit_job ON action_audit (job_id, id);

-- Each poll of a runner is its heartbeat.
CREATE TABLE IF NOT EXISTS runner_heartbeat (
    host TEXT PRIMARY KEY,
    last_seen_at TIMESTAMPTZ NOT NULL,
    version TEXT NOT NULL DEFAULT '',
    catalog TEXT NOT NULL DEFAULT ''
);
