-- Fix pull requests proposed by an analysis and approved in Slack. One proposal per analysis; the audit
-- log (action_audit) records their steps, next to the steps of the runbook jobs.
CREATE TABLE IF NOT EXISTS fix_pr (
    id BIGSERIAL PRIMARY KEY,
    token TEXT NOT NULL UNIQUE, -- the value of the approval button
    analysis_id BIGINT NOT NULL UNIQUE REFERENCES incident_analysis (id),
    incident_id BIGINT REFERENCES incident (id) ON DELETE SET NULL,
    repo TEXT NOT NULL, -- workspace/slug
    title TEXT NOT NULL,
    diff TEXT NOT NULL,
    branch TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('proposed', 'approved', 'created', 'failed', 'expired')),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    approved_by TEXT,
    approved_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    pr_url TEXT,
    error TEXT NOT NULL DEFAULT '',
    slack_channel TEXT,
    slack_ts TEXT,
    slack_state TEXT
);

-- The audit log serves jobs and fix pull requests: a row belongs to exactly one of them.
ALTER TABLE action_audit ALTER COLUMN job_id DROP NOT NULL;
ALTER TABLE action_audit ADD COLUMN IF NOT EXISTS fix_pr_id BIGINT REFERENCES fix_pr (id);
ALTER TABLE action_audit ADD CONSTRAINT action_audit_subject CHECK ((job_id IS NULL) <> (fix_pr_id IS NULL));
CREATE INDEX IF NOT EXISTS ix_action_audit_fix_pr ON action_audit (fix_pr_id, id) WHERE fix_pr_id IS NOT NULL;
