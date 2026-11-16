-- What the ops service ran by itself: the scheduled security jobs and the daily and weekly reports, one row per run.
-- Analyses of the agent (incident_analysis) and incidents are read from their own tables; this is the history that was
-- missing (job_run and check_state only keep the latest run). Rows older than 90 days are deleted by the daily
-- host_report_prune job.
CREATE TABLE IF NOT EXISTS ops_run (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL, -- the job name (osv_scan, vuln_intel, digest, ...)
    kind TEXT NOT NULL CHECK (kind IN ('check', 'report')),
    started_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('ok', 'failed')),
    summary TEXT NOT NULL DEFAULT '' -- one sentence, PII masked
);

CREATE INDEX IF NOT EXISTS ix_ops_run_started ON ops_run (started_at DESC);
CREATE INDEX IF NOT EXISTS ix_ops_run_name ON ops_run (name, started_at DESC);
