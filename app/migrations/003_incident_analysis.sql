-- Analyses of incidents by the analysis agent: who asked, what it found, what it cost.
CREATE TABLE IF NOT EXISTS incident_analysis (
    id BIGSERIAL PRIMARY KEY,
    incident_id BIGINT NOT NULL REFERENCES incident (id) ON DELETE CASCADE,
    requested_by TEXT NOT NULL, -- Slack user id, or 'auto' when the incident opened
    status TEXT NOT NULL CHECK (status IN ('running', 'done', 'failed')),
    started_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,
    model TEXT, -- the model that answered last
    analysis JSONB,
    error TEXT,
    interrupted BOOLEAN NOT NULL DEFAULT FALSE, -- a restart ended it: not a failed attempt, but capped separately
    verified BOOLEAN,
    dropped_evidence INTEGER,
    cost_usd NUMERIC(12, 6),
    iterations INTEGER,
    tool_calls INTEGER,
    posted_at TIMESTAMPTZ -- when the result was handled in the Slack thread; the tick posts rows where it is empty
);

CREATE INDEX IF NOT EXISTS ix_incident_analysis_incident ON incident_analysis (incident_id, started_at DESC);
-- One running analysis per incident, decided by the database so two requests cannot both start one.
CREATE UNIQUE INDEX IF NOT EXISTS ux_incident_analysis_running ON incident_analysis (incident_id) WHERE status = 'running';
-- The tick looks for results that were not posted yet.
CREATE INDEX IF NOT EXISTS ix_incident_analysis_unposted ON incident_analysis (finished_at) WHERE posted_at IS NULL;
