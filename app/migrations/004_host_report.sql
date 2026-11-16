-- Reports that the collector on each server pushes (deploy/host-agent/ops-collect.py): raw facts, one row per run.
-- The checks in app/security read the newest row per host and kind; older rows give trends (Lynis score per week).
CREATE TABLE IF NOT EXISTS host_report (
    id BIGSERIAL PRIMARY KEY,
    host TEXT NOT NULL,
    kind TEXT NOT NULL,
    collected_at TIMESTAMPTZ NOT NULL, -- clock of the server
    received_at TIMESTAMPTZ NOT NULL, -- clock of the ops service; freshness is judged by this one
    data JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_host_report_latest ON host_report (host, kind, received_at DESC);
CREATE INDEX IF NOT EXISTS ix_host_report_received ON host_report (received_at);
