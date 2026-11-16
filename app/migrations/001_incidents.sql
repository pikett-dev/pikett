-- Incidents opened from alerts, their timeline, and bookkeeping for scheduled jobs.
CREATE TABLE IF NOT EXISTS incident (
    id BIGSERIAL PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('P1', 'P2', 'P3')),
    status TEXT NOT NULL CHECK (status IN ('open', 'resolved')),
    labels JSONB NOT NULL,
    annotations JSONB NOT NULL,
    generator_url TEXT,
    started_at TIMESTAMPTZ NOT NULL,
    resolved_at TIMESTAMPTZ,
    last_seen_at TIMESTAMPTZ NOT NULL,
    acked_by TEXT,
    acked_at TIMESTAMPTZ,
    silenced_until TIMESTAMPTZ,
    slack_channel TEXT,
    slack_ts TEXT,
    paged_at TIMESTAMPTZ,
    escalated_at TIMESTAMPTZ,
    reminder_count INTEGER NOT NULL DEFAULT 0,
    last_notified_at TIMESTAMPTZ NOT NULL,
    resolution_posted_at TIMESTAMPTZ
);

-- One open incident per alert; a resolved one never blocks the next.
CREATE UNIQUE INDEX IF NOT EXISTS ux_incident_open_fingerprint ON incident (fingerprint) WHERE status = 'open';
CREATE INDEX IF NOT EXISTS ix_incident_started_at ON incident (started_at DESC);

CREATE TABLE IF NOT EXISTS incident_event (
    id BIGSERIAL PRIMARY KEY,
    incident_id BIGINT NOT NULL REFERENCES incident (id) ON DELETE CASCADE,
    at TIMESTAMPTZ NOT NULL,
    kind TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ix_incident_event_incident ON incident_event (incident_id, at);

CREATE TABLE IF NOT EXISTS job_run (
    name TEXT PRIMARY KEY,
    last_run_at TIMESTAMPTZ NOT NULL
);
