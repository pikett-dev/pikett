-- The health check after an action: the ops service checks the server's health URLs after every finished job
-- and opens a P1 when they stay red. `verify_status`: pending, ok, red (P1 open), recovered, skipped (no URLs).
ALTER TABLE action_job
    ADD COLUMN IF NOT EXISTS verify_status TEXT CHECK (verify_status IN ('pending', 'ok', 'red', 'recovered', 'skipped')),
    ADD COLUMN IF NOT EXISTS verify_detail TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS verify_until TIMESTAMPTZ; -- while pending: when a red check becomes a P1

CREATE INDEX IF NOT EXISTS ix_action_job_verify ON action_job (id) WHERE verify_status IN ('pending', 'red');
