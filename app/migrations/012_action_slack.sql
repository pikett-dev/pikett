-- The Slack message of a proposed action: the button, and later its state and result. One proposal per
-- analysis, so a retried post never offers the same action twice.
ALTER TABLE action_job
    ADD COLUMN IF NOT EXISTS analysis_id BIGINT REFERENCES incident_analysis (id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS slack_channel TEXT,
    ADD COLUMN IF NOT EXISTS slack_ts TEXT,
    ADD COLUMN IF NOT EXISTS slack_state TEXT; -- what the message shows now (status/verify), to update it on a change

CREATE UNIQUE INDEX IF NOT EXISTS ux_action_job_analysis ON action_job (analysis_id) WHERE analysis_id IS NOT NULL;
