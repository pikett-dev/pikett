-- An incident that matches an earlier one with a helpful analysis gets that solution instead of a new analysis
--. `known_from_incident_id` is the fact (no model call is started for this incident); `known_posted_at`
-- records that the Slack thread was told, so a failed post is retried by the tick.
ALTER TABLE incident
    ADD COLUMN IF NOT EXISTS known_from_incident_id BIGINT REFERENCES incident (id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS known_posted_at TIMESTAMPTZ;
