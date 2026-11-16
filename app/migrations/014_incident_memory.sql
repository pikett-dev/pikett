-- The incident memory: every incident of a vmalert alarm gets a key (alarm name, service, host). Incidents
-- with the same key are the same problem again; the latest backed analysis of one of them is its known solution.
-- Incidents raised by the ops service itself have no key: they are not alarms with a rule that recurs.
ALTER TABLE incident ADD COLUMN IF NOT EXISTS memory_key TEXT;

UPDATE incident
SET memory_key = coalesce(labels ->> 'alertname', title) || '|' || coalesce(labels ->> 'service', '') || '|' ||
                 coalesce(labels ->> 'host', '')
WHERE memory_key IS NULL AND NOT (labels @> '{"origin": "ops"}'::jsonb);

CREATE INDEX IF NOT EXISTS ix_incident_memory_key ON incident (memory_key) WHERE memory_key IS NOT NULL;
