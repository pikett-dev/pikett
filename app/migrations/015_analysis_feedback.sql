-- A person's verdict on an analysis. The latest click wins; only analyses marked helpful count as a
-- known solution later.
ALTER TABLE incident_analysis
    ADD COLUMN IF NOT EXISTS feedback TEXT CHECK (feedback IN ('helpful', 'not_helpful')),
    ADD COLUMN IF NOT EXISTS feedback_by TEXT,
    ADD COLUMN IF NOT EXISTS feedback_at TIMESTAMPTZ;
