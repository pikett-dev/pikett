-- The latest result of a scheduled security check that has no table of its own (image updates, Coolify version),
-- as JSON, so the weekly report can show it after a restart.
CREATE TABLE IF NOT EXISTS check_state (
    name TEXT PRIMARY KEY,
    data JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
