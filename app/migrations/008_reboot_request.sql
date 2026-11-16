-- Questions in Slack whether a server may reboot ("Sonntag 04:00 neu starten?") and their approvals.
-- The reboot itself is a runbook of the ops-runner; it needs an approved row that is not done yet.
CREATE TABLE IF NOT EXISTS reboot_request (
    id BIGSERIAL PRIMARY KEY,
    host TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '', -- the packages that asked for the reboot
    requested_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('asked', 'approved', 'expired', 'obsolete', 'done')),
    token TEXT NOT NULL, -- one-time value of the approval button
    slack_channel TEXT,
    slack_ts TEXT,
    expires_at TIMESTAMPTZ, -- 15 minutes after the question was posted
    approved_by TEXT,
    approved_at TIMESTAMPTZ,
    scheduled_for TIMESTAMPTZ,
    done_at TIMESTAMPTZ
);

-- At most one open question or approval per server.
CREATE UNIQUE INDEX IF NOT EXISTS ux_reboot_request_open ON reboot_request (host) WHERE status IN ('asked', 'approved');
