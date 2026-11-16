-- Threat intelligence for the findings: the CISA catalog of exploited vulnerabilities (KEV) and the EPSS score
-- (FIRST). Refreshed daily; a failed refresh keeps the rows of the last good one.
CREATE TABLE IF NOT EXISTS kev_entry (
    cve TEXT PRIMARY KEY,
    vendor TEXT NOT NULL DEFAULT '',
    product TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL DEFAULT '',
    date_added DATE,
    due_date DATE,
    ransomware TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS epss_score (
    cve TEXT PRIMARY KEY,
    epss NUMERIC(6, 5) NOT NULL, -- probability of exploitation in the next 30 days
    percentile NUMERIC(6, 5) NOT NULL,
    score_date DATE,
    fetched_at TIMESTAMPTZ NOT NULL
);
