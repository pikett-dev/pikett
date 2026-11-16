-- What the analysis agent has cost per day (Vienna time) and model, in USD. The daily budget is checked against it.
CREATE TABLE IF NOT EXISTS agent_spend (
    day DATE NOT NULL,
    model TEXT NOT NULL,
    cost_usd NUMERIC(12, 6) NOT NULL DEFAULT 0,
    requests INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, model)
);
