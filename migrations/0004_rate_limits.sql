-- Cross-replica rate limiting.
--
-- Each row is one fixed time window for one key (a route-group scope plus the
-- client IP). The counter is bumped with a single atomic upsert, so every app
-- replica shares one quota instead of each enforcing its own.
--
-- Only the low-volume sensitive routes use this (auth, OAuth, MCP, webhooks).
-- The global per-request backstop deliberately stays in-process — a database
-- round-trip on every request, including static assets, would cost far more
-- than the accuracy is worth.

CREATE TABLE rate_limits (
    key          TEXT        NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    count        INTEGER     NOT NULL,
    PRIMARY KEY (key, window_start)
);

-- Supports the periodic sweep of elapsed windows.
CREATE INDEX rate_limits_window_start_idx ON rate_limits (window_start);
