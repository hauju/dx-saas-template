-- Polar delivers each webhook at least once and retries on any non-2xx, so
-- every delivery's id (the Standard Webhooks `webhook-id` header) is recorded
-- in the same transaction as the change it caused. A redelivery finds its id
-- and does nothing. Rows past Polar's retry horizon are swept on insert.
CREATE TABLE polar_webhook_events (
    id          TEXT        PRIMARY KEY,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
