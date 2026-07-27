CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE users (
    id           UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    sub          TEXT        NOT NULL UNIQUE,
    email        TEXT        NOT NULL UNIQUE,
    name         TEXT,
    avatar_url   TEXT,
    -- Current subscription state, synced from Polar webhooks. Mirrors the
    -- `SubscriptionInfo` struct; NULL means no subscription on file.
    subscription JSONB,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
