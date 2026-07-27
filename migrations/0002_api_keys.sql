-- API keys (`oat_` tokens) authenticate machine-to-machine callers (CLI,
-- integrations, MCP). The plaintext token is shown to the user exactly once at
-- creation; only the Argon2 hash and an indexed lookup prefix are stored.

CREATE TABLE api_keys (
    id           UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id      UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT        NOT NULL,
    -- Indexed, non-secret lookup prefix (`crypto::api_key_prefix`).
    prefix       TEXT        NOT NULL,
    -- Argon2 PHC hash of the full token.
    hash         TEXT        NOT NULL,
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX api_keys_user_id_idx ON api_keys (user_id);
-- Lookup by prefix during verification only considers active keys.
CREATE INDEX api_keys_prefix_active_idx ON api_keys (prefix) WHERE revoked_at IS NULL;
