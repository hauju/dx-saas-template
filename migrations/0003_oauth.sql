-- Self-hosted OAuth 2.1 authorization server state (for the MCP connector).

-- Dynamically-registered clients (RFC 7591). `client_id` is public, not a
-- secret — the security boundary is the registered `redirect_uris` allowlist.
CREATE TABLE oauth_clients (
    id            UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    client_id     TEXT        NOT NULL UNIQUE,
    redirect_uris TEXT[]      NOT NULL,
    client_name   TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Short-lived, single-use authorization codes bound to a PKCE challenge.
-- Codes are deleted on consumption and rejected once `expires_at` passes;
-- abandoned ones are swept on the next `insert_code` (see oauth/store.rs).
CREATE TABLE oauth_codes (
    id             UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    code           TEXT        NOT NULL UNIQUE,
    client_id      TEXT        NOT NULL,
    redirect_uri   TEXT        NOT NULL,
    code_challenge TEXT        NOT NULL,
    user_id        UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scope          TEXT        NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL
);
