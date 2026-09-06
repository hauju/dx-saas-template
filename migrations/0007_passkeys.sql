-- Passkey (WebAuthn) credentials for AUTH_MODE=local, where this app is its own
-- Relying Party (the RP ID is BASE_URL's host), so credentials live next to the
-- users they belong to rather than in an identity provider.
--
-- `credential_id` is the authenticator-chosen id, base64url-encoded; the spec
-- makes it globally unique, which is what lets the conditional-UI login path
-- resolve an account from an assertion alone, before any email is typed.
--
-- `public_key` is the raw COSE key captured at registration. `sign_count` is the
-- authenticator's signature counter, which must never regress for a credential;
-- 0 means the authenticator does not implement one, which is normal for synced
-- platform passkeys. `backed_up` mirrors the BS flag from the last assertion.
CREATE TABLE user_passkeys (
    id            UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id       UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    credential_id TEXT        NOT NULL UNIQUE,
    public_key    BYTEA       NOT NULL,
    sign_count    BIGINT      NOT NULL DEFAULT 0,
    transports    JSONB       NOT NULL DEFAULT '[]'::jsonb,
    name          TEXT        NOT NULL DEFAULT '',
    backed_up     BOOLEAN     NOT NULL DEFAULT false,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at  TIMESTAMPTZ
);

-- Listing a user's credentials is what the login path does to choose between
-- the passkey and OTP prompts.
CREATE INDEX user_passkeys_user_id_idx ON user_passkeys (user_id);
