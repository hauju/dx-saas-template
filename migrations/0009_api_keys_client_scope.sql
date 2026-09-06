-- Keys minted for an OAuth client (the MCP flow) rather than by the user
-- carry what they were issued for: the client, the scope it was granted, and
-- when the key stops working. User-created keys leave all three NULL: no
-- client, every scope, no expiry, revocable from Settings.
ALTER TABLE api_keys
    ADD COLUMN client_id  TEXT,
    ADD COLUMN scope      TEXT,
    ADD COLUMN expires_at TIMESTAMPTZ;
