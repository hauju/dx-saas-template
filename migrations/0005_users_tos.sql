-- Terms-of-service acceptance, read back by dx-auth on every login: a NULL
-- version, or one older than the crate's current TOS_VERSION, sends the user
-- to the acceptance step. The timestamp is written by the database clock when
-- they accept, like every other timestamp in this schema.
ALTER TABLE users
    ADD COLUMN tos_version     TEXT,
    ADD COLUMN tos_accepted_at TIMESTAMPTZ;
