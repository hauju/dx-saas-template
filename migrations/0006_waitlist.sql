-- Pre-launch waitlist, fed by the coming-soon page (COMING_SOON=true).
--
-- One row per address, not per click: `email` is the primary key and a repeat
-- submission only bumps `updated_at`, so "how many people are waiting" is a
-- plain count rather than a DISTINCT query forever. The address is normalised
-- (trimmed, lowercased) before it gets here — see `models::waitlist`.
CREATE TABLE waitlist (
    email      TEXT        PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX waitlist_created_at_idx ON waitlist (created_at);
