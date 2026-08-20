-- Migration 0009 — saved hunt queries (hunt design §8, plan
-- docs/superpowers/plans/2026-08-20-hunt-saved-queries.md). Additive.
--
-- `name` is the key an investigator types at 2am, so it is the primary key and
-- the write path validates it against a narrow pattern before it ever gets
-- here (it is echoed into a terminal today and into HTML in PR3).
--
-- `expression` is the query in the YAML-rule grammar, stored verbatim. It is
-- COMPILED before it is stored, so a query that cannot compile never reaches
-- this table — but nothing here depends on that, because the compiler can
-- legitimately get stricter later and an old row must still round-trip.
--
-- Timestamps are UTC; `created_at` survives a replace, `updated_at` does not.
CREATE TABLE IF NOT EXISTS hunt_query (
    name        VARCHAR PRIMARY KEY,
    expression  VARCHAR NOT NULL,
    description VARCHAR,
    created_at  TIMESTAMP NOT NULL,
    updated_at  TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS hunt_query_updated_idx ON hunt_query (updated_at);
