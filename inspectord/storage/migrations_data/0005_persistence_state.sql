-- Migration 0005 — materialized persistence-mechanism state (spec
-- docs/superpowers/specs/2026-06-19-persistence-panel-design.md §4).
-- Additive; never destructive. Key follows parent design-spec §14.1.

-- kind=persistence — persist:<kind>:<id>
CREATE TABLE IF NOT EXISTS persistence_state (
    persist_key   VARCHAR PRIMARY KEY,
    kind          VARCHAR NOT NULL,
    name          VARCHAR,
    source_path   VARCHAR,
    details       VARCHAR,
    first_seen    TIMESTAMP NOT NULL,
    last_seen     TIMESTAMP NOT NULL,
    last_event_id VARCHAR
);
