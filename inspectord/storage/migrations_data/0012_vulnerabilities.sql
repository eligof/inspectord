-- Migration 0012 — materialized vulnerability state (spec
-- docs/superpowers/specs/2026-08-26-vuln-scanner-design.md §5).
-- Additive; never destructive.
--
-- One row per (avg_id, cve_id, package) — the granularity the worker emits.
-- `first_seen_at` is deliberately NOT `first_seen`: the event-level
-- `first_seen` flag is the rule engine's baseline suppression and must not be
-- confused with this column, which the upsert never touches after insert.
-- `acked_at`/`acked_note` are written only by the ack IPC (PR2) and likewise
-- survive every upsert. Rows are never deleted: the sweep sets `resolved_at`,
-- and a reappearing match clears it.
CREATE TABLE IF NOT EXISTS vulnerabilities (
    avg_id            VARCHAR NOT NULL,
    cve_id            VARCHAR NOT NULL,
    package           VARCHAR NOT NULL,
    installed_version VARCHAR,
    fixed_version     VARCHAR,
    severity          VARCHAR,
    status            VARCHAR,
    fix_in_testing    BOOLEAN,
    first_seen_at     TIMESTAMP NOT NULL,
    last_seen         TIMESTAMP NOT NULL,
    last_event_id     VARCHAR,
    resolved_at       TIMESTAMP,
    acked_at          TIMESTAMP,
    acked_note        VARCHAR,
    PRIMARY KEY (avg_id, cve_id, package)
);

CREATE INDEX IF NOT EXISTS vulnerabilities_first_seen_idx
    ON vulnerabilities (first_seen_at);
