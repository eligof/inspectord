-- Migration 0010 — anomaly detector: first_seen + metric_baseline
-- (spec 2026-08-20-anomaly-detector-design.md §7). Additive; never destructive.

CREATE TABLE IF NOT EXISTS first_seen (
    category      VARCHAR NOT NULL,
    entity_kind   VARCHAR NOT NULL,
    entity_key    VARCHAR NOT NULL,
    first_seen_at TIMESTAMP NOT NULL,
    event_id      VARCHAR NOT NULL,
    PRIMARY KEY (category, entity_kind, entity_key)
);

-- Checkpoint of in-memory rolling state; never the source of truth at runtime.
CREATE TABLE IF NOT EXISTS metric_baseline (
    metric_kind  VARCHAR NOT NULL,
    entity_key   VARCHAR NOT NULL,
    window_name  VARCHAR NOT NULL,
    state_json   VARCHAR NOT NULL,
    updated_at   TIMESTAMP NOT NULL,
    PRIMARY KEY (metric_kind, entity_key, window_name)
);
