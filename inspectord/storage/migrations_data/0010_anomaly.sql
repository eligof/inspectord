-- Anomaly detector (spec 2026-08-20-anomaly-detector-design.md §7).

CREATE TABLE IF NOT EXISTS first_seen (
    category      TEXT NOT NULL,
    entity_kind   TEXT NOT NULL,
    entity_key    TEXT NOT NULL,
    first_seen_at TIMESTAMP NOT NULL,
    event_id      TEXT NOT NULL,
    PRIMARY KEY (category, entity_kind, entity_key)
);

-- Checkpoint of in-memory rolling state; never the source of truth at runtime.
CREATE TABLE IF NOT EXISTS metric_baseline (
    metric_kind  TEXT NOT NULL,
    entity_key   TEXT NOT NULL,
    window_name  TEXT NOT NULL,
    state_json   TEXT NOT NULL,
    updated_at   TIMESTAMP NOT NULL,
    PRIMARY KEY (metric_kind, entity_key, window_name)
);
