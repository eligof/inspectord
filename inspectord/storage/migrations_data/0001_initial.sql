-- Migration 0001 — initial schema (Phase 0 minimum).
-- Subsequent phases extend this with table additions; never destructive.

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS events_enriched (
    event_id      VARCHAR PRIMARY KEY,
    ts            TIMESTAMP NOT NULL,
    kind          VARCHAR NOT NULL,
    module        VARCHAR NOT NULL,
    action        VARCHAR NOT NULL,
    severity      VARCHAR NOT NULL,
    payload_json  VARCHAR NOT NULL
);

CREATE INDEX IF NOT EXISTS events_enriched_ts_idx ON events_enriched (ts);
CREATE INDEX IF NOT EXISTS events_enriched_module_idx ON events_enriched (module);

CREATE TABLE IF NOT EXISTS worker_health (
    worker        VARCHAR NOT NULL,
    ts            TIMESTAMP NOT NULL,
    events_processed BIGINT NOT NULL,
    queue_depth   INTEGER NOT NULL,
    last_error    VARCHAR,
    uptime_s      DOUBLE NOT NULL
);

CREATE INDEX IF NOT EXISTS worker_health_worker_idx ON worker_health (worker, ts);
