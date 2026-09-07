-- Migration 0013 — scheduled hunts (hunt-followups design §4.2). Additive.
--
-- ingest_seq is the ground the scheduled-hunt watermark stands on: assigned at
-- INSERT (explicitly, in storage/events.py — no column DEFAULT, so behavior is
-- identical on every DuckDB version), monotonic, no clocks, not derivable from
-- event content. Pre-existing rows keep NULL: they are pre-watermark for every
-- schedule that will ever exist, and NULL never satisfies `ingest_seq > ?`.
CREATE SEQUENCE IF NOT EXISTS event_ingest_seq;
ALTER TABLE events_enriched ADD COLUMN IF NOT EXISTS ingest_seq BIGINT;

ALTER TABLE hunt_query ADD COLUMN IF NOT EXISTS schedule_interval_s INTEGER;
ALTER TABLE hunt_query ADD COLUMN IF NOT EXISTS schedule_severity VARCHAR;
ALTER TABLE hunt_query ADD COLUMN IF NOT EXISTS watermark_seq BIGINT;
ALTER TABLE hunt_query ADD COLUMN IF NOT EXISTS last_run_at TIMESTAMP;
ALTER TABLE hunt_query ADD COLUMN IF NOT EXISTS last_status VARCHAR;

CREATE INDEX IF NOT EXISTS events_ingest_seq_idx ON events_enriched (ingest_seq);
