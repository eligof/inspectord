-- Migration 0008 — materialized scanner-run state (plan
-- docs/superpowers/plans/2026-08-20-scanner-panel.md §3), the slice the
-- scanner_runner design (2026-08-19) §6 deferred. Additive; never destructive.
--
-- One row per scan run, keyed on the run_id that scan_started / scan_completed
-- already carry in raw.run_id. scan_skipped carries no run_id (nothing was
-- spawned), so a skip row is keyed skip:<event_id>.
--
-- `status` is the PROJECTED state only: running | success | failure | skipped.
-- A run that never completed stays 'running' forever here; the read path
-- derives the display-only 'interrupted' state from started_at's age, so an
-- abandoned run can never render as success nor as running-forever.
-- "clean vs findings" is derivable from finding_count, so there is no second enum.
CREATE TABLE IF NOT EXISTS scan_run (
    run_id           VARCHAR PRIMARY KEY,
    scanner          VARCHAR NOT NULL,
    status           VARCHAR NOT NULL,
    reason           VARCHAR,        -- failure reason or skip reason
    exit_code        INTEGER,
    duration_s       DOUBLE,
    finding_count    INTEGER,
    findings_dropped INTEGER,
    truncated        BOOLEAN,        -- the finding list was capped
    output_truncated BOOLEAN,        -- the scanner's output stream was clipped
    -- Failures only. Already bounded by the runner (MAX_FAILURE_OUTPUT_CHARS).
    output_excerpt   VARCHAR,
    started_at       TIMESTAMP NOT NULL,
    completed_at     TIMESTAMP,
    last_event_id    VARCHAR
);

CREATE INDEX IF NOT EXISTS scan_run_scanner_idx ON scan_run (scanner, started_at);
