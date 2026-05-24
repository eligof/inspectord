-- Migration 0003 — alerts, rule_stats, rule_dryrun_log (spec §10.1).
-- Additive; never destructive.

CREATE TABLE IF NOT EXISTS alerts (
    alert_id          VARCHAR PRIMARY KEY,
    rule_id           VARCHAR NOT NULL,
    ts                TIMESTAMP NOT NULL,
    severity          VARCHAR NOT NULL,
    status            VARCHAR NOT NULL DEFAULT 'new',
    category          VARCHAR NOT NULL,
    dedup_key         VARCHAR NOT NULL,
    dedup_count       INTEGER NOT NULL DEFAULT 1,
    first_seen_at     TIMESTAMP NOT NULL,
    last_seen_at      TIMESTAMP NOT NULL,
    rendered_short    VARCHAR NOT NULL,
    rendered_detail   VARCHAR NOT NULL,
    payload_json      VARCHAR NOT NULL
);

CREATE INDEX IF NOT EXISTS alerts_status_idx       ON alerts (status, ts);
CREATE INDEX IF NOT EXISTS alerts_rule_idx         ON alerts (rule_id, ts);
CREATE INDEX IF NOT EXISTS alerts_dedup_idx        ON alerts (dedup_key, last_seen_at);
CREATE INDEX IF NOT EXISTS alerts_severity_idx     ON alerts (severity, ts);

CREATE TABLE IF NOT EXISTS rule_stats (
    rule_id           VARCHAR PRIMARY KEY,
    fire_count        BIGINT NOT NULL DEFAULT 0,
    last_fired_at     TIMESTAMP,
    dryrun_count      BIGINT NOT NULL DEFAULT 0,
    suppressed_count  BIGINT NOT NULL DEFAULT 0,
    updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS rule_dryrun_log (
    ts                TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    rule_id           VARCHAR NOT NULL,
    event_id          VARCHAR NOT NULL,
    detail            VARCHAR
);

CREATE INDEX IF NOT EXISTS rule_dryrun_log_rule_idx ON rule_dryrun_log (rule_id, ts);
