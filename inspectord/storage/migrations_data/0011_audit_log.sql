-- Hash-chained audit log (spec 2026-08-25-audit-log-design §3).
CREATE TABLE IF NOT EXISTS audit_log (
    seq          BIGINT PRIMARY KEY,
    ts           TIMESTAMP NOT NULL,
    actor        VARCHAR NOT NULL,
    action       VARCHAR NOT NULL,
    target       VARCHAR,
    details_json VARCHAR NOT NULL,
    prev_hash    VARCHAR NOT NULL,
    row_hash     VARCHAR NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_log_ts_idx ON audit_log (ts);
