-- Cases (manual v1) — user-curated bundles of alerts + notes.
-- case_event is an append-only ACTIVITY/NOTES log, NOT a tamper-evident chain-of-custody
-- (parent spec §13.5/§20.4 audit_log is deferred). No foreign keys (consistent w/ schema).
CREATE TABLE IF NOT EXISTS cases (
    case_id     VARCHAR PRIMARY KEY,
    title       VARCHAR NOT NULL,
    status      VARCHAR NOT NULL DEFAULT 'open',
    opened_at   TIMESTAMP NOT NULL,
    closed_at   TIMESTAMP
);

CREATE TABLE IF NOT EXISTS case_alert (
    case_id     VARCHAR NOT NULL,
    alert_id    VARCHAR NOT NULL,
    attached_at TIMESTAMP NOT NULL,
    PRIMARY KEY (case_id, alert_id)
);

CREATE TABLE IF NOT EXISTS case_event (
    case_id     VARCHAR NOT NULL,
    ts          TIMESTAMP NOT NULL,
    seq         INTEGER NOT NULL,
    kind        VARCHAR NOT NULL,
    text        VARCHAR
);

CREATE INDEX IF NOT EXISTS case_alert_case_idx ON case_alert (case_id);
CREATE INDEX IF NOT EXISTS case_event_case_idx ON case_event (case_id, ts, seq);
