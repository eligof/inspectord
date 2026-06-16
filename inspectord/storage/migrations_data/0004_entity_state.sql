-- Migration 0004 — materialized entity-state tables + baseline store (spec
-- docs/superpowers/specs/2026-06-16-entity-state-panels-design.md §3).
-- Additive; never destructive. Keys follow design-spec §14.1.

-- kind=process — pid:<pid>@boot:<boot_id>
CREATE TABLE IF NOT EXISTS process_state (
    pid           INTEGER NOT NULL,
    boot_id       VARCHAR NOT NULL,
    ppid          INTEGER,
    comm          VARCHAR,
    exe_path      VARCHAR,
    exe_sha256    VARCHAR,
    uid           INTEGER,
    cmdline       VARCHAR,
    status        VARCHAR NOT NULL,
    exit_code     INTEGER,
    first_seen    TIMESTAMP NOT NULL,
    last_seen     TIMESTAMP NOT NULL,
    last_event_id VARCHAR,
    PRIMARY KEY (pid, boot_id)
);

-- kind=connection
CREATE TABLE IF NOT EXISTS connection_state (
    conn_key      VARCHAR PRIMARY KEY,
    pid           INTEGER,
    comm          VARCHAR,
    saddr         VARCHAR,
    sport         INTEGER,
    daddr         VARCHAR,
    dport         INTEGER,
    proto         VARCHAR,
    family        VARCHAR,
    status        VARCHAR NOT NULL,
    first_seen    TIMESTAMP NOT NULL,
    last_seen     TIMESTAMP NOT NULL,
    last_event_id VARCHAR
);

-- kind=listener — port:<addr>:<port>
CREATE TABLE IF NOT EXISTS listener_state (
    addr          VARCHAR NOT NULL,
    port          INTEGER NOT NULL,
    proto         VARCHAR NOT NULL,
    family        VARCHAR,
    pid           INTEGER,
    comm          VARCHAR,
    first_seen    TIMESTAMP NOT NULL,
    last_seen     TIMESTAMP NOT NULL,
    snapshot_gen  BIGINT NOT NULL,
    PRIMARY KEY (addr, port, proto)
);

-- kind=service — svc:<unit>
CREATE TABLE IF NOT EXISTS service_state (
    unit          VARCHAR PRIMARY KEY,
    active_state  VARCHAR,
    sub_state     VARCHAR,
    load_state    VARCHAR,
    first_seen    TIMESTAMP NOT NULL,
    last_seen     TIMESTAMP NOT NULL,
    last_event_id VARCHAR
);

-- kind=device — dev:<vendor:product:serial>
CREATE TABLE IF NOT EXISTS device_state (
    dev_key       VARCHAR PRIMARY KEY,
    vendor        VARCHAR,
    product       VARCHAR,
    serial        VARCHAR,
    subsystem     VARCHAR,
    devnode       VARCHAR,
    status        VARCHAR NOT NULL,
    first_seen    TIMESTAMP NOT NULL,
    last_seen     TIMESTAMP NOT NULL,
    last_event_id VARCHAR
);

-- kind=file — file:<path>
CREATE TABLE IF NOT EXISTS file_state (
    path          VARCHAR PRIMARY KEY,
    change_type   VARCHAR,
    sha256        VARCHAR,
    size          BIGINT,
    mode          INTEGER,
    uid           INTEGER,
    gid           INTEGER,
    first_seen    TIMESTAMP NOT NULL,
    last_seen     TIMESTAMP NOT NULL,
    last_event_id VARCHAR
);

-- generic baseline store (reference data; uniform across kinds)
CREATE TABLE IF NOT EXISTS baseline_entry (
    kind          VARCHAR NOT NULL,
    key           VARCHAR NOT NULL,
    attrs_json    VARCHAR NOT NULL,
    captured_at   TIMESTAMP NOT NULL,
    PRIMARY KEY (kind, key)
);
