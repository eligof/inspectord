-- Migration 0002 — dependency manager tables (spec §30).
-- All changes are additive; never destructive.

CREATE TABLE IF NOT EXISTS pending_dep_plans (
    plan_id            VARCHAR PRIMARY KEY,
    created_at         TIMESTAMP NOT NULL,
    created_by         VARCHAR NOT NULL,
    distro             VARCHAR NOT NULL,
    package_manager    VARCHAR NOT NULL,
    items_json         VARCHAR NOT NULL,
    estimated_disk_mb  INTEGER NOT NULL DEFAULT 0,
    expires_at         TIMESTAMP NOT NULL,
    status             VARCHAR NOT NULL DEFAULT 'pending'
);

CREATE INDEX IF NOT EXISTS pending_dep_plans_status_idx
    ON pending_dep_plans (status, expires_at);

CREATE TABLE IF NOT EXISTS dep_state (
    name               VARCHAR PRIMARY KEY,
    installed          BOOLEAN NOT NULL DEFAULT FALSE,
    installed_version  VARCHAR,
    dropin_present     BOOLEAN NOT NULL DEFAULT FALSE,
    dropin_sha256      VARCHAR,
    last_verify_ts     TIMESTAMP,
    last_verify_pass   BOOLEAN,
    last_verify_detail VARCHAR,
    updated_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS dep_config_backups (
    backup_id          VARCHAR PRIMARY KEY,
    dep_name           VARCHAR NOT NULL,
    original_path      VARCHAR NOT NULL,
    backup_path        VARCHAR NOT NULL,
    original_sha256    VARCHAR NOT NULL,
    created_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS dep_config_backups_name_idx
    ON dep_config_backups (dep_name, created_at);

CREATE TABLE IF NOT EXISTS dep_audit (
    ts                 TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    actor              VARCHAR NOT NULL,
    action             VARCHAR NOT NULL,
    target             VARCHAR,
    plan_id            VARCHAR,
    before_sha256      VARCHAR,
    after_sha256       VARCHAR,
    command            VARCHAR,
    exit_code          INTEGER,
    stderr_tail        VARCHAR
);

CREATE INDEX IF NOT EXISTS dep_audit_ts_idx ON dep_audit (ts);
CREATE INDEX IF NOT EXISTS dep_audit_target_idx ON dep_audit (target, ts);
