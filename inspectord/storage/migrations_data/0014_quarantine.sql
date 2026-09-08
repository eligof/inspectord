-- Migration 0014 — quarantine (quarantine design §3.1). Additive, idempotent.
--
-- `active` must earn its meaning: rows are INSERTed as `isolating` and flip
-- to `active` only after the original file's unlink succeeds. A crash between
-- INSERT and unlink leaves `isolating`, which reconciliation surfaces — the
-- panel can never show "contained" for a file still sitting on disk.
CREATE TABLE IF NOT EXISTS quarantine (
    quarantine_id  VARCHAR PRIMARY KEY,   -- uuid7
    sha256         VARCHAR NOT NULL,
    original_path  VARCHAR NOT NULL,
    file_mode      INTEGER NOT NULL,      -- st_mode & 0o7777 (setuid bits included — see §3.3)
    file_uid       INTEGER NOT NULL,
    file_gid       INTEGER NOT NULL,
    size_bytes     BIGINT  NOT NULL,      -- bytes actually stored (not fstat's answer)
    pkg_owner      VARCHAR,
    note           VARCHAR,
    alert_id       VARCHAR,
    case_id        VARCHAR,
    status         VARCHAR NOT NULL,      -- isolating | active | failed | restoring | restored | deleting | deleted
    quarantined_at TIMESTAMP NOT NULL,    -- naive UTC
    restored_at    TIMESTAMP,
    deleted_at     TIMESTAMP
);
