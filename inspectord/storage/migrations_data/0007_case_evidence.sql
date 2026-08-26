-- Evidence artifacts preserved by the evidence_collector (spec §3.2).
-- original_path is in the PK ('' for non-file kinds) so distinct paths with identical
-- content stay distinct rows. Content lives in the forensic store, keyed by sha256.
CREATE TABLE IF NOT EXISTS case_evidence (
    case_id       VARCHAR NOT NULL,
    kind          VARCHAR NOT NULL,   -- file | net_state | event_bundle | process_tree
    sha256        VARCHAR NOT NULL,
    original_path VARCHAR NOT NULL DEFAULT '',
    captured_at   TIMESTAMP NOT NULL,
    meta_json     VARCHAR,
    PRIMARY KEY (case_id, kind, sha256, original_path)
);
CREATE INDEX IF NOT EXISTS case_evidence_case_idx ON case_evidence (case_id);
