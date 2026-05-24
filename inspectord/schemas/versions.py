"""Centralized schema-version constants.

Bump MAJOR for breaking schema changes, MINOR for additive, PATCH for clarifications.
Every persisted/serialized object carries the relevant version so migrations can run.
"""

EVENT_SCHEMA_VERSION = "1.0.0"
ALERT_SCHEMA_VERSION = "1.0.0"
INCIDENT_SCHEMA_VERSION = "1.0.0"
ALLOWLIST_SCHEMA_VERSION = "1.0.0"
CASE_SCHEMA_VERSION = "1.0.0"
DB_SCHEMA_VERSION = 1
IPC_PROTOCOL_VERSION = "1.0.0"
RULE_YAML_VERSION = "1.0.0"
JOURNAL_FORMAT_VERSION = "1.0.0"
