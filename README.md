# Local Inspection

Unified Linux endpoint security console. See `docs/superpowers/specs/2026-05-24-local-inspection-design.md` for the design.

## Status

Phase 0 — skeleton only. No collectors, no rules, no notifications. The daemon, supervisor, router, journal, storage, IPC, healthcheck worker, CLI, and tray scaffolding are wired end-to-end so subsequent phases can plug detectors in.

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
pytest
inspectord --dev    # run the daemon in foreground, dev paths
inspectorctl status # in another shell
```
