"""scanner_runner worker — runs the on-disk scanners on a schedule (spec §5.1).

See `docs/superpowers/specs/2026-08-19-scanner-runner-design.md`. PR1 shipped the
framework plus the AIDE adapter; PR2 added the rkhunter and YARA adapters. The
`av.*` detection rules that turn these events into alerts are PR3.
"""
