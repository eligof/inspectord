"""Local web dashboard (spec §16.4).

User-mode FastAPI app that proxies daemon IPC into a single-pane-of-glass UI.
Bound to 127.0.0.1 only; no auth, no CSRF, no TLS in v1 — those land with the
hardening pass once the dashboard ships externally.
"""
