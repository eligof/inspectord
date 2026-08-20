"""Local web dashboard (spec §16.4).

User-mode FastAPI app that proxies daemon IPC into a single-pane-of-glass UI.
Bound to 127.0.0.1 only; no auth and no TLS in v1 — those land with the
hardening pass once the dashboard ships externally. State-changing requests are
guarded against cross-site submission by an Origin/Referer same-origin check
(``inspectorctl.web.csrf``), because loopback binding alone does not stop a
form POST from a page the user is visiting.
"""
