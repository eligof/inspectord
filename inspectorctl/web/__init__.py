"""Local web dashboard (spec §16.4).

User-mode FastAPI app that proxies daemon IPC into a single-pane-of-glass UI.
Bound to 127.0.0.1 only; no auth and no TLS in v1 — those land with the
hardening pass once the dashboard ships externally. Two ASGI guards stand in
for them (``inspectorctl.web.csrf``): the app answers only to ``Host`` values it
was configured for (loopback by default, so a DNS-rebinding name cannot reach
it at all), and state-changing requests must additionally carry an
``Origin``/``Referer`` from the dashboard's own origin, because loopback binding
alone does not stop a form POST from a page the user is visiting.
"""
