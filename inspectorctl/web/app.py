"""FastAPI app factory."""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator, Iterable
from importlib.resources import as_file, files
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from inspectorctl.web.csrf import AllowedHostMiddleware, SameOriginMiddleware
from inspectorctl.web.routes import (
    alerts,
    audit,
    cases,
    deps,
    devices,
    entity,
    events,
    file_integrity,
    health,
    hunt,
    network,
    persistence,
    processes,
    scanners,
    services,
)


def create_app(*, socket_path: Path, allowed_hosts: Iterable[str] | None = None) -> FastAPI:
    """Create a FastAPI app that proxies the daemon's IPC at ``socket_path``.

    ``allowed_hosts`` names extra ``Host`` header values this app answers to, on
    top of the always-allowed loopback spellings — the bind address and any
    ``--allowed-host`` from :mod:`inspectorctl.web.__main__`. Callers that only
    ever reach the dashboard over loopback can leave it unset.
    """

    pkg_static = files("inspectorctl.web.static")
    pkg_templates = files("inspectorctl.web.templates")

    # Keep the resource contexts alive for the lifetime of the app.
    _static_ctx = contextlib.ExitStack()
    static_dir = _static_ctx.enter_context(as_file(pkg_static))
    tmpl_dir = _static_ctx.enter_context(as_file(pkg_templates))

    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            _static_ctx.close()

    app = FastAPI(title="inspectord", lifespan=lifespan)
    app.state.socket_path = Path(socket_path)

    # CSRF: loopback binding does not stop a cross-site form POST, so every
    # state-changing request must come from the dashboard's own origin. This is
    # middleware rather than a per-route dependency so routes added later are
    # guarded by default. See inspectorctl/web/csrf.py.
    app.add_middleware(SameOriginMiddleware)

    # DNS rebinding makes both sides of that origin comparison attacker-
    # controlled, so constrain Host as well — on every request, not just the
    # mutating ones, because a rebinding attacker who can only GET can still
    # read the dashboard. add_middleware() prepends, so adding this last makes
    # it the *outermost* layer: Host is validated before anything trusts it.
    app.add_middleware(AllowedHostMiddleware, allowed_hosts=allowed_hosts)

    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    templates = Jinja2Templates(directory=str(tmpl_dir))
    app.state.templates = templates

    @app.get("/")
    async def root() -> RedirectResponse:
        return RedirectResponse(url="/alerts", status_code=307)

    app.include_router(health.router)
    app.include_router(deps.router)
    app.include_router(events.router)
    app.include_router(alerts.router)
    app.include_router(processes.router)
    app.include_router(services.router)
    app.include_router(network.router)
    app.include_router(devices.router)
    app.include_router(file_integrity.router)
    app.include_router(persistence.router)
    app.include_router(scanners.router)
    app.include_router(cases.router)
    app.include_router(hunt.router)
    app.include_router(entity.router)
    app.include_router(audit.router)

    return app
