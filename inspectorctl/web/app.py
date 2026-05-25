"""FastAPI app factory."""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator
from importlib.resources import as_file, files
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from inspectorctl.web.routes import alerts, deps, events, health


def create_app(*, socket_path: Path) -> FastAPI:
    """Create a FastAPI app that proxies the daemon's IPC at ``socket_path``."""

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

    return app
