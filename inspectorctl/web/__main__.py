"""inspectorctl-web entry point — runs uvicorn on 127.0.0.1.

Usage:
  inspectorctl-web                          # dev: socket under ./var/
  inspectorctl-web --socket /run/inspectord/inspectord.sock --port 8765
  inspectorctl-web --host 0.0.0.0 --allowed-host nuc.lan   # deliberate LAN use

The app answers only to hosts it was told about: loopback always, plus the
``--host`` bind address and every ``--allowed-host``. See
:mod:`inspectorctl.web.csrf` for why (DNS rebinding).
"""

from __future__ import annotations

import argparse
from pathlib import Path

import uvicorn

from inspectorctl.web.app import create_app


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="inspectorctl-web")
    parser.add_argument(
        "--socket",
        type=Path,
        default=Path.cwd() / "var" / "inspectord.sock",
        help="Path to the inspectord IPC socket",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind address; defaults to 127.0.0.1 (no external interface)",
    )
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument(
        "--allowed-host",
        action="append",
        default=[],
        metavar="HOST",
        help=(
            "Extra Host header value to answer to; repeatable. Loopback and the "
            "--host bind address are always accepted. A wildcard bind (0.0.0.0, "
            "::) names no host a browser can be pointed at, so reaching the "
            "dashboard by LAN address or name needs this flag."
        ),
    )
    args = parser.parse_args(argv)

    app = create_app(socket_path=args.socket, allowed_hosts=[args.host, *args.allowed_host])
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
