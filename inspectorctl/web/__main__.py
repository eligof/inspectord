"""inspectorctl-web entry point — runs uvicorn on 127.0.0.1.

Usage:
  inspectorctl-web                          # dev: socket under ./var/
  inspectorctl-web --socket /run/inspectord/inspectord.sock --port 8765
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
    args = parser.parse_args(argv)

    app = create_app(socket_path=args.socket)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
