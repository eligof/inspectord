"""inspectord entry point.

Usage:
  inspectord --dev                          # dev mode: paths under ./var/
  inspectord --config /etc/inspectord/config.toml
"""

from __future__ import annotations

import argparse
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Any

from inspectord.config import dev_config, load
from inspectord.ipc_server import IpcServer, Method
from inspectord.log import configure as configure_log
from inspectord.log import get
from inspectord.supervisor import Supervisor

log = get("inspectord")


def _ipc_methods(supervisor: Supervisor) -> list[Method]:
    def get_health(_params: dict[str, Any]) -> dict[str, Any]:
        return {
            "schema_version": "1.0.0",
            "supervisor": "running",
            "workers": [{"name": "healthcheck", "status": "up"}],
        }

    return [Method(name="get_health", handler=get_health, mutates=False)]


def main() -> None:
    parser = argparse.ArgumentParser(prog="inspectord")
    parser.add_argument("--dev", action="store_true", help="dev paths under ./var/")
    parser.add_argument("--config", type=Path, default=None)
    args = parser.parse_args()

    configure_log()

    if args.dev:
        cfg = dev_config(base=Path.cwd())
    elif args.config is not None:
        cfg = load(args.config)
    else:
        print("inspectord: pass --dev or --config <path>", file=sys.stderr)
        sys.exit(2)

    sup = Supervisor(cfg)
    sup.start()

    ipc = IpcServer(
        socket_path=cfg.ipc.socket_path,
        methods=_ipc_methods(sup),
        allowed_uids=cfg.ipc.allowed_uids,
    )
    ipc.start()
    log.info("inspectord ready; socket=%s", cfg.ipc.socket_path)

    stop = threading.Event()

    def _shutdown(*_: object) -> None:
        log.info("inspectord shutting down")
        stop.set()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    try:
        while not stop.is_set():
            time.sleep(0.2)
    finally:
        ipc.stop()
        sup.stop(timeout=5.0)
    log.info("inspectord exited cleanly")


if __name__ == "__main__":
    main()
