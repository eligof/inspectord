"""inspectorctl-tray — minimal status indicator.

Phase 0 deliverable: a system tray icon that polls inspectord's IPC every
few seconds and shows green if it's responding, red if not. No alert handling
yet.
"""

from __future__ import annotations

import argparse
import threading
import time
from pathlib import Path

import pystray
from PIL import Image, ImageDraw

from inspectorctl.ipc_client import IpcClient, IpcError


def _icon(color: str) -> Image.Image:
    img = Image.new("RGB", (64, 64), "white")
    draw = ImageDraw.Draw(img)
    draw.ellipse((6, 6, 58, 58), fill=color)
    return img


def main() -> None:
    parser = argparse.ArgumentParser(prog="inspectorctl-tray")
    parser.add_argument("--socket", type=Path, default=Path.cwd() / "var" / "inspectord.sock")
    parser.add_argument("--poll-interval", type=float, default=5.0)
    args = parser.parse_args()

    client = IpcClient(socket_path=args.socket)
    state = {"healthy": False}

    def build_menu() -> pystray.Menu:
        return pystray.Menu(
            pystray.MenuItem(
                "Healthy" if state["healthy"] else "Not responding",
                lambda _: None,
                enabled=False,
            ),
            pystray.MenuItem("Quit", lambda icon, _: icon.stop()),
        )

    def poll(icon: pystray.Icon) -> None:
        while True:
            try:
                client.call("get_health")
                state["healthy"] = True
                icon.icon = _icon("green")
            except IpcError:
                state["healthy"] = False
                icon.icon = _icon("red")
            icon.menu = build_menu()
            time.sleep(args.poll_interval)

    icon = pystray.Icon("inspectord", _icon("gray"), "Local Inspection", build_menu())

    def setup(icon: pystray.Icon) -> None:
        icon.visible = True
        threading.Thread(target=poll, args=(icon,), daemon=True).start()

    icon.run(setup=setup)


if __name__ == "__main__":
    main()
