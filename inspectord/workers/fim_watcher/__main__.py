"""fim_watcher worker — inotify-based file integrity monitor (spec §5.1)."""

from __future__ import annotations

import contextlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from inotify_simple import INotify, flags

from inspectord.ids import uuid7
from inspectord.schemas.event import Event
from inspectord.schemas.versions import EVENT_SCHEMA_VERSION
from inspectord.workers.contract import Worker, read_config_from_stdin
from inspectord.workers.fim_watcher.paths import default_watch_paths

_WATCH_MASK = (
    flags.CREATE
    | flags.DELETE
    | flags.MODIFY
    | flags.ATTRIB
    | flags.MOVED_FROM
    | flags.MOVED_TO
    | flags.DELETE_SELF
    | flags.MOVE_SELF
)


def _action_from_flags(event_flags: int) -> str:
    if event_flags & flags.CREATE or event_flags & flags.MOVED_TO:
        return "file_created"
    if (
        event_flags & flags.DELETE
        or event_flags & flags.MOVED_FROM
        or event_flags & flags.DELETE_SELF
        or event_flags & flags.MOVE_SELF
    ):
        return "file_deleted"
    if event_flags & flags.MODIFY:
        return "file_modified"
    if event_flags & flags.ATTRIB:
        return "file_attributes_changed"
    return "file_event"


class FimWatcherWorker(Worker):
    def __init__(self, *, name: str, **kwargs: Any) -> None:
        super().__init__(name=name, **kwargs)
        self._watch_paths: list[str] = self.config.get("watch_paths") or default_watch_paths()
        self._inotify: INotify | None = None
        self._wd_to_path: dict[int, str] = {}

    def step_interval_s(self) -> float:
        return 0.0

    def setup(self) -> None:
        self._inotify = INotify()
        for raw in self._watch_paths:
            p = Path(raw)
            if not p.exists():
                continue
            try:
                wd = self._inotify.add_watch(str(p), _WATCH_MASK)
                self._wd_to_path[wd] = str(p)
            except (OSError, PermissionError):
                continue

    def teardown(self) -> None:
        if self._inotify is not None:
            with contextlib.suppress(Exception):
                self._inotify.close()
            self._inotify = None

    def _emit(self, action: str, path: str, severity: str = "low") -> None:
        ev = Event.model_validate(
            {
                "schema_version": EVENT_SCHEMA_VERSION,
                "ts": datetime.now(UTC).isoformat(),
                "event_id": str(uuid7()),
                "kind": "event",
                "category": ["file"],
                "type": ["change"],
                "action": action,
                "severity": severity,
                "module": "fim_watcher",
                "file": {"path": path},
                "host": {"hostname": os.uname().nodename, "os": {"family": "linux"}},
                "labels": [f"fim:{Path(path).name}"],
                "message": f"{action} {path}",
            }
        )
        self.emit_event(json.loads(ev.model_dump_json()))

    def step(self) -> None:
        if self._inotify is None:
            return
        events = self._inotify.read(timeout=200)
        for ev in events:
            base_path = self._wd_to_path.get(ev.wd, "?")
            full_path = str(Path(base_path) / ev.name) if ev.name else base_path
            self._emit(_action_from_flags(ev.mask), full_path)


def main() -> None:
    cfg: dict[str, Any] = read_config_from_stdin()
    FimWatcherWorker(name="fim_watcher", config=cfg).run()


if __name__ == "__main__":
    main()
