"""log_tailer worker (spec §5.1)."""

from __future__ import annotations

import contextlib
import json
from pathlib import Path
from typing import Any, Protocol

from inspectord.parsers.auth_log import parse_auth_log_line
from inspectord.parsers.journald import parse_journald_entry
from inspectord.parsers.pacman import parse_pacman_line
from inspectord.schemas.event import Event
from inspectord.sources.file_tail import TailingFileSource
from inspectord.sources.journal_source import JournalSource
from inspectord.workers.contract import Worker, read_config_from_stdin


class _JournalSource(Protocol):
    def open(self) -> None: ...
    def close(self) -> None: ...
    def read_one(self, *, timeout: float = 0.5) -> dict[str, Any] | None: ...


_DEFAULT_PACMAN_LOG = "/var/log/pacman.log"
_DEFAULT_AUTH_LOG = "/var/log/auth.log"


class LogTailerWorker(Worker):
    def __init__(
        self,
        *,
        name: str,
        journal_source: _JournalSource | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(name=name, **kwargs)
        self._pacman_path = Path(self.config.get("pacman_log_path", _DEFAULT_PACMAN_LOG))
        self._auth_path = Path(self.config.get("auth_log_path", _DEFAULT_AUTH_LOG))
        self._journal_source: _JournalSource = (
            journal_source if journal_source is not None else JournalSource()
        )
        self._pacman_source = TailingFileSource(self._pacman_path, from_start=False)
        self._auth_source = TailingFileSource(self._auth_path, from_start=False)

    def step_interval_s(self) -> float:
        return 0.0  # the worker does its own internal polling on each source

    def setup(self) -> None:
        self._journal_source.open()
        self._pacman_source.open()
        self._auth_source.open()

    def teardown(self) -> None:
        for src in (self._journal_source, self._pacman_source, self._auth_source):
            with contextlib.suppress(Exception):
                src.close()

    def _emit(self, ev: Event | None) -> None:
        if ev is None:
            return
        self.emit_event(json.loads(ev.model_dump_json()))

    def step(self) -> None:
        entry = self._journal_source.read_one(timeout=0.1)
        if entry is not None:
            self._emit(parse_journald_entry(entry, source="journald"))
        pacman_line = self._pacman_source.read_one(timeout=0.05)
        if pacman_line is not None:
            self._emit(parse_pacman_line(pacman_line, source=str(self._pacman_path)))
        auth_line = self._auth_source.read_one(timeout=0.05)
        if auth_line is not None:
            self._emit(parse_auth_log_line(auth_line, source=str(self._auth_path)))


def main() -> None:
    cfg: dict[str, Any] = read_config_from_stdin()
    LogTailerWorker(name="log_tailer", config=cfg).run()


if __name__ == "__main__":
    main()
