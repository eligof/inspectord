"""Synthetic emitter worker — emits N canned events then exits.

Used by tests/integration/test_alerts_e2e.py to drive the rule_engine end-to-end
without needing a real process_collector. Reads three config keys:
  - events: list of literal Event dicts to emit (TOML inline tables)
  - events_file: path to a JSON file containing an array of Event dicts
  - delay_s: how long to wait between emissions (default 0.1)

``events_file`` is preferred for complex events whose structure cannot be
expressed as TOML inline tables (e.g. values that are arrays).
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from inspectord.workers.contract import Worker, read_config_from_stdin


class SyntheticEmitterWorker(Worker):
    def step_interval_s(self) -> float:
        return 0.0

    def setup(self) -> None:
        events_file = self.config.get("events_file")
        if events_file is not None:
            self._events: list[dict[str, Any]] = json.loads(Path(events_file).read_text())
        else:
            self._events = list(self.config.get("events", []))
        self._delay = float(self.config.get("delay_s", 0.1))
        self._emitted = False

    def step(self) -> None:
        if self._emitted:
            self.request_stop()
            return
        for ev in self._events:
            self.emit_event(ev)
            time.sleep(self._delay)
        self._emitted = True


def main() -> None:
    cfg: dict[str, Any] = read_config_from_stdin()
    SyntheticEmitterWorker(name="synthetic_emitter", config=cfg).run()


if __name__ == "__main__":
    main()
