"""Healthcheck worker.

Emits a synthetic event on a configurable cadence so the supervisor and
end-to-end pipeline can be validated without any OS-level collectors.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

from inspectord.ids import uuid7
from inspectord.schemas.versions import EVENT_SCHEMA_VERSION
from inspectord.workers.contract import Worker, read_config_from_stdin


class HealthcheckWorker(Worker):
    def step_interval_s(self) -> float:
        return float(self.config.get("interval_s", 1.0))

    def step(self) -> None:
        self.emit_event(
            {
                "schema_version": EVENT_SCHEMA_VERSION,
                "ts": datetime.now(UTC).isoformat(),
                "event_id": str(uuid7()),
                "kind": "event",
                "category": ["host"],
                "type": ["info"],
                "action": "synthetic_heartbeat",
                "severity": "info",
                "module": "healthcheck",
                "host": {"hostname": os.uname().nodename, "os": {"family": "linux"}},
                "message": "healthcheck synthetic event",
            }
        )


def main() -> None:
    cfg: dict[str, Any] = read_config_from_stdin()
    HealthcheckWorker(name="healthcheck", config=cfg).run()


if __name__ == "__main__":
    main()
