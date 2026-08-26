"""vuln_scanner worker entry point.

A contract worker: config arrives as one JSON object on stdin, events leave as
NDJSON on stdout, heartbeats on stderr. The contract's ``run()`` installs the
SIGTERM/SIGINT handlers itself, so its ``finally`` (final heartbeat + teardown)
always runs — the udev-monitor lesson.

Run standalone (for debugging):

    echo '{"advisory_path": "/var/lib/inspectord/advisories.json"}' \
        | python -m inspectord.workers.vuln_scanner
"""

from __future__ import annotations

from typing import Any

from inspectord.workers.contract import read_config_from_stdin
from inspectord.workers.vuln_scanner.worker import VulnScannerWorker


def main() -> None:
    config: dict[str, Any] = read_config_from_stdin()
    VulnScannerWorker(name="vuln_scanner", config=config).run()


if __name__ == "__main__":
    main()
