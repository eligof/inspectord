"""scanner_runner worker entry point.

A contract worker (design decision 1): config arrives as one JSON object on
stdin, events leave as NDJSON on stdout, heartbeats on stderr. The whole
behavior of this worker is configuration — which scanners, how often, what
timeouts — which is why it is not a source worker.

Run standalone (for debugging):

    echo '{"startup_delay_s": 0, "scanners": {"aide": {"enabled": true}}}' \
        | python -m inspectord.workers.scanner_runner
"""

from __future__ import annotations

from typing import Any

from inspectord.workers.contract import read_config_from_stdin
from inspectord.workers.scanner_runner.runner import ScannerRunnerWorker


def main() -> None:
    config: dict[str, Any] = read_config_from_stdin()
    ScannerRunnerWorker(name="scanner_runner", config=config).run()


if __name__ == "__main__":
    main()
