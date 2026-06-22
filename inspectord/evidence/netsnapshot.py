"""Bounded all-states /proc/net snapshot (spec §3.4).

Reads tcp/tcp6/udp/udp6, decoding every socket (not just LISTEN) via the listener
source's hex helpers. Bounded by _MAX_ROWS so a host with many sockets cannot blow up
the capture; malformed rows and missing proto files are skipped, never raised.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from inspectord.workers.listening_socket_snapshotter.source import _decode_local_addr

_PROTOS: tuple[str, ...] = ("tcp", "tcp6", "udp", "udp6")
_MAX_ROWS = 4096

# Only the two states we name; any other hex st byte is recorded verbatim (intentional).
_STATE_NAMES = {
    "0A": "listen",
    "01": "established",
}


def network_snapshot(proc_net_dir: Path = Path("/proc/net")) -> dict[str, Any]:
    """Return a bounded snapshot of all sockets across the four /proc/net protos."""
    proc_net_dir = Path(proc_net_dir)
    sockets: list[dict[str, Any]] = []
    truncated = False

    for proto in _PROTOS:
        if truncated:
            break
        try:
            text = (proc_net_dir / proto).read_text(encoding="ascii", errors="replace")
        except OSError:
            continue
        first = True
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if first:
                first = False  # skip header
                continue
            if len(sockets) >= _MAX_ROWS:
                truncated = True
                break
            parts = line.split()
            if len(parts) < 4:
                continue
            try:
                local_ip, local_port = _decode_local_addr(parts[1])
                rem_ip, rem_port = _decode_local_addr(parts[2])
                st = parts[3].upper()
            except (ValueError, IndexError):
                continue
            state = _STATE_NAMES.get(st, st)
            sockets.append(
                {
                    "proto": proto,
                    "local": [local_ip, local_port],
                    "remote": [rem_ip, rem_port],
                    "state": state,
                }
            )

    return {
        "captured_at": datetime.now(UTC).isoformat(),
        "truncated": truncated,
        "sockets": sockets,
    }
