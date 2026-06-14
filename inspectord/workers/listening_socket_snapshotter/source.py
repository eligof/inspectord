"""listening_socket_snapshotter source — polls /proc/net/{tcp,tcp6,udp,udp6} and diffs snapshots."""

from __future__ import annotations

import ipaddress
import time
from collections.abc import Callable
from typing import Any

_PROTOS: tuple[str, ...] = ("tcp", "tcp6", "udp", "udp6")


def _read_proc_net(proto: str) -> str:
    """Read and return the raw text of ``/proc/net/<proto>``."""
    with open(f"/proc/net/{proto}", encoding="ascii") as fh:
        return fh.read()


def _decode_ipv4(hexip: str) -> str:
    """Decode a little-endian 8-hex-char IPv4 address from ``/proc/net/tcp``.

    The kernel stores the address as 4 bytes in little-endian (host) byte order,
    written as a single 8-character uppercase hex string.  To decode, split into
    4 byte-pairs, reverse the list, and format as dotted-decimal.

    Examples::

        _decode_ipv4("0100007F") == "127.0.0.1"
        _decode_ipv4("00000000") == "0.0.0.0"
    """
    # Each pair of hex chars is one byte; reverse for big-endian
    octets = [int(hexip[i : i + 2], 16) for i in range(0, 8, 2)]
    octets.reverse()
    return ".".join(str(b) for b in octets)


def _decode_ipv6(hexip: str) -> str:
    """Decode a little-endian 32-hex-char IPv6 address from ``/proc/net/tcp6``.

    The kernel stores the address as four consecutive 32-bit words, each in
    little-endian byte order.  To decode: split into 4 chunks of 8 hex chars;
    for each chunk, take the 4 byte-pairs and reverse them; concatenate the
    resulting 16 bytes and pass to ``ipaddress.IPv6Address``.

    Examples::

        _decode_ipv6("00000000000000000000000000000000") == "::"
        _decode_ipv6("00000000000000000000000001000000") == "::1"
    """
    raw_bytes = bytearray()
    for chunk_start in range(0, 32, 8):
        chunk = hexip[chunk_start : chunk_start + 8]
        word_bytes = bytes(int(chunk[i : i + 2], 16) for i in range(0, 8, 2))
        raw_bytes.extend(reversed(word_bytes))
    return str(ipaddress.IPv6Address(bytes(raw_bytes)))


def _decode_local_addr(hexaddr: str) -> tuple[str, int]:
    """Split ``"HEXIP:HEXPORT"`` and decode the IP and port.

    The IP hex length determines the address family:
    - 8 hex chars → IPv4, decoded via ``_decode_ipv4``.
    - Anything else → passed to ``_decode_ipv6``; raises ``ValueError`` on
      invalid hex input.

    Returns:
        ``(ip_string, port_int)``
    """
    hex_ip, hex_port = hexaddr.split(":")
    port = int(hex_port, 16)
    ip = _decode_ipv4(hex_ip) if len(hex_ip) == 8 else _decode_ipv6(hex_ip)
    return ip, port


def parse_listeners(
    text: str,
    proto: str,
) -> dict[tuple[str, str, int], dict[str, Any]]:
    """Parse one ``/proc/net/<proto>`` text into a mapping of listening sockets.

    The first (header) line and blank lines are skipped.  Malformed rows are
    silently dropped.  Each whitespace-split row has:

    - index 1: ``local_address`` (``HEXIP:HEXPORT``)
    - index 2: ``rem_address``   (``HEXIP:HEXPORT``)
    - index 3: ``st``            (hex state byte)

    Selection rules:

    - ``tcp`` / ``tcp6``: include rows where ``st == "0A"`` (``TCP_LISTEN``).
    - ``udp`` / ``udp6``: include rows where the remote port is ``0`` (bound).

    Returns:
        ``{(proto, ip, port): {"proto": proto, "ip": ip, "port": port}}``
    """
    result: dict[tuple[str, str, int], dict[str, Any]] = {}
    is_udp = proto in ("udp", "udp6")
    lines = text.splitlines()
    # Skip the header (first non-blank line)
    first = True
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        if first:
            first = False
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        try:
            local_addr = parts[1]
            rem_addr = parts[2]
            state = parts[3]
            if is_udp:
                _rem_ip, rem_port = _decode_local_addr(rem_addr)
                if rem_port != 0:
                    continue
            elif state.upper() != "0A":
                continue
            ip, port = _decode_local_addr(local_addr)
        except (ValueError, IndexError):
            continue
        key = (proto, ip, port)
        result[key] = {"proto": proto, "ip": ip, "port": port}
    return result


def diff_listeners(
    prev: dict[tuple[str, str, int], dict[str, Any]],
    curr: dict[tuple[str, str, int], dict[str, Any]],
) -> list[dict[str, Any]]:
    """Compare two listener snapshots and return change records.

    For each key in ``curr`` but not ``prev``: ``{"action": "listener_added", ...}``.
    For each key in ``prev`` but not ``curr``: ``{"action": "listener_removed", ...}``.

    The result is sorted by ``(action, proto, ip, port)`` for deterministic output.
    """
    records: list[dict[str, Any]] = []
    for key, info in curr.items():
        if key not in prev:
            records.append(
                {
                    "action": "listener_added",
                    "proto": info["proto"],
                    "ip": info["ip"],
                    "port": info["port"],
                }
            )
    for key, info in prev.items():
        if key not in curr:
            records.append(
                {
                    "action": "listener_removed",
                    "proto": info["proto"],
                    "ip": info["ip"],
                    "port": info["port"],
                }
            )
    records.sort(key=lambda r: (r["action"], r["proto"], r["ip"], r["port"]))
    return records


def _snapshot_all(reader: Callable[[str], str]) -> dict[tuple[str, str, int], dict[str, Any]]:
    """Read all four proto files via *reader* and merge into one listener dict."""
    merged: dict[tuple[str, str, int], dict[str, Any]] = {}
    for proto in _PROTOS:
        merged.update(parse_listeners(reader(proto), proto))
    return merged


class ListeningSocketSource:
    """Polls ``/proc/net/{tcp,tcp6,udp,udp6}`` on each call to ``poll`` and returns diff records.

    Inject ``reader`` to avoid touching the real filesystem in tests.

    The baseline snapshot is captured in ``__init__``, so sockets already
    listening at startup are NOT reported as added.
    """

    def __init__(
        self,
        *,
        reader: Callable[[str], str] = _read_proc_net,
    ) -> None:
        self._reader = reader
        self._closed = False
        self._snapshot = _snapshot_all(reader)

    def poll(self, timeout_ms: int) -> list[dict[str, Any]]:
        """Sleep for *timeout_ms* ms, read all proc/net files, and return diff records."""
        if self._closed:
            raise RuntimeError("source is closed")
        time.sleep(timeout_ms / 1000)
        curr = _snapshot_all(self._reader)
        records = diff_listeners(self._snapshot, curr)
        self._snapshot = curr
        return records

    def close(self) -> None:
        """Mark the source closed (idempotent; no external resources to release)."""
        self._closed = True
