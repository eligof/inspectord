"""Tests for the listening_socket_snapshotter /proc/net diff source.

All tests inject a ``reader`` callable so they never touch the real filesystem.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from inspectord.workers.listening_socket_snapshotter.source import (
    ListeningSocketSource,
    _decode_ipv4,
    _decode_ipv6,
    _decode_local_addr,
    diff_listeners,
    parse_listeners,
)

# ---------------------------------------------------------------------------
# _decode_ipv4
# ---------------------------------------------------------------------------


def test_decode_ipv4_loopback() -> None:
    assert _decode_ipv4("0100007F") == "127.0.0.1"


def test_decode_ipv4_any() -> None:
    assert _decode_ipv4("00000000") == "0.0.0.0"


# ---------------------------------------------------------------------------
# _decode_ipv6
# ---------------------------------------------------------------------------


def test_decode_ipv6_all_zero() -> None:
    assert _decode_ipv6("00000000000000000000000000000000") == "::"


def test_decode_ipv6_loopback() -> None:
    # ::1 encoded as 4 little-endian 32-bit words: 00000000 00000000 00000000 01000000
    assert _decode_ipv6("00000000000000000000000001000000") == "::1"


# ---------------------------------------------------------------------------
# _decode_local_addr
# ---------------------------------------------------------------------------


def test_decode_local_addr_ipv4() -> None:
    ip, port = _decode_local_addr("0100007F:0016")
    assert ip == "127.0.0.1"
    assert port == 22


def test_decode_local_addr_ipv6() -> None:
    ip, port = _decode_local_addr("00000000000000000000000001000000:0050")
    assert ip == "::1"
    assert port == 80


# ---------------------------------------------------------------------------
# parse_listeners — tcp
# ---------------------------------------------------------------------------

_TCP_HDR = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"  # noqa: E501
_TCP_ROW0 = "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0"  # noqa: E501
_TCP_ROW1 = "   1: 0100007F:8AE2 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 67890 1 0000000000000000 20 0 0 10 0"  # noqa: E501
_TCP_SAMPLE = f"{_TCP_HDR}\n{_TCP_ROW0}\n{_TCP_ROW1}\n"


def test_parse_listeners_tcp_returns_only_listen_state() -> None:
    result = parse_listeners(_TCP_SAMPLE, "tcp")
    # Only the row with st=0A (LISTEN) on 0.0.0.0:22 should appear
    assert len(result) == 1
    key = ("tcp", "0.0.0.0", 22)
    assert key in result
    assert result[key] == {"proto": "tcp", "ip": "0.0.0.0", "port": 22}


def test_parse_listeners_tcp_excludes_established() -> None:
    result = parse_listeners(_TCP_SAMPLE, "tcp")
    # The ESTABLISHED row (port 35554, 0x8AE2) must not appear
    for _proto, _ip, port in result:
        assert port != 0x8AE2


# ---------------------------------------------------------------------------
# parse_listeners — tcp6
# ---------------------------------------------------------------------------

_TCP6_SAMPLE = """\
  sl  local_address                         remote_address                        st
   0: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A
"""


def test_parse_listeners_tcp6_loopback_listen() -> None:
    result = parse_listeners(_TCP6_SAMPLE, "tcp6")
    key = ("tcp6", "::1", 22)
    assert key in result
    assert result[key]["proto"] == "tcp6"
    assert result[key]["ip"] == "::1"
    assert result[key]["port"] == 22


# ---------------------------------------------------------------------------
# parse_listeners — udp
# ---------------------------------------------------------------------------

_UDP_ROW0 = "   0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 11111 2 0000000000000000 0"  # noqa: E501
_UDP_ROW1 = "   1: 0100007F:EA60 0100007F:EA61 07 00000000:00000000 00:00000000 00000000  1000        0 22222 2 0000000000000000 0"  # noqa: E501
_UDP_SAMPLE = f"{_TCP_HDR}\n{_UDP_ROW0}\n{_UDP_ROW1}\n"


def test_parse_listeners_udp_bound_socket_included() -> None:
    result = parse_listeners(_UDP_SAMPLE, "udp")
    # Remote port 0 → bound → included (port 53, DNS)
    key = ("udp", "0.0.0.0", 53)
    assert key in result


def test_parse_listeners_udp_nonzero_remote_port_excluded() -> None:
    result = parse_listeners(_UDP_SAMPLE, "udp")
    # The row with rem port 0xEA61 (non-zero) must be excluded
    assert ("udp", "127.0.0.1", 0xEA60) not in result


# ---------------------------------------------------------------------------
# parse_listeners — header and malformed rows
# ---------------------------------------------------------------------------


def test_parse_listeners_ignores_header_line() -> None:
    # Header has non-hex tokens in the address fields; must be silently skipped
    result = parse_listeners(_TCP_SAMPLE, "tcp")
    # No KeyError / ValueError should have propagated; and header isn't in result
    assert all(isinstance(k[2], int) for k in result)


def test_parse_listeners_skips_malformed_rows() -> None:
    text = "  sl  local_address rem_address   st\n   0: GARBAGE\n"
    result = parse_listeners(text, "tcp")
    assert result == {}


def test_parse_listeners_too_few_fields_skipped() -> None:
    text = "  sl  local_address rem_address   st\n   0: incomplete_row\n"
    result = parse_listeners(text, "tcp")
    assert result == {}


# ---------------------------------------------------------------------------
# diff_listeners
# ---------------------------------------------------------------------------


def test_diff_listeners_added() -> None:
    prev: dict = {}
    curr = {("tcp", "0.0.0.0", 22): {"proto": "tcp", "ip": "0.0.0.0", "port": 22}}
    result = diff_listeners(prev, curr)
    assert result == [{"action": "listener_added", "proto": "tcp", "ip": "0.0.0.0", "port": 22}]


def test_diff_listeners_removed() -> None:
    prev = {("tcp", "0.0.0.0", 22): {"proto": "tcp", "ip": "0.0.0.0", "port": 22}}
    curr: dict = {}
    result = diff_listeners(prev, curr)
    assert result == [{"action": "listener_removed", "proto": "tcp", "ip": "0.0.0.0", "port": 22}]


def test_diff_listeners_identical_returns_empty() -> None:
    snap = {("tcp", "0.0.0.0", 80): {"proto": "tcp", "ip": "0.0.0.0", "port": 80}}
    assert diff_listeners(snap, snap) == []


def test_diff_listeners_sort_order() -> None:
    # "listener_added" sorts before "listener_removed"
    prev = {("tcp", "0.0.0.0", 443): {"proto": "tcp", "ip": "0.0.0.0", "port": 443}}
    curr = {("tcp", "0.0.0.0", 80): {"proto": "tcp", "ip": "0.0.0.0", "port": 80}}
    result = diff_listeners(prev, curr)
    assert result[0]["action"] == "listener_added"
    assert result[1]["action"] == "listener_removed"


# ---------------------------------------------------------------------------
# ListeningSocketSource
# ---------------------------------------------------------------------------

# Minimal proc/net text snippets used across source tests
_EMPTY_HEADER = "  sl  local_address rem_address   st\n"
_LISTEN_22_ROW = "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0"  # noqa: E501
_LISTEN_80_ROW = "   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0"  # noqa: E501
_LISTEN_22_TCP = f"{_TCP_HDR}\n{_LISTEN_22_ROW}\n"
_LISTEN_80_TCP = f"{_TCP_HDR}\n{_LISTEN_80_ROW}\n"

_PROTOS = ("tcp", "tcp6", "udp", "udp6")


def _make_reader(
    *snapshots: dict[str, str],
) -> Callable[[str], str]:
    """Return a reader(proto) callable that steps through *snapshots* once per poll.

    Each element of *snapshots* is a ``{proto: text}`` mapping covering one full
    read round (all four protos).  Missing protos default to ``_EMPTY_HEADER``.
    The reader advances to the next snapshot after the last proto in ``_PROTOS``
    is served, so one snapshot == one complete read of all four protos.
    The last snapshot is held indefinitely once exhausted.
    """
    seq = list(snapshots)
    idx = 0
    call_count = 0
    n_protos = len(_PROTOS)

    def reader(proto: str) -> str:
        nonlocal idx, call_count
        text = seq[idx].get(proto, _EMPTY_HEADER)
        call_count += 1
        if call_count % n_protos == 0 and idx < len(seq) - 1:
            idx += 1
        return text

    return reader


def test_source_baseline_not_emitted() -> None:
    """Sockets present at construction must NOT appear on the first poll."""
    reader = _make_reader(
        {"tcp": _LISTEN_22_TCP},  # baseline
        {"tcp": _LISTEN_22_TCP},  # poll 1 — same state
    )
    src = ListeningSocketSource(reader=reader)
    result = src.poll(timeout_ms=0)
    assert result == []


def test_source_new_listener_emitted_as_added() -> None:
    """A listener that appears after baseline is emitted as listener_added."""
    reader = _make_reader(
        {},  # baseline: all protos empty
        {"tcp": _LISTEN_22_TCP},  # poll 1: port 22 appears
    )
    src = ListeningSocketSource(reader=reader)
    result = src.poll(timeout_ms=0)
    assert len(result) == 1
    assert result[0]["action"] == "listener_added"
    assert result[0]["proto"] == "tcp"
    assert result[0]["port"] == 22


def test_source_removed_listener_emitted_as_removed() -> None:
    """A listener that disappears after baseline is emitted as listener_removed."""
    reader = _make_reader(
        {"tcp": _LISTEN_22_TCP},  # baseline: port 22 present
        {},  # poll 1: all protos empty
    )
    src = ListeningSocketSource(reader=reader)
    result = src.poll(timeout_ms=0)
    assert len(result) == 1
    assert result[0]["action"] == "listener_removed"
    assert result[0]["port"] == 22


def test_source_poll_raises_after_close() -> None:
    """poll() must raise RuntimeError after close() has been called."""
    reader = _make_reader({})
    src = ListeningSocketSource(reader=reader)
    src.close()
    with pytest.raises(RuntimeError, match="closed"):
        src.poll(timeout_ms=0)


def test_source_close_is_idempotent() -> None:
    reader = _make_reader({})
    src = ListeningSocketSource(reader=reader)
    assert src._closed is False
    src.close()
    assert src._closed is True
    src.close()  # must not raise
    assert src._closed is True


def test_source_two_consecutive_polls() -> None:
    """Each poll advances the snapshot so diffs are relative to the previous call."""
    reader = _make_reader(
        {},  # baseline: empty
        {"tcp": _LISTEN_22_TCP},  # poll 1: port 22 appears
        {"tcp": _LISTEN_80_TCP},  # poll 2: port 80 replaces port 22
    )
    src = ListeningSocketSource(reader=reader)

    result1 = src.poll(timeout_ms=0)
    assert len(result1) == 1
    assert result1[0]["action"] == "listener_added"
    assert result1[0]["port"] == 22

    result2 = src.poll(timeout_ms=0)
    actions = {r["action"] for r in result2}
    ports = {r["port"] for r in result2}
    assert actions == {"listener_added", "listener_removed"}
    assert ports == {22, 80}
