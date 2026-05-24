"""Tests for the process enricher."""

from __future__ import annotations

from inspectord.enrichment.process import enrich_process
from inspectord.parsers.base import build_event


class _FakeProcReader:
    def __init__(self, data: dict[int, dict[str, object]]) -> None:
        self._data = data

    def read_pid(self, pid: int) -> dict[str, object] | None:
        return self._data.get(pid)


def _ev(pid: int) -> object:
    return build_event(
        module="log_tailer",
        action="ssh_login",
        category=["authentication"],
        type_=["start"],
        severity="info",
        process={"pid": pid},
    )


def test_enrich_attaches_exe_and_hash() -> None:
    reader = _FakeProcReader(
        {
            1234: {
                "exe": "/usr/sbin/sshd",
                "exe_sha256": "deadbeef" * 8,
                "cmdline": "/usr/sbin/sshd -D",
                "ppid": 1,
                "parent_comm": "systemd",
            }
        }
    )
    ev = _ev(1234)
    out = enrich_process(ev, reader=reader)
    assert out.process is not None
    assert out.process["executable"] == "/usr/sbin/sshd"
    assert out.process["hash"]["sha256"] == "deadbeef" * 8
    assert out.process["command_line"] == "/usr/sbin/sshd -D"
    assert out.process["parent"] == {"pid": 1, "name": "systemd"}


def test_enrich_is_noop_when_pid_unknown() -> None:
    reader = _FakeProcReader({})
    ev = _ev(99999)
    out = enrich_process(ev, reader=reader)
    assert out.process == {"pid": 99999}


def test_enrich_skips_when_event_has_no_pid() -> None:
    ev = build_event(
        module="log_tailer",
        action="x",
        category=["host"],
        type_=["info"],
        severity="info",
    )
    out = enrich_process(ev, reader=_FakeProcReader({}))
    assert out.process is None
