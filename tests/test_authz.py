"""Tests for the polkit authorization gate (quarantine design §2).

The pkcheck stderr phrasings pinned here were observed on the development box
(polkit 127, CachyOS, 2026-09-08) — the box is the oracle, not the docs:

- authorized:       exit 0, empty stderr.
- hard deny:        exit 1, stderr ``Not authorized.``
- needs auth, no -u: exit 2, stderr
  ``Authorization requires authentication and -u wasn't passed.``
- unknown action:   exit 127, stderr ``Error checking for authorization <id>:
  GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: Action <id> is not
  registered``
- no agent (compiled-in string, verified via ``strings /usr/bin/pkcheck`` —
  never run interactively in tests): ``Authorization requires authentication
  but no agent is available.``
- dismissed prompt (compiled-in): exit 126, ``Authentication request was
  dismissed.``
"""

from __future__ import annotations

import os
import subprocess
import threading
import xml.etree.ElementTree as ET
from pathlib import Path
from subprocess import CompletedProcess
from typing import Any

import pytest

from inspectord.authz import (
    AuthzResult,
    PeerIdentity,
    _parse_start_time,
    check_polkit,
    proc_start_time,
)

_PEER = PeerIdentity(pid=4321, uid=1000, start_time=86128722)
_ACTION = "org.inspectord.quarantine"


def _proc(returncode: int, stderr: str = "") -> CompletedProcess[str]:
    return CompletedProcess(args=["pkcheck"], returncode=returncode, stdout="", stderr=stderr)


# ---------------------------------------------------------------------------
# /proc/<pid>/stat parsing
# ---------------------------------------------------------------------------


def test_parse_start_time_comm_with_spaces_and_parens() -> None:
    # comm is "(a) b)" — fields resume after the LAST ')', so a naive
    # whitespace split would misplace every field.
    tail = " ".join(str(n) for n in range(1, 19))  # fields 4..21
    raw = f"7 ((a) b)) S {tail} 424242 55"
    assert _parse_start_time(raw) == 424242


def test_parse_start_time_short_line_is_none() -> None:
    assert _parse_start_time("7 (x) S 1 2") is None


def test_parse_start_time_non_numeric_is_none() -> None:
    tail = " ".join(str(n) for n in range(1, 19))
    assert _parse_start_time(f"7 (x) S {tail} notanumber 55") is None


def test_proc_start_time_of_self_matches_stat() -> None:
    raw = Path(f"/proc/{os.getpid()}/stat").read_text()
    expected = int(raw.rsplit(")", 1)[-1].split()[19])
    assert proc_start_time(os.getpid()) == expected


def test_proc_start_time_of_missing_pid_is_none() -> None:
    assert proc_start_time(2**31 - 1) is None


# ---------------------------------------------------------------------------
# Outcome taxonomy — every branch via a fake runner
# ---------------------------------------------------------------------------


def test_exit_zero_is_authorized() -> None:
    result = check_polkit(_ACTION, _PEER, runner=lambda *a, **k: _proc(0))
    assert result.outcome == "authorized"
    assert result.authorized


def test_no_agent_is_agent_missing() -> None:
    stderr = "Authorization requires authentication but no agent is available.\n"
    result = check_polkit(_ACTION, _PEER, runner=lambda *a, **k: _proc(127, stderr))
    assert result.outcome == "agent_missing"
    assert not result.authorized


def test_unregistered_action_is_action_unknown() -> None:
    stderr = (
        "Error checking for authorization org.inspectord.quarantine: "
        "GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: "
        "Action org.inspectord.quarantine is not registered\n"
    )
    result = check_polkit(_ACTION, _PEER, runner=lambda *a, **k: _proc(127, stderr))
    assert result.outcome == "action_unknown"


def test_hard_deny_is_denied() -> None:
    result = check_polkit(_ACTION, _PEER, runner=lambda *a, **k: _proc(1, "Not authorized.\n"))
    assert result.outcome == "denied"


def test_dismissed_prompt_is_denied() -> None:
    stderr = "Authentication request was dismissed.\n"
    result = check_polkit(_ACTION, _PEER, runner=lambda *a, **k: _proc(126, stderr))
    assert result.outcome == "denied"


def test_needs_auth_without_interaction_is_denied() -> None:
    stderr = "Authorization requires authentication and -u wasn't passed.\n"
    result = check_polkit(
        _ACTION, _PEER, runner=lambda *a, **k: _proc(2, stderr), interactive=False
    )
    assert result.outcome == "denied"


def test_missing_pkcheck_is_polkit_unavailable() -> None:
    def runner(*_a: Any, **_k: Any) -> CompletedProcess[str]:
        raise FileNotFoundError("pkcheck")

    result = check_polkit(_ACTION, _PEER, runner=runner)
    assert result.outcome == "polkit_unavailable"


def test_prompt_timeout_is_timeout() -> None:
    def runner(*_a: Any, **_k: Any) -> CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd="pkcheck", timeout=60.0)

    result = check_polkit(_ACTION, _PEER, runner=runner)
    assert result.outcome == "timeout"


def test_oserror_is_error() -> None:
    def runner(*_a: Any, **_k: Any) -> CompletedProcess[str]:
        raise OSError("exec failed")

    result = check_polkit(_ACTION, _PEER, runner=runner)
    assert result.outcome == "error"
    assert not result.authorized


# ---------------------------------------------------------------------------
# argv discipline
# ---------------------------------------------------------------------------


def test_argv_with_target() -> None:
    seen: list[list[str]] = []

    def runner(argv: list[str], **_k: Any) -> CompletedProcess[str]:
        seen.append(argv)
        return _proc(0)

    check_polkit(_ACTION, _PEER, target="/tmp/evil", runner=runner)
    assert seen == [
        [
            "pkcheck",
            "--action-id",
            _ACTION,
            "--process",
            "4321,86128722",
            "--allow-user-interaction",
            "--detail",
            "path",
            "/tmp/evil",
        ]
    ]


def test_argv_without_target_and_noninteractive() -> None:
    seen: list[list[str]] = []

    def runner(argv: list[str], **_k: Any) -> CompletedProcess[str]:
        seen.append(argv)
        return _proc(0)

    check_polkit(_ACTION, _PEER, runner=runner, interactive=False)
    assert seen == [["pkcheck", "--action-id", _ACTION, "--process", "4321,86128722"]]


def test_runner_receives_timeout() -> None:
    kwargs_seen: dict[str, Any] = {}

    def runner(argv: list[str], **kwargs: Any) -> CompletedProcess[str]:
        kwargs_seen.update(kwargs)
        return _proc(0)

    check_polkit(_ACTION, _PEER, runner=runner)
    assert kwargs_seen["timeout"] == 60.0
    assert kwargs_seen["capture_output"] is True
    assert kwargs_seen["text"] is True


# ---------------------------------------------------------------------------
# One prompt at a time
# ---------------------------------------------------------------------------


def test_second_concurrent_call_is_authz_busy() -> None:
    entered = threading.Event()
    release = threading.Event()
    results: dict[str, AuthzResult] = {}

    def blocking_runner(argv: list[str], **_k: Any) -> CompletedProcess[str]:
        entered.set()
        assert release.wait(timeout=5.0), "test choreography stalled"
        return _proc(0)

    def first_call() -> None:
        results["first"] = check_polkit(_ACTION, _PEER, runner=blocking_runner)

    thread = threading.Thread(target=first_call)
    thread.start()
    try:
        assert entered.wait(timeout=5.0), "first call never reached the runner"
        second = check_polkit(_ACTION, _PEER, runner=lambda *a, **k: _proc(0))
        assert second.outcome == "authz_busy"
        assert not second.authorized
    finally:
        release.set()
        thread.join(timeout=5.0)
    assert results["first"].outcome == "authorized"


def test_semaphore_released_after_failure() -> None:
    def runner(*_a: Any, **_k: Any) -> CompletedProcess[str]:
        raise FileNotFoundError("pkcheck")

    assert check_polkit(_ACTION, _PEER, runner=runner).outcome == "polkit_unavailable"
    # The gate must be usable again after any failure path.
    assert check_polkit(_ACTION, _PEER, runner=lambda *a, **k: _proc(0)).authorized


# ---------------------------------------------------------------------------
# Policy file — all three defaults pinned per spec §2.4
# ---------------------------------------------------------------------------

_POLICY = Path(__file__).resolve().parent.parent / "packaging" / "polkit" / "org.inspectord.policy"

_EXPECTED_DEFAULTS = {
    "org.inspectord.quarantine": ("no", "no", "auth_self_keep"),
    "org.inspectord.quarantine-restore": ("no", "no", "auth_self"),
    "org.inspectord.quarantine-delete": ("no", "no", "auth_self"),
}


def test_policy_file_pins_all_three_defaults() -> None:
    root = ET.fromstring(_POLICY.read_text())
    actions = {a.get("id"): a for a in root.findall("action")}
    assert set(actions) == set(_EXPECTED_DEFAULTS)
    for action_id, (allow_any, allow_inactive, allow_active) in _EXPECTED_DEFAULTS.items():
        defaults = actions[action_id].find("defaults")
        assert defaults is not None, action_id
        assert defaults.findtext("allow_any") == allow_any, action_id
        assert defaults.findtext("allow_inactive") == allow_inactive, action_id
        assert defaults.findtext("allow_active") == allow_active, action_id
        assert actions[action_id].findtext("description"), action_id
        assert actions[action_id].findtext("message"), action_id


def test_config_example_documents_policy_install() -> None:
    text = (_POLICY.parent.parent / "config.example.toml").read_text()
    assert "org.inspectord.policy" in text
    assert "/usr/share/polkit-1/actions" in text


# ---------------------------------------------------------------------------
# Real pkcheck (root-only, never interactive)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    os.geteuid() != 0 or not Path("/usr/bin/pkcheck").exists(),
    reason="requires root and an installed pkcheck",
)
def test_real_pkcheck_unknown_action_noninteractive() -> None:
    peer = PeerIdentity(
        pid=os.getpid(), uid=os.getuid(), start_time=proc_start_time(os.getpid()) or 0
    )
    result = check_polkit("org.inspectord.test-nonexistent", peer, interactive=False)
    assert result.outcome == "action_unknown"
