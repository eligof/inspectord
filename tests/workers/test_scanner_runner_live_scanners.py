"""Live scanner tests — the adapters against the real binaries.

The YARA tests need no privileges and run in the ordinary gate whenever `yara`
is installed; they drive the **whole worker**, so a real subprocess, the real
argv, the real parse and the real events are all exercised.

The rkhunter tests are **root-only**: `/usr/bin/rkhunter` is `0700 root:root`.
Run them with::

    sudo .venv/bin/python -m pytest tests/workers/test_scanner_runner_live_scanners.py

There is no marker for a root-only non-eBPF test in this repo (`ebpf_load` would
be a lie -- nothing here loads a BPF program), so they use the same
`skipif(os.geteuid() != 0)` guard `tests/test_native_loader.py` uses. They
therefore SKIP, never fail, under the CI gate
`-m "not integration and not ebpf_load"`.

Bounded on purpose: a full `rkhunter --check` takes minutes, so these run a
single narrow `--enable` group (~6s) and one invalid invocation (~0.4s). Nothing
here touches the network (design decision 8: no `--update`, ever), writes to
`/var/log` (the log goes to `tmp_path`) or runs `--propupd`, which would rewrite
a system baseline file.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from io import BytesIO
from pathlib import Path
from typing import Any

import pytest

from inspectord.workers.scanner_runner.runner import ScannerRunnerWorker
from inspectord.workers.scanner_runner.scanners.base import ScanOutcome
from inspectord.workers.scanner_runner.scanners.rkhunter import RkhunterAdapter
from inspectord.workers.scanner_runner.scanners.yara import YaraAdapter

requires_yara = pytest.mark.skipif(shutil.which("yara") is None, reason="needs the yara binary")
requires_root_rkhunter = pytest.mark.skipif(
    os.geteuid() != 0 or shutil.which("rkhunter") is None,
    reason="needs root and rkhunter (/usr/bin/rkhunter is 0700 root:root)",
)

RULE = """\
rule Inspectord_Live_Test_Rule
{
    meta:
        severity = "high"
        description = "live adapter test, with a comma and \\"quotes\\""
    strings:
        $marker = "INSPECTORD_LIVE_TEST_MARKER"
    condition:
        $marker
}
"""


def _run_worker(config: dict[str, Any], adapters: list[Any]) -> list[dict[str, Any]]:
    """Tick a real worker until a scan finishes (or 60s pass)."""
    buf = BytesIO()
    worker = ScannerRunnerWorker(
        name="scanner_runner",
        adapters=adapters,
        config=config,
        stdout=buf,
        stderr=BytesIO(),
        host_name="testhost",
    )
    deadline = time.monotonic() + 60.0
    try:
        while True:
            worker.step()
            events = [json.loads(line) for line in buf.getvalue().splitlines() if line]
            done = any(e["action"] in ("scan_completed", "scan_skipped") for e in events)
            if done or time.monotonic() > deadline:
                return events
            time.sleep(0.05)
    finally:
        worker.teardown()


# --------------------------------------------------------------------------
# YARA -- no root required
# --------------------------------------------------------------------------


@requires_yara
def test_live_yara_match_becomes_a_finding_event(tmp_path: Path) -> None:
    """End to end: real rules file, real target, real yara, real events."""
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "live.yar").write_text(RULE)
    target = tmp_path / "target"
    target.mkdir()
    hit = target / "hit.txt"
    hit.write_text("padding INSPECTORD_LIVE_TEST_MARKER padding\n")
    (target / "miss.txt").write_text("nothing interesting here\n")

    events = _run_worker(
        {
            "interval_s": 0.01,
            "startup_delay_s": 0.0,
            "scanners": {
                "yara": {
                    "enabled": True,
                    "interval_s": 1000.0,
                    "timeout_s": 60.0,
                    "rules_dir": str(rules),
                    "target": str(target),
                }
            },
        },
        [YaraAdapter()],
    )

    actions = [e["action"] for e in events]
    assert actions.count("scan_started") == 1, events
    completed = next(e for e in events if e["action"] == "scan_completed")
    assert completed["outcome"] == "success", completed
    assert completed["raw"]["scan_outcome"] == "findings", completed

    findings = [e for e in events if e["action"] == "scan_finding"]
    assert len(findings) == 1, findings
    indicator = findings[0]["threat"]["indicator"]
    assert indicator["type"] == "yara_rule"
    assert indicator["value"] == "Inspectord_Live_Test_Rule"
    assert indicator["source"] == "yara"
    # The SCANNER's own severity, read out of the rule's meta by `-m`.
    assert indicator["severity"] == "high"
    assert findings[0]["file"]["path"] == str(hit)


@requires_yara
def test_live_yara_clean_target_reports_success_with_no_findings(tmp_path: Path) -> None:
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "live.yar").write_text(RULE)
    target = tmp_path / "target"
    target.mkdir()
    (target / "miss.txt").write_text("nothing interesting here\n")

    events = _run_worker(
        {
            "interval_s": 0.01,
            "startup_delay_s": 0.0,
            "scanners": {
                "yara": {
                    "enabled": True,
                    "interval_s": 1000.0,
                    "timeout_s": 60.0,
                    "rules_dir": str(rules),
                    "target": str(target),
                }
            },
        },
        [YaraAdapter()],
    )

    assert [e["action"] for e in events] == ["scan_started", "scan_completed"], events
    assert events[-1]["raw"]["scan_outcome"] == "clean", events[-1]


@requires_yara
def test_live_yara_with_no_rules_skips_instead_of_failing(tmp_path: Path) -> None:
    """The state this adapter's preflight exists for: rules not shipped yet.

    Without it yara would read the TARGET as a rules file and exit 1, and a
    perfectly ordinary state would be reported as a broken scanner.
    """
    rules = tmp_path / "rules"
    rules.mkdir()
    target = tmp_path / "target"
    target.mkdir()

    events = _run_worker(
        {
            "interval_s": 0.01,
            "startup_delay_s": 0.0,
            "scanners": {
                "yara": {
                    "enabled": True,
                    "interval_s": 1000.0,
                    "timeout_s": 60.0,
                    "rules_dir": str(rules),
                    "target": str(target),
                }
            },
        },
        [YaraAdapter()],
    )

    assert [e["action"] for e in events] == ["scan_skipped"], events
    assert events[0]["raw"]["reason"] == "rules_empty", events[0]


# --------------------------------------------------------------------------
# rkhunter -- root only
# --------------------------------------------------------------------------


def _run_rkhunter(config: dict[str, Any], timeout_s: float) -> subprocess.CompletedProcess[str]:
    argv = RkhunterAdapter().argv(config)
    assert "--update" not in argv and "--propupd" not in argv  # decision 8
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        stdin=subprocess.DEVNULL,
        check=False,
    )


@requires_root_rkhunter
def test_live_rkhunter_warning_becomes_a_finding(tmp_path: Path) -> None:
    """A real warning from a real check must parse into a real Finding.

    `--enable properties` is the narrowest group that reports something on a
    stock host (~6s); a full `--check` is minutes and is deliberately not run.
    """
    adapter = RkhunterAdapter()
    config = {"enable": ["properties"], "logfile": str(tmp_path / "rkhunter.log")}
    proc = _run_rkhunter(config, timeout_s=300.0)

    findings = adapter.parse(proc.stdout, proc.stderr)
    if not findings:
        pytest.skip(f"this host reports no rkhunter warnings (exit {proc.returncode})")

    # The measured shape: warnings AND a non-zero exit code.
    assert proc.returncode != 0, proc.stdout
    assert adapter.interpret_outcome(proc.returncode, proc.stdout, proc.stderr) is (
        ScanOutcome.findings
    )
    for finding in findings:
        assert finding.indicator_type == "rkhunter_test"
        assert finding.indicator_value
        assert finding.message
        assert finding.category in ("file", "process")
    # Continuation lines are folded in, never counted as separate warnings.
    assert len(findings) == proc.stdout.count("\nWarning:") + proc.stdout.startswith("Warning:")


@requires_root_rkhunter
def test_live_rkhunter_invalid_invocation_is_a_failure_not_a_detection(tmp_path: Path) -> None:
    """The regression test for the whole point of this PR.

    `--disable all` is rejected by rkhunter with the SAME exit code a real
    warning produces. Classifying on the code alone would report a scanner that
    never ran as a rootkit detection.
    """
    adapter = RkhunterAdapter()
    proc = _run_rkhunter(
        {"disable": ["all"], "logfile": str(tmp_path / "rkhunter.log")}, timeout_s=120.0
    )

    assert proc.returncode != 0, proc.stdout
    assert adapter.parse(proc.stdout, proc.stderr) == []
    assert adapter.interpret_outcome(proc.returncode, proc.stdout, proc.stderr) is (
        ScanOutcome.failure
    )


@requires_root_rkhunter
def test_live_rkhunter_clean_check_is_clean(tmp_path: Path) -> None:
    """A check that finds nothing exits 0 with empty stdout -- the third case
    the exit code alone cannot be trusted to describe."""
    adapter = RkhunterAdapter()
    proc = _run_rkhunter(
        {"enable": ["hidden_ports"], "logfile": str(tmp_path / "rkhunter.log")}, timeout_s=120.0
    )
    outcome = adapter.interpret_outcome(proc.returncode, proc.stdout, proc.stderr)

    if proc.returncode == 0:
        assert outcome is ScanOutcome.clean
        assert adapter.parse(proc.stdout, proc.stderr) == []
    else:  # this host has something to report even here; then it must be findings
        assert outcome is ScanOutcome.findings, proc.stdout
