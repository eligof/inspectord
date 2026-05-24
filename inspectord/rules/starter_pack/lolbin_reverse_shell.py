"""Bash reverse-shell pattern (bash -i >& /dev/tcp/...)."""

from __future__ import annotations

import re

from inspectord.rules.base import EvalContext, Match

_PATTERN = re.compile(r"bash\b.*-i\b.*>&\s*/dev/tcp/(?P<ip>[^/\s]+)/(?P<port>\d+)")


class _Rule:
    rule_id = "lolbin.bash_dev_tcp"
    name = "Reverse-shell pattern: bash -i >& /dev/tcp/..."
    severity = "critical"
    category = "intrusion_detection"
    why = (
        "bash -i >& /dev/tcp/... is the classic reverse-shell idiom. "
        "Possible false positives: pentest/CTF tools you ran yourself."
    )

    def evaluate(self, ctx: EvalContext) -> list[Match]:
        ev = ctx.event
        if ev.module != "process_collector":
            return []
        proc = ev.process or {}
        if proc.get("name") != "bash":
            return []
        cmd = proc.get("command_line") or ""
        m = _PATTERN.search(cmd)
        if m is None:
            return []
        ip = m.group("ip")
        port = m.group("port")
        pid = proc.get("pid", "?")
        short = f"Reverse-shell pattern: bash → {ip}:{port} (pid {pid})"
        detail = (
            f"bash command line matched /dev/tcp pattern.\n"
            f"  pid: {pid}\n  command: {cmd}\n  destination: {ip}:{port}"
        )
        return [
            Match(
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=self.severity,
                category=self.category,
                dedup_key=f"{self.rule_id}:pid:{pid}",
                primary_entity_kind="process",
                primary_entity_key=f"pid:{pid}",
                short=short,
                detail=detail,
                why=self.why,
                false_positives=["pentest/CTF tools you ran yourself"],
                triggering_event_ids=[ev.event_id],
                labels=["lolbin", "reverse-shell"],
            )
        ]


RULE = _Rule()
