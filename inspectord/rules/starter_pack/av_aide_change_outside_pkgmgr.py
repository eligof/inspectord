"""AIDE reported a change that no package-manager transaction explains.

A Python rule rather than YAML because the YAML grammar has no time-window
syntax: only Python rules receive ``EvalContext.history``.

**What it keys on.** Structure only — ``event.module``, ``event.action`` and
``threat.indicator.source``, every one of them set by the scanner runner from
its own state. Nothing here reads the AIDE report's wording, and that matters
more for AIDE than for the other two scanners: a filename containing a line
break can forge a report line, and AIDE's parser is section-driven, so a forged
line can *suppress* a genuine entry as well as invent one (see
``scanners/aide.py``, "A filename can forge a report line"). The change kind and
the path are shown in the alert text but are never matched on.
"""

from __future__ import annotations

from inspectord.rules.base import EvalContext, Match
from inspectord.schemas.event import Event

#: How far back a package-manager transaction still explains an AIDE change.
#:
#: 300 s is not a tuning guess — it is the entire depth of the correlation
#: history the rule engine keeps. ``RuleEngine._HISTORY_WINDOW`` is 300 s and
#: ``_trim_history`` drops anything older on every event, so a larger constant
#: here would read as a promise the engine cannot keep and would silently
#: behave as 300 anyway. A test pins ``PKGMGR_WINDOW_S <= _HISTORY_WINDOW``.
#:
#: Using all of that ceiling, rather than a tighter slice of it, is deliberate:
#: a ``pacman -Syu`` writes its ALPM lines across the minutes it spends
#: unpacking, and an AIDE scan running concurrently can report a changed file
#: several minutes after the transaction line that explains it.
PKGMGR_WINDOW_S = 300.0

#: Actions that mean "the package manager touched this machine". All four are
#: emitted by ``parsers/pacman.py``; ``package_reinstalled`` is included
#: because a reinstall rewrites files exactly like an upgrade, so omitting it
#: would alert on every ``pacman -S <already-installed>``.
PKGMGR_ACTIONS = frozenset(
    {
        "package_installed",
        "package_upgraded",
        "package_removed",
        "package_reinstalled",
    }
)

#: Shown verbatim in the alert during an incident, so each entry is specific to
#: this machine's reality rather than generic filler.
_FALSE_POSITIVES: tuple[str, ...] = (
    "The correlation window is only "
    f"{PKGMGR_WINDOW_S:.0f} seconds wide, because that is the entire depth of "
    "the rule engine's correlation history. It suppresses the OVERLAP case — a "
    "scan running during or just after a transaction — and nothing else. A "
    "change caused by an upgrade that finished HOURS before the nightly scan "
    "is NOT suppressed and will alert. Expect the morning after a "
    "`pacman -Syu` to be noisy; closing that gap needs a persisted "
    "package-transaction index, which does not exist yet.",
    "You edited the file yourself — a config change, a manual patch, a "
    "`systemctl edit`, an AUR or `make install` build that writes outside the "
    "pacman database. AIDE reports the change; it cannot know you meant it.",
    "Ordinary churn inside a monitored directory: log rotation, a cache or "
    "state file, `/etc/ld.so.cache` after a library install, a timestamp-only "
    "difference. Narrow the AIDE config rather than muting this rule.",
    "The AIDE database is stale relative to a deliberate reconfiguration — "
    "inspectord never re-initializes it (that would erase the baseline this "
    "rule depends on), so after a big intentional change you must re-baseline "
    "it yourself.",
    "A forged report line. A filename or directory name inside a monitored "
    "tree can carry a line break, which lets an attacker-chosen tail read as "
    "its own AIDE entry — inventing a finding on a path AIDE never reported, "
    "or mislabelling a genuine one's change kind. Confirm the path exists and "
    "really differs before acting on the wording.",
)

_MODULE = "scanner_runner"
_ACTION = "scan_finding"
_SOURCE = "aide"


def _is_aide_finding(event: Event) -> bool:
    if event.module != _MODULE or event.action != _ACTION:
        return False
    indicator = (event.threat or {}).get("indicator")
    if not isinstance(indicator, dict):
        return False
    return indicator.get("source") == _SOURCE


class _Rule:
    rule_id = "av.aide_change_outside_pkgmgr"
    name = "AIDE change with no package transaction around it"
    severity = "medium"
    category = "integrity"
    why = (
        "AIDE — the file-integrity database — reported that a monitored file was "
        "added, removed or changed, and no package-manager transaction was seen "
        f"in the {PKGMGR_WINDOW_S:.0f} seconds before it. A system file that "
        "changes outside a package install, upgrade, reinstall or removal has no "
        "routine explanation: that is the shape of a tampered binary, a dropped "
        "payload, or a config edited by something that should not have edited it.\n\n"
        "This rule keys only on which scanner ran and on the fact of a finding. "
        "It never matches on the report's wording — a filename containing a line "
        "break can forge an AIDE report line, so the change kind and path shown "
        "below are untrusted text. Verify the named path directly."
    )
    false_positives = _FALSE_POSITIVES

    def evaluate(self, ctx: EvalContext) -> list[Match]:
        event = ctx.event
        if not _is_aide_finding(event):
            return []

        # `recent_events` sets a lower bound only, which is the right shape
        # here: a finding's ts is stamped when the runner emits it, at the END
        # of a scan that took minutes, so a transaction timestamped a little
        # after it is still concurrent with the scan and explains the change
        # just as well. Package events carry pacman's OWN timestamp (parsed
        # from /var/log/pacman.log), not the moment log_tailer read the line —
        # which is the clock this comparison wants.
        recent = ctx.recent_events(window_s=PKGMGR_WINDOW_S)
        if any(other.action in PKGMGR_ACTIONS for other in recent):
            return []

        indicator = (event.threat or {}).get("indicator") or {}
        change = str(indicator.get("value") or "changed")
        path = str((event.file or {}).get("path") or "")

        if path:
            entity_kind, entity_key = "file", path
            target = path
        else:
            entity_kind, entity_key = "event", event.event_id
            target = "a file AIDE did not name"

        return [
            Match(
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=self.severity,
                category=self.category,
                dedup_key=f"{self.rule_id}:{entity_kind}:{entity_key}",
                primary_entity_kind=entity_kind,
                primary_entity_key=entity_key,
                short=f"AIDE {change} outside any package transaction: {target}",
                detail=(
                    f"AIDE reported {change!r} for {target} during a scheduled scan, "
                    f"and no package_installed / package_upgraded / package_reinstalled / "
                    f"package_removed event was seen in the preceding "
                    f"{PKGMGR_WINDOW_S:.0f} seconds. Change kind and path are "
                    f"scanner-supplied text; verify the path before acting."
                ),
                why=self.why,
                false_positives=list(self.false_positives),
                triggering_event_ids=[event.event_id],
                labels=["scanner", "aide", "integrity"],
            )
        ]


RULE = _Rule()
