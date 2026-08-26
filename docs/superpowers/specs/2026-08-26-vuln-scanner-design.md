# vuln_scanner — design

Date: 2026-08-26 (v2 — concilium 3-lens review, unanimous REVISE: 2 BLOCKING +
8 MAJOR + ~10 MINOR findings folded)
Parent: `2026-05-24-local-inspection-design.md` §15.
Status: **autonomously drafted, NOT human-reviewed** (concilium-reviewed in-session).
**User decision on record (2026-08-26): local advisory file ONLY — zero egress, not
even opt-in.**

## 1. Goal

Surface known CVEs affecting installed packages: match `pacman -Q` against a
user-maintained local copy of the Arch Security Advisories JSON, materialize a
`vulnerabilities` table, alert on newly appearing Critical/High advisories, panel +
audited acknowledge flow. Data freshness (the user's own cron feeding the file) is
surfaced, never assumed.

## 2. Scope

### In

- **PR1 (daemon):** `vuln_scanner` worker; **`Event.vulnerability` schema field +
  `build_event` kwarg** (persistence precedent — `extra="forbid"` means the schema
  change is mandatory, not optional); projector branch + migration
  `0012_vulnerabilities.sql`; **`_primary_entity_for` vulnerability branch** in the
  YAML rule loader (dedup keys are underivable otherwise); starter rules
  `vuln.new_critical` / `vuln.new_high`.
- **PR2 (web):** `list_vulnerabilities` + `ack_vulnerability` IPC, `/vulnerabilities`
  panel with filters, ack, advisory-age + scan-freshness lines.

### Out (deliberate)

| Cut | Why |
| --- | --- |
| Network feed fetch | User decision: zero egress. The user refreshes the file via their own cron (`curl … -o advisories.json.tmp && mv` — atomic replace documented). |
| NVD subset | No coverage gain for an Arch box; format churn. |
| Pending action "apply -Syu" | Phase 4; v1 shows suggestion text. |
| AUR packages | No advisory source. Same-name custom-repo/AUR rebuilds with divergent versions are an accepted false-positive source. |
| Pure-Python version compare | alpm semantics are subtle; `vercmp` subprocess is correct by construction. Missing binary → scan fails with reason. |
| Unack flow | Ack is an acknowledgment, not a state machine. |
| Alert on stale advisory file | Surfaced as panel warning + summary field, not a rule; revisit if ignored staleness proves real. |
| Reappearance during daemon downtime alerting | A package downgraded back to a vulnerable version while the daemon is down re-enters via the baseline (suppressed) — no alert. Accepted; the row un-resolves so the panel shows it. |

## 3. Advisory file

- Config (inside the worker's `config` dict — `WorkerSpec` has no top-level
  `enabled`; inclusion = enabled): `advisory_path` (default
  `/var/lib/inspectord/advisories.json`), `interval_s` (86400), `poll_s` (60),
  `advisory_stale_after_s` (14 days).
- Format: security.archlinux.org `/json` dump — JSON array of AVG objects; consumed
  fields `name`, `packages`, `status`, `severity`, `affected`, `fixed`, `issues`.
- Robust parse: **pre-parse stat cap 64 MB** (over → `vuln_scan_failed`,
  `file_too_large`, no read); bounded read; not-a-JSON-array OR **empty array** →
  failed scan (`advisories_empty` — an empty Arch advisory DB is never legitimate,
  and treating it as data would mass-resolve everything); per-AVG malformed/cap
  violations → AVG **skipped and its id recorded** (see §5 sweep), counted warning.
  Caps: ≤ 50 000 AVGs, ≤ 64 packages/CVEs per AVG; strings length-capped +
  control-char-stripped; AVG id must match `^AVG-[0-9]+$`.
- Scan triggers: worker start; every `interval_s`; advisory-file `(mtime, size)`
  change; **`/var/lib/pacman/local` mtime change** (parent §15.1 requires rescan on
  package change — a `pacman -Syu` takes effect within a minute, exactly when the
  panel's own remediation advice was just followed). File-triggered scans are
  rate-limited to one per 300 s (a mid-`mv` flap cannot thrash).
- Guards before scanning: `/var/lib/pacman/db.lck` present → skip with reason
  `pacman_db_locked`, retry next poll (a mid-upgrade `pacman -Q` reads torn state);
  `pacman -Q` nonzero exit → failed scan, never partial data. Remaining `-Q` TOCTOU
  (unlocked read) is accepted eventual-consistency — the next scan corrects.

## 4. Matching

- Installed set: `pacman -Q` (shell=False, bounded, `name version` lines;
  unparseable lines counted).
- Full status set handled explicitly (real tracker values): `Not affected` → skip.
  `Vulnerable` / `Fixed` / `Testing`: if `fixed` set → vulnerable iff
  `vercmp(installed, fixed) < 0`; if `fixed` null and status `Vulnerable` →
  vulnerable. `Testing` matches carry `fix_in_testing: true` (the fix exists only in
  [testing]; the panel qualifies the `-Syu` suggestion). `Unknown` with null
  `fixed` → row + event, never an alert (treated like Medium severity).
  Unrecognized status string → counted warning, AVG treated as skipped (no guessing,
  no resolution side-effects).
- `affected` is **deliberately unused** for matching: it is a single version (the
  vulnerable version at AVG creation), not a range; the tracker's own semantics are
  "everything < fixed is vulnerable". Using it as a lower bound would be an
  incorrect "improvement". Downgrade-below-affected false positives are accepted.
- `vercmp` subprocess per (installed, fixed) pair after name filtering — realistic
  first-scan volume is hundreds to low thousands of calls (historical `Fixed` AVGs
  pass the status filter); the result cache is **worker-lifetime** (pure function of
  two strings), so steady-state rescans fork almost nothing. Scan duration is
  recorded in the summary event.
- Granularity: one row per `(avg_id, cve_id, package)`; severity is the AVG-level
  maximum (per-CVE severities are not in the dump — documented over-attribution).

## 5. Events, projection, rules

Worker never touches the DB. **Full-set emission + projector sweep** (the
`listener_state` snapshot_gen precedent), which makes resolution correct across
daemon downtime — the failure mode that killed the delta design:

- Every scan emits the **entire current match set** as `vulnerability_found` events
  (`module="vuln_scanner"`, `kind="state"`), payload `vulnerability = {avg_id,
  cve_id, package, installed_version, fixed_version, severity, status,
  fix_in_testing, new, advisory_url}`. `advisory_url` is constructed from the
  validated AVG id — never read from the file. `new` is computed against the
  worker's in-memory previous-set: true only for matches not present last scan
  (always false on the first scan of a worker lifetime).
- First scan after start additionally sets `first_seen=True` (rule engine drops
  those globally — restart never re-alerts; persistence precedent).
- Each scan ends with `vuln_scan_completed` carrying `{scan_started_at, advisories,
  matched, new, warnings, skipped_avg_ids, advisory_mtime, duration_ms}`
  (`skipped_avg_ids` capped at 500 — more than that means the file is broken and
  the scan should have failed instead).
- **Projector** (`_project_vulnerability`): on found → upsert (PK avg/cve/package):
  insert sets `first_seen_at`; update touches installed/fixed/severity/status/
  `fix_in_testing`/`last_seen`/`last_event_id` and clears `resolved_at`; **never
  touches `first_seen_at`, `acked_at`, `acked_note`** (ack survives upserts; the
  column is `first_seen_at` precisely to avoid colliding with the event-level
  `first_seen` suppression flag). On `vuln_scan_completed` → sweep: set
  `resolved_at = now` on unresolved rows whose `last_seen < scan_started_at` AND
  whose `avg_id` is NOT in `skipped_avg_ids` (a malformed AVG must never silently
  resolve real CVEs). Rows are never deleted.
- **Rules**: `vuln.new_critical` (alert high) / `vuln.new_high` (alert medium) match
  `vulnerability_found` where `vulnerability.new == true` and severity Critical/High.
  `_primary_entity_for` gains a vulnerability branch returning
  `("package", f"{avg_id}/{package}")` — one alert per advisory per package (not per
  CVE), with a real dedup key instead of the per-event fallback.
- Ack (PR2) writes only `acked_at`/`acked_note` from the IPC thread — same
  write-write-conflict window as the alerts table's IPC transitions (accepted,
  same precedent).

## 6. Failure honesty & freshness

- Any scan that cannot run or complete → `vuln_scan_failed` with `raw.reason`
  (`advisories_missing` / `advisories_empty` / `file_too_large` / `vercmp_missing` /
  `pacman_db_locked` / `pacman_failed` / `parse_failed`) — one per scan attempt, at
  the scan cadence (not per poll).
- The panel's freshness line reads the latest of `vuln_scan_completed` OR
  `vuln_scan_failed` and shows the failure reason inline — a perpetually failing
  scan must not render as mute staleness.
- **Advisory age**: `advisory_mtime` rides the summary; the panel renders
  "advisories updated N days ago", styled as a warning past
  `advisory_stale_after_s`. A silently dead refresh cron is this feature's single
  point of failure — it gets a face, not an assumption.

## 7. PR2 — IPC + panel + ack

- `list_vulnerabilities` (mutates=False): `{limit?, severity?, include_acked?,
  include_resolved?}`, newest-first by `first_seen_at`, cap 500.
- `ack_vulnerability` (mutates=True): `{avg_id, cve_id, package, note?}` → sets
  `acked_at`/`acked_note`; audit row `vulnerability_acked`, target
  `vuln:<avg_id>/<cve_id>/<package>`, details `{"note": ...}`.
- `/vulnerabilities` panel: package, installed, CVE (advisory link), severity badge,
  fixed-in (with "in [testing]" qualifier when `fix_in_testing`), status, acked;
  filters via query params; per-row Ack POST (same-origin, 303); `pacman -Syu <pkg>`
  suggestion text (qualified for testing-only fixes); freshness + advisory-age lines
  per §6. Autoescaped.

## 8. Testing

TDD. Parser: valid/malformed-AVG-skip/non-array/empty-array/size-cap/string
caps/control chars/id regex/unrecognized status. Matching: per-status branches,
fix_in_testing tag, vercmp mocked + live integration test with **epoch pairs
(`1:1.0-1` vs `2.0-1`) and missing-pkgrel pairs** (`vercmp('1.2.3-2','1.2.3') == 0`
— a feed entry missing pkgrel masks rel-only fixes; document), name filtering,
worker-lifetime cache. Worker: full-set emission each scan; `new` flag lifecycle
(first scan all-new=false+first_seen, later scans mark genuinely new);
pacman-db-mtime retrigger; file-change retrigger + 300 s rate limit; db.lck skip;
every failure reason; summary fields incl. skipped_avg_ids + advisory_mtime.
Projector: insert/update/sweep; **skipped-AVG rows survive the sweep**; ack +
first_seen_at preserved across upserts; resolve→reappear clears resolved_at. Rules:
Critical→high, High→medium, Medium/Unknown→none, `new=false` no alert, first_seen
suppressed, dedup key `avg/package`. PR2: IPC shapes, ack + audit row, panel
render/filters/XSS/ack POST/staleness warning.

## 9. Delivery

PR1 daemon (schema field + worker + projector + migration 0012 + rule-loader branch
+ rules), PR2 web. Worker entry in `dev_config` (no `enabled` key — inclusion is
enablement).
