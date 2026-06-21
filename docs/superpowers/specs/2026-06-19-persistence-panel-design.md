# Persistence inventory + panel (entity-state sub-project 2) — design

| Field | Value |
| --- | --- |
| Date | 2026-06-19 |
| Status | Approved (brainstorming) + concilium-reviewed 2026-06-21 — ready for implementation plan |
| Spec section refs | §2.2 (panels), §14.1 (entities), §16 (IPC), §19 (baselines), §31 (roadmap, Phase 2) |
| Parent spec | `docs/superpowers/specs/2026-05-24-local-inspection-design.md` |
| Sub-project 1 spec | `docs/superpowers/specs/2026-06-16-entity-state-panels-design.md` (the locked architecture this reuses) |

## 1. Purpose & context

Sub-project 1 shipped the entity-state projection core + 5 data-backed panels (Services,
Devices, Processes, Network, File integrity — PRs #99–#103). This is **sub-project 2**: the
**Persistence** panel (parent spec §2.2). Unlike sub-project 1, Persistence is **not backed
by an existing collector** — it needs a net-new poll-snapshot collector that inventories the
host's persistence mechanisms, then the now-familiar projection + panel.

The high-value security signal for this panel is **"a new persistence entry appeared"**, so
baseline-diff (from sub-project 1's generic `baseline_entry` machinery) is wired in.

> **A concilium (multi-lens design review) on 2026-06-21 verified the architecture and PR
> split against the codebase and approved them, but corrected three false premises and two
> enumerator specs in the first draft.** The fixes are folded in below and called out where
> relevant. The corrected premises: (a) `fim_watcher` is **non-recursive**, so `/etc`
> subdirectory vectors are NOT FIM-covered — the persistence inventory is the *primary*
> signal there; (b) the persistence detection **rules do not yet exist** — v1 is
> inventory + baseline-diff only, with no alerting; (c) `build_event()` has no `persistence`
> kwarg, so the Event-schema change is two-part.

### Design decisions (locked during brainstorming 2026-06-19; confirmed by concilium)

| Decision | Choice | Rationale |
| --- | --- | --- |
| Mechanisms in v1 | **Core four**: cron, systemd timers, XDG autostart, `authorized_keys` | High-signal, all enumerable unprivileged. Concilium confirmed: keep exactly this set, expand nothing into v1; name other vectors as explicit deferrals (§10). |
| Collector structure | **One `persistence_snapshotter` worker, four pluggable enumerators** | One poll process for slow-changing data; each enumerator pure & independently testable. (Rejected: 4 separate collectors = boilerplate ×4; query-time enumeration = breaks materialized-state architecture + no event stream for rules.) |
| Snapshot model | **Poll → full snapshot → diff → per-entry `persistence_added`/`persistence_removed` deltas** | Mirrors `listening_socket_snapshotter`; projector just upserts/deletes, current set = all rows. **Diff is per-source** (§3.2) so one unreadable source never mass-emits removals. |
| Baseline diff | **Included, wired to `kind='persistence'`** | "New entry appeared" is the point of a persistence panel; generic `baseline_entry` machinery already exists. Statuses: new / removed / unchanged (no "re-enabled" — entries either exist or not). |
| Removed-entry semantics | **Delete the row** (current set = all rows) | Inventory = "what exists now," like listeners. Concilium call: keep DELETE for consistency; document the add+remove-between-baselines blind spot (§11). |
| Alerting | **Out of v1 — inventory + baseline-diff only** | The `persistence.new_*` rules do not exist yet (only `sudoers_modified`, `new_suid`). Detection rules are a named follow-up (§10); v1 surfaces persistence in the panel, not as alerts. |

## 2. Architecture

Reuses sub-project 1's 4-layer model (collector → supervisor `_persist` → projector →
materialized table → IPC → web). The only net-new collector layer:

```
persistence_snapshotter (poll, pure-Python)
    source.snapshot() → {persist_key: attrs}      # 4 enumerators merged, per-source robust
    worker diffs vs previous snapshot (starts EMPTY → first poll emits all current as added)
        → Event(action=persistence_added | persistence_removed) per changed entry
            → Supervisor._persist → project() → persistence_state
                → list_persistence (IPC) → /persistence web panel
```

## 3. The collector — `persistence_snapshotter`

Pure-Python poll-snapshot worker; **mirror `listening_socket_snapshotter`** (poll → diff →
emit added/removed deltas). Slow poll (persistence changes rarely; default ~30 s).

**No subprocess use** (contract): every enumerator reads files directly — no `systemctl
list-timers`, no `crontab -l`, no `ssh-keygen`. This keeps the no-new-attack-surface property
reviewable.

### 3.1 `source.py` — `snapshot() -> dict[str, dict[str, Any]]`

Returns `{persist_key: attrs}`. Calls the enumerators and merges. **Robustness contract
(concilium must-fix #6):** a *parse error on readable content* skips that line/entry; a
*missing or unreadable source* (file/dir absent or permission denied) yields **zero entries
for that source and is logged**, never an exception and never a wider empty snapshot. Each
`attrs` dict carries: `kind`, `name`, `source_path`, `details` (see §6.2 for the `details`
length bound). On this Arch host none of `/etc/crontab`, `/etc/cron.d`, `/var/spool/cron`
need exist — the collector must degrade to "no entries from that source."

| Enumerator | Sources (all read directly, unprivileged) | `persist_key` | Notes |
| --- | --- | --- | --- |
| `_enum_cron` | **3 sub-parsers** (concilium must-fix #5) — see §3.1.1 | per sub-parser | distinct formats; do NOT use one parser |
| `_enum_timers` | **Enabled** timers only (concilium must-fix #4) — see §3.1.2 | `persist:timer:<scope>:<unit>` | resolve `*.wants/` symlinks; skip masked + template `@` units |
| `_enum_autostart` | `*.desktop` in `~/.config/autostart`, `/etc/xdg/autostart` | `persist:autostart:<path>` | name = `Name=`; details = `Exec=`; missing `Exec` → skip |
| `_enum_authorized_keys` | `~/.ssh/authorized_keys` | `persist:authkey:<keytype>:<fingerprint>` | options-prefixed lines — see §3.1.3 |

#### 3.1.1 Cron — three sub-parsers

Cron formats differ; one `sha256(schedule+command)` formula produces garbage keys for the
run-parts script dirs (which contain *scripts*, not crontab lines).

- **System crontab** (`/etc/crontab`, `/etc/cron.d/*`): lines are `schedule user command`.
  Honor `@`-shortcuts (`@daily`, `@reboot`), skip `ENV=value` assignment lines, comments,
  blanks. `name` = command (bounded); `details` = `schedule user command` (bounded);
  `persist_key = persist:cron:<source_path>:<sha256(schedule+command)[:12]>`.
- **User crontab** (`/var/spool/cron/<user>`): lines are `schedule command` (no user field).
  Same `@`-shortcut / `ENV=` / comment handling. Key as above.
- **Run-parts dirs** (`/etc/cron.{hourly,daily,weekly,monthly}/*`): each entry is an
  executable script, not a crontab line. `persist_key = persist:cron:<path>` (no content
  hash); `name` = filename; `details` = `run-parts <dirname>` (the schedule is the directory
  cadence). No schedule/command parsing.

#### 3.1.2 Timers — enabled only

Globbing every `.timer` file overstates ~9× (vendor units in `/usr/lib/systemd/system` are
mostly inert) and would drown baseline-diff. Enumerate **enabled** timers by resolving the
symlinks under `timers.target.wants/` for both scopes:
- system: `/etc/systemd/system/timers.target.wants/*.timer`,
  `/usr/lib/systemd/system/timers.target.wants/*.timer`
- user: `~/.config/systemd/user/timers.target.wants/*.timer`,
  `/etc/systemd/user/timers.target.wants/*.timer`

Skip masked units (symlink → `/dev/null`) and template units (`name@.timer`). `scope` =
`system`|`user`. `name` = unit; `details` = the `OnCalendar=`/`OnBootSec=` line(s) from the
resolved unit file if parseable, else `""`.

#### 3.1.3 authorized_keys

Per non-blank, non-`#` line: a key line may be **options-prefixed**
(`command="..." ssh-ed25519 AAAA... comment`). Detect the keytype as the first token matching
a known prefix (`ssh-rsa`, `ssh-ed25519`, `ecdsa-sha2-*`, `sk-ssh-*`, `sk-ecdsa-*`); treat
everything before it as ignored options. Base64-decode the next field, validate the embedded
length-prefixed type matches, and `fingerprint = SHA-256(blob)` rendered to match
`ssh-keygen -E sha256` (`SHA256:<base64>`), so the user can cross-check. Skip on mismatch.
`name` = comment (or fingerprint if none); `details` = `<keytype> <fingerprint>`.

### 3.2 `__main__.py` — the worker

Mirror the `listening_socket_snapshotter` worker structure, with **two deliberate
divergences** the concilium flagged:

1. **Start with an EMPTY previous snapshot** (concilium must-fix #7). The listener *source*
   baseline-suppresses pre-existing entries on init (so it only reports *changes*). We do the
   opposite: the first poll must emit every current entry as `persistence_added` so
   `persistence_state` is populated (an empty panel until something changes would be useless).
   Do not copy the listener source's init-suppression.
2. **Diff per-source, not globally** (concilium must-fix #6). Compute the new snapshot as the
   union of per-source results; if a source raised/was unreadable this poll, carry forward the
   previous poll's entries for *that source* rather than treating them as removed. This
   prevents a transient unreadable read from emitting a storm of `persistence_removed`
   (which would DELETE rows and, once rules exist, fire spurious alerts).

Per changed entry emit one Event:
- `persistence_added` (`type=["start"]`): keys present now but not previously.
- `persistence_removed` (`type=["end"]`): keys previously present but gone now.

Event shape: `module="persistence_snapshotter"`, `category=["host"]`,
`severity="low"` (except `authkey` deltas → `severity="medium"`: a new SSH key is high-value),
`labels=["persistence", f"persist:{kind}"]`, a normalized `persistence` block
`{"kind", "name", "source_path", "details", "key"}`, and `raw={"source": <source_path>}`.

**Event-schema change is two-part (concilium must-fix #1).** The listener template emits via
`build_event()`, which has no `persistence` param, so PR6 must:
1. add a typed `persistence: dict[str, Any] | None` field to the `Event` model
   (`inspectord/schemas/event.py`, which is `extra="forbid"`), mirroring `device`/`file`; AND
2. add a `persistence` kwarg to `build_event()` (`inspectord/parsers/base.py`) that forwards
   into `Event(...)`.

Without both, the worker physically cannot set `event.persistence` and the §5 projector read
fails.

### 3.3 Wiring & privileges

Add a `persistence_snapshotter` entry to `dev_config` (`inspectord/config.py`), `config={}`.
The collector runs unprivileged; it reads the invoking user's crontab, user systemd timers,
`~/.config/autostart`, and `~/.ssh/authorized_keys`, plus world-readable system locations
(`/etc/cron*`, `/usr/lib/systemd/system`, `/etc/xdg/autostart`). Root-owned per-user crontabs
of *other* users are out of scope (§10). Unreadable sources are logged (§3.1), so a missing
signal is visible rather than silent false-assurance.

## 4. Storage — migration `0005_persistence_state.sql`

```sql
-- kind=persistence — persist:<kind>:<id>  (parent spec §14.1)
CREATE TABLE IF NOT EXISTS persistence_state (
    persist_key   VARCHAR PRIMARY KEY,
    kind          VARCHAR NOT NULL,      -- cron | timer | autostart | authorized_key
    name          VARCHAR,
    source_path   VARCHAR,
    details       VARCHAR,
    first_seen    TIMESTAMP NOT NULL,
    last_seen     TIMESTAMP NOT NULL,
    last_event_id VARCHAR
);
```

Additive; `IF NOT EXISTS`. (`baseline_entry` already exists from `0004`.)

## 5. Projector (`inspectord/state/projector.py`)

Add one branch: `event.module == "persistence_snapshotter"` → `_project_persistence`.

| Action token | Transition |
| --- | --- |
| `persistence_removed` | `DELETE FROM persistence_state WHERE persist_key = ?` (short-circuit) |
| `persistence_added` (else) | upsert on `persist_key` (kind/name/source_path/details/last_seen/last_event_id), preserve `first_seen` |

Branch on `event.action == "persistence_removed"` → DELETE, else upsert (name the exact
token so worker/projector cannot drift). `persist_key` from `event.persistence["key"]` (carried
in the typed block, not reconstructed from ECS fields); no-op if absent. Mirrors
`_project_listener`.

## 6. IPC + baseline (`inspectord/state/ipc_handlers.py`, `baseline.py`, `__main__.py`)

- **`capture_baseline`** — extend `baseline.py`: add `'persistence'` to `_SUPPORTED` and a
  branch that snapshots `persistence_state` → `baseline_entry` (key = `persist_key`,
  `attrs_json = {kind, name, source_path, details}`, `details` bounded per §6.2). (Forward
  note: a generic table-driven `capture_baseline` is a deferred refactor once a *third* kind
  needs baselining; additive if/elif is the conscious choice for now.)
- **`handle_list_persistence(*, params, db_path)`** — params `diff?` (bool), `limit`
  (default 200). `SELECT persist_key, kind, name, source_path, details, first_seen, last_seen
  FROM persistence_state ORDER BY kind, name LIMIT ?`. When `diff`, each row carries
  `diff_status ∈ {new, removed, unchanged}` vs `baseline_entry` (kind='persistence');
  baseline keys absent from the current set appear as synthetic `removed` rows (mirror
  `handle_list_services`, minus "re-enabled"). Returns
  `{"schema_version": "1.0.0", "persistence": [...]}`.
- Register `list_persistence` (`mutates=False`) in `__main__.py`. `capture_baseline` already
  registered (now accepts `kind='persistence'`).

### 6.1 Persistence diff semantics

- **new** — `persist_key` in `persistence_state`, not in baseline.
- **removed** — `persist_key` in baseline, not in `persistence_state` (synthetic row).
- **unchanged** — present in both.

No "re-enabled": persistence entries have no active/inactive sub-state.

### 6.2 `details` length bound (privacy — concilium should-consider)

Cron commands and `.desktop` `Exec=` lines routinely embed secrets (`curl -u user:pass`,
`mysqldump -p…`). The high-signal datum is *that the entry exists and its hash changed*, not
the full argv. Bound `details` to a fixed max length (e.g. 256 chars, truncated with an
ellipsis) in the enumerators, and apply the same bound to the `baseline_entry.attrs_json`
copy. Key fingerprints (not raw keys) are stored for `authorized_keys`.

## 7. Web panel (`inspectorctl/web/`)

Mirror the **Services** panel (single table + Capture-baseline button):

| Panel | Route | IPC | Columns |
| --- | --- | --- | --- |
| Persistence | `/persistence` (+`/feed`) | `list_persistence?diff=1` | kind, name, source, details, diff badge, first_seen; **"Capture baseline"** button → `capture_baseline(kind='persistence')` |

Route `inspectorctl/web/routes/persistence.py` (`GET /persistence`, `GET /persistence/feed`,
`POST /persistence/capture-baseline`); templates `persistence.html` + `persistence_feed.html`;
router + `nav_link("/persistence", "Persistence", …)` (after File integrity). Reuses the
`status_badge` macro for diff status.

**Escaping (privacy/attack-surface — concilium should-consider):** this is the first panel
rendering fully attacker-controllable strings (cron commands, `Exec=`, key comments).
`name`/`source`/`details` MUST render as autoescaped text only — no `| safe`, no markup. §9
includes a test asserting a `<script>`/`onerror` payload in a cron command or key comment is
HTML-escaped.

## 8. PR breakdown

Two PRs (collector first, then projection+panel — the established split; the pure-Python
collector is a single PR):

- **PR6 — `persistence_snapshotter` collector**: the two-part Event-schema change (`Event`
  field + `build_event` kwarg), `source.py` (four enumerators incl. the cron 3-sub-parser and
  enabled-timer logic + per-source robustness), `__main__.py` (worker, empty-init + per-source
  diff, emitting `persistence_added`/`persistence_removed`), `dev_config` wiring. Unit tests
  over fixture files. No projection/panel yet.
- **PR7 — Persistence projection + baseline-diff + panel**: migration `0005`, projector
  branch, `capture_baseline` persistence branch, `handle_list_persistence` (with diff),
  Persistence web panel + nav, escaping test.

## 9. Testing (TDD throughout)

- **Enumerators** — fixture-file tests per kind: **cron** all three sub-parsers (system
  crontab schedule+user+command + `@`-shortcuts + `ENV=` skip; user crontab no-user-field;
  run-parts script dirs keyed by path); **timers** enabled-via-`*.wants`-symlink resolution,
  masked (`→/dev/null`) and template (`@`) units skipped, system vs user scope; **autostart**
  Name/Exec incl. malformed (no Exec → skip); **authorized_keys** plain + options-prefixed
  lines, multiple key types, blank/`#` lines, fingerprint format. **Parsing never raises** on
  garbage; **missing/unreadable source yields zero entries + is logged**, not an exception.
- **Snapshot diff** — added/removed deltas vs a previous snapshot; **first poll (empty init)
  emits all current as added**; **a source that errors one poll does NOT emit removals for its
  prior entries** (per-source carry-forward).
- **Projector** — `persistence_added` upsert (first_seen preserved on re-add),
  `persistence_removed` deletes; no-key no-op.
- **Baseline + IPC** — `capture_baseline('persistence')` count; `details` bound applied;
  `list_persistence` ordering; diff new/removed/unchanged.
- **Web** — shell renders, feed rows, diff badge, capture-baseline POST, empty state,
  daemon-unreachable, **and a `<script>`-payload-in-details escaping assertion**.

## 10. Out of scope (named deferrals)

These are conscious deferrals, not oversights (concilium should-consider #1):

- **Persistence detection rules** (`persistence.new_cron`, `new_systemd_user_timer`,
  `autostart_changed`, `authorized_keys_changed`) — do not exist yet; a named follow-up after
  the panel. **Until they ship, v1 is inventory + baseline-diff with no alerting.**
- **Other persistence vectors**: `/etc/ld.so.preload` + `/etc/ld.so.conf.d/*`,
  `~/.ssh/config` `ProxyCommand`/`LocalCommand`, `at`/`atd` jobs, systemd *generators*,
  `udev` rules, PAM modules, `/etc/rc.local`, init scripts. (Cheap high-value ones —
  `ld.so.preload`, ssh `ProxyCommand` — are the first candidates for a v2.)
- Systemd *service* unit persistence (covered by the Services panel); kernel modules (covered
  by `kmod_watcher`).
- Per-entry enable/disable sub-state; threat scoring; context cards; cross-user crontab
  reading requiring root.

**FIM-coverage correction:** `fim_watcher` uses *non-recursive* inotify (one watch per path),
so files inside `/etc` subdirectories (`/etc/cron.d/`, systemd unit dirs, `/etc/ld.so.conf.d/`,
`/etc/udev/rules.d/`, `/etc/pam.d/`) are **not** FIM-watched — this persistence inventory is
the *primary* signal for them. FIM *does* individually watch the shell dotfiles
(`.bashrc`/`.zshrc`/`.profile`) and `~/.config/autostart`, so rc-file *changes* remain
FIM-covered; rc-file *inventory* is intentionally not duplicated here.

## 11. Limitations (poll-snapshot inherent)

- **Poll-window blind spot**: a fast add-then-revert within one ~30 s poll interval is never
  observed (same class as sub-project 1's connection-liveness heuristic).
- **In-place edits show as new+removed, not modified**: editing an existing baselined cron
  line's command produces a `removed`(old hash) + `new`(new hash) pair, not a linked
  modification — the `new` row still surfaces via baseline-diff, but there is no per-entry
  "modified" status in v1.
- **Add+remove between baselines is panel-invisible**: a mechanism installed and removed
  entirely between two baseline captures leaves no durable `persistence_state` row (it was
  deleted on removal) and no baseline delta — only the raw event journal retains it. This is
  the cost of DELETE-on-removed; accepted for architectural consistency with listeners.
