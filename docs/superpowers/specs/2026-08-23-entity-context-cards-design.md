# Entity context cards — design

Date: 2026-08-23
Parent spec: `2026-05-24-local-inspection-design.md` §14 (entity-centric navigation).
Status: **autonomously drafted, NOT human-reviewed.** Drafted during an autonomous session;
the scope cuts in §2 and the page-instead-of-modal deviation in §5 are the decisions most
worth a human sanity-check.

## 1. Goal

Clicking any subject anywhere in the dashboard answers "what do we know about this thing?"
in one place: a unified view of an entity (process, IP, service, file, …) aggregating its
identity, recent events across every collector, alerts that reference it, and related
entities — each related entity itself a link, so the user can pivot laterally (process →
IP it talked to → every other process that talked to that IP).

This is the last unshipped Phase-2 item in parent §31.

## 2. Scope

### In (v1)

- 8 entity kinds, all backed by data that already exists in DuckDB (§3).
- A read-only card: header, recent events, alerts, related entities (§4).
- One new read-only IPC method `get_entity_card` (§6).
- A web page per entity + links to it from the existing panel templates (§5).

### Out (deliberate, v1)

| Cut | Why |
| --- | --- |
| `domain` and `package` kinds | No collector currently records domains; packages already have the Dependencies panel. Add when data exists. |
| Pending actions on the card (§14.2 item 5) | Pending Actions is Phase 4; no action framework exists. |
| Quick-allowlist (§14.2 item 6) | Mutating operation → needs the polkit story; every existing panel action is read-only or case-scoped. Separate slice. |
| Threat-intel matches in the header | `intel_updater` is Phase 4. |
| Geo/ASN for IPs | Already on the deferred list; needs the GeoLite2 downloader (egress decision). |
| Modal + `<span data-entity-...>` markup in every renderer (§14.3) | v1 uses a dedicated page + ordinary `<a>` links (§5). The IPC contract is identical, so a modal can be layered on later without daemon changes. |
| `inspectorctl entity show` CLI (parent §24) | Web + IPC first; the CLI is a thin client over the same method and can follow. |

## 3. Entity kinds and keys (v1)

Key formats follow parent §14.1. The `key` given to the IPC method is the part after the
`kind:` prefix (the prefix is redundant with the `kind` parameter).

| Kind | Key | Primary source | Exists check |
| --- | --- | --- | --- |
| `process` | `<pid>@<boot_id>` | `process_state` (pid, boot_id) | row |
| `executable` | `<sha256>` | `process_state.exe_sha256` | any row |
| `user` | `<username>` | events payload; uid resolved via `pwd.getpwnam` (best-effort) | any event/process match |
| `ip` | `<address>` | `connection_state.daddr` (+ `saddr` for completeness) | any row |
| `file` | `<absolute_path>` | `file_state.path` | row |
| `port` | `<addr>:<port>/<proto>` | `listener_state` (addr, port, proto) | row |
| `service` | `<unit_name>` | `service_state.unit` | row |
| `device` | `<dev_key>` | `device_state.dev_key` | row |

Parent §14.1 writes process keys as `pid:<pid>@boot:<boot_id>` and files as
`file:<sha256>` *or* path. v1 normalizes: process key is `<pid>@<boot_id>`; file cards are
keyed **by path only** (that is `file_state`'s primary key; a sha-keyed file card would
mostly duplicate `executable`). `port` gains a `/<proto>` suffix because
`listener_state`'s primary key is (addr, port, proto).

An unknown `kind` is an error. A syntactically valid key with no data returns a card with
`found: false` plus whatever event/alert matches exist — never an exception (a card for an
entity we've stopped tracking must still show its history).

## 4. Card content

Returned as one JSON object; all four sections computed in a single IPC call.

1. **Header** — kind, key, and per-kind identity fields from the state row (comm, cmdline,
   exe path/sha, uid for processes; vendor/product/serial for devices; sha/size/mode for
   files; …), plus `first_seen`, `last_seen`, `status` where the state table has them, and
   `found`.
2. **Recent events** — from `events_enriched`, default window 24 h, newest first, hard cap
   100 rows. Matching is per-kind on `payload_json` (§6). Each item: ts, module, action,
   severity, event_id, and a one-line summary rendered web-side from the payload.
3. **Alerts** — rows from `alerts` whose payload references the entity, newest first, cap
   50, any status (an acked alert is still history). Each item: alert_id, rule_id, ts,
   severity, status, rendered_short — alert_id links to the existing alert detail page.
4. **Related entities** — a list of `{kind, key, label, relation}` items, each rendered as
   a link to that entity's card:
   - `process` → parent (`ppid@boot`), children (`process_state.ppid = pid`, same boot),
     its `executable` (exe_sha256), outbound `ip`s (`connection_state.pid`), `port`s it
     listens on (`listener_state.pid`), its `user` (uid → name best-effort). Caps: 20
     children, 20 IPs.
   - `executable` → every `process` with that `exe_sha256` (cap 50).
   - `user` → `process`es with the resolved uid (cap 50).
   - `ip` → every `process` that talked to it (distinct pids in `connection_state` where
     `daddr` = key, cap 50).
   - `file` → an `executable` card if some process's `exe_path` equals the path.
   - `port` → the owning `process` (listener pid, resolved to pid@current-boot).
   - `service` → none in v1 (`service_state` stores no MainPID).
   - `device` → none in v1.

Boot-scoping: pid-based joins (children, connections → process links) are only meaningful
within one boot. `connection_state` and `listener_state` carry no boot_id; their pid joins
assume the **current boot** (`inspectord.state.reconcile.current_boot_id`) — a stale-pid
mismatch shows a wrong-but-clickable link whose own card immediately reveals the mismatch.
Accepted v1 limitation, noted in the module docstring.

## 5. Web surface

- `GET /entity/{kind}?key=<url-encoded key>` — server-rendered page (shell + no feed
  split: a card is a one-shot lookup, not a live feed). Template `entity.html`, one
  section per §4 block, autoescaped throughout (house XSS standard; keys and payload
  fields are attacker-influenced — a comm or filename can contain markup).
- The key travels as a **query parameter**, not a path segment: file paths contain `/`
  and device keys contain `:`, and encoded-slash path segments are dropped or rejected by
  proxies and routers. `request.query_params` round-trips them exactly.
- Existing panel templates get ordinary links on the cells that name an entity:
  processes feed (pid, exe sha), network feed (daddr, pid), services feed (unit), devices
  feed (dev_key), file-integrity feed (path), listeners in the network panel (port),
  alert detail (any entity fields present in its payload — v1: pid, daddr, path, unit
  when the payload carries them).
- Unknown kind → 404. Daemon unreachable → the existing `error` banner pattern.

## 6. Daemon side

New module `inspectord/entities/card.py`:

- `build_entity_card(db, *, kind, key, now, window_h=24) -> dict` — pure function over an
  open `Database`; one branch per kind, each returning the four §4 sections.
- Per-kind event matching on `events_enriched.payload_json` with DuckDB JSON functions
  (`json_extract_string`), always parameterized, always bounded by
  `ts >= now - window_h` (hits the existing ts index) and `LIMIT`:
  Payload field names below are the canonical ones the projector already reads
  (`inspectord/state/projector.py`) — implementers must not invent new ones:
  - process → `process.pid` = pid (string-compare on the extracted value); v1
    simplification: pid match + window only, no boot-range intersection.
  - ip → `destination.ip` = key OR `source.ip` = key.
  - file → `file.path` = key.
  - service → `service.name` = key.
  - user → `user.name` = key OR `user.id` = str(uid).
  - device → `raw.DEVPATH` = key OR `device.name` = key (that is how the projector
    builds `dev_key`; parent §14.1's `vendor:product:serial` key format was never what
    shipped in `device_state` — the card follows the table, not §14.1).
  - port → v1: listener state only, no event scan (port-scoped event queries would need
    source-address interpretation — defer).
  - executable → `process.hash.sha256` = key (the enrichment layer's field; the path
    lives in `process.executable`).

Pre-existing gap fixed in PR1: `process_state.exe_path` / `exe_sha256` columns exist
since migration 0004 but `_project_process` never writes them, so they are NULL for every
row. The projector's process_start upsert gains both fields (from `process.executable`
and `process.hash.sha256`) — without this the executable card's related-process list
would always be empty.
  - Alert matching: same predicates against `alerts.payload_json`.
- Key validation before any query: length ≤ 512, no control characters; kind must be in
  the fixed set. Invalid → `{"ok": False, "error": "invalid_kind" | "invalid_key"}`.

IPC: `get_entity_card` in `inspectord/entities/ipc_handlers.py`, registered in
`__main__.py`, `mutates=False`, params `{kind, key, window_h?}`. Opens its own
`Database(db_path)` per call like every other read handler. Response
`{schema_version, ok, card}` or the standard error shape.

## 7. Error handling

- Every per-section query is independently guarded: a failure in one section (e.g. a
  malformed payload_json row) degrades that section to `[]` plus a `warnings` entry on
  the card, never a failed card. Rationale: the card is an investigation tool; partial
  data with an honest warning beats a 502 mid-investigation.
- `pwd.getpwnam`/`getpwuid` failures (deleted user) → uid/name shown unresolved.

## 8. Testing

TDD, house gates. Unit tests per kind against a seeded tmp DuckDB (`run_migrations` +
handcrafted rows): found/not-found, event matching in/out of window, caps enforced,
related-entity links, key validation, the degraded-section path (inject a bad payload
row). IPC handler test (shape, mutates=False registration). Web tests: route renders,
404 on bad kind, XSS attempt in comm/path renders escaped, links present in panel feeds.

## 9. Delivery

Two PRs (house pattern — daemon first, web second):

1. **PR1**: `inspectord/entities/` (card builder + IPC handler) + registration + tests.
2. **PR2**: web route + `entity.html` + panel-template links + tests.
