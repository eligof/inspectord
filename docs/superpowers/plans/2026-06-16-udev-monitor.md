# Plan: `udev_monitor` collector (USB / device events)

Spec: `docs/superpowers/specs/2026-05-24-local-inspection-design.md` §5.1 (worker catalog),
§4.2 (`device.{name,kind,vendor,product,serial}`), §4.3 (`udev_parser`), §14.1 device entity id
`dev:<vendor:product:serial>`, §22.1 (both profiles).

## Design decision (settled with user)

**Approach (a): stream `udevadm monitor --property --udev` as a long-lived subprocess** and parse
its event blocks. Rejected: (b) periodic `/sys` snapshot+diff (misses transient plug/unplug — a
detection blind spot for BadUSB), (c) `pyudev` dependency (new supply-chain edge, against
minimal-attack-surface stance).

**Verified empirically on this host:** `udevadm monitor --udev` runs as uid 1000 with **no root and
no `CAP_NET_ADMIN`** — the libudev (`--udev`) broadcast socket is unprivileged. The spec's
`CAP_NET_ADMIN` note applies to the raw kernel netlink (`--kernel`), which we deliberately do not use.
This is the least-privilege win that motivates approach (a).

This is a **pure-Python collector → single PR** (per repo CLAUDE.md conventions). Mirror the
`services_monitor` worker shape (`source.py` + `__main__.py` + parser logic), but the source is a
**streaming subprocess** rather than a poll-snapshot+diff.

## Real output format (captured from `udevadm monitor --property --udev`)

Per event: a header line, then `KEY=VALUE` property lines, terminated by a **blank line**:

```
UDEV  [12345.678901] add      /devices/pci0000:00/.../usb1/1-1 (usb)
ACTION=add
DEVPATH=/devices/pci0000:00/.../usb1/1-1
SUBSYSTEM=usb
DEVTYPE=usb_device
PRODUCT=45e/800/944
BUSNUM=001
DEVNUM=002
ID_VENDOR_ID=045e
ID_MODEL_ID=0800
ID_VENDOR=Microsoft
ID_MODEL=Microsoft®_Nano_Transceiver_v2.0
ID_SERIAL_SHORT=...           # may be absent
<blank line>
```

`ACTION` ∈ `add | remove | change | bind | unbind | move`. Property keys vary by device; treat
**every field as untrusted attacker-controlled input** (USB descriptors are forgeable).

## Security safeguards (apply throughout)

- Spawn with **args as a list, `shell=False`** — never interpolate device strings into a shell.
- Default `--subsystem-match` filters to `usb`, `block`, `net` (privacy-first + low-noise + low-CPU;
  unfiltered udev is extremely chatty — input/drm/etc.). Configurable, but those are the defaults.
- Parse defensively: missing/garbage keys never raise; cap property-block size to avoid a hostile
  device wedging memory.
- Run unprivileged; a test asserts the command line uses `--udev` (not `--kernel`) and no `sudo`.
- Collector emits **normalized `device.*` events only** — threat indicators
  (`device.mass_storage_attached`, `device.new_network_interface`) are the rule_engine's job, not this
  worker's.

---

## Task 1 — `udev_parser` + streaming `UdevMonitorSource`

**Files:** `inspectord/workers/udev_monitor/__init__.py`, `inspectord/workers/udev_monitor/source.py`,
`tests/workers/test_udev_monitor_source.py`. **TDD.**

1. **`parse_event_block(lines: list[str]) -> dict | None`** — turn one property block (the lines
   between blank-line terminators, header line ignored or used only for the action fallback) into a
   record dict:
   - `action`: from `ACTION=` (required; return `None` if absent/empty).
   - `subsystem`, `devtype`, `devpath`: passthrough (default `""`).
   - `vendor`: `ID_VENDOR_ID` (fallback `ID_VENDOR`), `product`: `ID_MODEL_ID` (fallback `ID_MODEL`),
     `serial`: `ID_SERIAL_SHORT` (fallback `ID_SERIAL`) — all default `""`.
   - `name`: best human label — `ID_MODEL` or `ID_VENDOR` or `devpath` basename.
   - Keep the full raw key/value map under `properties` for the event `raw`.
   - Skip lines without `=`; only split on the **first** `=`.
2. **`UdevMonitorSource`** — streaming source with the same duck-typed interface the worker expects:
   `poll(timeout_ms: int) -> list[dict]` and `close() -> None`.
   - `__init__(*, spawn: Callable[[], Popen-like] = _default_spawn, subsystems=("usb","block","net"))`.
     `_default_spawn` runs `udevadm monitor --property --udev` + one `--subsystem-match=<s>` per
     subsystem, `shell=False`, `text=True`, line-buffered stdout, stderr to DEVNULL. The `spawn`
     injection lets tests feed a fake process with a canned `stdout` file-like — **no real udevadm,
     no privileges needed in tests**.
   - `poll`: use `select.select([stdout], [], [], timeout_ms/1000)`; drain available lines, buffering
     a partial block across calls; emit one record per **completed** block (blank-line terminated);
     return `[]` on timeout with no complete block.
   - **Subprocess death:** detect EOF / process exit in `poll` → raise `RuntimeError` so the worker
     exits non-zero and the **supervisor restarts** it (spec failure mode = "Restart"; no baseline to
     lose since this is a pure event stream).
   - `close()`: terminate the subprocess (idempotent), best-effort `terminate()` then `kill()`.

**Tests:** block parsing (add/remove/change; missing serial; missing ACTION → None; non-`=` lines;
forged/garbage values don't raise; first-`=`-only split); source emits records from a fed fake
stdout; partial block spanning two polls; timeout → `[]`; EOF → `RuntimeError`; `close()` idempotent;
`_default_spawn` builds a `--udev` (not `--kernel`) argv with `--subsystem-match` and `shell=False`.

## Task 2 — `UdevMonitorWorker` (`__main__.py`) + dev_config wiring

**Files:** `inspectord/workers/udev_monitor/__main__.py`, `tests/workers/test_udev_monitor_worker.py`,
`inspectord/config.py` (dev_config entry), `tests/test_dev_config_udev_monitor.py`. **TDD.**

1. **`UdevMonitorWorker`** mirroring `ServicesMonitorWorker` (stream_factory + sink injection,
   `start`/`step`/`stop`). `step` calls `stream.poll(timeout_ms)` and writes one NDJSON Event per
   record via `_record_to_event`.
2. **`_record_to_event`** → `build_event(module="udev_monitor", ...)`:
   - `device={"name","kind","vendor","product","serial"}` where `kind` = `devtype or subsystem`.
   - action map: `add`→`device_added`/`type_=["installation"]`; `remove`→`device_removed`/
     `["deletion"]`; `bind`/`unbind`/`change`/`move`→`device_changed`/`["change"]`.
   - `category=["host"]` (device events; mirror services_monitor's pattern), `severity="info"`,
     `labels=["device"]`, `host={"name": hostname}`, `message` a one-line human summary
     (e.g. `usb device added: Microsoft 045e:0800 at 1-1`), `raw={"source":"udevadm", **properties}`.
3. **`main(argv)`** with `--sink-path` (default `-`) and `--poll-timeout-ms` (default e.g. 1000 —
   streaming, so poll often for low latency). Mirror services_monitor's `_open_sink` + loop.
4. **dev_config:** add `{"name":"udev_monitor","module":"inspectord.workers.udev_monitor","config":{}}`
   to the `workers` list in `dev_config`.

**Tests:** each action maps to the right `event.action`/`type`/`device.*`; missing fields tolerated;
NDJSON written + flushed to an injected sink; `worker not started` guard; dev_config contains a
`udev_monitor` entry with the right module (mirror `test_dev_config_services_monitor.py`).

---

## Gates before PR (from CLAUDE.md)

`.venv/bin/python -m pytest -m "not integration and not ebpf_load"` ·
`.venv/bin/ruff check inspectord tests` · `.venv/bin/ruff format --check inspectord tests` ·
`.venv/bin/mypy inspectord`. Then branch → push → `gh pr create` → wait for `lint-and-test` + CodeQL
+ cargo-audit + dependency-review green → `gh pr merge --squash --delete-branch`.
