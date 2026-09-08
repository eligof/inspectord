"""inspectord entry point.

Usage:
  inspectord --dev                          # dev mode: paths under ./var/
  inspectord --config /etc/inspectord/config.toml
"""

from __future__ import annotations

import argparse
import json as _json
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Any

from inspectord.alerts.ipc_handlers import (
    handle_ack_alert,
    handle_get_alert,
    handle_list_alerts,
    handle_resolve_alert,
    handle_suppress_alert,
)
from inspectord.audit.ipc_handlers import handle_list_audit_log, handle_verify_audit_log
from inspectord.audit.log import append_audit, assert_audit_table
from inspectord.authz import AuthzResult, PeerIdentity, check_polkit
from inspectord.cases.ipc_handlers import (
    handle_add_note,
    handle_attach_alert,
    handle_close_case,
    handle_download_evidence,
    handle_export_case_zip,
    handle_get_case,
    handle_list_cases,
    handle_open_case,
)
from inspectord.config import DaemonConfig, dev_config, load
from inspectord.dependencies.ipc_handlers import (
    handle_apply_dependency_plan,
    handle_get_dep_audit,
    handle_list_dependencies,
    handle_plan_dependency_install,
)
from inspectord.dependencies.manifest import load_packaged_manifests
from inspectord.dependencies.pacman_backend import PacmanBackend
from inspectord.entities.ipc_handlers import handle_get_entity_card
from inspectord.evidence.store import ForensicStore
from inspectord.hunt.ipc_handlers import (
    handle_delete_hunt_query,
    handle_get_hunt_query,
    handle_list_hunt_queries,
    handle_run_hunt_query,
    handle_save_hunt_query,
    handle_schedule_hunt_query,
    handle_unschedule_hunt_query,
)
from inspectord.ipc_commands import make_run_worker_command_handler
from inspectord.ipc_server import IpcServer, Method
from inspectord.log import configure as configure_log
from inspectord.log import get
from inspectord.quarantine.ipc_handlers import (
    handle_delete_quarantined,
    handle_list_quarantine,
    handle_quarantine_file,
    handle_restore_quarantined,
)
from inspectord.quarantine.paths import QuarantinePaths
from inspectord.ratelimit import SlidingWindowLimiter
from inspectord.state.ipc_handlers import (
    handle_capture_baseline,
    handle_list_connections,
    handle_list_devices,
    handle_list_file_changes,
    handle_list_listeners,
    handle_list_persistence,
    handle_list_processes,
    handle_list_scan_findings,
    handle_list_scan_runs,
    handle_list_services,
)
from inspectord.storage.db import Database
from inspectord.supervisor import Supervisor
from inspectord.vuln.ipc_handlers import (
    handle_ack_vulnerability,
    handle_list_vulnerabilities,
)

log = get("inspectord")


def _list_events_handler(params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    since_id = params.get("since_id")
    module = params.get("module")
    limit = int(params.get("limit", 100))
    where = "WHERE 1=1"
    args: list[Any] = []
    if since_id:
        where += " AND event_id > ?"
        args.append(str(since_id))
    if module:
        where += " AND module = ?"
        args.append(str(module))
    with Database(db_path) as db:
        rows = db.query(
            "SELECT event_id, ts, kind, module, action, severity, payload_json "
            f"FROM events_enriched {where} ORDER BY event_id ASC LIMIT ?",
            [*args, limit],
        ).fetchall()
    return {
        "schema_version": "1.0.0",
        "events": [
            {
                "event_id": r[0],
                "ts": r[1].isoformat() if r[1] else None,
                "kind": r[2],
                "module": r[3],
                "action": r[4],
                "severity": r[5],
                **_json.loads(r[6]),
            }
            for r in rows
        ],
    }


def _authz_check(action_id: str, peer: PeerIdentity, target: str | None) -> AuthzResult:
    """`check_polkit` adapted to the server's positional gate signature."""
    return check_polkit(action_id, peer, target=target)


def _make_ipc_audit(db_path: Path) -> Any:
    """Audit sink for the server's denial rows (quarantine design §2.3).

    The server passes action/target/details; the actor is the peer's uid:pid
    identity, which rides in the details the server already assembled.
    """

    def _audit(*, action: str, target: str | None, details: dict[str, Any]) -> None:
        actor = f"uid:{details.get('peer_uid')}:pid:{details.get('peer_pid')}"
        append_audit(db_path, actor=actor, action=action, target=target, details=details)

    return _audit


def _polkit_target_path(params: dict[str, Any]) -> str | None:
    """`pkcheck --detail path` extractor for quarantine_file (§2.2)."""
    value = params.get("path")
    return value if isinstance(value, str) else None


def _ipc_methods(
    supervisor: Supervisor, cfg: DaemonConfig, *, config_path: Path | None = None
) -> list[Method]:
    def get_health(_params: dict[str, Any]) -> dict[str, Any]:
        # Hunt-scheduler liveness (hunt-followups §4.1): a dead scheduler
        # thread must be visible without reading logs — silent stop of
        # standing detections is the #127 incident shape one layer up.
        scheduler = getattr(supervisor, "_hunt_scheduler", None)
        last_tick = scheduler.last_tick_at if scheduler is not None else None
        return {
            "schema_version": "1.0.0",
            "supervisor": "running",
            "workers": [{"name": w.name, "status": "up"} for w in cfg.workers],
            "hunt_scheduler": {
                "alive": scheduler is not None and scheduler.is_alive(),
                "last_tick_at": last_tick.isoformat() if last_tick is not None else None,
            },
        }

    manifests = load_packaged_manifests()
    backend = PacmanBackend()
    # ONE sliding window across all four mutating hunt methods (hunt-followups
    # §4.6): each writes an audit row, and attacker-drivable append-only audit
    # growth is what the limiter bounds.
    hunt_limiter = SlidingWindowLimiter()

    # Quarantine (quarantine design §4). Per-verb windows: one shared window
    # would let a denied-quarantine flood lock the user out of `restore`
    # mid-incident — restore's availability is a security property.
    quarantine_limiter = SlidingWindowLimiter()
    restore_delete_limiter = SlidingWindowLimiter()
    quarantine_store = ForensicStore(cfg.storage.evidence_dir)
    quarantine_paths = QuarantinePaths(
        state_dir=cfg.storage.db_path.parent,
        socket_dir=cfg.ipc.socket_path.parent,
        config_path=config_path,
    )

    def _capture_lock() -> threading.Lock:
        # Resolved at call time: the supervisor owns the EvidenceCollector,
        # which exists only after start() (spec §3.2 — the lock serializes
        # captures against the retention pruner).
        collector = getattr(supervisor, "_evidence_collector", None)
        if collector is None:
            raise RuntimeError("evidence collector is not running; cannot quarantine")
        lock: threading.Lock = collector.capture_lock
        return lock

    return [
        Method(name="get_health", handler=get_health, mutates=False),
        Method(
            name="list_dependencies",
            handler=lambda params: handle_list_dependencies(
                params=params,
                manifests=manifests,
                backend=backend,
                db_path=cfg.storage.db_path,
            ),
            mutates=False,
        ),
        Method(
            name="plan_dependency_install",
            handler=lambda params: handle_plan_dependency_install(
                params=params,
                manifests=manifests,
                backend=backend,
                db_path=cfg.storage.db_path,
            ),
            mutates=True,
        ),
        Method(
            name="get_dep_audit",
            handler=lambda params: handle_get_dep_audit(
                params=params,
                db_path=cfg.storage.db_path,
            ),
            mutates=False,
        ),
        Method(
            name="apply_dependency_plan",
            handler=lambda params: handle_apply_dependency_plan(
                params=params,
                manifests=manifests,
                backend=backend,
                runner=backend._runner,
                db_path=cfg.storage.db_path,
                sidecar_dirs=None,
                chown=True,
            ),
            mutates=True,
        ),
        Method(
            name="list_events",
            handler=lambda params: _list_events_handler(params, cfg.storage.db_path),
            mutates=False,
        ),
        Method(
            name="list_alerts",
            handler=lambda params: handle_list_alerts(params=params, db_path=cfg.storage.db_path),
            mutates=False,
        ),
        Method(
            name="get_alert",
            handler=lambda params: handle_get_alert(params=params, db_path=cfg.storage.db_path),
            mutates=False,
        ),
        Method(
            name="ack_alert",
            handler=lambda params: handle_ack_alert(params=params, db_path=cfg.storage.db_path),
            mutates=True,
        ),
        Method(
            name="resolve_alert",
            handler=lambda params: handle_resolve_alert(params=params, db_path=cfg.storage.db_path),
            mutates=True,
        ),
        Method(
            name="suppress_alert",
            handler=lambda params: handle_suppress_alert(
                params=params, db_path=cfg.storage.db_path
            ),
            mutates=True,
        ),
        Method(
            name="list_services",
            handler=lambda params: handle_list_services(params=params, db_path=cfg.storage.db_path),
            mutates=False,
        ),
        Method(
            name="list_devices",
            handler=lambda params: handle_list_devices(params=params, db_path=cfg.storage.db_path),
            mutates=False,
        ),
        Method(
            name="list_processes",
            handler=lambda params: handle_list_processes(
                params=params, db_path=cfg.storage.db_path
            ),
            mutates=False,
        ),
        Method(
            name="list_connections",
            handler=lambda params: handle_list_connections(
                params=params, db_path=cfg.storage.db_path
            ),
            mutates=False,
        ),
        Method(
            name="list_listeners",
            handler=lambda params: handle_list_listeners(
                params=params, db_path=cfg.storage.db_path
            ),
            mutates=False,
        ),
        Method(
            name="list_file_changes",
            handler=lambda params: handle_list_file_changes(
                params=params, db_path=cfg.storage.db_path
            ),
            mutates=False,
        ),
        Method(
            name="list_persistence",
            handler=lambda params: handle_list_persistence(
                params=params, db_path=cfg.storage.db_path
            ),
            mutates=False,
        ),
        Method(
            name="list_scan_runs",
            handler=lambda params: handle_list_scan_runs(
                params=params, db_path=cfg.storage.db_path
            ),
            mutates=False,
        ),
        Method(
            name="list_scan_findings",
            handler=lambda params: handle_list_scan_findings(
                params=params, db_path=cfg.storage.db_path
            ),
            mutates=False,
        ),
        Method(
            name="capture_baseline",
            handler=lambda params: handle_capture_baseline(
                params=params, db_path=cfg.storage.db_path
            ),
            mutates=True,
        ),
        Method(
            name="get_entity_card",
            handler=lambda params: handle_get_entity_card(
                params=params, db_path=cfg.storage.db_path
            ),
            mutates=False,
        ),
        Method(
            name="open_case",
            handler=lambda params: handle_open_case(params=params, db_path=cfg.storage.db_path),
            mutates=True,
        ),
        Method(
            name="attach_alert",
            handler=lambda params: handle_attach_alert(params=params, db_path=cfg.storage.db_path),
            mutates=True,
        ),
        Method(
            name="add_note",
            handler=lambda params: handle_add_note(params=params, db_path=cfg.storage.db_path),
            mutates=True,
        ),
        Method(
            name="close_case",
            handler=lambda params: handle_close_case(params=params, db_path=cfg.storage.db_path),
            mutates=True,
        ),
        Method(
            name="list_cases",
            handler=lambda params: handle_list_cases(params=params, db_path=cfg.storage.db_path),
            mutates=False,
        ),
        Method(
            name="get_case",
            handler=lambda params: handle_get_case(params=params, db_path=cfg.storage.db_path),
            mutates=False,
        ),
        # export/download are user-initiated reads; mutates=False is deliberate (spec §2.2) so a
        # future polkit gate does not prompt on every download. They DO append a custody
        # case_event as an internal side-effect — that write must never require authorization.
        Method(
            name="export_case_zip",
            handler=lambda params: handle_export_case_zip(
                params=params,
                db_path=cfg.storage.db_path,
                evidence_dir=cfg.storage.evidence_dir,
            ),
            mutates=False,
        ),
        Method(
            name="download_evidence",
            handler=lambda params: handle_download_evidence(
                params=params,
                db_path=cfg.storage.db_path,
                evidence_dir=cfg.storage.evidence_dir,
            ),
            mutates=False,
        ),
        # Hunt (hunt design §8). Running a query is `mutates=False` and must stay
        # that way: Hunt is read-only by construction (§10) — the only statement
        # run_hunt_query executes is the compiled SELECT — and a permission
        # prompt on the most frequent action in an investigation would be both
        # unauthorizable and intolerable. Saving and deleting are the opposite:
        # they write durable, named state that another caller later runs, and a
        # save with `replace` destroys the previous query.
        Method(
            name="run_hunt_query",
            handler=lambda params: handle_run_hunt_query(
                params=params, db_path=cfg.storage.db_path
            ),
            mutates=False,
        ),
        Method(
            name="list_hunt_queries",
            handler=lambda params: handle_list_hunt_queries(
                params=params, db_path=cfg.storage.db_path
            ),
            mutates=False,
        ),
        Method(
            name="get_hunt_query",
            handler=lambda params: handle_get_hunt_query(
                params=params, db_path=cfg.storage.db_path
            ),
            mutates=False,
        ),
        Method(
            name="save_hunt_query",
            handler=lambda params: handle_save_hunt_query(
                params=params, db_path=cfg.storage.db_path, limiter=hunt_limiter
            ),
            mutates=True,
        ),
        Method(
            name="delete_hunt_query",
            handler=lambda params: handle_delete_hunt_query(
                params=params, db_path=cfg.storage.db_path, limiter=hunt_limiter
            ),
            mutates=True,
        ),
        # Scheduled hunts (hunt-followups design §4.6): scheduling creates and
        # unscheduling destroys a standing alert-generating detection — the
        # same class of act as ack/close, so both mutate and both audit.
        Method(
            name="schedule_hunt_query",
            handler=lambda params: handle_schedule_hunt_query(
                params=params, db_path=cfg.storage.db_path, limiter=hunt_limiter
            ),
            mutates=True,
        ),
        Method(
            name="unschedule_hunt_query",
            handler=lambda params: handle_unschedule_hunt_query(
                params=params, db_path=cfg.storage.db_path, limiter=hunt_limiter
            ),
            mutates=True,
        ),
        # Audit log (audit design §7). Both are read-only views over audit_log;
        # the audit rows themselves are only ever written by append_audit inside
        # the mutating handlers above.
        Method(
            name="list_audit_log",
            handler=lambda params: handle_list_audit_log(
                params=params, db_path=cfg.storage.db_path
            ),
            mutates=False,
        ),
        Method(
            name="verify_audit_log",
            handler=lambda params: handle_verify_audit_log(
                params=params, db_path=cfg.storage.db_path
            ),
            mutates=False,
        ),
        # Vulnerabilities (vuln-scanner design §7).
        Method(
            name="list_vulnerabilities",
            handler=lambda params: handle_list_vulnerabilities(
                params=params, db_path=cfg.storage.db_path
            ),
            mutates=False,
        ),
        Method(
            name="ack_vulnerability",
            handler=lambda params: handle_ack_vulnerability(
                params=params, db_path=cfg.storage.db_path
            ),
            mutates=True,
        ),
        # Worker command channel (worker-command-channel design §6): audited,
        # allowlisted, rate-limited trigger path into the running workers. The
        # supervisor reference is bound lazily inside the handler.
        Method(
            name="run_worker_command",
            handler=make_run_worker_command_handler(
                supervisor=supervisor, db_path=cfg.storage.db_path
            ),
            mutates=True,
        ),
        # Quarantine (quarantine design §4): the three mutating verbs are
        # polkit-gated server-side; list is a read like every other list_*.
        Method(
            name="quarantine_file",
            handler=lambda params: handle_quarantine_file(
                params=params,
                db_path=cfg.storage.db_path,
                store=quarantine_store,
                lock=_capture_lock(),
                paths=quarantine_paths,
            ),
            mutates=True,
            polkit_action="org.inspectord.quarantine",
            limiter=quarantine_limiter,
            polkit_target=_polkit_target_path,
        ),
        Method(
            name="list_quarantine",
            handler=lambda params: handle_list_quarantine(
                params=params, db_path=cfg.storage.db_path, store=quarantine_store
            ),
            mutates=False,
        ),
        Method(
            name="restore_quarantined",
            handler=lambda params: handle_restore_quarantined(
                params=params,
                db_path=cfg.storage.db_path,
                store=quarantine_store,
                paths=quarantine_paths,
            ),
            mutates=True,
            polkit_action="org.inspectord.quarantine-restore",
            limiter=restore_delete_limiter,
        ),
        Method(
            name="delete_quarantined",
            handler=lambda params: handle_delete_quarantined(
                params=params,
                db_path=cfg.storage.db_path,
                store=quarantine_store,
                lock=_capture_lock(),
            ),
            mutates=True,
            polkit_action="org.inspectord.quarantine-delete",
            limiter=restore_delete_limiter,
        ),
    ]


def main() -> None:
    parser = argparse.ArgumentParser(prog="inspectord")
    parser.add_argument("--dev", action="store_true", help="dev paths under ./var/")
    parser.add_argument("--config", type=Path, default=None)
    args = parser.parse_args()

    configure_log()

    if args.dev:
        cfg = dev_config(base=Path.cwd())
    elif args.config is not None:
        cfg = load(args.config)
    else:
        print("inspectord: pass --dev or --config <path>", file=sys.stderr)
        sys.exit(2)

    sup = Supervisor(cfg)
    sup.start()
    # Startup probe (spec §6): run_migrations (inside sup.start()) must have
    # left audit_log in place — a missing table would otherwise be silently
    # swallowed by every fail-open append for the daemon's whole lifetime.
    try:
        assert_audit_table(cfg.storage.db_path)
    except Exception:
        sup.stop(timeout=5.0)
        raise

    ipc = IpcServer(
        socket_path=cfg.ipc.socket_path,
        methods=_ipc_methods(sup, cfg, config_path=args.config),
        allowed_uids=cfg.ipc.allowed_uids,
        socket_group=cfg.ipc.socket_group,
        authz_check=_authz_check,
        audit=_make_ipc_audit(cfg.storage.db_path),
    )
    ipc.start()
    log.info("inspectord ready; socket=%s", cfg.ipc.socket_path)

    stop = threading.Event()

    def _shutdown(*_: object) -> None:
        log.info("inspectord shutting down")
        stop.set()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    try:
        while not stop.is_set():
            time.sleep(0.2)
    finally:
        ipc.stop()
        sup.stop(timeout=5.0)
    log.info("inspectord exited cleanly")


if __name__ == "__main__":
    main()
