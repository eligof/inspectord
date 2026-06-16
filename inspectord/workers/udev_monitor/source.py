"""udev_monitor source — streams and parses udevadm device hotplug events.

Spawns ``udevadm monitor --property --udev`` as a long-lived subprocess and
parses its event blocks into change records.  The ``--udev`` flag uses the
libudev broadcast socket, so this runs fully UNPRIVILEGED (no root, no
CAP_NET_ADMIN) — unlike ``--kernel``, which is deliberately never used.

Every field arrives from device descriptors and must be treated as untrusted,
attacker-controlled input (USB descriptors are forgeable): parsing never raises
on garbage.  Tests inject a fake ``spawn`` callable so no real ``udevadm``
invocation or special privileges are needed at test time.
"""

from __future__ import annotations

import codecs
import os
import select
import subprocess
from collections.abc import Callable
from typing import IO, Any

# Cap an in-progress (unterminated) block so a hostile device emitting an
# endless property stream can't wedge memory.  A real udev event is well under
# a hundred lines; this is a generous ceiling.
_MAX_BLOCK_LINES = 500

# Cap the trailing partial-line buffer so a hostile device emitting megabytes
# with NO newline can't grow memory without limit (``split("\n")`` would yield
# no complete lines, so the block-line cap above would never trip).  1 MiB is
# far beyond any legitimate udev property line.
_MAX_LINEBUF_CHARS = 1 << 20


def parse_event_block(lines: list[str]) -> dict[str, Any] | None:
    """Parse one udev event block into a record dict, or ``None`` if unclassifiable.

    *lines* are the raw lines of a single event block: optionally the header
    line followed by ``KEY=VALUE`` property lines.  The terminating blank line
    must NOT be included.

    Each property line is split on the FIRST ``=`` only (values may contain
    ``=``).  Lines without ``=`` (e.g. the header) and whitespace-only lines are
    skipped.  Returns ``None`` when ``ACTION`` is absent or empty — without it
    the event cannot be classified.
    """
    props: dict[str, str] = {}
    for line in lines:
        if not line or not line.strip():
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        if not key:
            continue
        props[key] = value

    action = props.get("ACTION", "")
    if not action:
        return None

    devpath = props.get("DEVPATH", "")
    vendor = props.get("ID_VENDOR_ID") or props.get("ID_VENDOR") or ""
    product = props.get("ID_MODEL_ID") or props.get("ID_MODEL") or ""
    serial = props.get("ID_SERIAL_SHORT") or props.get("ID_SERIAL") or ""

    name = (
        props.get("ID_MODEL")
        or props.get("ID_VENDOR")
        or (os.path.basename(devpath) if devpath else "")
        or ""
    )

    return {
        "action": action,
        "subsystem": props.get("SUBSYSTEM", ""),
        "devtype": props.get("DEVTYPE", ""),
        "devpath": devpath,
        "vendor": vendor,
        "product": product,
        "serial": serial,
        "name": name,
        "properties": props,
    }


def _default_spawn() -> subprocess.Popen[str]:
    """Spawn ``udevadm monitor --property --udev`` for the default subsystems.

    Uses ``shell=False`` (argv list) and the unprivileged ``--udev`` broadcast
    socket; never ``--kernel`` and never ``sudo``.
    """
    subsystems = ("usb", "block", "net")
    argv = ["udevadm", "monitor", "--property", "--udev"]
    for sub in subsystems:
        argv.append(f"--subsystem-match={sub}")
    return subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1,
    )


class UdevMonitorSource:
    """Streams udev hotplug events from a long-lived ``udevadm monitor`` process.

    Duck-typed to the worker interface: ``poll(timeout_ms)`` returns the records
    completed this call (``[]`` on timeout), and ``close()`` tears down the
    subprocess.  A partial (not-yet-terminated) event block persists across
    ``poll`` calls.

    Inject *spawn* to avoid a real subprocess in tests; it must return a
    Popen-like object exposing ``.stdout`` (a readable text file), ``.poll()``,
    ``.terminate()``, and ``.kill()``.
    """

    def __init__(
        self,
        *,
        spawn: Callable[[], Any] = _default_spawn,
    ) -> None:
        self._proc = spawn()
        if self._proc.stdout is None:
            raise RuntimeError("udevadm monitor produced no stdout pipe")
        self._stdout: IO[str] = self._proc.stdout
        self._fd = self._stdout.fileno()
        self._block: list[str] = []
        # Text not yet split into complete lines (the trailing partial line).
        self._linebuf = ""
        # Incremental UTF-8 decoder: reassembles multibyte sequences that
        # straddle ``os.read`` chunk boundaries while keeping ``replace``
        # semantics for genuine non-UTF-8 garbage.
        self._decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self._closed = False

    def poll(self, timeout_ms: int) -> list[dict[str, Any]]:
        """Wait up to *timeout_ms* for events; return records completed this call.

        Reads any available lines, accumulating into the in-progress block; a
        blank line terminates a block, which is parsed and (if classifiable)
        appended to the result.  Returns ``[]`` when nothing readable arrives
        within the timeout.

        Raises:
            RuntimeError: if the source is closed, or the subprocess has exited
                / its stdout reached EOF (the supervisor restarts the worker).
        """
        if self._closed:
            raise RuntimeError("udev_monitor source is closed")

        try:
            readable, _, _ = select.select([self._fd], [], [], timeout_ms / 1000)
        except (ValueError, OSError) as exc:
            # stdout closed out from under us → treat as process death.
            raise RuntimeError("udevadm monitor exited") from exc

        if not readable:
            return []

        # Read all currently-available bytes at the OS level.  After select
        # reports readable, an empty read means real EOF (the process closed
        # stdout) — distinct from "no data yet", which would have timed out
        # above.  Reading from the fd directly avoids the text-buffering /
        # ``select`` mismatch that hides buffered lines.
        try:
            chunk = os.read(self._fd, 65536)
        except (BlockingIOError, InterruptedError):
            return []
        except OSError as exc:
            raise RuntimeError("udevadm monitor exited") from exc

        if chunk == b"":
            raise RuntimeError("udevadm monitor exited")

        # Decode tolerantly via the incremental decoder — descriptor strings
        # may carry non-UTF-8 garbage (→ replaced), and multibyte sequences may
        # be split across this and the next ``os.read`` chunk (→ reassembled).
        self._linebuf += self._decoder.decode(chunk)

        # Bound the partial-line buffer: a hostile newline-free flood would
        # otherwise grow it without limit (the block-line cap below only bounds
        # COMPLETE lines).  Drop the hostile partial AND the in-progress block
        # and resync — the same strategy used for the block-line cap.
        if "\n" not in self._linebuf and len(self._linebuf) > _MAX_LINEBUF_CHARS:
            self._linebuf = ""
            self._block = []
            return []

        records: list[dict[str, Any]] = []
        # Split into complete lines, retaining any trailing partial line.
        *complete, self._linebuf = self._linebuf.split("\n")
        for line in complete:
            if line == "":
                # Blank line → block terminator.
                record = parse_event_block(self._block)
                self._block = []
                if record is not None:
                    records.append(record)
            else:
                self._block.append(line)
                if len(self._block) > _MAX_BLOCK_LINES:
                    # Hostile/unterminated block — drop it to bound memory.
                    self._block = []

        return records

    def close(self) -> None:
        """Terminate the subprocess (best-effort, idempotent, never raises)."""
        self._closed = True
        proc = self._proc
        try:
            if proc.poll() is None:
                proc.terminate()
        except Exception:
            pass
        # Reap the child to avoid leaving a zombie.  Wait briefly after
        # terminate; on timeout, escalate to kill and wait again.  Guarded so a
        # fake/already-dead proc without a real ``wait`` can't raise.
        try:
            if hasattr(proc, "wait"):
                proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                if proc.poll() is None:
                    proc.kill()
            except Exception:
                pass
            try:
                if hasattr(proc, "wait"):
                    proc.wait(timeout=5)
            except Exception:
                pass
        except Exception:
            pass
