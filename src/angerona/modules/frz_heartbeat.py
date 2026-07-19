"""frz_heartbeat.py — Anti-Suspension Heartbeat (Code: FRZ).

Purpose
    Defend against thread-suspension attacks: an adversary that gains code execution
    in the Angerona process can freeze all Python threads, preventing detection or
    response.  FRZ counters this by:

    1. Python side (this module) — continuously writes a monotonic nanosecond
       timestamp into a named ``mmap`` file (shared memory region) every
       ``HEARTBEAT_MS`` milliseconds.  Any thread suspension that halts Python will
       also freeze this clock.

    2. External watchdog (``frz_watchdog.exe``, pre-compiled from
       ``AngeronaSuite/frz/frz_watchdog.go``) — launched as a subprocess that is
       *not* the Python process.  It reads the mmap timestamp independently.  If
       the Python PID is still alive but the timestamp hasn't advanced for
       ``FREEZE_THRESHOLD_S`` seconds, the watchdog triggers:
         a. Emergency network isolation via ``netsh`` (severs external comms).
         b. Hard-kill of the frozen Python interpreter.

    The watchdog is a compiled binary so an attacker inside the Python process
    cannot suppress it by patching Python functions.

Drop-in contract
    BaseModule subclass + CODE/NAME/state/health_pct/self_test + register().

Safety
    Network isolation blocks external traffic only; loopback (127.0.0.1) stays
    reachable so Ollama (:11434) and IPC (:65432) are unaffected.  The watchdog
    never auto-executes on its own — it only fires when both conditions are true:
    (PID alive) AND (clock frozen).
"""
from __future__ import annotations

import mmap
import os
import pathlib
import struct
import subprocess
import sys
import threading
import time
from functools import lru_cache

from angerona.core.config import Config
from angerona.core.jitter import jittered
from angerona.core.module_base import BaseModule, Severity

# ── constants ────────────────────────────────────────────────────────────────
HEARTBEAT_MS: int = 500          # write interval (ms)
MMAP_SIZE: int = 16             # bytes: uint64 ts_ns (8) + uint32 pid (4) + uint32 flags (4)
_STRUCT = struct.Struct("<QII")  # little-endian: uint64, uint32, uint32

_WATCHDOG_NAME = "frz_watchdog.exe"


def _watchdog_path() -> pathlib.Path:
    """Look for the compiled watchdog next to the package root / app dir."""
    from angerona.core.data_paths import project_root
    # Try: next to __main__ frozen exe, then repo frz/ subdir
    candidates = [
        pathlib.Path(sys.executable).parent / _WATCHDOG_NAME,
        project_root() / "frz" / _WATCHDOG_NAME,
    ]
    for p in candidates:
        if p.exists():
            return p
    return candidates[-1]  # return canonical path even if missing (self_test notes it)


@lru_cache(maxsize=1)
def _trusted_watchdog_path() -> pathlib.Path | None:
    from angerona.core.executable_trust import executable_is_trusted
    path = _watchdog_path()
    return path if executable_is_trusted(path) else None


def _mmap_path() -> pathlib.Path:
    return pathlib.Path(Config().data_dir) / "frz_heartbeat.mmap"


# ── module ───────────────────────────────────────────────────────────────────
class FrzHeartbeatModule(BaseModule):
    CODE = "FRZ"
    NAME = "Anti-Suspension Heartbeat"

    name = "Anti-Suspension Heartbeat"
    description = (
        "Writes a nanosecond heartbeat to a shared mmap region every 500 ms so the "
        "external FRZ watchdog binary can detect thread-suspension attacks.  If the "
        "Python process is frozen but alive, the watchdog triggers emergency network "
        "isolation and terminates the compromised interpreter."
    )
    category = "Resilience"
    version = "1.0.0"
    enabled_by_default = True

    _WRITE_INTERVAL = HEARTBEAT_MS / 1000.0

    def __init__(self) -> None:
        super().__init__()
        self._mm: mmap.mmap | None = None
        self._mm_file = None
        self._watchdog_proc: subprocess.Popen | None = None
        self._lock = threading.Lock()
        self._beats: int = 0

    # ── dual-contract properties ─────────────────────────────────────────────
    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    # ── mmap helpers ─────────────────────────────────────────────────────────
    def _open_mmap(self) -> None:
        path = _mmap_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        self._mm_file = open(path, "w+b")
        self._mm_file.write(b"\x00" * MMAP_SIZE)
        self._mm_file.flush()
        self._mm = mmap.mmap(self._mm_file.fileno(), MMAP_SIZE)

    def _write_beat(self) -> None:
        if self._mm is None:
            return
        ts_ns = time.monotonic_ns()
        pid = os.getpid() & 0xFFFFFFFF
        data = _STRUCT.pack(ts_ns, pid, 1)  # flag=1 → running
        with self._lock:
            self._mm.seek(0)
            self._mm.write(data)
            self._mm.flush()
        self._beats += 1

    def _close_mmap(self) -> None:
        if self._mm:
            try:
                # Write flag=0 (stopping) so watchdog doesn't fire during clean shutdown
                ts_ns = time.monotonic_ns()
                pid = os.getpid() & 0xFFFFFFFF
                with self._lock:
                    self._mm.seek(0)
                    self._mm.write(_STRUCT.pack(ts_ns, pid, 0))
                    self._mm.flush()
                self._mm.close()
            except Exception:
                pass
        if self._mm_file:
            try:
                self._mm_file.close()
            except Exception:
                pass

    # ── watchdog management ──────────────────────────────────────────────────
    def _launch_watchdog(self) -> None:
        exe = _trusted_watchdog_path()
        if exe is None:
            self.emit(
                "A validly signed FRZ watchdog binary was not found. Heartbeat "
                "remains active; external termination is disabled.",
                Severity.LOW,
                watchdog_path="",
            )
            return
        try:
            self._watchdog_proc = subprocess.Popen(
                [str(exe), str(os.getpid()), str(_mmap_path())],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                # Detach so it outlives any parent-process suspension
                creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                | getattr(subprocess, "DETACHED_PROCESS", 8),
            )
            self.emit(
                f"FRZ watchdog launched (PID {self._watchdog_proc.pid}) — "
                f"monitoring this process (PID {os.getpid()}).",
                Severity.INFO,
                watchdog_pid=self._watchdog_proc.pid,
                monitored_pid=os.getpid(),
            )
        except Exception as exc:
            self.last_error = str(exc)
            self.emit(f"FRZ watchdog launch failed: {exc}", Severity.LOW)

    def _watchdog_alive(self) -> bool:
        if self._watchdog_proc is None:
            return False
        return self._watchdog_proc.poll() is None

    # ── lifecycle ────────────────────────────────────────────────────────────
    def run(self) -> None:
        try:
            self._open_mmap()
        except Exception as exc:
            self.last_error = str(exc)
            self.set_health(0, f"mmap open failed: {exc}")
            return

        self._launch_watchdog()
        watchdog_missing_warned = _trusted_watchdog_path() is None

        self.emit(
            f"FRZ online — heartbeat every {HEARTBEAT_MS} ms to "
            f"{_mmap_path().name}.",
            Severity.INFO,
            mmap_path=str(_mmap_path()),
            pid=os.getpid(),
        )

        consecutive_errors = 0
        while not self.stopping:
            try:
                self._write_beat()
                consecutive_errors = 0
            except Exception as exc:
                self.last_error = str(exc)
                consecutive_errors += 1
                if consecutive_errors >= 5:
                    self.set_health(40, f"mmap write errors: {exc}")

            # Check watchdog health
            if _trusted_watchdog_path() is not None:
                if not self._watchdog_alive():
                    # Watchdog died — relaunch
                    self._launch_watchdog()
                    self.set_health(70, "Watchdog restarted")
                else:
                    self.set_health(100, f"{self._beats} beats written")
            else:
                if not watchdog_missing_warned:
                    watchdog_missing_warned = True
                self.set_health(65, "Watchdog binary absent — mmap only")

            # Jittered write cadence (anti-TOCTOU). Stays well within the
            # watchdog's freeze threshold, so a late beat never false-triggers.
            self.sleep(jittered(self._WRITE_INTERVAL))

        self._close_mmap()
        if self._watchdog_proc and self._watchdog_alive():
            try:
                self._watchdog_proc.terminate()
            except Exception:
                pass

    def self_test(self) -> tuple[bool, str]:
        """Write two beats to a temp mmap and verify the timestamp advances."""
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".mmap", delete=False) as f:
            tmp = pathlib.Path(f.name)
            f.write(b"\x00" * MMAP_SIZE)
        try:
            with open(tmp, "r+b") as fh:
                mm = mmap.mmap(fh.fileno(), MMAP_SIZE)
                ts1 = time.monotonic_ns()
                mm.seek(0)
                mm.write(_STRUCT.pack(ts1, os.getpid(), 1))
                mm.flush()
                time.sleep(0.01)
                ts2 = time.monotonic_ns()
                mm.seek(0)
                mm.write(_STRUCT.pack(ts2, os.getpid(), 1))
                mm.flush()
                mm.seek(0)
                raw = mm.read(MMAP_SIZE)
                ts_r, pid_r, flag_r = _STRUCT.unpack(raw)
                mm.close()
            tmp.unlink()
            ok = (ts_r == ts2) and (pid_r == os.getpid()) and (flag_r == 1) and (ts2 > ts1)
            watchdog_note = (
                "signed watchdog binary present" if _trusted_watchdog_path() is not None
                else "signed watchdog binary absent"
            )
            return (ok, f"mmap round-trip OK ({watchdog_note})" if ok
                    else f"mmap read mismatch: ts={ts_r} pid={pid_r} flag={flag_r}")
        except Exception as exc:
            try:
                tmp.unlink()
            except Exception:
                pass
            return (False, f"mmap self-test exception: {exc}")


def register() -> FrzHeartbeatModule:
    return FrzHeartbeatModule()
