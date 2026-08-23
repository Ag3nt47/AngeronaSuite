"""frz_heartbeat.py — Anti-Suspension Heartbeat (Code: FRZ).

Purpose
    Defend against thread-suspension attacks: an adversary that gains code execution
    in the Angerona process can freeze all Python threads, preventing detection or
    response.  FRZ counters this by:

    1. Python side (this module) — continuously writes the authenticated fixed
       v2 resilience heartbeat into a named ``mmap`` file every ``HEARTBEAT_MS``
       milliseconds. Any thread suspension that halts Python freezes its signed
       counter/timestamp pair.

    2. External watchdog (``frz_watchdog_v2.exe``, pre-compiled from
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

import os
import pathlib
import subprocess
import sys
import threading
from functools import lru_cache

from angerona.core.config import Config
from angerona.core.jitter import jittered
from angerona.core.module_base import BaseModule, Severity
from angerona.resilience import heartbeat as hb

# ── constants ────────────────────────────────────────────────────────────────
HEARTBEAT_MS: int = 500          # write interval (ms)
MMAP_SIZE: int = hb.RECORD_SIZE
_HEARTBEAT_COMPONENT = "frz-core"

_WATCHDOG_NAME = "frz_watchdog_v2.exe"
_LEGACY_WATCHDOG_NAME = "frz_watchdog.exe"


def _watchdog_path() -> pathlib.Path:
    """Find only the authenticated-v2 watchdog binary.

    A signed legacy binary is still unsafe here: it interprets v2 magic bytes as
    a timestamp and cannot authenticate flags, PID, or progress.  Giving it this
    record could therefore cause a false emergency kill.  The distinct filename
    is an explicit wire-compatibility boundary.
    """
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


def _legacy_watchdog_present() -> bool:
    from angerona.core.data_paths import project_root
    return any(path.exists() for path in (
        pathlib.Path(sys.executable).parent / _LEGACY_WATCHDOG_NAME,
        project_root() / "frz" / _LEGACY_WATCHDOG_NAME,
    ))


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
        self._heartbeat_writer: hb.HeartbeatWriter | None = None
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
        self._heartbeat_writer = hb.HeartbeatWriter(
            _HEARTBEAT_COMPONENT,
            path=path,
        )

    def _write_beat(self) -> None:
        writer = self._heartbeat_writer
        if writer is None:
            return
        with self._lock:
            # HeartbeatWriter publishes the authenticated record in place and
            # intentionally does not flush on each beat. File-backed mappings
            # are coherent to the external reader without durable HDD writes.
            writer.beat()
        self._beats += 1

    def _close_mmap(self) -> None:
        writer = self._heartbeat_writer
        self._heartbeat_writer = None
        if writer is not None:
            try:
                with self._lock:
                    # close() publishes an authenticated stopped record before
                    # releasing the mapping, so only a valid writer can suppress
                    # the watchdog during clean shutdown.
                    writer.close()
            except Exception:
                pass

    # ── watchdog management ──────────────────────────────────────────────────
    def _launch_watchdog(self) -> None:
        exe = _trusted_watchdog_path()
        if exe is None:
            legacy_present = _legacy_watchdog_present()
            legacy = (
                " A legacy unauthenticated watchdog was ignored."
                if legacy_present else ""
            )
            self.emit(
                "A validly signed authenticated-v2 FRZ watchdog binary was not "
                "found. Heartbeat remains active; external termination is "
                f"disabled.{legacy}",
                Severity.LOW,
                watchdog_path="",
                legacy_incompatible=legacy_present,
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
        """Verify independent authenticated-v2 reads see advancing beats."""
        import tempfile
        key = bytes(range(32))
        with tempfile.TemporaryDirectory(prefix="frz_hb_selftest_") as directory:
            tmp = pathlib.Path(directory) / "frz.mmap"
            try:
                writer = hb.HeartbeatWriter(
                    _HEARTBEAT_COMPONENT,
                    token_raw=key,
                    path=tmp,
                )
                reader = hb.HeartbeatReader(
                    _HEARTBEAT_COMPONENT,
                    path=tmp,
                    key_raw=key,
                )
                first = reader.read()
                first_auth = reader.authentication_status(record=first)
                writer.beat()
                second = reader.read()
                second_auth = reader.authentication_status(record=second)
                wrong_key_rejected = (
                    hb.HeartbeatReader(
                        _HEARTBEAT_COMPONENT,
                        path=tmp,
                        key_raw=bytes(reversed(key)),
                    ).authentication_status(record=second)
                    == "invalid"
                )
                writer.close()
                stopped = reader.read()
                stopped_auth = reader.authentication_status(record=stopped)
                ok = bool(
                    first
                    and second
                    and stopped
                    and first_auth == "authenticated"
                    and second_auth == "authenticated"
                    and int(second["counter"]) > int(first["counter"])
                    and int(second["pid"]) == (os.getpid() & 0xFFFFFFFF)
                    and int(second["flags"]) == 1
                    and wrong_key_rejected
                    and stopped_auth == "authenticated"
                    and int(stopped["flags"]) == 0
                )
                watchdog_note = (
                    "signed v2 watchdog present"
                    if _trusted_watchdog_path() is not None
                    else "signed v2 watchdog absent; authenticated Python heartbeat only"
                )
                return (
                    ok,
                    f"authenticated v2 mmap round-trip OK ({watchdog_note})"
                    if ok else
                    "authenticated v2 mmap verification failed",
                )
            except Exception as exc:
                return (False, f"mmap self-test exception: {exc}")


def register() -> FrzHeartbeatModule:
    return FrzHeartbeatModule()
