"""manager.py — core-side driver for the resilience ecosystem.

This is what the Angerona core starts to bring the decoupled ecosystem up:

  * spawns + supervises the standalone Telemetry Scanner (and the compiled
    watchdog binary if one is present) as detached processes, respawning them
    with backoff (see supervisor.py);
  * beats the core's own shared-memory heartbeat so the watchdog can tell the
    core apart from a suspended zombie;
  * drains the raw-telemetry ring the scanner fills and republishes each frame
    onto the Angerona EventBus, where the existing modules decipher and act;
  * periodically writes the core's status diagnostic for the BlackBox.

Everything is cancellable and low-overhead: the ring drain and heartbeat run on
relaxed intervals, and process death is caught by the supervisor's blocking
waiter (0% idle CPU).
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Optional

from angerona.resilience import ipc_ring
from angerona.resilience import heartbeat as hb
from angerona.resilience import diagnostics as diag
from angerona.resilience import shutdown_token as tok
from angerona.resilience.supervisor import ProcessSupervisor

# Sensor id → human label for republished frames.
_SENSOR_LABELS = {1: "process_creation"}


def _watchdog_binary() -> Optional[Path]:
    """Locate a compiled watchdog binary if the operator has built one."""
    root = Path(__file__).resolve().parents[3]
    for cand in ("frz/angerona_watchdog.exe", "frz/angerona_watchdog",
                 "frz/frz_watchdog.exe", "frz/frz_watchdog"):
        p = root / cand
        if p.exists():
            return p
    return None


class ResilienceManager:
    def __init__(self, bus=None, heartbeat_interval: float = 0.5,
                 ring_interval: float = 0.5, start_watchdog: bool = True,
                 on_frame: Optional[Callable[[dict], None]] = None):
        self.bus = bus
        self.heartbeat_interval = heartbeat_interval
        self.ring_interval = ring_interval
        self.start_watchdog = start_watchdog
        self.on_frame = on_frame
        self._core_beat = hb.HeartbeatWriter("core")
        self._reader: Optional[ipc_ring.RingReader] = None
        self._sup = ProcessSupervisor(poll_interval=1.0, on_event=self._sup_event)
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self.frames_ingested = 0
        self.status = "stopped"

    # ── supervisor events → bus + diagnostics ────────────────────────────────
    def _sup_event(self, level: str, msg: str, details: dict) -> None:
        self._publish("Resilience Supervisor", f"[{level}] {msg}", level, details)

    def _publish(self, module: str, message: str, level: str = "INFO", details: dict | None = None):
        if self.bus is None:
            return
        try:
            from angerona.core.eventbus import Event, Severity
            sev = getattr(Severity, level if level in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
                          else "INFO", Severity.INFO)
            self.bus.publish(Event(module, message, sev, time.time(), details or {}))
        except Exception:
            pass

    # ── lifecycle ────────────────────────────────────────────────────────────
    def start(self) -> None:
        self._stop.clear()
        # Ensure the ring exists before the scanner attaches (we own it as reader).
        self._reader = ipc_ring.RingReader(ipc_ring.ring_path("telemetry"))

        env = {}
        wd = _watchdog_binary() if self.start_watchdog else None
        if wd is not None:
            self._sup.add("watchdog", [str(wd)], stale_after_s=2.0)
        else:
            self._publish("Resilience Manager",
                          "No compiled watchdog binary found (frz/angerona_watchdog[.exe]); "
                          "running with the Python supervisor only. Build the Go watchdog to "
                          "enable the compiled cross-monitor.", "LOW")

        self._sup.add("scanner",
                      [sys.executable, "-m", "angerona.resilience.scanner"],
                      stale_after_s=3.0)
        self._sup.start()

        self._spawn_thread(self._heartbeat_loop, "core-heartbeat")
        self._spawn_thread(self._ring_loop, "ring-drain")
        self._spawn_thread(self._status_loop, "core-status")
        self.status = "running"
        self._publish("Resilience Manager", "Ecosystem online — scanner supervised, "
                      "ring draining, core heartbeat beating.", "INFO")

    def _spawn_thread(self, target, name):
        t = threading.Thread(target=target, name=name, daemon=True)
        t.start()
        self._threads.append(t)

    def _heartbeat_loop(self):
        while not self._stop.wait(self.heartbeat_interval):
            self._core_beat.beat()
            if tok.is_standdown_requested():
                self._publish("Resilience Manager", "Stand-down token present — stopping.", "MEDIUM")
                self.stop()
                return

    def _ring_loop(self):
        while not self._stop.wait(self.ring_interval):
            try:
                batch = self._reader.read_batch(2048) if self._reader else []
            except Exception:
                batch = []
            for fr in batch:
                self.frames_ingested += 1
                self._handle_frame(fr)

    def _handle_frame(self, fr: dict) -> None:
        label = _SENSOR_LABELS.get(fr.get("sensor_id"), f"sensor{fr.get('sensor_id')}")
        try:
            payload = json.loads(fr["payload"].decode("utf-8", "ignore"))
        except Exception:
            payload = {"raw": fr["payload"][:120].hex()}
        if self.on_frame:
            try:
                self.on_frame({"label": label, **payload})
            except Exception:
                pass
        # Republish raw telemetry onto the bus for the core's modules to decipher.
        name = payload.get("name") or label
        self._publish("Telemetry Scanner",
                      f"{label}: {name} (pid {payload.get('pid')})",
                      "INFO", {**payload, "source": "scanner", "sensor": label})

    def _status_loop(self):
        while not self._stop.wait(3.0):
            diag.write_status("core", "running", {
                "frames_ingested": self.frames_ingested,
                "supervised": list(self._sup.components.keys()),
                "safe_mode": [n for n, c in self._sup.components.items() if c.safe_mode],
            })

    def stop(self) -> None:
        if self._stop.is_set():
            return
        self._stop.set()
        try:
            self._sup.stop(terminate_children=True)
        finally:
            try:
                self._core_beat.close()
            finally:
                if self._reader:
                    self._reader.close()
        self.status = "stopped"


def start_resilience(bus=None, **kw) -> ResilienceManager:
    """Convenience entry point for the Angerona core."""
    m = ResilienceManager(bus=bus, **kw)
    m.start()
    return m


def self_test() -> tuple[bool, str]:
    """Live: start the manager (which spawns a REAL scanner subprocess), confirm
    frames flow ring→core, kill the scanner and confirm respawn, then stop."""
    import tempfile, shutil
    prev = os.environ.get("ANGERONA_DATA")
    prev_diag = os.environ.get("ANGERONA_DIAG_DIR")
    workdir = tempfile.mkdtemp(prefix="mgr_selftest_")
    os.environ["ANGERONA_DATA"] = workdir
    os.environ["ANGERONA_DIAG_DIR"] = os.path.join(workdir, "diag")
    os.environ["ANGERONA_SCANNER_INTERVAL"] = "0.2"

    class _Bus:
        def __init__(self): self.events = []
        def publish(self, ev): self.events.append(ev)

    bus = _Bus()
    mgr = ResilienceManager(bus=bus, heartbeat_interval=0.2, ring_interval=0.2,
                            start_watchdog=False)
    import subprocess, threading as _th
    churn_stop = _th.Event()
    def _churn():
        live = []
        while not churn_stop.is_set():
            try:
                live.append(subprocess.Popen([sys.executable, "-c", "pass"]))
            except Exception:
                pass
            time.sleep(0.15)
            live = [q for q in live if q.poll() is None]
        for q in live:
            try: q.wait(timeout=1)
            except Exception: q.kill()
    try:
        mgr.start()
        # Continuous process churn so the (separate) scanner sees NEW pids after
        # it has baselined, and forwards them to the core.
        _th.Thread(target=_churn, daemon=True).start()
        time.sleep(3.0)
        scanner = mgr._sup.components["scanner"]
        alive_ok = scanner.reader.classify(stale_after_s=3.0) == "alive"
        ingested_ok = mgr.frames_ingested >= 1     # raw frames reached the core

        before = scanner.restarts
        if scanner.proc:
            scanner.proc.kill()
        time.sleep(0.6)
        for _ in range(8):
            mgr._sup.tick(); time.sleep(0.3)
            if scanner.restarts > before:
                break
        respawn_ok = scanner.restarts > before

        churn_stop.set()
        ok = alive_ok and respawn_ok and ingested_ok
        return ok, (f"scanner spawned+alive, respawned on kill, {mgr.frames_ingested} raw "
                    f"frame(s) ingested core-side" if ok else
                    f"failed: alive={alive_ok} respawn={respawn_ok} ingested={ingested_ok}")
    finally:
        mgr.stop()
        for k, v in (("ANGERONA_DATA", prev), ("ANGERONA_DIAG_DIR", prev_diag)):
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        os.environ.pop("ANGERONA_SCANNER_INTERVAL", None)
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    print(self_test())
