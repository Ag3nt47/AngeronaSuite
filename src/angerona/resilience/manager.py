"""manager.py — core-side driver for the resilience ecosystem.

Started by Angerona at launch. It brings up the decoupled ecosystem as separate,
MINIMIZED processes and keeps them alive:

  * Telemetry Scanner   — lean raw-telemetry forwarder (own Angerona-themed window)
  * BlackBox            — decoupled flight recorder (own themed window, self-minimizes)
  * Watchdog            — compiled Go binary if built, else the Python watchdog
                          (angerona.resilience.watchdog); restarts the core, and is
                          restarted BY the core → mutual keep-alive
  * Watchdog monitor    — a themed window presenting the watchdog's status

Angerona and the Watchdog watch EACH OTHER (mutual restart) and BOTH also watch
and restart the scanner and BlackBox. A cross-process spawn lock + adopt-if-alive
mean relaunching Angerona never opens duplicate instances of anything running.

The core beats its own heartbeat (so the watchdog can restart it after a crash),
drains the raw-telemetry ring the scanner fills and republishes each frame onto
the EventBus, and writes its status for the BlackBox.
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

_SENSOR_LABELS = {1: "process_creation"}


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _watchdog_binary() -> Optional[Path]:
    for cand in ("frz/angerona_watchdog.exe", "frz/angerona_watchdog",
                 "frz/frz_watchdog.exe", "frz/frz_watchdog"):
        p = _repo_root() / cand
        if p.exists():
            return p
    return None


def _blackbox_script() -> Optional[Path]:
    p = _repo_root() / "blackbox_recorder.py"
    return p if p.exists() else None


def _pythonw() -> str:
    exe = sys.executable
    if os.name == "nt":
        cand = exe.replace("python.exe", "pythonw.exe")
        if os.path.exists(cand):
            return cand
    return exe


def _cmdline_probe(*needles: str) -> Callable[[], bool]:
    def _probe() -> bool:
        try:
            import psutil
            for pr in psutil.process_iter(["cmdline"]):
                cl = " ".join(pr.info.get("cmdline") or [])
                if cl and all(n in cl for n in needles):
                    return True
        except Exception:
            pass
        return False
    return _probe


class ResilienceManager:
    def __init__(self, bus=None, heartbeat_interval: float = 0.5,
                 ring_interval: float = 0.5, start_watchdog: bool = True,
                 with_ui: bool = True, on_frame: Optional[Callable[[dict], None]] = None):
        self.bus = bus
        self.heartbeat_interval = heartbeat_interval
        self.ring_interval = ring_interval
        self.start_watchdog = start_watchdog
        self.with_ui = with_ui
        self.on_frame = on_frame
        self._core_beat = hb.HeartbeatWriter("core")
        self._reader: Optional[ipc_ring.RingReader] = None
        self._sup = ProcessSupervisor(poll_interval=1.0, on_event=self._sup_event)
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self.frames_ingested = 0
        self.status = "stopped"

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
        self._reader = ipc_ring.RingReader(ipc_ring.ring_path("telemetry"))

        py = sys.executable
        pyw = _pythonw()
        # The watchdog (Go or Python) inherits how to relaunch Angerona.
        os.environ.setdefault("ANGERONA_PY", pyw)
        os.environ.setdefault("ANGERONA_CORE_CMD", f'"{pyw}" -m angerona')

        # 1) Watchdog. BL-01: the compiled Go watchdog is a resilience PARENT that
        # LAUNCHES + hashes + relaunches Angerona (deployed by start-angerona.bat,
        # which sets ANGERONA_EXTERNAL_WATCHDOG=1). It is NOT a child to spawn here —
        # doing so passed no agent arg and just errored. So: if an external parent
        # watchdog is running, skip our own; otherwise run the Python PEER watchdog.
        external_wd = os.environ.get("ANGERONA_EXTERNAL_WATCHDOG") == "1"
        if external_wd:
            self._publish("Resilience Manager",
                          "External signed watchdog is the resilience parent — skipping the "
                          "internal watchdog to avoid double-supervision.", "INFO")
        elif self.start_watchdog:
            self._sup.add("watchdog", [pyw, "-m", "angerona.resilience.watchdog"],
                          stale_after_s=2.0, window="hidden")
            if _watchdog_binary() is None:
                self._publish("Resilience Manager",
                              "Using the Python peer watchdog. Build + code-sign the Go binary "
                              "(see frz/BUILD_SIGN_DEPLOY.md) for the out-of-process parent.", "LOW")

        # 2) Telemetry Scanner — lean forwarder with its own themed window.
        self._sup.add("scanner", [pyw, "-m", "angerona.resilience.scanner"],
                      stale_after_s=3.0, window="hidden")

        # 3) BlackBox — decoupled recorder, its own themed self-minimizing window.
        bb = _blackbox_script()
        if bb is not None:
            self._sup.add("blackbox", [pyw, str(bb)], window="hidden",
                          running_probe=_cmdline_probe("blackbox_recorder.py"))

        # 4) Themed Watchdog monitor window (presents the watchdog's status).
        if self.with_ui:
            self._sup.add("watchdog_ui",
                          [pyw, "-m", "angerona.resilience.status_ui", "watchdog",
                           "--title", "Angerona - Watchdog"],
                          window="hidden",
                          running_probe=_cmdline_probe("status_ui", "watchdog"))

        self._sup.start()          # adopt-if-alive: never double-spawns

        self._spawn_thread(self._heartbeat_loop, "core-heartbeat")
        self._spawn_thread(self._ring_loop, "ring-drain")
        self._spawn_thread(self._status_loop, "core-status")
        self.status = "running"
        self._publish("Resilience Manager",
                      "Ecosystem online — watchdog + scanner + BlackBox supervised (minimized), "
                      "core heartbeat beating, ring draining.", "INFO")

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

    def stop(self, terminate_children: bool = False) -> None:
        if self._stop.is_set():
            return
        self._stop.set()
        try:
            self._sup.stop(terminate_children=terminate_children)
        finally:
            try:
                self._core_beat.close()
            finally:
                if self._reader:
                    self._reader.close()
        self.status = "stopped"


def start_resilience(bus=None, **kw) -> ResilienceManager:
    """Convenience entry point for the Angerona core (call at launch)."""
    m = ResilienceManager(bus=bus, **kw)
    m.start()
    return m


def self_test() -> tuple[bool, str]:
    """Live: start the manager (spawns a REAL scanner subprocess), confirm frames
    flow ring->core, a SECOND start does NOT duplicate the scanner (adopt), kill
    the scanner and confirm exactly one respawn, then stop."""
    import tempfile, shutil, subprocess, threading as _th
    prev = os.environ.get("ANGERONA_DATA")
    prev_diag = os.environ.get("ANGERONA_DIAG_DIR")
    workdir = tempfile.mkdtemp(prefix="mgr_selftest_")
    os.environ["ANGERONA_DATA"] = workdir
    os.environ["ANGERONA_DIAG_DIR"] = os.path.join(workdir, "diag")
    os.environ["ANGERONA_SCANNER_INTERVAL"] = "0.2"
    os.environ["ANGERONA_SCANNER_UI"] = "0"

    class _Bus:
        def __init__(self): self.events = []
        def publish(self, ev): self.events.append(ev)

    bus = _Bus()
    mgr = ResilienceManager(bus=bus, heartbeat_interval=0.2, ring_interval=0.2,
                            start_watchdog=False, with_ui=False)
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
        _th.Thread(target=_churn, daemon=True).start()
        time.sleep(3.0)
        scanner = mgr._sup.components["scanner"]
        alive_ok = mgr._sup._is_running(scanner)
        ingested_ok = mgr.frames_ingested >= 1
        before = scanner.restarts
        mgr._sup._spawn(scanner)
        time.sleep(0.2)
        no_dup_ok = scanner.restarts == before
        if scanner.proc:
            scanner.proc.kill()
        time.sleep(0.6)
        for _ in range(8):
            mgr._sup.tick(); time.sleep(0.3)
            if scanner.restarts > before:
                break
        respawn_ok = scanner.restarts == before + 1
        churn_stop.set()
        ok = alive_ok and ingested_ok and no_dup_ok and respawn_ok
        return ok, (f"scanner alive + {mgr.frames_ingested} frame(s) + no-duplicate adopt + "
                    f"single respawn" if ok else
                    f"failed: alive={alive_ok} ingested={ingested_ok} no_dup={no_dup_ok} "
                    f"respawn={respawn_ok}")
    finally:
        mgr.stop(terminate_children=True)
        for k, v in (("ANGERONA_DATA", prev), ("ANGERONA_DIAG_DIR", prev_diag)):
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        os.environ.pop("ANGERONA_SCANNER_INTERVAL", None)
        os.environ.pop("ANGERONA_SCANNER_UI", None)
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    print(self_test())
