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
from angerona.resilience.supervisor import ProcessSupervisor, cached_cmdline_probe

_SENSOR_LABELS = {1: "process_creation"}
_WATCHDOG_STALE_AFTER_SECONDS = 10.0


def _repo_root() -> Path:
    from angerona.core.data_paths import project_root
    return project_root()


def _watchdog_binary() -> Optional[Path]:
    from angerona.core.executable_trust import executable_is_trusted
    for cand in ("frz/angerona_watchdog.exe", "frz/angerona_watchdog",
                 "frz/frz_watchdog.exe", "frz/frz_watchdog"):
        p = _repo_root() / cand
        if executable_is_trusted(p):
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
    return cached_cmdline_probe(*needles)


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
        self._sup = ProcessSupervisor(
            poll_interval=1.0,
            on_event=self._sup_event,
            state_namespace="core-manager",
        )
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self.frames_ingested = 0
        self.frames_rejected = 0
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

        # Publish core liveness BEFORE the watchdog process is allowed to assess
        # us. The previous ordering spawned the watchdog first; during a busy boot
        # it saw no core heartbeat and launched replacement cores into SAFE_MODE.
        self._core_beat.beat()
        self._spawn_thread(self._heartbeat_loop, "core-heartbeat")
        # Diagnostics and telemetry draining must not wait behind helper-process
        # discovery/spawn. If Windows takes time probing an existing sidecar, the
        # core remains observable and continues consuming scanner frames.
        self._spawn_thread(self._ring_loop, "ring-drain")
        self._spawn_thread(self._status_loop, "core-status")

        py = sys.executable
        pyw = _pythonw()
        # The watchdog (Go or Python) inherits how to relaunch Angerona.
        os.environ.setdefault("ANGERONA_PY", pyw)
        core_args = "-m angerona --chill" if os.environ.get(
            "ANGERONA_CHILL_ACTIVE"
        ) == "1" else "-m angerona"
        # Rebuild this from the trusted current interpreter every generation.
        # An older watchdog may legitimately hand us a stale pre-Chill command;
        # carrying it forward would make the next crash restart in Full mode.
        os.environ["ANGERONA_CORE_CMD"] = f'"{pyw}" {core_args}'
        # Run the hidden scanner HEADLESS. It was spawning a full QApplication +
        # Qt window per (detached, no-console) scanner process — heavy RAM and a
        # frequent startup failure that pushed the scanner into SAFE_MODE. Headless
        # is lean and reliable; the BlackBox + watchdog_ui already give visibility.
        os.environ["ANGERONA_SCANNER_UI"] = "0"

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
                          stale_after_s=_WATCHDOG_STALE_AFTER_SECONDS, window="hidden")
            if _watchdog_binary() is None:
                self._publish("Resilience Manager",
                              "Using the Python peer watchdog. Build + code-sign the Go binary "
                              "(see frz/BUILD_SIGN_DEPLOY.md) for the out-of-process parent.", "LOW")

        # 2) Telemetry Scanner — lean forwarder with its own themed window.
        # stale_after_s is generous (was 3s): the scanner's 1 Hz psutil snapshot can
        # briefly exceed 3s under heavy load (Eco off, ~48 modules), and a too-tight
        # threshold flapped it into SAFE_MODE — which starved DRILL of echoes and
        # produced false "telemetry blinding" CRITICALs. 8s absorbs the jitter.
        self._sup.add("scanner", [pyw, "-m", "angerona.resilience.scanner"],
                      stale_after_s=8.0, window="hidden")

        # 3) BlackBox — decoupled recorder, its own themed self-minimizing window.
        bb = _blackbox_script()
        blackbox_enabled = os.environ.get(
            "ANGERONA_BLACKBOX_ENABLED", "1"
        ).strip().lower() not in ("0", "false", "no", "off")
        if bb is not None and blackbox_enabled:
            self._sup.add("blackbox", [pyw, str(bb)], window="hidden",
                          running_probe=_cmdline_probe("blackbox_recorder.py"))

        # 4) Themed monitor windows (present a component's status; lean readers).
        if self.with_ui:
            self._sup.add("watchdog_ui",
                          [pyw, "-m", "angerona.resilience.status_ui", "watchdog",
                           "--title", "Angerona - Watchdog"],
                          window="hidden",
                          running_probe=_cmdline_probe("status_ui", "watchdog"))
            # Telemetry Scanner monitor window. The scanner PROCESS itself runs
            # headless (ANGERONA_SCANNER_UI=0) for reliability — its old inline
            # QApplication was heavy and flaky and pushed it into SAFE_MODE. So the
            # scanner had no window and looked like it "wasn't starting with the
            # others." This dedicated status_ui reader gives it a visible themed
            # window like the watchdog's, without the fragile inline UI — it just
            # reads status_scanner.json + the scanner heartbeat on a timer.
            self._sup.add("scanner_ui",
                          [pyw, "-m", "angerona.resilience.status_ui", "scanner",
                           "--title", "Angerona - Telemetry Scanner"],
                          window="hidden",
                          running_probe=_cmdline_probe("status_ui", "scanner"))

        self._sup.start()          # adopt-if-alive: never double-spawns

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
            before = (
                int(getattr(self._reader, "authentication_failures", 0))
                if self._reader is not None else 0
            )
            try:
                batch = self._reader.read_batch(2048) if self._reader else []
            except Exception:
                batch = []
            after = (
                int(getattr(self._reader, "authentication_failures", before))
                if self._reader is not None else before
            )
            if after > before:
                self._record_ipc_rejection(
                    after - before,
                    "frame authentication, sequence, or ring-header integrity",
                )
            for fr in batch:
                self.frames_ingested += 1
                self._handle_frame(fr)

    def _record_ipc_rejection(self, count: int, reason: str) -> None:
        self.frames_rejected += max(1, int(count))
        total = self.frames_rejected
        if total <= 3 or total & (total - 1) == 0:
            self._publish(
                "Resilience Manager",
                f"Authenticated IPC input rejected ({reason}); "
                f"{total} rejected frame(s) this run.",
                "HIGH",
                {"rejected_frames": total, "reason": reason},
            )

    def _handle_frame(self, fr: dict) -> bool:
        sensor_id = fr.get("sensor_id")
        label = _SENSOR_LABELS.get(sensor_id, f"sensor{sensor_id}")
        try:
            payload = ipc_ring.decode_sensor_payload(sensor_id, fr["payload"])
        except (ipc_ring.FrameError, KeyError, TypeError):
            self._record_ipc_rejection(1, "authenticated sensor payload schema")
            return False
        if self.on_frame:
            try:
                self.on_frame({"label": label, **payload})
            except Exception:
                pass
        name = payload.get("name") or label
        self._publish("Telemetry Scanner",
                      f"{label}: {name} (pid {payload.get('pid')})",
                      "INFO", {**payload, "source": "scanner", "sensor": label})
        return True

    def _status_loop(self):
        while not self._stop.wait(3.0):
            diag.write_status("core", "running", {
                "frames_ingested": self.frames_ingested,
                "frames_rejected": self.frames_rejected,
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
    prev_blackbox = os.environ.get("ANGERONA_BLACKBOX_ENABLED")
    workdir = tempfile.mkdtemp(prefix="mgr_selftest_")
    os.environ["ANGERONA_DATA"] = workdir
    os.environ["ANGERONA_DIAG_DIR"] = os.path.join(workdir, "diag")
    os.environ["ANGERONA_SCANNER_INTERVAL"] = "0.2"
    os.environ["ANGERONA_SCANNER_UI"] = "0"
    # Never adopt or terminate the operator's live Black Box during this
    # isolated lifecycle test.
    os.environ["ANGERONA_BLACKBOX_ENABLED"] = "0"

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
        scanner = mgr._sup.components["scanner"]
        # Detached Windows processes can take more than a second to reach their
        # first heartbeat while Defender/ETW inspects the new interpreter. Wait
        # for observable readiness and an actual ring frame instead of relying
        # on one fixed startup sleep.
        ready_deadline = time.time() + 8.0
        alive_ok = False
        ingested_ok = False
        while time.time() < ready_deadline:
            alive_ok = mgr._sup._is_running(scanner)
            ingested_ok = mgr.frames_ingested >= 1
            if alive_ok and ingested_ok:
                break
            time.sleep(0.1)
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
        if prev_blackbox is None:
            os.environ.pop("ANGERONA_BLACKBOX_ENABLED", None)
        else:
            os.environ["ANGERONA_BLACKBOX_ENABLED"] = prev_blackbox
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    print(self_test())
