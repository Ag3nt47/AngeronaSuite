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
from angerona.resilience.supervisor import Component, ProcessSupervisor, cached_cmdline_probe

_SENSOR_LABELS = {1: "process_creation"}
_WATCHDOG_STALE_AFTER_SECONDS = 10.0
_SOURCE_REVIEW_INTERVAL_SECONDS = 60.0


class _OwnedSelfTestProcesses:
    """Exact process custody for the manager's detached lifecycle self-test."""

    def __init__(self, marker: str = "angerona.resilience.scanner") -> None:
        self._marker = marker.casefold()
        self._identities: dict[int, tuple[float, str, int]] = {}
        self._roots: list[object] = []

    def capture(self, popen) -> None:
        if popen is None:
            return
        if all(item is not popen for item in self._roots):
            self._roots.append(popen)
        try:
            import psutil

            root = psutil.Process(int(popen.pid))
            candidates = [(root, 0)]
            candidates.extend((child, 1) for child in root.children(recursive=True))
            for process, depth in candidates:
                command = " ".join(str(part) for part in process.cmdline()).casefold()
                if self._marker not in command:
                    continue
                self._identities[int(process.pid)] = (
                    float(process.create_time()),
                    os.path.normcase(os.path.abspath(process.exe())),
                    depth,
                )
        except Exception:
            return

    def reap(self) -> None:
        """Terminate only captured marker-bound identities, children first."""
        for root in tuple(self._roots):
            self.capture(root)
        try:
            import psutil
        except ImportError:
            psutil = None
        if psutil is not None:
            ordered = sorted(
                self._identities.items(), key=lambda item: item[1][2], reverse=True
            )
            for pid, (created, executable, _depth) in ordered:
                try:
                    process = psutil.Process(pid)
                    command = " ".join(
                        str(part) for part in process.cmdline()
                    ).casefold()
                    if (
                        abs(float(process.create_time()) - created) > 0.001
                        or os.path.normcase(os.path.abspath(process.exe())) != executable
                        or self._marker not in command
                    ):
                        continue
                    process.terminate()
                    try:
                        process.wait(timeout=2.0)
                    except psutil.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=2.0)
                except (psutil.Error, OSError):
                    continue
        # The exact Popen launchers are safe fallbacks if psutil was unavailable
        # before their descendants could be captured.
        for root in tuple(self._roots):
            try:
                if root.poll() is None:
                    root.terminate()
                    try:
                        root.wait(timeout=2.0)
                    except Exception:
                        root.kill()
                        root.wait(timeout=2.0)
            except Exception:
                continue


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


def _cmdline_probe(*needles: str, expected_argv=None) -> Callable[[], bool]:
    return cached_cmdline_probe(*needles, expected_argv=expected_argv)


class ResilienceManager:
    def __init__(self, bus=None, heartbeat_interval: float = 0.5,
                 ring_interval: float = 0.5, start_watchdog: bool = True,
                 with_ui: bool = True, on_frame: Optional[Callable[[dict], None]] = None, config=None):
        self.bus = bus
        self.heartbeat_interval = heartbeat_interval
        self.ring_interval = ring_interval
        self.start_watchdog = start_watchdog
        self.with_ui = with_ui
        self.on_frame = on_frame
        self._core_beat = hb.HeartbeatWriter("core")
        self._unsigned_watchdog_enabled = getattr(config, "watchdog3_unsigned_enabled", False) is True
        self._unsigned_watchdog = None
        self._unsigned_watchdog_start_failure = None
        self._reader: Optional[ipc_ring.RingReader] = None
        self._ring_retry_at = 0.0
        self._ring_unretired_reader = None
        self._ring_gap_observations = 0
        self._ring_gap_reason = ""
        self._ring_coverage = {"state": "unmeasured", "initial_continuity_verified": False,
                               "rejection_observations": 0, "missed_frames_lower_bound": 0,
                               "close_unresolved": False, "state_scope": "ring transport",
                               "freshness_scope": "process-local; v2 restart rollback unverified"}
        self._sup = ProcessSupervisor(
            poll_interval=1.0,
            on_event=self._sup_event,
            state_namespace="core-manager",
        )
        self._stop = threading.Event()
        self._shutdown_lock = threading.RLock()
        self._closed = False
        self._threads: list[threading.Thread] = []
        self.frames_ingested = 0
        self.frames_rejected = 0
        self.status = "stopped"
        self._component_heartbeat_cache = None
        self._source_update_controller = None
        self._source_guard = None
        self._source_guard_lock = threading.Lock()
        self._source_integrity = {"state": "pending", "reason": "Source seal not captured"}
        self._owned_core_pid = os.getpid() if os.name == "nt" else None

    def _start_optional_native_watchdog(self) -> None:
        """An optional monitor must never prevent existing Core resilience startup."""
        if not getattr(self, "_unsigned_watchdog_enabled", False):
            return
        try:
            from angerona.resilience.native_watchdog import UnsignedWatchdogMonitor, third_watchdog_status
            self._unsigned_watchdog = UnsignedWatchdogMonitor(self._core_beat)
            if self._unsigned_watchdog.start() is True:
                self._unsigned_watchdog_start_failure = None
                return
            failure = third_watchdog_status()
            failure.update(state="unavailable", heartbeat_verified=False)
        except Exception as error:
            failure = {"state": "unavailable", "heartbeat_verified": False,
                       "mode": "unsigned-observe", "reduced_protection": True,
                       "response_authorized": False, "recovery_available": False,
                       "reason": "Optional native monitor could not start; existing Core resilience continues: "
                                 + (str(error) or type(error).__name__)[:256]}
            # Import/construction failures also need an explicit cached UI state.
            # Keep the local failure even if the optional module/cache is broken.
            try:
                from angerona.resilience.native_watchdog import _cache_observe
                _cache_observe(**failure)
            except Exception:
                pass
        self._unsigned_watchdog_start_failure = dict(failure)

    def _prepare_source_guard(self) -> None:
        """Bind peer launches to this source session without approving new code."""
        if getattr(sys, "frozen", False):
            self._source_integrity = {
                "state": "not-applicable",
                "reason": "Packaged executable trust uses the installed signing boundary",
            }
            return
        from angerona.resilience.source_guard import SourceGuard, SourceGuardError

        try:
            self._source_guard = SourceGuard.capture(
                _repo_root(), expected_digest=os.environ.get("ANGERONA_PEER_SOURCE_DIGEST"))
        except (SourceGuardError, OSError, ValueError):
            self._source_integrity = {
                "state": "unavailable", "reason": "Source continuity could not be established; peer launches held",
            }
        else:
            os.environ["ANGERONA_PEER_SOURCE_DIGEST"] = self._source_guard.digest
            self._source_integrity = {
                "state": "verified", "reason": "Source bytes match the current session seal",
                "digest": self._source_guard.digest,
            }
        self._sup.launch_guard = self._peer_launch_allowed

    def _peer_launch_allowed(self, component) -> bool:
        """A failed seal stays held until an explicit reviewed fresh session."""
        with self._source_guard_lock:
            return self._check_peer_source()

    def _check_peer_source(self) -> bool:
        if self._source_integrity["state"] in {"changed", "unavailable"}:
            return False
        guard = self._source_guard
        if guard is None:
            return False
        try:
            result = guard.check()
        except Exception:
            from angerona.resilience.source_guard import SourceCheck

            result = SourceCheck(False, "unavailable", "Source observation failed; peer launches held")
        self._source_integrity = {
            "state": result.state, "reason": result.reason,
            "digest": guard.digest, "changed": list(result.changed),
            "repair": "Use start-angerona.bat after normal STOP for pinned recovery; review intentional edits in Source Sandbox",
        }
        if not result.ok:
            self._publish(
                "Resilience Supervisor",
                "Source files changed or could not be checked. Peer relaunches are held; "
                "STOP and the current dashboard remain available. Use Safe Startup for verified recovery.",
                "CRITICAL", {**self._source_integrity, "response_authorized": False,
                             "disposition": "observation"})
        return result.ok

    def _source_guard_loop(self) -> None:
        while not self._stop.wait(_SOURCE_REVIEW_INTERVAL_SECONDS):
            self._peer_launch_allowed(None)

    def _sup_event(self, level: str, msg: str, details: dict) -> None:
        self._publish("Resilience Supervisor", f"[{level}] {msg}", level, details)

    def _publish(self, module: str, message: str, level: str = "INFO", details: dict | None = None):
        if self.bus is None:
            return False
        try:
            from angerona.core.eventbus import Event, Severity
            sev = getattr(Severity, level if level in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
                          else "INFO", Severity.INFO)
            self.bus.publish(Event(module, message, sev, time.time(), details or {}))
            return True
        except Exception:
            return False

    # ── lifecycle ────────────────────────────────────────────────────────────
    def start(self) -> None:
        self._stop.clear()
        # Optional ring admission runs on its worker; corrupt transport must
        # not prevent heartbeat/supervision startup. Never reset existing bytes.
        self._ring_retry_at = 0.0

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
        self._start_optional_native_watchdog()

        self._prepare_source_guard()
        if self._source_guard is not None:
            self._spawn_thread(self._source_guard_loop, "peer-source-integrity")

        py = sys.executable
        pyw = _pythonw()
        # The watchdog (Go or Python) inherits how to relaunch Angerona.
        os.environ.setdefault("ANGERONA_PY", pyw)
        # Recovery always starts quiet. A peer watchdog may retain this command
        # across later Full/Chill changes; only a fresh manual Full selection
        # may authorize local AI after an automatic restart.
        from angerona.core.privilege import OPERATOR_ELEVATION_ARGUMENT

        if getattr(sys, "frozen", False) and OPERATOR_ELEVATION_ARGUMENT in sys.argv[1:]:
            # An installed administrator session requires fresh consent after it ends.
            # The peer can still supervise the other owned components.
            os.environ.pop("ANGERONA_CORE_CMD", None)
        else:
            # Replace stale commands so an ordinary crash recovery starts quiet.
            os.environ["ANGERONA_CORE_CMD"] = f'"{pyw}" -m angerona --chill'
        # Run the hidden scanner HEADLESS. It was spawning a full QApplication +
        # Qt window per (detached, no-console) scanner process — heavy RAM and a
        # frequent startup failure that pushed the scanner into SAFE_MODE. Headless
        # is lean and reliable; the BlackBox + watchdog_ui already give visibility.
        os.environ["ANGERONA_SCANNER_UI"] = "0"

        # The footer reads immutable memory only. This separate bounded loop
        # validates known authenticated heartbeat files and native process
        # generations; a supervisor state/process-presence label cannot pulse.
        from angerona.resilience.component_status import ComponentHeartbeatCache
        blackbox_entry = _blackbox_script()
        external_wd = os.environ.get("ANGERONA_EXTERNAL_WATCHDOG") == "1"
        blackbox_enabled = os.environ.get("ANGERONA_BLACKBOX_ENABLED", "1").strip().lower() not in (
            "0", "false", "no", "off")
        producer_path = getattr(self._core_beat, "path", None)
        self._component_heartbeat_cache = ComponentHeartbeatCache({
            "core": (py,) if getattr(sys, "frozen", False) else (py, "-m", "angerona"),
            "watchdog": None if external_wd else (pyw, "-m", "angerona.resilience.watchdog"),
            "scanner": (pyw, "-m", "angerona.resilience.scanner"),
            "blackbox": (pyw, str(blackbox_entry)) if blackbox_entry is not None else None,
        }, enabled={"blackbox": blackbox_enabled,
                    "watchdog": external_wd or self.start_watchdog},
            heartbeat_directory=producer_path.parent if isinstance(producer_path, Path) else None,
            owned_core_pid=self._owned_core_pid, owner_matcher=self._owns_component_native_identity)
        self._spawn_thread(self._component_heartbeat_loop, "component-heartbeat-status")

        # 1) Watchdog. BL-01: the compiled Go watchdog is a resilience PARENT that
        # LAUNCHES + hashes + relaunches an explicitly configured agent and sets
        # ANGERONA_EXTERNAL_WATCHDOG=1. The source starter uses the Python peer.
        # The compiled parent is NOT a child to spawn here —
        # doing so passed no agent arg and just errored. So: if an external parent
        # watchdog is running, skip our own; otherwise run the Python PEER watchdog.
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
        bb = blackbox_entry
        if bb is not None and blackbox_enabled:
            self._sup.add("blackbox", [pyw, str(bb)], window="hidden",
                          running_probe=_cmdline_probe("blackbox_recorder.py", expected_argv=[pyw, str(bb)]))

        # 4) Themed monitor windows (present a component's status; lean readers).
        if self.with_ui:
            self._sup.add("watchdog_ui",
                          [pyw, "-m", "angerona.resilience.status_ui", "watchdog",
                           "--title", "Angerona - Watchdog"],
                          window="hidden",
                          running_probe=_cmdline_probe("status_ui", "watchdog",
                              expected_argv=[pyw, "-m", "angerona.resilience.status_ui", "watchdog"]))
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
                          running_probe=_cmdline_probe("status_ui", "scanner",
                              expected_argv=[pyw, "-m", "angerona.resilience.status_ui", "scanner"]))

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
            if self._sup.heartbeat_allowed():
                self._core_beat.beat()
            if tok.is_standdown_requested():
                self._publish("Resilience Manager", "Stand-down token present — stopping.", "MEDIUM")
                self.stop()
                return

    def _record_ring_gap(self, reason: str, *, missed: int = 0) -> None:
        self._ring_gap_observations = getattr(self, "_ring_gap_observations", 0) + 1
        coverage = getattr(self, "_ring_coverage", {})
        coverage.update(initial_continuity_verified=False,
                        rejection_observations=self._ring_gap_observations,
                        missed_frames_lower_bound=coverage.get("missed_frames_lower_bound", 0) + missed)
        self._ring_coverage = coverage
        total = self._ring_gap_observations
        if reason != getattr(self, "_ring_gap_reason", "") or total <= 3 or total & (total - 1) == 0:
            self._publish("Resilience Manager", "Telemetry ring coverage is incomplete: " + reason,
                          "HIGH", {**coverage, "reason": reason,
                                   "count_unit": "rejection/retry observations, not distinct events",
                                   "disposition": "health", "active_attack": False,
                                   "response_authorized": False})
        self._ring_gap_reason = reason

    def _admit_ring_reader(self) -> bool:
        if self._closed or self._ring_unretired_reader is not None:
            raise ipc_ring.FrameError("Telemetry reader admission is closed")
        candidate = ipc_ring.RingReader(ipc_ring.ring_path("telemetry"))
        with self._shutdown_lock:
            if not self._closed and not self._stop.is_set():
                self._reader = candidate
                return True
            try:
                candidate.close()
            except Exception as error:
                # Do not lose a late owned mapping or retry an ambiguous close.
                self._ring_unretired_reader = candidate
                self._ring_coverage.update(state="unavailable", close_unresolved=True)
                self._record_ring_gap("late reader close/" + type(error).__name__)
            return False

    def _ring_loop(self):
        while not self._stop.wait(self.ring_interval):
            now = time.monotonic()
            retry_at = getattr(self, "_ring_retry_at", 0.0)
            if self._reader is None and now >= retry_at:
                try:
                    admitted = self._admit_ring_reader()
                except Exception as error:
                    self._ring_retry_at = now + 30.0
                    self._ring_coverage["state"] = "unavailable"
                    self._record_ring_gap("reader admission/" + type(error).__name__)
                else:
                    if not admitted:
                        return
                    self._ring_coverage["state"] = "available"
            if self._stop.is_set():
                return
            before = int(getattr(self._reader, "authentication_failures", 0))
            batch = []
            if self._reader is not None and now >= getattr(self, "_ring_retry_at", 0.0):
                try:
                    batch = self._reader.read_batch(2048)
                except Exception as error:
                    # Retain this exact reader and its authenticated high-water.
                    # Recreating it on bad bytes would erase replay protection.
                    self._ring_retry_at = now + 30.0
                    self._ring_coverage["state"] = "unavailable"
                    self._record_ring_gap("reader observation/" + type(error).__name__)
                else:
                    self._ring_coverage["state"] = "available"
            after = int(getattr(self._reader, "authentication_failures", before))
            if after > before:
                self._ring_coverage["state"] = "degraded"
                self._record_ring_gap("rejected frame/header observations")
                self._record_ipc_rejection(after - before,
                    "frame authentication, sequence, or ring-header integrity observations")
            for fr in batch:
                missed = fr.get("missed", 0)
                if type(missed) is int and missed > 0:
                    self._record_ring_gap("authenticated sequence gap", missed=missed)
                self.frames_ingested += 1
                self._handle_frame(fr)
            self._drain_peer_alerts()

    def _drain_peer_alerts(self) -> None:
        """Publish each independent outbox before acknowledging its cursor."""
        now = time.monotonic()
        if now < getattr(self, "_peer_alert_due", 0.0):
            return
        self._peer_alert_due = now + 2.0
        try:
            if getattr(self, "_peer_alerts", None) is None:
                from angerona.resilience.peer_alerts import PeerAlertReader
                self._peer_alerts = PeerAlertReader()
            records = self._peer_alerts.peek()
        except Exception:
            records = []
        for record in records:
            details = dict(record.get("details") or {})
            details.pop("response_contract", None)
            details.update(peer_alert=True, observed_ts=record.get("ts"),
                           peer_source=record.get("source"), peer_record_id=record.get("id"),
                           peer_record_mac=record.get("mac"), disposition="observation",
                           active_attack=False, response_authorized=False)
            if not self._publish("Peer Watchdog", str(record.get("msg", "")),
                                 str(record.get("level", "HIGH")), details):
                break
            try:
                self._peer_alerts.ack(record)
            except Exception:
                # A delivered but unacknowledged row may repeat; retain its
                # original id/MAC so consumers can identify that delivery gap.
                break
        # One independent native chain/cursor cannot block Python peer delivery.
        try:
            if getattr(self, "_native_peer_alerts", None) is None:
                from angerona.resilience.native_watchdog import NativeAlertReader
                self._native_peer_alerts = NativeAlertReader()
            records = self._native_peer_alerts.peek()
        except Exception:
            records = []
        for record in records:
            details = dict(record.get("details") or {})
            details.pop("response_contract", None)
            details.update(peer_alert=True, native_watchdog=True,
                           observed_ts=record.get("ts"), peer_source=record.get("source"),
                           peer_record_id=record.get("id"), peer_record_mac=record.get("mac"),
                           disposition="observation", active_attack=False, response_authorized=False)
            if not self._publish("Native Third Watchdog", str(record.get("msg", "")),
                                 str(record.get("level", "HIGH")), details):
                break
            try:
                self._native_peer_alerts.ack(record)
            except Exception:
                break

    def _record_ipc_rejection(self, count: int, reason: str) -> None:
        self.frames_rejected += max(1, int(count))
        total = self.frames_rejected
        if total <= 3 or total & (total - 1) == 0:
            self._publish(
                "Resilience Manager",
                f"Authenticated IPC input rejected ({reason}); "
                f"{total} rejected frame(s) this run.",
                "HIGH",
                {"rejected_frames": total, "reason": reason,
                 "count_unit": "rejection observations, not distinct events",
                 "disposition": "health", "active_attack": False, "response_authorized": False},
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
            state = self._source_integrity.get("state")
            progress = self._sup.supervision_status()
            degraded = (state in {"changed", "unavailable"}
                        or progress["state"] not in {"starting", "running"}
                        or self._ring_coverage["state"] != "available")
            diag.write_status("core", "degraded" if degraded else "running", {
                "frames_ingested": self.frames_ingested,
                "frames_rejected": self.frames_rejected,
                "ring_coverage": dict(self._ring_coverage),
                "supervised": list(self._sup.components.keys()),
                "safe_mode": [n for n, c in self._sup.components.items() if c.safe_mode],
                "source_integrity": dict(self._source_integrity),
                "supervision_progress": progress,
                "native_watchdog": self._native_watchdog_status(),
            })

    def _native_watchdog_status(self) -> dict:
        """Observe on the status worker, never in a GUI refresh or core launch."""
        failure = getattr(self, "_unsigned_watchdog_start_failure", None)
        if type(failure) is dict:
            return dict(failure)
        try:
            if getattr(self, "_unsigned_watchdog_enabled", False):
                from angerona.resilience.native_watchdog import third_watchdog_status
                return third_watchdog_status()
            if getattr(self, "_native_watchdog_observer", None) is None:
                from angerona.resilience.native_watchdog import NativeWatchdogObserver
                self._native_watchdog_observer = NativeWatchdogObserver()
            return self._native_watchdog_observer.snapshot()
        except Exception:
            return {"state": "unavailable", "reason": "Native third-watchdog observation is unavailable"}

    def component_heartbeats(self) -> tuple[dict, ...]:
        cache = self._component_heartbeat_cache
        rows = cache.snapshot() if cache is not None else ()
        if getattr(self, "_unsigned_watchdog_enabled", False):
            failure = getattr(self, "_unsigned_watchdog_start_failure", None)
            if type(failure) is dict:
                row = {"role": "watchdog3", "state": "unavailable", "generation_id": "",
                       "pid": 0, "last_heartbeat_monotonic": None, "deadline_seconds": 10.0,
                       "reason": failure.get("reason", "Optional native monitor did not start")}
            else:
                from angerona.resilience.native_watchdog import third_watchdog_heartbeat
                row = third_watchdog_heartbeat()
            rows = (*rows, row)
        return rows

    def owned_process_identities(self) -> tuple:
        """Cached native context; no process/file query or lock on callers."""
        cache = self._component_heartbeat_cache
        return cache.owned_process_identities() if not self._stop.is_set() and cache is not None else ()

    def _capture_owned_process_scope(self, *, timeout: float = 1.0) -> tuple:
        """Capture strong native-owner/configuration references; no native I/O."""
        import math
        from angerona.core.windows_child_job import OwnedWindowsChild
        from angerona.core.windows_process_lease import ProcessObjectIdentity
        from angerona.resilience.component_status import ComponentHeartbeatCache, ROLES
        from angerona.telemetry.process_snapshot_worker import InventoryWorkerError, on_gui_thread

        if on_gui_thread() or os.name != "nt":
            raise InventoryWorkerError("Companion ownership requires a Windows background owner")
        if (type(timeout) not in (int, float) or not math.isfinite(timeout)
                or not 0 < timeout <= 1.0):
            raise InventoryWorkerError("Invalid companion ownership deadline")
        started = time.monotonic()
        if type(started) not in (int, float) or not math.isfinite(started) or started < 0:
            raise InventoryWorkerError("Companion ownership clock unavailable")
        deadline = started + timeout
        supervisor, cache = self._sup, self._component_heartbeat_cache
        if type(supervisor) is not ProcessSupervisor or type(cache) is not ComponentHeartbeatCache:
            raise InventoryWorkerError("Configured companion native owners are unavailable")

        def remaining():
            now = time.monotonic()
            if type(now) not in (int, float) or not math.isfinite(now) or not started <= now < deadline:
                raise InventoryWorkerError("Companion ownership observation deadline")
            return min(timeout, deadline - now)

        def current():
            if (self._stop.is_set() or self.status != "running" or self._sup is not supervisor
                    or self._component_heartbeat_cache is not cache
                    or supervisor._stop.is_set() or cache._stopped):
                raise InventoryWorkerError("Companion ownership lifetime is unavailable")

        current()
        if cache._owned_close_failure or cache._native_cleanup_failed_roles:
            raise InventoryWorkerError("Companion native observation cleanup remains unproven")
        if type(self.start_watchdog) is not bool or type(self.with_ui) is not bool:
            raise InventoryWorkerError("Configured companion roles are unavailable")
        configuration = tuple((role, cache._enabled.get(role), cache._expected.get(role))
                              for role in ROLES)
        if (any(type(enabled) is not bool or expected is not None and type(expected) is not tuple
                for _role, enabled, expected in configuration)
                or cache._enabled.get("core") is not True
                or cache._enabled.get("scanner") is not True):
            raise InventoryWorkerError("Configured companion roles are unavailable")
        if cache._enabled.get("watchdog") is True and not cache._expected.get("watchdog"):
            raise InventoryWorkerError("External watchdog has no retained native ownership provider")
        if cache._enabled.get("watchdog") is not self.start_watchdog:
            raise InventoryWorkerError("Configured watchdog ownership state is contradictory")
        required = {"scanner"}
        if cache._enabled.get("watchdog") is True:
            required.add("watchdog")
        if cache._enabled.get("blackbox") is True:
            required.add("blackbox")
        if self.with_ui:
            required.update(("watchdog_ui", "scanner_ui"))
        if not supervisor._lifecycle_lock.acquire(timeout=remaining()):
            raise InventoryWorkerError("Companion registry admission deadline")
        try:
            current()
            registry = supervisor.components
            if (type(registry) is not dict or not all(type(name) is str for name in registry)
                    or not required.issubset(registry)):
                raise InventoryWorkerError("Configured companion is missing its retained registry entry")
            entries = []
            for name, component in sorted(registry.items()):
                if (type(component) is not Component or component.name != name
                        or component._dead is not False or type(component.argv) is not list
                        or not component.argv or not all(type(arg) is str and arg for arg in component.argv)):
                    raise InventoryWorkerError("Configured companion registry is ambiguous")
                owner, native_state, alias = component.proc, None, None
                if owner is None:
                    alias = cache._authenticated_identities.get(name)
                    if type(alias) is not ProcessObjectIdentity:
                        raise InventoryWorkerError("Configured companion has no retained native custody: " + name[:32])
                else:
                    if type(owner) is not OwnedWindowsChild:
                        raise InventoryWorkerError("Configured companion has no retained native Job: " + name[:32])
                    if not owner._handle_lock.acquire(timeout=remaining()):
                        raise InventoryWorkerError("Companion native-owner admission deadline")
                    try:
                        process, job = owner._process, owner._job
                        handle = getattr(job, "_handle", None)
                        epoch = getattr(owner, "_owned_observation_epoch", None)
                        holds = getattr(owner, "_owned_observation_close_holds", None)
                        if (process is None or job is None or handle is None
                                or type(epoch) is not int or epoch < 0
                                or getattr(owner, "_owned_observation_stopped", None) is not False
                                or type(holds) is not list or holds):
                            raise InventoryWorkerError("Companion native custody is closed or uncertain")
                        try:
                            process_value, job_value = int(process), int(handle)
                        except Exception:
                            raise InventoryWorkerError("Companion retained native handle is not numeric") from None
                        if not 0 < process_value < 0xFFFFFFFFFFFFFFFF or not 0 < job_value < 0xFFFFFFFFFFFFFFFF:
                            raise InventoryWorkerError("Companion retained native handle is closed")
                        native_state = (id(process), process, id(job), job, id(handle), handle,
                                        owner.pid, epoch)
                    finally:
                        owner._handle_lock.release()
                entries.append((name, id(component), component, tuple(component.argv),
                                owner, native_state, alias))
            current()
            return (supervisor, cache, cache._owned_epoch, configuration, self.start_watchdog,
                    self.with_ui, id(registry), registry, tuple(entries))
        finally:
            supervisor._lifecycle_lock.release()

    def _owned_core_identity(self, cache, *, not_before: float):
        """Admit the existing cached Core observation without refreshing it."""
        from angerona.core.werfault_guard import OwnedProcessIdentity, read_owned_process_snapshot
        from angerona.telemetry.process_snapshot_worker import InventoryWorkerError

        rows = cache.owned_process_identities()
        if type(rows) is not tuple or any(type(row) is not OwnedProcessIdentity for row in rows):
            raise InventoryWorkerError("Retained Core native context is unavailable")
        core = tuple(row for row in rows if row.role == "core")
        checked = read_owned_process_snapshot(lambda: core, not_before=not_before,
                                              clock=time.monotonic).rows
        if (len(checked) != 1 or checked[0].pid != os.getpid()
                or checked[0].pid != self._owned_core_pid):
            raise InventoryWorkerError("Retained Core native identity differs from this process")
        return checked[0]

    def observe_owned_process_identities(self, *, timeout: float = 1.0) -> tuple:
        """Observe complete registered child Jobs and Core off Qt; never authorize.

        Native Job closure, not heartbeat health, includes redirectors and UI
        helpers. An authenticated role alias can only select an already-proved
        member. All original immutable two-second leases retain their expiry.
        """
        import math
        from angerona.core.werfault_guard import MAX_OWNED_PROCESSES, read_owned_process_snapshot
        from angerona.telemetry.process_snapshot_worker import InventoryWorkerError, on_gui_thread

        if on_gui_thread() or os.name != "nt":
            raise InventoryWorkerError("Companion ownership requires a Windows background owner")
        if (type(timeout) not in (int, float) or not math.isfinite(timeout)
                or not 0 < timeout <= 1.0):
            raise InventoryWorkerError("Invalid companion ownership deadline")
        started = time.monotonic()
        if type(started) not in (int, float) or not math.isfinite(started) or started < 0:
            raise InventoryWorkerError("Companion ownership clock unavailable")
        deadline = started + timeout

        def remaining():
            now = time.monotonic()
            if type(now) not in (int, float) or not math.isfinite(now) or not started <= now < deadline:
                raise InventoryWorkerError("Companion ownership observation deadline")
            return min(timeout, deadline - now)

        captured = self._capture_owned_process_scope(timeout=remaining())
        cache = captured[1]
        initial_core = self._owned_core_identity(cache, not_before=started)
        rows_by_pid = {initial_core.pid: initial_core}
        for name, _key, _component, _argv, owner, _native_state, _alias in captured[8]:
            if owner is None:
                continue
            rows = owner.observe_owned_process_identities(
                role=name.replace("_", "-"), timeout=remaining())
            # Each actual owner must return its complete sample before any
            # consistent overlap is deduplicated. No missing owner is skipped.
            for row in read_owned_process_snapshot(lambda: rows, not_before=started,
                                                   clock=time.monotonic).rows:
                prior = rows_by_pid.get(row.pid)
                if prior is not None:
                    if ((prior.birth_ticks, prior.image, prior.create_time)
                            != (row.birth_ticks, row.image, row.create_time)):
                        raise InventoryWorkerError("Companion native PID identity is contradictory")
                    if row.expires_monotonic < prior.expires_monotonic:
                        rows_by_pid[row.pid] = row  # Preserve an original, no-later expiry.
                else:
                    rows_by_pid[row.pid] = row
                if len(rows_by_pid) > MAX_OWNED_PROCESSES:
                    raise InventoryWorkerError("Complete companion ownership exceeds its bound")
        for name, _key, _component, _argv, owner, _native_state, alias in captured[8]:
            if owner is None:
                proved = rows_by_pid.get(alias.pid)
                if (proved is None or str(alias.birth_ticks) != proved.birth_ticks
                        or alias.image != proved.image or alias.create_time != proved.create_time):
                    raise InventoryWorkerError("Adopted companion is outside retained native Jobs: " + name[:32])
        if self._capture_owned_process_scope(timeout=remaining()) != captured:
            raise InventoryWorkerError("Companion registry or native owner changed during observation")
        current_core = self._owned_core_identity(cache, not_before=started)
        if ((initial_core.pid, initial_core.birth_ticks, initial_core.image, initial_core.create_time)
                != (current_core.pid, current_core.birth_ticks, current_core.image, current_core.create_time)):
            raise InventoryWorkerError("Core native generation changed during companion observation")
        remaining()
        return read_owned_process_snapshot(lambda: tuple(rows_by_pid.values()), not_before=started,
                                           clock=time.monotonic).rows

    def _owns_component_native_identity(self, role, identity) -> bool:
        """Background-only membership proof against a current retained owner."""
        from angerona.core.windows_child_job import OwnedWindowsChild

        if role not in {"watchdog", "scanner", "blackbox"} or self._stop.is_set():
            return False
        lock = getattr(self._sup, "_lifecycle_lock", None)
        if lock is None or not lock.acquire(blocking=False):
            return False
        try:
            component = self._sup.components.get(role)
            owner = getattr(component, "proc", None)
            return bool(component is not None and not component._dead
                        and type(owner) is OwnedWindowsChild and owner.contains_native_process(identity))
        finally:
            lock.release()

    def set_source_update_controller(self, owner):
        from angerona.core.source_activation import SourceActivationController
        if type(owner) is not SourceActivationController or self._stop.is_set():
            raise ValueError("Source-update observer needs its exact current controller")
        prior = getattr(self, "_source_update_controller", None)
        if prior is not None and prior is not owner:
            raise ValueError("Source-update observer cannot replace an active generation")
        self._source_update_controller = owner

    def _component_heartbeat_loop(self):
        cache = self._component_heartbeat_cache
        if cache is None:
            return
        external = getattr(self, "_source_update_controller", None)
        external_started = False
        try:
            if external is not None:
                try:
                    external.heartbeat_started(threading.current_thread())
                    external_started = True
                except Exception as exc:
                    self._source_update_observer_error = type(exc).__name__
            while not self._stop.wait(1.0):
                held = {}
                components = getattr(self._sup, "components", {})
                for role in ("watchdog", "scanner", "blackbox"):
                    component = components.get(role)
                    if component is not None and (component.safe_mode or component.state_fault):
                        held[role] = "Component recovery is held by authenticated supervisor safety state."
                if os.environ.get("ANGERONA_EXTERNAL_WATCHDOG") == "1":
                    held["watchdog"] = "The external native watchdog uses a separate protocol; no compatible component heartbeat is published."
                cache.sample(held=held)
                if external is not None and external_started:
                    try:
                        external.heartbeat_sample()
                    except Exception as exc:
                        self._source_update_observer_error = type(exc).__name__
                refresh = getattr(cache, "refresh_owned_processes", None)
                if callable(refresh):
                    refresh()
        except Exception as exc:
            self._publish("Component Heartbeats", "Read-only heartbeat observation is unavailable.",
                          "LOW", {"error_type": type(exc).__name__})
        finally:
            try:
                cache.close()
            except Exception as exc:
                self._publish("Component Heartbeats", "Read-only native observation handles could not all be released.",
                              "LOW", {"error_type": type(exc).__name__})
            if external is not None and external_started:
                try:
                    external.heartbeat_close()
                except Exception as exc:
                    self._publish("Source Update Progress", "Local observer query cleanup remains held.",
                                  "LOW", {"error_type": type(exc).__name__})

    def request_stop(self) -> None:
        self._stop.set()
        monitor = getattr(self, "_unsigned_watchdog", None)
        if monitor is not None:
            monitor.request_stop()
        external = getattr(self, "_source_update_controller", None)
        if external is not None:
            try:
                external.heartbeat_stop()
            except Exception as exc:
                self._source_update_observer_error = type(exc).__name__
        cache = self._component_heartbeat_cache
        if cache is not None:
            cache.mark_stopped()
        self._sup.request_stop()

    def stop(self, terminate_children: bool = False) -> None:
        self.request_stop()
        with self._shutdown_lock:
            monitor = getattr(self, "_unsigned_watchdog", None)
            if monitor is not None:
                monitor.stop()
            try:
                self._sup.stop(terminate_children=terminate_children)
            finally:
                if not self._closed:
                    self._closed = True
                    try:
                        self._core_beat.close()
                    finally:
                        if self._reader:
                            self._reader.close()
                        self.status = "stopped"


def start_resilience(bus=None, *, source_update_controller=None, **kw) -> ResilienceManager:
    """Convenience entry point for the Angerona core (call at launch)."""
    m = ResilienceManager(bus=bus, **kw)
    if source_update_controller is not None:
        m.set_source_update_controller(source_update_controller)
    m.start()
    return m


def self_test() -> tuple[bool, str]:
    """Live: start the manager (spawns a REAL scanner subprocess), confirm frames
    flow ring->core, a SECOND start does NOT duplicate the scanner (adopt), kill
    the scanner and confirm exactly one respawn, then stop."""
    from angerona.resilience._selftest_environment import run_isolated_selftest

    environment = lambda root: {
        "ANGERONA_DATA": str(root),
        "ANGERONA_DIAG_DIR": str(root / "diag"),
        "ANGERONA_SCANNER_INTERVAL": "0.2",
        "ANGERONA_SCANNER_UI": "0",
        # Never adopt or terminate the operator's live Black Box during this
        # isolated lifecycle test.
        "ANGERONA_BLACKBOX_ENABLED": "0",
    }

    return run_isolated_selftest(
        "manager", "mgr_selftest_", environment, timeout=45.0
    )


def _isolated_self_test() -> tuple[bool, str]:
    import subprocess, threading as _th
    from contextlib import nullcontext

    with nullcontext(Path(os.environ["ANGERONA_DATA"])) as work_root:
        workdir = str(work_root)
        custody = _OwnedSelfTestProcesses()

        class _Bus:
            def __init__(self): self.events = []
            def publish(self, ev): self.events.append(ev)

        bus = _Bus()
        mgr = ResilienceManager(bus=bus, heartbeat_interval=0.2, ring_interval=0.2,
                                start_watchdog=False, with_ui=False)
        churn_stop = _th.Event()
        churn_thread: _th.Thread | None = None
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
            churn_thread = _th.Thread(target=_churn, daemon=True)
            churn_thread.start()
            scanner = mgr._sup.components["scanner"]
            custody.capture(scanner.proc)
        # Detached Windows processes can take more than a second to reach their
        # first heartbeat while Defender/ETW inspects the new interpreter. Wait
        # for observable readiness and an actual ring frame instead of relying
        # on one fixed startup sleep.
            ready_deadline = time.time() + 15.0
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
            # A production supervisor intentionally keeps the cross-process
            # spawn claim for up to five seconds while a new child publishes
            # its authenticated heartbeat, then applies restart backoff.  The
            # previous assertion also called ``tick()`` from this thread while
            # the real supervisor thread was ticking, which could spend the
            # failure budget twice as fast and manufacture SAFE_MODE. Observe
            # the actual bounded lifecycle without injecting extra ticks.
            respawn_deadline = time.time() + 12.0
            while time.time() < respawn_deadline:
                time.sleep(0.3)
                custody.capture(scanner.proc)
                if scanner.restarts > before:
                    break
            respawn_ok = scanner.restarts == before + 1
            churn_stop.set()
            ok = alive_ok and ingested_ok and no_dup_ok and respawn_ok
            return ok, (f"scanner alive + {mgr.frames_ingested} frame(s) + no-duplicate adopt + "
                        f"single respawn" if ok else
                        f"failed: alive={alive_ok} ingested={ingested_ok} no_dup={no_dup_ok} "
                        f"respawn={respawn_ok} restarts={scanner.restarts} before={before} "
                        f"state={scanner.last_state} safe_mode={scanner.safe_mode} "
                        f"state_fault={scanner.state_fault}")
        finally:
            churn_stop.set()
            if churn_thread is not None:
                churn_thread.join(timeout=2.0)
            for component in mgr._sup.components.values():
                if component.name == "scanner":
                    custody.capture(component.proc)
            mgr.stop(terminate_children=True)
            custody.reap()


if __name__ == "__main__":
    print(self_test())
