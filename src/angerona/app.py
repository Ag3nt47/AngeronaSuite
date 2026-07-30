"""Application wiring: builds the core services and the GUI, and ties them
together. Keep this thin — real logic lives in core/ and modules/."""
from __future__ import annotations

from PySide6.QtWidgets import QApplication

from angerona.core.config import Config
from angerona.core.eventbus import EventBus
from angerona.core.storage import AsyncFlightRecorder, FlightRecorder
from angerona.core.module_manager import ModuleManager
from angerona.core.platforms import current_platform
from angerona.core.status_report import StatusReporter
from angerona.core.telemetry_coverage import TelemetryCoverageAccountant
from angerona.core.evidence_store import EvidenceStore
from angerona.core.evidence_ingestion import EvidenceIngestionWorker
from angerona.gui.main_window import MainWindow


class AngeronaApp:
    """Owns the lifecycle of every long-lived service."""

    def __init__(self, qt: QApplication) -> None:
        self.qt = qt
        self.config = Config.load()
        # Do not rewrite the highest-privilege Scheduled Task during ordinary
        # startup. That caused repeated Defender/UAC access prompts. Settings
        # changes registration only after an explicit operator toggle.
        self.storage = FlightRecorder(self.config.db_path)
        self.bus = EventBus()
        self.bus.arm(self.storage.authority)

        # Optional, offline normal-process learning. The EventBus callback only
        # performs a bounded put_nowait; signature verification, executable
        # hashing, Authenticode inspection, and authenticated state writes stay
        # on its dedicated worker. Observation never changes trust by itself.
        self.process_baseline = None
        try:
            from angerona.core.process_baseline import ProcessBaselineLearner

            self.process_baseline = ProcessBaselineLearner(
                self.config.data_dir,
                self.storage.authority,
                enabled=getattr(
                    self.config,
                    "process_baseline_enabled",
                    False,
                ),
            )
            self.bus.subscribe(self.process_baseline.submit_event)
            self.process_baseline.start()
        except Exception:
            self.process_baseline = None

        # The authoritative recorder batches signed events off producer
        # threads. Queue overflow is preserved in the authenticated append-only
        # dead-letter queue instead of stalling every sensor on SQLite.
        self.flight_recorder_worker = AsyncFlightRecorder(self.storage)
        self.flight_recorder_worker.start()
        self.bus.subscribe(self.flight_recorder_worker.submit)

        # Build the normalized hunt read-model asynchronously. EventBus invokes
        # subscribers inline, so this subscriber only performs a bounded
        # put_nowait; normalization, hashing, and SQLite work stay on the
        # dedicated local writer. Queue pressure is observable through metrics
        # and drops evidence-read-model copies rather than blocking protection.
        self.evidence_store = None
        self.evidence_ingestion = None
        try:
            self.evidence_store = EvidenceStore(
                self.config.data_dir / "normalized-evidence.db"
            )
            self.evidence_ingestion = EvidenceIngestionWorker(
                self.evidence_store
            )
            self.evidence_ingestion.start()
            self.bus.subscribe(self.evidence_ingestion.submit_event)
        except Exception:
            # The normalized read-model is additive. Its failure must not take
            # down the authoritative signed recorder or protection modules.
            if self.evidence_store is not None:
                try:
                    self.evidence_store.close()
                except Exception:
                    pass
            self.evidence_store = None
            self.evidence_ingestion = None

        # Account for sensor sequence continuity independently of conclusions.
        # Legacy sensors without sequence metadata remain explicitly "unknown".
        self.telemetry_coverage = TelemetryCoverageAccountant()
        self.bus.subscribe(self.telemetry_coverage.observe_event)

        # Correlate the flat event stream into scored incidents (O(1)/event).
        from angerona.core.incidents import get_correlator
        self.bus.subscribe(get_correlator().on_event)

        # Initialise the remediation audit log (same DB, separate table).
        from angerona.core.remediation_log import init_log
        init_log(self.config.db_path)

        # Initialise the ATT&CK heat tracker and wire it to every bus event.
        from angerona.core.attack_tracker import init_tracker
        self.bus.subscribe(init_tracker().on_event)

        self.manager  = ModuleManager(self.bus, self.config)
        self.reporter = StatusReporter(
            self.bus, self.storage, self.manager, self.config,
            telemetry_coverage=self.telemetry_coverage,
        )
        self._resilience = None
        self._fleet_plane = None
        self._fleet_service = None

        # MCP server — opt-in loopback tool server for Claude Desktop / Claude Code.
        # Exposes six read-only security-data tools; nothing leaves the machine.
        # Enable in Settings ▸ MCP, or set mcp_enabled=true in settings.json.
        self._mcp: object | None = None
        if getattr(self.config, "mcp_enabled", False):
            try:
                from angerona.engines.mcp_server import AngeronaMCPServer
                self._mcp = AngeronaMCPServer(
                    self.storage, self.bus, self.manager, self.config)
            except Exception:
                pass   # MCP failure must never block startup

        self.window = MainWindow(
            self.bus, self.storage, self.manager, self.config,
            evidence_store=self.evidence_store,
            evidence_ingestion=self.evidence_ingestion,
            flight_recorder_worker=self.flight_recorder_worker,
            process_baseline=self.process_baseline,
        )

    def start(self) -> None:
        # Show the window immediately so the user sees a responsive UI.
        # Module discovery (37 importlib.import_module calls) and thread
        # starts are deferred to a background thread via a zero-delay timer
        # so the event loop gets at least one paint cycle first.
        # The dashboard itself is the only content window created before the
        # global reveal coordinator becomes active. Route its first frame
        # through the same live-content line-to-window transition used by every
        # later Angerona window. Its close/minimize path remains owned by the
        # holographic orb so the two animations cannot compete.
        reveal = getattr(self.window, "_panel_reveal", None)
        if reveal is not None:
            setattr(self.window, "_angerona_reveal_open_only", True)

            def _show_dashboard():
                self.window.show()
                return self.window

            reveal.reveal(
                self.window,
                _show_dashboard,
                "#38bdf8",
            )
        else:
            self.window.show()
        self.qt.aboutToQuit.connect(self.shutdown)
        from PySide6.QtCore import QTimer
        # Let the window actually paint and become interactive before kicking off
        # the ~40-module import burst. A zero-delay timer can fire before the OS
        # has composited the first frame; a short delay guarantees a clean, centered
        # first paint so the app *feels* up immediately.
        QTimer.singleShot(120, self._deferred_start)
        # The resilience supervisor owns Black Box when enabled. Launching it here
        # as well raced the supervisor and created two 150 MB Qt processes. Retain
        # the direct launcher only for deliberately resilience-free operation.
        import os
        if os.environ.get("ANGERONA_RESILIENCE", "1").strip().lower() in (
            "0", "false", "no", "off"
        ):
            QTimer.singleShot(800, self._launch_blackbox)

    # ── Black Box diagnostic recorder (decoupled sidecar) ────────────────────
    def _launch_blackbox(self, force: bool = False) -> None:
        """Start blackbox_recorder.py as an independent, tray-resident process.

        Shares nothing with the suite (read-only file tailing) so we spawn it
        detached, with ``--show`` so its window actually appears. Its stdout/stderr
        are captured to ``<data_dir>/logs/blackbox.log`` so a startup crash is
        diagnosable, and a liveness check reports to the console if it dies fast
        (the usual cause: PySide6-Addons/QtCharts missing — now handled gracefully
        in the recorder itself). Single-instance guarded; fail-open."""
        if not force and not getattr(self.config, "blackbox_enabled", True):
            return
        try:
            import os
            import subprocess
            import sys
            from pathlib import Path
            from angerona.core.data_paths import project_root

            frozen = bool(getattr(sys, "frozen", False))
            bb = project_root() / (
                "AngeronaBlackBox.exe" if frozen else "blackbox_recorder.py"
            )
            if not bb.is_file():
                self._blackbox_note(f"{bb.name} not found — cannot launch.")
                return

            if frozen:
                from angerona.core.release_integrity import verify_frozen_blackbox
                if not verify_frozen_blackbox(bb):
                    self._blackbox_note(
                        "packaged Black Box is not in a protected Program Files "
                        "install or failed its embedded integrity check; refusing "
                        "to launch it.")
                    return

            # Single-instance guard: skip if a recorder is already running.
            if not force:
                try:
                    import psutil
                    me = os.getpid()
                    for p in psutil.process_iter(["pid", "cmdline"]):
                        if p.info["pid"] == me:
                            continue
                        cmdline = " ".join(p.info.get("cmdline") or []).lower()
                        if ("blackbox_recorder" in cmdline
                                or "angeronablackbox" in cmdline):
                            return   # already up — leave it
                except Exception:
                    pass

            # Prefer a windowless interpreter so no console flashes.
            creationflags = 0
            if sys.platform.startswith("win"):
                creationflags = 0x08000000  # CREATE_NO_WINDOW
            if frozen:
                command = [str(bb), "--show"]
            else:
                exe = sys.executable
                if sys.platform.startswith("win"):
                    pyw = Path(exe).with_name("pythonw.exe")
                    if pyw.exists():
                        exe = str(pyw)
                command = [exe, str(bb), "--show"]

            # Capture output so a crash-on-startup is recoverable.
            try:
                logdir = Path(self.config.data_dir) / "logs"
                logdir.mkdir(parents=True, exist_ok=True)
                logf = open(logdir / "blackbox.log", "ab", buffering=0)
            except Exception:
                logf = subprocess.DEVNULL

            self._blackbox_proc = subprocess.Popen(
                command,
                cwd=str(bb.parent),
                creationflags=creationflags,
                stdin=subprocess.DEVNULL,
                stdout=logf,
                stderr=logf,
                close_fds=True,
            )
            from PySide6.QtCore import QTimer
            QTimer.singleShot(3500, self._check_blackbox_alive)
        except Exception as exc:
            self._blackbox_note(f"failed to launch: {exc}")

    def _check_blackbox_alive(self) -> None:
        proc = getattr(self, "_blackbox_proc", None)
        if proc is None:
            return
        if proc.poll() is None:
            self._blackbox_note("recorder launched — check the system tray "
                                "(Angerona Black Box).")
            return
        code = proc.poll()
        tail = ""
        try:
            from pathlib import Path
            logp = Path(self.config.data_dir) / "logs" / "blackbox.log"
            if logp.exists():
                tail = logp.read_bytes()[-1400:].decode("utf-8", "replace").strip()
        except Exception:
            pass
        self._blackbox_note(
            f"recorder exited immediately (code {code}). Last output:\n"
            + (tail or "(no output captured — see logs/blackbox.log)"))

    def _blackbox_note(self, msg: str) -> None:
        try:
            self.window.console._append("[blackbox] " + msg)
        except Exception:
            pass

    def _deferred_start(self) -> None:
        """Called on the main thread after the first event-loop cycle.
        Spawns a background thread for the slow work so the GUI stays
        responsive while modules import and start."""
        import threading
        threading.Thread(target=self._load_modules, daemon=True,
                         name="ModuleLoader").start()

    def _load_modules(self) -> None:
        """Background thread — no Qt widget access here, only thread-safe
        bus/manager calls. Qt signals emitted by modules are automatically
        queued to the main thread by the Qt runtime."""
        # Bring the out-of-process watchdog and telemetry scanner online first.
        # They used to wait behind every module's initial scan, so during staged
        # startup their windows could appear minutes late (or not at all if one
        # sensor was slow). The core heartbeat now starts before supervision, so
        # early launch is safe and cannot create replacement Angerona instances.
        import os as _os
        _os.environ["ANGERONA_BLACKBOX_ENABLED"] = (
            "1" if getattr(self.config, "blackbox_enabled", True) else "0"
        )
        if (
            current_platform() == "windows"
            and _os.environ.get("ANGERONA_RESILIENCE", "1") not in (
                "0", "false", "no", "off"
            )
        ):
            try:
                from angerona.resilience.manager import start_resilience
                from angerona.resilience import shutdown_token as _tok
                _tok.clear_standdown()
                self._resilience = start_resilience(self.bus)
            except Exception:
                self._resilience = None

        self.manager.discover()        # find built-in + drop-in modules
        # In startup Eco Mode, do not start heavy scanners merely to stop them a
        # moment later. Their first scans were racing at boot and starving Qt.
        deferred = set()
        if getattr(self.config, "eco_mode", True):
            deferred.update(getattr(self.window, "_ECO_HEAVY_MODULES", ()))
        self.manager.start_enabled(deferred_names=deferred)
        # If the user's saved preference is Eco Mode, pause the heavy scanners now
        # (hops to the GUI thread via a queued signal — no widget access here).
        try:
            self.window.startup_eco_requested.emit()
        except Exception:
            pass
        self.reporter.start()          # begin writing diagnostics/status.txt
        # Start MCP server after modules are loaded so all tools have live data
        if self._mcp is not None:
            try:
                self._mcp.start()
            except Exception:
                self._mcp = None   # port bind failure → silently disable
        self._start_fleet_service()

    def _start_fleet_service(self) -> bool:
        """Start the opt-in, authenticated, loopback-only fleet endpoint."""
        if not getattr(self.config, "fleet_service_enabled", False):
            return False
        try:
            import hashlib
            import hmac
            import os

            secret = os.environ.get("ANGERONA_FLEET_SERVICE_KEY", "")
            if len(secret) < 32:
                raise ValueError("protected fleet service key is unavailable")
            service_key = hashlib.sha256(
                b"angerona-fleet-service-v1\0" + secret.encode("utf-8")
            ).digest()
            tenant_key = hmac.new(
                service_key,
                b"angerona-fleet-tenant-v1\0"
                + self.config.fleet_tenant_id.encode("utf-8"),
                hashlib.sha256,
            ).digest()
            from angerona.core.fleet_control_plane import FleetControlPlane
            from angerona.core.fleet_service import FleetLoopbackService

            self._fleet_plane = FleetControlPlane(
                self.config.data_dir / "fleet-control.db",
                {self.config.fleet_tenant_id: tenant_key},
            )
            self._fleet_service = FleetLoopbackService(
                self._fleet_plane,
                service_key,
                self.config.data_dir / "fleet-replay.json",
                port=self.config.fleet_service_port,
            )
            self._fleet_service.start()
            return True
        except Exception as exc:
            service, plane = self._fleet_service, self._fleet_plane
            self._fleet_service = None
            self._fleet_plane = None
            try:
                if service is not None:
                    service.stop()
            except Exception:
                pass
            try:
                if plane is not None:
                    plane.close()
            except Exception:
                pass
            self._blackbox_note(f"local fleet service unavailable: {exc}")
            return False

    def shutdown(self) -> None:
        # Clean shutdown: tell the ecosystem to STAND DOWN so the watchdog does
        # not resurrect the core, then stop the child processes. (A crash — with
        # no stand-down — leaves the watchdog free to restart everything.)
        if getattr(self, "_resilience", None) is not None:
            try:
                from angerona.resilience import shutdown_token as _tok
                _tok.request_standdown("angerona gui shutdown")
                self._resilience.stop(terminate_children=True)
            except Exception:
                pass
        self.reporter.stop()
        if self._mcp is not None:
            try:
                self._mcp.stop()
            except Exception:
                pass
        if self._fleet_service is not None:
            try:
                self._fleet_service.stop()
            except Exception:
                pass
            self._fleet_service = None
        if self._fleet_plane is not None:
            try:
                self._fleet_plane.close()
            except Exception:
                pass
            self._fleet_plane = None
        self.manager.stop_all()
        try:
            if self.process_baseline is not None:
                self.process_baseline.stop(timeout=2.0)
        except Exception:
            pass
        recorder_drained = False
        try:
            recorder_drained = self.flight_recorder_worker.stop(timeout=3.0)
        except Exception:
            pass
        # Producers are stopped before the normalized evidence worker drains.
        # The timeout prevents shutdown from hanging on damaged/locked storage.
        evidence_drained = self.evidence_ingestion is None
        try:
            if self.evidence_ingestion is not None:
                evidence_drained = self.evidence_ingestion.stop(
                    drain_timeout=3.0
                )
        except Exception:
            pass
        # Release Angerona's resident llama3 model immediately. Ollama normally
        # keeps models loaded for several minutes, which left its runner using
        # CPU/GPU after the GUI had closed. Keep the Ollama service itself alive
        # for other local applications and fail silently if it is unavailable.
        try:
            from angerona.core.ollama_lifecycle import unload_angerona_models
            unload_angerona_models(
                getattr(self.config, "ollama_host", "http://localhost:11434"),
                getattr(self.config, "ollama_model", "llama3"),
            )
        except Exception:
            pass
        # Never close a SQLite connection underneath a still-running writer.
        # If a bounded drain times out, process teardown will reclaim it; this
        # is safer than creating a worker/use-after-close race during shutdown.
        if recorder_drained:
            self.storage.close()
        try:
            if self.evidence_store is not None and evidence_drained:
                self.evidence_store.close()
        except Exception:
            pass
