"""Application wiring: builds the core services and the GUI, and ties them
together. Keep this thin — real logic lives in core/ and modules/."""
from __future__ import annotations

import threading

from PySide6.QtWidgets import QApplication

from angerona.core.config import Config
from angerona.core.eventbus import Event, EventBus, Severity
from angerona.core.independent_high_water import IndependentHighWater
from angerona.core.storage import AsyncFlightRecorder, FlightRecorder
from angerona.core.module_manager import ModuleManager
from angerona.core.platforms import current_platform
from angerona.core.status_report import StatusReporter
from angerona.core.telemetry_coverage import TelemetryCoverageAccountant
from angerona.core.evidence_store import EvidenceStore
from angerona.core.evidence_ingestion import EvidenceIngestionWorker
from angerona.gui.main_window import MainWindow


def _mark_dashboard_ready(config) -> bool:
    """Publish the source-launcher handshake only to the canonical log path."""
    import json
    import os
    import tempfile
    import time
    from pathlib import Path

    configured = str(os.environ.get("ANGERONA_STARTUP_READY", "")).strip()
    if not configured:
        return False
    expected = (Path(config.data_dir) / "logs" / "dashboard-ready.signal").resolve()
    requested = Path(configured).resolve()
    if requested != expected:
        return False
    try:
        requested.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(
            prefix=".dashboard-ready.", suffix=".tmp", dir=str(requested.parent)
        )
        tmp = Path(temporary)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump({"pid": os.getpid(), "ready_at": time.time()}, handle)
                handle.flush()
                os.fsync(handle.fileno())
            from angerona.core.atomic_io import replace_with_retry

            replace_with_retry(tmp, requested)
        finally:
            tmp.unlink(missing_ok=True)
        return True
    except OSError:
        return False


class AngeronaApp:
    """Owns the lifecycle of every long-lived service."""

    def __init__(
        self,
        qt: QApplication,
        *,
        force_chill: bool = False,
        live_debug: bool = False,
        high_water_provider: IndependentHighWater | None = None,
        startup_endpoint: str | None = None,
        process_snapshot_lifecycle=None,
    ) -> None:
        self.qt = qt
        # Production entry supplies a register-only owner before constructing
        # GUI readers. Direct/offline constructors do not create a collector.
        self._process_snapshot_lifecycle = process_snapshot_lifecycle
        self._startup_endpoint = startup_endpoint
        self._dashboard_ready_scheduled = False
        self._dashboard_ready_sent = False
        self._shutdown_requested = threading.Event()
        self._shutdown_gate = threading.Lock()
        self._startup_lifecycle_lock = threading.Lock()
        self.config = Config.load()
        # Native logon/launcher entry points pass --chill. This is a runtime
        # safety profile, not a rewrite of the operator's saved manual-launch
        # preference: a crash/restart during an unattended session therefore
        # always comes back network-first and low-impact.
        if force_chill:
            self.config.eco_mode = True
        # Publish Chill before any module can issue a background local-model
        # request. The GUI controller later owns transitions and sequential wake.
        import os
        from angerona.core.chill_mode import set_chill_ai_blocked
        set_chill_ai_blocked(self.config, bool(getattr(self.config, "eco_mode", True)))
        if getattr(self.config, "eco_mode", True):
            os.environ["ANGERONA_CHILL_ACTIVE"] = "1"
            setattr(self.config, "runtime_chill_active", True)
        else:
            os.environ.pop("ANGERONA_CHILL_ACTIVE", None)
            setattr(self.config, "runtime_chill_active", False)
        self._startup_degradations: list[Event] = []
        self._startup_events_ready = False
        # Do not rewrite the highest-privilege Scheduled Task during ordinary
        # startup. That caused repeated Defender/UAC access prompts. Settings
        # changes registration only after an explicit operator toggle.
        self.storage = FlightRecorder(self.config.db_path)
        self.bus = EventBus()
        self.bus.arm(self.storage.authority)

        self.live_debug_service = None

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
        except Exception as exc:
            self.process_baseline = None
            self._record_startup_degradation(
                "Process Baseline Learner",
                "normal-process learning is unavailable; protection remains active",
                exc,
            )

        # The authoritative recorder batches signed events off producer
        # threads. Queue overflow is preserved in the authenticated append-only
        # dead-letter queue instead of stalling every sensor on SQLite.
        self.flight_recorder_worker = AsyncFlightRecorder(self.storage)
        self.flight_recorder_worker.start()
        self.bus.subscribe(self.flight_recorder_worker.submit)
        self._startup_events_ready = True
        self._flush_startup_degradations()

        # Disposable diagnostics have independent, optional retention. The GUI
        # only queues bounded text; directory custody and cleanup stay here.
        self.alert_retention_worker = None
        try:
            from angerona.core.alert_retention import AlertRetentionWorker, RetentionPolicy
            self.alert_retention_worker = AlertRetentionWorker(
                self.config.data_dir, RetentionPolicy.from_config(self.config),
            )
            self.alert_retention_worker.start()
        except Exception as exc:
            self.alert_retention_worker = None
            self._record_startup_degradation(
                "Alert archive cleanup", "disposable diagnostic retention is unavailable", exc,
            )

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
        except Exception as exc:
            # The normalized read-model is additive. Its failure must not take
            # down the authoritative signed recorder or protection modules.
            if self.evidence_store is not None:
                try:
                    self.evidence_store.close()
                except Exception:
                    pass
            self.evidence_store = None
            self.evidence_ingestion = None
            self._record_startup_degradation(
                "Normalized Evidence Store",
                "structured hunting is unavailable; the signed recorder remains authoritative",
                exc,
            )

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

        self.manager  = ModuleManager(
            self.bus,
            self.config,
            recorder=self.storage,
            high_water_provider=high_water_provider,
        )
        self.manager.live_debug_service = self.live_debug_service
        # SentinelLens is an additive, local-only read model. Its EventBus
        # subscriber performs only a bounded put_nowait; deterministic parsing,
        # graph construction, and anomaly scoring run on the owned worker.
        self.sentinel_lens_service = None
        try:
            from angerona.core.sentinel_lens import SentinelLensService

            self.sentinel_lens_service = SentinelLensService(self.bus)
            self.sentinel_lens_service.start()
            # Tool windows already receive the manager. Publish only the safe
            # read-side service facade there, not an execution capability.
            self.manager.sentinel_lens_service = self.sentinel_lens_service
        except Exception as exc:
            self.sentinel_lens_service = None
            self._record_startup_degradation(
                "SentinelLens",
                "continuous local hunt snapshots are unavailable; protection remains active",
                exc,
            )
        self.reporter = StatusReporter(
            self.bus, self.storage, self.manager, self.config,
            telemetry_coverage=self.telemetry_coverage,
        )
        self._resilience = None
        self._fleet_plane = None
        self._fleet_service = None
        self._admin_audit = None
        self._endpoint_identity = None

        # MCP server — opt-in loopback tool server for Claude Desktop / Claude Code.
        # Exposes six read-only security-data tools; nothing leaves the machine.
        # Enable in Settings ▸ MCP, or set mcp_enabled=true in settings.json.
        self._mcp: object | None = None
        if getattr(self.config, "mcp_enabled", False):
            try:
                from angerona.engines.mcp_server import AngeronaMCPServer
                self._mcp = AngeronaMCPServer(
                    self.storage, self.bus, self.manager, self.config)
            except Exception as exc:
                self._record_startup_degradation(
                    "Model Context Protocol Server",
                    "the optional local tool server could not be prepared",
                    exc,
                )

        # Authenticated JARVIS control is deliberately separate from read-only
        # MCP. It exposes only confirmation-gated, local defensive scans.
        self._jarvis_control: object | None = None
        if getattr(self.config, "jarvis_control_enabled", False):
            try:
                from angerona.engines.jarvis_control_server import (
                    AngeronaJarvisControlServer,
                )
                self._jarvis_control = AngeronaJarvisControlServer(
                    self.manager, self.config
                )
                # Publish the bounded adapter immediately.  This keeps the
                # standalone Angerona GUI independent: it never launches or
                # activates JARVIS, but JARVIS can connect later if the user
                # has opened it separately.  Module counts fill in as normal
                # background discovery completes.
                self._jarvis_control.start()
            except Exception as exc:
                self._jarvis_control = None
                self._record_startup_degradation(
                    "JARVIS Control Adapter",
                    "the optional authenticated defensive control channel could not start",
                    exc,
                )

        self.runtime_metrics = None
        self.runtime_metrics_publisher = None
        if os.environ.get("ANGERONA_RUNTIME_METRICS") == "1":
            from angerona.core.runtime_metrics import RuntimeMetrics, optional_publisher
            self.runtime_metrics = RuntimeMetrics(
                gui=True, recorder=self.flight_recorder_worker,
                evidence=self.evidence_ingestion, retention=self.alert_retention_worker,
            )
            self.runtime_metrics_publisher = optional_publisher(self.runtime_metrics, self.config.data_dir)

        self.window = MainWindow(
            self.bus, self.storage, self.manager, self.config,
            evidence_store=self.evidence_store,
            evidence_ingestion=self.evidence_ingestion,
            flight_recorder_worker=self.flight_recorder_worker,
            process_baseline=self.process_baseline,
            alert_retention_worker=self.alert_retention_worker,
            runtime_metrics=self.runtime_metrics,
            shutdown_prepare=self.prepare_shutdown,
            shutdown_callback=self.shutdown,
        )
        # Settings consumes only this bounded, privacy-safe status provider; it
        # never receives fleet service keys or endpoint private-key material.
        self.window.enterprise_runtime_provider = self.enterprise_runtime_snapshot
        orb = getattr(self.window, "_holographic_orb", None)
        if orb is not None:
            orb.set_service_status_source(self._orb_cached_service_statuses)
        # Open sharing only after all mandatory construction has succeeded. A
        # failed constructor must not leave a live endpoint with no App owner.
        self._start_live_debug(live_debug)

    def _orb_cached_service_statuses(self) -> dict:
        """Expose existing manager/supervisor fields without host I/O or locks.

        Supervisor states have no observation timestamp. The presentation must
        retain unknown age and may never treat this copy as fresh attestation.
        """
        unknown = {
            "state": "unknown", "age_seconds": None,
            "reason": "No running resilience supervisor supplies cached status.",
            "scope": "Cached supervisor state only; current process liveness and detector coverage are unverified.",
        }
        result = {name: dict(unknown) for name in ("core", "watchdog", "scanner", "blackbox")}
        manager = getattr(self, "manager", None)
        if getattr(manager, "_shutdown", False) is True:
            state, reason = "stopped", "The module manager has requested shutdown."
        elif getattr(manager, "ugcap_paused", False) is True:
            state, reason = "held", "UGCAP verification holds ordinary managed workers."
        elif getattr(manager, "_runtime_active", False) is True:
            state, reason = "running", "The module manager's runtime is active."
        else:
            state, reason = "unknown", "Managed runtime startup has not been confirmed."
        result["core"] = {
            "state": state, "reason": reason, "age_seconds": None,
            "scope": "In-process manager state; individual detector health and scan coverage are not assessed.",
        }
        resilience = getattr(self, "_resilience", None)
        if resilience is None or getattr(resilience, "status", None) != "running":
            return result
        components = getattr(getattr(resilience, "_sup", None), "components", None)
        if not isinstance(components, dict):
            return result
        try:
            # Fixed-name lookups avoid concurrent dictionary iteration and do
            # not call a process probe, heartbeat reader or persisted status.
            for name in ("watchdog", "scanner", "blackbox"):
                component = components.get(name)
                if component is None:
                    continue
                if name == "blackbox" and getattr(self.config, "blackbox_enabled", True) is not True:
                    result[name]["reason"] = "Black Box is disabled in settings; process liveness is unverified."
                    continue
                cached = getattr(component, "last_state", "unknown")
                cached = cached if isinstance(cached, str) else "unknown"
                if (getattr(component, "safe_mode", False) is True
                        or getattr(component, "state_fault", False) is True):
                    state, reason = "degraded", "Supervisor recovery is held in safe mode or has a state fault."
                elif cached in {"alive", "dead", "suspended", "stopped"}:
                    state, reason = cached, f"The supervisor's last cached state was {cached}."
                elif cached.startswith("unauthenticated_") or cached == "legacy_unverified":
                    state, reason = "degraded", "The supervisor could not authenticate component status."
                else:
                    state, reason = "unknown", "The supervisor has no recognized cached observation."
                result[name] = dict(unknown, state=state, reason=reason)
            if (resilience is not getattr(self, "_resilience", None)
                    or getattr(resilience, "status", None) != "running"):
                raise RuntimeError("resilience owner changed")
        except (AttributeError, RuntimeError):
            for name in ("watchdog", "scanner", "blackbox"):
                result[name] = dict(unknown)
        return result

    def _start_live_debug(self, requested: bool = False) -> None:
        """Start the optional, outbound diagnostic copy after construction."""
        try:
            from angerona.core.live_debug import LiveDebugService

            self.live_debug_service = LiveDebugService(
                self.bus, self.config.data_dir,
                enabled=(requested or getattr(self.config, "live_debug_enabled", False)),
            )
            started = self.live_debug_service.start()
            self.manager.live_debug_service = self.live_debug_service
            status = self.live_debug_service.status()
            if status.get("enabled") and not started:
                self._record_startup_degradation(
                    "Live debug harness", "live diagnostic sharing is unavailable",
                    RuntimeError(status.get("error", "debug service did not start")),
                )
        except Exception as exc:
            if self.live_debug_service is not None:
                try:
                    self.live_debug_service.stop(timeout=1.0)
                except Exception:
                    pass
            self._record_startup_degradation(
                "Live debug harness", "live diagnostic sharing is unavailable", exc,
            )

    def _record_startup_degradation(
        self,
        service: str,
        impact: str,
        exc: BaseException,
        severity: Severity = Severity.MEDIUM,
    ) -> None:
        """Expose startup failures without leaking paths, secrets, or raw errors."""
        event = Event(
            module="Startup Health",
            severity=severity,
            message=f"{service} degraded: {impact}.",
            details={
                "service": str(service)[:120],
                "impact": str(impact)[:300],
                "error_type": type(exc).__name__[:120],
                "startup_degraded": True,
            },
        )
        if getattr(self, "_startup_events_ready", False):
            bus = getattr(self, "bus", None)
            if bus is not None:
                bus.publish(event)
                return
        pending = getattr(self, "_startup_degradations", None)
        if pending is None:
            self._startup_degradations = [event]
        else:
            pending.append(event)

    def _flush_startup_degradations(self) -> None:
        bus = getattr(self, "bus", None)
        if bus is None:
            return
        pending = list(getattr(self, "_startup_degradations", ()))
        self._startup_degradations = []
        for event in pending:
            bus.publish(event)

    def start(self) -> bool:
        import os
        from angerona.resilience import shutdown_token

        # Only an explicit operator launch can resume after STOP. Automatic
        # children retain the inhibit flag even if their launch was in flight.
        if os.environ.get("ANGERONA_SUPERVISED_RECOVERY") == "1":
            if shutdown_token.is_standdown_requested():
                shutdown_token.signal_external_watchdog_stop()
                return False
        else:
            shutdown_token.clear_standdown(strict=True)
            if shutdown_token.is_standdown_requested():
                raise RuntimeError("Explicit launch could not clear the authenticated operator STOP.")
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
                self._schedule_dashboard_ready()
                return self.window

            reveal.reveal(
                self.window,
                _show_dashboard,
                "#38bdf8",
            )
        else:
            self.window.show()
            self._schedule_dashboard_ready()
        self.qt.aboutToQuit.connect(self.shutdown)
        from PySide6.QtCore import QTimer
        if os.environ.get("ANGERONA_SUPERVISED_RECOVERY") == "1":
            # Covers a native-parent launch already past its admission check
            # when the previous core saves STOP. This child may never revive it.
            self._operator_stop_timer = QTimer(self.window)
            self._operator_stop_timer.setInterval(250)
            self._operator_stop_timer.timeout.connect(self._honor_operator_stop)
            self._operator_stop_timer.start()
        # Let the window actually paint and become interactive before kicking off
        # the ~40-module import burst. A zero-delay timer can fire before the OS
        # has composited the first frame; a short delay guarantees a clean, centered
        # first paint so the app *feels* up immediately.
        QTimer.singleShot(120, self._deferred_start)
        # The saved startup choice is explicit operator consent. Repair a
        # missing/stale native entry off the GUI thread so upgrades and moved
        # source checkouts still start quietly at sign-in.
        if getattr(self.config, "autostart_enabled", True):
            QTimer.singleShot(1500, self._ensure_autostart_async)
        # The resilience supervisor owns Black Box when enabled. Launching it here
        # as well raced the supervisor and created two 150 MB Qt processes. Retain
        # the direct launcher only for deliberately resilience-free operation.
        import os
        if os.environ.get("ANGERONA_RESILIENCE", "1").strip().lower() in (
            "0", "false", "no", "off"
        ):
            QTimer.singleShot(800, self._launch_blackbox)
        return True

    def _honor_operator_stop(self) -> None:
        from angerona.resilience.shutdown_token import is_standdown_requested

        if is_standdown_requested():
            self._operator_stop_timer.stop()
            self.window._terminate()

    def _schedule_dashboard_ready(self) -> None:
        """Allow a shown dashboard to paint before reporting it to the helper."""
        if getattr(self, "_dashboard_ready_scheduled", False):
            return
        self._dashboard_ready_scheduled = True
        from PySide6.QtCore import QTimer

        QTimer.singleShot(250, self._dashboard_ready_after_paint)

    def _dashboard_ready_after_paint(self) -> None:
        if getattr(self, "_dashboard_ready_sent", False):
            return
        if self._startup_cancelled():
            return
        try:
            if not self.window.isVisible():
                return
        except RuntimeError:
            # The native widget may have been destroyed while startup waited.
            return
        self._dashboard_ready_sent = True
        threading.Thread(
            target=self._publish_dashboard_ready,
            name="DashboardReadyNotifier",
            daemon=True,
        ).start()

    def _publish_dashboard_ready(self) -> None:
        """Keep socket waits and legacy filesystem handshakes off the UI thread."""
        from angerona.core.startup_protocol import notify_dashboard_ready

        endpoint = getattr(self, "_startup_endpoint", None)
        if endpoint is not None:
            notify_dashboard_ready(endpoint)
        _mark_dashboard_ready(self.config)

    def _ensure_autostart_async(self) -> None:
        import threading

        def _repair() -> None:
            try:
                from angerona.core.autostart import enable_autostart, is_enabled
                if is_enabled() is not True:
                    enable_autostart()
            except Exception:
                # Settings exposes the detected state and manual retry. Startup
                # registration failure must never take down protection.
                pass

        threading.Thread(
            target=_repair,
            name="AutostartReconciler",
            daemon=True,
        ).start()

    # ── Black Box diagnostic recorder (decoupled sidecar) ────────────────────
    def _launch_blackbox(self, force: bool = False) -> None:
        """Start blackbox_recorder.py as an independent, tray-resident process.

        Shares nothing with the suite (read-only file tailing) so we spawn it
        detached, with ``--show`` so its window actually appears. Black Box owns
        its startup crash log; a liveness check reports to the console if it dies fast
        (the usual cause: PySide6-Addons/QtCharts missing — now handled gracefully
        in the recorder itself). Single-instance guarded; fail-open."""
        if self._startup_cancelled():
            return
        import sys
        if not sys.platform.startswith("win"):
            # The existing decoupled recorder consumes Windows watchdog/ETW
            # evidence. A missing .exe in a POSIX frozen build is not a fault.
            return
        if not force and not getattr(self.config, "blackbox_enabled", True):
            return
        try:
            from pathlib import Path
            from angerona.core.data_paths import project_root
            from angerona.resilience.supervisor import spawn_detached

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

            # Prefer a windowless interpreter so no console flashes.
            if frozen:
                command = [str(bb), "--show"]
            else:
                exe = sys.executable
                if sys.platform.startswith("win"):
                    pyw = Path(exe).with_name("pythonw.exe")
                    if pyw.exists():
                        exe = str(pyw)
                command = [exe, str(bb), "--show"]

            if not force:
                from angerona.resilience.supervisor import cached_cmdline_probe
                expected = command[:1] if frozen else command[:2]
                if cached_cmdline_probe(expected_argv=expected)():
                    return

            self._blackbox_proc = spawn_detached(command, cwd=str(bb.parent), window="hidden")
            if self._startup_cancelled():
                self._blackbox_proc.terminate()
                self._blackbox_proc.wait(timeout=3.0)
                self._blackbox_proc.wait_tree(timeout=3.0)
                self._blackbox_proc.close()
                self._blackbox_proc = None
                return
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
            for logp in (
                Path(self.config.data_dir) / "diagnostics" / "blackbox_startup.log",
                Path(self.config.data_dir) / "blackbox_startup.log",
                Path(self.config.data_dir) / "logs" / "blackbox.log",
            ):
                if logp.is_file():
                    with logp.open("rb") as stream:
                        stream.seek(max(0, logp.stat().st_size - 1400))
                        tail = stream.read(1400).decode("utf-8", "replace").strip()
                    break
        except Exception:
            pass
        self._blackbox_note(
            f"recorder exited immediately (code {code}). Last output:\n"
            + (tail or "(see diagnostics/blackbox_startup.log)"))

    def _blackbox_note(self, msg: str) -> None:
        try:
            self.window.console._append("[blackbox] " + msg)
        except Exception:
            pass

    def _deferred_start(self) -> None:
        """Called on the main thread after the first event-loop cycle.
        Spawns a background thread for the slow work so the GUI stays
        responsive while modules import and start."""
        if self._startup_cancelled():
            return
        from angerona.core.ollama_lifecycle import request_ollama_start
        request_ollama_start(
            self.config.ollama_host,
            stop_event=getattr(self, "_shutdown_requested", None),
        )
        from angerona.gui.animations import begin_loading

        token = begin_loading("Preparing protection services…")
        self._startup_loading_token = token
        threading.Thread(target=self._load_modules_guarded, args=(token,), daemon=True,
                         name="ModuleLoader").start()

    def _load_modules_guarded(self, loading_token: str | None = None) -> None:
        """Keep a loader failure observable instead of losing a daemon thread."""
        try:
            inventory = getattr(self, "_process_snapshot_lifecycle", None)
            if inventory is not None and not self._startup_cancelled():
                inventory.start()
                ready = inventory.wait_started()
                if not ready and not self._startup_cancelled():
                    self._record_startup_degradation(
                        "Process Inventory",
                        "isolated inventory is unavailable; local fallback is disabled",
                        RuntimeError("process inventory did not become ready"),
                    )
            # Waiting for the child happens before the startup/teardown lock,
            # so a closing GUI never waits for native bootstrap to finish.
            lifecycle_lock = getattr(self, "_startup_lifecycle_lock", None)
            if lifecycle_lock is None:
                self._load_modules()
            else:
                with lifecycle_lock:
                    if not self._startup_cancelled():
                        self._load_modules()
        except Exception as exc:
            self._record_startup_degradation(
                "Protection Module Loader",
                "module discovery or startup stopped before completion",
                exc,
                Severity.CRITICAL,
            )
            self._blackbox_note(
                "protection module loading failed; open Startup Health in Live Alerts"
            )
        finally:
            if loading_token:
                from angerona.gui.animations import finish_loading

                finish_loading(loading_token)
                self._startup_loading_token = None

    def _startup_cancelled(self) -> bool:
        requested = getattr(self, "_shutdown_requested", None)
        if requested is not None and requested.is_set():
            return True
        from angerona.resilience.shutdown_token import is_standdown_requested
        return is_standdown_requested()

    def _load_modules(self) -> None:
        """Background thread — no Qt widget access here, only thread-safe
        bus/manager calls. Qt signals emitted by modules are automatically
        queued to the main thread by the Qt runtime."""
        from angerona.gui.animations import update_loading

        if self._startup_cancelled():
            return

        loading_token = getattr(self, "_startup_loading_token", None)

        def _loading(label: str, done: int = 0, total: int = 0) -> None:
            if loading_token:
                update_loading(loading_token, label, done=done, total=total)

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
            _loading("Starting recovery and watchdog services…")
            try:
                from angerona.resilience.manager import start_resilience
                # In Chill the real watchdog and scanner still run, but their
                # two standalone Qt status windows are redundant: the orb and
                # Console already expose the same live status on demand. Not
                # spawning those idle windows saves two full Qt processes and
                # hundreds of MB while preserving supervision and telemetry.
                self._resilience = start_resilience(
                    self.bus,
                    with_ui=not bool(
                        getattr(
                            self.config,
                            "runtime_chill_active",
                            getattr(self.config, "eco_mode", True),
                        )
                    ),
                )
            except Exception as exc:
                self._resilience = None
                self._record_startup_degradation(
                    "Resilience Supervisor",
                    "watchdog, scanner, or Black Box supervision is unavailable",
                    exc,
                    Severity.HIGH,
                )

        if self._startup_cancelled():
            return

        _loading("Discovering protection modules…")
        self.manager.discover()        # find built-in + drop-in modules
        if self._startup_cancelled():
            return
        mark_operations_discovered = getattr(
            self.window, "_mark_operations_modules_discovered", None
        )
        compose_operations = getattr(
            self.window, "_ensure_operations_service", None
        )
        # Discovery and composition are a single startup barrier. The service
        # publishes UI readiness only after both live module bindings succeed.
        if not callable(mark_operations_discovered) or not callable(
            compose_operations
        ):
            self._record_startup_degradation(
                "Local SOC Runtime Composition",
                "authoritative fleet and detection binding is unavailable",
                RuntimeError("operations composition boundary is unavailable"),
                Severity.HIGH,
            )
            return
        mark_operations_discovered()
        try:
            compose_operations(startup_owner=True, wait=True)
        except Exception as exc:
            self._record_startup_degradation(
                "Local SOC Runtime Composition",
                "fleet and detection observers could not bind authoritative local stores",
                exc,
                Severity.HIGH,
            )
            return
        if self._startup_cancelled():
            return
        # In startup Chill Mode, do not start deep scanners merely to stop them a
        # moment later. Their first scans were racing at boot and starving Qt.
        deferred = set()
        if getattr(self.config, "eco_mode", True):
            deferred.update(getattr(self.window, "_ECO_HEAVY_MODULES", ()))
        enabled_total = (
            sum(
                1 for name in self.manager.modules
                if self.manager.is_enabled(name) and name not in deferred
            )
            if isinstance(self.manager, ModuleManager)
            else 0
        )
        _loading("Bringing protection modules online…", 0, enabled_total)

        def _module_progress(done: int, total: int, name: str) -> None:
            _loading(f"Bringing {name} online…", done, total)

        if isinstance(self.manager, ModuleManager):
            self.manager.start_enabled(
                deferred_names=deferred,
                progress=_module_progress,
            )
        else:
            # Lightweight test/dry-run managers may implement the older,
            # narrower call surface. Production always uses ModuleManager.
            self.manager.start_enabled(deferred_names=deferred)
        if self._startup_cancelled():
            return
        # Establish the saved Chill policy now (sentinel cadence + model release)
        # (hops to the GUI thread via a queued signal — no widget access here).
        try:
            self.window.startup_eco_requested.emit()
        except Exception:
            pass
        if self._startup_cancelled():
            return
        _loading("Starting status reporting…")
        self.reporter.start()          # begin writing diagnostics/status.txt
        self._start_runtime_healer()
        if self._startup_cancelled():
            return
        # Start MCP server after modules are loaded so all tools have live data
        if self._mcp is not None:
            try:
                self._mcp.start()
            except Exception as exc:
                self._mcp = None
                self._record_startup_degradation(
                    "Model Context Protocol Server",
                    "the optional local tool server could not start",
                    exc,
                )
        if self._startup_cancelled():
            return
        _loading("Finalizing protection services…")
        self._start_fleet_service()

    def _start_runtime_healer(self) -> None:
        """Supervise essential local workers after their normal startup."""
        if self._startup_cancelled() or getattr(self, "_runtime_healer", None) is not None:
            return
        try:
            from angerona.core.runtime_healer import RuntimeHealer

            healer = RuntimeHealer(
                self.reporter, self.flight_recorder_worker, self.bus, self.config,
            )
            self.reporter.runtime_healer = healer
            healer.start()
            self._runtime_healer = healer
        except Exception as exc:
            self.reporter.runtime_healer = None
            self._record_startup_degradation(
                "Runtime Self-Healing",
                "automatic status and recorder worker recovery is unavailable",
                exc,
            )

    def _start_fleet_service(self) -> bool:
        """Start the opt-in, authenticated, loopback-only fleet endpoint."""
        if not getattr(self.config, "fleet_service_enabled", False):
            return False
        if not hasattr(self, "_admin_audit"):
            self._admin_audit = None
        try:
            import hashlib
            import hmac
            import base64
            import os
            import platform
            import socket
            import time

            from angerona import __version__
            from angerona.core.endpoint_identity import EndpointIdentity
            from angerona.core.fleet_control_plane import (
                FleetControlPlane,
                FleetDevice,
            )
            from angerona.core.fleet_credentials import (
                LEGACY_FLEET_SERVICE_KEY,
                load_or_migrate_local_credentials,
            )
            from angerona.core.fleet_service import (
                FLEET_DEVICE_PERMISSIONS,
                FLEET_TENANT_PERMISSIONS,
                FleetLoopbackService,
            )
            from angerona.core.admin_audit import AdminAuditLedger
            from angerona.core.authorization import (
                AuthorizationPolicy,
                Principal,
                PrincipalKind,
                Role,
                RoleBinding,
            )

            self._endpoint_identity = EndpointIdentity(
                self.config.data_dir / "identity"
            )
            identity = self._endpoint_identity
            # A fleet key is durable authority. Never accept it from a wrapper's
            # inherited environment; migration reads only the OS-protected store.
            os.environ.pop(LEGACY_FLEET_SERVICE_KEY, None)
            credential_set = load_or_migrate_local_credentials(
                self.config.data_dir,
                self.config.fleet_tenant_id,
                identity.device_id,
            )
            tenant_key = credential_set.receipt_signing_key
            self._fleet_plane = FleetControlPlane(
                self.config.data_dir / "fleet-control.db",
                {self.config.fleet_tenant_id: tenant_key},
            )
            hostname_token = "tok_" + hmac.new(
                tenant_key,
                b"angerona-hostname-v1\0"
                + socket.gethostname().encode("utf-8", errors="replace"),
                hashlib.sha256,
            ).hexdigest()[:48]
            desired_state = (
                "revoked" if identity.revoked
                else "quarantined" if identity.quarantined
                else "active"
            )
            existing = next((
                item for item in self._fleet_plane.devices(
                    self.config.fleet_tenant_id
                ) if item.device_id == identity.device_id
            ), None)
            current_state = existing.state if existing is not None else "active"
            self._fleet_plane.register_device(FleetDevice(
                tenant_id=self.config.fleet_tenant_id,
                device_id=identity.device_id,
                public_key=base64.urlsafe_b64encode(
                    identity.public_key
                ).decode("ascii").rstrip("="),
                hostname_token=hostname_token,
                platform=platform.system().casefold()[:40] or "unknown",
                version=__version__,
                state=current_state,
            ))
            if desired_state != current_state:
                restrictive = {
                    "active": {"quarantined", "revoked"},
                    "quarantined": {"revoked"},
                    "revoked": set(),
                    "retired": set(),
                }
                if desired_state in restrictive[current_state]:
                    self._fleet_plane.transition_device_state(
                        self.config.fleet_tenant_id,
                        identity.device_id,
                        desired_state,
                        expected_state=current_state,
                    )
            credentials = credential_set.registry
            audit_key = credential_set.authorization_audit_key
            self._admin_audit = AdminAuditLedger(
                self.config.data_dir / "admin-audit.db", audit_key
            )
            authenticated_at = time.time()
            # Principal authority must never outlive the durable credentials
            # that authenticated it.  In particular, restarting Angerona must
            # not roll a fresh one-year principal expiry forward indefinitely.
            authorization_expiry = min(
                credential_set.operator.expires_at,
                credential_set.device.expires_at,
            )
            if authorization_expiry <= authenticated_at:
                raise RuntimeError("local fleet credentials have expired")
            operator_context = credential_set.operator.authenticated_context(
                authenticated_at
            )
            device_context = credential_set.device.authenticated_context(
                authenticated_at
            )
            authorization_policy = AuthorizationPolicy(
                (
                    Principal(
                        operator_context.principal_id,
                        PrincipalKind.SERVICE,
                        expires_at=authorization_expiry,
                    ),
                    Principal(
                        device_context.principal_id,
                        PrincipalKind.SERVICE,
                        expires_at=authorization_expiry,
                    ),
                ),
                (
                    Role("fleet-local-operator", FLEET_TENANT_PERMISSIONS),
                    Role("fleet-local-device", FLEET_DEVICE_PERMISSIONS),
                ),
                (
                    RoleBinding(
                        operator_context.principal_id,
                        "fleet-local-operator",
                        f"fleet/{self.config.fleet_tenant_id}",
                    ),
                    RoleBinding(
                        device_context.principal_id,
                        "fleet-local-device",
                        "fleet/"
                        f"{self.config.fleet_tenant_id}/device/"
                        f"{identity.device_id}",
                    ),
                ),
                audit_key,
                audit_sink=self._admin_audit.record_authorization,
            )
            self._fleet_service = FleetLoopbackService(
                self._fleet_plane,
                credentials,
                self.config.data_dir / "fleet-replay.json",
                port=self.config.fleet_service_port,
                authorization_policy=authorization_policy,
            )
            self._fleet_service.start()
            return True
        except Exception as exc:
            service, plane, admin_audit = (
                self._fleet_service,
                self._fleet_plane,
                getattr(self, "_admin_audit", None),
            )
            self._fleet_service = None
            self._fleet_plane = None
            self._admin_audit = None
            self._endpoint_identity = None
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
            try:
                if admin_audit is not None:
                    admin_audit.close()
            except Exception:
                pass
            self._blackbox_note(
                "local fleet service unavailable "
                f"({type(exc).__name__}); see Startup Health for impact."
            )
            self._record_startup_degradation(
                "Fleet Control Plane",
                "the opt-in loopback fleet service could not start",
                exc,
            )
            return False

    def enterprise_runtime_snapshot(self) -> dict[str, object]:
        """Return low-cardinality enterprise state without local identifiers."""
        service = getattr(self, "_fleet_service", None)
        identity = getattr(self, "_endpoint_identity", None)
        server = getattr(service, "_server", None) if service is not None else None
        if identity is None:
            identity_state = "not-initialized"
        elif bool(getattr(identity, "revoked", False)):
            identity_state = "revoked"
        elif bool(getattr(identity, "quarantined", False)):
            identity_state = "quarantined"
        else:
            identity_state = "active"
        device_count = 0
        ingestion_state = "unknown"
        stored_events = 0
        duplicate_retries = 0
        uncertain_clock_events = 0
        plane = getattr(self, "_fleet_plane", None)
        if plane is not None:
            try:
                device_count = len(plane.devices(self.config.fleet_tenant_id))
            except Exception:
                device_count = 0
            try:
                health = plane.ingestion_health(self.config.fleet_tenant_id)
                ingestion_state = str(
                    health.get("clock_quality_state", "unknown")
                )[:40]
                stored_events = int(health.get("stored_events", 0) or 0)
                duplicate_retries = int(
                    health.get("duplicate_retries", 0) or 0
                )
                quality = dict(health.get("clock_quality", {}))
                uncertain_clock_events = int(quality.get("skewed", 0) or 0) + int(
                    quality.get("untrusted", 0) or 0
                ) + int(quality.get("legacy", 0) or 0)
            except Exception:
                ingestion_state = "unavailable"
        try:
            from angerona.core.fleet_service import openapi_contract_sha256

            api_contract_sha256 = openapi_contract_sha256()
        except Exception:
            api_contract_sha256 = "unavailable"

        def bounded_count(value: int) -> int:
            return min(max(int(value), 0), 100_000_000)

        return {
            "fleet_service": "running" if server is not None else "stopped",
            "fleet_transport": "loopback",
            "endpoint_identity": identity_state,
            "registered_devices": min(max(int(device_count), 0), 100_000),
            "fleet_ingestion": ingestion_state,
            "stored_events": bounded_count(stored_events),
            "duplicate_retries": bounded_count(duplicate_retries),
            "uncertain_clock_events": bounded_count(uncertain_clock_events),
            "fleet_api_contract_sha256": api_contract_sha256,
        }

    def _cancel_owned_work(self) -> None:
        """Fence work without classifying a startup exception as operator STOP."""
        from angerona.core.ollama_lifecycle import begin_ollama_shutdown

        requested = getattr(self, "_shutdown_requested", None)
        if requested is None:
            requested = threading.Event()
            self._shutdown_requested = requested
        requested.set()
        begin_ollama_shutdown()
        resilience = getattr(self, "_resilience", None)
        if resilience is not None:
            resilience.request_stop()

    def prepare_shutdown(self) -> None:
        """Persist explicit STOP before any owned process can exit."""
        from angerona.resilience import shutdown_token

        shutdown_token.request_operator_stop()
        self._cancel_owned_work()
        shutdown_token.signal_external_watchdog_stop()

    def shutdown(self) -> None:
        """Mark cancellation immediately, then serialize startup teardown."""
        shutdown_gate = getattr(self, "_shutdown_gate", None)
        if shutdown_gate is None:
            shutdown_gate = threading.Lock()
            self._shutdown_gate = shutdown_gate
        requested = getattr(self, "_shutdown_requested", None)
        if requested is None:
            requested = threading.Event()
            self._shutdown_requested = requested
        with shutdown_gate:
            if getattr(self, "_shutdown_cleanup_started", False):
                return
            self._shutdown_cleanup_started = True
            requested.set()
        try:
            self._cancel_owned_work()
        except Exception:
            # Still retire retained handles if a worker fence is unavailable.
            pass
        window = getattr(self, "window", None)
        signal_operations = getattr(window, "_begin_operations_shutdown", None)
        if callable(signal_operations):
            signal_operations()
        # Watchdogs/AI must retire even if a sensor is stuck inside the startup
        # lock. Their own admission fences and native ownership serialize them.
        self._shutdown_critical_owned()
        lifecycle_lock = getattr(self, "_startup_lifecycle_lock", None)
        if lifecycle_lock is None:
            lifecycle_lock = threading.Lock()
            self._startup_lifecycle_lock = lifecycle_lock
        with lifecycle_lock:
            self._shutdown_owned()

    def _shutdown_owned(self) -> None:
        # A manager created just before cancellation may only become visible
        # after the startup lock drains; finish that late ownership as well.
        self._shutdown_critical_owned()
        metrics_publisher = getattr(self, "runtime_metrics_publisher", None)
        if metrics_publisher is not None:
            metrics_publisher.stop()
        self._shutdown_services_and_stores()

    def _shutdown_critical_owned(self) -> None:
        inventory = getattr(self, "_process_snapshot_lifecycle", None)
        if inventory is not None:
            inventory.request_stop()
        # Resilience-free launches still retain their exact Black Box handle.
        blackbox = getattr(self, "_blackbox_proc", None)
        if blackbox is not None:
            try:
                if getattr(blackbox, "owns_descendants", False):
                    blackbox.terminate()
                    blackbox.wait(timeout=3.0)
                    blackbox.wait_tree(timeout=3.0)
                    blackbox.close()
                    self._blackbox_proc = None
                elif blackbox.poll() is None:
                    blackbox.terminate()
                    try:
                        blackbox.wait(timeout=2.0)
                    except Exception:
                        blackbox.kill()
                        blackbox.wait(timeout=2.0)
            except Exception:
                pass
        # Release AI before either supervisor/healer lifecycle lock can wait.
        # The terminal fence also catches an in-flight late server launch.
        try:
            if not getattr(self, "_critical_ai_done", False):
                from angerona.core.ollama_lifecycle import shutdown_ollama
                shutdown_ollama(
                    getattr(self.config, "ollama_host", "http://localhost:11434"),
                    getattr(self.config, "ollama_model", "llama3"),
                )
                self._critical_ai_done = True
        except Exception:
            pass
        resilience = getattr(self, "_resilience", None)
        if resilience is not None:
            try:
                resilience.stop(terminate_children=True)
            except Exception:
                pass
        healer = getattr(self, "_runtime_healer", None)
        if healer is not None:
            healer.stop()

    def _shutdown_services_and_stores(self) -> None:
        self.reporter.stop()
        if self._mcp is not None:
            try:
                self._mcp.stop()
            except Exception:
                pass
        if getattr(self, "_jarvis_control", None) is not None:
            try:
                self._jarvis_control.stop()
            except Exception:
                pass
        fleet_drained = True
        if self._fleet_service is not None:
            try:
                fleet_drained = bool(self._fleet_service.stop())
            except Exception:
                fleet_drained = False
            self._fleet_service = None
        if self._fleet_plane is not None and fleet_drained:
            try:
                self._fleet_plane.close()
            except Exception:
                pass
            self._fleet_plane = None
        admin_audit = getattr(self, "_admin_audit", None)
        if admin_audit is not None and fleet_drained:
            try:
                admin_audit.close()
            except Exception:
                pass
            self._admin_audit = None
        self._endpoint_identity = None
        try:
            self.manager.stop_all()
        finally:
            inventory = getattr(self, "_process_snapshot_lifecycle", None)
            if inventory is not None:
                inventory.request_stop()
        debug_service = getattr(self, "live_debug_service", None)
        if debug_service is not None:
            try:
                debug_service.stop(timeout=2.0)
            except Exception:
                pass
        alert_worker = getattr(self, "alert_retention_worker", None)
        if alert_worker is not None:
            try:
                alert_worker.stop(timeout=2.0)
            except Exception:
                pass
        # Fleet Health is a module consumer of the eager Local SOC fabric.
        # Stop all consumers first, then close that shared store exactly once.
        try:
            self.window._close_operations_service()
        except Exception:
            pass
        # Producers stop first so the bounded SentinelLens queue has a stable
        # terminal suffix to drain and analyze. It never executes remediation.
        try:
            if self.sentinel_lens_service is not None:
                self.sentinel_lens_service.stop(timeout=3.0)
        except Exception:
            pass
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
