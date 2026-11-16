"""Application wiring: builds the core services and the GUI, and ties them
together. Keep this thin — real logic lives in core/ and modules/."""
from __future__ import annotations

import os
import threading
import time
from pathlib import Path

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


def _apply_startup_normal_log_policy(config) -> dict:
    """Attempt once; retain a UI-visible saved-versus-live gap without waiting."""
    try:
        from angerona.core.crashlog import configure_normal_log_budget
        result = configure_normal_log_budget(
            limit_mib=getattr(config, "normal_log_max_mib", 8),
            message_kib=getattr(config, "normal_log_message_kib", 64),
            paused=getattr(config, "normal_log_paused", False),
        )
    except Exception:
        result = {"accepted": False, "reason": "configuration-unavailable"}
    pending = result.get("accepted") is not True
    config._normal_log_policy_pending = pending
    config._normal_log_apply_note = (
        "Saved normal log preferences were not applied at startup. Active limits are shown below. "
        "Choose Apply now / retry to try once without restarting." if pending else "")
    return result


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
        source_stop_context=None,
    ) -> None:
        self.qt = qt
        # Production entry supplies a register-only owner before constructing
        # GUI readers. Direct/offline constructors do not create a collector.
        self._process_snapshot_lifecycle = process_snapshot_lifecycle
        # Only __main__ supplies this after owning the desktop singleton. No
        # source epoch is created or recovered implicitly inside the App.
        self._source_stop_context = source_stop_context
        self._startup_endpoint = startup_endpoint
        self._dashboard_ready_scheduled = False
        self._dashboard_ready_sent = False
        self._shutdown_requested = threading.Event()
        self._shutdown_gate = threading.Lock()
        self._shutdown_custody_gate = threading.RLock()
        self._shutdown_fence_errors = ()
        self._shutdown_fences_incomplete = False
        self._startup_lifecycle_lock = threading.Lock()
        self.config = Config.load()
        # Hooks arm before Config is available. Apply saved normal-write limits
        # without waiting for any concurrent crash writer or probing files here.
        # A logging-policy failure must not hold dashboard startup.
        self._normal_log_budget_apply_result = _apply_startup_normal_log_policy(self.config)
        if high_water_provider is None:
            from angerona.core.recorder_integrity import provider_from_config
            high_water_provider = provider_from_config(self.config)
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
        from angerona.core.config import apply_telemetry_storage_policy
        self._telemetry_storage_policy_result = apply_telemetry_storage_policy(self.config, self.storage)
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
        from angerona.core.config import settings_load_warning
        settings_warning = settings_load_warning(self.config)
        if settings_warning is not None:
            self.bus.publish(settings_warning)

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
        # Mutator workers observe the complete retained native ownership scope.
        # Display readers retain the separate memory-only cached getter.
        self.manager.owned_process_identities = self._owned_process_identities_for_response
        from angerona.core.source_activation import (
            register_source_activation_runtime, source_activation_controller_registration,
        )
        self._source_update_controller = (source_activation_controller_registration(
            Path(__file__).absolute().parents[2], Path(self.config.data_dir) / "github-updates")
            if startup_endpoint is not None else None)
        register_source_activation_runtime(self)
        from angerona.core.recorder_integrity_runtime import RecorderIntegrityRuntime
        self.recorder_integrity_runtime = RecorderIntegrityRuntime(self.config, self.bus, high_water_provider)
        self.manager.recorder_integrity_runtime = self.recorder_integrity_runtime
        self._breach_state_controller = None
        try:
            from angerona.core.breach_state import ensure_breach_controller
            self._breach_state_controller = ensure_breach_controller(self.manager)
        except Exception as exc:
            self._record_startup_degradation(
                "Breach review", "verified breach review state is unavailable", exc,
            )
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
            process_snapshot_lifecycle=self._process_snapshot_lifecycle,
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
            shutdown_critical=self._shutdown_critical_owned,
            shutdown_companions_retired=self.shutdown_companions_retired,
            shutdown_retired_callback=self.finalize_source_stop,
        )
        # Settings consumes only this bounded, privacy-safe status provider; it
        # never receives fleet service keys or endpoint private-key material.
        self.window.enterprise_runtime_provider = self.enterprise_runtime_snapshot
        heartbeat_setter = getattr(self.window, "set_component_heartbeat_source", None)
        if callable(heartbeat_setter):
            heartbeat_setter(self._component_heartbeats_cached)
        orb = getattr(self.window, "_holographic_orb", None)
        if orb is not None:
            orb.set_service_status_source(self._orb_cached_service_statuses)
        # Open sharing only after all mandatory construction has succeeded. A
        # failed constructor must not leave a live endpoint with no App owner.
        self._start_live_debug(live_debug)

    def _owned_process_identities_cached(self) -> tuple:
        """Display context reads immutable native-owner memory, never UI status."""
        requested = getattr(self, "_shutdown_requested", None)
        if requested is not None and requested.is_set():
            return ()
        resilience = getattr(self, "_resilience", None)
        supplier = getattr(resilience, "owned_process_identities", None)
        return supplier() if callable(supplier) else ()

    def _owned_process_identities_for_response(self) -> tuple:
        """Complete native companion/inventory context, on a worker only.

        This is an exclusion read, never response authority. Display callers
        retain the separate no-I/O cached getter. A configured owner cannot be
        omitted or replaced by a fresh Core-only tuple after any failure.
        """
        import math
        from angerona.core.process_snapshot_lifecycle import ProcessSnapshotLifecycle
        from angerona.core.werfault_guard import (
            MAX_OWNED_PROCESSES, OwnedProcessFailurePhase, OwnedProcessReadError,
            read_owned_process_snapshot,
        )
        from angerona.core.windows_child_job import NativeOwnershipObservationError
        from angerona.resilience.manager import ResilienceManager
        from angerona.telemetry import sensors
        from angerona.telemetry.process_snapshot_worker import (
            InventoryWorkerError, ProcessSnapshotProvider, _Job, _Pin, on_gui_thread,
        )

        if on_gui_thread():
            raise InventoryWorkerError("Complete companion ownership cannot run on the GUI thread")
        started = time.monotonic()
        if type(started) not in (int, float) or not math.isfinite(started) or started < 0:
            raise InventoryWorkerError("Complete companion ownership clock unavailable")
        deadline = started + 1.0
        resilience = getattr(self, "_resilience", None)
        inventory = getattr(self, "_process_snapshot_lifecycle", None)
        if type(resilience) is not ResilienceManager or type(inventory) is not ProcessSnapshotLifecycle:
            raise InventoryWorkerError("Configured companion and inventory owners are required")
        provider = inventory.provider
        if type(provider) is not ProcessSnapshotProvider:
            raise InventoryWorkerError("Configured inventory native provider is unavailable")
        routing_generation = sensors._process_snapshot_provider_generation
        external_controller = getattr(self, "_source_update_controller", None)
        tool_owner = getattr(getattr(self, "manager", None), "red_team_tool_owner", None)
        if tool_owner is not None:
            from angerona.gui.red_team_bridge import RedTeamBridge
            if type(tool_owner) is not RedTeamBridge:
                raise InventoryWorkerError("Configured Red Team owner has an unknown type")

        def remaining():
            now = time.monotonic()
            if type(now) not in (int, float) or not math.isfinite(now) or not started <= now < deadline:
                raise InventoryWorkerError("Complete companion ownership observation deadline")
            return min(1.0, deadline - now)

        def observe_phase(phase, operation):
            # Preserve the original exception class and every exclusion check.
            # Only closed phase/type labels cross the diagnostic boundary; an
            # arbitrary provider's exception message is never copied there.
            try:
                return operation()
            except Exception as error:
                kind = ("inventory-owner" if isinstance(error, InventoryWorkerError)
                        else "native-owner" if isinstance(error, NativeOwnershipObservationError)
                        else "snapshot-validation" if isinstance(error, OwnedProcessReadError)
                        else "provider")
                try:
                    error._angerona_owned_phase = OwnedProcessFailurePhase(phase, kind)
                except (AttributeError, TypeError, ValueError):
                    pass
                raise

        def capture_inventory():
            requested = getattr(self, "_shutdown_requested", None)
            if (requested is None or requested.is_set() or self._resilience is not resilience
                    or self._process_snapshot_lifecycle is not inventory
                    or sensors._process_snapshot_provider is not provider
                    or sensors._process_snapshot_provider_generation != routing_generation
                    or getattr(self, "_source_update_controller", None) is not external_controller):
                raise InventoryWorkerError("Configured ownership lifetime or inventory routing changed")
            if not inventory._lock.acquire(timeout=remaining()):
                raise InventoryWorkerError("Inventory lifecycle admission deadline")
            try:
                if (inventory.provider is not provider or inventory._ready is not True
                        or inventory._state != "running" or inventory._error_type
                        or inventory._stop_requested.is_set() or inventory._retired.is_set()):
                    raise InventoryWorkerError("Configured inventory owner is unavailable or stopping")
                owner_thread = inventory._thread
            finally:
                inventory._lock.release()
            if not provider._lock.acquire(timeout=remaining()):
                raise InventoryWorkerError("Inventory native-owner admission deadline")
            try:
                if (not provider._ready or provider._stopping or provider._retired
                        or provider._failure or provider._launching or provider._starting_thread
                        or provider._retirement_error or provider._popen_close_failed
                        or provider._auxiliary_close_unproven):
                    raise InventoryWorkerError("Configured inventory native custody is unavailable")
                job, wrapper, child = provider._job, provider._wrapper, provider._child
                if (type(job) is not _Job or job.handle is None or job.close_failed
                        or type(wrapper) is not _Pin or type(child) is not _Pin
                        or any(pin.closed or pin.close_failed or pin.handle is None
                               for pin in (wrapper, child))):
                    raise InventoryWorkerError("Configured inventory native custody is incomplete")
                return (owner_thread, job, id(job.handle), job.handle,
                        wrapper, id(wrapper.handle), wrapper.handle,
                        child, id(child.handle), child.handle)
            finally:
                provider._lock.release()

        from angerona.core import ollama_lifecycle
        ai_scope = observe_phase("ai-capture", lambda: ollama_lifecycle.capture_owned_ollama_process_scope(timeout=remaining()))
        inventory_scope = observe_phase("inventory-capture", capture_inventory)
        companion_scope = observe_phase("companion-capture", lambda: resilience._capture_owned_process_scope(timeout=remaining()))
        tool_scope = (None if tool_owner is None else observe_phase("tool-capture",
            lambda: tool_owner.capture_owned_process_scope(timeout=remaining())))
        companion_rows = observe_phase("companion-observe", lambda: resilience.observe_owned_process_identities(timeout=remaining()))
        inventory_rows = observe_phase("inventory-observe", lambda: provider.observe_owned_process_identities(timeout=remaining()))
        ai_rows = observe_phase("ai-observe", lambda: ollama_lifecycle.observe_owned_ollama_process_identities(captured=ai_scope, timeout=remaining()))
        external_rows = (() if external_controller is None else
                         observe_phase("external-observe", lambda: external_controller.observe(timeout=remaining())))
        tool_rows = (() if tool_owner is None else observe_phase("tool-observe",
            lambda: tool_owner.observe_owned_process_identities(captured=tool_scope, timeout=remaining())))
        if observe_phase("inventory-revalidate", capture_inventory) != inventory_scope:
            raise InventoryWorkerError("Configured inventory native owner changed during observation")
        if observe_phase("companion-revalidate", lambda: resilience._capture_owned_process_scope(timeout=remaining())) != companion_scope:
            raise InventoryWorkerError("Configured companion native owners changed during observation")
        if observe_phase("ai-revalidate", lambda: ollama_lifecycle.capture_owned_ollama_process_scope(timeout=remaining())) != ai_scope:
            raise InventoryWorkerError("Owned AI registry/admission changed during complete observation")
        if (getattr(getattr(self, "manager", None), "red_team_tool_owner", None) is not tool_owner
                or tool_owner is not None and observe_phase("tool-revalidate",
                    lambda: tool_owner.capture_owned_process_scope(timeout=remaining())) != tool_scope):
            raise InventoryWorkerError("Owned Red Team lifetime changed during complete observation")
        current_core = observe_phase("core-validate", lambda: resilience._owned_core_identity(companion_scope[1], not_before=started))
        native_scopes = [companion_rows, inventory_rows]
        # Only an actually revalidated empty AI registry is an absent scope.
        # Required producers and every configured external owner stay strict.
        if not (type(ai_rows) is tuple and not ai_rows and ai_scope[2] == ()):
            native_scopes.append(ai_rows)
        if external_controller is not None:
            native_scopes.append(external_rows)
        if tool_owner is not None and tool_scope[1] is not None and tool_scope[1][2] != "retired":
            native_scopes.append(tool_rows)
        rows_by_pid = {}
        for rows in native_scopes:
            for row in read_owned_process_snapshot(lambda: rows, not_before=started,
                                                   clock=time.monotonic).rows:
                prior = rows_by_pid.get(row.pid)
                if prior is not None:
                    if ((prior.birth_ticks, prior.image, prior.create_time)
                            != (row.birth_ticks, row.image, row.create_time)):
                        raise InventoryWorkerError("Complete native ownership has contradictory PID identities")
                    if row.expires_monotonic < prior.expires_monotonic:
                        rows_by_pid[row.pid] = row  # Keep an original DTO; never renew its lease.
                else:
                    rows_by_pid[row.pid] = row
                if len(rows_by_pid) > MAX_OWNED_PROCESSES:
                    raise InventoryWorkerError("Complete native ownership exceeds its bound")
        original_core = rows_by_pid.get(current_core.pid)
        if (original_core is None or original_core.role != "core"
                or (original_core.birth_ticks, original_core.image, original_core.create_time)
                != (current_core.birth_ticks, current_core.image, current_core.create_time)):
            raise InventoryWorkerError("Retained Core generation changed during complete observation")
        remaining()
        return read_owned_process_snapshot(lambda: tuple(rows_by_pid.values()), not_before=started,
                                           clock=time.monotonic).rows

    def source_update_controller_status(self) -> dict:
        """Cached display metadata, no file/native I/O or Core retirement join."""
        controller = getattr(self, "_source_update_controller", None)
        return ({"configured": False, "state": "unsupported-direct-launch"}
                if controller is None else controller.cached_status())

    def source_update_observer_workers(self) -> tuple:
        controller = getattr(self, "_source_update_controller", None)
        if controller is None:
            return ()
        worker = getattr(controller, "_observer_thread", None)
        if worker is None:
            if getattr(controller, "_heartbeat_cache", None) is not None:
                raise RuntimeError("Source progress has query custody without its exact observer thread")
            return ()
        return (worker,)

    def source_update_observer_retirement_proven(self, worker) -> bool:
        controller = getattr(self, "_source_update_controller", None)
        return bool(controller is not None and controller.heartbeat_retired(worker))

    def _component_heartbeats_cached(self) -> tuple[dict, ...]:
        """GUI publication copy only: no files, native probes or held locks."""
        resilience = getattr(self, "_resilience", None)
        supplier = getattr(resilience, "component_heartbeats", None)
        records = supplier() if callable(supplier) else ()
        if not records:
            records = tuple({"role": role, "generation_id": "", "pid": None,
                             "last_heartbeat_monotonic": None, "deadline_seconds": 10.0,
                             "state": "unavailable",
                             "reason": "No real component heartbeat publication is available."}
                            for role in ("core", "watchdog", "scanner", "blackbox"))
        rows = [dict(record) for record in records[:4]]
        if getattr(self.config, "blackbox_enabled", True) is not True:
            for row in rows:
                if row.get("role") == "blackbox":
                    row.update(state="disabled", reason="Black Box is disabled in current settings.")
        with_ui = bool(getattr(resilience, "with_ui", False))
        for role in ("watchdog_ui", "scanner_ui"):
            rows.append({"role": role, "generation_id": "", "pid": None,
                         "last_heartbeat_monotonic": None, "deadline_seconds": 10.0,
                         "state": "unavailable" if with_ui else "disabled",
                         "reason": "This monitor has no authenticated progress heartbeat." if with_ui else "Separate monitor windows are not enabled for this core generation."})
        for role in ("inventory", "local_ai"):
            rows.append({"role": role, "generation_id": "", "pid": None,
                         "last_heartbeat_monotonic": None, "deadline_seconds": 10.0,
                         "state": "unavailable",
                         "reason": "This helper does not publish an authenticated component progress heartbeat."})
        if getattr(self.config, "runtime_chill_ai_blocked", getattr(
                self.config, "runtime_chill_active", getattr(self.config, "eco_mode", False))) is True:
            rows[-1].update(state="disabled", reason="Chill Mode blocks local AI; no model heartbeat is expected.")
        controller = getattr(self, "_source_update_controller", None)
        if controller is None:
            rows.extend({"role": role, "generation_id": "", "pid": None,
                "last_heartbeat_monotonic": None, "deadline_seconds": 10.0,
                "state": "disabled", "reason": "No canonical source-update controller is enrolled for this launch."}
                for role in ("source_startup", "source_update_owner", "activation_broker"))
        else:
            optional_rows = controller.heartbeat_snapshot()
            if getattr(resilience, "_source_update_observer_error", ""):
                optional_rows = tuple(dict(row, state="held", last_heartbeat_monotonic=None,
                    reason="The optional controller observer failed; baseline component observation remains independent.")
                    for row in optional_rows)
            rows.extend(optional_rows)
        requested = getattr(self, "_shutdown_requested", None)
        if requested is not None and requested.is_set():
            for row in rows:
                row.update(state="stopped", last_heartbeat_monotonic=None,
                           reason="The core requested shutdown; component heartbeat observation is stopped.")
        return tuple(rows)

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

        source_context = getattr(self, "_source_stop_context", None)
        if source_context is not None:
            # Explicit source launch already rotated its epoch after singleton
            # admission. Recovery joins that exact epoch and never clears STOP.
            if not source_context.admission_current():
                raise RuntimeError("The admitted source STOP session is unavailable.")
            if not source_context.respawn_allowed():
                return False
            from angerona.resilience.source_stop import SOURCE_SESSION_ENV
            os.environ[SOURCE_SESSION_ENV] = source_context.epoch
        else:
            from angerona.resilience.source_stop import source_runtime_admitted
            if source_runtime_admitted():
                raise RuntimeError("Ordinary source startup has no admitted STOP session.")
            # Installed/protected startup retains its independent authority. A
            # source session never clears or requests this machine-wide token.
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
        # __main__ owns this fully constructed graph before starting a new
        # non-daemon reader. A later start failure therefore runs shutdown.
        self._start_recorder_integrity()
        from PySide6.QtCore import QTimer
        if source_context is not None or os.environ.get("ANGERONA_SUPERVISED_RECOVERY") == "1":
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

    def _start_recorder_integrity(self):
        try:
            self.recorder_integrity_runtime.start()
        except Exception as exc:
            self._record_startup_degradation("Recorder Integrity",
                "independent history witnessing is unavailable; local records are preserved", exc)

    def _honor_operator_stop(self) -> None:
        source_context = getattr(self, "_source_stop_context", None)
        if source_context is not None:
            superseded = getattr(source_context, "is_superseded", None)
            requested = (source_context.is_stop_requested() is True
                         or callable(superseded) and superseded() is True)
        else:
            from angerona.resilience.shutdown_token import is_standdown_requested
            requested = is_standdown_requested()
        if requested:
            timer = getattr(self, "_operator_stop_timer", None)
            if timer is not None:
                timer.stop()
            self.window._terminate()  # Authenticated intent bypasses UI locking.

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
        # Optional scanner preparation follows the painted dashboard and its
        # readiness publication. The controller does all storage/network work
        # on its own worker and never holds the startup handshake.
        from PySide6.QtCore import QTimer
        QTimer.singleShot(0, self._prepare_curated_tools_after_paint)

    def _prepare_curated_tools_after_paint(self) -> None:
        if self._startup_cancelled():
            return
        try:
            from angerona.gui.curated_tools import get_curated_tools_controller
            controller = get_curated_tools_controller(self.manager)
            queue_notice = getattr(self.window, "_queue_automatic_scan_notice", None)
            if callable(queue_notice):
                controller.scan_outcome_ready.connect(queue_notice)
            controller.start_automatic_schedule()
            if getattr(self.config, "github_tools_enabled", True) is True:
                controller.auto_prepare()
        except Exception as exc:
            self._record_startup_degradation(
                "Curated scanners", "optional scanner preparation is unavailable", exc,
            )

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
        source_context = getattr(self, "_source_stop_context", None)
        if source_context is not None:
            return not source_context.respawn_allowed()
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
                source_owner = getattr(self, "_source_update_controller", None)
                source_options = ({"source_update_controller": source_owner}
                                  if source_owner is not None else {})
                source_context = getattr(self, "_source_stop_context", None)
                if source_context is not None:
                    from angerona.resilience.source_stop import SOURCE_SESSION_ENV
                    _os.environ[SOURCE_SESSION_ENV] = source_context.epoch
                    source_options["source_stop_context"] = source_context
                self._resilience = start_resilience(
                    self.bus,
                    config=self.config,
                    with_ui=not bool(
                        getattr(
                            self.config,
                            "runtime_chill_active",
                            getattr(self.config, "eco_mode", True),
                        )
                    ),
                    **source_options,
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
            "source_update_controller": self.source_update_controller_status(),
        }

    def _cancel_owned_work(self) -> None:
        """Attempt every independent fence; keep any failure explicitly held."""
        failures = set()

        def fence(phase, operation):
            try:
                operation()
            except Exception as error:
                # Closed phase names and bounded exception types only. A broken
                # optional fence never prevents cancellation of the other owners.
                failures.add(phase + ":" + type(error).__name__[:80])

        requested = getattr(self, "_shutdown_requested", None)
        if requested is None:
            requested = threading.Event()
            self._shutdown_requested = requested
        fence("app-admission", lambda: requested.set())
        # Staged startup must not keep bringing modules online after STOP.
        fence_startup = getattr(getattr(self, "manager", None), "fence_module_startup", None)
        if callable(fence_startup):
            fence("module-startup", fence_startup)
        integrity = getattr(self, "recorder_integrity_runtime", None)
        if integrity is not None:
            fence("recorder-integrity", lambda: integrity.request_stop())
        tools_controller = getattr(getattr(self, "manager", None), "_curated_tools_controller", None)
        if tools_controller is not None:
            fence("community-tools", lambda: tools_controller.shutdown())
        breach_controller = getattr(self, "_breach_state_controller", None)
        if breach_controller is not None:
            fence("breach-response", lambda: breach_controller.request_stop())

        def stop_ai():
            from angerona.core.ollama_lifecycle import begin_ollama_shutdown, begin_operator_ollama_shutdown
            if getattr(self, "_operator_stop_recorded", False) is True:
                begin_operator_ollama_shutdown()
            else:
                begin_ollama_shutdown()
        fence("owned-ai", stop_ai)

        def stop_signal():
            from angerona.core.mobile_cli_custody import request_signal_stop, request_operator_signal_stop
            if getattr(self, "_operator_stop_recorded", False) is True:
                request_operator_signal_stop()
            else:
                request_signal_stop()
        fence("signal-cli", stop_signal)
        resilience = getattr(self, "_resilience", None)
        if resilience is not None:
            fence("resilience", lambda: resilience.request_stop())
        # Production initializes the shared gate before workers start. The
        # fallback supports narrowly constructed offline fixtures/older owners.
        gate = getattr(self, "_shutdown_custody_gate", None)
        if gate is None:
            gate = self._shutdown_custody_gate = threading.RLock()
        with gate:
            prior = set(getattr(self, "_shutdown_fence_errors", ()))
            self._shutdown_fence_errors = tuple(sorted(prior | failures))[:32]
            # Errors remain latched for this STOP. A later callback returning or
            # a cosmetic worker exit cannot retroactively prove a failed fence.
            self._shutdown_fences_incomplete = bool(self._shutdown_fence_errors)

    def _capture_shutdown_custody(self) -> None:
        """Retain exact existing owners before STOP hides their live inventory.

        This runs on a preparation/cleanup worker. It does not stop anything,
        select a process by name or grant source control over installed services.
        """
        gate = getattr(self, "_shutdown_custody_gate", None)
        if gate is None:
            gate = self._shutdown_custody_gate = threading.RLock()
        with gate:
            resilience_rows = tuple(getattr(self, "_shutdown_resilience_custody", ()))
            blackboxes = tuple(getattr(self, "_shutdown_blackbox_custody", ()))
            inventories = tuple(getattr(self, "_shutdown_inventory_custody", ()))
            healers = tuple(getattr(self, "_shutdown_healer_custody", ()))
            capture_errors = set(getattr(self, "_shutdown_custody_capture_errors", ()))
            resilience = getattr(self, "_resilience", None)
            if resilience is not None and not any(owner is resilience for owner, _ in resilience_rows):
                custody = None
                try:
                    capture = getattr(resilience, "capture_retirement_custody", None)
                    if not callable(capture):
                        raise RuntimeError("Configured resilience owner has no exact retirement custody")
                    custody = capture()
                except Exception as error:
                    # Unknown proof is retained, not a veto on STOP for every
                    # other owner. No protected/source authority is substituted.
                    capture_errors.add("capture-resilience:" + type(error).__name__)
                resilience_rows += ((resilience, custody),)
            blackbox = getattr(self, "_blackbox_proc", None)
            if blackbox is not None and not any(owner is blackbox for owner in blackboxes):
                blackboxes += (blackbox,)  # Retain even when its query cut fails.
                try:
                    prepare_tree = getattr(blackbox, "prepare_tree_retirement", None)
                    if getattr(blackbox, "owns_descendants", False) is True and callable(prepare_tree):
                        prepare_tree(timeout=3.0)
                except Exception as error:
                    capture_errors.add("capture-blackbox:" + type(error).__name__)
            inventory = getattr(self, "_process_snapshot_lifecycle", None)
            if inventory is not None and not any(owner is inventory for owner in inventories):
                inventories += (inventory,)
            healer = getattr(self, "_runtime_healer", None)
            if healer is not None and not any(owner is healer for owner in healers):
                healers += (healer,)
            if any(len(rows) > 8 for rows in (resilience_rows, blackboxes, inventories, healers)):
                raise RuntimeError("Shutdown ownership exceeds its bounded custody inventory")
            self._shutdown_resilience_custody = resilience_rows
            self._shutdown_blackbox_custody = blackboxes
            self._shutdown_inventory_custody = inventories
            self._shutdown_healer_custody = healers
            self._shutdown_custody_capture_errors = tuple(sorted(capture_errors))
            self._shutdown_custody_captured = True

    def prepare_shutdown(self) -> None:
        """Capture ownership, persist STOP, then close owned work admission."""
        # This must precede both the durable command and request_stop(): the
        # manager intentionally hides response/exclusion inventories afterward.
        self._capture_shutdown_custody()
        source_context = getattr(self, "_source_stop_context", None)
        if source_context is not None:
            source_context.request_stop(reason="dashboard or tray STOP")
        else:
            from angerona.resilience.source_stop import source_runtime_admitted
            if source_runtime_admitted():
                raise RuntimeError("Source STOP has no admitted ordinary-user session")
            from angerona.resilience import shutdown_token
            shutdown_token.request_operator_stop()
        self._operator_stop_recorded = True
        self._cancel_owned_work()
        if source_context is None:
            from angerona.resilience import shutdown_token
            try:
                shutdown_token.signal_external_watchdog_stop()
            except Exception as error:
                # The authenticated protected STOP already exists. Preserve its
                # auxiliary-signalling failure and continue the owned cleanup.
                with self._shutdown_custody_gate:
                    prior = set(getattr(self, "_shutdown_fence_errors", ()))
                    prior.add("external-watchdog:" + type(error).__name__[:80])
                    self._shutdown_fence_errors = tuple(sorted(prior))[:32]
                    self._shutdown_fences_incomplete = True

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
        self._optional_owned_drained = self._drain_optional_owned()
        metrics_publisher = getattr(self, "runtime_metrics_publisher", None)
        if metrics_publisher is not None:
            metrics_publisher.stop()
        self._shutdown_services_and_stores()
        from angerona.core.mobile_cli_custody import SignalCliRetirementIncomplete
        signal_outcome = self._signal_retirement_outcome()
        self._signal_retirement_at_shutdown = signal_outcome
        from angerona.core.ollama_lifecycle import OllamaRetirementIncomplete, owned_ollama_retirement_proven, ollama_retirement_snapshot
        if not owned_ollama_retirement_proven():
            # All remaining critical/service cleanup ran before this error.
            try:
                outcome = ollama_retirement_snapshot()
            except Exception as error:
                raise OllamaRetirementIncomplete({"state": "incomplete", "complete": False,
                    "diagnostic_error_type": type(error).__name__,
                    "coverage": "Owned retirement is unproven; its diagnostic snapshot is unavailable"}) from error
            raise OllamaRetirementIncomplete(outcome)
        if not self._signal_retirement_proven(signal_outcome):
            raise SignalCliRetirementIncomplete(signal_outcome)

    @staticmethod
    def _signal_retirement_outcome() -> dict:
        """Read memory-only ownership facts; never run Signal for shutdown."""
        from angerona.core.mobile_cli_custody import signal_cli_custody_snapshot
        try:
            return signal_cli_custody_snapshot()
        except Exception as error:
            return {"schema": 1, "state": "unavailable",
                    "diagnostic_error_type": type(error).__name__[:80]}

    @staticmethod
    def _signal_retirement_proven(outcome) -> bool:
        if type(outcome) is not dict or type(outcome.get("schema")) is not int or outcome["schema"] != 1:
            return False
        fields = ("active_invocations", "pending_external_trees", "held_resources")
        if any(type(outcome.get(field)) is not int or outcome[field] < 0 for field in fields):
            return False
        # A retained executable/closed-resource reference fences Signal only.
        # An unknown live process tree must still prevent a false STOP receipt.
        return (type(outcome.get("launch_quiescent")) is bool and outcome["launch_quiescent"]
                and outcome["active_invocations"] == 0 and outcome["pending_external_trees"] == 0)

    def _drain_optional_owned(self, timeout: float = 5.0) -> bool:
        """Retire scanner/review workers before their evidence stores close."""
        from angerona.core.mobile_cli_custody import request_signal_stop
        request_signal_stop()
        deadline = time.monotonic() + max(0.0, min(float(timeout), 10.0))
        drained = True
        tools_controller = getattr(getattr(self, "manager", None), "_curated_tools_controller", None)
        if tools_controller is not None:
            try:
                tools_controller.shutdown()
                drained = tools_controller.wait_for_shutdown(
                    max(0.0, deadline - time.monotonic())
                ) is True
            except Exception:
                drained = False
        breach_controller = getattr(self, "_breach_state_controller", None)
        if breach_controller is not None:
            try:
                breach_drained = breach_controller.close(
                    timeout=max(0.0, deadline - time.monotonic())
                ) is True
            except Exception:
                breach_drained = False
            drained = breach_drained and drained
        signal_outcome = self._signal_retirement_outcome()
        while not self._signal_retirement_proven(signal_outcome) and time.monotonic() < deadline:
            time.sleep(min(0.02, max(0.0, deadline - time.monotonic())))
            signal_outcome = self._signal_retirement_outcome()
        self._signal_retirement_at_shutdown = signal_outcome
        drained = self._signal_retirement_proven(signal_outcome) and drained
        return drained

    def _record_ai_retirement_outcome(self) -> None:
        """Reuse bounded private diagnostics; immutable originals stay separate."""
        self._critical_ai_diagnostic_error_type = ""
        from angerona.core.ollama_lifecycle import ollama_retirement_snapshot
        outcome = ollama_retirement_snapshot()
        self._critical_ai_outcome = outcome
        saved = False
        directory = getattr(getattr(self, 'config', None), 'data_dir', None)
        if directory is not None:
            try:
                from angerona.core.startup_diagnostics import StartupDiagnostics
                writer = StartupDiagnostics(Path(directory))
                saved = writer.record('ollama-owned-retirement', outcome['state'],
                    pid=os.getpid(), coverage='Exact retained owners only; shared listeners are not owned or killed',
                    actual='pending=' + str(outcome['pending_owned']) + '; launch_quiescent=' + str(outcome['launch_quiescent']))
                for row in outcome['records']:
                    identities = row['identities'] or ({'pid': row['pid'], 'birth_ticks': None, 'image': ''},)
                    for identity in identities:
                        saved = writer.record('ollama-owned-generation', row['state'],
                            pid=identity['pid'], birth_filetime=identity['birth_ticks'], executable=identity['image'],
                            exception_type=row['error_type'], coverage='historical native identity; server_exit=' + str(row['service_exited'])
                                + '; Job0=' + str(row['job_empty']) + '; handles_closed=' + str(row['handles_closed'])
                                + '; close_held=' + str(row['close_held'])) and saved
            except Exception as error:
                saved = False
                self._critical_ai_diagnostic_error_type = type(error).__name__
        self._critical_ai_diagnostic_saved = saved

    @staticmethod
    def _blackbox_retirement_proven(owner) -> bool:
        """Read an exact owner's existing native-signal/close receipt only."""
        snapshot = getattr(owner, "tree_retirement_snapshot", None)
        if not callable(snapshot):
            return False
        try:
            value = snapshot()
            return (type(value) is dict and value.get("cut_ready") is True
                    and value.get("dispatched") is True
                    and value.get("signals_proven") is True
                    and value.get("handles_closed") is True
                    and value.get("close_held") is False and not value.get("error_type"))
        except Exception:
            return False

    @staticmethod
    def _inventory_retirement_proven(owner) -> bool:
        # The lifecycle's retained owner loop sets _retired only after native
        # provider.stop() proves retirement. Also require actual thread exit.
        retired = getattr(owner, "_retired", None)
        thread = getattr(owner, "_thread", None)
        return (isinstance(retired, threading.Event) and retired.is_set()
                and (thread is None or isinstance(thread, threading.Thread)
                     and not thread.is_alive()))

    @staticmethod
    def _healer_retirement_proven(owner) -> bool:
        stopped = getattr(owner, "_stop", None)
        thread = getattr(owner, "_thread", None)
        return (isinstance(stopped, threading.Event) and stopped.is_set()
                and (thread is None or isinstance(thread, threading.Thread)
                     and not thread.is_alive()))

    def shutdown_companions_retired(self) -> bool:
        """GUI-safe retained memory only; no files, sockets or native probes."""
        # Diagnostic only: names the stage that last withheld proof.
        self._companion_retirement_blocker = "preconditions"
        if (getattr(self, "_shutdown_custody_captured", False) is not True
                or getattr(self, "_critical_cleanup_observed", False) is not True
                or getattr(self, "_shutdown_fences_incomplete", False) is True):
            return False
        requested = getattr(self, "_shutdown_requested", None)
        if not isinstance(requested, threading.Event) or not requested.is_set():
            return False
        resilience_rows = tuple(getattr(self, "_shutdown_resilience_custody", ()))
        blackboxes = tuple(getattr(self, "_shutdown_blackbox_custody", ()))
        inventories = tuple(getattr(self, "_shutdown_inventory_custody", ()))
        healers = tuple(getattr(self, "_shutdown_healer_custody", ()))
        # An owner published late by startup must be captured and retired too.
        self._companion_retirement_blocker = "late-owner-uncaptured"
        for current, retained in (
            (getattr(self, "_resilience", None), tuple(owner for owner, _ in resilience_rows)),
            (getattr(self, "_blackbox_proc", None), blackboxes),
            (getattr(self, "_process_snapshot_lifecycle", None), inventories),
            (getattr(self, "_runtime_healer", None), healers),
        ):
            if current is not None and not any(current is owner for owner in retained):
                return False
        self._companion_retirement_blocker = "resilience-manager"
        for owner, custody in resilience_rows:
            proof = getattr(owner, "shutdown_retired", None)
            try:
                if not callable(proof) or proof(custody) is not True:
                    detail = str(getattr(owner, "_retirement_blocker", ""))
                    if detail:
                        self._companion_retirement_blocker = "resilience-manager:" + detail[:180]
                    return False
            except Exception:
                return False
        self._companion_retirement_blocker = "blackbox-inventory-healer"
        if (any(not self._blackbox_retirement_proven(owner) for owner in blackboxes)
                or any(not self._inventory_retirement_proven(owner) for owner in inventories)
                or any(not self._healer_retirement_proven(owner) for owner in healers)):
            return False
        # A critical worker's earlier false sample cannot permanently hold a
        # helper that retires later. Both getters inspect current owned memory
        # without waiting on a lock or performing native/file/socket discovery.
        from angerona.core.mobile_cli_custody import signal_retirement_proven_memory
        self._companion_retirement_blocker = "signal-helper"
        if signal_retirement_proven_memory() is not True:
            return False
        from angerona.core.ollama_lifecycle import owned_ollama_retirement_proven
        # Configured-model unload errors remain in their separate diagnostic;
        # this predicate establishes actual owned process/admission retirement.
        self._companion_retirement_blocker = "owned-ollama"
        retired = owned_ollama_retirement_proven() is True
        if retired:
            self._companion_retirement_blocker = ""
        return retired

    def _shutdown_critical_owned(self) -> None:
        errors = set(getattr(self, "_shutdown_custody_capture_errors", ()))
        errors.update(getattr(self, "_shutdown_fence_errors", ()))
        try:
            # Include a manager/sidecar published by in-flight startup after the
            # initial STOP capture. Never replace the earlier retained owners.
            self._capture_shutdown_custody()
        except Exception as error:
            errors.add("custody:" + type(error).__name__)
        for inventory in tuple(getattr(self, "_shutdown_inventory_custody", ())):
            try:
                inventory.request_stop()
            except Exception as error:
                errors.add("inventory:" + type(error).__name__)
        # Resilience-free launches retain their exact Black Box process/Job.
        # A root-only Popen wait is not proof that all descendants retired.
        for blackbox in tuple(getattr(self, "_shutdown_blackbox_custody", ())):
            if self._blackbox_retirement_proven(blackbox):
                continue
            try:
                if getattr(blackbox, "owns_descendants", False) is True:
                    from angerona.core.windows_child_job import OwnedWindowsChild
                    if (getattr(self, "_operator_stop_recorded", False) is True
                            and type(blackbox) is OwnedWindowsChild):
                        OwnedWindowsChild.terminate_for_operator_stop(blackbox)
                    else:
                        blackbox.terminate()
                    blackbox.wait(timeout=3.0)
                    blackbox.wait_tree(timeout=3.0)
                    blackbox.close()
                    if not self._blackbox_retirement_proven(blackbox):
                        raise RuntimeError("Black Box native retirement receipt is incomplete")
                    if getattr(self, "_blackbox_proc", None) is blackbox:
                        self._blackbox_proc = None
                else:
                    if blackbox.poll() is None:
                        blackbox.terminate()
                        try:
                            blackbox.wait(timeout=2.0)
                        except Exception:
                            blackbox.kill()
                            blackbox.wait(timeout=2.0)
                    errors.add("blackbox:descendant-custody-unavailable")
            except Exception as error:
                errors.add("blackbox:" + type(error).__name__)
        # AI retires independently even when another companion is held.
        try:
            from angerona.core.ollama_lifecycle import shutdown_ollama, owned_ollama_retirement_proven
            if (not getattr(self, "_critical_ai_done", False)
                    or not owned_ollama_retirement_proven()):
                shutdown_ollama(
                    getattr(self.config, "ollama_host", "http://localhost:11434"),
                    getattr(self.config, "ollama_model", "llama3"),
                )
            self._critical_ai_done = owned_ollama_retirement_proven() is True
            self._critical_ai_error_type = "" if self._critical_ai_done else "OllamaRetirementIncomplete"
        except Exception as error:
            self._critical_ai_done = False
            self._critical_ai_error_type = type(error).__name__
        try:
            self._record_ai_retirement_outcome()
        except Exception as error:
            self._critical_ai_diagnostic_saved = False
            self._critical_ai_diagnostic_error_type = type(error).__name__
        for resilience, custody in tuple(getattr(self, "_shutdown_resilience_custody", ())):
            try:
                resilience.stop(terminate_children=True)
                proof = getattr(resilience, "shutdown_retired", None)
                # A companion that observes STOP itself may prove its exit a
                # moment after the first pass. stop() keeps exact custody and
                # skips receipted components, so bounded retries stay narrow.
                retry_until = time.monotonic() + 8.0
                while (callable(proof) and proof(custody) is not True
                       and time.monotonic() < retry_until):
                    time.sleep(0.25)
                    resilience.stop(terminate_children=True)
                if not callable(proof) or proof(custody) is not True:
                    errors.add("resilience:retirement-unproven")
            except Exception as error:
                errors.add("resilience:" + type(error).__name__)
        for healer in tuple(getattr(self, "_shutdown_healer_custody", ())):
            try:
                healer.stop()
                if not self._healer_retirement_proven(healer):
                    errors.add("healer:retirement-unproven")
            except Exception as error:
                errors.add("healer:" + type(error).__name__)
        for inventory in tuple(getattr(self, "_shutdown_inventory_custody", ())):
            waiter = getattr(inventory, "wait_retired", None)
            if callable(waiter):
                try:
                    waiter(timeout=3.0)
                except Exception as error:
                    errors.add("inventory:" + type(error).__name__)
            if not self._inventory_retirement_proven(inventory):
                errors.add("inventory:retirement-unproven")
        # Cancellation already fenced new Signal calls. Sample/wait off Qt;
        # no GUI predicate takes the Signal registry's potentially held lock.
        signal_outcome = self._signal_retirement_outcome()
        deadline = time.monotonic() + 3.0
        while not self._signal_retirement_proven(signal_outcome) and time.monotonic() < deadline:
            time.sleep(.02)
            signal_outcome = self._signal_retirement_outcome()
        self._signal_retirement_at_shutdown = signal_outcome
        self._critical_signal_done = self._signal_retirement_proven(signal_outcome)
        if not self._critical_signal_done:
            errors.add("signal:retirement-unproven")
        self._critical_companion_errors = tuple(sorted(errors))
        self._critical_cleanup_observed = True

    def _engine_threads_retired(self) -> bool:
        """Bounded exact in-memory references, never name-based thread discovery."""
        manager = getattr(self, "manager", None)
        modules = getattr(manager, "modules", None)
        if type(modules) is not dict or len(modules) > 256:
            return False
        owners = [self, manager, *tuple(modules.values())]
        for name in ("reporter", "flight_recorder_worker", "evidence_ingestion",
                     "process_baseline", "alert_retention_worker", "sentinel_lens_service",
                     "recorder_integrity_runtime", "live_debug_service", "_breach_state_controller"):
            owner = getattr(self, name, None)
            if owner is not None:
                owners.append(owner)
        current = threading.current_thread()
        for owner in owners:
            fields = vars(owner)
            if len(fields) > 512:
                return False
            for value in tuple(fields.values()):
                values = (value,)
                if type(value) in (tuple, list):
                    if len(value) > 512:
                        return False
                    values = value
                elif type(value) is dict:
                    if len(value) > 512:
                        continue  # Data maps are not a thread-ownership API.
                    values = tuple(value.values())
                for worker in values:
                    if isinstance(worker, threading.Thread) and worker is not current and worker.is_alive():
                        return False
        return True

    def finalize_source_stop(self, gui_result) -> None:
        """Worker-only epoch receipt after GUI and owned companions have retired."""
        source_context = getattr(self, "_source_stop_context", None)
        if source_context is None:
            return  # Installed authority has its separate durable STOP protocol.
        if (type(gui_result) is not dict or gui_result.get("state") != "retired"
                or gui_result.get("forced") is not False
                or gui_result.get("pending_workers") != []
                or gui_result.get("pending_custody") != []
                or getattr(self, "_operator_stop_recorded", False) is not True
                or getattr(self, "_optional_owned_drained", False) is not True
                or self.shutdown_companions_retired() is not True):
            raise RuntimeError("Source epoch remains stopped; complete retirement is unproven")
        # Module.stop() signals rather than joins. Give those exact captured
        # generations a short final chance to retire; never claim hung work did.
        deadline = time.monotonic() + 3.0
        while not self._engine_threads_retired() and time.monotonic() < deadline:
            time.sleep(.02)
        if not self._engine_threads_retired():
            raise RuntimeError("Source epoch remains stopped; an owned engine thread is pending")
        source_context.mark_retired()
        self._source_stop_epoch_retired = True

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
        recorder_generation = None
        try:
            before_stop = self.flight_recorder_worker.retirement_snapshot()
            if (type(before_stop) is dict and type(before_stop.get("schema")) is int
                    and before_stop["schema"] == 1
                    and type(before_stop.get("worker_generation")) is int and before_stop["worker_generation"] >= 0):
                recorder_generation = before_stop["worker_generation"]
        except Exception:
            pass
        try:
            recorder_drained = self.flight_recorder_worker.stop(timeout=3.0)
        except Exception:
            pass
        self._recorder_drained_at_shutdown = recorder_drained is True
        recorder_retired = recorder_drained is True
        if not recorder_retired and recorder_generation is not None:
            try:
                retired = self.flight_recorder_worker.retirement_snapshot()
                if (type(retired) is dict and type(retired.get("schema")) is int and retired["schema"] == 1
                        and retired.get("worker_generation") == recorder_generation
                        and type(retired.get("worker_generation")) is int
                        and retired.get("workers_retired") is True and retired.get("stopping") is True
                        and type(retired.get("pending_events")) is int and retired["pending_events"] >= 0):
                    recorder_retired = True
                    self._recorder_pending_at_shutdown = retired["pending_events"]
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
        optional_drained = getattr(self, "_optional_owned_drained", True)
        integrity = getattr(self, "recorder_integrity_runtime", None)
        if integrity is not None:
            try:
                optional_drained = integrity.stop(timeout=3.0) and optional_drained
            except Exception:
                optional_drained = False
        if recorder_retired and optional_drained:
            self.storage.close()
        try:
            if self.evidence_store is not None and evidence_drained and optional_drained:
                self.evidence_store.close()
        except Exception:
            pass
