"""headless.py — GUI-less execution mode for silent sensor / home-server nodes.

Launched via ``python -m angerona --headless``. Builds exactly the core services
the suite needs to sense, persist, and forward telemetry — Config, EventBus,
FlightRecorder, the incident correlator, the ATT&CK tracker, the remediation
audit log, and the ModuleManager — and starts every enabled module. It never
imports PySide6, so it runs cleanly on a headless box with no Qt installed.

Typical deployment: run the sensor node headless with the Remote Bridge module in
SENDER mode (``ANGERONA_BRIDGE_MODE=SENDER``) so HIGH/CRITICAL telemetry is
forwarded to the main PC, which runs the full GUI and Ollama triage.

The process blocks until Ctrl+C / SIGTERM, then shuts modules and storage down
cleanly. This mirrors ``app.py`` minus the window — keep the two service graphs
in sync if either changes.
"""
from __future__ import annotations

import signal
import os
import threading
import time

from angerona.core.config import Config
from angerona.core.chill_runtime import ChillRuntimeController
from angerona.core.eventbus import Event, EventBus
from angerona.core.independent_high_water import IndependentHighWater
from angerona.core.module_manager import ModuleManager
from angerona.core.platforms import current_platform
from angerona.core.status_report import StatusReporter
from angerona.core.process_snapshot_lifecycle import ProcessSnapshotLifecycle
from angerona.core.storage import AsyncFlightRecorder, FlightRecorder, RecorderInitializationPending

_HEADLESS_RETIREMENT_HOLD = None


class HeadlessRetirementPending(RuntimeError):
    """The graph still owns resources; its service lease must remain held."""


class _HeadlessResources:
    def __init__(self, stop, inventory, runtime_control):
        self.stop, self.inventory, self.runtime_control = stop, inventory, runtime_control
        self.storage = self.recorder = self.retention = self.metrics_publisher = None
        self.recorder_integrity = None
        self.manager = self.reporter = self.chill = self.jarvis = self.resilience = self.core_context = None
        self.pending = []
        self.partial_storage = None
        self._closed = False

    def _retire(self, name, target, callback, *, boolean=False):
        if target is None:
            return
        try:
            result = callback()
            if result is False or boolean and result is not True:
                self.pending.append(name)
        except BaseException as exc:
            self.pending.append(name + ":" + type(exc).__name__)

    def _join_owned_threads(self, targets, timeout=3.0):
        deadline = time.monotonic() + timeout
        seen = set()
        for name, worker in targets:
            if not isinstance(worker, threading.Thread) or id(worker) in seen:
                continue
            seen.add(id(worker))
            try:
                if worker.ident is not None and worker is not threading.current_thread():
                    worker.join(max(0.0, deadline - time.monotonic()))
                if worker.is_alive():
                    self.pending.append(name)
            except BaseException as exc:
                self.pending.append(name + ":" + type(exc).__name__)

    def hold(self, reason):
        global _HEADLESS_RETIREMENT_HOLD

        if reason:
            self.pending.append(reason)
        _HEADLESS_RETIREMENT_HOLD = self
        if self.runtime_control is not None:
            self.runtime_control.graph_retirement_pending = True

    def close(self):
        if self._closed:
            if self.pending:
                raise HeadlessRetirementPending("Headless resource retirement remains pending")
            return
        self._closed = True
        self.stop.set()
        if self.recorder_integrity is not None:
            self._retire("integrity-request", self.recorder_integrity, self.recorder_integrity.request_stop)
        if self.core_context is not None:
            self._retire("core-context-request", self.core_context, self.core_context.request_stop)
        self._retire("chill", self.chill, lambda: self.chill.stop())
        self._retire("jarvis", self.jarvis, lambda: self.jarvis.stop())
        self._retire("resilience", self.resilience, lambda: self.resilience.stop(terminate_children=True))
        self._retire("reporter", self.reporter, lambda: self.reporter.stop())
        self._retire("modules", self.manager, lambda: self.manager.stop_all())
        if self.inventory is not None:
            self._retire("inventory-request", self.inventory, self.inventory.request_stop)
            self._retire("inventory", self.inventory, self.inventory.wait_retired, boolean=True)
        self._retire("core-context", self.core_context, lambda: self.core_context.close(), boolean=True)
        self._retire("retention", self.retention, lambda: self.retention.stop(timeout=2.0), boolean=True)
        self._retire("metrics", self.metrics_publisher, lambda: self.metrics_publisher.stop())
        threads = [("reporter-thread", getattr(self.reporter, "_thread", None)),
                   ("metrics-thread", getattr(self.metrics_publisher, "thread", None))]
        for name in ("_monitor_thread", "_wake_thread", "_maintenance_thread", "_release_thread"):
            threads.append(("chill" + name, getattr(self.chill, name, None)))
        for worker in getattr(self.resilience, "_threads", ()):
            threads.append(("resilience-thread", worker))
        for name, module in tuple(getattr(self.manager, "modules", {}).items()):
            threads.extend((("module:" + str(name), getattr(module, "_thread", None)),
                            ("module-restart:" + str(name), getattr(module, "_restart_waiter", None))))
        self._join_owned_threads(threads)
        self._retire("recorder", self.recorder, lambda: self.recorder.stop(timeout=3.0), boolean=True)
        self._retire("recorder-integrity", self.recorder_integrity,
                     lambda: self.recorder_integrity.stop(timeout=3.0), boolean=True)
        # Both producers and writer must retire before closing SQLite. A failed
        # startup has the same resource ownership obligations as normal STOP.
        if not self.pending:
            self._retire("storage", self.storage, lambda: self.storage.close())
        if self.pending:
            self.hold("")
            raise HeadlessRetirementPending("Headless resource retirement remains pending: " + ", ".join(self.pending))


def run_headless(
    *, high_water_provider: IndependentHighWater | None = None,
    stop_event: threading.Event | None = None,
    runtime_control=None,
    force_chill: bool = False,
    process_snapshot_lifecycle: ProcessSnapshotLifecycle | None = None,
    service_custody=None,
) -> int:
    """Build core services (no Qt), start modules, and block until signalled."""
    if service_custody is not None:
        from angerona.core.windows_engine_custody import active_engine_custody
        from angerona.core.engine_service_status import ServiceStatusControl

        if (service_custody is not active_engine_custody()
                or type(runtime_control) is not ServiceStatusControl):
            raise PermissionError("A protection service requires its admitted custody and read-only OS console")
    if _HEADLESS_RETIREMENT_HOLD is not None:
        raise HeadlessRetirementPending("A previous headless graph still owns pending resources")
    resources = _HeadlessResources(stop_event or threading.Event(), process_snapshot_lifecycle, runtime_control)
    try:
        return _run_headless_graph(resources=resources, high_water_provider=high_water_provider,
            runtime_control=runtime_control, force_chill=force_chill,
            process_snapshot_lifecycle=process_snapshot_lifecycle, service_custody=service_custody)
    except RecorderInitializationPending as error:
        # The constructor never returned, so resources.storage was not assigned.
        # Keep its exact partial owner and service lease rather than losing it
        # when the startup traceback is released.
        resources.partial_storage = error.owner
        resources.hold("storage-construction")
        raise
    finally:
        try:
            resources.close()
        except HeadlessRetirementPending:
            raise
        except BaseException as exc:
            resources.hold("cleanup:" + type(exc).__name__)
            raise HeadlessRetirementPending("Headless cleanup failed with retained resource ownership") from exc


def _run_headless_graph(*, resources, high_water_provider, runtime_control, force_chill,
                        process_snapshot_lifecycle, service_custody):
    config = Config.load()
    if high_water_provider is None:
        from angerona.core.recorder_integrity import provider_from_config
        high_water_provider = provider_from_config(config)
    if force_chill:
        # Runtime launch intent does not rewrite the saved startup preference.
        config.eco_mode = True
        from angerona.core.chill_mode import set_chill_ai_blocked
        set_chill_ai_blocked(config, True)
    storage = resources.storage = FlightRecorder(config.db_path)
    bus = EventBus()
    bus.arm(storage.authority)

    # Same authoritative, bounded recorder path as the GUI. Direct SQLite work
    # in an EventBus callback stalls the publishing sensor even though the bus
    # mutex is released; the worker callback is only a bounded put_nowait and
    # preserves overflow through the authenticated DLQ.
    recorder_worker = resources.recorder = AsyncFlightRecorder(storage)
    recorder_worker.start()
    bus.subscribe(recorder_worker.submit)
    from angerona.core.alert_retention import AlertRetentionWorker, RetentionPolicy
    from angerona.core.eventbus import Severity
    alert_retention = resources.retention = AlertRetentionWorker(config.data_dir, RetentionPolicy.from_config(config))
    alert_retention.start()
    from angerona.core.runtime_metrics import MetricsPublisher, RuntimeMetrics
    runtime_metrics = RuntimeMetrics(gui=False, recorder=recorder_worker, retention=alert_retention)
    if os.environ.get("ANGERONA_RUNTIME_METRICS") == "1":
        publisher = resources.metrics_publisher = MetricsPublisher(runtime_metrics, config.data_dir)
        publisher.start()

    def _retain_alert(event):
        if event.severity >= Severity.MEDIUM:
            alert_retention.append(f"{event.time_str} [{event.module}] {event.message[:2000]}")

    bus.subscribe(_retain_alert)
    try:
        from angerona.core.incidents import get_correlator
        bus.subscribe(get_correlator().on_event)
    except Exception:
        pass
    try:
        from angerona.core.remediation_log import init_log
        init_log(config.db_path)
    except Exception:
        pass
    try:
        from angerona.core.attack_tracker import init_tracker
        bus.subscribe(init_tracker().on_event)
    except Exception:
        pass

    manager = resources.manager = ModuleManager(
        bus,
        config,
        recorder=storage,
        high_water_provider=high_water_provider,
    )
    from angerona.core.recorder_integrity_runtime import RecorderIntegrityRuntime
    integrity = resources.recorder_integrity = RecorderIntegrityRuntime(config, bus, high_water_provider)
    manager.recorder_integrity_runtime = integrity
    try:
        integrity.start()
    except Exception:
        bus.publish(Event(
            module="Recorder Integrity", severity=Severity.MEDIUM,
            message="Independent recorder witnessing could not start; local records are preserved",
            details={"category": "integrity-coverage", "active_attack": False,
                "response_authorized": False, "response_authority": "unattributed-advisory"}))
    if service_custody is not None:
        from angerona.core.service_process_context import ServiceProcessContext

        context = resources.core_context = ServiceProcessContext(service_custody)
        manager.owned_process_identities = context.owned_process_identities
        context.start()
    reporter = resources.reporter = StatusReporter(
        bus, storage, manager, config,
        process_snapshot_lifecycle=process_snapshot_lifecycle,
    )
    chill = None
    if getattr(config, "eco_mode", True):
        chill = resources.chill = ChillRuntimeController(
            manager,
            bus,
            config,
            notify=lambda message: print(
                f"[Angerona] [chill] {message}", flush=True
            ),
        )
        # Publish before discovery/startup so every module and Ollama caller
        # observes the correct runtime profile from its first instruction.
        chill.prepare_runtime()
    else:
        from angerona.core.background_pacing import get_pacing_controller
        from angerona.core.chill_mode import set_chill_ai_blocked
        get_pacing_controller().set_chill_active(False)
        set_chill_ai_blocked(config, False)
        setattr(config, "runtime_chill_active", False)
        os.environ.pop("ANGERONA_CHILL_ACTIVE", None)

    stop = resources.stop
    if runtime_control is not None:
        runtime_control.attach(manager, bus, config, chill)
        runtime_control.retention = alert_retention
        runtime_control.runtime_metrics = runtime_metrics
    from angerona.core.ollama_lifecycle import request_ollama_start
    request_ollama_start(config.ollama_host, stop_event=stop)

    # The JARVIS adapter is independent from read-only MCP and works in
    # headless mode so JARVIS can remain the single visible control surface.
    # Start it before the expensive module-discovery pass; status truthfully
    # reports 0/0 until discovery fills the manager, while the bounded scan
    # catalog is already usable.
    _jarvis_control = None
    if service_custody is None and getattr(config, "jarvis_control_enabled", False):
        try:
            from angerona.engines.jarvis_control_server import (
                AngeronaJarvisControlServer,
            )
            _jarvis_control = resources.jarvis = AngeronaJarvisControlServer(manager, config)
            _jarvis_control.start()
            print(
                "[Angerona] Authenticated JARVIS defensive control adapter started.",
                flush=True,
            )
        except Exception as exc:
            print(
                "[Angerona] JARVIS control adapter unavailable: "
                f"{type(exc).__name__}.",
                flush=True,
            )

    if process_snapshot_lifecycle is not None:
        process_snapshot_lifecycle.start()
        if not process_snapshot_lifecycle.wait_started():
            print("[Angerona] Process inventory collector unavailable; local fallback is disabled.",
                  flush=True)
    manager.discover()
    if chill is not None:
        deferred = chill.prepare_modules()
        skipped = manager.start_enabled(deferred_names=deferred)
        chill.start(skipped)
    else:
        # Preserve the historical Full-mode startup path exactly.
        manager.start_enabled()
    reporter.start()
    if runtime_control is not None:
        runtime_control.ready()

    # Opt-in decoupled resilience ecosystem (standalone scanner + supervisor +
    # core heartbeat, feeding raw telemetry back onto the bus). Off by default;
    # enable with ANGERONA_RESILIENCE=1. Never fatal to core startup.
    _resilience = None
    if (
        service_custody is None
        and
        current_platform() == "windows"
        and os.environ.get("ANGERONA_RESILIENCE", "") in ("1", "true", "yes", "on")
    ):
        try:
            from angerona.resilience.manager import ResilienceManager
            _resilience = resources.resilience = ResilienceManager(bus=bus)
            _resilience.start()
            print("[Angerona] Resilience ecosystem started (scanner supervised).", flush=True)
        except Exception as exc:
            print(f"[Angerona] Resilience ecosystem failed to start: {exc}", flush=True)

    mode = "network-first Chill" if chill is not None else "Full"
    print(f"[Angerona] Headless mode ({mode}) — {len(manager.modules)} modules discovered, "
          f"enabled ones running. DB: {config.db_path}. Ctrl+C to stop.", flush=True)

    def _handle(_signum, _frame):
        stop.set()

    for sig in (signal.SIGINT, getattr(signal, "SIGTERM", signal.SIGINT)):
        try:
            signal.signal(sig, _handle)
        except (ValueError, OSError):
            pass   # not on the main thread / unsupported — Ctrl+C still raises

    try:
        while not stop.is_set():
            manager.reconcile_usage()
            stop.wait(timeout=1.0)
    except KeyboardInterrupt:
        pass
    return 0
