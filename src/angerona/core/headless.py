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
from angerona.core.eventbus import EventBus
from angerona.core.independent_high_water import IndependentHighWater
from angerona.core.module_manager import ModuleManager
from angerona.core.platforms import current_platform
from angerona.core.status_report import StatusReporter
from angerona.core.storage import AsyncFlightRecorder, FlightRecorder


def run_headless(
    *, high_water_provider: IndependentHighWater | None = None
) -> int:
    """Build core services (no Qt), start modules, and block until signalled."""
    config = Config.load()
    storage = FlightRecorder(config.db_path)
    bus = EventBus()
    bus.arm(storage.authority)

    # Same authoritative, bounded recorder path as the GUI. Direct SQLite work
    # in an EventBus callback stalls the publishing sensor even though the bus
    # mutex is released; the worker callback is only a bounded put_nowait and
    # preserves overflow through the authenticated DLQ.
    recorder_worker = AsyncFlightRecorder(storage)
    recorder_worker.start()
    bus.subscribe(recorder_worker.submit)
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

    manager = ModuleManager(
        bus,
        config,
        recorder=storage,
        high_water_provider=high_water_provider,
    )
    reporter = StatusReporter(bus, storage, manager, config)
    chill = None
    if getattr(config, "eco_mode", True):
        chill = ChillRuntimeController(
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
        setattr(config, "runtime_chill_active", False)
        os.environ.pop("ANGERONA_CHILL_ACTIVE", None)

    # The JARVIS adapter is independent from read-only MCP and works in
    # headless mode so JARVIS can remain the single visible control surface.
    # Start it before the expensive module-discovery pass; status truthfully
    # reports 0/0 until discovery fills the manager, while the bounded scan
    # catalog is already usable.
    _jarvis_control = None
    if getattr(config, "jarvis_control_enabled", False):
        try:
            from angerona.engines.jarvis_control_server import (
                AngeronaJarvisControlServer,
            )
            _jarvis_control = AngeronaJarvisControlServer(manager, config)
            _jarvis_control.start()
            print(
                "[Angerona] Authenticated JARVIS defensive control adapter started.",
                flush=True,
            )
        except Exception as exc:
            _jarvis_control = None
            print(
                "[Angerona] JARVIS control adapter unavailable: "
                f"{type(exc).__name__}.",
                flush=True,
            )

    manager.discover()
    if chill is not None:
        deferred = chill.prepare_modules()
        skipped = manager.start_enabled(deferred_names=deferred)
        chill.start(skipped)
    else:
        # Preserve the historical Full-mode startup path exactly.
        manager.start_enabled()
    reporter.start()

    # Opt-in decoupled resilience ecosystem (standalone scanner + supervisor +
    # core heartbeat, feeding raw telemetry back onto the bus). Off by default;
    # enable with ANGERONA_RESILIENCE=1. Never fatal to core startup.
    _resilience = None
    if (
        current_platform() == "windows"
        and os.environ.get("ANGERONA_RESILIENCE", "") in ("1", "true", "yes", "on")
    ):
        try:
            from angerona.resilience.manager import start_resilience
            _resilience = start_resilience(bus)
            print("[Angerona] Resilience ecosystem started (scanner supervised).", flush=True)
        except Exception as exc:
            print(f"[Angerona] Resilience ecosystem failed to start: {exc}", flush=True)

    mode = "network-first Chill" if chill is not None else "Full"
    print(f"[Angerona] Headless mode ({mode}) — {len(manager.modules)} modules discovered, "
          f"enabled ones running. DB: {config.db_path}. Ctrl+C to stop.", flush=True)

    stop = threading.Event()

    def _handle(_signum, _frame):
        stop.set()

    for sig in (signal.SIGINT, getattr(signal, "SIGTERM", signal.SIGINT)):
        try:
            signal.signal(sig, _handle)
        except (ValueError, OSError):
            pass   # not on the main thread / unsupported — Ctrl+C still raises

    try:
        while not stop.is_set():
            stop.wait(timeout=1.0)
    except KeyboardInterrupt:
        pass
    finally:
        if chill is not None:
            chill.stop()
        if _jarvis_control is not None:
            try:
                _jarvis_control.stop()
            except Exception:
                pass
        if _resilience is not None:
            try:
                _resilience.stop()
            except Exception:
                pass
        reporter.stop()
        manager.stop_all()
        recorder_drained = False
        try:
            recorder_drained = recorder_worker.stop(timeout=3.0)
        except Exception:
            pass
        # Never close SQLite underneath a still-running writer. Process teardown
        # safely reclaims it if a damaged filesystem exceeds the bounded drain.
        if recorder_drained:
            storage.close()
        else:
            print(
                "[Angerona] Recorder drain timed out; storage left open for safe process teardown.",
                flush=True,
            )
        print("[Angerona] Headless shutdown complete.", flush=True)
    return 0
