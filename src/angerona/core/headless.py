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
from angerona.core.eventbus import EventBus
from angerona.core.module_manager import ModuleManager
from angerona.core.status_report import StatusReporter
from angerona.core.storage import FlightRecorder


def run_headless() -> int:
    """Build core services (no Qt), start modules, and block until signalled."""
    config = Config.load()
    storage = FlightRecorder(config.db_path)
    bus = EventBus()
    bus.arm(storage.authority)

    # Same subscriptions app.py wires, minus anything GUI-bound.
    bus.subscribe(storage.record_bus)
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

    manager = ModuleManager(bus, config)
    reporter = StatusReporter(bus, storage, manager, config)

    manager.discover()
    manager.start_enabled()
    reporter.start()

    # Opt-in decoupled resilience ecosystem (standalone scanner + supervisor +
    # core heartbeat, feeding raw telemetry back onto the bus). Off by default;
    # enable with ANGERONA_RESILIENCE=1. Never fatal to core startup.
    _resilience = None
    if os.environ.get("ANGERONA_RESILIENCE", "") in ("1", "true", "yes", "on"):
        try:
            from angerona.resilience.manager import start_resilience
            _resilience = start_resilience(bus)
            print("[Angerona] Resilience ecosystem started (scanner supervised).", flush=True)
        except Exception as exc:
            print(f"[Angerona] Resilience ecosystem failed to start: {exc}", flush=True)

    print(f"[Angerona] Headless mode — {len(manager.modules)} modules discovered, "
          f"enabled ones running. DB: {config.db_path}. Ctrl+C to stop.", flush=True)

    stop = threading.Event()

    def _handle(signum, _frame):
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
        if _resilience is not None:
            try:
                _resilience.stop()
            except Exception:
                pass
        reporter.stop()
        manager.stop_all()
        storage.close()
        print("[Angerona] Headless shutdown complete.", flush=True)
    return 0
