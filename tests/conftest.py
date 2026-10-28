"""Repository-wide test isolation for Angerona runtime state.

Tests must never read, rewrite, harden, or delete the operator's real
``runtime-data`` tree.  A few older tests only isolated their SQLite file and
still resolved signing keys and diagnostics through the production data root.
That became visible once the launcher correctly protected the real tree.
"""

from __future__ import annotations

import hashlib
import importlib
import os
import secrets
import threading
from pathlib import Path

import pytest


_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_SESSION_ROOT = (
    _PROJECT_ROOT
    / ".tmp"
    / "pytest-runtime"
    / f"{os.getpid()}-{secrets.token_hex(6)}"
)
_BOOTSTRAP_ROOT = _SESSION_ROOT / "collection"
_BOOTSTRAP_ROOT.mkdir(parents=True, exist_ok=True)

# Apply a D-drive boundary before pytest imports test modules. Individual tests
# receive a separate child below, but collection-time imports are isolated too.
os.environ["ANGERONA_DATA"] = str(_BOOTSTRAP_ROOT)
os.environ["ANGERONA_DIAG_DIR"] = str(_BOOTSTRAP_ROOT / "diagnostics")
os.environ["TEMP"] = str(_BOOTSTRAP_ROOT / "tmp")
os.environ["TMP"] = str(_BOOTSTRAP_ROOT / "tmp")
# Process-level adoption probes must never attach the test supervisor to the
# operator's live Black Box and terminate it during fixture cleanup.
os.environ["ANGERONA_BLACKBOX_ENABLED"] = "0"
# A Qt application is process-global native state.  Some UI tests create their
# first widget through a short-lived local Python reference; allowing that
# wrapper to be collected can destroy and later recreate QApplication, which
# PySide does not support reliably in one process (notably on Python 3.13).
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
Path(os.environ["TEMP"]).mkdir(parents=True, exist_ok=True)

# Hosted Windows runners use an administrator token. Tests still need their
# disposable per-case roots, while the dedicated custody tests below explicitly
# monkeypatch elevated mode back on when exercising that production boundary.
_data_paths = importlib.import_module("angerona.core.data_paths")
_data_paths._elevated_source_runtime = lambda: False


@pytest.fixture(scope="session", autouse=True)
def keep_qt_application_alive():
    """Anchor one headless QApplication for the entire pytest process."""
    try:
        from PySide6.QtWidgets import QApplication
    except ImportError:
        # Core-only development environments may intentionally omit the GUI
        # extra; their non-Qt tests should remain collectible and runnable.
        yield
        return

    app = QApplication.instance()
    owns_application = app is None
    if owns_application:
        app = QApplication([])
    app.setQuitOnLastWindowClosed(False)
    try:
        yield
    finally:
        # Complete requested deletions without dispatching unrelated timers or
        # callbacks from completed tests. The fixture that creates Qt also owns
        # its final cleanup, while Python and native wrappers are still intact.
        _drain_qt_deferred_deletes()
        if owns_application:
            app.shutdown()
            assert QApplication.instance() is None


@pytest.fixture(autouse=True)
def isolate_process_inventory_provider(monkeypatch):
    """Entry fixtures must not select an unavailable provider for later tests.

    Runtime shutdown deliberately keeps its provider registered to prevent a
    local fallback. Tests own and retire any started worker separately; this
    fixture restores only process-global routing and cached observations.
    """
    from angerona.telemetry import sensors

    monkeypatch.setattr(sensors, "_process_snapshot_provider", None)
    monkeypatch.setattr(sensors, "_process_snapshot_provider_generation", 0)
    monkeypatch.setattr(sensors, "_proc_cache", (0.0, None))


@pytest.fixture(autouse=True)
def isolate_runtime_chill_profile(monkeypatch):
    """Each test owns quiet pacing and the persistent operator AI lock."""
    from angerona.core import background_pacing

    monkeypatch.setattr(background_pacing, "_CONTROLLER", background_pacing.BackgroundPacingController())
    monkeypatch.delenv("ANGERONA_CHILL_ACTIVE", raising=False)
    monkeypatch.delenv("ANGERONA_CHILL_AI_BLOCKED", raising=False)


@pytest.fixture(autouse=True)
def isolate_automatic_ollama_startup(request: pytest.FixtureRequest, monkeypatch):
    """Legacy app/self-test fixtures must never start the operator's daemon.

    The dedicated startup suite keeps the real orchestration helpers and owns
    its own listener, process-launch and trust mocks. Other tests may replace
    these inert helpers explicitly when proving an integration decision.
    """
    from angerona.core import ollama_lifecycle
    monkeypatch.setattr(ollama_lifecycle, "_owned_services", {})
    if request.node.path.name in {"test_ollama_startup.py", "test_chill_ai_lock.py"}:
        return

    unavailable = ollama_lifecycle.OllamaStartupStatus(
        "failed", "Offline test", 0,
        "Native Ollama startup is disabled by the isolated test harness.",
    )

    def offline_start(*_args, progress=None, **_kwargs):
        if progress is not None:
            progress(unavailable)
        return unavailable

    def forbid_native_spawn(*_args, **_kwargs):
        raise AssertionError("An isolated test attempted to launch real Ollama")

    monkeypatch.setattr(ollama_lifecycle, "request_ollama_start", offline_start)
    monkeypatch.setattr(ollama_lifecycle, "ensure_ollama_service", offline_start)
    monkeypatch.setattr(ollama_lifecycle, "_spawn_ollama_service", forbid_native_spawn)


def _clear_data_path_caches() -> None:
    try:
        from angerona.core import data_paths

        data_paths._canonical_data_path.cache_clear()
        data_paths._ready_source_roots.clear()
    except Exception:
        pass


def _drain_qt_deferred_deletes() -> None:
    """Deliver only Qt deletions that the completed test already requested.

    QApplication and its top-level widgets are process-global native state.
    Closing every top-level here would make this fixture an owner of objects it
    did not create, including windows whose close handlers still coordinate
    worker shutdown.  Likewise, a general ``processEvents()`` pass can dispatch
    their timers and queued worker callbacks in the middle of teardown.

    ``deleteLater()`` is the one operation that does need an explicit boundary
    under pytest because there is no continuously running Qt event loop.  Two
    targeted passes also cover a destructor that queues another deferred delete
    without dispatching unrelated Qt work.
    """

    try:
        from PySide6.QtCore import QCoreApplication, QEvent
        from PySide6.QtWidgets import QApplication
    except ImportError:
        return

    app = QApplication.instance()
    if app is None:
        return

    for _ in range(2):
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)


@pytest.fixture(autouse=True)
def isolate_angerona_runtime(request: pytest.FixtureRequest, monkeypatch):
    """Give every test an independent runtime, diagnostics, and temp root."""
    identity = hashlib.sha256(request.node.nodeid.encode("utf-8")).hexdigest()[:20]
    root = _SESSION_ROOT / identity
    temp = root / "tmp"
    temp.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("ANGERONA_DATA", str(root))
    monkeypatch.setenv("ANGERONA_DIAG_DIR", str(root / "diagnostics"))
    monkeypatch.setenv("TEMP", str(temp))
    monkeypatch.setenv("TMP", str(temp))
    monkeypatch.setenv("ANGERONA_BLACKBOX_ENABLED", "0")
    _clear_data_path_caches()
    # Startup resolves canonical OS storage deliberately, ignoring ANGERONA_DATA.
    # Synthetic startup cases must replace that consumer alias too; custody tests
    # exercise the real implementation in core.startup_diagnostics separately.
    from angerona import startup

    monkeypatch.setattr(startup, "canonical_storage", lambda: root)
    monkeypatch.setattr(startup, "_STARTUP_CONTEXT", threading.local())
    # STOP is terminal for a real process generation, but pytest exercises
    # several independent generations in one interpreter.
    from angerona.core import ollama_lifecycle
    monkeypatch.setattr(ollama_lifecycle, "_ai_shutdown", threading.Event())
    try:
        yield
    finally:
        _drain_qt_deferred_deletes()
        _clear_data_path_caches()
