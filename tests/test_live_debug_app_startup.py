"""A real desktop graph can share inert diagnostics without starting sensors."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap

import pytest


_DESKTOP_SMOKE = textwrap.dedent(r'''
    import json
    import os
    from pathlib import Path
    import subprocess
    import sys
    import threading
    import time

    from PySide6.QtCore import QCoreApplication, QEvent, QTimer
    from PySide6.QtWidgets import QApplication
    from angerona.core import data_paths
    data_paths._elevated_source_runtime = lambda: False
    from angerona.core.config import Config
    from angerona.core.eventbus import Event, Severity
    from angerona.core.live_debug import LiveDebugClient
    from angerona.core import ollama_lifecycle
    from angerona.app import AngeronaApp

    root = Path(sys.argv[1])
    config = Config(data_dir=root, blackbox_enabled=False, autostart_enabled=False,
                    holographic_orb_enabled=False, alert_retention_enabled=False,
                    ollama_host="http://127.0.0.1:65534", eco_mode=True)
    config.save()
    # No test should unload or start the operator's existing model service.
    ollama_lifecycle.unload_angerona_models = lambda *_args, **_kwargs: None
    ollama_lifecycle.request_ollama_start = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        AssertionError("desktop constructor tried to start Ollama"))
    # Constructor-only smoke does not permit a helper, scanner, browser, or
    # notification process. Optional read-only Wi-Fi probes fail closed here.
    native_popen = subprocess.Popen
    subprocess.Popen = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        AssertionError("desktop constructor tried to start a child process"))
    qt = QApplication([])
    qt.setQuitOnLastWindowClosed(False)
    owned = AngeronaApp(qt, force_chill=True, live_debug=True)
    service = owned.live_debug_service
    assert service is not None and service.status()["running"], service.status()
    assert owned.manager.modules == {}, "constructor unexpectedly discovered sensors"
    assert owned._resilience is None
    records, failures, heartbeats = [], [], []
    done, stop = threading.Event(), threading.Event()
    client_ref = []

    def read_views():
        client = LiveDebugClient(service.endpoint, os.getpid(), service.birth)
        client_ref.append(client)
        try:
            client.connect()
            deadline = time.monotonic() + 12
            while not stop.is_set() and time.monotonic() < deadline:
                record = client.read(timeout=.1)
                if record is not None:
                    records.append(record)
                event_seen = any(row.get("message") == "Inert desktop harness smoke" for row in records)
                error_seen = any("desktop error smoke" in row.get("message", "") for row in records)
                if event_seen and error_seen:
                    done.set()
                    return
        except Exception as error:
            failures.append(type(error).__name__ + ": " + str(error))
        finally:
            client.close()

    reader = threading.Thread(target=read_views, name="DesktopSmokeReader")
    reader.start()
    timer = QTimer()
    timer.setInterval(10)
    timer.timeout.connect(lambda: heartbeats.append(time.monotonic()))
    started = time.monotonic()
    timer.start()
    try:
        owned.window.show()
        owned.bus.publish(Event("Self-Test", "Inert desktop harness smoke", Severity.INFO,
                                details={"self_test": True, "simulation": True,
                                         "disposition": "observation", "pid": os.getpid()}))
        error_log = root / "diagnostics" / "crash.log"
        error_log.parent.mkdir(exist_ok=True)
        error_log.write_text("ValueError: desktop error smoke password=private-fixture\n", encoding="utf-8")
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline and (not done.is_set() or len(heartbeats) < 10):
            qt.processEvents()
            time.sleep(.003)
        assert not failures, failures
        assert done.is_set(), records
        assert len(heartbeats) >= 10, heartbeats
        gaps = [heartbeats[0] - started, *(b - a for a, b in zip(heartbeats, heartbeats[1:]))]
        assert max(gaps) < 2.0, gaps
        event = next(row for row in records if row.get("message") == "Inert desktop harness smoke")
        assert event["original_integrity_verified"] is True
        assert len(event["original_hmac"]) == 64
        assert event["advisory_only"] is True
        error = next(row for row in records if "desktop error smoke" in row.get("message", ""))
        assert error["kind"] == "diagnostic"
        assert "private-fixture" not in error["message"]
        assert owned.manager.modules == {}
        result = {"event_verified": True, "error_redacted": True, "qt_heartbeats": len(heartbeats),
                  "max_heartbeat_gap_ms": max(gaps) * 1000, "records": len(records)}
    finally:
        timer.stop()
        stop.set()
        for client in client_ref:
            client.cancel()
        reader.join(3)
        owned.shutdown()
        # This test keeps QApplication alive after app shutdown to inspect the
        # completed graph, so stop presentation timers before closing stores.
        for child_timer in owned.window.findChildren(QTimer):
            child_timer.stop()
        watchdog = getattr(owned.window, "_ui_watchdog", None)
        if watchdog is not None:
            watchdog.stop()
        owned.window._panel_reveal.shutdown()
        owned.window._holographic_orb.shutdown()
        owned.window.tray.hide()
        owned.window.hide()
        owned.window.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        subprocess.Popen = native_popen
    assert not reader.is_alive()
    assert not service.status()["running"]
    assert service._thread is None or not service._thread.is_alive()
    assert all(not thread.is_alive() for thread in service._server.threads)
    assert not any("LiveDebugService" in metric.name for metric in owned.bus.subscriber_metrics())
    result["native_readers_stopped"] = True
    print("LIVE_DEBUG_DESKTOP_SMOKE " + json.dumps(result), flush=True)
    qt.shutdown()
''')


@pytest.mark.skipif(os.name != "nt", reason="Windows desktop outbound pipe")
def test_real_desktop_constructor_streams_signed_event_and_error_off_gui_thread(tmp_path):
    data_root = tmp_path / "desktop-data"
    data_root.mkdir()
    temporary = tmp_path / "temporary"
    temporary.mkdir()
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith("ANGERONA_")}
    environment.update(ANGERONA_DATA=str(data_root), ANGERONA_DIAG_DIR=str(data_root / "diagnostics"),
                       ANGERONA_BLACKBOX_ENABLED="0", ANGERONA_RESILIENCE="0",
                       QT_QPA_PLATFORM="offscreen", OLLAMA_HOST="http://127.0.0.1:65534",
                       TEMP=str(temporary), TMP=str(temporary), PYTHONNOUSERSITE="1")
    completed = subprocess.run([sys.executable, "-c", _DESKTOP_SMOKE, str(data_root)],
                               cwd=Path(__file__).parents[1], env=environment,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               encoding="utf-8", errors="replace", timeout=90,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    assert completed.returncode == 0, completed.stdout + "\n" + completed.stderr
    marker = next(line for line in completed.stdout.splitlines() if line.startswith("LIVE_DEBUG_DESKTOP_SMOKE "))
    result = json.loads(marker.partition(" ")[2])
    assert result["event_verified"] and result["error_redacted"]
    assert result["native_readers_stopped"]
    assert result["qt_heartbeats"] >= 10
    assert result["max_heartbeat_gap_ms"] < 2000


def test_live_debug_switch_reaches_app_and_is_removed_before_qt(monkeypatch):
    from types import SimpleNamespace
    import PySide6.QtWidgets as widgets
    import angerona.__main__ as entrypoint
    import angerona.app as application
    from angerona import branding
    from angerona.core import crashlog, data_paths, hardening, privilege, singleton, win
    from angerona.core.process_snapshot_lifecycle import ProcessSnapshotLifecycle
    from angerona.telemetry import sensors

    calls = {}

    class Qt:
        def __init__(self, arguments):
            calls["qt_arguments"] = arguments

        def setApplicationName(self, _name):
            pass

        def setQuitOnLastWindowClosed(self, _enabled):
            pass

        def exec(self):
            return 0

    class App:
        def __init__(self, qt, **kwargs):
            calls["application_arguments"] = kwargs
            self.inventory = kwargs["process_snapshot_lifecycle"]
            assert isinstance(self.inventory, ProcessSnapshotLifecycle)
            assert sensors._process_snapshot_provider is self.inventory.provider
            assert self.inventory._thread is None

        def start(self):
            calls["started"] = True

        def shutdown(self):
            calls["shutdown"] = calls.get("shutdown", 0) + 1
            self.inventory.request_stop()

    monkeypatch.setattr(sys, "argv", ["angerona", "--chill", "--live-debug"])
    monkeypatch.delattr(sys, "frozen", raising=False)
    monkeypatch.setattr(privilege, "is_admin", lambda: False)
    monkeypatch.setattr(data_paths, "configure_runtime_environment", lambda: None)
    monkeypatch.setattr(crashlog, "install", lambda: [])
    monkeypatch.setattr(hardening, "apply_process_mitigations", lambda: {})
    monkeypatch.setattr(win, "install_no_window_default", lambda: None)
    monkeypatch.setattr(singleton, "acquire_single_instance", lambda: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(branding, "icon_path", lambda: None)
    monkeypatch.setattr(entrypoint, "_install_fast_pyside_feature_detection", lambda: True)
    monkeypatch.setattr(application, "AngeronaApp", App)
    # Restore QApplication before the repository's earlier autouse fixture
    # drains native Qt deferred deletions during teardown.
    with monkeypatch.context() as qt_patch:
        qt_patch.setattr(widgets, "QApplication", Qt)
        assert entrypoint.main() == 0
    assert calls["qt_arguments"] == ["angerona"]
    assert calls["application_arguments"]["live_debug"] is True
    assert calls["application_arguments"]["force_chill"] is True
    assert calls["started"] is True
    owner = calls["application_arguments"]["process_snapshot_lifecycle"]
    assert calls["shutdown"] == 1
    assert owner._thread is None and owner._stop_requested.is_set()
    assert owner.lifecycle_snapshot()["retired"] is True
    assert sensors._process_snapshot_provider is owner.provider
