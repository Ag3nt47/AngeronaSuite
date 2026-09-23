from __future__ import annotations

from types import SimpleNamespace
import sys

import pytest


def test_console_close_detaches_without_a_stop_command():
    pytest.importorskip("PySide6")
    from angerona.gui.engine_console import EngineConsole
    window = EngineConsole(start_worker=False)
    window.show()
    window.close()
    assert window.worker.stop.is_set()
    assert window.worker.commands.empty()


def test_console_reports_disconnect_and_bounds_event_history():
    pytest.importorskip("PySide6")
    from angerona.gui.engine_console import EngineConsole
    window = EngineConsole(start_worker=False)
    try:
        status = {"instance": "x", "state": "ready", "mode": "Chill", "enabled_count": 1,
                  "pid": 42, "reason": "Running", "modules": [],
                  "settings": {"alert_retention_days": 14, "alert_retention_max_mib": 128},
                  "response": {"state": "DISABLED", "reason": "Operator policy disables response"}}
        window.render_frame({"status": status, "events": {"events": []}})
        assert window.chill.isEnabled()
        assert window.retention_days.value() == 14
        assert "Operator policy" in window.response.text()
        for index in range(1100):
            window.events.appendPlainText(str(index))
        assert window.events.document().blockCount() <= 1000
        window.render_frame({"error": "Connection lost"})
        assert "unknown" in window.banner.text()
        assert not window.chill.isEnabled()
    finally:
        window.close()


def test_console_worker_queues_are_bounded_and_detach_never_stops_engine():
    pytest.importorskip("PySide6")
    from angerona.gui.engine_console import ConsoleWorker
    worker = ConsoleWorker()
    for _ in range(8):
        assert worker.submit("connect")
    assert not worker.submit("connect")
    for value in range(8):
        worker._post({"error": str(value)})
    assert worker.frames.qsize() == 4
    assert worker.dropped_frames == 4
    worker.detach()
    assert worker.commands.qsize() == 8


@pytest.mark.parametrize("flag", ["--engine-console", "--engine-serve"])
def test_user_engine_route_precedes_embedded_singleton(monkeypatch, flag):
    from angerona import __main__ as entry
    from angerona.core import privilege, singleton
    monkeypatch.setattr(sys, "argv", ["angerona", flag])
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    monkeypatch.setattr(privilege, "is_admin", lambda: False)
    def forbidden():
        raise AssertionError("client must not own embedded singleton or elevate")
    monkeypatch.setattr(privilege, "ensure_admin", forbidden)
    monkeypatch.setattr(singleton, "acquire_single_instance", forbidden)
    monkeypatch.setattr(entry, "_run_engine_mode", lambda selected: 123 if selected == flag else 0)
    assert entry.main() == 123


def test_packaged_console_still_requires_exact_identity_without_uac(monkeypatch):
    from angerona import __main__ as entry
    from angerona.core import privilege, windows_package_identity
    monkeypatch.setattr(sys, "argv", ["angerona", "--engine-console"])
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(privilege, "is_admin", lambda: False)
    monkeypatch.setattr(privilege, "ensure_admin", lambda: pytest.fail("console must not request UAC"))
    monkeypatch.setattr(windows_package_identity, "verify_current_msix_authority",
                        lambda: SimpleNamespace(trusted=False, reason="unprovisioned pin"))
    monkeypatch.setattr(entry, "_run_engine_mode", lambda mode: pytest.fail("untrusted package ran"))
    assert entry.main() == 2


def test_source_elevated_console_remains_refused(monkeypatch):
    from angerona import __main__ as entry
    from angerona.core import privilege
    monkeypatch.setattr(sys, "argv", ["angerona", "--engine-console"])
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    monkeypatch.setattr(privilege, "is_admin", lambda: True)
    monkeypatch.setattr(entry, "_run_engine_mode", lambda mode: pytest.fail("elevated source ran"))
    assert entry.main() == 2
