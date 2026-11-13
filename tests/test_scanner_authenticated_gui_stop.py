"""Inert scanner STOP/UI contracts; no native sensors, keys, files or Qt windows."""
from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from angerona.resilience import scanner


def _inert_host(monkeypatch, *, token=False, token_error=None, close_error=False):
    calls = []

    def close_ring():
        calls.append("ring-close")
        if close_error:
            raise OSError("inert ambiguous ring close")

    ring = SimpleNamespace(backpressure=False, drops=0, close=close_ring)
    beat = SimpleNamespace(beat=lambda: calls.append("beat"),
                           close=lambda: calls.append("beat-close"))
    monkeypatch.setattr(scanner.ipc_ring, "ring_path", lambda _name: "inert-ring")
    monkeypatch.setattr(scanner.ipc_ring, "RingWriter", lambda *_a, **_k: ring)
    monkeypatch.setattr(scanner.hb, "HeartbeatWriter", lambda *_a, **_k: beat)
    monkeypatch.setattr(scanner.ScannerHost, "_read_ping", lambda _self: "")
    monkeypatch.setattr(scanner.diag, "write_status",
                        lambda *_a, **_k: calls.append("status"))

    def admit():
        calls.append("token")
        if token_error:
            raise token_error
        return token

    monkeypatch.setattr(scanner.tok, "is_standdown_requested", admit)
    host = scanner.ScannerHost(interval=0.05)

    def poll():
        calls.append("poll")
        host.stop()  # Bound the unarmed case without sleeps or a native sensor.
        return []

    host.sensors = [SimpleNamespace(sensor_id=1, poll=poll)]
    return host, ring, calls


def test_verified_stop_retires_sensor_owners_before_requesting_gui_quit(monkeypatch):
    host, _ring, calls = _inert_host(monkeypatch, token=True)
    scanner._run_gui_worker(host, lambda: calls.append("gui-quit"))
    assert host._authenticated_standdown is True
    assert "poll" not in calls and "beat" not in calls
    assert calls.count("beat-close") == calls.count("ring-close") == 1
    assert calls[-4:] == ["beat-close", "ring-close", "status", "gui-quit"]


@pytest.mark.parametrize("token", [False, None, 0, 1, "true"])
def test_no_authenticated_stop_keeps_diagnostic_ui_available(monkeypatch, token):
    host, _ring, calls = _inert_host(monkeypatch, token=token)
    scanner._run_gui_worker(host, lambda: pytest.fail("unverified result closed GUI"))
    assert host._authenticated_standdown is False
    assert calls.count("poll") == 1
    assert calls.count("beat-close") == calls.count("ring-close") == 1


def test_local_stop_is_not_authenticated_operator_stop(monkeypatch):
    host, _ring, calls = _inert_host(monkeypatch, token=True)
    host.stop()
    scanner._run_gui_worker(host, lambda: pytest.fail("local stop closed diagnostic GUI"))
    assert host._authenticated_standdown is False and "token" not in calls


def test_stop_verification_failure_does_not_close_diagnostic_gui(monkeypatch):
    host, _ring, calls = _inert_host(
        monkeypatch, token_error=OSError("inert verification unavailable"))
    with pytest.raises(OSError, match="verification unavailable"):
        scanner._run_gui_worker(host, lambda: pytest.fail("failed verifier closed GUI"))
    assert host._authenticated_standdown is False
    assert calls.count("beat-close") == calls.count("ring-close") == 1


def test_authenticated_stop_with_unresolved_cleanup_does_not_close_diagnostic_gui(monkeypatch):
    host, ring, calls = _inert_host(monkeypatch, token=True, close_error=True)
    with pytest.raises(OSError, match="ambiguous ring close"):
        scanner._run_gui_worker(host, lambda: pytest.fail("unresolved owner closed GUI"))
    assert host._authenticated_standdown is True
    assert host.ring is ring and host._ring_close_failed is True
    assert calls.count("beat-close") == calls.count("ring-close") == 1


@pytest.mark.parametrize("authenticated", [False, True])
def test_gui_queues_early_verified_stop_until_event_loop_starts(monkeypatch, authenticated):
    # Fake only presentation/thread boundaries; run the real main and worker
    # adapter. A synchronous inert start deliberately completes before exec().
    calls, queued = [], []
    queued_connection = object()

    class Signal:
        def connect(self, slot, connection):
            assert connection is queued_connection
            self.slot = slot

        def emit(self):
            calls.append("emit")
            queued.append(self.slot)

    class Object:
        def __init__(self, parent):
            self.parent = parent

    class Application:
        @staticmethod
        def instance():
            return None

        def __init__(self, _argv):
            calls.append("app")

        def quit(self):
            assert "exec" in calls  # Never quit before the event loop exists.
            calls.append("quit")

        def exec(self):
            calls.append("exec")
            if authenticated:
                assert len(queued) == 1
                queued.pop()()
            else:
                assert queued == []
                calls.append("review-available")
            return 37

    class Window:
        def setWindowTitle(self, _title):
            pass

        def setCentralWidget(self, _widget):
            pass

        def resize(self, *_args):
            pass

        def showMinimized(self):
            calls.append("window")

    class Thread:
        ident = None

        def __init__(self, *, target, args, name, daemon):
            assert name == "TelemetryScanner" and daemon is True
            self.target, self.args = target, args

        def start(self):
            self.ident = 101
            self.target(*self.args)

        def join(self, timeout):
            assert timeout == 2
            calls.append("join")

    host = SimpleNamespace(_authenticated_standdown=authenticated,
                           run=lambda: calls.append("run-finished"),
                           stop=lambda: calls.append("stop"))
    monkeypatch.setattr(scanner, "ScannerHost", lambda **_kwargs: host)
    monkeypatch.setattr(scanner, "threading", SimpleNamespace(Thread=Thread))
    monkeypatch.setenv("ANGERONA_SCANNER_UI", "1")
    monkeypatch.setenv("ANGERONA_SCANNER_INTERVAL", "1.0")
    monkeypatch.setitem(sys.modules, "PySide6", SimpleNamespace(__path__=[]))
    monkeypatch.setitem(sys.modules, "PySide6.QtWidgets", SimpleNamespace(
        QApplication=Application, QMainWindow=Window))
    monkeypatch.setitem(sys.modules, "PySide6.QtCore", SimpleNamespace(
        QObject=Object, Signal=Signal,
        Qt=SimpleNamespace(ConnectionType=SimpleNamespace(QueuedConnection=queued_connection))))
    status_view = SimpleNamespace(_qss=lambda: "", build_status_widget=lambda *_args: object())
    monkeypatch.setitem(sys.modules, "angerona.resilience.status_ui", status_view)
    monkeypatch.setattr(sys.modules["angerona.resilience"], "status_ui", status_view, raising=False)
    monkeypatch.setitem(sys.modules, "angerona.gui.header_controls", SimpleNamespace(
        install_global_window_reveal=lambda *_a, **_k: None))
    monkeypatch.setitem(sys.modules, "angerona.core.config", SimpleNamespace(
        Config=SimpleNamespace(load=lambda: None)))
    assert scanner.main([]) == 37
    assert calls[-2:] == ["stop", "join"]
    if authenticated:
        assert calls.index("run-finished") < calls.index("emit") < calls.index("exec") < calls.index("quit")
    else:
        assert "emit" not in calls and "quit" not in calls and "review-available" in calls
