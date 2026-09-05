from __future__ import annotations

import json
import os
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest


_TOKEN = "a" * 64


def test_startup_option_preserves_uac_arguments_and_other_application_options() -> None:
    from angerona.core.startup_protocol import parse_startup_arguments

    arguments = ["Angerona.exe", "--chill", f"--startup-ready=49152:{_TOKEN}", "--setup"]
    original = list(arguments)
    clean, endpoint = parse_startup_arguments(arguments)

    assert arguments == original
    assert clean == ["Angerona.exe", "--chill", "--setup"]
    assert endpoint == f"49152:{_TOKEN}"
    assert parse_startup_arguments(["Angerona.exe", "--headless"]) == (
        ["Angerona.exe", "--headless"], None,
    )


@pytest.mark.parametrize("arguments", [
    ["--startup-ready"],
    ["--startup-ready="],
    [f"--startup-ready=1023:{_TOKEN}"],
    [f"--startup-ready=65536:{_TOKEN}"],
    [f"--startup-ready=01024:{_TOKEN}"],
    [f"--startup-ready=127.0.0.1:49152:{_TOKEN}"],
    [f"--startup-ready=localhost:49152:{_TOKEN}"],
    [f"--startup-ready=49152:{'A' * 64}"],
    [f"--startup-ready=49152:{'a' * 63}"],
    [f"--startup-ready=49152:{'a' * 65}"],
    [f"--startup-ready=49152:{_TOKEN}\n"],
    [f"--startup-ready=49152:{_TOKEN}", f"--startup-ready=49153:{_TOKEN}"],
])
def test_startup_option_rejects_malformed_or_duplicate_endpoint(arguments) -> None:
    from angerona.core.startup_protocol import parse_startup_arguments

    with pytest.raises(ValueError):
        parse_startup_arguments(["Angerona.exe", *arguments])


def test_readiness_notice_uses_loopback_and_this_process_identity() -> None:
    import socket

    from angerona.core.startup_protocol import notify_dashboard_ready

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(1.0)
        endpoint = f"{listener.getsockname()[1]}:{_TOKEN}"
        assert notify_dashboard_ready(endpoint) is True
        connection, address = listener.accept()
        with connection:
            connection.settimeout(1.0)
            data = bytearray()
            while chunk := connection.recv(1024):
                data.extend(chunk)

    assert address[0] == "127.0.0.1"
    assert data.endswith(b"\n")
    assert json.loads(data) == {"token": _TOKEN, "pid": os.getpid()}


def test_readiness_notice_has_bounded_socket_wait_and_no_response_read(monkeypatch) -> None:
    from angerona.core import startup_protocol

    calls = []

    class TimedOutSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def settimeout(self, timeout):
            calls.append(("timeout", timeout))

        def connect(self, address):
            calls.append(("connect", address))
            raise TimeoutError("helper is no longer reachable")

    monkeypatch.setattr(startup_protocol.socket, "socket", lambda *_args: TimedOutSocket())
    assert startup_protocol.notify_dashboard_ready(f"49152:{_TOKEN}") is False
    assert calls == [("timeout", 0.5), ("connect", ("127.0.0.1", 49152))]


@pytest.mark.parametrize("reveal_enabled", [False, True])
def test_dashboard_ready_waits_for_shown_visible_window_and_later_gui_timer(
    monkeypatch, reveal_enabled,
) -> None:
    from PySide6.QtCore import QTimer

    import angerona.app as app_module

    calls = []
    timers = []
    reveal_callbacks = []
    workers = []
    window = SimpleNamespace(
        isVisible=lambda: "shown" in calls,
        show=lambda: calls.append("shown"),
    )
    if reveal_enabled:
        window._panel_reveal = SimpleNamespace(
            reveal=lambda _window, callback, _color: reveal_callbacks.append(callback)
        )
    app = app_module.AngeronaApp.__new__(app_module.AngeronaApp)
    app.window = window
    app.config = SimpleNamespace(autostart_enabled=False)
    app.qt = SimpleNamespace(aboutToQuit=SimpleNamespace(connect=lambda _callback: None))
    app._deferred_start = lambda: None
    monkeypatch.setenv("ANGERONA_RESILIENCE", "1")
    monkeypatch.setattr(QTimer, "singleShot", lambda delay, callback: timers.append((delay, callback)))
    monkeypatch.setattr(
        app_module.threading, "Thread",
        lambda **kwargs: SimpleNamespace(start=lambda: workers.append(kwargs)),
    )
    monkeypatch.setattr(app, "_publish_dashboard_ready", lambda: calls.append("published"))

    app.start()
    assert workers == []
    if reveal_enabled:
        assert "shown" not in calls
        assert not any(delay == 250 for delay, _ in timers)
        reveal_callbacks[0]()
    assert calls == ["shown"]
    ready = [callback for delay, callback in timers if delay == 250]
    assert len(ready) == 1
    assert workers == []

    ready[0]()
    ready[0]()  # duplicate timer dispatch cannot create extra notifications
    assert calls == ["shown"]
    assert len(workers) == 1
    assert workers[0]["daemon"] is True
    workers[0]["target"]()
    assert calls == ["shown", "published"]


@pytest.mark.parametrize("cancelled", [False, True])
def test_dashboard_ready_does_not_report_hidden_or_stopping_dashboard(monkeypatch, cancelled) -> None:
    import angerona.app as app_module

    app = app_module.AngeronaApp.__new__(app_module.AngeronaApp)
    app.window = SimpleNamespace(isVisible=lambda: cancelled)
    app._startup_cancelled = lambda: cancelled

    def must_not_start_thread(**_kwargs):
        raise AssertionError("unready dashboard must not notify the helper")

    monkeypatch.setattr(app_module.threading, "Thread", must_not_start_thread)
    app._dashboard_ready_after_paint()


def test_dashboard_ready_sends_helper_notice_before_legacy_file_io(monkeypatch) -> None:
    import angerona.app as app_module
    from angerona.core import startup_protocol

    calls = []
    app = app_module.AngeronaApp.__new__(app_module.AngeronaApp)
    app._startup_endpoint = f"49152:{_TOKEN}"
    app.config = object()
    monkeypatch.setattr(startup_protocol, "notify_dashboard_ready", lambda value: calls.append(value))
    monkeypatch.setattr(app_module, "_mark_dashboard_ready", lambda value: calls.append(value))
    app._publish_dashboard_ready()

    assert calls == [app._startup_endpoint, app.config]


def test_dashboard_ready_marker_is_canonical_atomic_and_pid_bound(
    tmp_path: Path, monkeypatch,
) -> None:
    from angerona.app import _mark_dashboard_ready

    marker = tmp_path / "logs" / "dashboard-ready.signal"
    monkeypatch.setenv("ANGERONA_STARTUP_READY", str(marker))

    assert _mark_dashboard_ready(SimpleNamespace(data_dir=tmp_path)) is True
    payload = json.loads(marker.read_text(encoding="utf-8"))
    assert payload["pid"] == os.getpid()
    assert isinstance(payload["ready_at"], float)
    assert not list(marker.parent.glob(".dashboard-ready.*.tmp"))


def test_dashboard_ready_marker_rejects_any_other_write_location(
    tmp_path: Path, monkeypatch,
) -> None:
    from angerona.app import _mark_dashboard_ready

    outside = tmp_path / "outside" / "dashboard-ready.signal"
    monkeypatch.setenv("ANGERONA_STARTUP_READY", str(outside))

    assert _mark_dashboard_ready(SimpleNamespace(data_dir=tmp_path / "runtime")) is False
    assert not outside.exists()


def test_fast_pyside_detection_uses_module_state_instead_of_source_reads(
    monkeypatch,
) -> None:
    from PySide6.QtCore import QObject
    import shibokensupport.feature as feature

    from angerona.__main__ import _install_fast_pyside_feature_detection

    monkeypatch.delattr(feature, "_angerona_fast_detection", raising=False)

    def source_read_must_not_run(_module):
        raise AssertionError("unexpected source inspection")

    monkeypatch.setattr(feature, "_mod_uses_pyside", source_read_must_not_run)
    assert _install_fast_pyside_feature_detection() is True

    angerona_module = ModuleType("angerona.startup_probe")
    assert feature._mod_uses_pyside(angerona_module) is True

    qt_module = ModuleType("third_party.qt_probe")
    qt_module.QObject = QObject
    assert feature._mod_uses_pyside(qt_module) is True

    plain_module = ModuleType("third_party.plain_probe")
    assert feature._mod_uses_pyside(plain_module) is False
