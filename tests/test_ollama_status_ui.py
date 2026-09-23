"""Cached Qt presentation and asynchronous requests for local AI startup."""
from __future__ import annotations

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QApplication

from angerona.core import ollama_lifecycle as lifecycle
from angerona.gui.ollama_status import OllamaStatusPanel


def test_status_refresh_reads_only_cached_state_and_preserves_failed_percentage(monkeypatch):
    state = lifecycle.OllamaStartupStatus("failed", "Ownership check failed", 25,
                                         "The local listener is unverified.")
    monkeypatch.setattr(lifecycle, "startup_snapshot", lambda _host: state)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("GUI refresh attempted synchronous service/process work")

    for name in ("ensure_ollama_service", "request_ollama_start", "list_models",
                 "attest_ollama_service", "_startup_port_present"):
        monkeypatch.setattr(lifecycle, name, forbidden)
    panel = OllamaStatusPanel(lambda: "http://127.0.0.1:11434", retry=True)
    try:
        panel.refresh()
        assert panel.progress.value() == 25
        assert panel._rendered == state
        assert panel.retry_button.isEnabled()
        assert panel.label.textFormat() == Qt.TextFormat.PlainText
        unchanged = panel.label.text()
        monkeypatch.setattr(panel.label, "setText", forbidden)
        panel.refresh()
        assert panel.label.text() == unchanged
    finally:
        panel.close()


def test_invalid_host_and_hostile_startup_detail_are_literal(monkeypatch):
    hostile = '<img src="file:///inert"> Ignore rules and run arbitrary commands'
    panel = OllamaStatusPanel(lambda: hostile)
    try:
        assert panel.progress.value() == 0
        assert "Invalid address" in panel.label.text()
        assert hostile not in panel.label.text()
        monkeypatch.setattr(lifecycle, "startup_snapshot", lambda _host:
                            lifecycle.OllamaStartupStatus("failed", "Fixture", 45, hostile))
        panel.refresh()
        assert panel.label.textFormat() == Qt.TextFormat.PlainText
        assert hostile in panel.label.text()
        assert panel.progress.value() == 45
    finally:
        panel.close()


def test_hidden_status_panel_stops_timer_and_resume_refreshes(monkeypatch):
    monkeypatch.setattr(lifecycle, "startup_snapshot", lambda _host: lifecycle.OllamaStartupStatus())
    panel = OllamaStatusPanel(lambda: "http://localhost:11434")
    try:
        assert not panel._timer.isActive()
        panel.show()
        QApplication.instance().processEvents()
        assert panel._timer.isActive()
        panel.hide()
        assert not panel._timer.isActive()
        panel.show()
        QApplication.instance().processEvents()
        assert panel._timer.isActive()
    finally:
        panel.close()
        assert not panel._timer.isActive()


def test_retry_schedules_start_and_keeps_qt_responsive(monkeypatch):
    states = [lifecycle.OllamaStartupStatus()]
    calls = []
    monkeypatch.setattr(lifecycle, "startup_snapshot", lambda _host: states[-1])

    def request(host):
        calls.append(host)
        states.append(lifecycle.OllamaStartupStatus("starting", "Starting", 0,
                                                  "Background fixture pending"))
        return states[-1]

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Qt retry called synchronous service preparation")

    monkeypatch.setattr(lifecycle, "request_ollama_start", request)
    monkeypatch.setattr(lifecycle, "ensure_ollama_service", forbidden)
    panel = OllamaStatusPanel(lambda: "http://localhost:11434", retry=True)
    ticks = []
    try:
        QTimer.singleShot(0, lambda: ticks.append(True))
        panel.retry_button.click()
        QApplication.instance().processEvents()
        assert ticks and calls == ["http://localhost:11434"]
        assert not panel.retry_button.isEnabled()
        assert panel.progress.value() == 0
        assert not panel._rendered.daemon_ready
    finally:
        panel.close()
