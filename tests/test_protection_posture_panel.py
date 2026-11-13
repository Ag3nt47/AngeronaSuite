"""Watchdog monitor Protection panel: plain-language posture rows."""
from __future__ import annotations

import os

import pytest

from angerona.resilience import control_authority as ca
from angerona.resilience import posture


@pytest.fixture(autouse=True)
def _fixed_environment(monkeypatch):
    monkeypatch.setitem(posture._CACHE, "service", {"state": "not_installed"})
    monkeypatch.setitem(posture._CACHE, "until", float("inf"))
    monkeypatch.setattr(ca, "status", lambda root=None: {"state": "unprovisioned"})
    monkeypatch.setattr(ca, "deadman_policy", lambda root=None: None)


def _rows(status=None):
    return {row["key"]: row for row in posture.protection_posture(status)}


def test_default_host_reports_unprotected_stop_and_everything_else_off_or_normal():
    rows = _rows({"restarts": {"core": 2}})
    assert rows["stop"]["tone"] == "warn" and rows["stop"]["text"].startswith("Not set up")
    assert rows["pressure"] == {"key": "pressure", "label": "Restart pressure", "tone": "ok",
                                "text": "Normal. Core restarts this session: 2."}
    assert rows["deadman"]["tone"] == "off" and rows["service"]["tone"] == "off"
    assert list(rows) == ["stop", "pressure", "deadman", "service", "watchdog3"]


def test_protected_stop_attack_pressure_and_engaged_hold_are_reported(monkeypatch):
    monkeypatch.setattr(ca, "status", lambda root=None: {"state": "protected", "stop_active": False})
    monkeypatch.setattr(ca, "deadman_policy", lambda root=None: {"enabled": True, "threshold_s": 300.0})
    monkeypatch.setitem(posture._CACHE, "service", {"state": "configured"})
    rows = _rows({"restart_pressure": {"core": "attack"}, "deadman": "armed"})
    assert rows["stop"]["tone"] == "ok" and "administrator approval" in rows["stop"]["text"]
    assert rows["pressure"]["tone"] == "alert"
    assert rows["deadman"]["tone"] == "ok" and "5 minutes" in rows["deadman"]["text"]
    assert rows["service"]["tone"] == "ok"
    assert _rows({"deadman": "engaged"})["deadman"]["tone"] == "alert"
    assert _rows({"deadman": "not_elevated"})["deadman"]["tone"] == "warn"


def test_compromised_authority_and_missing_watchdog_status_are_not_shown_as_healthy(monkeypatch):
    monkeypatch.setattr(ca, "status", lambda root=None: {"state": "compromised"})
    rows = _rows(None)
    assert rows["stop"]["tone"] == "alert" and rows["pressure"]["tone"] == "off"
    monkeypatch.setattr(ca, "status", lambda root=None: (_ for _ in ()).throw(OSError("x")))
    assert _rows({})["stop"]["tone"] == "warn"  # Failure reads as "not set up", never "on".


def test_details_row_is_readable_text_not_python_reprs():
    from angerona.resilience.status_ui import _format_details
    text = _format_details({"supervised": ["core", "scanner"], "restarts": {"core": 1, "scanner": 0},
                            "safe_mode": [], "dropped": 3, "unrelated": "x"})
    assert text == "Dropped: 3 · Watching: core, scanner · Paused (safe mode): none · Restarts: core 1"
    assert _format_details({}) == "—"


@pytest.mark.skipif(os.name != "nt", reason="Windows monitor window")
def test_watchdog_monitor_renders_the_panel_and_offers_setup_only_when_unprotected(monkeypatch):
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication, QGroupBox
    from angerona.resilience import status_ui

    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(status_ui, "_read_status", lambda _c: {"state": "running", "restarts": {"core": 0}})
    monkeypatch.setattr(status_ui, "_hb_state", lambda _c: "alive")
    widget = status_ui.build_status_widget("watchdog")
    try:
        assert "Protection" in [box.title() for box in widget.findChildren(QGroupBox)]
        assert widget._posture_labels["stop"].text().startswith("Not set up")
        assert not widget._stop_setup.isHidden()
        monkeypatch.setattr(ca, "status", lambda root=None: {"state": "protected", "stop_active": False})
        widget.refresh()
        assert widget._posture_labels["stop"].text().startswith("On.")
        assert widget._stop_setup.isHidden()
    finally:
        widget._timer.stop()
        widget.deleteLater()
        app.processEvents()

    scanner = status_ui.build_status_widget("scanner")
    try:
        assert scanner._posture_labels == {}
        assert "Protection" not in [box.title() for box in scanner.findChildren(QGroupBox)]
    finally:
        scanner._timer.stop()
        scanner.deleteLater()
        app.processEvents()
