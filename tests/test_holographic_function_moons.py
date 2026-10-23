"""Function moons reuse cached status and existing routes without host probes."""
from __future__ import annotations

import builtins
from pathlib import Path
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QPoint, QRect, QRectF, QTimer, Qt
from PySide6.QtGui import QPainter
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QMainWindow

from angerona.app import AngeronaApp
from angerona.gui.holographic_orb import HolographicOrb, HolographicOrbController
from angerona.gui import holographic_orb as orb_module


def _config():
    return SimpleNamespace(ui_motion_enabled=False, holographic_orb_enabled=True,
                           holographic_orb_x=-1, holographic_orb_y=-1)


def _no_io(*_args, **_kwargs):
    pytest.fail("A cached status copy or orb paint attempted filesystem I/O")


def test_collapsed_globe_has_four_labeled_clickable_moons_and_no_paint_io(monkeypatch):
    app = QApplication.instance()
    orb = HolographicOrb(_config())
    chosen = []
    orb.serviceTriggered.connect(chosen.append)
    try:
        orb.show_token()
        app.processEvents()
        assert not orb._tick.isActive()
        assert len({service.color.name() for service in orb.services}) == 4
        assert set(orb._node_rects) == {"core", "watchdog", "scanner", "blackbox"}
        assert all(status.state == "unknown" for status in orb._service_statuses.values())
        assert "Moon colors identify functions" in orb.accessibleDescription()
        assert all(f"{service.label}: UNKNOWN" in orb.accessibleDescription()
                   for service in orb.services)
        timer_count = len(orb.findChildren(QTimer))
        with monkeypatch.context() as scoped:
            scoped.setattr(builtins, "open", _no_io)
            scoped.setattr(Path, "read_text", _no_io)
            scoped.setattr(Path, "read_bytes", _no_io)
            scoped.setattr(Path, "stat", _no_io)
            assert not orb.grab().isNull()
            for service in orb.services:
                center = orb._node_rects[service.key].center().toPoint()
                assert orb.rect().contains(orb._node_rects[service.key].toRect())
                QTest.mouseClick(orb, Qt.LeftButton, pos=center)
                app.processEvents()
        assert chosen == [service.key for service in orb.services]
        assert len(orb.findChildren(QTimer)) == timer_count
    finally:
        orb.hide_token()
        orb.deleteLater()


def test_status_badges_keep_identity_colors_and_report_unknown_age_safely():
    orb = HolographicOrb(_config())
    try:
        colors = tuple(service.color.name() for service in orb.services)
        supplied = {
            "core": {"state": "running", "reason": "Manager is active."},
            "watchdog": {"state": "degraded", "reason": "<b>not markup</b>"},
            "scanner": {"state": "stopped", "age_seconds": 3.2},
            "blackbox": {"state": [], "age_seconds": 10 ** 1000},
        }
        orb.set_service_statuses(supplied)
        supplied["scanner"]["state"] = "alive"
        assert orb._service_statuses["scanner"].state == "stopped"
        assert orb._service_statuses["scanner"].age_seconds == 3.2
        assert orb._service_statuses["blackbox"].state == "unknown"
        assert orb._service_statuses["blackbox"].age_seconds is None
        watchdog = next(service for service in orb.services if service.key == "watchdog")
        tooltip = orb._service_tooltip(watchdog)
        assert "DEGRADED" in tooltip and "&lt;b&gt;not markup&lt;/b&gt;" in tooltip
        assert "Observation age: unknown" in tooltip
        assert tuple(service.color.name() for service in orb.services) == colors
    finally:
        orb.deleteLater()


def test_app_adapter_reads_only_existing_cached_fields_and_preserves_unknown(monkeypatch):
    owner = AngeronaApp.__new__(AngeronaApp)
    owner.manager = SimpleNamespace(_shutdown=False, _runtime_active=True, ugcap_paused=False)
    owner.config = SimpleNamespace(blackbox_enabled=True)
    components = {
        "watchdog": SimpleNamespace(last_state="alive", safe_mode=False, state_fault=False),
        "scanner": SimpleNamespace(last_state="suspended", safe_mode=False, state_fault=False),
        "blackbox": SimpleNamespace(last_state="alive", safe_mode=False, state_fault=True),
    }
    owner._resilience = SimpleNamespace(status="running", _sup=SimpleNamespace(components=components))
    with monkeypatch.context() as scoped:
        scoped.setattr(builtins, "open", _no_io)
        scoped.setattr(Path, "read_text", _no_io)
        scoped.setattr(Path, "stat", _no_io)
        status = owner._orb_cached_service_statuses()
    assert {key: row["state"] for key, row in status.items()} == {
        "core": "running", "watchdog": "alive", "scanner": "suspended", "blackbox": "degraded",
    }
    assert all(row["age_seconds"] is None for row in status.values())
    assert "current process liveness" in status["watchdog"]["scope"]
    components["scanner"].last_state = "alive"
    assert status["scanner"]["state"] == "suspended"
    components["scanner"].last_state = "unauthenticated_invalid"
    assert owner._orb_cached_service_statuses()["scanner"]["state"] == "degraded"
    owner.config.blackbox_enabled = False
    assert owner._orb_cached_service_statuses()["blackbox"]["state"] == "unknown"
    owner._resilience = None
    assert all(row["state"] == "unknown" for key, row in owner._orb_cached_service_statuses().items()
               if key != "core")
    owner.manager.ugcap_paused = True
    assert owner._orb_cached_service_statuses()["core"]["state"] == "held"
    owner.manager._shutdown = True
    assert owner._orb_cached_service_statuses()["core"]["state"] == "stopped"


def test_status_refresh_shares_existing_timer_and_ugcap_holds_existing_routes(monkeypatch):
    app = QApplication.instance()
    main = QMainWindow()
    main.manager = SimpleNamespace(ugcap_paused=False)
    main.timer = QTimer(main)
    controller = HolographicOrbController(main, _config())
    cached = QMainWindow()
    controller._component_windows["scanner"] = cached
    calls = []
    try:
        controller.set_service_status_source(lambda: calls.append("snapshot") or {
            "scanner": {"state": "dead", "reason": "Cached supervisor observation."},
        })
        assert calls == ["snapshot"]
        main.timer.timeout.emit()  # hidden token does no optional presentation work
        assert calls == ["snapshot"]
        controller.orb.show_token()
        app.processEvents()
        main.timer.timeout.emit()
        assert calls == ["snapshot"] * 3
        assert controller.orb._service_statuses["scanner"].state == "dead"
        assert not controller.orb._tick.isActive()
        monkeypatch.setattr(controller, "_component_window", lambda key: calls.append(key) or cached)
        monkeypatch.setattr(controller, "restore_window", lambda window: calls.append("restore"))
        monkeypatch.setattr(controller, "restore_main", lambda: calls.append("core"))
        main.manager.ugcap_paused = True
        controller.sync_security_gate()
        assert not cached.isEnabled()
        controller._service_triggered("scanner")
        assert "scanner" not in calls
        controller._service_triggered("core")
        assert calls[-1] == "core"
        main.manager.ugcap_paused = False
        controller.sync_security_gate()
        assert cached.isEnabled()
        controller._service_triggered("scanner")
        assert calls[-2:] == ["scanner", "restore"]
        controller.shutdown()
        before = list(calls)
        main.timer.timeout.emit()
        assert calls == before
    finally:
        if not controller._shutting_down:
            controller.shutdown()
        cached.close()
        cached.deleteLater()
        main.deleteLater()


@pytest.mark.parametrize("available", [
    QRect(0, 0, 320, 240),
    QRect(0, 0, 640, 480),
    QRect(-1280, -720, 1280, 720),
])
def test_expanded_moon_names_fit_the_actual_window_at_logical_screen_corners(monkeypatch, available):
    """Record production drawText rectangles, including the outer Scanner chip."""
    class Screen:
        def availableGeometry(self):
            return QRect(available)

    painted = {}
    labels = {"CORE", "WATCHDOG", "SCANNER", "BLACK BOX"}

    class RecordingPainter(QPainter):
        def drawText(self, *args):
            if len(args) == 3 and isinstance(args[2], str) and args[2] in labels:
                painted[args[2]] = QRectF(args[0])
            return super().drawText(*args)

    screen = Screen()
    monkeypatch.setattr(orb_module, "QPainter", RecordingPainter)
    orb = HolographicOrb(_config())
    monkeypatch.setattr(orb, "_screen", lambda: screen)
    monkeypatch.setattr(orb, "_screen_for_point", lambda _point: screen)
    try:
        for point in (available.topLeft(), available.topRight(),
                      available.bottomLeft(), available.bottomRight()):
            orb.set_menu_expanded(False, animated=False)
            orb.set_anchor(point)
            saved_anchor = QPoint(orb.anchor)
            orb.show_token()
            orb.set_menu_expanded(True, animated=False)
            QApplication.processEvents()
            painted.clear()
            assert not orb.grab().isNull()
            assert set(painted) == labels
            assert available.contains(orb.geometry())
            for name, rect in painted.items():
                assert QRectF(orb.rect()).contains(rect), (available, point, name, rect)
                global_rect = rect.translated(orb.pos())
                assert QRectF(available).contains(global_rect), (available, point, name, global_rect)
            orb.set_menu_expanded(False, animated=False)
            assert orb.anchor == saved_anchor
            assert available.contains(orb.geometry())
    finally:
        orb.hide_token()
        orb.deleteLater()
