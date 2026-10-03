"""Orbital mode presents existing evidence without starting collectors."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

from PySide6.QtCore import QTimer, Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

from angerona.gui.orbital_dashboard import OrbitalDashboard


def _view(count=73):
    modules = {}
    for index in range(count):
        status = "error" if index == 1 else "running"
        health = 0 if index == 1 else 100
        state = "failed" if index == 1 else "ok"
        modules[f"Module {index:03}"] = SimpleNamespace(
            CODE=f"M{index}", health_note="fixture evidence",
            health_summary=Mock(return_value=(status, health, state)),
        )
    manager = SimpleNamespace(modules=modules, module_usage=Mock(side_effect=AssertionError("policy IO")))
    bus = SimpleNamespace(recent=Mock(side_effect=AssertionError("unexpected event scan")))
    return OrbitalDashboard(bus, manager, SimpleNamespace(ui_motion_enabled=False))


def test_all_live_modules_remain_reachable_without_policy_or_event_scans(monkeypatch):
    view = _view()
    try:
        view.resize(1100, 650)
        view.show()
        QApplication.instance().processEvents()
        assert len(view._nodes) == 73
        assert len({(point.x(), point.y()) for point in view._nodes.values()}) == 73
        assert "73 module satellites" in view.accessibleDescription()
        update = Mock(wraps=view.update)
        monkeypatch.setattr(view, "update", update)
        assert not view.refresh()
        assert update.call_count == 0
        module = view.manager.modules["Module 001"]
        module.health_summary.return_value = ("running", 74, "degraded")
        assert view.refresh()
        updated = next(row for row in view._modules if row.name == "Module 001")
        assert updated.health == 74 and updated.state == "degraded"
        assert view.manager.module_usage.call_count == 0
        assert view.bus.recent.call_count == 0
        assert not view.findChildren(QTimer)
    finally:
        view.close()
        view.deleteLater()


def test_orbital_keyboard_and_mouse_open_exact_existing_targets():
    view = _view()
    modules, alerts, posture = [], Mock(), Mock()
    view.module_requested.connect(modules.append)
    view.alerts_requested.connect(alerts)
    view.posture_requested.connect(posture)
    try:
        view.resize(1100, 650)
        view.show()
        QApplication.instance().processEvents()
        QTest.keyClick(view, Qt.Key_End)
        QTest.keyClick(view, Qt.Key_Return)
        assert modules == ["Module 072"]
        assert "Module 072" in view.accessibleDescription()
        QTest.keyClick(view, Qt.Key_Right)
        QTest.keyClick(view, Qt.Key_Space)
        assert modules[-1] == "Module 000"
        QTest.mouseClick(view, Qt.LeftButton, pos=view._nodes["Module 015"].toPoint())
        assert modules[-1] == "Module 015"
        QTest.keyClick(view, Qt.Key_A)
        QTest.mouseClick(view, Qt.LeftButton, pos=view._core.center().toPoint())
        assert alerts.call_count == posture.call_count == 1
        del view.manager.modules["Module 015"]
        view.refresh()
        QTest.keyClick(view, Qt.Key_Return)
        assert modules[-1] == "Module 000"
    finally:
        view.close()
        view.deleteLater()


def test_orbital_history_is_bounded_and_errors_do_not_fabricate_samples():
    view = _view(0)
    try:
        view.update_posture(dict(score=63, label="Critical", color="#ef4444"))
        assert "Posture 63/100: Critical" in view.accessibleDescription()
        for index in range(100):
            view.update_sample(dict(cpu=42, ram=65, down=index * 10, up=index))
        assert len(view._network_history) == 60
        assert view._network_history[-1] == (990, 99)
        view.update_sample(dict(error="collector unavailable"))
        assert len(view._network_history) == 60
        assert view._sample == (None, None, None, None)
        assert "CPU: unavailable" in view.toolTip()
        view.update_posture(dict(score=float("nan"), label="Critical", color="invalid"))
        assert "Posture unavailable" in view.accessibleDescription()
        view.set_idle_mode(True)
        assert not view.findChildren(QTimer)
    finally:
        view.close()
        view.deleteLater()


def test_orbital_rendering_works_narrow_wide_hidden_and_empty():
    for count in (0, 73):
        view = _view(count)
        try:
            for width, height in ((480, 560), (1600, 900)):
                view.resize(width, height)
                view.show()
                QApplication.instance().processEvents()
                assert not view.grab().isNull()
                assert all(view.rect().contains(point.toPoint()) for point in view._nodes.values())
                view.hide()
                view.set_idle_mode(True)
                assert not view.findChildren(QTimer)
        finally:
            view.close()
            view.deleteLater()
