"""Persistent metrics must remain readable, truthful, and sampling-free."""
from __future__ import annotations

from unittest.mock import Mock

from PySide6.QtCore import QTimer, Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

from angerona.gui.dashboard_footer import DashboardFooter


def test_footer_preserves_exact_metrics_and_keyboard_details(monkeypatch):
    footer = DashboardFooter()
    details = Mock()
    footer.details_requested.connect(details)
    try:
        footer.update_sample(dict(cpu=32.125, ram=68.75, down=12_345, up=678_901))
        footer.update_posture(dict(score=63, label="Critical", color="#ef4444"))
        assert "CPU: 32.125%" in footer.accessibleName()
        assert "RAM: 68.75%" in footer.toolTip()
        assert "Network receive: 12345 bytes/s" in footer.toolTip()
        assert "Network send: 678901 bytes/s" in footer.toolTip()
        assert "Posture score: 63/100. State: Critical." in footer.accessibleName()
        setters = []
        for name in ("setAccessibleName", "setAccessibleDescription", "setToolTip", "update"):
            setter = Mock(wraps=getattr(footer, name))
            monkeypatch.setattr(footer, name, setter)
            setters.append(setter)
        footer.update_sample(dict(cpu=32.125, ram=68.75, down=12_345, up=678_901))
        footer.update_posture(dict(score=63, label="Critical", color="#ef4444"))
        assert all(setter.call_count == 0 for setter in setters)
        footer.show()
        QTest.keyClick(footer, Qt.Key_Return)
        QTest.keyClick(footer, Qt.Key_Space)
        QTest.mouseClick(footer, Qt.LeftButton)
        assert details.call_count == 3
        assert not footer.findChildren(QTimer)
    finally:
        footer.close()
        footer.deleteLater()


def test_footer_invalid_or_failed_samples_never_claim_zero_usage():
    footer = DashboardFooter()
    try:
        footer.update_sample(dict(cpu=float("nan"), ram=101, down=-1, up=float("inf")))
        assert "CPU: unavailable" in footer.accessibleName()
        assert "RAM: unavailable" in footer.accessibleName()
        assert "Network receive: unavailable" in footer.accessibleName()
        footer.update_sample(dict(cpu=25, ram=60, down=0, up=0))
        assert "CPU: 25%" in footer.accessibleName()
        footer.update_sample(dict(error="inert collection failure"))
        assert "Host metrics unavailable" in footer.accessibleName()
        assert "CPU: 25%" not in footer.accessibleName()
        footer.update_posture(dict(score=float("inf"), label="Critical"))
        assert "Posture unavailable" in footer.toolTip()
        footer.update_sample(dict(cpu=0, ram=0, down=0, up=0))
        assert "CPU: 0%" in footer.accessibleName()  # actual zero is meaningful
    finally:
        footer.close()
        footer.deleteLater()


def test_footer_reflows_at_480_and_restores_single_row_for_larger_windows():
    footer = DashboardFooter()
    try:
        footer.update_sample(dict(cpu=100, ram=100, down=10**10, up=10**10))
        footer.update_posture(dict(score=63, label="Critical", color="#ef4444"))
        footer.resize(480, 40)
        footer.show()
        QApplication.instance().processEvents()
        assert footer.width() == 480
        assert footer.height() <= footer.fontMetrics().height() * 2 + 12
        font = footer.font()
        font.setPixelSize(22)
        footer.setFont(font)
        QApplication.instance().processEvents()
        assert footer.height() == footer.fontMetrics().height() * 2 + 12
        assert "Network receive: 1e+10 bytes/s" in footer.toolTip()
        footer.resize(1600, footer.height())
        QApplication.instance().processEvents()
        assert footer.height() == footer.fontMetrics().height() + 12
        assert not footer.grab().isNull()
    finally:
        footer.close()
        footer.deleteLater()
