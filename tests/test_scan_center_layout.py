from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QCoreApplication, QEvent
from PySide6.QtWidgets import QApplication, QHeaderView

from angerona.gui.scan_center import ScanCenterPanel


_QAPP: QApplication | None = None


def _app() -> QApplication:
    global _QAPP
    _QAPP = QApplication.instance() or QApplication([])
    return _QAPP


def _settle(app: QApplication, panel: ScanCenterPanel, width: int, height: int) -> None:
    panel.resize(width, height)
    panel.show()
    app.processEvents()
    panel._scroll.widget().layout().activate()
    app.processEvents()


def test_scan_center_reflows_narrow_controls_without_clipping() -> None:
    app = _app()
    panel = ScanCenterPanel()
    _settle(app, panel, 400, 520)

    buttons = panel._action_buttons
    assert len({button.geometry().y() for button in buttons}) == len(buttons)
    assert all(button.height() >= 40 for button in buttons)
    assert all(button.width() >= button.sizeHint().width() for button in buttons)
    assert panel.path_edit.geometry().y() < panel._browse_button.geometry().y()
    assert panel._browse_button.geometry().y() < panel.include_defender.geometry().y()
    assert panel.status.geometry().y() < panel.progress.geometry().y()
    assert panel.log.geometry().y() < panel.export_button.geometry().y()
    assert "custom scan" not in panel.include_defender.text().casefold()
    assert panel._scroll.verticalScrollBar().maximum() > 0

    header = panel.findings.horizontalHeader()
    assert panel.findings.isSortingEnabled()
    assert header.sectionResizeMode(1) == QHeaderView.ResizeMode.Interactive
    assert sum(panel.findings.columnWidth(index) for index in range(5)) > (
        panel.findings.viewport().width()
    )
    panel.close()
    panel.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    app.processEvents()


def test_scan_center_uses_two_columns_then_restores_wide_layout() -> None:
    app = _app()
    panel = ScanCenterPanel()
    _settle(app, panel, 760, 700)

    assert panel.path_scan_button.geometry().y() == panel.quick_scan_button.geometry().y()
    assert panel.ports_button.geometry().y() == panel.network_button.geometry().y()
    assert panel.stop_button.geometry().y() > panel.ports_button.geometry().y()
    assert panel.stop_button.width() >= panel.path_scan_button.width()
    assert "custom scan" in panel.include_defender.text().casefold()

    _settle(app, panel, 1220, 650)
    assert panel.path_scan_button.geometry().y() == panel.quick_scan_button.geometry().y()
    assert panel.stop_button.geometry().y() == panel.path_scan_button.geometry().y()
    assert panel.stop_button.height() >= (
        panel.network_button.geometry().bottom() - panel.quick_scan_button.geometry().top()
    )
    assert panel.status.geometry().y() == panel.progress.geometry().y()
    assert panel.log.geometry().top() <= panel.export_button.geometry().top()
    assert panel.export_button.geometry().bottom() <= panel.log.geometry().bottom()
    assert panel.findings.horizontalHeader().sectionResizeMode(1) == (
        QHeaderView.ResizeMode.Stretch
    )
    panel.close()
    panel.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    app.processEvents()
