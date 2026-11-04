"""Heatmap geometry uses inert sources and real Qt layout, not host actions."""
from __future__ import annotations

import os
import socket
import subprocess
import threading

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, Qt
from PySide6.QtWidgets import QApplication, QPushButton
from shiboken6 import isValid

from angerona.gui import attack_heatmap


@pytest.fixture(autouse=True)
def inert_heatmap_sources(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Heatmap layout cannot dispatch host work")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    monkeypatch.setattr(threading.Thread, "start", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(attack_heatmap, "get_tracker", lambda: None)
    monkeypatch.setattr(attack_heatmap.AttackHeatmapWindow, "_refresh_coverage", lambda _self: None)


def settle():
    for _ in range(4):
        QApplication.processEvents()


def test_long_heatmap_headings_keep_work_area_and_controls_reachable():
    assert QApplication.instance() is not None
    dialog = attack_heatmap.AttackHeatmapWindow()
    try:
        detail = ("A long technique and coverage explanation remains available "
                  "without moving the filter or action controls outside the window. ") * 3
        for label in (dialog._stats_lbl, dialog._cov_hdr, dialog._detail_hdr):
            label.setText(detail)
        dialog.resize(1200, 900)
        dialog.show()
        settle()
        available = dialog.screen().availableGeometry()
        assert dialog.minimumWidth() <= available.width()
        assert dialog.minimumHeight() <= available.height()
        assert dialog.frameGeometry().width() <= available.width()
        assert dialog.frameGeometry().height() <= available.height()
        assert dialog._view.horizontalScrollBarPolicy() == Qt.ScrollBarAlwaysOn
        for index in range(dialog._tabs.count()):
            dialog._tabs.setCurrentIndex(index)
            settle()
            assert dialog._tabs.currentIndex() == index
            assert dialog.frameGeometry().width() <= available.width()
            assert dialog.frameGeometry().height() <= available.height()
        for name in ("HeatmapExplainPosture", "HeatmapExportNavigator", "HeatmapResetCounts"):
            button = dialog.findChild(QPushButton, name)
            assert button is not None and button.isVisible()
            assert button.mapTo(dialog, button.rect().topLeft()).x() >= dialog.contentsRect().left()
            assert button.mapTo(dialog, button.rect().bottomRight()).x() <= dialog.contentsRect().right()
            assert button.mapTo(dialog, button.rect().bottomRight()).y() <= dialog.contentsRect().bottom()
        for widget in (dialog._search, dialog._active_only, dialog._actor_combo):
            assert widget.isVisible()
            assert widget.mapTo(dialog, widget.rect().bottomRight()).x() <= dialog.contentsRect().right()
    finally:
        dialog.close()
        dialog.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        assert not isValid(dialog)
