from __future__ import annotations

import os
import threading
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Signal
from PySide6.QtTest import QSignalSpy
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QMessageBox, QPushButton, QScrollArea,
)

from angerona.gui.main_window import MainWindow


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


class _ForensicsShell(QMainWindow):
    _open_forensics_hub = MainWindow._open_forensics_hub

    def __init__(self) -> None:
        super().__init__()
        self.opened: list[str] = []

    def _qss(self) -> str:
        return ""

    def _record(self, name: str) -> None:
        self.opened.append(name)

    def _open_collision(self) -> None:
        self._record("collision")

    def _open_blast_prompt(self) -> None:
        self._record("blast")

    def _open_top_talkers(self) -> None:
        self._record("talkers")

    def _open_incident_timeline(self) -> None:
        self._record("timeline")

    def _open_sandbox(self) -> None:
        self._record("sandbox")

    def _open_ir_bundle(self) -> None:
        self._record("bundle")


def test_forensics_hub_is_nonmodal_scrollable_and_defers_child_open() -> None:
    app = _app()
    shell = _ForensicsShell()
    hub = shell._open_forensics_hub()
    app.processEvents()

    assert hub.isVisible()
    assert not hub.isModal()
    assert hub.property("_angerona_no_reveal") is True
    assert hub.findChild(QScrollArea) is not None

    open_buttons = [
        button for button in hub.findChildren(QPushButton)
        if button.text() == "Open"
    ]
    assert len(open_buttons) == 6
    open_buttons[0].click()
    app.processEvents()

    assert not hub.isVisible()
    assert shell.opened == ["collision"]
    hub.close()
    shell.close()


class _BundleShell(QMainWindow):
    _ir_bundle_done = Signal(object, object)
    _open_ir_bundle = MainWindow._open_ir_bundle
    _on_ir_bundle_done = MainWindow._on_ir_bundle_done

    def __init__(self) -> None:
        super().__init__()
        self.bus = None
        self._ir_bundle_in_flight = False
        self._ir_bundle_done.connect(self._on_ir_bundle_done)


def test_ir_bundle_collection_does_not_block_ui_thread(monkeypatch, tmp_path) -> None:
    _app()
    entered = threading.Event()
    release = threading.Event()

    def _slow_collect(**_kwargs):
        entered.set()
        release.wait(2.0)
        return tmp_path / "triage.zip"

    monkeypatch.setattr("angerona.core.ir_bundle.collect_triage_bundle", _slow_collect)
    monkeypatch.setattr(
        QMessageBox,
        "warning",
        lambda *_args, **_kwargs: QMessageBox.StandardButton.Yes,
    )
    shell = _BundleShell()
    completed = QSignalSpy(shell._ir_bundle_done)

    # The method must return while collection remains deliberately blocked.
    shell._open_ir_bundle()
    assert entered.wait(1.0)
    assert shell._ir_bundle_in_flight is True
    assert getattr(shell, "_ir_bundle_progress").isVisible()

    release.set()
    deadline = time.monotonic() + 2.0
    while completed.count() == 0 and time.monotonic() < deadline:
        QApplication.processEvents()
        time.sleep(0.01)
    QApplication.processEvents()
    assert completed.count() == 1
    assert shell._ir_bundle_in_flight is False
    getattr(shell, "_ir_bundle_result").close()
    shell.close()
