"""A queued minimize must not act on restored or destroyed Qt windows."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

from PySide6.QtWidgets import QApplication, QMainWindow

from angerona.core.privilege import sanitized_child_environment
from angerona.gui.holographic_orb import HolographicOrbController


def test_deferred_minimize_preserves_immediate_operator_restore(monkeypatch):
    monkeypatch.setenv("ANGERONA_REDUCE_MOTION", "1")
    app = QApplication.instance()
    window = QMainWindow()
    window.resize(640, 420)
    controller = HolographicOrbController(
        window, SimpleNamespace(holographic_orb_enabled=True))
    try:
        window.show()
        app.processEvents()
        window.showMinimized()
        window.showNormal()
        app.processEvents()
        assert window.isVisible()
        assert not window.isMinimized()
        assert not controller.is_collapsed(window)
        assert not controller.orb.isVisible()
    finally:
        controller.shutdown()
        window.deleteLater()


def test_deleted_minimize_target_cannot_corrupt_later_footer_paints(tmp_path):
    # Keep a possible native regression inside a child process. The previous
    # callback reproducibly raised pure-virtual paint errors and then crashed
    # inside GC; neither Qt/GC assertions nor garbage collection are disabled.
    source = r'''
import gc
import os
from types import SimpleNamespace
if os.name == "nt":
    import ctypes
    ctypes.windll.kernel32.SetErrorMode(0x8007)
from PySide6.QtCore import QCoreApplication, QEvent
from PySide6.QtWidgets import QApplication, QMainWindow, QWidget
from angerona.gui.dashboard_footer import DashboardFooter
from angerona.gui.holographic_orb import HolographicOrbController
app = QApplication([])
app.setQuitOnLastWindowClosed(False)
main = QMainWindow()
controller = HolographicOrbController(
    main, SimpleNamespace(holographic_orb_enabled=True))
for index in range(10):
    owner = QWidget()
    footer = DashboardFooter(owner)
    owner.resize(800, 100)
    owner.show()
    app.processEvents()
    owner.showMinimized()
    if index % 2:
        owner.showNormal()
    owner.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
    owner = footer = None
    next_owner = QWidget()
    next_footer = DashboardFooter(next_owner)
    next_owner.resize(800, 100)
    next_owner.show()
    app.processEvents()
    assert not next_footer.grab().isNull()
    assert not controller._collapsed_windows()
    gc.collect()
    next_owner.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
    next_owner = next_footer = None
controller.shutdown()
main.deleteLater()
QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
gc.collect()
print("ten minimize/delete/repaint/GC cycles completed")
'''
    environment = sanitized_child_environment(source={})
    environment.update({
        "QT_QPA_PLATFORM": "offscreen", "ANGERONA_REDUCE_MOTION": "1",
        "ANGERONA_DATA": str(tmp_path), "TEMP": str(tmp_path), "TMP": str(tmp_path),
    })
    result = subprocess.run(
        [sys.executable, "-X", "faulthandler", "-c", source],
        cwd=Path(__file__).resolve().parents[1], env=environment,
        capture_output=True, text=True, timeout=30,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "ten minimize/delete/repaint/GC cycles completed" in result.stdout
    assert "Error calling Python override" not in result.stderr
