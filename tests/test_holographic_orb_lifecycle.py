"""A queued minimize must not act on restored or destroyed Qt windows."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import weakref

import pytest
import PySide6
from PySide6.QtCore import QCoreApplication, QEvent, QRect
from PySide6.QtWidgets import QApplication, QMainWindow, QWidget
from shiboken6 import isValid

from angerona.core.privilege import sanitized_child_environment
from angerona.gui.holographic_orb import HolographicOrbController


@pytest.mark.parametrize("event_type", [
    QEvent.Destroy, QEvent.DeferredDelete, QEvent.WindowDeactivate,
    QEvent.ActivationChange, QEvent.Hide, QEvent.HideToParent,
    QEvent.PlatformSurface, QEvent.WinIdChange, QEvent.ChildRemoved,
    QEvent.Paint,
])
def test_teardown_and_unrelated_events_never_inspect_native_widget(monkeypatch, event_type):
    class DyingWindow:
        pass

    window = QMainWindow()
    controller = HolographicOrbController(window)
    dying = DyingWindow()
    controller._collapsed.append(weakref.ref(dying))
    controller._normal_geometries[dying] = QRect(0, 0, 640, 420)
    try:
        # A pure Python stand-in cannot safely be passed to any native Qt
        # method, including QObject.eventFilter. Destruction needs only identity
        # bookkeeping; unrelated events must not enter the native classifier.
        with monkeypatch.context() as scoped:
            scoped.setattr(controller, "_is_managed_window", lambda _watched: pytest.fail(
                "Native widget inspection during destruction/unrelated event"))
            assert controller.eventFilter(dying, QEvent(event_type)) is False
        if event_type == QEvent.Destroy:
            assert not controller._collapsed
            assert dying not in controller._normal_geometries
        else:
            assert controller._collapsed[0]() is dying
    finally:
        controller.shutdown()
        window.deleteLater()


def test_deleted_native_wrapper_is_not_classified_as_live_window():
    window = QMainWindow()
    controller = HolographicOrbController(window)
    target = QWidget()
    target.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
    try:
        assert not isValid(target)
        assert controller._is_managed_window(target) is False
        assert controller.eventFilter(target, QEvent(QEvent.WindowStateChange)) is False
    finally:
        controller.shutdown()
        window.deleteLater()


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
import PySide6
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
print("Qt binding", PySide6.__version__)
'''
    environment = sanitized_child_environment(source={})
    environment.update({
        "QT_QPA_PLATFORM": "offscreen", "ANGERONA_REDUCE_MOTION": "1",
        "ANGERONA_DATA": str(tmp_path), "TEMP": str(tmp_path), "TMP": str(tmp_path),
        # Exercise the parent's actual binding when validating an isolated Qt
        # version. Do not inherit arbitrary ambient PYTHONPATH entries.
        "PYTHONPATH": str(Path(PySide6.__file__).resolve().parent.parent),
    })
    result = subprocess.run(
        [sys.executable, "-X", "faulthandler", "-c", source],
        cwd=Path(__file__).resolve().parents[1], env=environment,
        capture_output=True, text=True, timeout=30,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "ten minimize/delete/repaint/GC cycles completed" in result.stdout
    assert f"Qt binding {PySide6.__version__}" in result.stdout
    assert "Error calling Python override" not in result.stderr
