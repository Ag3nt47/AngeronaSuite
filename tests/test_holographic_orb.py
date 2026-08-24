from __future__ import annotations

import os
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QEvent, QPoint, QPointF, QRect, Qt
from PySide6.QtGui import QMouseEvent
from PySide6.QtTest import QSignalSpy, QTest
from PySide6.QtWidgets import QApplication, QMainWindow

import angerona.gui.holographic_orb as orb_module
from angerona.gui.holographic_orb import (
    CollapseTrail,
    HolographicOrb,
    HolographicOrbController,
)


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def _config():
    return SimpleNamespace(
        ui_motion_enabled=True,
        holographic_orb_enabled=True,
        holographic_orb_x=-1,
        holographic_orb_y=-1,
        save=lambda: None,
    )


def test_collapse_trail_reduces_window_to_line_then_orb_dot() -> None:
    _app()
    source = QRect(100, 80, 900, 620)
    destination = QPoint(1300, 820)
    trail = CollapseTrail(source, destination)

    start = trail.animated_rect(0.0)
    line = trail.animated_rect(0.48)
    dot = trail.animated_rect(1.0)
    assert round(start.width()) == source.width()
    assert round(start.height()) == source.height()
    assert line.width() <= 5
    assert line.height() < source.height()
    assert dot.width() <= 4
    assert dot.height() <= 4
    assert round(dot.center().x()) == destination.x() - trail.geometry().left()
    assert round(dot.center().y()) == destination.y() - trail.geometry().top()
    trail.deleteLater()


def test_orb_paints_globe_and_expands_four_unique_services(monkeypatch) -> None:
    monkeypatch.setenv("ANGERONA_REDUCE_MOTION", "1")
    app = _app()
    orb = HolographicOrb(_config())
    screen = app.primaryScreen()
    assert screen is not None
    orb.set_anchor(screen.availableGeometry().center())
    orb.show_token()
    orb.set_menu_expanded(True, animated=False)
    app.processEvents()

    assert orb.isVisible()
    assert orb.menuProgress == 1.0
    assert {service.key for service in orb.services} == {
        "core",
        "watchdog",
        "scanner",
        "blackbox",
    }
    assert set(orb._node_rects) == {
        "core",
        "watchdog",
        "scanner",
        "blackbox",
    }
    image = orb.grab().toImage()
    assert image.width() > 200
    assert image.height() > 200
    assert image.hasAlphaChannel()
    assert not orb._tick.isActive()
    orb.hide_token()
    orb.deleteLater()


def test_orb_service_node_emits_destination(monkeypatch) -> None:
    monkeypatch.setenv("ANGERONA_REDUCE_MOTION", "1")
    app = _app()
    orb = HolographicOrb(_config())
    screen = app.primaryScreen()
    assert screen is not None
    orb.set_anchor(screen.availableGeometry().center())
    orb.show_token()
    orb.set_menu_expanded(True, animated=False)
    app.processEvents()
    selected: list[str] = []
    orb.serviceTriggered.connect(selected.append)

    center = orb._node_rects["watchdog"].center().toPoint()
    QTest.mouseClick(orb, Qt.LeftButton, pos=center)
    app.processEvents()
    assert selected == ["watchdog"]
    assert orb.menuProgress == 0.0
    orb.hide_token()
    orb.deleteLater()


def test_orb_restores_saved_position_on_monitor_left_of_primary() -> None:
    _app()
    config = _config()
    config.holographic_orb_x = -720
    config.holographic_orb_y = 420
    orb = HolographicOrb(config)

    assert orb._saved_anchor() == QPoint(-720, 420)
    orb.deleteLater()


def test_orb_crosses_monitor_gap_using_nearest_destination_screen(monkeypatch) -> None:
    _app()

    class _Screen:
        def __init__(self, rect: QRect) -> None:
            self._rect = rect

        def availableGeometry(self) -> QRect:
            return QRect(self._rect)

    first = _Screen(QRect(0, 0, 800, 600))
    second = _Screen(QRect(1000, 0, 800, 600))

    class _Screens:
        @staticmethod
        def screenAt(point: QPoint):
            for screen in (first, second):
                if screen.availableGeometry().contains(point):
                    return screen
            return None

        @staticmethod
        def screens():
            return [first, second]

        @staticmethod
        def primaryScreen():
            return first

    orb = HolographicOrb(_config())
    monkeypatch.setattr(orb_module, "QGuiApplication", _Screens)
    orb.set_anchor(QPoint(700, 300))
    press = QMouseEvent(
        QEvent.Type.MouseButtonPress,
        QPointF(58, 58),
        QPointF(700, 300),
        Qt.MouseButton.LeftButton,
        Qt.MouseButton.LeftButton,
        Qt.KeyboardModifier.NoModifier,
    )
    orb.mousePressEvent(press)

    # Use many small pointer updates through the empty space between screens.
    # Incremental anchor+delta tracking used to clamp every update back onto the
    # first screen; total mouse-down displacement must carry it across.
    for x in range(720, 1_101, 20):
        move = QMouseEvent(
            QEvent.Type.MouseMove,
            QPointF(58 + x - 700, 58),
            QPointF(x, 300),
            Qt.MouseButton.NoButton,
            Qt.MouseButton.LeftButton,
            Qt.KeyboardModifier.NoModifier,
        )
        orb.mouseMoveEvent(move)
    assert orb.anchor.x() > 1000
    assert orb._screen() is second
    orb.deleteLater()


def test_native_minimize_collapses_to_orb_and_restores(monkeypatch) -> None:
    monkeypatch.setenv("ANGERONA_REDUCE_MOTION", "1")
    app = _app()
    window = QMainWindow()
    window.resize(640, 420)
    window.show()
    app.processEvents()
    original_size = window.size()
    controller = HolographicOrbController(window, _config())

    window.setWindowState(Qt.WindowMinimized)
    for _ in range(4):
        app.processEvents()

    assert controller.is_collapsed(window)
    assert not window.isVisible()
    assert controller.orb.isVisible()
    assert not (window.windowState() & Qt.WindowMinimized)

    controller.restore_main()
    app.processEvents()
    assert window.isVisible()
    assert not controller.is_collapsed(window)
    assert not controller.orb.isVisible()
    assert window.size() == original_size

    controller.shutdown()
    window.close()


def test_disabling_orb_restores_collapsed_windows(monkeypatch) -> None:
    monkeypatch.setenv("ANGERONA_REDUCE_MOTION", "1")
    app = _app()
    config = _config()
    window = QMainWindow()
    window.resize(540, 320)
    window.show()
    app.processEvents()
    controller = HolographicOrbController(window, config)
    controller.collapse_window(window)
    assert controller.is_collapsed(window)

    config.holographic_orb_enabled = False
    controller.sync_config()
    app.processEvents()
    assert window.isVisible()
    assert not controller.orb.isVisible()
    assert not controller.enabled()

    controller.shutdown()
    window.close()


def test_animated_collapse_and_restore_complete_without_stranding_window(
    monkeypatch,
) -> None:
    monkeypatch.delenv("ANGERONA_REDUCE_MOTION", raising=False)
    monkeypatch.setattr(
        "angerona.gui.holographic_orb.motion_allowed",
        lambda _config=None: True,
    )
    app = _app()
    window = QMainWindow()
    window.resize(620, 380)
    window.show()
    app.processEvents()
    controller = HolographicOrbController(window, _config())

    controller.collapse_window(window)
    assert controller._trails
    collapse_completed = QSignalSpy(controller._trails[-1].completed)
    assert collapse_completed.wait(2_000)
    app.processEvents()
    assert controller.orb.isVisible()
    assert controller.is_collapsed(window)

    controller.restore_main()
    assert controller._trails
    restore_trail = controller._trails[-1]
    restore_completed = QSignalSpy(restore_trail.completed)
    # Simulate a display/animation interruption.  The independent completion
    # guard must still restore the real window rather than strand it hidden.
    restore_trail._animation.stop()
    restore_trail._completion_guard.setInterval(40)
    restore_trail._completion_guard.start()
    assert restore_completed.wait(2_000)
    app.processEvents()
    assert window.isVisible()
    assert not controller.is_collapsed(window)
    assert not controller.orb.isVisible()
    assert controller._trails == []

    controller.shutdown()
    window.close()
