"""Real Qt failure recovery; no runtime, host action or security decision."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from PySide6.QtCore import QAbstractAnimation, QCoreApplication, QElapsedTimer, QEvent, Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QDialog, QWidget
from shiboken6 import delete, isValid

from angerona.gui import header_controls
from angerona.gui.header_controls import PanelRevealOverlay


@pytest.fixture
def scene(monkeypatch):
    monkeypatch.delenv("ANGERONA_REDUCE_MOTION", raising=False)
    monkeypatch.setattr(header_controls, "_windows_client_animations_enabled", lambda: True)
    app = QApplication.instance()
    assert app is not None
    owner = QWidget()
    owner.resize(640, 400)
    owner.show()
    overlay = PanelRevealOverlay(owner)
    overlay.enable_global_windows()
    dialogs = []

    def destination(*, modal=False):
        dialog = QDialog(owner)
        dialog.resize(360, 240)
        if modal:
            dialog.setWindowModality(Qt.ApplicationModal)
        dialogs.append(dialog)
        return dialog

    state = SimpleNamespace(app=app, owner=owner, overlay=overlay, destination=destination)
    try:
        yield state
    finally:
        if isValid(overlay):
            overlay.shutdown()
        for dialog in dialogs:
            if isValid(dialog):
                dialog.reject()
                delete(dialog)
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        if isValid(owner):
            delete(owner)
        app.processEvents()


def wait_for_running_reveal(scene, target):
    """Let both queued 0ms phases run before advancing the real animation."""
    elapsed = QElapsedTimer()
    elapsed.start()
    while elapsed.elapsed() < 5_000:
        if (scene.overlay._target is target
                and scene.overlay._animation.state() == QAbstractAnimation.Running
                and not scene.overlay._reveal_start_timer.isActive()):
            return
        QTest.qWait(1)
    assert scene.overlay._target is target, "queued destination did not become the reveal owner"
    assert scene.overlay._animation.state() == QAbstractAnimation.Running, "reveal did not start"
    assert not scene.overlay._reveal_start_timer.isActive(), "reveal start remained queued"


def begin_opening(scene):
    first = scene.destination()
    first.show()
    scene.app.processEvents()
    assert scene.overlay._target is first and scene.overlay._frame is not None
    wait_for_running_reveal(scene, first)
    # Keep the first animation active independently of machine scheduling.
    scene.overlay._animation.setDuration(60_000)
    scene.overlay._animation.setCurrentTime(1_000)
    assert scene.overlay._animation.state() == QAbstractAnimation.Running
    assert not first.mask().isEmpty()
    assert not scene.overlay._reveal_start_timer.isActive()
    return first


@pytest.mark.parametrize("destroy_queued", [False, True])
def test_mid_animation_destination_loss_restores_queue_and_advances_modal(scene, destroy_queued):
    first = begin_opening(scene)
    skipped = scene.destination()
    if destroy_queued:
        skipped.show()
    second = scene.destination(modal=True)
    third = scene.destination()
    second.show()
    third.show()
    assert not second.mask().isEmpty() and not third.mask().isEmpty()
    assert scene.app.activeModalWidget() is second
    if destroy_queued:
        delete(skipped)

    delete(first)
    # The first start timer already ran. Exercise its next animation callback,
    # not the separate pre-start deletion branch covered by the older test.
    scene.overlay.set_reveal_progress(0.5)

    assert scene.overlay._target is scene.overlay._frame is None
    assert scene.overlay._mode == "idle"
    assert scene.overlay._animation.state() == QAbstractAnimation.Stopped
    assert second.mask().isEmpty() and third.mask().isEmpty()
    assert scene.overlay._pending_start_timer.isActive()
    scene.app.processEvents()
    assert scene.overlay._target is second
    assert scene.overlay._mode == "opening"
    assert third.mask().isEmpty()  # No later window stays a queued narrow slice.
    assert scene.app.activeModalWidget() is second
    assert second.result() == QDialog.Rejected  # Showing/recovering grants no acceptance.

    wait_for_running_reveal(scene, second)
    scene.overlay._animation.setCurrentTime(scene.overlay._animation.duration())
    wait_for_running_reveal(scene, third)
    assert scene.overlay._target is third
    scene.overlay._animation.setCurrentTime(scene.overlay._animation.duration())
    scene.app.processEvents()
    assert scene.overlay._target is None and not scene.overlay._pending_windows
    assert second.mask().isEmpty() and third.mask().isEmpty()


def test_destroyed_frame_restores_live_destination_and_leaves_close_usable(scene):
    first = begin_opening(scene)
    second = scene.destination()
    second.show()
    delete(scene.overlay._frame)

    scene.overlay.set_reveal_progress(0.5)

    assert first.mask().isEmpty() and second.mask().isEmpty()
    assert first.close() and not first.isVisible()
    scene.app.processEvents()
    assert scene.overlay._target is second


def test_shutdown_after_destination_loss_never_rearms_pending_modal(scene):
    first = begin_opening(scene)
    second = scene.destination(modal=True)
    second.show()
    delete(first)
    scene.overlay.set_reveal_progress(0.5)
    assert scene.overlay._pending_start_timer.isActive()

    scene.overlay.shutdown()
    scene.app.processEvents()

    assert scene.overlay._shut_down and not scene.overlay._global_windows
    assert scene.overlay._target is scene.overlay._frame is None
    assert not scene.overlay._pending_windows and second.mask().isEmpty()
    assert not scene.overlay._reveal_start_timer.isActive()
    assert not scene.overlay._pending_start_timer.isActive()
    assert second.close() and not second.isVisible()


def test_missing_native_motion_driver_falls_back_to_unmasked_windows(scene):
    first = begin_opening(scene)
    second = scene.destination(modal=True)
    second.show()
    delete(scene.overlay._animation)
    delete(scene.overlay._frame)

    scene.overlay.set_reveal_progress(0.5)

    assert scene.overlay._shut_down and not scene.overlay._global_windows
    assert scene.overlay._target is scene.overlay._frame is None
    assert not scene.overlay._pending_windows
    assert first.mask().isEmpty() and second.mask().isEmpty()
    assert first.close() and second.close()
