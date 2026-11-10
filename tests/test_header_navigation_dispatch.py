"""Inert Qt routing: decorative motion never owns action admission."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, QTimer
from PySide6.QtWidgets import QApplication, QDialog, QWidget
from shiboken6 import delete, isValid

from angerona.gui import main_window
from angerona.gui.header_controls import PanelRevealOverlay
from angerona.gui.main_window import MainWindow


@pytest.fixture
def owner(monkeypatch):
    monkeypatch.setattr(main_window, "motion_allowed", lambda _config: True)
    widget = QWidget()
    widget.config = SimpleNamespace()
    widget._termination_started = False
    widget.resize(640, 400)
    try:
        yield widget
    finally:
        overlay = getattr(widget, "_panel_reveal", None)
        if isinstance(overlay, PanelRevealOverlay) and isValid(overlay):
            overlay.shutdown()
        if isValid(widget):
            delete(widget)
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)


@pytest.mark.parametrize("busy", ["armed", "target", "running", "shutdown", "deleted-driver"])
def test_every_real_animation_refusal_dispatches_the_action_once(owner, busy):
    overlay = PanelRevealOverlay(owner)
    owner._panel_reveal = overlay
    if busy == "armed":
        overlay._armed = True
    elif busy == "target":
        overlay._target = QDialog(owner)
    elif busy == "running":
        overlay._animation.start()
    elif busy == "shutdown":
        overlay.shutdown()
    else:
        delete(overlay._animation)
    calls = []

    MainWindow._reveal_window_from(owner, owner, lambda: calls.append("action"))

    assert calls == ["action"]


def test_accepted_real_reveal_retains_the_single_callback_widget_result(owner):
    overlay = PanelRevealOverlay(owner)
    owner._panel_reveal = overlay
    calls = []
    destination = QDialog(owner)
    destination.resize(320, 200)

    def action():
        calls.append("action")
        return destination

    MainWindow._reveal_window_from(owner, owner, action)

    assert calls == ["action"] and overlay._target is destination
    assert destination.isVisible() and not destination.mask().isEmpty()


@pytest.mark.parametrize("mode", ["false", "none", "called-false", "called-none", "twice", "queued-false"])
def test_fallback_and_late_callback_share_one_dispatch_ownership(owner, mode):
    calls, delayed, results = [], [], []
    sentinel = object()

    def reveal(_source, after, _color):
        if mode.startswith("called") or mode == "twice":
            results.append(after())
        if mode == "twice":
            results.append(after())
        delayed.append(after)
        if mode == "queued-false":
            QTimer.singleShot(0, after)
        return None if mode.endswith("none") or mode == "none" else False

    owner._panel_reveal = SimpleNamespace(reveal=reveal)
    MainWindow._reveal_window_from(owner, owner, lambda: (calls.append("action"), sentinel)[1])
    QApplication.processEvents()
    assert calls == ["action"]
    assert delayed[0]() is sentinel and calls == ["action"]
    assert all(result is sentinel for result in results)


@pytest.mark.parametrize("has_overlay,motion", [(False, True), (True, False)])
def test_missing_or_disabled_motion_does_not_block_the_action(owner, monkeypatch, has_overlay, motion):
    monkeypatch.setattr(main_window, "motion_allowed", lambda _config: motion)
    if has_overlay:
        owner._panel_reveal = SimpleNamespace(reveal=lambda *_args: pytest.fail("motion is disabled"))
    calls = []
    MainWindow._reveal_window_from(owner, owner, lambda: calls.append("action"))
    assert calls == ["action"]


@pytest.mark.parametrize("after_action", [False, True])
def test_visual_exception_retires_optional_motion_without_retrying_action(owner, after_action):
    calls, retired = [], []

    def reveal(_source, after, _color):
        if after_action:
            after()
        raise RuntimeError("inert visual-driver failure")

    owner._panel_reveal = SimpleNamespace(reveal=reveal, shutdown=lambda: retired.append(True))
    MainWindow._reveal_window_from(owner, owner, lambda: calls.append("action"))
    assert calls == ["action"] and retired == [True]
    assert owner._header_reveal_error == "RuntimeError"


def test_action_exception_propagates_once_instead_of_becoming_visual_fallback(owner):
    calls, late = [], []

    def reveal(_source, after, _color):
        late.append(after)
        return after()

    def action():
        calls.append("partially performed")
        raise ValueError("inert action failure")

    owner._panel_reveal = SimpleNamespace(reveal=reveal)
    with pytest.raises(ValueError, match="inert action failure"):
        MainWindow._reveal_window_from(owner, owner, action)
    assert late[0]() is None and calls == ["partially performed"]
    assert not hasattr(owner, "_header_reveal_error")


@pytest.mark.parametrize("termination", ["before", "during", "queued"])
def test_operator_termination_fences_direct_and_late_destination_actions(owner, termination):
    calls, late = [], []

    def reveal(_source, after, _color):
        late.append(after)
        if termination == "during":
            owner._termination_started = True
        return termination == "queued"

    owner._panel_reveal = SimpleNamespace(reveal=reveal)
    owner._termination_started = termination == "before"
    MainWindow._reveal_window_from(owner, owner, lambda: calls.append("action"))
    owner._termination_started = True
    for after in late:
        assert after() is None
    assert calls == []


def test_critical_stop_still_bypasses_the_optional_router(owner):
    stop = QWidget(owner)
    owner._stop_btn = stop
    owner._reveal_window_from = lambda *_args: pytest.fail("STOP entered optional motion")
    calls = []
    MainWindow._run_header_action(owner, stop, lambda: calls.append("inert STOP"), "#ef4444")
    assert calls == ["inert STOP"]
