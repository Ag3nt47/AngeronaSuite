"""Inert Qt contracts for explicitly opted-in modeless content windows.

These tests construct only Qt widgets and the shared helper. They never import
MainWindow, pages, providers, scanners, policy, storage, or report readers.
"""
from __future__ import annotations

import os
import socket
import subprocess
import threading

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, QRect, Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QDialog, QMessageBox, QPushButton, QWidget
from shiboken6 import isValid

from angerona.gui.window_controls import (
    WindowLifetime, WindowRetirementPending, configure_work_window,
    work_window_registry,
)


@pytest.fixture(autouse=True)
def no_host_operations(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Window controls must not start host work")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(threading.Thread, "start", forbidden)
    monkeypatch.setattr(os, "system", forbidden)


@pytest.fixture
def make_window():
    allocated = []

    def make(kind=QDialog, parent=None, **kwargs):
        window = kind(parent, **kwargs)
        allocated.append(window)
        return window

    yield make
    for window in reversed(allocated):
        if isValid(window):
            window.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)


def settle():
    QApplication.processEvents()
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)


class CountedDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.flag_changes = 0

    def setWindowFlags(self, flags):  # noqa: N802 - Qt signature
        self.flag_changes += 1
        super().setWindowFlags(flags)


def test_native_controls_apply_once_before_show_without_changing_type_or_size(make_window):
    window = make_window(CountedDialog)
    window.setFixedSize(330, 210)
    original_flags = window.windowFlags()
    original_type = window.windowType()
    original_sizes = (window.size(), window.minimumSize(), window.maximumSize())
    controller = configure_work_window(window)
    expected_hints = (Qt.WindowMinimizeButtonHint | Qt.WindowMaximizeButtonHint
                      | Qt.WindowCloseButtonHint | Qt.WindowSystemMenuHint)
    assert window.windowFlags() == original_flags | expected_hints
    assert window.windowType() == original_type
    assert (window.size(), window.minimumSize(), window.maximumSize()) == original_sizes
    changes = window.flag_changes
    assert changes <= 1
    window.show()
    settle()
    for _ in range(2):
        window.hide()
        window.show()
        assert configure_work_window(window) is controller
        assert window.isVisible()
    assert window.flag_changes == changes


@pytest.mark.parametrize("hidden_again", [False, True])
def test_previously_created_native_windows_never_reset_flags(make_window, hidden_again):
    window = make_window(CountedDialog)
    window.show()
    settle()
    if hidden_again:
        window.hide()
    before = (window.flag_changes, window.windowFlags(), window.isVisible())
    controller = configure_work_window(window)
    assert controller is not None and not controller.native_hints_changed
    assert (window.flag_changes, window.windowFlags(), window.isVisible()) == before


@pytest.mark.parametrize("excluded", ["message", "modal", "popup", "tooltip", "splash",
                                    "security", "orb", "opt_out", "child"])
def test_transient_and_security_surfaces_are_excluded(make_window, excluded):
    if excluded == "message":
        window = make_window(QMessageBox)
    elif excluded == "child":
        window = make_window(QWidget, parent=make_window(QWidget))
    else:
        window = make_window()
    if excluded == "modal":
        window.setModal(True)
    if excluded in {"popup", "tooltip", "splash"}:
        window.setWindowFlags({"popup": Qt.Popup, "tooltip": Qt.ToolTip,
                               "splash": Qt.SplashScreen}[excluded])
    if excluded in {"security", "orb", "opt_out"}:
        window.setProperty({"security": "_angerona_security_prompt",
                            "orb": "_angerona_orb_ignore",
                            "opt_out": "_angerona_no_window_controls"}[excluded], True)
    before = (window.windowFlags(), window.windowModality(), window.size())
    assert configure_work_window(window) is None
    assert (window.windowFlags(), window.windowModality(), window.size()) == before
    assert not hasattr(window, "_angerona_work_window_controller")


def test_distinct_modeless_workspaces_remain_interactable_and_reuse_one_factory(make_window):
    owner = make_window(QWidget)
    owner.show()
    registry = work_window_registry(owner)
    assert work_window_registry(owner) is registry
    calls, clicks = [], []

    def factory(name):
        calls.append(name)
        window = make_window(parent=owner)
        button = QPushButton(name, window)
        button.clicked.connect(lambda: clicks.append(name))
        return window

    spy = registry.show("spyware", lambda: factory("spyware"))
    aar = registry.show("redteam-aar", lambda: factory("redteam-aar"))
    settle()
    assert registry.show("spyware", lambda: factory("duplicate")) is spy
    assert spy is not aar and owner.isVisible() and spy.isVisible() and aar.isVisible()
    assert not spy.isModal() and not aar.isModal()
    assert QApplication.activeModalWidget() is None
    for window in (spy, aar, spy):
        QTest.mouseClick(window.findChild(QPushButton), Qt.LeftButton)
    assert clicks == ["spyware", "redteam-aar", "spyware"]
    assert calls == ["spyware", "redteam-aar"]
    assert set(registry.keys()) == {"spyware", "redteam-aar"}


def test_registry_keys_are_scoped_to_the_owner(make_window):
    first, second = make_window(QWidget), make_window(QWidget)
    left, right = work_window_registry(first), work_window_registry(second)
    a = left.show("same-key", lambda: make_window(parent=first))
    b = right.show("same-key", lambda: make_window(parent=second))
    assert a is not b and left.get("same-key") is a and right.get("same-key") is b


def test_reusable_dialog_keeps_state_after_finished_and_reopens_without_new_backend(make_window):
    owner = make_window(QWidget)
    registry = work_window_registry(owner)
    built = []

    def factory():
        built.append(True)
        return make_window(parent=owner)

    window = registry.show("workspace", factory)
    window.setProperty("unsaved-edit", "retained")
    window.reject()
    settle()
    assert registry.get("workspace") is window and isValid(window)
    assert registry.show("workspace", factory) is window
    assert window.property("unsaved-edit") == "retained" and built == [True]
    assert not window.testAttribute(Qt.WA_DeleteOnClose)


@pytest.mark.parametrize("kind", [QWidget, QDialog])
def test_disposable_accepted_close_releases_widget_and_key(make_window, kind):
    owner = make_window(QWidget)
    registry = work_window_registry(owner)
    released = []

    def factory():
        window = make_window(kind, parent=owner)
        if kind is QWidget:
            window.setWindowFlag(Qt.Window, True)
        return window

    window = registry.show("detail", factory,
                           lifetime=WindowLifetime.DISPOSABLE, on_release=released.append)
    assert window.close()
    settle()
    assert registry.get("detail") is None and not isValid(window)
    assert released == [window]


def test_vetoed_close_and_later_plain_hide_do_not_dispose(make_window):
    class VetoDialog(QDialog):
        def closeEvent(self, event):  # noqa: N802 - Qt signature
            event.ignore()

    owner = make_window(QWidget)
    registry = work_window_registry(owner)
    window = registry.show("veto", lambda: make_window(VetoDialog, parent=owner),
                           lifetime=WindowLifetime.DISPOSABLE)
    assert not window.close()
    settle()
    assert window.isVisible() and registry.get("veto") is window
    window.hide()
    settle()
    assert isValid(window) and registry.get("veto") is window


def test_hidden_async_owner_retains_key_until_owner_retirement_continuation(make_window):
    class AsyncOwnerDialog(QDialog):
        def closeEvent(self, event):  # noqa: N802 - Qt signature
            self._angerona_work_window_retained = True
            self.hide()
            event.ignore()

    owner = make_window(QWidget)
    registry = work_window_registry(owner)
    ready, built, released = [False], [], []

    def factory():
        built.append(True)
        return make_window(AsyncOwnerDialog, parent=owner)

    window = registry.show("async", factory, lifetime=WindowLifetime.DISPOSABLE,
                           can_release=lambda _window: ready[0], on_release=released.append)
    assert not window.close()
    settle()
    assert not window.isVisible() and isValid(window) and registry.get("async") is window
    with pytest.raises(WindowRetirementPending):
        registry.show("async", factory, lifetime=WindowLifetime.DISPOSABLE)
    assert built == [True] and released == []
    ready[0] = True
    assert not registry.release("async")  # The owner's retained flag remains a fence.
    window._angerona_work_window_retained = False
    assert registry.release("async")
    settle()
    assert not isValid(window) and registry.get("async") is None and released == [window]


def test_failed_owner_retirement_callback_keeps_closed_window(make_window):
    owner = make_window(QWidget)
    registry = work_window_registry(owner)

    def failed(_window):
        raise RuntimeError("Owner retirement is incomplete")

    window = registry.show("retained", lambda: make_window(parent=owner),
                           lifetime=WindowLifetime.DISPOSABLE, can_release=failed)
    window.close()
    settle()
    assert isValid(window) and registry.get("retained") is window
    assert not registry.release("retained")


def test_reentrant_release_callback_cannot_run_twice(make_window):
    owner = make_window(QWidget)
    registry = work_window_registry(owner)
    released = []

    def release_callback(window):
        released.append(window)
        assert not registry.release("detail")

    window = registry.show("detail", lambda: make_window(parent=owner),
                           lifetime=WindowLifetime.DISPOSABLE,
                           on_release=release_callback)
    window.reject()
    settle()
    assert released == [window] and not isValid(window)
    assert registry.get("detail") is None


def test_hidden_widget_close_veto_does_not_supply_disposal_permission(make_window):
    class VetoWidget(QWidget):
        def __init__(self, parent=None):
            super().__init__(parent, Qt.Window)

        def closeEvent(self, event):  # noqa: N802 - Qt signature
            event.ignore()

    owner = make_window(QWidget)
    registry = work_window_registry(owner)
    window = registry.show("hidden-veto", lambda: make_window(VetoWidget, parent=owner),
                           lifetime=WindowLifetime.DISPOSABLE)
    window.hide()
    assert not window.close()
    settle()
    assert isValid(window) and registry.get("hidden-veto") is window


def test_destroyed_old_generation_cannot_remove_replacement_key(make_window):
    owner = make_window(QWidget)
    registry = work_window_registry(owner)
    old = registry.show("detail", lambda: make_window(parent=owner),
                        lifetime=WindowLifetime.DISPOSABLE)
    old.reject()  # finished releases the key; native deletion is still deferred.
    assert registry.get("detail") is None
    new = registry.show("detail", lambda: make_window(parent=owner),
                        lifetime=WindowLifetime.DISPOSABLE)
    settle()
    assert not isValid(old) and isValid(new) and registry.get("detail") is new


def test_modal_and_self_deleting_factories_are_rejected_without_overrides(make_window):
    owner = make_window(QWidget)
    registry = work_window_registry(owner)
    modal, self_deleting = make_window(parent=owner), make_window(parent=owner)
    modal.setModal(True)
    self_deleting.setAttribute(Qt.WA_DeleteOnClose, True)
    for key, window in (("modal", modal), ("self-deleting", self_deleting)):
        with pytest.raises(ValueError):
            registry.show(key, lambda: window)
        assert registry.get(key) is None and not window.isVisible()
    assert modal.isModal() and self_deleting.testAttribute(Qt.WA_DeleteOnClose)


def test_fullscreen_shortcuts_affect_only_active_window_and_restore_normal_geometry(make_window,
                                                                                  monkeypatch):
    first, second = make_window(), make_window()
    first.setGeometry(QRect(80, 60, 360, 240))
    left, right = configure_work_window(first), configure_work_window(second)
    first.show()
    second.show()
    settle()
    active = [first]
    monkeypatch.setattr(QApplication, "activeWindow", staticmethod(lambda: active[0]))
    normal = QRect(first.geometry())
    assert not right.toggle_fullscreen()
    left.fullscreen_shortcut.activated.emit()
    assert first.isFullScreen() and not second.isFullScreen()
    assert left.escape_shortcut.isEnabled() and not right.escape_shortcut.isEnabled()
    right.escape_shortcut.activated.emit()
    assert first.isFullScreen()
    active[0] = second
    assert not left.leave_fullscreen()
    active[0] = first
    left.escape_shortcut.activated.emit()
    assert not first.isFullScreen() and not first.isMaximized()
    assert first.geometry() == normal and not left.escape_shortcut.isEnabled()
    assert second.isVisible() and first.isVisible()


def test_fullscreen_restores_previously_maximized_window_and_its_normal_geometry(make_window,
                                                                                monkeypatch):
    window = make_window()
    window.setGeometry(QRect(90, 70, 380, 250))
    controller = configure_work_window(window)
    window.show()
    settle()
    window.showMaximized()
    settle()
    normal = QRect(window.normalGeometry())
    monkeypatch.setattr(QApplication, "activeWindow", staticmethod(lambda: window))
    assert controller.toggle_fullscreen() and window.isFullScreen()
    assert controller.leave_fullscreen() and window.isMaximized()
    assert window.normalGeometry() == normal
    window.showNormal()
    assert window.geometry() == normal


def test_escape_outside_fullscreen_keeps_dialogs_existing_reject_behavior(make_window):
    window = make_window()
    controller = configure_work_window(window)
    window.show()
    settle()
    assert not controller.escape_shortcut.isEnabled()
    QTest.keyClick(window, Qt.Key_Escape)
    assert not window.isVisible() and isValid(window)


def test_reveal_animation_opt_out_still_allows_explicit_work_window_controls(make_window):
    window = make_window()
    window.setProperty("_angerona_no_reveal", True)
    assert configure_work_window(window) is not None
    assert window.windowFlags() & Qt.WindowMinimizeButtonHint
    assert window.windowFlags() & Qt.WindowMaximizeButtonHint
    assert window.property("_angerona_no_reveal") is True
