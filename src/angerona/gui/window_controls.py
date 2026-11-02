"""Explicit content-window controls and owner-scoped modeless workspaces.

Call ``configure_work_window`` after construction, before the first show. This
module never patches QDialog, changes modality, resizes a widget, or starts a
worker. Owners remain responsible for cancellation and worker retirement.
"""
from __future__ import annotations

from collections.abc import Callable, Hashable
from dataclasses import dataclass
from enum import Enum
import weakref

from PySide6.QtCore import QCoreApplication, QEvent, QObject, QRect, Qt
from PySide6.QtGui import QKeySequence, QShortcut
from PySide6.QtWidgets import QApplication, QMessageBox, QWidget
from shiboken6 import isValid


_NATIVE_CONTROLS = (
    Qt.WindowMinimizeButtonHint | Qt.WindowMaximizeButtonHint
    | Qt.WindowCloseButtonHint | Qt.WindowSystemMenuHint
)
_CLOSE_CHECK_EVENT = QEvent.Type(QEvent.registerEventType())
_EXCLUDED_TYPES = frozenset((Qt.Popup, Qt.ToolTip, Qt.SplashScreen))
_OPT_OUT_FLAGS = (
    "_angerona_no_window_controls", "_angerona_security_prompt",
    "_angerona_orb_ignore",
)


def _flag(window: QWidget, name: str) -> bool:
    return bool(getattr(window, name, False) or window.property(name))


def _is_work_window(window: QWidget) -> bool:
    if not isinstance(window, QWidget) or not isValid(window):
        return False
    return (
        window.isWindow() and not isinstance(window, QMessageBox)
        and window.windowType() not in _EXCLUDED_TYPES
        and window.windowModality() == Qt.NonModal
        and not any(_flag(window, name) for name in _OPT_OUT_FLAGS)
    )


@dataclass
class _FullscreenRestore:
    normal_geometry: QRect
    maximized: bool


class WorkWindowController(QObject):
    """One content window's native controls and active-window shortcuts."""

    def __init__(self, window: QWidget, *, fullscreen: bool = True) -> None:
        super().__init__(window)
        self._window = window
        self._retired = False
        self._fullscreen_enabled = bool(fullscreen)
        self._restore: _FullscreenRestore | None = None
        self.native_hints_changed = False
        # A previously mapped (even currently hidden) window must keep its
        # native identity. Adding flags later can hide/recreate that window.
        if (not window.isVisible()
                and not window.testAttribute(Qt.WA_WState_Created)):
            original = window.windowFlags()
            wanted = original | _NATIVE_CONTROLS
            if wanted != original:
                window.setWindowFlags(wanted)
                self.native_hints_changed = True
        self.fullscreen_shortcut: QShortcut | None = None
        self.escape_shortcut: QShortcut | None = None
        if fullscreen:
            self.fullscreen_shortcut = QShortcut(QKeySequence(Qt.Key_F11), window)
            self.fullscreen_shortcut.setContext(Qt.WindowShortcut)
            self.fullscreen_shortcut.setAutoRepeat(False)
            self.fullscreen_shortcut.activated.connect(self.toggle_fullscreen)
            self.escape_shortcut = QShortcut(QKeySequence(Qt.Key_Escape), window)
            self.escape_shortcut.setContext(Qt.WindowShortcut)
            self.escape_shortcut.setAutoRepeat(False)
            self.escape_shortcut.setEnabled(window.isFullScreen())
            self.escape_shortcut.activated.connect(self.leave_fullscreen)
        window.installEventFilter(self)

    def _live_window(self) -> QWidget | None:
        window = getattr(self, "_window", None)
        if (getattr(self, "_retired", True) or window is None
                or not isValid(window)):
            return None
        return window

    def _active_window(self) -> QWidget | None:
        window = self._live_window()
        if (window is None or not window.isVisible()
                or QApplication.activeWindow() is not window):
            return None
        return window

    def toggle_fullscreen(self) -> bool:
        """Toggle true fullscreen for this active window only."""
        window = self._active_window()
        if window is None or not self._fullscreen_enabled:
            return False
        if window.isFullScreen():
            return self.leave_fullscreen()
        normal = window.normalGeometry() if window.isMaximized() else window.geometry()
        self._restore = _FullscreenRestore(QRect(normal), window.isMaximized())
        window.showFullScreen()
        return True

    def leave_fullscreen(self) -> bool:
        """Restore normal geometry, then the previous maximized state if any."""
        window = self._active_window()
        if window is None or not self._fullscreen_enabled or not window.isFullScreen():
            return False
        restore = self._restore
        if restore is None:
            restore = _FullscreenRestore(QRect(window.normalGeometry()), False)
        # WindowStateChange is synchronous: keep the snapshot in this local
        # before showNormal clears it. No native flags are reapplied here.
        window.showNormal()
        if restore.normal_geometry.isValid():
            window.setGeometry(restore.normal_geometry)
        if restore.maximized:
            window.showMaximized()
        return True

    def eventFilter(self, watched, event) -> bool:  # noqa: N802 - Qt signature
        # Qt can dispatch while cyclic collection has cleared Python state.
        if not isValid(self) or getattr(self, "_retired", True):
            return False
        window = getattr(self, "_window", None)
        if watched is not window:
            return False
        kind = event.type()
        if kind == QEvent.Destroy:
            self._retired = True
            self._window = None
            return False
        if window is None or not isValid(window):
            return False
        if kind == QEvent.WindowStateChange:
            fullscreen = window.isFullScreen()
            if fullscreen and self._restore is None:
                # Also support fullscreen entered through an owner's menu.
                self._restore = _FullscreenRestore(
                    QRect(window.normalGeometry()),
                    bool(event.oldState() & Qt.WindowMaximized),
                )
            elif not fullscreen:
                self._restore = None
            shortcut = getattr(self, "escape_shortcut", None)
            if shortcut is not None and isValid(shortcut):
                shortcut.setEnabled(fullscreen)
        return False


def configure_work_window(
    window: QWidget, *, fullscreen: bool = True,
) -> WorkWindowController | None:
    """Opt in one modeless content window; the first call fixes its options.

    Modal dialogs, message boxes, transient surfaces, and explicit opt-outs
    receive no changes. Already-created native windows can gain local keyboard
    controls but never have their native flags reset. Fixed sizes are preserved.
    """
    if not _is_work_window(window):
        return None
    existing = getattr(window, "_angerona_work_window_controller", None)
    if isinstance(existing, WorkWindowController) and isValid(existing):
        return existing
    controller = WorkWindowController(window, fullscreen=fullscreen)
    window._angerona_work_window_controller = controller
    return controller


class WindowLifetime(Enum):
    REUSABLE = "reusable"
    DISPOSABLE = "disposable"


class WindowRetirementPending(RuntimeError):
    """The owner still retains a closed disposable workspace for its workers."""


@dataclass
class _WindowEntry:
    window: QWidget
    observer: _RegistryObserver
    token: object
    lifetime: WindowLifetime
    can_release: Callable[[QWidget], bool] | None
    on_release: Callable[[QWidget], None] | None
    closed: bool = False
    releasing: bool = False


class _RegistryObserver(QObject):
    """Check close outcome on one posted event, without a polling timer."""

    def __init__(self, registry: WorkWindowRegistry, key: Hashable,
                 token: object, window: QWidget) -> None:
        super().__init__(window)
        self._registry = weakref.ref(registry)
        self._key = key
        self._token = token
        self._close_check_pending = False
        self._close_was_visible = False
        window.installEventFilter(self)

    def eventFilter(self, watched, event) -> bool:  # noqa: N802 - Qt signature
        if not isValid(self) or not hasattr(self, "_registry"):
            return False
        if event.type() == QEvent.Close:
            self._close_was_visible = self._close_was_visible or watched.isVisible()
            if not self._close_check_pending:
                self._close_check_pending = True
                QCoreApplication.postEvent(self, QEvent(_CLOSE_CHECK_EVENT))
        return False

    def event(self, event) -> bool:
        if event.type() == _CLOSE_CHECK_EVENT:
            if not hasattr(self, "_registry"):
                return True
            self._close_check_pending = False
            was_visible = self._close_was_visible
            self._close_was_visible = False
            registry = self._registry()
            if registry is not None and isValid(registry):
                registry._check_close(self._key, self._token, was_visible)
            return True
        return super().event(event)


class WorkWindowRegistry(QObject):
    """Strong references keyed within one UI owner, never a global singleton.

    Factories are invoked only for a missing key. DISPOSABLE is an explicit
    owner assertion that release is safe, subject to ``can_release`` and the
    owner's ``_angerona_preserve_on_close`` / ``_angerona_work_window_retained``
    flags. This registry does not cancel, join, or stop any worker.
    """

    def __init__(self, owner: QWidget) -> None:
        super().__init__(owner)
        self._entries: dict[Hashable, _WindowEntry] = {}

    def get(self, key: Hashable) -> QWidget | None:
        entry = self._entries.get(key)
        if entry is None:
            return None
        if not isValid(entry.window):
            self._entries.pop(key, None)
            return None
        return entry.window

    def keys(self) -> tuple[Hashable, ...]:
        return tuple(key for key in tuple(self._entries) if self.get(key) is not None)

    def show(
        self, key: Hashable, factory: Callable[[], QWidget], *,
        lifetime: WindowLifetime = WindowLifetime.REUSABLE,
        can_release: Callable[[QWidget], bool] | None = None,
        on_release: Callable[[QWidget], None] | None = None,
    ) -> QWidget:
        """Create/reuse a modeless workspace and show it without a nested loop.

        An occupied key retains its original callbacks and policy. Modal or
        self-deleting factories are rejected, requiring a deliberate owner
        integration instead of silently overriding their lifetime/modality.
        """
        if not isValid(self):
            raise RuntimeError("The workspace owner has been destroyed")
        hash(key)
        if not isinstance(lifetime, WindowLifetime):
            raise TypeError("lifetime must be a WindowLifetime")
        window = self.get(key)
        if window is None:
            window = factory()
            if not _is_work_window(window):
                raise ValueError("A workspace factory must return an opted-in modeless content window")
            if window.testAttribute(Qt.WA_DeleteOnClose):
                raise ValueError("The workspace owner must construct without WA_DeleteOnClose")
            configure_work_window(window)
            token = object()
            observer = _RegistryObserver(self, key, token, window)
            self._entries[key] = _WindowEntry(
                window, observer, token, lifetime, can_release, on_release,
            )
            registry_ref = weakref.ref(self)

            def finished(*_args):
                registry = registry_ref()
                if registry is not None and isValid(registry):
                    registry._finished(key, token)

            def destroyed(*_args):
                registry = registry_ref()
                if registry is not None:
                    registry._destroyed(key, token)

            signal = getattr(window, "finished", None)
            if signal is not None:
                signal.connect(finished)
            window.destroyed.connect(destroyed)
        else:
            entry = self._entries[key]
            if entry.lifetime is not lifetime:
                raise ValueError("An occupied workspace key cannot change its lifetime")
            if entry.closed and lifetime is WindowLifetime.DISPOSABLE:
                raise WindowRetirementPending("The workspace owner has not retired its closed window")
            # A security gate may have changed since initial construction.
            if not _is_work_window(window):
                raise ValueError("The workspace no longer permits modeless content-window use")
        self._entries[key].closed = False
        if window.isMinimized():
            window.showNormal()
        else:
            window.show()
        window.raise_()
        window.activateWindow()
        return window

    def _entry(self, key: Hashable, token: object) -> _WindowEntry | None:
        entry = getattr(self, "_entries", {}).get(key)
        return entry if entry is not None and entry.token is token else None

    def _check_close(self, key: Hashable, token: object, was_visible: bool) -> None:
        entry = self._entry(key, token)
        # A hidden widget provides no visibility transition to distinguish an
        # accepted Close from a veto. Retain it unless finished or an explicit
        # owner release supplies that missing lifecycle decision.
        if (was_visible and entry is not None and isValid(entry.window)
                and not entry.window.isVisible()):
            self._finished(key, token)

    def _finished(self, key: Hashable, token: object) -> None:
        entry = self._entry(key, token)
        if entry is None:
            return
        entry.closed = True
        if entry.lifetime is WindowLifetime.DISPOSABLE:
            self.release(key)

    def _destroyed(self, key: Hashable, token: object) -> None:
        if self._entry(key, token) is not None:
            self._entries.pop(key, None)

    def _release_allowed(self, key: Hashable, entry: _WindowEntry) -> bool:
        window = entry.window

        def unchanged_and_hidden() -> bool:
            return (
                isValid(self) and self._entry(key, entry.token) is entry and isValid(window)
                and not window.isVisible()
                and not _flag(window, "_angerona_preserve_on_close")
                and not _flag(window, "_angerona_work_window_retained")
            )

        if not unchanged_and_hidden():
            return False
        if entry.can_release is not None and not entry.can_release(window):
            return False
        # Readiness is owner code and may itself reenter Qt or change a fence.
        return unchanged_and_hidden()

    def release(self, key: Hashable) -> bool:
        """Delete a hidden workspace only after owner retirement fences pass.

        Call again from the owner's worker-completion continuation when an
        earlier close was retained. A failed callback keeps the window/key.
        Visible windows and vetoed closes are never released here.
        """
        window = self.get(key)
        if window is None:
            return False
        entry = self._entries[key]
        if entry.releasing:
            return False
        entry.releasing = True
        try:
            if not self._release_allowed(key, entry):
                return False
            if entry.on_release is not None:
                entry.on_release(window)
            if not self._release_allowed(key, entry):
                return False
            if isValid(entry.observer):
                window.removeEventFilter(entry.observer)
                entry.observer.deleteLater()
            window.deleteLater()
            self._entries.pop(key)
            return True
        except Exception:
            # A failed owner retirement callback is not permission to delete.
            return False
        finally:
            entry.releasing = False


def work_window_registry(owner: QWidget) -> WorkWindowRegistry:
    """Return this owner's registry; different owners can use identical keys."""
    existing = getattr(owner, "_angerona_work_window_registry", None)
    if isinstance(existing, WorkWindowRegistry) and isValid(existing):
        return existing
    registry = WorkWindowRegistry(owner)
    owner._angerona_work_window_registry = registry
    return registry
