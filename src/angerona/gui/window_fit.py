"""Opt-in, dialog-owned fitting inside Qt's current screen work area.

Qt window and screen rectangles already use device-independent coordinates.
Only the measured window decorations are deducted from the client budget;
neither monitor origins nor rectangles are multiplied by a pixel ratio.
"""
from __future__ import annotations

from PySide6.QtCore import QEvent, QObject, QPoint, QRect, QSize, QTimer
from PySide6.QtWidgets import QDialog, QLayout, QScrollArea, QVBoxLayout, QWidget


def _normal_window(dialog: QDialog) -> bool:
    return (dialog.isWindow() and dialog.isVisible()
            and not dialog.isMinimized() and not dialog.isMaximized()
            and not dialog.isFullScreen())


def _fit_window_to_work_area(
    dialog: QDialog, normal_minimum: QSize, available: QRect,
) -> bool:
    """Fit a normal window using measured, device-independent rectangles."""
    work = QRect(available)
    if work.isEmpty():
        return False
    if work.width() > 4 and work.height() > 4:
        work.adjust(2, 2, -2, -2)
    frame = dialog.frameGeometry()
    decoration_width = max(0, frame.width() - dialog.width())
    decoration_height = max(0, frame.height() - dialog.height())
    budget = QSize(max(1, work.width() - decoration_width),
                   max(1, work.height() - decoration_height))
    minimum = QSize(min(normal_minimum.width(), budget.width()),
                    min(normal_minimum.height(), budget.height()))
    before = dialog.size()
    minimum_changed = dialog.minimumSize() != minimum
    if minimum_changed:
        dialog.setMinimumSize(minimum)
    target = QSize(min(dialog.width(), budget.width()),
                   min(dialog.height(), budget.height()))
    if dialog.size() != target:
        dialog.resize(target)
    resized = before != dialog.size()
    frame = dialog.frameGeometry()
    left = max(work.left(), min(frame.left(),
                               work.x() + work.width() - frame.width()))
    top = max(work.top(), min(frame.top(),
                             work.y() + work.height() - frame.height()))
    delta = QPoint(left - frame.left(), top - frame.top())
    moved = not delta.isNull()
    if moved:
        dialog.move(dialog.pos() + delta)
    return minimum_changed or resized or moved


class WindowFitController(QObject):
    """Coalesce one opted-in dialog's layout and screen changes."""

    def __init__(self, dialog: QDialog, *, scroll_content: bool = False) -> None:
        super().__init__(dialog)
        self._dialog = dialog
        self._normal_minimum = QSize(dialog.minimumSize())
        self._fitting = False
        self._window_handle = None
        self._screen = None
        self.scroll_area: QScrollArea | None = None
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self.fit_now)
        if scroll_content:
            self._wrap_content()
        dialog.installEventFilter(self)
        self._connect_window()
        self.schedule()

    def _wrap_content(self) -> None:
        if self.scroll_area is not None:
            return
        existing = self._dialog.layout()
        content = QWidget()
        if existing is not None:
            # QWidget.setLayout transfers an installed layout and reparents its
            # widgets. Keep that layout's readable minimum inside the viewport.
            content.setLayout(existing)
        scroll = QScrollArea(self._dialog)
        scroll.setObjectName("DialogWindowFitScrollArea")
        scroll.setFrameShape(QScrollArea.NoFrame)
        scroll.setWidgetResizable(True)
        scroll.setWidget(content)
        root = QVBoxLayout(self._dialog)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSizeConstraint(QLayout.SetNoConstraint)
        root.addWidget(scroll)
        self.scroll_area = scroll

    def _connect_screen(self, screen) -> None:
        if screen is self._screen:
            return
        if self._screen is not None:
            try:
                self._screen.availableGeometryChanged.disconnect(
                    self._work_area_changed)
            except (RuntimeError, TypeError):
                pass
        self._screen = screen
        if screen is not None:
            screen.availableGeometryChanged.connect(self._work_area_changed)

    def _connect_window(self) -> None:
        handle = self._dialog.windowHandle()
        if handle is not self._window_handle:
            if self._window_handle is not None:
                try:
                    self._window_handle.screenChanged.disconnect(
                        self._screen_changed)
                except (RuntimeError, TypeError):
                    pass
            self._window_handle = handle
            if handle is not None:
                handle.screenChanged.connect(self._screen_changed)
        if handle is not None:
            self._connect_screen(handle.screen())

    def _screen_changed(self, screen) -> None:
        self._connect_screen(screen)
        self.schedule()

    def _work_area_changed(self, _available: QRect) -> None:
        self.schedule()

    def schedule(self) -> None:
        """Queue at most one fit while this dialog is a visible normal window."""
        if self._fitting or not _normal_window(self._dialog):
            return
        if not self._timer.isActive():
            self._timer.start(0)

    def fit_now(self, available: QRect | None = None) -> bool:
        """Fit the outer frame, or leave hidden/window-manager states alone."""
        self._timer.stop()
        if self._fitting or not _normal_window(self._dialog):
            return False
        if available is None:
            screen = self._dialog.screen()
            if screen is None:
                return False
            available = screen.availableGeometry()
        self._fitting = True
        try:
            return _fit_window_to_work_area(
                self._dialog, self._normal_minimum, available)
        finally:
            self._fitting = False

    def eventFilter(self, watched, event) -> bool:  # noqa: N802 - Qt signature
        if watched is self._dialog:
            kind = event.type()
            if kind in (QEvent.Hide, QEvent.Close):
                self._timer.stop()
            elif kind in (QEvent.Show, QEvent.WinIdChange):
                self._connect_window()
                self.schedule()
            elif kind in (QEvent.Resize, QEvent.Move, QEvent.LayoutRequest,
                          QEvent.StyleChange, QEvent.FontChange,
                          QEvent.WindowStateChange):
                self.schedule()
        return super().eventFilter(watched, event)


def install_window_fit(
    dialog: QDialog, *, scroll_content: bool = False,
) -> WindowFitController:
    """Install once after constructing an explicitly opted-in dialog's layout."""
    controller = getattr(dialog, "_window_fit_controller", None)
    if isinstance(controller, WindowFitController):
        if scroll_content:
            controller._wrap_content()
        controller.schedule()
        return controller
    controller = WindowFitController(dialog, scroll_content=scroll_content)
    dialog._window_fit_controller = controller
    return controller
