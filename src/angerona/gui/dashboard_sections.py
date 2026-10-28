"""Compact dashboard disclosures that keep their underlying views alive."""
from __future__ import annotations

from PySide6.QtCore import QEvent, QObject, Qt, Signal
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QLayout, QScrollArea, QSizePolicy, QToolButton, QVBoxLayout, QWidget,
)


class _DisclosureButton(QToolButton):
    def keyPressEvent(self, event) -> None:  # noqa: N802 - Qt signature
        if event.key() in (Qt.Key_Return, Qt.Key_Enter):
            self.click()
            event.accept()
            return
        super().keyPressEvent(event)


class DashboardDisclosure(QWidget):
    """One short summary row; explicit expansion reveals the original widget.

    Collapse only changes presentation. It does not discard records, disable
    sensors or stop background samplers. A fixed collapsed height prevents an
    old splitter allocation from leaving an empty, oversized panel behind.
    """

    expanded_changed = Signal(bool)

    def __init__(self, title: str, content: QWidget, summary: str = "", parent=None,
                 *, expanded: bool = False) -> None:
        super().__init__(parent)
        self.setObjectName("DashboardDisclosure")
        self._title = title
        self._expanded = bool(expanded)
        self._summary_text = summary
        self._summary_level = "normal"
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        self._heading = QWidget(self)
        row = QHBoxLayout(self._heading)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(10)
        self.toggle = _DisclosureButton(self._heading)
        self.toggle.setObjectName("DashboardDisclosureToggle")
        self.toggle.setText(title)
        self.toggle.setCheckable(True)
        self.toggle.setFocusPolicy(Qt.StrongFocus)
        self.toggle.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self.toggle.setSizePolicy(QSizePolicy.Minimum, QSizePolicy.Fixed)
        self.toggle.setStyleSheet(
            "QToolButton {border:1px solid #334155; border-radius:6px;"
            "padding:5px 8px; font-weight:600; background:transparent;}"
            "QToolButton:hover, QToolButton:focus {border-color:#38bdf8;}"
        )
        self.toggle.toggled.connect(self.set_expanded)
        row.addWidget(self.toggle)
        self._summary = QLabel(self._heading)
        self._summary.setMinimumWidth(0)
        self._summary.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        self._summary.installEventFilter(self)
        row.addWidget(self._summary, 1)
        layout.addWidget(self._heading)
        self.content = content
        layout.addWidget(content, 1)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)
        self._sync_presentation()

    def is_expanded(self) -> bool:
        return self._expanded

    def set_summary(self, text: str, *, warning: bool = False, critical: bool = False) -> None:
        level = "critical" if critical else "warning" if warning else "normal"
        if level != self._summary_level:
            self._summary_level = level
            self._summary.setStyleSheet(
                "color:#ef4444;font-weight:600;" if critical else
                "color:#f59e0b;" if warning else "")
        if text != self._summary_text:
            self._summary_text = text
            self._fit_summary()

    def set_expanded(self, expanded: bool) -> None:
        expanded = bool(expanded)
        if self._expanded == expanded:
            return
        self._expanded = expanded
        self._sync_presentation()
        self.expanded_changed.emit(expanded)

    def collapsed_height(self) -> int:
        return max(self.toggle.sizeHint().height(), self._heading.sizeHint().height())

    def _sync_presentation(self) -> None:
        if self.toggle.isChecked() != self._expanded:
            self.toggle.setChecked(self._expanded)
        self.toggle.setArrowType(Qt.DownArrow if self._expanded else Qt.RightArrow)
        action = "Collapse" if self._expanded else "Expand"
        self.toggle.setToolTip(f"{action} {self._title.lower()} details")
        self.toggle.setAccessibleName(f"{self._title}: {action.lower()} details")
        self.content.setVisible(self._expanded)
        self.setSizePolicy(QSizePolicy.Expanding,
                           QSizePolicy.Preferred if self._expanded else QSizePolicy.Maximum)
        self.setMaximumHeight(16_777_215 if self._expanded else self.collapsed_height())
        self._fit_summary()
        self.updateGeometry()

    def _fit_summary(self) -> None:
        self._summary.setText(self._summary.fontMetrics().elidedText(
            self._summary_text, Qt.ElideRight, max(0, self._summary.contentsRect().width())))
        self._summary.setToolTip(self._summary_text)
        self._summary.setAccessibleName(self._summary_text)

    def resizeEvent(self, event) -> None:  # noqa: N802 - Qt signature
        super().resizeEvent(event)
        self._fit_summary()

    def eventFilter(self, watched, event):  # noqa: N802 - Qt signature
        if watched is getattr(self, "_summary", None) and event.type() in (QEvent.Resize, QEvent.FontChange):
            self._fit_summary()
        return super().eventFilter(watched, event)

    def changeEvent(self, event) -> None:  # noqa: N802 - Qt signature
        super().changeEvent(event)
        if event.type() in (QEvent.FontChange, QEvent.StyleChange) and hasattr(self, "toggle"):
            self._sync_presentation()


class DashboardPanelCollapse(QObject):
    """Minimize an existing panel body without adding another title row.

    Original widgets, signal connections and explicit child visibility survive
    the move. Hiding their common parent cannot undo a producer's later show/hide
    decision or pause collection. Scrollable bodies keep their readable natural
    content height while the dashboard row itself can fit a short display.
    """

    collapsed_changed = Signal(bool)

    def __init__(self, panel: QWidget, title: str, *, scroll_body: bool = False) -> None:
        super().__init__(panel)
        root = panel.layout()
        if not isinstance(root, QVBoxLayout) or root.count() < 2:
            raise ValueError("Dashboard minimization needs a heading and a body")
        self.panel = panel
        self.title = title
        self._collapsed = False
        self._original_maximum = panel.maximumHeight()
        margins = root.contentsMargins()
        root.setContentsMargins(margins.left(), 6, margins.right(), 6)
        root.setSpacing(4)
        first = root.itemAt(0)
        header = first.layout()
        if header is None:
            heading = first.widget()
            if heading is None:
                raise ValueError("Dashboard panel heading is unavailable")
            root.takeAt(0)
            header = QHBoxLayout()
            header.setContentsMargins(0, 0, 0, 0)
            header.addWidget(heading, 1)
            root.insertLayout(0, header)
        self.header = header
        self._minimize_button = _DisclosureButton(panel)
        self._minimize_button.setCheckable(True)
        self._minimize_button.setFocusPolicy(Qt.StrongFocus)
        self._minimize_button.setObjectName("DashboardPanelMinimize")
        self._minimize_button.setStyleSheet(
            "QToolButton {border:1px solid #334155;border-radius:4px;"
            "padding:0px 4px;font-weight:700;background:transparent;}"
            "QToolButton:hover,QToolButton:focus {border-color:#38bdf8;}"
        )
        self._minimize_button.toggled.connect(self.set_collapsed)
        header.addWidget(self._minimize_button)
        self.body = QWidget(panel)
        body_layout = QVBoxLayout(self.body)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(4)
        while root.count() > 1:
            stretch = root.stretch(1)
            item = root.takeAt(1)
            saved_visibility = self._widget_visibility(item)
            if item.widget() is not None:
                body_layout.addWidget(item.widget(), stretch, item.alignment())
            elif item.layout() is not None:
                nested = item.layout()
                nested.setParent(None)
                body_layout.addLayout(nested, stretch)
            else:
                body_layout.addItem(item)
            for widget, hidden in saved_visibility:
                widget.setVisible(not hidden)
        if scroll_body:
            viewport = QScrollArea(panel)
            viewport.setFrameShape(QFrame.NoFrame)
            viewport.setWidgetResizable(True)
            viewport.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
            viewport.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
            viewport.setMinimumSize(0, 48)
            viewport.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Ignored)
            viewport.setWidget(self.body)
            self.view = viewport
        else:
            body_layout.setSizeConstraint(QLayout.SetNoConstraint)
            self.view = self.body
            self.view.setMinimumHeight(64)
            self.view.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Ignored)
        root.addWidget(self.view, 1)
        panel._minimize_button = self._minimize_button
        panel._collapse_control = self
        self.panel.installEventFilter(self)
        self._sync_presentation()

    @staticmethod
    def _widget_visibility(item):
        widget, layout = item.widget(), item.layout()
        if widget is not None:
            return [(widget, widget.isHidden())]
        result = []
        if layout is not None:
            for index in range(layout.count()):
                result.extend(DashboardPanelCollapse._widget_visibility(layout.itemAt(index)))
        return result

    def is_collapsed(self) -> bool:
        return self._collapsed

    def set_collapsed(self, collapsed: bool) -> None:
        collapsed = bool(collapsed)
        if collapsed == self._collapsed:
            return
        self._collapsed = collapsed
        self._sync_presentation()
        self.collapsed_changed.emit(collapsed)

    def collapsed_height(self) -> int:
        margins = self.panel.layout().contentsMargins()
        return self.header.minimumSize().height() + margins.top() + margins.bottom()

    def _sync_presentation(self) -> None:
        button = self._minimize_button
        if button.isChecked() != self._collapsed:
            button.setChecked(self._collapsed)
        button.setText("+" if self._collapsed else "−")
        action = "Restore" if self._collapsed else "Minimize"
        button.setToolTip(f"{action} {self.title}")
        button.setAccessibleName(f"{action} {self.title}")
        extent = max(22, button.fontMetrics().height() + 6)
        button.setFixedSize(extent, extent)
        self.view.setVisible(not self._collapsed)
        self.panel.setMinimumHeight(0 if self._collapsed else self.collapsed_height() + 48)
        self.panel.setMaximumHeight(self.collapsed_height() if self._collapsed else self._original_maximum)
        self.panel.updateGeometry()

    def eventFilter(self, watched, event):  # noqa: N802 - Qt signature
        if watched is self.panel and event.type() in (QEvent.FontChange, QEvent.StyleChange):
            self._sync_presentation()
        return super().eventFilter(watched, event)


class DashboardPanelGroup(QObject):
    """Programmatic group adapter; users use each existing panel's own button.

    This adds no duplicate title bar or hidden parent. Even when every body is
    minimized, all original headings and their restore buttons remain visible.
    """

    expanded_changed = Signal(bool)

    def __init__(self, content: QWidget, controls: list[DashboardPanelCollapse]) -> None:
        super().__init__(content)
        self.content = content
        self.controls = tuple(controls)
        self._last_expanded = self.is_expanded()
        for control in self.controls:
            control.collapsed_changed.connect(self._changed)

    def is_expanded(self) -> bool:
        return any(not control.is_collapsed() for control in self.controls)

    def set_expanded(self, expanded: bool) -> None:
        for control in self.controls:
            control.set_collapsed(not expanded)

    def _changed(self, _collapsed: bool) -> None:
        expanded = self.is_expanded()
        if expanded != self._last_expanded:
            self._last_expanded = expanded
            self.expanded_changed.emit(expanded)

    def collapsed_height(self) -> int:
        heights = [control.collapsed_height() for control in self.controls]
        if getattr(self.content, "orientation", lambda: Qt.Horizontal)() == Qt.Vertical:
            return sum(heights) + max(0, len(heights) - 1) * self.content.handleWidth()
        return max(heights, default=0)

    def minimumSizeHint(self):  # noqa: N802 - Qt signature adapter
        return self.content.minimumSizeHint()
