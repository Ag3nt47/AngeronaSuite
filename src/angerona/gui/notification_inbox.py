"""Session-local inbox for pending dashboard prompts."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from html import escape

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtWidgets import (
    QDialog, QHBoxLayout, QLabel, QListWidget, QListWidgetItem, QPlainTextEdit,
    QPushButton, QVBoxLayout, QWidget,
)

from angerona.gui.window_controls import work_window_registry
from angerona.gui.window_fit import install_window_fit


@dataclass(frozen=True)
class _Notice:
    title: str
    description: str
    review_label: str
    review: Callable[[], None] = field(compare=False)
    dismiss: Callable[[], None] | None = field(compare=False)


class _InboxDialog(QDialog):
    def __init__(self, inbox: NotificationInbox, owner: QWidget) -> None:
        super().__init__(owner)
        self._inbox = inbox
        self._rows: dict[str, QListWidgetItem] = {}
        self.setWindowTitle("Angerona — Notifications")
        self.setModal(False)
        self.resize(620, 430)
        self.setMinimumSize(340, 260)

        layout = QVBoxLayout(self)
        self._summary = QLabel(self)
        self._summary.setAccessibleName("Notification count")
        layout.addWidget(self._summary)
        self._list = QListWidget(self)
        self._list.setAccessibleName("Pending notifications")
        layout.addWidget(self._list, 1)
        self._details = QPlainTextEdit(self)
        self._details.setReadOnly(True)
        self._details.setAccessibleName("Notification details")
        layout.addWidget(self._details, 1)

        actions = QHBoxLayout()
        self._review = QPushButton("Review", self)
        self._dismiss = QPushButton("Dismiss", self)
        close = QPushButton("Close", self)
        for button in (self._review, self._dismiss, close):
            button.setAutoDefault(False)
        actions.addWidget(self._review)
        actions.addWidget(self._dismiss)
        actions.addStretch()
        actions.addWidget(close)
        layout.addLayout(actions)

        self._list.currentItemChanged.connect(self._refresh_selection)
        self._list.itemClicked.connect(self._review_row)
        self._review.clicked.connect(self._review_selected)
        self._dismiss.clicked.connect(self._dismiss_selected)
        close.clicked.connect(self.close)
        for key, notice in inbox._entries.items():
            self.upsert_row(key, notice)
        self.refresh_count()
        self._refresh_selection()
        install_window_fit(self)

    def upsert_row(self, key: str, notice: _Notice) -> None:
        row = self._rows.get(key)
        if row is None:
            row = QListWidgetItem(notice.title)
            row.setData(Qt.UserRole, key)
            self._rows[key] = row
            self._list.addItem(row)
            if self._list.currentItem() is None:
                self._list.setCurrentItem(row)
        elif row.text() != notice.title:
            row.setText(notice.title)
        preview = notice.description[:640]
        if len(notice.description) > len(preview):
            preview += "…"
        preview = escape(preview).replace("\n", "<br>")
        hint = escape(f"Click to {notice.review_label.lower()} this notification.")
        row.setToolTip(f"<p>{preview}</p><p>{hint}</p>")
        if self._list.currentItem() is row:
            self._refresh_selection()

    def remove_row(self, key: str) -> None:
        row = self._rows.pop(key)
        selected = self._list.currentItem() is row
        self._list.takeItem(self._list.row(row))
        if selected:
            self._refresh_selection()

    def refresh_count(self) -> None:
        count = self._inbox.count
        if count == 0:
            label = "No pending notifications"
        elif count == 1:
            label = "1 pending notification"
        else:
            label = f"{count} pending notifications"
        self._summary.setText(label)
        self._summary.setAccessibleDescription(label)

    def _selected(self) -> _Notice | None:
        row = self._list.currentItem()
        if row is None or self._inbox._closed:
            return None
        return self._inbox._entries.get(row.data(Qt.UserRole))

    def _refresh_selection(self, *_args) -> None:
        notice = self._selected()
        description = notice.description if notice is not None else ""
        if self._details.toPlainText() != description:
            self._details.setPlainText(description)
        self._review.setText(notice.review_label if notice is not None else "Review")
        self._review.setEnabled(notice is not None)
        self._dismiss.setVisible(notice is not None and notice.dismiss is not None)

    def _review_row(self, row: QListWidgetItem | None) -> None:
        if row is None or self._inbox._closed:
            return
        notice = self._inbox._entries.get(row.data(Qt.UserRole))
        if notice is not None:
            notice.review()

    def _review_selected(self) -> None:
        self._review_row(self._list.currentItem())

    def _dismiss_selected(self) -> None:
        notice = self._selected()
        if notice is not None and notice.dismiss is not None:
            notice.dismiss()


class NotificationInbox(QObject):
    """Keep pending entries separate from the modeless view and their actions.

    Producers supply stable string keys and remove entries when requests are
    resolved. The inbox invokes the producer's original UI action on demand.
    """

    count_changed = Signal(int)
    _WINDOW_KEY = "notification-inbox"

    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self._owner = parent
        self._registry = work_window_registry(parent)
        self._entries: dict[str, _Notice] = {}
        self._closed = False

    @property
    def count(self) -> int:
        return len(self._entries)

    def upsert(
        self, key: str, title: str, description: str, review: Callable[[], None], *,
        review_label: str = "Review", dismiss: Callable[[], None] | None = None,
    ) -> None:
        if self._closed:
            return
        previous = self._entries.get(key)
        notice = _Notice(title, description, review_label, review, dismiss)
        self._entries[key] = notice
        if (previous is not None and previous == notice
                and (previous.dismiss is None) == (dismiss is None)):
            return
        window = self._registry.get(self._WINDOW_KEY)
        if window is not None:
            window.upsert_row(key, notice)
            if previous is None:
                window.refresh_count()
        if previous is None:
            self.count_changed.emit(self.count)

    def remove(self, key: str) -> None:
        if self._entries.pop(key, None) is None:
            return
        window = self._registry.get(self._WINDOW_KEY)
        if window is not None:
            window.remove_row(key)
            window.refresh_count()
        self.count_changed.emit(self.count)

    def show(self) -> QWidget | None:
        if self._closed:
            return None
        return self._registry.show(self._WINDOW_KEY, lambda: _InboxDialog(self, self._owner))

    def shutdown(self) -> None:
        if self._closed:
            return
        self._closed = True
        window = self._registry.get(self._WINDOW_KEY)
        if window is not None:
            window.close()
            self._registry.release(self._WINDOW_KEY)
        if self._entries:
            self._entries.clear()
            self.count_changed.emit(0)
