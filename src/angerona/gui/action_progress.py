"""Finite user-action presentation, bound to exact operation handles.

No worker, polling, authority or inferred progress lives here. Owners settle a
handle only when their existing producer/result lifecycle actually settles.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import partial

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtWidgets import QHBoxLayout, QLabel, QSizePolicy, QWidget
from shiboken6 import isValid

from angerona.gui.animations import begin_loading, finish_loading, update_loading
from angerona.gui.progress_ring import ProgressRing


@dataclass(frozen=True)
class ActionHandle:
    key: str
    serial: int
    token: str


def _retire(entries, *_args):
    # Retain plain Python state only; destruction must never call deleted Qt.
    for value in tuple(entries.values()):
        try:
            if value.get("publish_global", True):
                finish_loading(value["handle"].token)
        except RuntimeError:
            pass  # Qt's global signal bus may already be gone at app teardown.
    entries.clear()


class ActionActivities(QObject):
    changed = Signal(dict)

    def __init__(self, owner, *, publish_global=True):
        super().__init__(owner)
        self._publish_global = publish_global
        self._entries = {}
        self._serial = 0
        self.destroyed.connect(partial(_retire, self._entries))

    def begin(self, key, label, *, done=0, total=0, replace=False):
        """Coalesce one action key unless a new admitted generation replaces it."""
        existing = self._entries.get(key)
        if existing is not None and not replace:
            return existing["handle"]
        if existing is not None:
            if existing["publish_global"]:
                finish_loading(existing["handle"].token)
        self._serial += 1
        token = begin_loading(label, done=done, total=total) if self._publish_global else ""
        handle = ActionHandle(key, self._serial, token)
        self._entries[key] = dict(handle=handle, label=str(label)[:240], done=done, total=total,
                                  publish_global=self._publish_global)
        self._emit()
        return handle

    def update(self, handle, *, label=None, done=None, total=None):
        value = self._entries.get(handle.key) if isinstance(handle, ActionHandle) else None
        if value is None or value["handle"] != handle:
            return False
        if label is not None:
            value["label"] = str(label)[:240]
        if done is not None:
            value["done"] = done
        if total is not None:
            value["total"] = total
        if value["publish_global"]:
            update_loading(handle.token, value["label"], done=value["done"], total=value["total"])
        self._emit()
        return True

    def finish(self, handle):
        value = self._entries.get(handle.key) if isinstance(handle, ActionHandle) else None
        if value is None or value["handle"] != handle:
            return False
        self._entries.pop(handle.key)
        if value["publish_global"]:
            finish_loading(handle.token)
        self._emit()
        return True

    def close(self):
        _retire(self._entries)
        self._emit()

    def snapshot(self):
        if not self._entries:
            return {}
        value = max(self._entries.values(), key=lambda item: item["handle"].serial)
        return dict(label=value["label"], done=value["done"], total=value["total"],
                    active_count=len(self._entries), serial=value["handle"].serial)

    def _emit(self):
        # A retained Python owner may close after Qt deleted this child.
        # Plain entries still retire; never emit through a deleted native source.
        if isValid(self):
            self.changed.emit(self.snapshot())


class ActionProgressView(QWidget):
    """A compact local wheel; existing result labels retain terminal outcomes."""

    def __init__(self, activities, parent=None, *, config=None):
        super().__init__(parent)
        self.activities = activities
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        self.ring = ProgressRing(config, self, diameter=34, scope="action")
        self.caption = QLabel()
        self.caption.setTextFormat(Qt.TextFormat.PlainText)
        self.caption.setWordWrap(True)
        self.caption.setMinimumWidth(0)
        # A wrapped label's content hint must not force a scroll page wider
        # than its viewport. Let Qt allocate the available width and then
        # request the corresponding height; preserve the full text and font.
        policy = self.caption.sizePolicy()
        policy.setHorizontalPolicy(QSizePolicy.Policy.Ignored)
        policy.setHeightForWidth(True)
        self.caption.setSizePolicy(policy)
        row.addWidget(self.ring)
        row.addWidget(self.caption, 1)
        self.setMinimumWidth(0)
        activities.changed.connect(self._apply)
        self._apply(activities.snapshot())

    def _apply(self, value):
        if value:
            self.ring.set_state(value["done"], value["total"], True)
            suffix = f" · {value['active_count']} actions active" if value["active_count"] > 1 else ""
            self.caption.setText(value["label"] + suffix)
        else:
            self.ring.set_state(0, 0, False)
            self.caption.clear()
        self.setVisible(bool(value))
