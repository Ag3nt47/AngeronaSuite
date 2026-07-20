import os
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from angerona.core.eventbus import Event, Severity
from angerona.gui.pages import AlertsPanel


class _Storage:
    def __init__(self, events):
        self.events = list(events)
        self._revision = 1

    def revision(self):
        return self._revision

    def try_recent(self, limit):
        return self.events[:limit]

    def replace(self, events):
        self.events = list(events)
        self._revision += 1


def _event(ts):
    return Event(
        module="Test Monitor",
        message=f"event {ts}",
        severity=Severity.INFO,
        ts=float(ts),
    )


def _wait_for_rows(app, panel, minimum=1):
    deadline = time.monotonic() + 2.0
    while panel.table.rowCount() < minimum and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.01)
    app.processEvents()


def test_new_alert_stays_visible_in_default_newest_first_view():
    app = QApplication.instance() or QApplication([])
    original = [_event(ts) for ts in range(200, 80, -1)]
    storage = _Storage(original)
    panel = AlertsPanel(storage)
    panel.resize(900, 240)
    panel.show()

    panel.refresh()
    _wait_for_rows(app, panel, 120)
    bar = panel.table.verticalScrollBar()
    assert bar.maximum() > bar.minimum()
    bar.setValue(bar.maximum())

    newest = _event(201)
    storage.replace([newest, *original[:119]])
    panel.refresh()
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        app.processEvents()
        item = panel.table.item(0, 0)
        if item is not None and item.data(Qt.UserRole) is newest:
            break
        time.sleep(0.01)

    top_event = panel.table.item(0, 0).data(Qt.UserRole)
    assert top_event is newest
    assert bar.value() == bar.minimum()

    panel.close()
    panel.deleteLater()
    app.processEvents()
