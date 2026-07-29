from __future__ import annotations

import os
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QPushButton

from angerona.core.eventbus import Event, Severity
from angerona.gui import resolve_center


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


class _Bus:
    def recent(self, _limit=100):
        return []


class _Storage:
    def revision(self):
        return 1


def _events(count: int) -> list[Event]:
    now = time.time()
    return [
        Event("Load Test", f"unresolved event {index}", Severity.HIGH, now - index)
        for index in range(count)
    ]


def _center(monkeypatch, count: int):
    _app()
    events = _events(count)
    monkeypatch.setattr(resolve_center.ResolveCenter, "_events", lambda _self: events)
    monkeypatch.setattr(resolve_center.alert_ack, "acked_signatures", lambda: set())
    monkeypatch.setattr(resolve_center.alert_ack, "acked_records", lambda: [])
    return resolve_center.ResolveCenter(_Bus(), _Storage(), manager=None), events


def test_resolve_center_paginates_without_per_event_action_widgets(monkeypatch) -> None:
    center, events = _center(monkeypatch, 495)
    try:
        assert center.table.rowCount() == 25
        assert center._page_label.text() == "Page 1 / 20"
        assert center._foot.text().startswith("495 active")
        assert len(center.findChildren(QPushButton)) < 20

        center._change_page(19)
        assert center.table.rowCount() == 20
        assert center._page_label.text() == "Page 20 / 20"
        assert center._selected_event() is events[475]

        center._change_page(-1)
        assert center.table.rowCount() == 25
        assert center._page_label.text() == "Page 19 / 20"
    finally:
        center.close()


def test_resolve_center_shared_actions_follow_selection(monkeypatch) -> None:
    center, events = _center(monkeypatch, 30)
    seen = []
    try:
        center.table.selectRow(7)
        center._act_selected(seen.append)
        assert seen == [events[7]]
        assert center._detail_btn.isEnabled()

        center.table.clearSelection()
        center.table.setCurrentCell(-1, -1)
        center._sync_action_state()
        assert not center._detail_btn.isEnabled()
    finally:
        center.close()
