from __future__ import annotations

import os
import queue

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from angerona.core.eventbus import Event, EventBus, Severity
from angerona.core.module_base import BaseModule
from angerona.core.storage import _BoundedSimpleQueue
from angerona.gui.pages import ModuleInspector, _capability_summary


class _ProbeModule(BaseModule):
    name = "Performance Probe"
    description = "Exercises revision-gated inspector refreshes."
    category = "General"

    def run(self) -> None:
        return None


class _Manager:
    modules: dict = {}

    @staticmethod
    def is_enabled(_name: str) -> bool:
        return True

    @staticmethod
    def set_enabled(_name: str, _enabled: bool) -> None:
        return None


class _CountingBus(EventBus):
    def __init__(self) -> None:
        super().__init__()
        self.recent_calls: list[int] = []

    def recent(self, limit: int = 100):
        self.recent_calls.append(limit)
        return super().recent(limit)


def test_module_inspector_reuses_one_revision_gated_event_snapshot(
    monkeypatch,
) -> None:
    app = QApplication.instance() or QApplication([])
    bus = _CountingBus()
    module = _ProbeModule()
    bus.publish(Event(module.name, "initial", Severity.HIGH, ts=1.0))
    inspector = ModuleInspector(_Manager(), bus, module)
    inspector._timer.stop()
    try:
        assert bus.recent_calls == [1000]
        rebuilt: list[int] = []
        original = inspector.feed.setRowCount

        def counted(rows: int) -> None:
            rebuilt.append(rows)
            original(rows)

        monkeypatch.setattr(inspector.feed, "setRowCount", counted)
        inspector._refresh()
        inspector._refresh()

        assert bus.recent_calls == [1000]
        assert rebuilt == []

        # An unrelated event refreshes the shared snapshot but does not rebuild
        # this module's table. A relevant event rebuilds it exactly once.
        bus.publish(Event("Other", "unrelated", Severity.INFO, ts=2.0))
        inspector._refresh()
        assert bus.recent_calls == [1000, 1000]
        assert rebuilt == []

        bus.publish(Event(module.name, "new", Severity.MEDIUM, ts=3.0))
        inspector._refresh()
        assert bus.recent_calls == [1000, 1000, 1000]
        assert rebuilt == [0]
        assert inspector.feed.rowCount() == 2
    finally:
        inspector.close()
        app.processEvents()


def test_live_capability_summary_does_not_request_recursive_export_copy() -> None:
    class Contract:
        capability_id = "angerona.test.performance"
        description = "bounded"
        implementation_version = "1.1.0"
        maturity = "stable"
        metadata_gaps = ()
        metadata_level = "native"
        mode = "detect"
        response_authority = "none"
        supported_platforms = ("windows",)

        @staticmethod
        def as_dict() -> dict:
            raise AssertionError("live summary must not recursively copy the contract")

    module = type("Module", (), {"_angerona_contract": Contract()})()

    assert _capability_summary(module) == {
        "capability_id": "angerona.test.performance",
        "description": "bounded",
        "implementation_version": "1.1.0",
        "maturity": "stable",
        "metadata_gaps": (),
        "metadata_level": "native",
        "mode": "detect",
        "response_authority": "none",
        "supported_platforms": ("windows",),
    }


def test_bounded_simple_queue_releases_capacity_after_failed_handoff() -> None:
    lane = _BoundedSimpleQueue(1)

    class FailingQueue:
        @staticmethod
        def put(_event) -> None:
            raise MemoryError("injected allocation failure")

    lane._queue = FailingQueue()  # type: ignore[assignment]
    with pytest.raises(MemoryError, match="injected"):
        lane.put_nowait(Event("test", "failed"))

    lane._queue = queue.SimpleQueue()
    event = Event("test", "accepted")
    lane.put_nowait(event)
    with pytest.raises(queue.Full):
        lane.put_nowait(Event("test", "full"))
    assert lane.get_nowait() is event
