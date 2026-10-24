"""Real Qt ribbon churn, yielding, binding and owned-timer retirement."""
from __future__ import annotations

import threading
import time
from types import SimpleNamespace

from PySide6.QtCore import QCoreApplication, QEvent, QObject, Qt, QTimer
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication
from shiboken6 import isValid

from angerona.gui import pages


def owner(names):
    return SimpleNamespace(modules={name: SimpleNamespace(
        name=name, CODE=name[:5], status="running", health_state="ok",
        health=90, health_note="Inert fixture",
    ) for name in names}, is_enabled=lambda _name: True)


def bus():
    return SimpleNamespace(recent=lambda _limit: [])


def drain(strip):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        QApplication.processEvents()
        if (getattr(strip, "_chip_reconcile_job", None) is None
                and set(strip._chips) == set(strip.manager.modules)):
            return
        time.sleep(0.001)
    raise AssertionError("The bounded ribbon did not settle to the latest module names")


def dispose(strip):
    strip.close()
    # Drain the original implementation's queued singleShot while its native
    # widgets are still alive; otherwise baseline cases contaminate each other.
    QApplication.processEvents()
    strip.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)


class StyleEvents(QObject):
    def __init__(self, chip):
        super().__init__(chip)
        self.count = 0
        chip.installEventFilter(self)

    def eventFilter(self, _watched, event):
        if event.type() == QEvent.StyleChange:
            self.count += 1
        return False


def test_loader_growth_retains_widget_focus_and_unchanged_style_cache():
    manager = owner(["Alpha"])
    strip = pages.ResourceStrip(manager, bus())
    strip.refresh()
    strip.show()
    drain(strip)
    retained = strip._chips["Alpha"]
    retained.setFocus()
    QApplication.processEvents()
    observer = StyleEvents(retained)
    try:
        manager.modules.update(owner(["Beta"]).modules)
        strip.refresh()
        drain(strip)
        assert strip._chips["Alpha"] is retained
        assert observer.count == 0
        assert QApplication.focusWidget() is retained
        assert [strip._lay.itemAt(i).widget()._name for i in range(strip._lay.count())] == ["Alpha", "Beta"]
        assert all(chip.text().endswith("\n16%") for chip in strip._chips.values())
    finally:
        dispose(strip)


def test_bulk_resource_widgets_yield_before_completion_and_stay_on_qt(monkeypatch):
    original = pages._ClickableChip
    created = []
    gui = threading.get_ident()

    class TrackedChip(original):
        def __init__(self, name):
            created.append((name, threading.get_ident()))
            super().__init__(name)

    monkeypatch.setattr(pages, "_ClickableChip", TrackedChip)
    manager = owner([f"Sensor {index:03}" for index in range(73)])
    strip = pages.ResourceStrip(manager, bus())
    heartbeat = []
    try:
        assert 1 <= len(created) <= 8
        QTimer.singleShot(0, lambda: heartbeat.append(len(created)))
        drain(strip)
        assert heartbeat and heartbeat[0] < 73
        assert len(created) == 73 and {thread for _name, thread in created} == {gui}
        assert [strip._lay.itemAt(i).widget()._name for i in range(73)] == sorted(manager.modules)
        assert len({id(chip) for chip in strip._chips.values()}) == 73
    finally:
        dispose(strip)


def test_pending_target_replacement_retains_original_and_discards_obsolete_chips():
    manager = owner(["Alpha"])
    strip = pages.ResourceStrip(manager, bus())
    strip.refresh()
    drain(strip)
    retained = strip._chips["Alpha"]
    try:
        manager.modules.update(owner([f"Obsolete {i:03}" for i in range(73)]).modules)
        strip.refresh()
        stale_chips = [chip for name, chip in strip._chips.items() if name != "Alpha"]
        manager.modules = {"Alpha": manager.modules["Alpha"], **owner(["Beta", "Zulu"]).modules}
        strip.refresh()
        drain(strip)
        assert strip._chips["Alpha"] is retained
        assert list(strip._chips) == ["Alpha", "Beta", "Zulu"]
        assert all(chip.text().endswith("\n16%") for chip in strip._chips.values())
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        assert stale_chips and all(not isValid(chip) for chip in stale_chips)
    finally:
        dispose(strip)


def test_name_bound_keyboard_actions_survive_insert_remove_and_sort(monkeypatch):
    opened = []
    monkeypatch.setattr(pages.ResourceStrip, "_open_resource", lambda _self, name: opened.append(name))
    manager = owner(["Alpha", "Epsilon", "Zulu"])
    strip = pages.ResourceStrip(manager, bus())
    strip.refresh()
    drain(strip)
    retained = strip._chips["Zulu"]
    try:
        manager.modules.pop("Alpha")
        manager.modules.update(owner(["Beta"]).modules)
        strip.refresh()
        drain(strip)
        assert strip._chips["Zulu"] is retained
        for index in range(strip._lay.count()):
            chip = strip._lay.itemAt(index).widget()
            QTest.keyClick(chip, Qt.Key_Return)
        assert opened == ["Beta", "Epsilon", "Zulu"]
    finally:
        dispose(strip)


def test_close_cancels_resource_churn_and_dimension_timers(monkeypatch):
    manager = owner([f"Sensor {index:03}" for index in range(73)])
    strip = pages.ResourceStrip(manager, bus())
    dimension_calls = []
    monkeypatch.setattr(strip, "_update_dimensions", lambda: dimension_calls.append(True))
    try:
        assert len(strip._chips) < 73
        strip._queue_dimensions()
        strip.close()
        count = len(strip._chips)
        QTest.qWait(5)
        assert len(strip._chips) == count and dimension_calls == []
        assert strip._chip_reconcile_job is None
        assert not strip._chip_reconcile_timer.isActive()
        assert not strip._dimensions_timer.isActive()
    finally:
        dispose(strip)


def test_repeated_font_style_requests_keep_one_full_resize(monkeypatch):
    strip = pages.ResourceStrip(owner(["Alpha", "Beta"]), bus())
    strip.refresh()
    drain(strip)
    QApplication.processEvents()
    calls = []
    update = strip._update_dimensions
    monkeypatch.setattr(strip, "_update_dimensions", lambda: (calls.append(True), update()))
    try:
        for _ in range(10):
            strip._queue_dimensions()
        QApplication.processEvents()
        assert calls == [True]
        for chip in strip._chips.values():
            metrics = chip.fontMetrics()
            assert chip.width() >= max(metrics.horizontalAdvance(line) for line in chip.text().splitlines()) + 12
    finally:
        dispose(strip)
