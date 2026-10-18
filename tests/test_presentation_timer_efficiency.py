"""Native Qt wakeup, pressure and lifecycle evidence for presentation refreshes."""
from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import pytest
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QVBoxLayout, QWidget

from angerona.gui import presentation_timer
from angerona.gui.animations import (
    ClashingSwords, MicMeter, SharkSwimBanner, SharkSwimIndicator, _SpinRing,
)
from angerona.gui.dashboard_details import ModuleResourceDialog
from angerona.gui.async_snapshot import AsyncSnapshot
from angerona.gui.presentation_timer import PresentationTimer


def process():
    QApplication.instance().processEvents()


def test_hidden_minimized_and_explicitly_stopped_refreshes_have_zero_wakeups():
    window = QWidget()
    child = QWidget(window)
    QVBoxLayout(window).addWidget(child)
    timer = PresentationTimer(child, pressure_sensitive=False)
    callbacks = []
    timer.timeout.connect(lambda: callbacks.append(1))
    timer.start(20)
    try:
        QTest.qWait(120)
        assert not timer.isActive() and callbacks == []
        window.show()
        process()
        QTest.qWait(160)
        assert timer.isActive() and len(callbacks) >= 3

        for suspend, resume in (
            (child.hide, child.show),
            (window.showMinimized, window.showNormal),
            (window.hide, window.show),
        ):
            suspend()
            process()
            assert not timer.isActive()
            before = len(callbacks)
            QTest.qWait(120)
            assert len(callbacks) == before
            resume()
            process()
            assert timer.isActive()
            QTest.qWait(100)
            assert len(callbacks) > before

        timer.stop()
        window.hide()
        window.show()
        process()
        assert not timer.isActive()
    finally:
        window.close()
        window.deleteLater()


def test_visible_pressure_reduces_refresh_rate_and_recovers_original_interval(monkeypatch):
    factor = [1]
    controller = SimpleNamespace(interval=lambda base: min(base * factor[0], base + 30.0))
    monkeypatch.setattr(presentation_timer, "get_pacing_controller", lambda: controller)
    window = QWidget()
    window.show()
    timer = PresentationTimer(window)
    try:
        timer.start(40)
        assert timer.interval() == 40
        factor[0] = 8
        timer._next_pressure_sample = 0.0
        timer._sync()
        assert timer.interval() == 320  # 25 requested refreshes/s -> 3.125/s
        timer.setInterval(8000)
        assert timer.interval() == 38000  # routine interval adds at most 30s
        factor[0] = 1
        timer._next_pressure_sample = 0.0
        timer._sync()
        assert timer.interval() == 8000
    finally:
        timer.stop()
        window.close()
        window.deleteLater()


def test_single_shot_waits_for_visibility_then_never_restarts_on_reopen():
    window = QWidget()
    timer = PresentationTimer(window, pressure_sensitive=False)
    timer.setSingleShot(True)
    callbacks = []
    timer.timeout.connect(lambda: callbacks.append(1))
    timer.start(20)
    try:
        QTest.qWait(60)
        assert callbacks == []
        window.show()
        QTest.qWait(80)
        assert callbacks == [1] and not timer.isActive()
        window.hide()
        window.show()
        QTest.qWait(80)
        assert callbacks == [1] and not timer.isActive()
    finally:
        window.close()
        window.deleteLater()


def test_reparented_view_watches_its_new_window():
    first, second = QWidget(), QWidget()
    child = QWidget(first)
    timer = PresentationTimer(child, pressure_sensitive=False)
    first.show()
    second.show()
    timer.start(20)
    try:
        assert timer.isActive()
        child.setParent(second)
        child.show()
        process()
        first.showMinimized()
        process()
        assert timer.isActive()
        second.showMinimized()
        process()
        assert not timer.isActive()
        second.showNormal()
        process()
        assert timer.isActive()
    finally:
        timer.stop()
        first.close()
        second.close()
        first.deleteLater()
        second.deleteLater()


def test_rejected_window_close_does_not_suspend_a_still_visible_view():
    class RetainedWindow(QWidget):
        def closeEvent(self, event):  # noqa: N802 - Qt signature
            event.ignore()

    window = RetainedWindow()
    timer = PresentationTimer(window, pressure_sensitive=False)
    window.show()
    timer.start(20)
    try:
        assert not window.close()
        assert window.isVisible() and timer.isActive()
    finally:
        timer.stop()
        window.hide()
        window.deleteLater()


@pytest.mark.parametrize("kind", [_SpinRing, MicMeter, SharkSwimIndicator, SharkSwimBanner,
                                 ClashingSwords])
def test_continuous_indicators_suspend_with_their_window_and_completed_state(kind):
    window = QWidget()
    indicator = kind(window)
    window.show()
    if kind in (MicMeter, ClashingSwords):
        indicator.set_active(True)
    else:
        indicator.start()
    process()
    try:
        assert indicator._timer.isActive()
        window.hide()
        process()
        assert not indicator._timer.isActive()
        window.show()
        process()
        assert indicator._timer.isActive()
        if kind in (MicMeter, ClashingSwords):
            indicator.set_active(False)
        else:
            indicator.stop()
        window.hide()
        window.show()
        process()
        assert not indicator._timer.isActive()
    finally:
        window.close()
        window.deleteLater()


def test_static_swords_never_schedule_an_idle_timer():
    window = QWidget()
    swords = ClashingSwords(window)
    window.show()
    try:
        process()
        assert not swords._timer.isActive()
    finally:
        window.close()
        window.deleteLater()


def test_hidden_module_resource_window_does_no_periodic_snapshot_work():
    calls = []

    def snapshot(name):
        calls.append(name)
        return {"intensity": 5, "health": 100, "status": "running", "events": []}

    dialog = ModuleResourceDialog("Fixture", snapshot)
    # This case measures visibility; pressure cadence has its own fake above.
    dialog._timer._pressure_sensitive = False
    dialog._timer.setInterval(20)
    try:
        initial = len(calls)
        QTest.qWait(100)
        assert len(calls) == initial
        dialog.show()
        QTest.qWait(120)
        assert len(calls) > initial
        dialog.hide()
        process()
        paused = len(calls)
        QTest.qWait(100)
        assert len(calls) == paused
    finally:
        dialog.close()


def test_slow_snapshot_polling_backs_off_then_resets_for_the_next_read():
    owner = QWidget()
    entered, release = threading.Event(), threading.Event()
    values = []

    def read():
        entered.set()
        assert release.wait(3)
        return 7

    reader = AsyncSnapshot(owner, lambda: read, values.append, name="SlowPollEvidence")
    try:
        reader.request()
        assert entered.wait(1)
        assert reader._timer.interval() == 40
        intervals = []
        for _ in range(6):
            reader._poll()
            intervals.append(reader._timer.interval())
        assert intervals == [80, 160, 250, 250, 250, 250]
        release.set()
        deadline = time.monotonic() + 2
        while reader.busy and time.monotonic() < deadline:
            reader._poll()
            time.sleep(0.001)
        assert values == [7] and not reader._timer.isActive()
        reader.request()
        assert reader._timer.interval() == 40
    finally:
        release.set()
        reader.close()
        if reader.thread is not None:
            reader.thread.join(2)
        owner.deleteLater()
