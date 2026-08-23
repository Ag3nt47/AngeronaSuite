"""Focused regression coverage for low-idle GUI presentation policy."""
from __future__ import annotations

import os
import threading
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

from angerona.core.eventbus import Event, Severity
from angerona.gui.aria_hud import AriaHud
from angerona.gui.main_window import MainWindow, _dashboard_refresh_plan
from angerona.resilience.status_ui import _monitor_refresh_interval_ms


_APP_ANCHOR: QApplication | None = None


def _app() -> QApplication:
    global _APP_ANCHOR
    _APP_ANCHOR = QApplication.instance() or QApplication([])
    return _APP_ANCHOR


def test_dashboard_chill_plan_reduces_idle_wakes_but_preserves_elapsed_cadence() -> None:
    full = _dashboard_refresh_plan(False, visible=True, active=True)
    chill = _dashboard_refresh_plan(True, visible=True, active=True)
    background = _dashboard_refresh_plan(True, visible=False, active=False)

    assert full == (1_000, 1, 2, 4, 12)
    assert chill == (5_000, 2, 2, 4, 12)
    assert background == (15_000, 2, 4, 4, 4)
    # Panel/posture/flow work retains its intended wall-clock cadence even
    # though the presentation timer itself wakes five times less in Chill.
    assert chill[0] * chill[2] == 10_000
    assert chill[0] * chill[3] == 20_000
    assert chill[0] * chill[4] == 60_000


def test_high_priority_wake_is_coalesced_and_info_does_not_wake() -> None:
    class _Signal:
        def __init__(self) -> None:
            self.emissions = 0

        def emit(self) -> None:
            self.emissions += 1

    calls: list[str] = []
    harness = SimpleNamespace(
        _security_wake_pending=threading.Event(),
        _security_event_wake=_Signal(),
        _check_threat_animation=lambda: calls.append("checked"),
    )
    MainWindow._queue_security_event_wake(
        harness, Event("Telemetry", "routine", Severity.INFO)
    )
    MainWindow._queue_security_event_wake(
        harness, Event("Network", "active evidence", Severity.HIGH)
    )
    MainWindow._queue_security_event_wake(
        harness, Event("Network", "same burst", Severity.CRITICAL)
    )
    assert harness._security_event_wake.emissions == 1
    assert harness._security_wake_pending.is_set()

    MainWindow._handle_security_event_wake(harness)
    assert calls == ["checked"]
    assert not harness._security_wake_pending.is_set()


def test_aria_orb_stops_all_animation_callbacks_in_idle_mode() -> None:
    app = _app()
    hud = AriaHud(score_fn=lambda: 100, compact=True)
    hud.show()
    app.processEvents()

    # Make window-manager activation deterministic under the offscreen backend.
    hud._orb._animation_allowed = lambda: not hud._orb._idle_mode
    callbacks = 0

    def _count() -> None:
        nonlocal callbacks
        callbacks += 1

    hud._orb._timer.timeout.connect(_count)
    hud.set_idle_mode(False)
    QTest.qWait(330)
    assert callbacks >= 2

    hud.set_idle_mode(True)
    at_idle = callbacks
    QTest.qWait(330)
    assert callbacks == at_idle
    assert not hud._orb._timer.isActive()
    hud.close()


def test_minimized_monitor_window_uses_slow_presentation_cadence() -> None:
    assert _monitor_refresh_interval_ms(
        visible=True, minimized=False, active=True
    ) == 1_000
    assert _monitor_refresh_interval_ms(
        visible=True, minimized=True, active=False
    ) == 10_000
    assert _monitor_refresh_interval_ms(
        visible=False, minimized=False, active=False
    ) == 10_000
