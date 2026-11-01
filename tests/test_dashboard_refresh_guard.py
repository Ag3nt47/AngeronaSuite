"""Gate transitions share the dashboard's exception and elapsed-time boundary."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from angerona.gui import main_window


class Clock:
    def __init__(self):
        self.now = 10.0

    def perf_counter(self):
        return self.now

    def advance(self, elapsed):
        self.now += elapsed


def harness(monkeypatch):
    clock = Clock()
    ticks, reports = [], []
    monkeypatch.setattr(main_window, "time", SimpleNamespace(perf_counter=clock.perf_counter))
    owner = SimpleNamespace(
        runtime_metrics=SimpleNamespace(record_tick=ticks.append),
        _tick_count=0,
        _blackbox_feed=reports.append,
    )
    return owner, clock, ticks, reports


def test_failed_gate_is_contained_timed_and_does_not_break_the_next_tick(monkeypatch):
    owner, clock, ticks, reports = harness(monkeypatch)
    body_calls = []

    def fail_gate():
        clock.advance(.025)
        raise RuntimeError("inert gate transition failed")

    owner._sync_ugcap_gate = fail_gate
    owner._refresh_body = lambda: body_calls.append("body")
    main_window.MainWindow._refresh(owner)
    assert owner._tick_count == 1 and not body_calls
    assert ticks == pytest.approx([25.0])
    assert reports == ["UI refresh error (non-fatal): inert gate transition failed"]

    def next_gate():
        clock.advance(.005)

    def next_body():
        body_calls.append("body")
        clock.advance(.010)

    owner._sync_ugcap_gate, owner._refresh_body = next_gate, next_body
    main_window.MainWindow._refresh(owner)
    assert owner._tick_count == 2 and body_calls == ["body"]
    assert ticks == pytest.approx([25.0, 15.0]) and len(reports) == 1


def test_gate_elapsed_time_is_included_with_the_body_in_one_measurement(monkeypatch):
    owner, clock, ticks, reports = harness(monkeypatch)
    calls = []

    def gate():
        calls.append("gate")
        clock.advance(.125)

    def body():
        calls.append("body")
        clock.advance(.250)

    owner._sync_ugcap_gate, owner._refresh_body = gate, body
    main_window.MainWindow._refresh(owner)
    assert calls == ["gate", "body"] and not reports
    assert owner._tick_count == 1 and ticks == pytest.approx([375.0])


def test_body_failure_still_has_one_timing_and_a_bounded_diagnostic(monkeypatch):
    owner, clock, ticks, reports = harness(monkeypatch)
    owner._sync_ugcap_gate = lambda: clock.advance(.030)

    def body():
        clock.advance(.020)
        raise RuntimeError("x" * 20_000)

    owner._refresh_body = body
    main_window.MainWindow._refresh(owner)
    assert owner._tick_count == 1 and ticks == pytest.approx([50.0])
    assert reports == ["UI refresh error (non-fatal): " + "x" * 512]


def test_uninstrumented_gate_failure_and_failed_diagnostic_sink_remain_contained():
    owner = SimpleNamespace(runtime_metrics=None, _tick_count=0)

    def gate():
        raise RuntimeError("inert transition failure")

    def unavailable_feed(_text):
        raise RuntimeError("inert diagnostic sink failure")

    owner._sync_ugcap_gate = gate
    owner._refresh_body = lambda: pytest.fail("body must wait for a successful gate transition")
    owner._blackbox_feed = unavailable_feed
    main_window.MainWindow._refresh(owner)
    assert owner._tick_count == 1
