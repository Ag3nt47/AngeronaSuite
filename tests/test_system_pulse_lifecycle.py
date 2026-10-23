"""Plain collector ownership and GUI-only delivery without host collection."""
from __future__ import annotations

import ast
from pathlib import Path
import sys
import threading
import time
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, QObject, QTimer
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QVBoxLayout, QWidget
from shiboken6 import isValid

from angerona.gui import system_pulse
from angerona.gui.system_pulse import (
    SystemPulseCard, _SystemPulseCollector, _SystemPulseSampler,
)


def _wait_for(predicate, timeout=1.0):
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, "Owned sampler state did not settle"
        threading.Event().wait(0.001)


def _retire(state):
    state.close()
    if state.thread.ident is not None:
        state.thread.join(1.0)
    assert not state.thread.is_alive()


@pytest.fixture
def fake_cards(monkeypatch):
    """All real Qt-card construction here uses an inert plain provider."""
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(_SystemPulseCollector, "__call__", lambda _self: {
        "cpu": 12.0, "ram": 34.0, "available": 1024.0,
        "wifi": 55, "down": 6.0, "up": 7.0,
    })
    owners = []

    def make():
        parent = QWidget()
        card = SystemPulseCard(parent)
        QVBoxLayout(parent).addWidget(card)
        parent.show()
        card._timer.stop()
        owners.append((parent, card, card._sampler))
        return parent, card, card._sampler

    yield app, make
    for parent, card, state in owners:
        if isValid(card):
            card.shutdown()
        else:
            state.close()
        _retire(state)
        if isValid(parent):
            parent.hide()
            parent.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def test_idle_worker_owns_only_plain_state_and_close_wakes_it():
    state = _SystemPulseSampler(lambda: {})
    assert state.thread._target.__self__ is state
    assert not any(isinstance(value, QObject) for value in vars(state).values())
    state.thread.start()
    try:
        assert state.thread.is_alive()
        state.close()
        state.close()
        state.thread.join(1.0)
        assert not state.thread.is_alive()
        assert state.retired.is_set()
        assert state.snapshot() == {
            "accepted": 0, "completed": 0, "cancelled": 0,
            "discarded": 0, "failed": 0, "pending": False,
            "active": False, "buffered": False, "closed": True,
            "retired": True,
        }
    finally:
        _retire(state)


def test_queued_request_is_cancelled_before_worker_enters_provider():
    calls = []
    state = _SystemPulseSampler(lambda: calls.append(True))
    assert state.request()
    assert not any(state.request() for _ in range(100))
    state.close()
    state.thread.start()
    try:
        state.thread.join(1.0)
        assert not state.thread.is_alive()
        assert not calls and not state.request()
        assert state.drain() == (None, False)
        snapshot = state.snapshot()
        assert snapshot["accepted"] == snapshot["cancelled"] == 1
        assert snapshot["completed"] == snapshot["discarded"] == 0
        assert not state.busy.is_set()
    finally:
        _retire(state)


def test_close_does_not_wait_for_active_provider_and_discards_late_output():
    entered, release, closed = (threading.Event() for _ in range(3))

    def collect():
        entered.set()
        assert release.wait(2.0)
        return {"late": "must not be published"}

    state = _SystemPulseSampler(collect)
    state.thread.start()
    closer = threading.Thread(target=lambda: (state.close(), closed.set()))
    try:
        assert state.request() and entered.wait(1.0)
        closer.start()
        assert closed.wait(1.0), "Close waited on the provider"
        closer.join(1.0)
        assert not closer.is_alive()
        assert state.thread.is_alive() and state.busy.is_set()
        assert not state.retired.is_set() and not state.request()
        assert state.drain() == (None, False)
        release.set()
        state.thread.join(1.0)
        snapshot = state.snapshot()
        assert snapshot["completed"] == snapshot["discarded"] == 1
        assert snapshot["cancelled"] == 0 and snapshot["retired"]
        assert not snapshot["buffered"] and not state.busy.is_set()
    finally:
        release.set()
        _retire(state)
        if closer.ident is not None:
            closer.join(1.0)
        assert not closer.is_alive()


@pytest.mark.parametrize("kind", [RuntimeError, KeyboardInterrupt])
def test_provider_failure_clears_admission_without_rendering_private_error(kind):
    class Unrenderable(kind):
        def __str__(self):
            raise KeyboardInterrupt("sensitive formatter must not run")

    def failed():
        raise Unrenderable("sensitive provider body")

    state = _SystemPulseSampler(failed)
    state.thread.start()
    try:
        assert state.request()
        _wait_for(lambda: state.snapshot()["completed"] == 1)
        assert state.drain() == ({"error": "Host sample unavailable"}, False)
        assert state.snapshot()["failed"] == 1
        state.collect = lambda: {"next": 2}
        assert state.request()
        _wait_for(lambda: state.snapshot()["completed"] == 2)
        assert state.drain() == ({"next": 2}, False)
    finally:
        _retire(state)


def test_mailbox_keeps_only_latest_completed_result_and_counts_replacement():
    values = iter([{"value": 1}, {"value": 2}])
    state = _SystemPulseSampler(lambda: next(values))
    state.thread.start()
    try:
        for count in (1, 2):
            assert state.request()
            _wait_for(lambda: state.snapshot()["completed"] == count)
        assert state.snapshot()["discarded"] == 1
        assert state.drain() == ({"value": 2}, False)
        assert state.drain() == (None, False)
    finally:
        _retire(state)


def test_completed_result_is_published_with_busy_transition_under_same_lock():
    entered, release, returning = (threading.Event() for _ in range(3))

    def collect():
        entered.set()
        assert release.wait(2.0)
        returning.set()
        return {"value": 3}

    state = _SystemPulseSampler(collect)
    state.thread.start()
    try:
        assert state.request() and entered.wait(1.0)
        with state._lock:
            release.set()
            assert returning.wait(1.0)
            # Publication needs this lock. Neither busy nor completion may be
            # cleared early while the finished result is still unpublished.
            assert state.busy.is_set()
            assert state._active and state._completed == 0
            assert state._result is None
        _wait_for(lambda: state.snapshot()["completed"] == 1)
        assert state.drain() == ({"value": 3}, False)
    finally:
        release.set()
        _retire(state)


def test_close_discards_already_completed_mailbox_and_refuses_future_requests():
    state = _SystemPulseSampler(lambda: {"ready": True})
    state.thread.start()
    try:
        assert state.request()
        _wait_for(lambda: state.snapshot()["completed"] == 1)
        state.close()
        assert state.drain() == (None, False)
        assert not state.request()
        assert state.snapshot()["discarded"] == 1
    finally:
        _retire(state)


def test_collector_preserves_metrics_order_rate_floor_and_fifth_sample_wifi(monkeypatch):
    calls, wifi_calls = [], []
    counters = iter(SimpleNamespace(bytes_recv=100 + i * 100,
                                    bytes_sent=50 + i * 50) for i in range(6))
    clocks = iter([10.0, 10.1, 11.0, 12.0, 13.0, 14.0])

    def clock():
        calls.append("clock")
        return next(clocks)

    def memory():
        calls.append("memory")
        return SimpleNamespace(percent=25, available=1024)

    def network():
        calls.append("network")
        return next(counters)

    def cpu(*, interval):
        assert interval is None
        calls.append("cpu")
        return 12

    def wifi():
        calls.append("wifi")
        wifi_calls.append(True)
        return 80 if len(wifi_calls) == 1 else 70

    monkeypatch.setitem(sys.modules, "psutil", SimpleNamespace(
        virtual_memory=memory, net_io_counters=network, cpu_percent=cpu,
    ))
    monkeypatch.setattr(system_pulse, "time", SimpleNamespace(monotonic=clock))
    monkeypatch.setattr(system_pulse, "_wifi_signal_windows", wifi)
    collector = _SystemPulseCollector()
    results = [collector() for _ in range(6)]
    assert results[0] == {"cpu": 12.0, "ram": 25.0, "available": 1024.0,
                          "down": 0.0, "up": 0.0, "wifi": 80}
    assert results[1]["down"] == 400.0 and results[1]["up"] == 200.0
    assert [row["wifi"] for row in results] == [80] * 5 + [70]
    assert calls == (["clock", "memory", "network", "cpu", "wifi"]
                     + ["clock", "memory", "network", "cpu"] * 4
                     + ["clock", "memory", "network", "cpu", "wifi"])


def test_collector_preserves_renderable_error_result_and_does_not_advance_cache(monkeypatch):
    def unavailable():
        raise RuntimeError("fixture unavailable")

    monkeypatch.setitem(sys.modules, "psutil", SimpleNamespace(virtual_memory=unavailable))
    collector = _SystemPulseCollector()
    assert collector() == {"error": "fixture unavailable"}
    assert collector._sample_index == 0 and collector._last_net is None


def test_card_delivers_on_gui_only_and_stops_completion_timer_when_idle(fake_cards):
    _app, make = fake_cards
    _parent, card, state = make()
    owner_thread = threading.get_ident()
    delivery_threads = []
    card.sample_ready.connect(lambda _data: delivery_threads.append(threading.get_ident()))
    assert card._delivery_timer.isSingleShot()
    assert card._delivery_timer.interval() == 25
    assert not card._delivery_timer.isActive()
    assert state.thread._target.__self__ is state
    assert isinstance(state.collect, _SystemPulseCollector)
    assert not any(isinstance(value, QObject) for value in vars(state).values())
    card.request_sample()
    assert card._delivery_timer.isActive()
    _wait_for(lambda: state.snapshot()["completed"] == 1)
    assert not delivery_threads and card.sample_revision() == 0
    card._drain_sample()
    assert delivery_threads == [owner_thread] and card.sample_revision() == 1
    assert card.snapshot()["latest"]["cpu"] == 12.0
    assert not card._delivery_timer.isActive()


def test_repeated_manual_requests_do_not_postpone_an_active_delivery_timer(fake_cards, monkeypatch):
    _app, make = fake_cards
    _parent, card, state = make()
    card._delivery_timer.start()
    starts = []
    original = card._delivery_timer.start
    monkeypatch.setattr(card._delivery_timer, "start", lambda: starts.append(True))
    card.request_sample()
    _wait_for(lambda: state.snapshot()["completed"] == 1)
    assert not starts
    monkeypatch.setattr(card._delivery_timer, "start", original)


def test_parent_deletion_closes_plain_state_while_provider_is_still_running(fake_cards):
    _app, make = fake_cards
    parent, card, state = make()
    entered, release = threading.Event(), threading.Event()

    def blocked():
        entered.set()
        assert release.wait(2.0)
        return {"late": True}

    state.collect = blocked
    worker = card._sample_worker
    assert worker is state.thread
    try:
        card.request_sample()
        assert entered.wait(1.0)
        parent.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        assert not isValid(parent) and not isValid(card)
        assert state.closed.is_set() and worker.is_alive()
        assert state.busy.is_set() and not state.retired.is_set()
        assert not state.request()
        release.set()
        worker.join(1.0)
        assert not worker.is_alive()
        assert state.drain() == (None, False)
        assert state.snapshot()["discarded"] == 1
        # Even explicit repeated cleanup after C++ destruction must not invoke
        # a method on either deleted timer.
        card.shutdown()
    finally:
        release.set()
        _retire(state)


@pytest.mark.parametrize("action", ["close", "delete_parent"])
def test_delivery_slot_can_close_or_delete_its_parent_without_late_qt_access(fake_cards, action):
    _app, make = fake_cards
    parent, card, state = make()

    def close_owner(_data):
        if action == "close":
            card.close()
        else:
            parent.deleteLater()
            QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)

    card.sample_ready.connect(close_owner)
    card.request_sample()
    _wait_for(lambda: state.snapshot()["completed"] == 1)
    card._drain_sample()
    assert state.closed.is_set()
    _retire(state)
    if action == "close":
        assert not card._delivery_timer.isActive()
    else:
        assert not isValid(card) and not isValid(parent)


def test_delivery_close_cancels_rearmed_timer_with_another_active_sample(fake_cards):
    _app, make = fake_cards
    _parent, card, state = make()
    entered, release = threading.Event(), threading.Event()

    def blocked():
        entered.set()
        assert release.wait(2.0)
        return {"late": True}

    try:
        card.request_sample()
        _wait_for(lambda: state.snapshot()["completed"] == 1)
        state.collect = blocked
        card.request_sample()
        assert entered.wait(1.0)
        card.sample_ready.connect(lambda _data: card.shutdown())
        card._drain_sample()
        assert state.closed.is_set() and state.thread.is_alive()
        assert not card._delivery_timer.isActive()
    finally:
        release.set()
        _retire(state)


def test_quit_hook_closes_owned_state_without_joining_gui_thread(fake_cards, monkeypatch):
    callbacks = []
    fake_app = SimpleNamespace(aboutToQuit=SimpleNamespace(connect=callbacks.append))
    monkeypatch.setattr(system_pulse, "QApplication", SimpleNamespace(instance=lambda: fake_app))
    _app, make = fake_cards
    _parent, card, state = make()
    assert callbacks == [card.shutdown]
    original_join = state.thread.join

    def forbidden_join(*_args, **_kwargs):
        raise AssertionError("GUI cleanup attempted a blocking join")

    monkeypatch.setattr(state.thread, "join", forbidden_join)
    callbacks[0]()
    assert state.closed.is_set() and not card._delivery_timer.isActive()
    monkeypatch.setattr(state.thread, "join", original_join)
    _retire(state)


@pytest.mark.parametrize("parts", [(), ("state",), ("timer",), ("state", "timer")])
def test_partial_initialization_shutdown_closes_available_parts_without_starting_work(parts):
    app = QApplication.instance() or QApplication([])
    assert app is not None
    owner = SimpleNamespace()
    state = _SystemPulseSampler(lambda: pytest.fail("Unstarted partial provider ran"))
    timer = QTimer()
    timer.start(1000)
    if "state" in parts:
        owner._sampler = state
        assert state.request()
    if "timer" in parts:
        owner._delivery_timer = timer
    try:
        SystemPulseCard.shutdown(owner)
        SystemPulseCard.shutdown(owner)
        assert state.thread.ident is None
        if "state" in parts:
            assert state.closed.is_set() and state.snapshot()["cancelled"] == 1
        if "timer" in parts:
            assert not timer.isActive()
    finally:
        timer.stop()
        state.close()


def test_selfcheck_retirement_preserves_qt_owner_until_actual_sampler_returns(fake_cards):
    from angerona.core import selftest

    # Read only the actual pinned helper definition; importing tools/selfcheck
    # would execute its full host/self-test campaign during test collection.
    path = Path(selftest.__file__).resolve().parents[3] / "tools/selfcheck.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                    and node.name == "_teardown_qt_owned")
    namespace = {"time": time}
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(path), "exec"), namespace)
    cleanup = namespace[function.name]
    assert cleanup.__code__.co_filename == str(path)
    app, make = fake_cards
    parent, card, state = make()
    entered, release = threading.Event(), threading.Event()

    def blocked():
        entered.set()
        assert release.wait(2.0)
        return {"late": True}

    state.collect = blocked
    try:
        card.request_sample()
        assert entered.wait(1.0)
        with pytest.raises(AssertionError, match="GUI reader did not stop: SystemPulseSampler"):
            cleanup(app, [parent], timeout=0)
        assert isValid(parent) and isValid(card)
        assert state.thread.is_alive() and state.closed.is_set()
        release.set()
        state.thread.join(1.0)
        assert not state.thread.is_alive()
        cleanup(app, [parent])
        assert not isValid(parent) and not isValid(card)
    finally:
        release.set()
        _retire(state)


def test_constructor_prelaunch_start_failure_closes_owned_state_and_timers(fake_cards, monkeypatch):
    _app, _make = fake_cards
    parent = QWidget()
    parent.show()
    owned = []
    failure = RuntimeError("inert prelaunch start failure")
    original_start = threading.Thread.start

    def refuse_start(worker):
        if worker.name != "SystemPulseSampler":
            return original_start(worker)
        card = parent.findChildren(SystemPulseCard)[0]
        owned.append(card)
        card.show()
        card._timer.refresh()
        assert card._timer.isActive()
        raise failure

    monkeypatch.setattr(threading.Thread, "start", refuse_start)
    try:
        with pytest.raises(RuntimeError) as caught:
            SystemPulseCard(parent)
        assert caught.value is failure
        assert len(owned) == 1
        card = owned[0]
        state = card._sampler
        assert state.closed.is_set() and state.thread.ident is None
        assert not state.request() and not state.retired.is_set()
        assert not card._timer.isActive() and not card._delivery_timer.isActive()
        card.request_sample()
        assert not card._delivery_timer.isActive()
    finally:
        for card in owned:
            card.shutdown()
            _retire(card._sampler)
        parent.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)


@pytest.mark.parametrize("failure_at", ["constructor", "interval"])
def test_constructor_partial_delivery_timer_failure_cancels_available_parts(
    fake_cards, monkeypatch, failure_at,
):
    _app, _make = fake_cards
    parent = QWidget()
    parent.show()
    owned = []
    failure = RuntimeError("inert timer setup failure")

    def remember_card():
        card = parent.findChildren(SystemPulseCard)[0]
        owned.append(card)
        card.show()
        card._timer.refresh()
        assert card._timer.isActive()
        return card

    class BrokenTimer(QTimer):
        def __init__(self, owner):
            super().__init__(owner)
            remember_card()
            if failure_at == "constructor":
                raise failure

        def setInterval(self, interval):  # noqa: N802 - Qt signature
            super().setInterval(interval)
            raise failure

    monkeypatch.setattr(system_pulse, "QTimer", BrokenTimer)
    try:
        with pytest.raises(RuntimeError) as caught:
            SystemPulseCard(parent)
        assert caught.value is failure and len(owned) == 1
        card = owned[0]
        state = card._sampler
        assert state.closed.is_set() and state.thread.ident is None
        assert not card._timer.isActive() and not state.request()
        if failure_at == "interval":
            assert not card._delivery_timer.isActive()
    finally:
        for card in owned:
            card.shutdown()
            _retire(card._sampler)
        parent.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def test_constructor_interrupted_after_real_owned_start_closes_without_claiming_retirement(
    fake_cards, monkeypatch,
):
    _app, _make = fake_cards
    parent = QWidget()
    entered, release = threading.Event(), threading.Event()
    owned = []
    failure = KeyboardInterrupt("inert postlaunch interruption")
    original_start = threading.Thread.start

    def collect(_collector):
        entered.set()
        assert release.wait(2.0)
        return {"late": "discard"}

    monkeypatch.setattr(_SystemPulseCollector, "__call__", collect)

    def start_then_interrupt(worker):
        if worker.name != "SystemPulseSampler":
            return original_start(worker)
        card = parent.findChildren(SystemPulseCard)[0]
        owned.append(card)
        original_start(worker)
        assert card._sampler.request() and entered.wait(1.0)
        raise failure

    monkeypatch.setattr(threading.Thread, "start", start_then_interrupt)
    try:
        with pytest.raises(KeyboardInterrupt) as caught:
            SystemPulseCard(parent)
        assert caught.value is failure and len(owned) == 1
        card = owned[0]
        state = card._sampler
        assert state.thread.is_alive() and state.closed.is_set()
        assert state.busy.is_set() and not state.retired.is_set()
        assert not state.request() and state.drain() == (None, False)
        assert not card._timer.isActive() and not card._delivery_timer.isActive()
        assert not any(isinstance(value, QObject) for value in vars(state).values())
        release.set()
        state.thread.join(1.0)
        assert not state.thread.is_alive() and state.retired.is_set()
        assert state.snapshot()["discarded"] == 1
    finally:
        release.set()
        for card in owned:
            card.shutdown()
            _retire(card._sampler)
        parent.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def test_context_owned_initial_request_is_cancelled_before_original_120ms_deadline(
    fake_cards, monkeypatch,
):
    _app, make = fake_cards
    calls, exceptions, scheduled = [], [], []
    original_single_shot = QTimer.singleShot

    def single_shot(*args):
        if args[0] == 120:
            scheduled.append(args)
        return original_single_shot(*args)

    monkeypatch.setattr(QTimer, "singleShot", single_shot)
    monkeypatch.setattr(_SystemPulseCollector, "__call__", lambda _self: calls.append(True))
    monkeypatch.setattr(sys, "excepthook", lambda kind, *_rest: exceptions.append(kind.__name__))
    monkeypatch.setattr(threading, "excepthook", lambda args: exceptions.append(args.exc_type.__name__))
    parent, card, state = make()
    assert len(scheduled) == 1
    assert len(scheduled[0]) == 3 and scheduled[0][0] == 120
    assert scheduled[0][1] is card and scheduled[0][2].__self__ is card
    parent.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    assert not isValid(card) and state.closed.is_set()
    _retire(state)
    # The original request deadline remains 120ms; this observes its complete
    # delivery window without extending any production/test callback budget.
    QTest.qWait(150)
    assert not calls and not exceptions
    # A deliberately retained Python wrapper must also refuse a direct late
    # request before calling native window() on its deleted C++ object.
    card.request_sample()
    assert not calls
