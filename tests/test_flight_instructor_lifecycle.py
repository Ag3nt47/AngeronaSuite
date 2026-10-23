"""Owned instructor lifecycle; all coaching/model/network work is inert."""
from __future__ import annotations

import ast
from pathlib import Path
import queue
import threading
import time
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import QApplication, QMainWindow
from shiboken6 import delete, isValid

from angerona.gui import main_window


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def forbid_model_and_network(monkeypatch):
    from angerona.academy import security_academy

    def forbidden(*_args, **_kwargs):
        raise AssertionError("real model/network forbidden in lifecycle test")

    monkeypatch.setattr(security_academy.FlightInstructor, "_ollama_chat", forbidden)
    monkeypatch.setattr(security_academy, "safe_urlopen", forbidden)


@pytest.fixture(scope="module")
def app():
    application = QApplication.instance()
    owns = application is None
    if owns:
        application = QApplication([])
    application.setQuitOnLastWindowClosed(False)
    yield application
    if owns:
        application.shutdown()
        assert QApplication.instance() is None


@pytest.fixture
def owned_queue(monkeypatch):
    states = []

    def create(callback):
        state = main_window._FlightInstructorQueue(callback)
        states.append(state)
        return state

    yield create
    for state in states:
        state.close()
        state.thread.join(3)
        assert not state.thread.is_alive(), "owned inert instructor did not retire"
        assert state.retired.is_set()
        assert state._requests.unfinished_tasks == 0


def drained(state):
    with state._requests.all_tasks_done:
        assert state._requests.all_tasks_done.wait_for(
            lambda: state._requests.unfinished_tasks == 0, timeout=3)


class FixtureWindow(main_window.MainWindow):
    """Exercise real worker/lifecycle methods without the full dashboard."""

    def __init__(self, callback):
        QMainWindow.__init__(self)
        self.flight_instructor = SimpleNamespace(narrate_event=callback)
        self._fi_enabled = True
        self._holographic_orb = SimpleNamespace(enabled=lambda: False, shutdown=lambda: None)
        self.tray = SimpleNamespace(hide=lambda: None, showMessage=lambda *_args: None)
        self._ui_watchdog = None
        self._close_operations_service = lambda: None
        self.deliveries = []
        self._fi_coaching.connect(lambda text: self.deliveries.append((text, threading.get_ident())))
        self._init_flight_instructor_worker()
        # Tests explicitly drive delivery; no unrelated timer scheduling.
        self._fi_delivery_timer.stop()

    # This deliberately partial dashboard owns no presentation fields. Keep
    # its inherited close/worker/quit paths, while native display events use
    # the base widget handlers and cannot queue unrelated dashboard refreshes.
    def showEvent(self, event):
        QMainWindow.showEvent(self, event)

    def hideEvent(self, event):
        QMainWindow.hideEvent(self, event)

    def changeEvent(self, event):
        QMainWindow.changeEvent(self, event)


def cleanup_function():
    path = ROOT / "tools/selfcheck.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                    and node.name == "_teardown_qt_owned")
    namespace = {"time": time}
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(path), "exec"), namespace)
    return namespace[function.name]


def retire_window(window):
    if isValid(window):
        window._close_flight_instructor()
    window._fi_worker.join(3)
    assert not window._fi_worker.is_alive()
    if isValid(window):
        delete(window)


def test_source_overlay_is_actual_reviewed_module():
    assert Path(main_window.__file__).resolve() == ROOT / "src/angerona/gui/main_window.py"


@pytest.mark.parametrize("part", ["none", "state", "timer"])
def test_partial_initialization_close_is_safe_and_preserves_available_cleanup(part):
    calls = []
    owner = SimpleNamespace()
    if part == "state":
        owner._fi_coaching_worker = SimpleNamespace(close=lambda: calls.append("state"))
    if part == "timer":
        owner._fi_delivery_timer = SimpleNamespace(stop=lambda: calls.append("timer"))
    main_window.MainWindow._close_flight_instructor(owner)
    assert owner._fi_enabled is False
    assert calls == ([] if part == "none" else [part])


def test_idle_close_wakes_and_retires_with_idempotent_accounting(owned_queue):
    calls = []
    state = owned_queue(calls.append)
    state.close()
    state.close()
    state.thread.join(3)
    assert not state.thread.is_alive() and state.retired.is_set()
    assert state.closed.is_set() and not state.active.is_set()
    assert calls == [] and state.take_ready() == []
    assert not state.submit("late coaching")


def test_close_cancels_queued_and_late_output_but_retains_active_call(owned_queue, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    calls = []

    def narrate(line):
        calls.append(line)
        entered.set()
        assert release.wait(3)
        return "late model explanation"

    state = owned_queue(narrate)
    assert state.submit("active")
    assert entered.wait(3)
    for index in range(12):
        assert state.submit(f"queued {index}")
    assert state._requests.qsize() == 8
    original_join = state.thread.join

    def forbidden_join(*_args, **_kwargs):
        raise AssertionError("close must not join a GUI-owned worker")

    monkeypatch.setattr(state.thread, "join", forbidden_join)
    try:
        state.close()
        state.close()
        assert state.thread.is_alive() and not state.retired.is_set()
        assert state.active.is_set() and not state.submit("after close")
        assert state.take_ready() == []
    finally:
        release.set()
        monkeypatch.setattr(state.thread, "join", original_join)
        original_join(3)
    assert calls == ["active"]
    assert state.take_ready() == []


def test_original_newest_stage_admission_policy_is_preserved(owned_queue):
    entered, release = threading.Event(), threading.Event()
    calls = []

    def narrate(line):
        calls.append(line)
        if line == "first":
            entered.set()
            assert release.wait(3)
        return "coaching " + line

    state = owned_queue(narrate)
    try:
        assert state.submit("first")
        assert entered.wait(3)
        for index in range(12):
            assert state.submit(str(index))
        release.set()
        drained(state)
        assert calls == ["first", *map(str, range(4, 12))]
        assert state.take_ready() == ["coaching " + str(index) for index in range(4, 12)]
        assert state.take_ready() == []
    finally:
        release.set()


def test_callback_exception_remains_explanatory_not_a_thread_leak(owned_queue):
    def narrate(_line):
        raise RuntimeError("inert fixture failure")

    state = owned_queue(narrate)
    assert state.submit("stage")
    drained(state)
    assert state.take_ready() == ["\U0001F393 (Flight Instructor error) inert fixture failure"]
    assert not state.closed.is_set()


def test_close_wins_after_dequeue_before_callback_admission(owned_queue, monkeypatch):
    taken, release = threading.Event(), threading.Event()

    class PausedGet(queue.Queue):
        pause_next = True

        def get(self, *args, **kwargs):
            value = super().get(*args, **kwargs)
            if self.pause_next:
                self.pause_next = False
                taken.set()
                assert release.wait(3)
            return value

    monkeypatch.setattr(main_window, "queue", SimpleNamespace(
        Queue=PausedGet, Full=queue.Full, Empty=queue.Empty))
    calls = []
    state = owned_queue(calls.append)
    try:
        assert state.submit("dequeued but not admitted")
        assert taken.wait(3)
        state.close()
        assert not state.active.is_set()
        assert not state.submit("after close")
    finally:
        release.set()
        state.thread.join(3)
    assert calls == []


def test_result_delivery_only_runs_on_gui_thread(app):
    worker_ids = []

    def narrate(line):
        worker_ids.append(threading.get_ident())
        return "inert " + line

    window = FixtureWindow(narrate)
    try:
        assert window._fi_coaching_worker.submit("stage")
        drained(window._fi_coaching_worker)
        assert window.deliveries == []
        window._drain_flight_instructor_coaching()
        assert window.deliveries == [("inert stage", threading.get_ident())]
        assert worker_ids and worker_ids[0] != threading.get_ident()
    finally:
        retire_window(window)


def test_close_to_tray_keeps_instructor_available(app):
    window = FixtureWindow(lambda line: "inert " + line)
    try:
        window.show()
        window.close()
        assert isValid(window) and not window.isVisible()
        assert not window._fi_coaching_worker.closed.is_set()
        assert window._fi_worker.is_alive()
        assert window._fi_coaching_worker.submit("after hide")
        drained(window._fi_coaching_worker)
        window._drain_flight_instructor_coaching()
        assert window.deliveries == [("inert after hide", threading.get_ident())]
    finally:
        retire_window(window)


def test_qt_owner_can_be_destroyed_while_plain_worker_retains_active_call(app):
    entered, release = threading.Event(), threading.Event()

    def narrate(_line):
        entered.set()
        assert release.wait(3)
        return "must not emit to destroyed Qt owner"

    window = FixtureWindow(narrate)
    state = window._fi_coaching_worker
    try:
        state.submit("active")
        assert entered.wait(3)
        delete(window)
        assert not isValid(window) and state.closed.is_set()
        assert state.thread.is_alive() and not state.retired.is_set()
    finally:
        release.set()
        state.thread.join(3)
    assert not state.thread.is_alive() and state.retired.is_set()
    assert state.take_ready() == [] and window.deliveries == []


def test_about_to_quit_closes_without_join_or_native_cancellation(app, monkeypatch):
    from angerona.gui.cve_detail_admission import detail_analysis_admission

    # The session's real QApplication also owns other shutdown subscribers.
    # Exercise this initializer's actual Qt connection with a scoped signal;
    # emitting process-global aboutToQuit would permanently close those peers.
    class ScopedQuitApplication(QObject):
        aboutToQuit = Signal()

    quit_application = ScopedQuitApplication()
    pool = detail_analysis_admission()
    before_active = pool.active_count
    assert not pool.closing
    before_token = pool.reserve()
    assert before_token is not None
    pool.abandon(before_token)
    assert pool.active_count == before_active
    actual_quit_calls = []

    def observed_actual_quit():
        actual_quit_calls.append(True)

    monkeypatch.setattr(
        main_window, "QApplication",
        SimpleNamespace(instance=lambda: quit_application),
    )
    entered, release = threading.Event(), threading.Event()

    def narrate(_line):
        entered.set()
        assert release.wait(3)
        return "late explanation"

    window = FixtureWindow(narrate)
    state = window._fi_coaching_worker
    original_join = state.thread.join

    def forbidden_join(*_args, **_kwargs):
        raise AssertionError("Qt quit callback must not join")

    app.aboutToQuit.connect(observed_actual_quit)
    try:
        state.submit("active")
        assert entered.wait(3)
        monkeypatch.setattr(state.thread, "join", forbidden_join)
        quit_application.aboutToQuit.emit()
        assert state.closed.is_set() and state.thread.is_alive()
        assert not window._fi_delivery_timer.isActive()
        assert actual_quit_calls == []
        assert detail_analysis_admission() is pool and not pool.closing
        after_token = pool.reserve()
        assert after_token is not None
        pool.abandon(after_token)
        assert pool.active_count == before_active
    finally:
        release.set()
        monkeypatch.setattr(state.thread, "join", original_join)
        retire_window(window)
        app.aboutToQuit.disconnect(observed_actual_quit)
    assert window.deliveries == []
    assert actual_quit_calls == []


def test_actual_selfcheck_teardown_collects_and_retires_idle_instructor(app):
    window = FixtureWindow(lambda line: line)
    worker = window._fi_worker
    try:
        detail = cleanup_function()(app, [window])
        assert not worker.is_alive() and window._fi_coaching_worker.retired.is_set()
        assert not isValid(window)
        assert "1 Python / 0 Qt workers retired" in detail
    finally:
        retire_window(window)


def test_actual_selfcheck_refuses_teardown_green_and_owner_deletion_while_active(app):
    entered, release = threading.Event(), threading.Event()

    def narrate(_line):
        entered.set()
        assert release.wait(3)
        return "late explanation"

    window = FixtureWindow(narrate)
    state = window._fi_coaching_worker
    try:
        state.submit("active")
        assert entered.wait(3)
        with pytest.raises(AssertionError, match="GUI reader did not stop: FlightInstructorWorker"):
            cleanup_function()(app, [window], timeout=0)
        assert isValid(window) and state.thread.is_alive()
        assert state.closed.is_set() and not state.retired.is_set()
        release.set()
        state.thread.join(3)
        detail = cleanup_function()(app, [window])
        assert not isValid(window)
        assert "1 Python / 0 Qt workers retired" in detail
        assert window.deliveries == []
    finally:
        release.set()
        retire_window(window)
