"""Synthetic action producers only; no installs, scans, service or policy writes."""
from __future__ import annotations

import sys
import threading
import time
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, QObject, Slot
from PySide6.QtWidgets import QApplication, QWidget
from shiboken6 import isValid

from angerona.gui import action_progress, action_worker, aria_hud, engine_console, prevention_panel
from angerona.gui import analysis_qemu_setup as qemu
from angerona.gui import protection_service_console as service


def until(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        QApplication.instance().processEvents()
        time.sleep(.005)
    assert predicate()


@pytest.fixture
def finite(monkeypatch):
    assert not action_worker.active_finite_actions()
    monkeypatch.setattr(action_worker, "_CLOSING", False)
    releases = []
    yield releases
    for release in releases:
        release.set()
    for worker in action_worker.active_finite_actions():
        worker.requestInterruption()
        assert worker.wait(3000)
    until(lambda: not action_worker.active_finite_actions())


class Receiver(QObject):
    def __init__(self):
        super().__init__()
        self.rows = []
        self.gui_thread = threading.get_ident()

    @Slot()
    def finished(self):
        assert threading.get_ident() == self.gui_thread
        self.rows.append(self.sender().outcome)


def test_finite_worker_is_retained_bounded_and_shutdown_does_not_invent_exit(finite, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    finite.append(release)
    receiver = Receiver()
    monkeypatch.setattr(action_worker, "_LIMIT", 1)

    def work(owner):
        entered.set()
        assert release.wait(4)
        return owner.isInterruptionRequested()

    worker = action_worker.start_finite_action(work, name="FixtureFiniteAction", finished=receiver.finished)
    assert entered.wait(2)
    assert action_worker.start_finite_action(lambda _owner: pytest.fail("Capacity must hold admission"),
                                           name="MustNotStart", finished=receiver.finished) is None
    action_worker.hold_finite_actions()
    assert worker.isInterruptionRequested() and worker in action_worker.active_finite_actions()
    assert receiver.rows == []
    release.set()
    until(lambda: bool(receiver.rows) and not action_worker.active_finite_actions())
    assert receiver.rows == [(True, "")]
    receiver.deleteLater()


def test_deleting_receiver_does_not_delete_its_live_finite_worker(finite):
    entered, release = threading.Event(), threading.Event()
    finite.append(release)
    receiver = Receiver()

    def work(_owner):
        entered.set()
        assert release.wait(4)
        return "private fixture"

    worker = action_worker.start_finite_action(work, name="DeletedReceiverFixture", finished=receiver.finished)
    assert entered.wait(2)
    receiver.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    assert not isValid(receiver) and isValid(worker) and worker.isRunning()
    assert worker in action_worker.active_finite_actions()
    release.set()
    until(lambda: not action_worker.active_finite_actions())


def test_aria_question_is_single_admitted_and_measured_progress_stays_unknown(finite):
    entered, release = threading.Event(), threading.Event()
    finite.append(release)
    calls = []

    def ask(text):
        calls.append((text, threading.get_ident()))
        entered.set()
        assert release.wait(4)
        return "fixture answer"

    hud = aria_hud.AriaHud(score_fn=lambda: 100, ask_fn=ask)
    try:
        hud._input.setText("fixture question")
        hud._on_submit()
        assert entered.wait(2)
        assert hud._ask_worker.isRunning() and hud._activities.snapshot()
        assert hud.progress_view.ring.percent is None and not hud._input.isEnabled()
        hud._input.setText("preserve next question")
        hud._on_submit()
        assert hud._input.text() == "preserve next question" and len(calls) == 1
        release.set()
        until(lambda: hud._ask_worker is None and not action_worker.active_finite_actions())
        assert "fixture answer" in hud._log.toPlainText()
        assert hud._activities.snapshot() == {} and hud._input.isEnabled()
        assert calls[0][1] != threading.get_ident()
    finally:
        release.set()
        for worker in action_worker.active_finite_actions():
            assert worker.wait(3000)
        until(lambda: not action_worker.active_finite_actions())
        hud.close()
        hud.deleteLater()


def test_local_only_progress_does_not_duplicate_existing_global_token(monkeypatch):
    monkeypatch.setattr(action_progress, "begin_loading", lambda *_args, **_kwargs: pytest.fail("Existing owner already owns the global token"))
    owner = QWidget()
    group = action_progress.ActionActivities(owner, publish_global=False)
    view = action_progress.ActionProgressView(group, owner)
    handle = group.begin("batch", "Actual record returns", done=1, total=4)
    assert view.ring.percent == 25
    group.update(handle, done=2, total=4)
    assert view.ring.percent == 50 and group.finish(handle)
    assert group.snapshot() == {}
    owner.deleteLater()


def test_prevention_result_marker_does_not_finish_before_exact_worker_exit(monkeypatch):
    original = threading.Thread
    published, release = threading.Event(), threading.Event()

    def held_thread(*, target, **kwargs):
        def run():
            target()
            published.set()
            assert release.wait(4)
        return original(target=run, **kwargs)

    panel = prevention_panel.PreventionPanel(inspector=lambda: {"state": "partial", "bits": 0})
    monkeypatch.setattr(prevention_panel.threading, "Thread", held_thread)
    try:
        assert panel._start("inspect", lambda _cancel: {"state": "partial", "bits": 0})
        assert published.wait(2) and panel._job.done.is_set()
        panel._poll()
        assert panel._job is not None and panel._activities.snapshot()
        assert not panel._start("inspect", lambda _cancel: pytest.fail("No duplicate may be admitted"))
        release.set()
        until(lambda: panel._job is None)
        assert not panel._activities.snapshot()
    finally:
        release.set()
        if panel._worker is not None:
            panel._worker.join(3)
            assert not panel._worker.is_alive()
        panel.close()
        panel.deleteLater()


def test_emulator_progress_and_completion_stay_bound_to_native_worker(tmp_path, monkeypatch):
    original = threading.Thread
    published, release = threading.Event(), threading.Event()
    monkeypatch.setitem(sys.modules, "angerona.core.analysis_qemu_setup", SimpleNamespace(
        install_and_configure=lambda _root, _operation, progress: progress("Fixture verification phase") or "Fixture setup returned"))

    def held_thread(*, target, **kwargs):
        def run():
            target()
            published.set()
            assert release.wait(4)
        return original(target=run, **kwargs)

    dialog = qemu.QEMUSetupDialog(root=tmp_path)
    monkeypatch.setattr(qemu.threading, "Thread", held_thread)
    try:
        dialog._install()
        assert published.wait(2)
        dialog._poll()
        assert dialog._busy and dialog._activities.snapshot() and dialog.progress_view.ring.percent is None
        assert "Fixture verification phase" in dialog.status.text()
        release.set()
        until(lambda: not dialog._busy)
        assert not dialog._activities.snapshot() and "Fixture setup returned" in dialog.status.text()
    finally:
        release.set()
        if dialog._worker is not None:
            dialog._worker.join(3)
            assert not dialog._worker.is_alive()
        dialog.close()
        dialog.deleteLater()


def _status_payload():
    return dict(service="AngeronaProtection", protection_verified=False, authority=[], mutating_operations=[],
                event_text_available=False, storage_access_available=False, state="ready", mode="full",
                version="fixture", coverage_reason="Counts do not verify coverage.",
                modules=dict(discovered=8, sampled=8, truncated=False, enabled=7, running=6))


def test_service_manual_ticket_is_not_finished_by_an_older_inflight_read(monkeypatch):
    monkeypatch.setattr(service, "_RETIREMENT_HOLD", None)
    first_entered, second_entered, first_release, second_release = [threading.Event() for _ in range(4)]
    calls = []

    class Client:
        cleanup_proven = True

        def status(self):
            calls.append(True)
            entered, release = (first_entered, first_release) if len(calls) == 1 else (second_entered, second_release)
            entered.set()
            assert release.wait(4)
            return _status_payload()

    reader = service.ServiceStatusReader(client_factory=Client, clock=lambda: 100.0)
    window = service.ProtectionServiceConsole(reader=reader, start_reader=False, clock=lambda: 100.0)
    try:
        reader.start()
        assert first_entered.wait(2) and not window._activities.snapshot()
        window._request(manual=True)
        ticket = window._manual_ticket
        assert ticket == 2 and window._activities.snapshot()
        first_release.set()
        until(second_entered.is_set)
        assert reader.snapshot.request_ticket == 1
        window._tick()
        assert window._manual_ticket == ticket and window._activities.snapshot()
        second_release.set()
        until(lambda: reader.snapshot.request_ticket >= ticket)
        window._tick()
        assert not window._activities.snapshot()
    finally:
        first_release.set()
        second_release.set()
        reader.request_detach()
        assert reader.wait_retired(4)
        window.close()
        window.deleteLater()


def test_console_progress_reservations_are_bounded_and_queue_failure_is_not_orphaned():
    worker = engine_console.ConsoleWorker()
    ids = [f"{index:032x}" for index in range(9)]
    for request_id in ids[:8]:
        assert worker.submit("selftest", "fixture", request_id=request_id)
    assert not worker.submit("selftest", "fixture", request_id=ids[8])
    assert set(worker.operation_progress()) == set(ids[:8])
    assert not worker.submit("selftest", "fixture", request_id="invalid")
    worker._progress(ids[0], "unavailable", "Actual outcome unknown")
    worker.acknowledge(ids[0])
    assert ids[0] not in worker.operation_progress()
    assert worker.commands.qsize() == 8


def test_console_tracks_actual_engine_terminal_state_without_ending_monitor():
    worker = engine_console.ConsoleWorker()
    worker.instance = "fixture-instance"

    class Client:
        def self_test(self, _name):
            return {"id": "fixture-job"}

        def status(self):
            return {"instance": "fixture-instance"}

        def events(self, _cursor):
            return {"cursor": 0}

        def operation_status(self, job):
            assert job == "fixture-job"
            worker.stop.set()
            return {"state": "completed", "operation": "selftest"}

    worker.client = Client()
    request_id = "a" * 32
    assert worker.submit("selftest", "fixture", request_id=request_id)
    native = threading.Thread(target=worker.run)
    native.start()
    native.join(3)
    assert not native.is_alive()
    row = worker.operation_progress()[request_id]
    assert row["state"] == "completed" and row["operation"] == "selftest"
    assert worker._operation_requests == {} and not worker.pending
