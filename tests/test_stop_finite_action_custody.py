"""Real parentless producers, exact retirement proof and deferred deletion."""
from __future__ import annotations

import os
import threading
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, QThread
from PySide6.QtWidgets import QApplication, QWidget
from shiboken6 import isValid

from angerona.gui import action_worker
from angerona.gui.shutdown_retirement import RetainedWorker, ShutdownRetirement, worker_retired


def wait(app, predicate):
    end = time.monotonic() + 4
    while time.monotonic() < end:
        app.processEvents()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        if predicate():
            return
        time.sleep(.005)
    raise AssertionError("Owned finite producer did not reach its exact native retirement boundary")


@pytest.fixture
def app(monkeypatch):
    value = QApplication.instance() or QApplication([])
    wait(value, lambda: not action_worker.active_finite_actions())
    monkeypatch.setattr(action_worker, "_CLOSING", False)
    return value


def barrier(owner, tmp_path, workers, **kwargs):
    results, cleanup = [], []
    value = ShutdownRetirement(owner, workers=workers, cleanup=lambda: cleanup.append(True),
        finish=results.append, data_root=tmp_path, diagnostic_writer=lambda *_args: None, **kwargs)
    value.start()
    return value, results, cleanup


def test_active_finite_producer_retains_native_object_through_delete_request_and_late_completion(app, tmp_path):
    owner, release, entered = QWidget(), threading.Event(), threading.Event()
    completed = []
    def produce(worker):
        entered.set()
        worker.piece.emit("Early cosmetic observation")
        release.wait(3)
        return "Actual producer result"
    worker = action_worker.start_finite_action(produce, name="inert-stop-finite", finished=lambda: completed.append(True))
    assert worker is not None
    wait(app, entered.is_set)
    retirement, results, cleanup = barrier(owner, tmp_path,
        lambda: (RetainedWorker("finite-producer", worker, True, action_worker.poll_finite_action_retirement),))
    try:
        action_worker.hold_finite_actions()
        assert action_worker.start_finite_action(lambda _w: None, name="held", finished=lambda: None) is None
        worker.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        assert isValid(worker) and worker.isRunning() and not results and cleanup == []
        release.set()
        wait(app, lambda: bool(results))
        assert results[0]["state"] == "retired" and results[0]["forced"] is False
        assert completed == [True] and action_worker.finite_action_retirement_proven(worker) is True
        assert cleanup == [True] and not action_worker.active_finite_actions()
    finally:
        release.set()
        wait(app, lambda: action_worker.finite_action_retirement_proven(worker))
        owner.close()


def test_completed_auto_deleted_action_has_exact_prior_proof_during_later_stop(app, tmp_path):
    completed = []
    worker = action_worker.start_finite_action(lambda _worker: "done", name="inert-already-finished",
        finished=lambda: completed.append(True))
    assert worker is not None
    wait(app, lambda: completed == [True] and not isValid(worker))
    assert action_worker.finite_action_retirement_proven(worker) is True
    other = QThread()
    assert action_worker.finite_action_retirement_proven(other) is False
    owner = QWidget()
    # The view deliberately still retains the deleted wrapper. Only its
    # producer's exact prior native proof can settle that object.
    _, results, cleanup = barrier(owner, tmp_path,
        lambda: (RetainedWorker("previous-action-wrapper", worker, True,
                               action_worker.finite_action_retirement_proven),))
    wait(app, lambda: bool(results))
    assert results[0]["state"] == "retired" and cleanup == [True]
    other.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    owner.close()


def test_never_started_qthread_without_admission_witness_cannot_be_called_completed(app, tmp_path):
    owner, worker, now = QWidget(), QThread(), [0.0]
    assert worker_retired(worker) is False
    retirement, results, cleanup = barrier(owner, tmp_path,
        lambda: (RetainedWorker("unproven-never-started", worker, True),), timeout=.1, clock=lambda: now[0])
    try:
        now[0] = 1.0
        retirement.poll()
        wait(app, lambda: bool(results))
        assert results[0]["state"] == "forced-incomplete" and cleanup == []
        assert results[0]["pending_workers"] == ["unproven-never-started"]
    finally:
        # This test owns explicit construction/no-start knowledge, unlike the
        # product admission path. Remove its filter before fixture disposal.
        worker.removeEventFilter(retirement)
        worker.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        owner.close()


def test_restarting_same_native_wrapper_cannot_reuse_its_previous_retirement_proof(app, tmp_path):
    owner, release, gate = QWidget(), threading.Event(), threading.Event()
    class Reusable(QThread):
        def run(self):
            release.wait(10)
    worker = Reusable()
    blocker = threading.Thread(target=lambda: gate.wait(10), daemon=True)
    worker.start()
    release.set()
    wait(app, lambda: worker_retired(worker))
    blocker.start()
    retirement, results, cleanup = barrier(owner, tmp_path,
        lambda: (RetainedWorker("native-generation", worker, True), RetainedWorker("fixture-gate", blocker, True)))
    try:
        retirement.poll()
        assert id(worker) in retirement._native_proven
        release.clear()
        worker.start()
        wait(app, worker.isRunning)
        gate.set()
        wait(app, lambda: not blocker.is_alive())
        retirement.poll()
        assert id(worker) not in retirement._native_proven and not results and cleanup == []
        release.set()
        wait(app, lambda: bool(results))
        assert results[0]["state"] == "retired" and cleanup == [True]
    finally:
        release.set()
        gate.set()
        wait(app, lambda: worker_retired(worker) and not blocker.is_alive())
        worker.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        owner.close()
