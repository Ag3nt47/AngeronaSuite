"""Actual fixture QThreads, with explicit modeled finished-before-wait proof."""
from __future__ import annotations

import json
import threading
import time

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, QObject, QThread, Slot
from PySide6.QtWidgets import QApplication
from shiboken6 import isValid

from angerona.gui import action_worker as actions
from angerona.gui import breach_display as reports
from angerona.gui import native_retirement as native


def until(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        QApplication.instance().processEvents()
        time.sleep(.005)
    assert predicate()


@pytest.fixture
def owned(monkeypatch):
    assert not actions.active_finite_actions() and not reports.active_report_exports()
    monkeypatch.setattr(actions, "_CLOSING", False)
    monkeypatch.setattr(reports, "_REPORT_EXPORT_ADMISSION", True)
    yield
    for worker in (*actions.active_finite_actions(), *reports.active_report_exports()):
        if hasattr(worker, "allow_native_proof"):
            worker.allow_native_proof.set()
        worker.requestInterruption()
        # This actual native wait is fixture cleanup, not a substituted proof.
        assert QThread.wait(worker, 3000)
        native.poll_native_retirement(worker)
    until(lambda: not actions.active_finite_actions() and not reports.active_report_exports())


class Receiver(QObject):
    def __init__(self):
        super().__init__()
        self.worker = None
        self.rows = []

    @Slot()
    def retired(self):
        worker = self.sender()
        assert worker is self.worker
        assert QThread.isFinished(worker) and QThread.wait(worker, 0)
        # A nested STOP hook cannot recursively invoke this owner or allow
        # deletion while the producer's reference cleanup is still running.
        assert actions.poll_finite_action_retirement(worker) is False
        self.worker = None
        self.rows.append(worker.outcome)


def test_finished_without_wait_proof_keeps_exact_worker_and_owner_pending(owned, monkeypatch):
    real = actions.FiniteActionWorker

    class HeldWait(real):
        def __init__(self, *args):
            super().__init__(*args)
            self.allow_native_proof = threading.Event()

        def wait(self, timeout=0):
            return super().wait(timeout) if self.allow_native_proof.is_set() else False

    monkeypatch.setattr(actions, "FiniteActionWorker", HeldWait)
    receiver = Receiver()
    receiver.worker = worker = actions.start_finite_action(lambda _owner: "fixture result", name="FinishedBeforeWaitFixture", finished=receiver.retired)
    until(worker.isFinished)
    QApplication.instance().processEvents()
    assert worker in actions.active_finite_actions() and receiver.rows == []
    assert not actions.finite_action_retirement_proven(worker)
    assert not actions.poll_finite_action_retirement(worker)
    worker.allow_native_proof.set()
    assert actions.poll_finite_action_retirement(worker)
    assert receiver.worker is None and receiver.rows == [("fixture result", "")]
    assert worker not in actions.active_finite_actions()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    assert not isValid(worker)
    assert actions.finite_action_retirement_proven(worker)
    receiver.deleteLater()


def test_actual_auto_deleted_action_keeps_identity_bound_ordinary_stop_proof(owned):
    receiver = Receiver()
    receiver.worker = worker = actions.start_finite_action(lambda _owner: "normal actual result", name="ActualAutoDeleteFixture", finished=receiver.retired)
    until(lambda: bool(receiver.rows) and not actions.active_finite_actions())
    assert receiver.worker is None and actions.finite_action_retirement_proven(worker)
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    assert not isValid(worker)
    assert actions.poll_finite_action_retirement(worker) is True
    stranger = QThread()
    assert not actions.finite_action_retirement_proven(stranger)
    assert not actions.poll_finite_action_retirement(stranger)
    stranger.deleteLater()
    receiver.deleteLater()


def test_export_success_and_reference_cleanup_wait_for_actual_native_proof(owned, tmp_path, monkeypatch):
    real = reports._ReportExportWorker

    class HeldExportWait(real):
        def __init__(self, *args):
            super().__init__(*args)
            self.allow_native_proof = threading.Event()

        def wait(self, timeout=0):
            return super().wait(timeout) if self.allow_native_proof.is_set() else False

    monkeypatch.setattr(reports, "_ReportExportWorker", HeldExportWait)
    target = tmp_path / "exact-retained-fixture.json"
    monkeypatch.setattr(reports.QFileDialog, "getSaveFileName", lambda *_args: (str(target), "JSON reports (*.json)"))
    dialog = reports.AfterActionReportDialog({"fixture": "exact complete report"})
    try:
        assert dialog.export_complete_report()
        worker, = reports.active_report_exports()
        until(worker.isFinished)
        assert json.loads(target.read_bytes()) == {"fixture": "exact complete report"}
        assert dialog._export_handles and dialog._activities.snapshot()
        assert not reports.report_export_retirement_proven(worker)
        assert not reports.poll_report_export_retirement(worker)
        worker.allow_native_proof.set()
        assert reports.poll_report_export_retirement(worker)
        assert not dialog._export_handles and not dialog._activities.snapshot()
        assert "exported" in dialog.review_status.text()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        assert not isValid(worker) and reports.report_export_retirement_proven(worker)
    finally:
        dialog.close()
        dialog.deleteLater()


def test_raised_unstarted_admission_is_not_mistaken_for_native_completion(owned, monkeypatch):
    real = actions.FiniteActionWorker

    class RaisedStart(real):
        def start(self, *_args, **_kwargs):
            self._start_attempted = True
            raise RuntimeError("modeled uncertain admission")

    monkeypatch.setattr(actions, "FiniteActionWorker", RaisedStart)
    receiver = Receiver()
    receiver.worker = worker = actions.start_finite_action(lambda _owner: "inert late admission", name="UncertainStartFixture", finished=receiver.retired)
    assert worker.admission_error == "RuntimeError" and worker.retirement_uncertain
    assert QThread.wait(worker, 0) is True and QThread.isFinished(worker) is False
    assert worker in actions.active_finite_actions() and not actions.poll_finite_action_retirement(worker)
    assert receiver.rows == []
    # Explicit fixture-only resolution models a late native admission. Product
    # code never retries the failed start. Use Qt's actual start and wait so
    # this test does not abandon an unresolved owner at process teardown.
    QThread.start(worker)
    until(lambda: bool(receiver.rows) and not actions.active_finite_actions())
    assert actions.finite_action_retirement_proven(worker)
    receiver.deleteLater()
