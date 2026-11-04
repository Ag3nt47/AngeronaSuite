"""Real atomic fixture exports, with bounded inert gates and exact worker waits."""
from __future__ import annotations

import json
import threading
import time

import pytest
from PySide6.QtCore import QCoreApplication, QEvent
from PySide6.QtWidgets import QApplication
from shiboken6 import isValid

from angerona.gui import breach_display as ui


def until(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        QApplication.instance().processEvents()
        time.sleep(.005)
    assert predicate()


@pytest.fixture
def export(monkeypatch, tmp_path):
    target = tmp_path / "selected-report.json"
    prior = b'{"original":"preserved until commit"}'
    target.write_bytes(prior)
    monkeypatch.setattr(ui, "_REPORT_EXPORT_ADMISSION", True)
    assert not ui.active_report_exports()
    monkeypatch.setattr(ui.QFileDialog, "getSaveFileName", lambda *_args: (str(target), "JSON reports (*.json)"))
    entered, release = threading.Event(), threading.Event()
    gui_thread = threading.get_ident()
    real = ui.QSaveFile

    class DelayedSave:
        def __init__(self, filename):
            assert threading.get_ident() != gui_thread
            self.file = real(filename)
            self.first = True

        def __getattr__(self, name):
            return getattr(self.file, name)

        def write(self, chunk):
            if self.first:
                self.first = False
                entered.set()
                assert release.wait(5)
            return self.file.write(chunk)

    monkeypatch.setattr(ui, "QSaveFile", DelayedSave)
    yield target, prior, entered, release
    release.set()
    workers = ui.active_report_exports()
    for worker in workers:
        assert worker.wait(3000)
    until(lambda: not ui.active_report_exports())


def test_export_is_atomic_detached_and_keeps_local_wheel_until_worker_finishes(export):
    target, prior, entered, release = export
    report = {"state": "held", "details": {"original": "literal data"}, "coverage_incomplete": True}
    dialog = ui.AfterActionReportDialog(report)
    requests = []
    dialog.action_requested.connect(requests.append)
    try:
        assert dialog.export_complete_report()
        assert entered.wait(2)
        worker, = ui.active_report_exports()
        assert worker.isRunning() and dialog._activities.snapshot()
        assert target.read_bytes() == prior and not dialog.export_original_button.isEnabled()
        report["details"]["original"] = "changed after export admission"
        dialog.update_report({"state": "different later report"})
        assert not dialog.export_complete_report()  # One admitted export per dialog.
        release.set()
        until(lambda: not dialog._export_handles and not ui.active_report_exports())
        assert json.loads(target.read_bytes()) == {
            "state": "held", "details": {"original": "literal data"}, "coverage_incomplete": True}
        assert not dialog._activities.snapshot() and dialog.export_original_button.isEnabled()
        assert "exported" in dialog.review_status.text() and not requests
    finally:
        release.set()
        dialog.close()
        dialog.deleteLater()


def test_destroyed_report_window_does_not_destroy_its_live_export_worker(export):
    target, prior, entered, release = export
    dialog = ui.AfterActionReportDialog({"fixture": "detached ownership"})
    assert dialog.export_complete_report() and entered.wait(2)
    worker, = ui.active_report_exports()
    dialog.close()
    dialog.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    assert not isValid(dialog) and isValid(worker) and worker.isRunning()
    assert worker in ui.active_report_exports() and target.read_bytes() == prior
    release.set()
    until(lambda: not ui.active_report_exports())
    assert json.loads(target.read_bytes()) == {"fixture": "detached ownership"}


def test_shutdown_closes_export_admission_and_cancels_before_atomic_commit(export):
    target, prior, entered, release = export
    dialog = ui.AfterActionReportDialog({"fixture": list(range(50))})
    try:
        assert dialog.export_complete_report() and entered.wait(2)
        worker, = ui.active_report_exports()
        ui.hold_report_exports()
        assert worker.isInterruptionRequested() and worker in ui.active_report_exports()
        other = ui.AfterActionReportDialog({"fixture": "must not start"})
        try:
            assert not other.export_complete_report()
            assert "held" in other.review_status.text()
        finally:
            other.close()
            other.deleteLater()
        release.set()
        until(lambda: not ui.active_report_exports())
        assert target.read_bytes() == prior and not dialog._export_handles
        assert "not exported" in dialog.review_status.text()
        assert not list(target.parent.glob("*.tmp"))
    finally:
        release.set()
        dialog.close()
        dialog.deleteLater()


def test_plain_export_capture_rejects_arbitrary_copy_hooks_and_cycles():
    called = []

    class Unknown:
        def __deepcopy__(self, _memo):
            called.append(True)
            raise AssertionError("Untrusted copy hook must never execute")

    with pytest.raises(ValueError, match="unsupported"):
        ui._detach_export_report({"unknown": Unknown()})
    cycle = []
    cycle.append(cycle)
    with pytest.raises(ValueError, match="cyclic"):
        ui._detach_export_report(cycle)
    assert not called
