"""Actual threads and signed journal boundaries; no live suite/process control."""
from __future__ import annotations

import os
import threading
import time
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import QApplication, QMainWindow, QWidget

from angerona.core import remediation_log, report_attest
from angerona.gui import main_window
from angerona.gui.shutdown_retirement import RetainedWorker, ShutdownRetirement, worker_retired


@pytest.fixture
def app():
    return QApplication.instance() or QApplication([])


def wait(app, predicate):
    end = time.monotonic() + 3
    while time.monotonic() < end:
        app.processEvents()
        if predicate():
            return
        time.sleep(.005)
    raise AssertionError("Exact owned test worker did not retire")


class ExportWorker(QThread):
    result_ready = Signal(str)
    def __init__(self, release):
        super().__init__()
        self.release = release
        self.early = threading.Event()
    def run(self):
        self.result_ready.emit("Cosmetic result is not native retirement")
        self.early.set()
        self.release.wait(3)


def make(owner, tmp_path, *, workers=lambda: (), cleanup=lambda: None, critical=None, **kwargs):
    finished, diagnostics = [], []
    retirement = ShutdownRetirement(owner, workers=workers, cleanup=cleanup, critical=critical,
        finish=finished.append, data_root=tmp_path,
        diagnostic_writer=lambda _root, payload: diagnostics.append(payload), **kwargs)
    retirement.start()
    return retirement, finished, diagnostics


def test_zero_worker_stop_runs_cleanup_once_and_finishes_retired(app, tmp_path):
    owner, calls = QWidget(), []
    retirement, finished, diagnostics = make(owner, tmp_path, cleanup=lambda: calls.append("cleanup"))
    wait(app, lambda: bool(finished))
    assert calls == ["cleanup"] and finished[0]["state"] == "retired"
    assert finished[0]["forced"] is False and finished[0]["pending_workers"] == []
    assert diagnostics[-1]["state"] == "retired" and retirement.start() is False
    owner.close()


def test_export_early_result_never_substitutes_for_actual_native_retirement(app, tmp_path):
    owner, release = QWidget(), threading.Event()
    export = ExportWorker(release)
    export.start()
    wait(app, export.early.is_set)
    retirement, finished, _ = make(owner, tmp_path,
        workers=lambda: (RetainedWorker("atomic-export", export),))
    try:
        app.processEvents()
        retirement.poll()
        assert not finished and worker_retired(export) is False
        export.requestInterruption()  # Request alone is not observed exit.
        retirement.poll()
        assert not finished
        release.set()
        wait(app, lambda: bool(finished))
        assert worker_retired(export) and finished[0]["state"] == "retired"
    finally:
        release.set()
        wait(app, lambda: worker_retired(export))
        owner.close()


def test_durable_patch_commit_precedes_store_cleanup_while_critical_cleanup_runs(app, tmp_path, monkeypatch):
    monkeypatch.setattr(report_attest, "_load_key", lambda: b"s" * 32)
    store = remediation_log.RemediationLog(tmp_path / "flight-recorder.db")
    release, prepared, critical_done = threading.Event(), threading.Event(), threading.Event()
    custody, cleaned = {}, []
    def patch():
        record = {"action": "inert-stop-test", "mitre": "T1112", "compensation_ready": True,
                  "mutation_started": False, "verified": True, "ok": True}
        capability = store.prepare_transaction(trigger="inert-stop-test", mitre="T1112",
            action_key="inert-stop-test", action_title="Inert fixture", host_level=False, record=record)
        record.update(transaction_id=capability.transaction_id, mutation_started=True)
        store.transition_transaction(capability, state="MUTATING", record=record)
        prepared.set()
        release.wait(3)
        proof = store.finish_transaction(capability, result="applied", record=record)
        custody.update(transaction=capability.transaction_id, proof=proof)
    patch_thread = threading.Thread(target=patch, daemon=True)
    patch_thread.start()
    wait(app, prepared.is_set)
    def cleanup():
        proof = custody["proof"]
        assert store.verify_committed_application(custody["transaction"], proof["receipt_hash"], proof["receipt_id"],
            expected_mitre="T1112", expected_action="inert-stop-test") is True
        cleaned.append("stores may now close")
    owner = QWidget()
    retirement, finished, _ = make(owner, tmp_path, cleanup=cleanup, critical=critical_done.set,
        workers=lambda: (RetainedWorker("admitted-patch", patch_thread, True),))
    try:
        wait(app, critical_done.is_set)
        retirement.poll()
        assert cleaned == [] and not finished and store.transaction(1)["state"] == "MUTATING"
        release.set()
        wait(app, lambda: bool(finished))
        assert cleaned == ["stores may now close"] and finished[0]["state"] == "retired"
        assert not store.unresolved_transactions()
    finally:
        release.set()
        wait(app, lambda: not patch_thread.is_alive())
        owner.close()
        store.close()


def test_dropped_ui_reference_does_not_drop_retained_worker_generation(app, tmp_path):
    owner, release = QWidget(), threading.Event()
    worker = threading.Thread(target=lambda: release.wait(3), daemon=True)
    worker.start()
    live = [RetainedWorker("old-view-generation", worker)]
    retirement, finished, _ = make(owner, tmp_path, workers=lambda: tuple(live))
    try:
        live.clear()  # The cosmetic result removed its owner's attribute.
        retirement.poll()
        assert not finished and any(row.worker is worker for row in retirement._retained.values())
        release.set()
        wait(app, lambda: bool(finished))
        assert finished[0]["state"] == "retired"
    finally:
        release.set()
        wait(app, lambda: not worker.is_alive())
        owner.close()


def test_timeout_is_explicitly_incomplete_and_never_waits_or_destroys_running_qthread(app, tmp_path):
    owner, release, now = QWidget(), threading.Event(), [0.0]
    export = ExportWorker(release)
    export.start()
    wait(app, export.early.is_set)
    cleaned = []
    retirement, finished, diagnostics = make(owner, tmp_path, timeout=1, clock=lambda: now[0],
        workers=lambda: (RetainedWorker("unretired-export", export),), cleanup=lambda: cleaned.append(True))
    try:
        wait(app, lambda: bool(cleaned))
        now[0] = 1.1
        retirement.poll()
        wait(app, lambda: bool(finished))
        assert finished[0]["state"] == "forced-incomplete" and finished[0]["forced"] is True
        assert finished[0]["pending_workers"] == ["unretired-export"] and cleaned == [True]
        assert diagnostics[-1]["state"] == "forced-incomplete" and export.isRunning()
    finally:
        release.set()
        wait(app, lambda: worker_retired(export))
        owner.close()


def test_blocked_diagnostic_writer_cannot_be_reported_as_clean_retirement(app, tmp_path):
    owner, release, now = QWidget(), threading.Event(), [0.0]
    finished = []
    retirement = ShutdownRetirement(owner, workers=lambda: (), cleanup=lambda: None,
        finish=finished.append, data_root=tmp_path, clock=lambda: now[0], diagnostic_timeout=.1,
        diagnostic_writer=lambda *_args: release.wait(3))
    retirement.start()
    try:
        wait(app, lambda: retirement._final is not None)
        now[0] = 1.0
        retirement.poll()
        assert finished and finished[0]["forced"] is True
        assert "shutdown-diagnostic-writer" in finished[0]["pending_workers"]
        assert finished[0]["diagnostic_persisted"] is False
    finally:
        release.set()
        wait(app, lambda: not retirement._diagnostic_thread.is_alive())
        owner.close()


def test_cleanup_exception_is_never_labelled_clean(app, tmp_path):
    owner = QWidget()
    def broken():
        raise OSError("Inert cleanup error")
    _, finished, _ = make(owner, tmp_path, cleanup=broken)
    wait(app, lambda: bool(finished))
    assert finished[0]["forced"] is True and finished[0]["cleanup_error"] == "OSError"
    owner.close()


def test_repeated_main_stop_keeps_one_durable_intent_and_one_retirement_generation(app, tmp_path):
    calls, finished = [], []
    class Shell(QMainWindow):
        _terminate = main_window.MainWindow._terminate
        _retained_shutdown_custody = main_window.MainWindow._retained_shutdown_custody
        def __init__(self):
            super().__init__()
            self._termination_started = False
            self._sim_launch_job = None
            self._simulation_session = None
            self._shutdown_prepare = lambda: calls.append("durable-stop")
            self._shutdown_critical = lambda: calls.append("critical")
            self.config = SimpleNamespace(data_dir=tmp_path)
        def _hold_shutdown_views(self):
            calls.append("admissions-closed")
        def _retained_shutdown_workers(self):
            return ()
        def _operator_stop_cleanup(self):
            calls.append("cleanup")
        def _operator_stop_progress(self, *_args):
            return
        def _operator_stop_finish(self, value):
            finished.append(value)
    shell = Shell()
    shell._terminate()
    generation = shell._operator_stop_retirement
    shell._terminate()
    wait(app, lambda: bool(finished))
    assert shell._operator_stop_retirement is generation
    assert calls.count("durable-stop") == calls.count("critical") == calls.count("cleanup") == 1
    assert calls.index("admissions-closed") < calls.index("critical") < calls.index("cleanup")
    shell.close()


@pytest.mark.parametrize("forced", [False, True])
def test_main_forced_exit_skips_qt_teardown_but_normal_retirement_allows_it(monkeypatch, forced):
    from angerona.core import process_exit
    calls = []
    class SelfExit(Exception):
        pass
    def exit_self():
        calls.append("self-exit")
        raise SelfExit()
    monkeypatch.setattr(process_exit, "exit_after_operator_shutdown", exit_self)
    monkeypatch.setattr(main_window, "QApplication", SimpleNamespace(instance=lambda:
        SimpleNamespace(quit=lambda: calls.append("qt-quit"))))
    shell = SimpleNamespace(_holographic_orb=SimpleNamespace(shutdown=lambda: calls.append("orb")),
        tray=SimpleNamespace(hide=lambda: calls.append("tray")))
    with pytest.raises(SelfExit):
        main_window.MainWindow._operator_stop_finish(shell, {"forced": forced})
    assert calls == (["self-exit"] if forced else ["orb", "tray", "qt-quit", "self-exit"])


def test_stop_denies_new_after_action_mutation_before_other_admission_checks():
    shell = SimpleNamespace(_termination_started=True)
    assert main_window.MainWindow._admit_aar_work(shell, object(), "patch") is False
