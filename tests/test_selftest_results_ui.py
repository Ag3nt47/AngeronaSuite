"""Exercise self-test result controls without constructing the live dashboard."""
from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

pytest.importorskip("PySide6")
from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtTest import QTest
from PySide6.QtWidgets import (
    QApplication, QDialog, QMainWindow, QMessageBox, QPlainTextEdit, QPushButton,
)

from angerona.gui import main_window
from angerona.gui.main_window import MainWindow


class _ManualModule:
    selftest_auto_repair = False


class _RestartableModule:
    selftest_auto_repair = True


class _Spinner:
    def __init__(self):
        self.messages = []

    def start(self, message):
        self.messages.append(message)

    def finish(self, message):
        self.messages.append(message)


class _Harness(QMainWindow):
    _selftest_done = Signal(str, object)
    _selftest_progress = Signal(int, int)
    _selftest_repair_done = Signal(object, object)

    _claim_self_test = MainWindow._claim_self_test
    _run_self_test = MainWindow._run_self_test
    _self_test_worker = MainWindow._self_test_worker
    _on_selftest_done = MainWindow._on_selftest_done
    _prompt_selftest_fix = MainWindow._prompt_selftest_fix
    _selftest_results_closed = MainWindow._selftest_results_closed
    _retry_selftest_results = MainWindow._retry_selftest_results
    _eligible_selftest_failures = MainWindow._eligible_selftest_failures
    _start_selftest_repairs = MainWindow._start_selftest_repairs
    _selftest_repair_worker = MainWindow._selftest_repair_worker
    _on_selftest_repair_done = MainWindow._on_selftest_repair_done

    def __init__(self):
        super().__init__()
        self._selftest_active = threading.Event()
        self._selftest_btn = QPushButton("Self-test", self)
        self._selftest_btn.resize(100, 30)
        self.logs = []
        self.busy = []
        self.console = SimpleNamespace(
            _append=self.logs.append,
            _start_busy=lambda: self.busy.append(True),
            _end_busy=lambda: self.busy.append(False),
        )
        self.run_spinner = _Spinner()
        self.manager = SimpleNamespace(modules={})
        self.bus = SimpleNamespace()
        self.opened_modules = []
        self._selftest_done.connect(self._on_selftest_done)
        self._selftest_repair_done.connect(self._on_selftest_repair_done)

    def _open_module_window(self, name):
        self.opened_modules.append(name)


@pytest.fixture
def window():
    result = _Harness()
    yield result
    dialog = getattr(result, "_selftest_results", None)
    if dialog is not None:
        dialog.close()
    result.close()
    result.deleteLater()


def _attention_items():
    return [
        {"module": "AI Triage (Ollama)", "detail": "local model unavailable", "repairable": False},
        {"module": "AV Telemetry Bridge", "detail": "continuity evidence gap", "repairable": False},
        {"module": "Adversary Combat", "detail": "recovery required", "repairable": False},
    ]


def _show_results(window, failures):
    window._last_selftest_report = "Full test report\nA diagnostic failure remains visible."
    window._prompt_selftest_fix(failures)
    return window._selftest_results


def _pending_workers(monkeypatch):
    started = []

    class PendingThread:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def start(self):
            started.append(self.kwargs)

    monkeypatch.setattr(main_window, "threading", SimpleNamespace(Thread=PendingThread))
    return started


@pytest.mark.parametrize("close_action", ["button", "escape"])
def test_results_are_nonmodal_and_parent_controls_remain_responsive(
    window, monkeypatch, close_action,
):
    def nested_modal(*args, **kwargs):
        pytest.fail("Self-test results must not enter a nested modal loop")

    monkeypatch.setattr(QDialog, "exec", nested_modal)
    for method in ("information", "warning", "critical", "question"):
        monkeypatch.setattr(QMessageBox, method, nested_modal)
    window.show()
    dialog = _show_results(window, _attention_items())
    assert dialog.isVisible()
    assert not dialog.isModal()
    assert dialog.windowModality() == Qt.WindowModality.NonModal
    assert dialog.property("_angerona_no_reveal") is True
    ticks, clicks = [], []
    window._selftest_btn.clicked.connect(lambda: clicks.append(True))
    QTimer.singleShot(0, lambda: ticks.append(True))
    QTest.mouseClick(window._selftest_btn, Qt.MouseButton.LeftButton)
    QTest.qWait(20)
    assert clicks == [True]
    assert ticks == [True]
    if close_action == "escape":
        QTest.keyClick(dialog, Qt.Key.Key_Escape)
    else:
        QTest.mouseClick(dialog.close_button, Qt.MouseButton.LeftButton)
    assert window._selftest_results is None


@pytest.mark.parametrize("reported_repairable", [False, True])
def test_manual_failures_have_working_details_copy_and_no_restart(window, reported_repairable):
    failures = _attention_items()
    for failure in failures:
        failure["repairable"] = reported_repairable
    window.manager.modules = {item["module"]: _ManualModule() for item in failures}
    dialog = _show_results(window, failures)
    assert "3 item(s) need attention" in dialog.summary.text()
    assert dialog.restart_button.isHidden()
    assert dialog.approval.isHidden()
    restarts = []
    dialog.restart_requested.connect(lambda: restarts.append(True))
    dialog._restart()
    assert restarts == []
    text = "\n".join(view.toPlainText() for view in dialog.findChildren(QPlainTextEdit))
    assert "Check that local Ollama is running" in text
    assert "cannot restore missing event records" in text
    assert "does not arm response or clear its recovery hold" in text
    for item in failures:
        assert item["detail"] in text
    previous_clipboard = QApplication.clipboard().text()
    try:
        dialog.copy_button.click()
        assert QApplication.clipboard().text() == window._last_selftest_report
    finally:
        QApplication.clipboard().setText(previous_clipboard)
    dialog.modules.setCurrentText("AV Telemetry Bridge")
    dialog.details_button.click()
    assert window.opened_modules == ["AV Telemetry Bridge"]


def test_restart_needs_explicit_approval_and_only_starts_one_worker(window, monkeypatch):
    workers = _pending_workers(monkeypatch)
    failure = {"module": "Lifecycle sensor", "detail": "worker stopped", "repairable": True}
    window.manager.modules = {"Lifecycle sensor": _RestartableModule()}
    dialog = _show_results(window, [failure])
    assert not dialog.restart_button.isEnabled()
    dialog.restart_button.click()
    dialog._restart()
    assert workers == []
    dialog.approval.setChecked(True)
    assert dialog.restart_button.isEnabled()
    dialog.restart_button.click()
    dialog.restart_button.click()
    dialog._restart()
    assert len(workers) == 1
    assert workers[0]["name"] == "AngeronaSelfTestRepair"
    assert workers[0]["args"] == ([failure],)
    assert window._selftest_active.is_set()
    assert not dialog.restart_button.isEnabled()
    assert not dialog.approval.isEnabled()


def test_recovery_errors_stay_visible_and_release_the_gate(window, monkeypatch):
    workers = _pending_workers(monkeypatch)
    failure = {"module": "Lifecycle sensor", "detail": "worker stopped", "repairable": True}
    window.manager.modules = {"Lifecycle sensor": _RestartableModule()}
    dialog = _show_results(window, [failure])
    dialog.approval.setChecked(True)
    dialog.restart_button.click()

    def failed_recovery(failures):
        raise RuntimeError("controlled recovery failure")

    window._attempt_selftest_repairs = failed_recovery
    window._selftest_repair_worker([failure])
    assert not window._selftest_active.is_set()
    assert window._selftest_btn.isEnabled()
    assert "controlled recovery failure" in dialog.summary.text()
    assert "Run self-test again to verify" in dialog.summary.text()
    assert "success" not in dialog.summary.text().casefold()
    assert dialog.retry_button.isEnabled()
    dialog.retry_button.click()
    QTest.qWait(20)
    assert len(workers) == 2
    assert workers[-1]["name"] == "AngeronaSelfTest"


def test_retry_never_starts_a_concurrent_selftest(window, monkeypatch):
    workers = _pending_workers(monkeypatch)
    dialog = _show_results(window, [])
    assert window._run_self_test() is True
    assert window._run_self_test() is False
    dialog.retry_button.click()
    window._retry_selftest_results()
    QTest.qWait(20)
    assert len(workers) == 1
    assert window._selftest_active.is_set()


def test_runner_exception_is_an_actionable_result_and_retry_remains_available(window, monkeypatch):
    from angerona.core import selftest

    workers = _pending_workers(monkeypatch)

    class FailedRunner:
        def __init__(self, *args):
            raise RuntimeError("controlled runner failure")

    monkeypatch.setattr(selftest, "SelfTestRunner", FailedRunner)
    assert window._run_self_test() is True
    window._self_test_worker()
    assert not window._selftest_active.is_set()
    assert window._selftest_btn.isEnabled()
    dialog = window._selftest_results
    assert "1 item(s) need attention" in dialog.summary.text()
    assert "controlled runner failure" in window._last_selftest_report
    assert dialog.retry_button.isEnabled()
    assert dialog.restart_button.isHidden()
    dialog.retry_button.click()
    QTest.qWait(20)
    assert len(workers) == 2


def test_worker_launch_failure_is_visible_and_does_not_strand_controls(window, monkeypatch):
    class FailedThread:
        def __init__(self, **kwargs):
            pass

        def start(self):
            raise RuntimeError("controlled worker launch failure")

    monkeypatch.setattr(main_window, "threading", SimpleNamespace(Thread=FailedThread))
    assert window._run_self_test() is False
    assert not window._selftest_active.is_set()
    assert window._selftest_btn.isEnabled()
    assert window.busy[-1] is False
    assert "Running self-test" != window.run_spinner.messages[-1]
    assert "controlled worker launch failure" in window._last_selftest_report
    assert window._selftest_results.retry_button.isEnabled()


def test_recovery_launch_failure_releases_gate_and_leaves_close_and_retry_usable(window, monkeypatch):
    class FailedThread:
        def __init__(self, **kwargs):
            pass

        def start(self):
            raise RuntimeError("controlled recovery launch failure")

    monkeypatch.setattr(main_window, "threading", SimpleNamespace(Thread=FailedThread))
    failure = {"module": "Lifecycle sensor", "detail": "worker stopped", "repairable": True}
    window.manager.modules = {"Lifecycle sensor": _RestartableModule()}
    dialog = _show_results(window, [failure])
    dialog.approval.setChecked(True)
    dialog.restart_button.click()
    assert not window._selftest_active.is_set()
    assert window._selftest_btn.isEnabled()
    assert "worker could not start" in dialog.summary.text()
    assert dialog.retry_button.isEnabled()
    assert dialog.close_button.isEnabled()
    assert "success" not in dialog.summary.text().casefold()
