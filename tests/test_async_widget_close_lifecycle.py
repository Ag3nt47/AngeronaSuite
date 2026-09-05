from __future__ import annotations

import os
import threading
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import shiboken6
from PySide6.QtCore import QCoreApplication, QEvent, Qt
from PySide6.QtWidgets import QApplication

from angerona.gui.pages import AlertsPanel, DashboardCards, ModuleInspector, ThreatWindow
from angerona.gui.scan_center import ScanCenterPanel


_QAPP: QApplication | None = None


def _app() -> QApplication:
    global _QAPP
    _QAPP = QApplication.instance() or QApplication([])
    return _QAPP


def _drain_deletes(app: QApplication) -> None:
    app.processEvents()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    app.processEvents()


def _close_during_worker(
    widget,
    worker: threading.Thread,
    entered: threading.Event,
    release: threading.Event,
    errors: list[BaseException],
) -> None:
    app = _app()
    try:
        assert entered.wait(timeout=1.0)
        assert worker.is_alive()
        assert widget.close()
        deadline = time.monotonic() + 1.0
        while shiboken6.isValid(widget) and time.monotonic() < deadline:
            _drain_deletes(app)
            time.sleep(0.005)
        assert not shiboken6.isValid(widget)
    finally:
        release.set()
        worker.join(timeout=2.0)
        _drain_deletes(app)
    assert not worker.is_alive()
    assert errors == []


def _capture_worker_errors(monkeypatch) -> list[BaseException]:
    errors: list[BaseException] = []
    monkeypatch.setattr(
        threading,
        "excepthook",
        lambda args: errors.append(args.exc_value),
    )
    return errors


class _Bus:
    def recent(self, _limit: int) -> list:
        return []


class _Manager:
    modules: dict = {}

    @staticmethod
    def is_enabled(_name: str) -> bool:
        return True


class _BlockingStorage:
    def __init__(self, entered: threading.Event, release: threading.Event) -> None:
        self.entered = entered
        self.release = release

    @staticmethod
    def revision() -> int:
        return 1

    def try_count_since(self, _since: float) -> int:
        self.entered.set()
        self.release.wait(timeout=3.0)
        return 7

    def try_recent(self, _limit: int) -> list:
        self.entered.set()
        self.release.wait(timeout=3.0)
        return []


class _BlockingModule:
    name = "Lifecycle Probe"
    category = "Test"
    version = "1"
    description = "Deterministic close-lifecycle probe."
    health_state = "ok"
    health = 100
    health_note = ""
    status = "running"
    enabled_by_default = True
    mitre_tags: tuple = ()
    last_error = ""
    _throttle = 1.0
    _thread = None

    def __init__(self, entered: threading.Event, release: threading.Event) -> None:
        self.entered = entered
        self.release = release

    def self_test(self) -> tuple[bool, str]:
        self.entered.set()
        self.release.wait(timeout=3.0)
        return True, "complete"

    def start(self) -> None:
        return None

    def stop(self) -> None:
        return None


def test_scan_center_drops_result_after_delete(monkeypatch) -> None:
    app = _app()
    entered = threading.Event()
    release = threading.Event()
    errors = _capture_worker_errors(monkeypatch)
    panel = ScanCenterPanel()
    panel.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
    panel.show()
    app.processEvents()
    monkeypatch.setattr(panel, "_service", lambda: object())

    def operation(_service, _cancellation, _progress) -> dict:
        entered.set()
        release.wait(timeout=3.0)
        return {"status": "completed", "findings": [], "summary": "complete"}

    panel._start("Lifecycle scan", operation)
    worker = panel._worker_thread
    assert worker is not None
    _close_during_worker(panel, worker, entered, release, errors)


def test_dashboard_cards_drop_count_after_delete(monkeypatch) -> None:
    app = _app()
    entered = threading.Event()
    release = threading.Event()
    errors = _capture_worker_errors(monkeypatch)
    cards = DashboardCards(_Bus(), _BlockingStorage(entered, release), _Manager())
    cards.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
    cards.show()
    app.processEvents()

    cards.refresh()
    worker = cards._count_worker
    assert worker is not None
    _close_during_worker(cards, worker, entered, release, errors)


def test_threat_window_drops_action_after_delete(monkeypatch) -> None:
    app = _app()
    entered = threading.Event()
    release = threading.Event()
    errors = _capture_worker_errors(monkeypatch)
    dialog = ThreatWindow(_Bus(), object(), _Manager())
    dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
    dialog.show()
    app.processEvents()

    def action() -> str:
        entered.set()
        release.wait(timeout=3.0)
        return "complete"

    dialog._run_async(action)
    worker = dialog._action_worker
    assert worker is not None
    _close_during_worker(dialog, worker, entered, release, errors)


def test_module_inspector_drops_selftest_after_delete(monkeypatch) -> None:
    app = _app()
    entered = threading.Event()
    release = threading.Event()
    errors = _capture_worker_errors(monkeypatch)
    module = _BlockingModule(entered, release)
    dialog = ModuleInspector(_Manager(), _Bus(), module)
    dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
    dialog.show()
    app.processEvents()

    dialog._selftest()
    worker = dialog._test_worker
    assert worker is not None
    _close_during_worker(dialog, worker, entered, release, errors)


def test_module_inspector_timeout_releases_ui_but_retains_check_lock(monkeypatch) -> None:
    from angerona.core import selftest
    from PySide6.QtTest import QTest

    app = _app()
    entered, release = threading.Event(), threading.Event()
    module = _BlockingModule(entered, release)
    dialog = ModuleInspector(_Manager(), _Bus(), module)
    bounded = selftest.run_module_selftest
    monkeypatch.setattr(selftest, "run_module_selftest", lambda mod, timeout: bounded(mod, 0.02))
    try:
        dialog._selftest()
        assert entered.wait(1)
        dialog._test_worker.join(1)
        app.processEvents()
        assert "timed out" in dialog.test_lbl.text()
        assert dialog.selftest_btn.isEnabled()
        assert selftest.module_selftest_lock(module).locked()
        previous = dialog._test_worker
        dialog._selftest()
        assert "No duplicate" in dialog.test_lbl.text()
        assert dialog._test_worker is previous
    finally:
        release.set()
        deadline = time.monotonic() + 2
        while selftest.module_selftest_lock(module).locked() and time.monotonic() < deadline:
            QTest.qWait(5)
        dialog.close()
    assert not selftest.module_selftest_lock(module).locked()


def test_alerts_panel_drops_storage_result_after_delete(monkeypatch) -> None:
    app = _app()
    entered = threading.Event()
    release = threading.Event()
    errors = _capture_worker_errors(monkeypatch)
    panel = AlertsPanel(_BlockingStorage(entered, release), bus=_Bus())
    panel.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
    panel.show()
    app.processEvents()

    panel.refresh()
    worker = panel._events_worker
    assert worker is not None
    _close_during_worker(panel, worker, entered, release, errors)
