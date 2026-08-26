from __future__ import annotations

import os
import threading

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QDialog, QLabel, QPushButton

from angerona.core.model_pack_manager import (
    AdmissionPlan,
    BUILTIN_CATALOG_SHA256,
    ResourceSnapshot,
    load_catalog,
)
from angerona.gui import top_talkers, upgrade_console


PACK_ID = "aria-defense-llama3"


class _FakePackManager:
    def __init__(self) -> None:
        self.catalog = load_catalog(
            "assets/aria_model_packs.json",
            expected_sha256=BUILTIN_CATALOG_SHA256,
        )
        self.installed = False
        self.state_threads: list[threading.Thread] = []
        self.install_threads: list[threading.Thread] = []

    def state(self) -> dict:
        self.state_threads.append(threading.current_thread())
        return {
            "active_pack": None,
            "installed": {PACK_ID: {}} if self.installed else {},
            "activation_history": [],
        }

    def admission_plan(self, pack_id: str) -> AdmissionPlan:
        pack = self.catalog[pack_id]
        available = ResourceSnapshot(2**40, 2**40, 2**40)
        return AdmissionPlan(pack_id, True, pack.requirements, available, ())

    def install(self, pack_id: str) -> dict:
        self.install_threads.append(threading.current_thread())
        self.installed = True
        return {"action": "install", "pack_id": pack_id}

    def activate(self, pack_id: str) -> dict:
        return {"action": "activate", "pack_id": pack_id}

    def rollback(self) -> dict:
        return {"action": "rollback"}

    def remove(self, pack_id: str) -> dict:
        self.installed = False
        return {"action": "remove", "pack_id": pack_id}

    def runbook_roots(self) -> tuple:
        return ()


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


class _HoldingPool:
    """Record Qt jobs so tests, rather than host load, control scheduling."""

    def __init__(self) -> None:
        self.jobs: list[tuple[object, int]] = []

    def start(self, worker, priority: int = 0) -> None:
        self.jobs.append((worker, priority))

    def take(self):
        worker, _priority = self.jobs.pop(0)
        return worker


def _run_off_qt(worker) -> threading.Thread:
    """Run a captured QRunnable on a real non-Qt thread, then join it."""
    errors: list[BaseException] = []

    def run() -> None:
        try:
            worker.run()
        except BaseException as exc:  # pragma: no cover - assertion aid
            errors.append(exc)

    thread = threading.Thread(target=run)
    thread.start()
    thread.join(timeout=10.0)
    assert not thread.is_alive(), "captured UI worker did not finish"
    assert errors == []
    return thread


def _process_queued_signals() -> None:
    app = _app()
    # A fixed event-pump count drains the worker signal and any signal emitted
    # by its stable bridge.  It deliberately makes no wall-clock assumption.
    for _ in range(6):
        app.processEvents()


def test_top_talkers_ask_ai_returns_promptly_and_finishes_on_qt(monkeypatch) -> None:
    app = _app()
    pool = _HoldingPool()
    monkeypatch.setattr(top_talkers, "_top_talkers_pool", lambda: pool)
    monkeypatch.setattr(top_talkers, "psutil", None)
    window = top_talkers.TopTalkersDialog()
    action = QDialog(window)
    button = QPushButton("🤖 Ask AI", action)
    status = QLabel("", action)
    request_threads = []
    messages = []
    main_thread = threading.current_thread()

    def request(_name: str, _pid: int, _dest: str) -> str:
        request_threads.append(threading.current_thread())
        return "allow: deterministic test result"

    monkeypatch.setattr(window, "_ask_ai", request)
    monkeypatch.setattr(
        top_talkers.QMessageBox,
        "information",
        lambda parent, title, body: messages.append(
            (threading.current_thread(), parent, title, body)
        ),
    )

    try:
        assert window._start_ai_request(
            "browser.exe", 42, "203.0.113.8:443", action, button, status
        )
        # Scheduling is the only synchronous operation: the request has not
        # run on the Qt thread and remains under deterministic test control.
        assert request_threads == []
        assert len(pool.jobs) == 1
        assert pool.jobs[0][1] > 0
        assert button.isEnabled() is False
        assert status.text() == "Contacting local AI…"

        assert not window._start_ai_request(
            "second.exe", 43, "198.51.100.9:80", action, button, status
        )
        assert len(pool.jobs) == 1

        worker_thread = _run_off_qt(pool.take())
        _process_queued_signals()
        assert window._ai_in_flight is False
        assert request_threads[0] is not main_thread
        assert request_threads[0] is worker_thread
        assert len(messages) == 1
        assert messages[0][0] is main_thread
        assert messages[0][2:] == (
            "AI recommendation",
            "allow: deterministic test result",
        )
        assert button.isEnabled() is True
        assert status.text() == "Recommendation ready."
    finally:
        action.reject()
        window.reject()
        app.processEvents()


def test_top_talkers_ignores_ai_result_after_close(monkeypatch) -> None:
    app = _app()
    pool = _HoldingPool()
    monkeypatch.setattr(top_talkers, "_top_talkers_pool", lambda: pool)
    monkeypatch.setattr(top_talkers, "psutil", None)
    window = top_talkers.TopTalkersDialog()
    window.show()
    action = QDialog(window)
    button = QPushButton("🤖 Ask AI", action)
    status = QLabel("", action)
    messages = []

    def request(_name: str, _pid: int, _dest: str) -> str:
        return "late result"

    monkeypatch.setattr(window, "_ask_ai", request)
    monkeypatch.setattr(
        top_talkers.QMessageBox,
        "information",
        lambda *_args: messages.append("shown"),
    )

    try:
        assert window._start_ai_request("proc.exe", 7, "example:443", action, button, status)
        assert len(pool.jobs) == 1
        window.reject()
        app.processEvents()
        _run_off_qt(pool.take())
        _process_queued_signals()
        assert window._ai_in_flight is False
        assert messages == []
    finally:
        action.reject()
        window.reject()
        app.processEvents()


def test_upgrade_console_loads_curated_pack_status_without_blocking_construction(
    monkeypatch,
) -> None:
    app = _app()
    pool = _HoldingPool()
    main_thread = threading.current_thread()
    manager = _FakePackManager()

    monkeypatch.setattr(upgrade_console, "_upgrade_ui_pool", lambda: pool)
    monkeypatch.setattr(
        upgrade_console.AngeronaUpgradeConsole,
        "_refresh_watchdog",
        lambda _self: None,
    )
    monkeypatch.setattr(
        upgrade_console.AngeronaUpgradeConsole,
        "_refresh_telemetry",
        lambda _self: None,
    )
    window = upgrade_console.AngeronaUpgradeConsole(model_pack_manager=manager)
    try:
        # Construction only submits the bounded request.  This structural
        # assertion remains valid even on a heavily loaded CI/desktop host.
        assert manager.state_threads == []
        assert len(pool.jobs) == 1
        assert "Loading curated pack" in window._model_status.text()
        assert window.model_box.isEditable() is False
        assert window.model_box.currentData() == PACK_ID

        worker_thread = _run_off_qt(pool.take())
        _process_queued_signals()
        assert window._pack_status_in_flight is False
        assert manager.state_threads[0] is not main_thread
        assert manager.state_threads[0] is worker_thread
        assert "resource admission admitted" in window._model_status.text()
        assert window._pack_install_btn.isEnabled() is True
    finally:
        window.close()
        app.processEvents()


def test_upgrade_console_ignores_stale_pack_status_token(monkeypatch) -> None:
    app = _app()
    pool = _HoldingPool()
    manager = _FakePackManager()
    monkeypatch.setattr(upgrade_console, "_upgrade_ui_pool", lambda: pool)
    monkeypatch.setattr(
        upgrade_console.AngeronaUpgradeConsole,
        "_refresh_watchdog",
        lambda _self: None,
    )
    monkeypatch.setattr(
        upgrade_console.AngeronaUpgradeConsole,
        "_refresh_telemetry",
        lambda _self: None,
    )
    window = upgrade_console.AngeronaUpgradeConsole(model_pack_manager=manager)
    try:
        current = window._pack_status_token
        before = window._model_status.text()
        window._handle_async_result(
            "pack_status",
            current + 100,
            {"active_pack": "forged", "can_rollback": True, "packs": {}},
        )
        assert window._pack_status_in_flight is True
        assert window._pack_snapshot == {}
        assert window._model_status.text() == before

        _run_off_qt(pool.take())
        _process_queued_signals()
        assert window._pack_status_in_flight is False
        assert PACK_ID in window._pack_snapshot["packs"]
    finally:
        window.close()
        app.processEvents()


def test_upgrade_pack_install_is_single_flight_and_updates_on_qt(monkeypatch) -> None:
    app = _app()
    pool = _HoldingPool()
    monkeypatch.setattr(upgrade_console, "_upgrade_ui_pool", lambda: pool)
    monkeypatch.setattr(
        upgrade_console.AngeronaUpgradeConsole,
        "_refresh_watchdog",
        lambda _self: None,
    )
    monkeypatch.setattr(
        upgrade_console.AngeronaUpgradeConsole,
        "_refresh_telemetry",
        lambda _self: None,
    )
    manager = _FakePackManager()
    window = upgrade_console.AngeronaUpgradeConsole(model_pack_manager=manager)
    _run_off_qt(pool.take())
    _process_queued_signals()
    main_thread = threading.current_thread()
    monkeypatch.setattr(window, "_rebuild_pack_runbooks", lambda: 0)

    try:
        assert window._start_pack_operation("install", PACK_ID)
        assert manager.install_threads == []
        assert len(pool.jobs) == 1
        assert window._pack_install_btn.isEnabled() is False
        assert window._model_status.text() == "Install in progress…"

        assert not window._start_pack_operation("install", PACK_ID)
        assert len(pool.jobs) == 1
        assert "already running" in window._model_status.text()

        worker_thread = _run_off_qt(pool.take())
        _process_queued_signals()
        assert window._pack_operation_in_flight is False
        assert manager.install_threads[0] is not main_thread
        assert manager.install_threads[0] is worker_thread
        assert "authenticated receipt" in window._model_status.text()
        assert len(pool.jobs) == 1  # asynchronous post-mutation status refresh
        _run_off_qt(pool.take())
        _process_queued_signals()
        assert window._pack_activate_btn.isEnabled() is True
    finally:
        window.close()
        app.processEvents()


def test_upgrade_console_ignores_pack_result_after_close(monkeypatch) -> None:
    app = _app()
    pool = _HoldingPool()
    monkeypatch.setattr(upgrade_console, "_upgrade_ui_pool", lambda: pool)
    monkeypatch.setattr(
        upgrade_console.AngeronaUpgradeConsole,
        "_refresh_watchdog",
        lambda _self: None,
    )
    monkeypatch.setattr(
        upgrade_console.AngeronaUpgradeConsole,
        "_refresh_telemetry",
        lambda _self: None,
    )
    manager = _FakePackManager()
    window = upgrade_console.AngeronaUpgradeConsole(model_pack_manager=manager)
    window.show()
    _run_off_qt(pool.take())
    _process_queued_signals()
    assert window._pack_status_in_flight is False
    rebuilt: list[str] = []
    monkeypatch.setattr(window, "_rebuild_pack_runbooks", lambda: rebuilt.append("yes") or 0)

    try:
        assert window._start_pack_operation("install", PACK_ID)
        assert len(pool.jobs) == 1
        window.close()
        app.processEvents()
        assert window._accept_async_results is False

        _run_off_qt(pool.take())
        _process_queued_signals()
        assert window._pack_operation_in_flight is False
        assert rebuilt == ["yes"]
        assert len(pool.jobs) == 0
    finally:
        window.close()
        app.processEvents()
