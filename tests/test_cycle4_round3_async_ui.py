from __future__ import annotations

import os
import threading

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QDialog, QLabel, QPushButton

from angerona.gui import top_talkers, upgrade_console


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


def test_upgrade_console_lists_models_without_blocking_construction(monkeypatch) -> None:
    app = _app()
    pool = _HoldingPool()
    request_threads = []
    main_thread = threading.current_thread()

    def list_models(_self) -> list[str]:
        request_threads.append(threading.current_thread())
        return ["unit-model:latest"]

    monkeypatch.setattr(upgrade_console, "_upgrade_ui_pool", lambda: pool)
    monkeypatch.setattr(
        upgrade_console.AngeronaUpgradeConsole,
        "_refresh_watchdog",
        lambda _self: None,
    )
    monkeypatch.setattr(
        upgrade_console.AngeronaUpgradeConsole,
        "_list_ollama_models",
        list_models,
    )

    window = upgrade_console.AngeronaUpgradeConsole()
    try:
        # Construction only submits the bounded request.  This structural
        # assertion remains valid even on a heavily loaded CI/desktop host.
        assert request_threads == []
        assert len(pool.jobs) == 1
        assert window._model_status.text() == "Loading local Ollama models…"
        assert window.model_box.isEnabled() is False

        worker_thread = _run_off_qt(pool.take())
        _process_queued_signals()
        assert window._model_list_in_flight is False
        assert request_threads[0] is not main_thread
        assert request_threads[0] is worker_thread
        assert window.model_box.currentText() == "unit-model:latest"
        assert window.model_box.isEnabled() is True
        assert window._model_check_btn.isEnabled() is True
        assert window._model_status.text() == "Loaded 1 local model(s)."
    finally:
        window.close()
        app.processEvents()


def test_upgrade_model_check_is_single_flight_and_updates_on_qt(monkeypatch) -> None:
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
        "_list_ollama_models",
        lambda _self: ["unit-model:latest"],
    )
    window = upgrade_console.AngeronaUpgradeConsole()
    _run_off_qt(pool.take())
    _process_queued_signals()
    assert window._model_list_in_flight is False

    request_threads = []
    dialogs = []
    main_thread = threading.current_thread()

    def check(_model: str) -> bool:
        request_threads.append(threading.current_thread())
        return True

    monkeypatch.setattr(window, "_model_is_available", check)
    monkeypatch.setattr(
        window,
        "_copy_dialog",
        lambda title, body, command=None: dialogs.append(
            (threading.current_thread(), title, body, command)
        ),
    )

    try:
        window._check_model()
        assert request_threads == []
        assert len(pool.jobs) == 1
        assert window._model_check_btn.isEnabled() is False
        assert window._model_status.text() == "Checking unit-model:latest…"

        window._check_model()
        assert request_threads == []
        assert len(pool.jobs) == 1
        assert "already running" in window._model_status.text()

        worker_thread = _run_off_qt(pool.take())
        _process_queued_signals()
        assert window._model_check_in_flight is False
        assert request_threads[0] is not main_thread
        assert request_threads[0] is worker_thread
        assert len(dialogs) == 1
        assert dialogs[0][0] is main_thread
        assert dialogs[0][1] == "Model Status"
        assert "installed locally" in dialogs[0][2]
        assert dialogs[0][3] == "ollama pull unit-model:latest"
        assert window._model_check_btn.isEnabled() is True
    finally:
        window.close()
        app.processEvents()


def test_upgrade_console_ignores_model_check_after_close(monkeypatch) -> None:
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
        "_list_ollama_models",
        lambda _self: ["unit-model:latest"],
    )
    window = upgrade_console.AngeronaUpgradeConsole()
    window.show()
    _run_off_qt(pool.take())
    _process_queued_signals()
    assert window._model_list_in_flight is False

    dialogs = []

    def check(_model: str) -> bool:
        return True

    monkeypatch.setattr(window, "_model_is_available", check)
    monkeypatch.setattr(window, "_copy_dialog", lambda *_args, **_kwargs: dialogs.append("shown"))

    try:
        window._check_model()
        assert len(pool.jobs) == 1
        window.close()
        app.processEvents()
        assert window._accept_async_results is False

        _run_off_qt(pool.take())
        _process_queued_signals()
        assert window._model_check_in_flight is False
        assert dialogs == []
    finally:
        window.close()
        app.processEvents()
