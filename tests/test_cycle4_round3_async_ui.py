from __future__ import annotations

import os
import threading
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QDialog, QLabel, QPushButton

from angerona.gui import top_talkers, upgrade_console


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def _wait_until(predicate, timeout: float = 2.0) -> bool:
    app = _app()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        app.processEvents()
        if predicate():
            return True
        time.sleep(0.005)
    app.processEvents()
    return bool(predicate())


def test_top_talkers_ask_ai_returns_promptly_and_finishes_on_qt(monkeypatch) -> None:
    app = _app()
    monkeypatch.setattr(top_talkers, "psutil", None)
    window = top_talkers.TopTalkersDialog()
    action = QDialog(window)
    button = QPushButton("🤖 Ask AI", action)
    status = QLabel("", action)
    entered = threading.Event()
    release = threading.Event()
    request_threads = []
    messages = []
    main_thread = threading.current_thread()

    def slow_request(_name: str, _pid: int, _dest: str) -> str:
        request_threads.append(threading.current_thread())
        entered.set()
        release.wait(timeout=1.0)
        return "allow: deterministic test result"

    monkeypatch.setattr(window, "_ask_ai", slow_request)
    monkeypatch.setattr(
        top_talkers.QMessageBox,
        "information",
        lambda parent, title, body: messages.append(
            (threading.current_thread(), parent, title, body)
        ),
    )

    try:
        started_at = time.perf_counter()
        assert window._start_ai_request(
            "browser.exe", 42, "203.0.113.8:443", action, button, status
        )
        assert time.perf_counter() - started_at < 0.2
        assert entered.wait(timeout=1.0)
        assert button.isEnabled() is False
        assert status.text() == "Contacting local AI…"

        assert not window._start_ai_request(
            "second.exe", 43, "198.51.100.9:80", action, button, status
        )
        assert len(request_threads) == 1

        release.set()
        assert _wait_until(lambda: not window._ai_in_flight)
        assert request_threads[0] is not main_thread
        assert len(messages) == 1
        assert messages[0][0] is main_thread
        assert messages[0][2:] == (
            "AI recommendation",
            "allow: deterministic test result",
        )
        assert button.isEnabled() is True
        assert status.text() == "Recommendation ready."
    finally:
        release.set()
        action.reject()
        window.reject()
        app.processEvents()


def test_top_talkers_ignores_ai_result_after_close(monkeypatch) -> None:
    app = _app()
    monkeypatch.setattr(top_talkers, "psutil", None)
    window = top_talkers.TopTalkersDialog()
    window.show()
    action = QDialog(window)
    button = QPushButton("🤖 Ask AI", action)
    status = QLabel("", action)
    entered = threading.Event()
    release = threading.Event()
    messages = []

    def slow_request(_name: str, _pid: int, _dest: str) -> str:
        entered.set()
        release.wait(timeout=1.0)
        return "late result"

    monkeypatch.setattr(window, "_ask_ai", slow_request)
    monkeypatch.setattr(
        top_talkers.QMessageBox,
        "information",
        lambda *_args: messages.append("shown"),
    )

    try:
        assert window._start_ai_request("proc.exe", 7, "example:443", action, button, status)
        assert entered.wait(timeout=1.0)
        window.reject()
        app.processEvents()
        release.set()
        assert _wait_until(lambda: not window._ai_in_flight)
        assert messages == []
    finally:
        release.set()
        action.reject()
        window.reject()
        app.processEvents()


def test_upgrade_console_lists_models_without_blocking_construction(monkeypatch) -> None:
    app = _app()
    entered = threading.Event()
    release = threading.Event()
    request_threads = []
    main_thread = threading.current_thread()

    def slow_list(_self) -> list[str]:
        request_threads.append(threading.current_thread())
        entered.set()
        release.wait(timeout=1.0)
        return ["unit-model:latest"]

    monkeypatch.setattr(
        upgrade_console.AngeronaUpgradeConsole,
        "_list_ollama_models",
        slow_list,
    )

    started_at = time.perf_counter()
    window = upgrade_console.AngeronaUpgradeConsole()
    elapsed = time.perf_counter() - started_at
    try:
        assert elapsed < 0.3
        assert window._model_status.text() == "Loading local Ollama models…"
        assert window.model_box.isEnabled() is False
        assert entered.wait(timeout=1.0)

        release.set()
        assert _wait_until(lambda: not window._model_list_in_flight)
        assert request_threads[0] is not main_thread
        assert window.model_box.currentText() == "unit-model:latest"
        assert window.model_box.isEnabled() is True
        assert window._model_check_btn.isEnabled() is True
        assert window._model_status.text() == "Loaded 1 local model(s)."
    finally:
        release.set()
        window.close()
        app.processEvents()


def test_upgrade_model_check_is_single_flight_and_updates_on_qt(monkeypatch) -> None:
    app = _app()
    monkeypatch.setattr(
        upgrade_console.AngeronaUpgradeConsole,
        "_list_ollama_models",
        lambda _self: ["unit-model:latest"],
    )
    window = upgrade_console.AngeronaUpgradeConsole()
    assert _wait_until(lambda: not window._model_list_in_flight)

    entered = threading.Event()
    release = threading.Event()
    request_threads = []
    dialogs = []
    main_thread = threading.current_thread()

    def slow_check(_model: str) -> bool:
        request_threads.append(threading.current_thread())
        entered.set()
        release.wait(timeout=1.0)
        return True

    monkeypatch.setattr(window, "_model_is_available", slow_check)
    monkeypatch.setattr(
        window,
        "_copy_dialog",
        lambda title, body, command=None: dialogs.append(
            (threading.current_thread(), title, body, command)
        ),
    )

    try:
        started_at = time.perf_counter()
        window._check_model()
        assert time.perf_counter() - started_at < 0.2
        assert entered.wait(timeout=1.0)
        assert window._model_check_btn.isEnabled() is False
        assert window._model_status.text() == "Checking unit-model:latest…"

        window._check_model()
        assert len(request_threads) == 1
        assert "already running" in window._model_status.text()

        release.set()
        assert _wait_until(lambda: not window._model_check_in_flight)
        assert request_threads[0] is not main_thread
        assert len(dialogs) == 1
        assert dialogs[0][0] is main_thread
        assert dialogs[0][1] == "Model Status"
        assert "installed locally" in dialogs[0][2]
        assert dialogs[0][3] == "ollama pull unit-model:latest"
        assert window._model_check_btn.isEnabled() is True
    finally:
        release.set()
        window.close()
        app.processEvents()


def test_upgrade_console_ignores_model_check_after_close(monkeypatch) -> None:
    app = _app()
    monkeypatch.setattr(
        upgrade_console.AngeronaUpgradeConsole,
        "_list_ollama_models",
        lambda _self: ["unit-model:latest"],
    )
    window = upgrade_console.AngeronaUpgradeConsole()
    window.show()
    assert _wait_until(lambda: not window._model_list_in_flight)

    entered = threading.Event()
    release = threading.Event()
    dialogs = []

    def slow_check(_model: str) -> bool:
        entered.set()
        release.wait(timeout=1.0)
        return True

    monkeypatch.setattr(window, "_model_is_available", slow_check)
    monkeypatch.setattr(window, "_copy_dialog", lambda *_args, **_kwargs: dialogs.append("shown"))

    try:
        window._check_model()
        assert entered.wait(timeout=1.0)
        window.close()
        app.processEvents()
        assert window._accept_async_results is False

        release.set()
        assert _wait_until(lambda: not window._model_check_in_flight)
        assert dialogs == []
    finally:
        release.set()
        window.close()
        app.processEvents()
