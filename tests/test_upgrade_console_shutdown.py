from __future__ import annotations

import os
import sys
import threading
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QThreadPool, Qt, qInstallMessageHandler
from PySide6.QtWidgets import QApplication

from angerona.gui import upgrade_console


def test_upgrade_console_immediate_close_during_model_listing_is_quiet(
    monkeypatch,
) -> None:
    app = QApplication.instance() or QApplication([])
    entered = threading.Event()
    release = threading.Event()
    returned = threading.Event()
    python_errors: list[BaseException] = []
    qt_messages: list[str] = []

    def slow_list(_self) -> list[str]:
        entered.set()
        release.wait(timeout=2.0)
        returned.set()
        return ["unit-model:latest"]

    def capture_thread_error(args: threading.ExceptHookArgs) -> None:
        python_errors.append(args.exc_value)

    monkeypatch.setattr(
        upgrade_console.AngeronaUpgradeConsole,
        "_list_ollama_models",
        slow_list,
    )
    monkeypatch.setattr(
        sys,
        "excepthook",
        lambda _kind, value, _traceback: python_errors.append(value),
    )
    monkeypatch.setattr(threading, "excepthook", capture_thread_error)
    monkeypatch.setattr(
        sys,
        "unraisablehook",
        lambda failure: python_errors.append(failure.exc_value),
    )
    previous_handler = qInstallMessageHandler(
        lambda _kind, _context, message: qt_messages.append(message)
    )

    window = upgrade_console.AngeronaUpgradeConsole()
    window.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
    window.show()
    try:
        assert entered.wait(timeout=1.0)
        started_at = time.perf_counter()
        window.close()
        app.processEvents()
        assert time.perf_counter() - started_at < 0.2

        release.set()
        assert returned.wait(timeout=1.0)
        assert QThreadPool.globalInstance().waitForDone(2_000)
        for _ in range(4):
            app.processEvents()

        assert python_errors == []
        assert not any(
            "signal source has been deleted" in message.casefold()
            for message in qt_messages
        )
    finally:
        release.set()
        qInstallMessageHandler(previous_handler)
