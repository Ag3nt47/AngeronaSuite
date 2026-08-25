from __future__ import annotations

import os
import sys
import threading

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt, qInstallMessageHandler
from PySide6.QtWidgets import QApplication

from angerona.gui import upgrade_console


class _HoldingPool:
    def __init__(self) -> None:
        self.jobs: list[object] = []

    def start(self, worker, _priority: int = 0) -> None:
        self.jobs.append(worker)


def test_upgrade_console_immediate_close_during_pack_status_is_quiet(
    monkeypatch,
) -> None:
    app = QApplication.instance() or QApplication([])
    pool = _HoldingPool()
    python_errors: list[BaseException] = []
    qt_messages: list[str] = []

    def capture_thread_error(args: threading.ExceptHookArgs) -> None:
        python_errors.append(args.exc_value)

    monkeypatch.setattr(upgrade_console, "_upgrade_ui_pool", lambda: pool)
    monkeypatch.setattr(
        upgrade_console.AngeronaUpgradeConsole,
        "_refresh_watchdog",
        lambda _self: None,
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
        assert len(pool.jobs) == 1
        # The held worker proves close is not coupled to request completion;
        # elapsed-time limits would only measure scheduler load on the host.
        window.close()
        app.processEvents()

        errors: list[BaseException] = []

        def run_worker() -> None:
            try:
                pool.jobs.pop().run()
            except BaseException as exc:  # pragma: no cover - assertion aid
                errors.append(exc)

        thread = threading.Thread(target=run_worker)
        thread.start()
        thread.join(timeout=10.0)
        assert not thread.is_alive()
        assert errors == []
        for _ in range(6):
            app.processEvents()

        assert python_errors == []
        assert not any(
            "signal source has been deleted" in message.casefold()
            for message in qt_messages
        )
    finally:
        qInstallMessageHandler(previous_handler)
