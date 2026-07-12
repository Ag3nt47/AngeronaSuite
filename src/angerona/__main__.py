"""Entry point: `python -m angerona`."""
from __future__ import annotations

import sys


def main() -> int:
    # Capture any crash (unhandled exception, background-thread exception, or a
    # native Qt fault) to a log file. Under pythonw there is no console, so this
    # is the only trace we'd otherwise get. Writes to
    # %LOCALAPPDATA%\Angerona\logs\crash.log and the repo's diagnostics\crash.log.
    try:
        from angerona.core.crashlog import install as _install_crashlog
        _install_crashlog()
    except Exception:
        pass

    # Ensure we're elevated for full-system telemetry (no-op if already admin
    # or on a non-Windows dev box).
    from angerona.core.privilege import ensure_admin
    ensure_admin()

    # Self-harden this process (block legacy injection vectors, remote/low-IL
    # image loads, weak ASLR) before we load Qt and the module set. Best-effort;
    # never allowed to stop startup.
    try:
        from angerona.core.hardening import apply_process_mitigations
        apply_process_mitigations()
    except Exception:
        pass

    # Refuse to start a second copy (avoids stacked instances / duplicate scanners).
    from angerona.core.singleton import acquire_single_instance
    lock = acquire_single_instance()

    # Headless mode: silent sensor / home-server node. Build the core service
    # graph WITHOUT importing PySide6 so the suite runs on a box with no Qt.
    if "--headless" in sys.argv:
        if lock is None:
            print("[Angerona] Already running — refusing a second instance.", flush=True)
            return 0
        from angerona.core.headless import run_headless
        try:
            return run_headless()
        finally:
            try:
                lock.close()
            except Exception:
                pass

    from PySide6.QtGui import QIcon
    from PySide6.QtWidgets import QApplication, QMessageBox
    qt = QApplication(sys.argv)
    qt.setApplicationName("Angerona")

    # Custom shield icon (assets/icons/angerona.ico) — sets the taskbar/
    # alt-tab icon for the whole process, including the "already running"
    # dialog below, which fires before MainWindow (and its own
    # setWindowIcon call) ever gets created.
    from angerona.branding import icon_path
    _icon_file = icon_path()
    if _icon_file:
        qt.setWindowIcon(QIcon(_icon_file))

    if lock is None:
        QMessageBox.information(
            None, "Angerona already running",
            "Angerona is already running — look for the shield icon in your system "
            "tray. Use the tray menu to open it or to Quit.")
        return 0

    qt.setQuitOnLastWindowClosed(False)  # keep running in the system tray

    from angerona.app import AngeronaApp
    app = AngeronaApp(qt)
    app._instance_lock = lock  # keep the lock socket alive for the app's lifetime
    app.start()
    return qt.exec()


if __name__ == "__main__":
    raise SystemExit(main())
