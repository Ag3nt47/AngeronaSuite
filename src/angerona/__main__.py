"""Entry point: `python -m angerona`."""
from __future__ import annotations

import sys
from types import ModuleType


def _install_fast_pyside_feature_detection() -> bool:
    """Avoid Shiboken rereading every imported source file during startup.

    PySide's feature hook normally calls ``inspect.getsource()`` after imports
    to decide whether a module uses PySide.  Angerona does not use
    ``from __feature__`` anywhere, and on antivirus-inspected Windows volumes
    those redundant reads can block for tens of seconds per module.  A module
    that explicitly imports ``__feature__`` registers itself before this
    fallback runs, so replacing only the fallback preserves that mechanism.
    """
    try:
        import shibokensupport.feature as feature

        if bool(getattr(feature, "_angerona_fast_detection", False)):
            return True
        original = feature._mod_uses_pyside

        def _uses_pyside_without_source_read(module) -> bool:
            name = str(getattr(module, "__name__", ""))
            if name.startswith(("PySide6", "shiboken6", "shibokensupport")):
                return bool(original(module))
            # All Angerona code uses PySide's default naming/property behavior.
            # Selecting the default explicitly avoids source inspection while
            # preserving the exact API exposed before this optimization.
            if name == "angerona" or name.startswith("angerona."):
                return True
            try:
                for value in vars(module).values():
                    origin = (
                        value.__name__
                        if isinstance(value, ModuleType)
                        else getattr(value, "__module__", "")
                    )
                    if str(origin).startswith("PySide6"):
                        return True
            except (AttributeError, RuntimeError, TypeError):
                pass
            return False

        feature._mod_uses_pyside = _uses_pyside_without_source_read
        feature._angerona_fast_detection = True
        return True
    except (AttributeError, ImportError, RuntimeError):
        # Compatibility fallback for a future PySide build that changes this
        # private hook. Startup remains correct, only less optimized.
        return False

def main() -> int:
    setup_requested = "--setup" in sys.argv
    chill_requested = "--chill" in sys.argv
    frozen = bool(getattr(sys, "frozen", False))
    from angerona.core.privilege import ElevationResult, ensure_admin, is_admin
    if frozen and sys.platform == "win32":
        # Packaging metadata is not privilege authority.  Prove the exact
        # process-bound MSIX family/publisher before UAC, then prove it again
        # after ensure_admin returns in the elevated child.
        from angerona.core.windows_package_identity import (
            verify_current_msix_authority,
        )
        authority = verify_current_msix_authority()
        if not authority.trusted:
            print(
                "[Angerona] Refusing privileged frozen execution: "
                f"{authority.reason}.",
                flush=True,
            )
            return 2
        elevation = ensure_admin()
        authority_after_elevation = verify_current_msix_authority()
        effective_administrator = is_admin()
        if (
            not isinstance(elevation, ElevationResult)
            or not elevation.effective_administrator
            or not effective_administrator
            or not authority_after_elevation.trusted
        ):
            elevation_reason = (
                elevation.reason
                if isinstance(elevation, ElevationResult)
                else "the elevation helper returned no typed result"
            )
            print(
                "[Angerona] Refusing frozen execution after UAC: "
                f"{elevation_reason}; {authority_after_elevation.reason}; "
                "the complete post-UAC package and Administrator authority "
                "was not proven.",
                flush=True,
            )
            return 2
    elif sys.platform == "win32" and is_admin():
        # A mutable checkout is not privileged execution authority, even when
        # started manually from an already-elevated terminal.
        print(
            "[Angerona] Refusing elevated source execution. Use a normal user "
            "session for Observe/development coverage, or install the signed "
            "MSIX for full Windows Protect coverage.",
            flush=True,
        )
        return 2

    # Keep sys.argv intact for the UAC handoff above. The helper's loopback
    # readiness option belongs to Angerona and must not reach Qt's parser.
    from angerona.core.startup_protocol import parse_startup_arguments
    try:
        application_args, startup_endpoint = parse_startup_arguments(sys.argv)
    except ValueError as error:
        print(f"[Angerona] {error}.", flush=True)
        return 2

    # Establish the canonical install-drive/ProgramData runtime boundary before
    # crash logging, singleton locks, Qt, or scanner imports can create files.
    from angerona.core.data_paths import configure_runtime_environment
    configure_runtime_environment()

    # Stop child processes (netsh, tasklist, signal-cli, yara, git, …) from
    # flashing console windows every time a module runs one. Must happen before
    # any module loads. Best-effort; no-op off Windows.
    try:
        from angerona.core.win import install_no_window_default
        install_no_window_default()
    except Exception:
        pass

    # Capture any crash (unhandled exception, background-thread exception, or a
    # native Qt fault) to a log file. Under pythonw there is no console, so this
    # is the only trace we'd otherwise get. Writes to
    # <runtime-data>\logs\crash.log and diagnostics\crash.log.
    try:
        from angerona.core.crashlog import install as _install_crashlog
        _install_crashlog()
    except Exception:
        pass

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
    _install_fast_pyside_feature_detection()
    # ``--setup`` is an Angerona switch, not a Qt switch. Remove it before Qt
    # parses arguments so the same dedicated setup shortcut works in source and
    # frozen releases without an unknown-option warning.
    qt = QApplication([
        arg for arg in application_args if arg not in {"--setup", "--chill"}
    ])
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
    app = AngeronaApp(
        qt, force_chill=chill_requested, startup_endpoint=startup_endpoint,
    )
    app._instance_lock = lock  # keep the lock socket alive for the app's lifetime
    app.start()
    if setup_requested:
        from PySide6.QtCore import QTimer
        QTimer.singleShot(700, app.window._open_setup)
    return qt.exec()


if __name__ == "__main__":
    raise SystemExit(main())
