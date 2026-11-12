"""Entry point: `python -m angerona`."""
from __future__ import annotations

import sys
import os
from types import ModuleType


def _run_kernel_telemetry_canary(arguments: tuple[str, ...]) -> int:
    """Run only the fixed inert packaged probe, before application startup.

    This route grants no engine, response or elevation authority. Frozen
    Windows builds retain the same immutable process-bound package admission;
    neither this helper nor its caller ever requests a UAC handoff.
    """
    import re

    if (len(arguments) != 2 or arguments[0] != "--kernel-telemetry-canary"
            or re.fullmatch(r"DRILLCANARY_[0-9A-F]{16}", arguments[1]) is None):
        print("[Angerona] Invalid kernel telemetry canary arguments.", file=sys.stderr, flush=True)
        return 2
    if bool(getattr(sys, "frozen", False)) and sys.platform == "win32":
        from angerona.core.windows_package_identity import verify_current_msix_authority

        authority = verify_current_msix_authority()
        if not authority.trusted:
            print("[Angerona] Refusing packaged telemetry canary: " + authority.reason,
                  file=sys.stderr, flush=True)
            return 2
    import time

    time.sleep(2.0)
    return 0


def _run_red_team_inert_probe(arguments: tuple[str, ...]) -> int:
    """Fixed tagged idle target. It accepts neither executable code nor paths."""
    import re
    if (len(arguments) != 2 or arguments[0] != "--red-team-inert-probe"
            or re.fullmatch(r"ANGERONA_REDTEAM_[0-9a-f]{8}", arguments[1]) is None):
        print("[Angerona] Invalid inert Red Team target arguments.", file=sys.stderr, flush=True)
        return 2
    import time
    time.sleep(30)
    return 0


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


def _source_activation_pending_at(base) -> bool:
    """Presence/redirect predicate only; production supplies the OS-known folder."""
    from pathlib import Path
    import stat
    base = Path(base)
    if not base.is_absolute():
        raise OSError("Canonical source storage is not absolute")
    pending = base / "Angerona" / "SourceData" / "github-updates" / "activation-pending.json"
    for path in (*reversed(pending.parents), pending):
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if (stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400
                or stat.S_ISREG(info.st_mode) and info.st_nlink != 1):
            raise OSError("Source activation storage has uncertain custody")
    return os.path.lexists(pending)


def _background_entry_requested(arguments) -> bool:
    """A background failure must never create a modal retry storm.

    This affects presentation only. Malformed reserved variants remain quiet
    and still fail their custody/argument checks; no worker gains authority.
    """
    prefixes = (
        "--process-snapshot-worker", "--curated-tool-worker", "--community-tool-probe",
        "--red-team-tool-worker", "--red-team-inert-probe", "--kernel-telemetry-canary",
        "--ugcap-worker", "--spyware-beacon-watch", "--engine-service", "--response-service",
        "--automatic-start", "--control-authority",
    )
    return (any(type(argument) is str and argument.startswith(prefixes) for argument in arguments)
            or os.environ.get("ANGERONA_SUPERVISED_RECOVERY") == "1"
            or os.environ.get("ANGERONA_EXTERNAL_WATCHDOG") == "1")


def _source_storage_lookup_error(operation, code=None):
    error = OSError("Canonical source storage is unavailable")
    error.source_storage_operation = operation
    if type(code) is int and -(1 << 31) <= code < (1 << 32):
        error.source_storage_code = code & 0xffffffff
    return error


def _source_storage_known_folder():
    """Resolve LocalAppData from our actual Windows token, not a child profile.

    SHGetKnownFolderPath(NULL) can expand USERPROFILE from the calling process.
    Helpers intentionally replace that variable with a private scratch profile.
    An explicit current-user token keeps this custody check at the real source
    activation store, including when the scratch profile happens to exist.
    """
    import ctypes
    from ctypes import wintypes as w
    from pathlib import Path
    class GUID(ctypes.Structure):
        _fields_ = [("a", w.DWORD), ("b", w.WORD), ("c", w.WORD), ("d", ctypes.c_ubyte * 8)]
    guid = GUID(0xF1B32785, 0x6FBA, 0x4FCF, (ctypes.c_ubyte * 8)(0x9D, 0x55, 0x7B, 0x8E, 0x7F, 0x15, 0x70, 0x91))
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    ole = ctypes.WinDLL("ole32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel.GetCurrentProcess.argtypes, kernel.GetCurrentProcess.restype = (), w.HANDLE
    kernel.CloseHandle.argtypes, kernel.CloseHandle.restype = (w.HANDLE,), w.BOOL
    advapi.OpenProcessToken.argtypes = (w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE))
    advapi.OpenProcessToken.restype = w.BOOL
    shell.SHGetKnownFolderPath.argtypes = (ctypes.POINTER(GUID), w.DWORD, w.HANDLE, ctypes.POINTER(ctypes.c_void_p))
    shell.SHGetKnownFolderPath.restype = ctypes.c_long
    ole.CoTaskMemFree.argtypes, ole.CoTaskMemFree.restype = (ctypes.c_void_p,), None
    token = w.HANDLE()
    # TOKEN_QUERY | TOKEN_IMPERSONATE, as required for an explicit folder token.
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008 | 0x0004, ctypes.byref(token)):
        raise _source_storage_lookup_error("token-open", ctypes.get_last_error())
    if not token.value:
        raise _source_storage_lookup_error("token-open")
    try:
        result = ctypes.c_void_p()
        try:
            status = shell.SHGetKnownFolderPath(ctypes.byref(guid), 0, token, ctypes.byref(result))
            if status != 0 or not result.value:
                raise _source_storage_lookup_error("folder-query", status)
            return Path(ctypes.wstring_at(result.value))
        finally:
            if result.value:
                ole.CoTaskMemFree(result)
    finally:
        # Never retry an ambiguous numeric handle. Failure still holds startup.
        if not kernel.CloseHandle(token):
            raise _source_storage_lookup_error("token-close", ctypes.get_last_error())


def _source_activation_pending_guard() -> bool:
    """Hold mixed source before engine imports; package __init__ already ran.

    This presence check executes no transaction or pending-supplied command.
    Canonical startup alone may verify/reconcile the approved original capsule.
    """
    if bool(getattr(sys, "frozen", False)) or sys.platform != "win32":
        return False
    import ctypes
    from ctypes import wintypes as w
    message = ""
    phase = "canonical-user-folder"
    try:
        base = _source_storage_known_folder()
        phase = "activation-store-custody"
        if _source_activation_pending_at(base):
            message = ("An interrupted source update is retained. Angerona's engines were not started. "
                       "Run start-angerona.bat so Safe Startup can verify the approved original recovery capsule. "
                       "Unknown or damaged evidence remains held; no approval is inferred.")
    except Exception as error:
        operation = getattr(error, "source_storage_operation", None)
        code = getattr(error, "source_storage_code", None)
        native_diagnostic = ""
        if type(operation) is str and operation in {"token-open", "folder-query", "token-close"}:
            native_diagnostic = f" Native operation: {operation}."
            if type(code) is int and 0 <= code <= 0xffffffff:
                native_diagnostic += f" Native code: 0x{code:08x}."
        message = ("Source update custody could not be checked. Angerona's engines were not started. "
                   "Run start-angerona.bat for Safe Startup. Existing source and evidence were preserved. "
                   f"Diagnostic phase: {phase}; error type: {type(error).__name__[:80]}." + native_diagnostic)
    if not message:
        return False
    print("[Angerona Safe Startup] " + message, file=sys.stderr, flush=True)
    if _background_entry_requested(sys.argv[1:]):
        # Parent-owned startup/job diagnostics retain stderr and the nonzero
        # result. Hidden helpers must not open a foreground Win32 MessageBox.
        return True
    # A fixed system UI remains available even when application/Qt files are
    # mixed. Never import those files just to display the held explanation.
    try:
        user = ctypes.WinDLL("user32", use_last_error=True)
        user.MessageBoxW.argtypes, user.MessageBoxW.restype = (w.HWND, w.LPCWSTR, w.LPCWSTR, w.UINT), ctypes.c_int
        user.MessageBoxW(None, message, "Angerona Safe Startup — source update held", 0x10 | 0x40000)
    except Exception:
        pass
    return True

def main() -> int:
    if sys.argv[1:2] == ["--control-authority"]:
        # Elevated STOP/RESUME helper (UAC). Exact arity; no GUI or Config.
        if len(sys.argv) != 3:
            return 2
        from angerona.resilience.control_authority import main as control_main
        return control_main(sys.argv[2:])
    red_team_diagnostic_entry = sys.argv[1:] == ["--red-team-tool-worker"]
    if red_team_diagnostic_entry:
        try:
            os.write(2, b'ANGERONA_REDTEAM_STARTUP {"phase":"entry","status":"started","error_type":"","elapsed_ms":0}\n')
        except OSError:
            pass
    if _source_activation_pending_guard():
        if red_team_diagnostic_entry:
            try:
                os.write(2, b'ANGERONA_REDTEAM_STARTUP {"phase":"source-pending-guard","status":"failed","error_type":"EntryGuardHeld","elapsed_ms":0}\n')
            except OSError:
                pass
        return 85
    if red_team_diagnostic_entry:
        try:
            os.write(2, b'ANGERONA_REDTEAM_STARTUP {"phase":"source-pending-guard","status":"completed","error_type":"","elapsed_ms":0}\n')
        except OSError:
            pass
    if any(argument.startswith("--kernel-telemetry-canary") for argument in sys.argv[1:]):
        # Reserved malformed variants must also fail here; they must never
        # fall through to Config, GUI startup or automatic-start mutation.
        return _run_kernel_telemetry_canary(tuple(sys.argv[1:]))
    from angerona.core.privilege import (
        ElevationResult, OPERATOR_ELEVATION_ARGUMENT, ensure_admin, is_admin,
    )

    frozen = bool(getattr(sys, "frozen", False))
    installed_windows = frozen and sys.platform == "win32"
    arguments = sys.argv[1:]
    operator_elevation = any(arg.startswith(OPERATOR_ELEVATION_ARGUMENT) for arg in arguments)
    console_requested = any(arg.startswith("--protection-console") for arg in arguments)
    console_endpoint = None
    if operator_elevation or console_requested:
        from angerona.core.startup_protocol import parse_startup_arguments

        try:
            clean, ready = parse_startup_arguments(sys.argv)
        except ValueError as error:
            print(f"[Angerona] {error}.", flush=True)
            return 2
        if operator_elevation:
            if (not installed_windows or ready is None
                    or clean[1:] != [OPERATOR_ELEVATION_ARGUMENT, "--chill"]):
                print("[Angerona] Request administrator mode from the installed Angerona settings.",
                      flush=True)
                return 2
        elif clean[1:] == ["--protection-console"] and (ready is None or installed_windows):
            console_endpoint = ready
        else:
            print("[Angerona] Invalid installed service status arguments.", flush=True)
            return 2
    if "--automatic-start" in sys.argv[1:]:
        # An inhibit-only flag: scheduled/recovery launches cannot resume STOP.
        os.environ["ANGERONA_SUPERVISED_RECOVERY"] = "1"
        sys.argv = [arg for arg in sys.argv if arg != "--automatic-start"]
    process_worker = "--process-snapshot-worker" in sys.argv[1:]
    curated_worker = "--curated-tool-worker" in sys.argv[1:]
    community_worker = any(arg.startswith("--community-tool-probe") for arg in sys.argv[1:])
    red_team_worker = any(arg.startswith("--red-team-tool-worker") for arg in sys.argv[1:])
    inert_probe = any(arg.startswith("--red-team-inert-probe") for arg in sys.argv[1:])
    if red_team_worker and sys.argv[1:] != ["--red-team-tool-worker"]:
        print("[Angerona] Invalid standalone Red Team worker arguments.", file=sys.stderr, flush=True)
        return 2
    if inert_probe:
        import re
        if (len(sys.argv) != 3 or sys.argv[1] != "--red-team-inert-probe"
                or re.fullmatch(r"ANGERONA_REDTEAM_[0-9a-f]{8}", sys.argv[2]) is None):
            print("[Angerona] Invalid inert Red Team target arguments.", file=sys.stderr, flush=True)
            return 2
    if community_worker and (len(sys.argv) != 6 or sys.argv[1] != "--community-tool-probe"
            or sys.argv[2] != "--request" or sys.argv[4] != "--sha256"):
        print("[Angerona] Invalid community rule probe arguments.", file=sys.stderr, flush=True)
        return 2
    if curated_worker and (len(sys.argv) != 3 or sys.argv[1] != "--curated-tool-worker"):
        print("[Angerona] Invalid curated scanner worker arguments.", file=sys.stderr, flush=True)
        return 2
    if process_worker and sys.argv[1:] != ["--process-snapshot-worker"]:
        print("[Angerona] Invalid process inventory worker arguments.", file=sys.stderr, flush=True)
        return 2
    setup_requested = "--setup" in sys.argv
    chill_requested = "--chill" in sys.argv
    engine_flags = {"--engine-console", "--engine-serve", "--engine-service", "--response-service", "--protection-console"}.intersection(sys.argv)
    if len(engine_flags) > 1:
        print("[Angerona] Choose exactly one engine launch mode.", flush=True)
        return 2
    engine_mode = next(iter(engine_flags), "")
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
        if community_worker:
            if is_admin():
                print("[Angerona] Community rule probes require an ordinary-user worker.", file=sys.stderr, flush=True)
                return 2
            from angerona.core.community_tool_probe_worker import worker_main
            return worker_main(sys.argv[2:])
        if red_team_worker or inert_probe:
            if is_admin():
                print("[Angerona] Red Team tools require an ordinary-user worker.", file=sys.stderr, flush=True)
                return 2
            if inert_probe:
                return _run_red_team_inert_probe(tuple(sys.argv[1:]))
            from angerona.gui.red_team_app import worker_main
            return worker_main()
        if curated_worker:
            # A maintained external scanner remains an ordinary-user child.
            # Package identity is still proved; this entry never requests UAC.
            if is_admin():
                print("[Angerona] Curated scanners require an ordinary-user worker.",
                      file=sys.stderr, flush=True)
                return 2
            from angerona.core.curated_tool_worker import main as curated_worker_main
            return curated_worker_main(sys.argv[2:])
        if process_worker:
            # The child inherits its parent's token. It must verify packaged
            # authority, but must never trigger a separate UAC handoff.
            from angerona.telemetry.process_snapshot_worker import worker_main
            return worker_main()
        # The detachable desktop console is an ordinary-user client. A signed
        # SCM package enters through its own native dispatcher. Neither route
        # requests elevation implicitly or bypasses the exact package pin.
        if engine_mode:
            if engine_mode not in {"--engine-service", "--response-service"} and is_admin():
                print("[Angerona] Open the engine console in an ordinary-user session.", flush=True)
                return 2
            if console_endpoint is not None:
                return _run_engine_mode(engine_mode, startup_endpoint=console_endpoint)
            return _run_engine_mode(engine_mode, **({"force_chill": True} if chill_requested else {}))
        if not operator_elevation:
            if is_admin() or sys.argv[1:]:
                print("[Angerona] Open Angerona normally and use Settings to request administrator mode.",
                      flush=True)
                return 2
            return _run_engine_mode("--protection-console")
        from angerona.core.windows_package_identity import require_current_package_image

        try:
            require_current_package_image("Angerona.exe")
        except OSError:
            print("[Angerona] The administrator request did not come from the installed package image.",
                  flush=True)
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

    if curated_worker:
        # The source privilege guard above applies before reading the private
        # bounded request. No Config, Qt, singleton or security engine is loaded.
        from angerona.core.curated_tool_worker import main as curated_worker_main
        return curated_worker_main(sys.argv[2:])

    if community_worker:
        from angerona.core.community_tool_probe_worker import worker_main
        return worker_main(sys.argv[2:])

    if inert_probe:
        return _run_red_team_inert_probe(tuple(sys.argv[1:]))

    if red_team_worker:
        from angerona.gui.red_team_app import worker_main
        return worker_main()

    if process_worker:
        # The ordinary-source privilege guard above still applies. No Config,
        # Qt, singleton, resilience service or module graph is constructed.
        from angerona.telemetry.process_snapshot_worker import worker_main
        return worker_main()

    if "--spyware-beacon-watch" in sys.argv:
        from angerona.core.spyware_beacon import watch_main
        return watch_main()

    if "--ugcap-worker" in sys.argv:
        from angerona.core.ugcap_worker import worker_main
        return worker_main()

    if engine_mode:
        return _run_engine_mode(engine_mode, **({"force_chill": True} if chill_requested else {}))

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

    if os.environ.get("ANGERONA_SUPERVISED_RECOVERY") == "1":
        from angerona.resilience.shutdown_token import (
            is_standdown_requested, signal_external_watchdog_stop,
        )
        if is_standdown_requested():
            signal_external_watchdog_stop()
            return 0

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
    except Exception as error:
        # A logging failure must neither hide its coverage gap nor prevent the
        # dashboard from starting. Keep details private and stderr bounded.
        diagnostic_written = False
        try:
            from angerona.core.data_paths import data_dir
            from angerona.core.startup_diagnostics import StartupDiagnostics
            diagnostic_written = StartupDiagnostics(data_dir()).record(
                "crash-log-arming", "unavailable",
                reason="Crash logger installer/import failed; startup continues.",
                exception_type=type(error).__name__[:64], process_role="core",
                error_code=getattr(error, "winerror", None) or getattr(error, "errno", None),
                coverage="Crash capture was not verified by this installer attempt.",
            )
        except Exception:
            diagnostic_written = False
        try:
            print(f"[Angerona] Crash logging unavailable ({type(error).__name__[:64]}; "
                  f"private receipt {'written' if diagnostic_written else 'unavailable'}). Startup continues.",
                  file=sys.stderr, flush=True)
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
    if lock is None and operator_elevation:
        print("[Angerona] A protected dashboard is already running.", flush=True)
        return 2

    # Headless mode: silent sensor / home-server node. Build the core service
    # graph WITHOUT importing PySide6 so the suite runs on a box with no Qt.
    if "--headless" in sys.argv:
        if lock is None:
            print("[Angerona] Already running — refusing a second instance.", flush=True)
            return 0
        from angerona.core.headless import run_headless
        from angerona.core.process_snapshot_lifecycle import ProcessSnapshotLifecycle
        inventory = ProcessSnapshotLifecycle()
        try:
            return run_headless(
                process_snapshot_lifecycle=inventory,
                **({"force_chill": True} if chill_requested else {}),
            )
        finally:
            inventory.request_stop()
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
        arg for arg in application_args
        if arg not in {"--setup", "--chill", "--live-debug", OPERATOR_ELEVATION_ARGUMENT}
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
    from angerona.core.process_snapshot_lifecycle import ProcessSnapshotLifecycle
    inventory = ProcessSnapshotLifecycle()
    try:
        app = AngeronaApp(
            qt, force_chill=chill_requested, startup_endpoint=startup_endpoint,
            process_snapshot_lifecycle=inventory,
            **({"live_debug": True} if "--live-debug" in application_args else {}),
        )
    except BaseException:
        inventory.request_stop()
        raise
    app._instance_lock = lock  # keep the lock socket alive for the app's lifetime
    try:
        if app.start() is False:
            return 0
        if setup_requested:
            from PySide6.QtCore import QTimer
            QTimer.singleShot(700, app.window, app.window._queue_setup_notice)
        return qt.exec()
    finally:
        app.shutdown()


def _run_engine_mode(mode: str, *, force_chill: bool = False,
                     startup_endpoint: str | None = None) -> int:
    """Route before the embedded GUI singleton so only the engine owns sensors."""
    if mode == "--protection-console":
        from angerona.core.persistent_engine import _require_user
        _require_user()
        _install_fast_pyside_feature_detection()
        from angerona.gui.protection_service_console import run_console
        return run_console(startup_endpoint=startup_endpoint) if startup_endpoint is not None else run_console()
    if mode == "--response-service":
        from angerona.core.response_service_host import run_dispatcher
        try:
            return run_dispatcher()
        except PermissionError as error:
            print(f"[Angerona] Isolated response broker unavailable: {error}.", flush=True)
            return 2
    if mode == "--engine-service":
        from angerona.core.engine_windows_service import run_dispatcher
        return run_dispatcher()
    if mode == "--engine-serve":
        from angerona.core.persistent_engine import serve
        return serve()
    from angerona.core.persistent_engine import _require_user
    _require_user()
    from angerona.core.data_paths import configure_runtime_environment
    configure_runtime_environment()
    _install_fast_pyside_feature_detection()
    from PySide6.QtWidgets import QApplication
    from angerona.gui.engine_console import EngineConsole
    qt = QApplication([sys.argv[0]])
    qt.setApplicationName("Angerona Protection Console")
    qt.setQuitOnLastWindowClosed(True)
    from angerona.core.config import Config
    from angerona.gui.theme import build_qss
    from angerona.branding import icon_path
    from PySide6.QtGui import QIcon
    config = Config.load()
    qt.setStyleSheet(build_qss(config.theme))
    icon = icon_path()
    if icon:
        qt.setWindowIcon(QIcon(icon))
    window = EngineConsole(**({"force_chill": True} if force_chill else {}))
    window.show()
    return qt.exec()


if __name__ == "__main__":
    raise SystemExit(main())
