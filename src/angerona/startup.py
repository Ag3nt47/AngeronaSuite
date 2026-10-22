"""Separate, bounded startup assistant; never imports or starts live sensors.

The Tk window is independent of Qt. Repairs are confined to missing startup
directories and a clean child environment. Configuration, evidence, credentials,
response policy and authenticated journals are never reset here.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import queue
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, replace
from typing import Callable

from angerona.core.startup_recovery import (
    REPAIR_EXIT_CODES, private_directory, private_repair_file, select_temporary, write_read_proof,
)


class StartupError(RuntimeError):
    """A startup condition requiring a visible, actionable explanation."""


class RepairableStartupError(StartupError):
    """A closed pre-dashboard failure; the external parent owns any repair."""

    def __init__(self, code: int, message: str):
        if type(code) is not int or code not in REPAIR_EXIT_CODES:
            raise ValueError("Unknown automatic startup repair category")
        super().__init__(message)
        self.exit_code = code


def _plain_path(path: Path) -> None:
    """Reject redirected ancestors before creating/opening our own files."""
    if not path.is_absolute() or ".." in path.parts:
        raise StartupError("Startup requires an absolute local path.")
    for part in (*reversed(path.parents), path):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise StartupError(f"Startup path is redirected: {part}")
        if stat.S_ISREG(info.st_mode) and info.st_nlink > 1:
            raise StartupError(f"Startup file has multiple links: {part}")


def prepare_storage(root: Path) -> None:
    """Repair missing helper directories and verify a real write/flush cycle."""
    for path in (root, root / "logs"):
        _plain_path(path)
        path.mkdir(parents=True, exist_ok=True)
        _plain_path(path)
        if not path.is_dir():
            raise StartupError(f"Startup storage is not a directory: {path}")
    if shutil.disk_usage(root).free < 128 * 1024 * 1024:
        raise StartupError("Less than 128 MB is free on the canonical startup data drive. Free space there and retry; a temporary directory on another drive cannot replace settings/evidence capacity.")
    write_read_proof(root / "logs")
    # A bad temp candidate does not become storage authority. A later selector
    # may create fresh private scratch on the checked installation drive, while
    # the persistent data gate above remains independently mandatory.
    temporary = root / "tmp"
    try:
        _plain_path(temporary)
        temporary.mkdir(exist_ok=True)
        _plain_path(temporary)
    except (OSError, StartupError):
        pass


class StartupLease:
    """OS lease prevents two helpers from launching competing dashboards."""

    def __init__(self, root: Path):
        path = root / "startup-helper.lock"
        _plain_path(path)
        self.root = root
        self.pid = os.getpid()
        self._references = 1
        self._reference_lock = threading.Lock()
        self.stream = path.open("a+b")
        try:
            self.stream.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self.stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self.stream.close()
            raise StartupError("Another Angerona startup window is already working. Use that window.") from exc

    def borrow(self, root: Path) -> StartupLease:
        """Retain an actual same-process lease across the UI/worker boundary."""
        with self._reference_lock:
            if self.pid != os.getpid() or self.root != root or self.stream.closed:
                raise StartupError("Startup helper custody could not be retained.")
            path = root / "startup-helper.lock"
            _plain_path(path)
            current, retained = path.stat(), os.fstat(self.stream.fileno())
            if (current.st_dev, current.st_ino) != (retained.st_dev, retained.st_ino):
                raise StartupError("Startup helper custody changed before its worker started.")
            self._references += 1
            return self

    def close(self) -> None:
        with self._reference_lock:
            if self._references <= 0:
                return
            self._references -= 1
            if self._references == 0:
                self.stream.close()  # Release custody only after UI and worker finish.


@dataclass(frozen=True)
class LaunchPlan:
    root: Path
    storage: Path
    command: tuple[str, ...]
    frozen: bool
    temporary: Path | None = None


def _assert_no_pending_repair(plan: LaunchPlan) -> None:
    if plan.frozen:
        return
    for pending in (
        plan.root / ".tmp" / "repair-wheels" / "startup-repair.pending",
        plan.root / "venv" / ".angerona-startup-repair.json",
    ):
        _plain_path(pending)
        if pending.exists():
            raise StartupError("An interrupted source repair requires recovery before startup. Run start-angerona.bat so its trusted supervisor can inspect the transaction; no runtime probe or dashboard was started.")
    parent = plan.root / ".tmp" / "repair-wheels"
    _plain_path(parent)
    if not parent.exists():
        return
    def closed_object(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise ValueError("Duplicate runtime repair resolution field")
            result[name] = value
        return result

    try:
        for count, directory in enumerate(parent.iterdir()):
            if count >= 512:
                raise ValueError("Too many startup repair entries to verify safely")
            match = re.fullmatch(r"startup-repair\.([0-9a-f]{32})", directory.name)
            if match is None:
                continue
            _plain_path(directory)
            witness = directory / "intent.witness.json"
            _plain_path(witness)
            if not witness.exists():
                continue
            if not private_directory(directory, create=False) or not private_repair_file(witness):
                raise ValueError("Runtime intent witness custody is unsafe")
            resolution = directory / "resolution.json"
            _plain_path(resolution)
            if not private_repair_file(resolution):
                raise ValueError("Runtime repair resolution custody is unsafe")
            with resolution.open("rb") as stream:
                raw = stream.read(1025)
            if len(raw) > 1024:
                raise ValueError("Runtime repair resolution is oversized")
            result = json.loads(raw, object_pairs_hook=closed_object)
            if (
                not isinstance(result, dict) or set(result) != {"Schema", "Id", "Outcome"}
                or type(result["Schema"]) is not int or result["Schema"] != 1
                or result["Id"] != match.group(1)
                or result["Outcome"] not in ("Verified", "RolledBack")
            ):
                raise ValueError("Runtime repair resolution is unknown or changed")
    except (OSError, ValueError) as exc:
        raise StartupError("Unresolved or unsafe source repair evidence requires maintainer review before startup. Preserve the repair scratch and use start-angerona.bat; no runtime probe or dashboard was started.") from exc


def _interface_lease() -> StartupLease:
    """Claim canonical helper custody before Tcl/Tk can load runtime files."""
    plan = platform_plan()
    prepare_storage(plan.storage)
    lease = StartupLease(plan.storage)
    try:
        _assert_no_pending_repair(plan)
        return lease
    except Exception:
        lease.close()
        raise


def platform_plan() -> LaunchPlan:
    if sys.platform != "win32":
        raise StartupError("This startup assistant is for Windows. Use the platform's Angerona launcher.")
    from angerona.core.privilege import _windows_known_folder, is_admin

    frozen = bool(getattr(sys, "frozen", False))
    local = _windows_known_folder(0x1C) / "Angerona"
    if frozen:
        from angerona.core.windows_package_identity import verify_current_msix_authority

        authority = verify_current_msix_authority()
        if not authority.trusted:
            raise StartupError(f"Signed installation verification failed: {authority.reason}. Use the verified MSIX installer.")
        root = Path(sys.executable).absolute().parent
        executable = root / "Angerona.exe"
        storage = local / "Startup"
    else:
        if is_admin():
            raise StartupError("Open the source launcher from a normal user session. Protected coverage requires the signed MSIX.")
        root = Path(__file__).absolute().parents[2]
        executable = root / "venv" / "Scripts" / "python.exe"
        storage = local / "SourceData"
        for required in ("start-angerona.bat", "pyproject.toml", "src/angerona/__init__.py"):
            candidate = root / required
            _plain_path(candidate)
            if not candidate.is_file():
                raise StartupError("The source checkout is incomplete. Restore it before starting Angerona.")
    _plain_path(executable)
    if not executable.is_file():
        raise StartupError("The application runtime is missing. Run start-angerona.bat for source setup, or the signed release installer.")
    from angerona.core.data_paths import _fixed_volume_available

    if not _fixed_volume_available(Path(root.anchor)):
        raise StartupError("Angerona must start from a fixed local installation drive.")
    command = (str(executable),) if frozen else (str(executable), "-m", "angerona")
    return LaunchPlan(root, storage, command, frozen)


def _source_model_directory(name: str, value: str) -> str:
    """Validate a source user's model location without trusting model contents."""
    from angerona.core.ollama_lifecycle import (
        _windows_fixed_drive,
        _windows_install_location,
    )

    message = (
        f"{name} must name an existing, nonredirected local model directory "
        "on a fixed drive. Correct this setting or remove it to use Ollama's "
        "default model folder, then retry."
    )
    location = _windows_install_location(value)
    if location is None or not _windows_fixed_drive(location.anchor):
        raise StartupError(message)
    path = Path(str(location))
    try:
        _plain_path(path)
        info = path.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 0x400
        ):
            raise StartupError(message)
    except (OSError, ValueError, StartupError) as error:
        raise StartupError(message) from error
    return str(location)


def child_environment(plan: LaunchPlan) -> dict[str, str]:
    from angerona.core.privilege import _minimal_environment

    # Do not inherit even the generic sidecar overrides: the helper owns all
    # runtime coordinates and must not propagate an inherited response command.
    environment = _minimal_environment({})
    environment.update({
        "TEMP": str(plan.temporary or plan.storage / "tmp"),
        "TMP": str(plan.temporary or plan.storage / "tmp"),
        "PYINSTALLER_RESET_ENVIRONMENT": "1",
    })
    if not plan.frozen:
        environment.update({
            "ANGERONA_DATA": str(plan.storage),
            "ANGERONA_DIAG_DIR": str(plan.storage / "diagnostics"),
            "ANGERONA_STORAGE_AUTOMIGRATE": "0",
        })
        # The source launcher and dashboard both reject elevated execution.
        # Preserve only explicit local model locations, never Ollama commands,
        # endpoints or other inherited controls. The authenticated model guard
        # still independently checks the approved root and exact model bytes.
        for name in ("ANGERONA_OLLAMA_MODELS", "OLLAMA_MODELS"):
            value = os.environ.get(name)
            if value is not None:
                environment[name] = _source_model_directory(name, value)
    return environment


def _log_file(root: Path, name: str):
    path = root / "logs" / name
    previous = path.with_suffix(".previous.log")
    for candidate in (path, previous):
        _plain_path(candidate)
        if candidate.exists() and not candidate.is_file():
            raise StartupError(f"Startup log is not a regular file: {candidate}")
    if path.exists():
        os.replace(path, previous)
    return path.open("wb")


_PROBE = """import sys, sysconfig, importlib.metadata as m
if sys.version_info[:2] != (3, 12) or sysconfig.get_platform() != 'win-amd64':
    raise SystemExit(81)
try:
    from pathlib import Path
    for line in Path('constraints-release.txt').read_text(encoding='utf-8').splitlines():
        if line.strip() and not line.lstrip().startswith('#'):
            name, version = line.strip().split('==')
            if m.version(name) != version:
                print('Reviewed dependency version is missing:', name, flush=True)
                raise SystemExit(82)
    import angerona, psutil, yaml, dotenv, cryptography, requests
except (ImportError, m.PackageNotFoundError) as exc:
    print(type(exc).__name__, str(exc), flush=True)
    raise SystemExit(82)
print('Reviewed runtime and dependency versions are ready', flush=True)
"""
_QT_PROBE = """import sys
try:
    from PySide6.QtWidgets import QApplication
    app = QApplication([])
    app.processEvents()
except (ImportError, OSError) as exc:
    print(type(exc).__name__, str(exc), flush=True)
    raise SystemExit(83)
print('Offscreen native Qt is ready', flush=True)
"""
_PIP_CHECK = """from pip._internal.commands.check import CheckCommand
result = CheckCommand(name='check', summary='Check installed dependencies').main(['--isolated'])
raise SystemExit(82 if result == 1 else result)
"""
# Only these documented native loader/crash statuses from the dedicated Qt
# process are eligible. Unknown statuses and generic exit 1 remain fail-closed.
_QT_NATIVE_FAILURES = {0xC0000005, 0xC000001D, 0xC000007B, 0xC0000135, 0xC0000142, 0xC0000409}


def probe_source(plan: LaunchPlan, environment: dict[str, str], cancel: threading.Event) -> None:
    if plan.frozen:
        return  # Main executable independently verifies package/UAC and imports Qt.
    probe_env = dict(environment, QT_QPA_PLATFORM="offscreen", PIP_CONFIG_FILE=os.devnull)
    deadline = time.monotonic() + 30
    with _log_file(plan.storage, "startup-preflight.log") as log:
        for phase, arguments in (
            ("Dependencies", ["-c", _PROBE]),
            ("Dependencies", ["-c", _PIP_CHECK]),
            ("GuiRuntime", ["-c", _QT_PROBE]),
        ):
            if cancel.is_set() or time.monotonic() >= deadline:
                raise StartupError("The dependency check was cancelled or timed out. No dashboard was started.")
            process = subprocess.Popen(
                [plan.command[0], *arguments], cwd=plan.root, env=probe_env,
                stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            while process.poll() is None:
                if cancel.wait(0.1) or time.monotonic() >= deadline:
                    # Only this disposable probe is terminated, never a dashboard.
                    process.kill()
                    process.wait(timeout=5)
                    raise StartupError("The dependency check was cancelled or timed out. See startup-preflight.log; no dashboard was started.")
            if cancel.is_set():
                raise StartupError("Startup cancelled before launching the dashboard.")
            code = process.returncode
            if code != 0:
                repair_code = code if code in REPAIR_EXIT_CODES else None
                if phase == "GuiRuntime" and (code & 0xFFFFFFFF) in _QT_NATIVE_FAILURES:
                    repair_code = 83
                message = "The Python/Qt startup check failed. See startup-preflight.log. Your settings and evidence were preserved."
                if repair_code is not None:
                    raise RepairableStartupError(repair_code, message)
                raise StartupError(message)


class ReadyListener:
    """Ephemeral, nonce-bound readiness receipt; never grants any authority."""

    def __init__(self):
        self.token = secrets.token_hex(32)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            self.socket.bind(("127.0.0.1", 0))
            self.socket.listen(2)
            self.socket.settimeout(0.2)
        except Exception:
            self.socket.close()
            raise
        self.endpoint = f"{self.socket.getsockname()[1]}:{self.token}"

    def receive(self) -> int | None:
        try:
            connection, _ = self.socket.accept()
        except socket.timeout:
            return None
        with connection:
            connection.settimeout(0.2)
            data = bytearray()
            deadline = time.monotonic() + 0.3
            try:
                while len(data) <= 256 and time.monotonic() < deadline:
                    chunk = connection.recv(257 - len(data))
                    if not chunk:
                        break
                    data.extend(chunk)
                    if b"\n" in chunk:
                        break
                if len(data) > 256:
                    return None
                payload = json.loads(data)
            except (OSError, ValueError, UnicodeError):
                return None
        if not isinstance(payload, dict) or set(payload) != {"token", "pid"}:
            return None
        if payload["token"] != self.token or type(payload["pid"]) is not int or payload["pid"] <= 0:
            return None
        return payload["pid"]

    def close(self) -> None:
        self.socket.close()


def _ready_process(pid: int, process, plan: LaunchPlan, started: float) -> bool:
    if not plan.frozen:
        if process.poll() is not None:
            return False
        if pid == process.pid:
            return True
        if sys.platform != "win32":
            return False
        # Windows venv python.exe can be a redirector that keeps its own PID
        # while the actual interpreter runs as its child. Bind that child to
        # our retained launcher and the helper's real CPython image.
        import psutil

        try:
            candidate = psutil.Process(pid)
            return (
                candidate.ppid() == process.pid
                and candidate.create_time() >= started - 1
                and Path(candidate.exe()).resolve() == Path(psutil.Process(os.getpid()).exe()).resolve()
                and candidate.is_running()
            )
        except (psutil.Error, OSError):
            return False
    # UAC can replace the initial child; require the actual installed dashboard
    # image and a fresh live process, not the pre-elevation bootstrap PID.
    import psutil

    try:
        candidate = psutil.Process(pid)
        return (
            Path(candidate.exe()).resolve() == Path(plan.command[0]).resolve()
            and candidate.create_time() >= started - 1
            and candidate.is_running()
        )
    except (psutil.Error, OSError):
        return False


def wait_dashboard(listener: ReadyListener, process, plan: LaunchPlan, started: float,
                   cancel: threading.Event, timeout: float = 120) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cancel.is_set():
            raise StartupError("Startup monitoring closed. The dashboard process was left running; do not launch another copy while it opens.")
        pid = listener.receive()
        if pid is not None and _ready_process(pid, process, plan, started):
            return
        code = process.poll()
        if code is not None and (not plan.frozen or code != 0):
            raise StartupError(f"Angerona exited before confirming its dashboard (code {code}). It may already be running; check the tray. Otherwise inspect startup-dashboard.log and the crash log before retrying.")
    raise StartupError("The dashboard did not respond within 120 seconds. Startup will not retry or start another copy. Check the existing dashboard, startup-dashboard.log and the crash log.")


def run_startup(report: Callable[[str], None], cancel: threading.Event, *, setup: bool = False,
                check_only: bool = False, _interface_lease: StartupLease | None = None) -> Path:
    report("Checking the installation and Windows startup authority...")
    plan = platform_plan()
    report("Preparing startup folders and checking available disk space...")
    prepare_storage(plan.storage)
    if _interface_lease is not None and type(_interface_lease) is not StartupLease:
        raise StartupError("Startup helper custody requires an actual retained OS lease.")
    lease = _interface_lease.borrow(plan.storage) if _interface_lease is not None else StartupLease(plan.storage)
    try:
        _assert_no_pending_repair(plan)
        report(f"Startup logs: {plan.storage / 'logs'}")
        from angerona.core.data_paths import _fixed_volume_available

        plan = replace(plan, temporary=select_temporary(
            plan.storage, plan.root, validate=_plain_path,
            fixed=_fixed_volume_available if sys.platform == "win32" else lambda _root: True,
            inherited=dict(os.environ),
        ))
        environment = child_environment(plan)
        report("Checking dependencies in a separate process...")
        probe_source(plan, environment, cancel)
        if cancel.is_set():
            raise StartupError("Startup cancelled before launching the dashboard.")
        if check_only:
            report("All source startup checks passed. No dashboard was requested.")
            return plan.storage
        listener = ReadyListener()
        try:
            command = [*plan.command, "--chill", f"--startup-ready={listener.endpoint}"]
            if setup:
                command.append("--setup")
            report("Opening the dashboard in Chill Mode...")
            started = time.time()
            with _log_file(plan.storage, "startup-dashboard.log") as log:
                process = subprocess.Popen(
                    command, cwd=plan.root, env=environment, stdin=subprocess.DEVNULL,
                    stdout=log, stderr=log,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            report("Waiting for the dashboard to paint and respond...")
            wait_dashboard(listener, process, plan, started, cancel)
        finally:
            listener.close()
        report("Dashboard ready. Closing the startup assistant.")
        return plan.storage
    finally:
        lease.close()


def _configure_tk_environment() -> None:
    # The UI runs before the worker's checks. Tcl must use the interpreter's
    # own libraries, never caller-selected startup libraries or search paths.
    for name in list(os.environ):
        if name.upper() in {"TCL_LIBRARY", "TK_LIBRARY", "TCLLIBPATH"}:
            os.environ.pop(name, None)
    if getattr(sys, "frozen", False):
        root = Path(sys._MEIPASS)
        for name, directory in (("TCL_LIBRARY", "_tcl_data"), ("TK_LIBRARY", "_tk_data")):
            path = root / directory
            _plain_path(path)
            if not path.is_dir():
                raise StartupError("The bundled startup interface is incomplete. Repair the signed installation.")
            os.environ[name] = str(path)


def _startup_window(tk):
    class StartupWindow(tk.Tk):
        def readprofile(self, _base_name, _class_name):
            # Tk normally loads optional per-user Python/Tcl profiles here.
            # A startup assistant must not execute those before its checks.
            pass

    return StartupWindow()


def main() -> int:
    parser = argparse.ArgumentParser(description="Angerona Safe Startup")
    parser.add_argument("--setup", action="store_true", help="Open setup after the dashboard starts")
    parser.add_argument("--chill", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--check-only", action="store_true", help=argparse.SUPPRESS)
    options = parser.parse_args()
    if options.check_only:
        try:
            run_startup(print, threading.Event(), check_only=True)
            return 0
        except RepairableStartupError as exc:
            print(str(exc), file=sys.stderr)
            return exc.exit_code
        except (StartupError, OSError) as exc:
            print(str(exc), file=sys.stderr)
            return 1
    try:
        interface_lease = _interface_lease()
    except (StartupError, OSError) as exc:
        if sys.stderr is not None:
            print(str(exc), file=sys.stderr)
        return 1
    try:
        _configure_tk_environment()
        import tkinter as tk
        from tkinter import ttk

        window = _startup_window(tk)
    except Exception as exc:
        interface_lease.close()
        message = (
            f"The startup interface could not open ({type(exc).__name__}). "
            "Repair the signed installation, or use Repair-Angerona-Python.bat "
            "for a source checkout. The dashboard was not started."
        )
        repairable = not getattr(sys, "frozen", False) and (
            isinstance(exc, (ImportError, OSError))
            or type(exc).__name__ == "TclError"
        )
        if repairable:
            if sys.stderr is not None:
                print(message, file=sys.stderr)
            return 83
        if sys.platform == "win32":
            import ctypes

            ctypes.windll.user32.MessageBoxW(None, message, "Angerona Safe Startup", 0x10)
        elif sys.stderr is not None:
            print(message, file=sys.stderr)
        return 1
    window.title("Angerona Safe Startup")
    window.geometry("650x350")
    window.minsize(540, 300)
    window.configure(background="#101820")
    messages: queue.Queue[tuple[str, str]] = queue.Queue(maxsize=32)
    cancel = threading.Event()
    outcome = {"code": 1}
    tk.Label(window, text="ANGERONA  |  SAFE STARTUP", bg="#101820", fg="#38bdf8",
             font=("Segoe UI", 18, "bold"), anchor="w").pack(fill="x", padx=24, pady=(22, 8))
    tk.Label(window, text="This window closes when your dashboard is ready.", bg="#101820",
             fg="#d9e4ed", anchor="w").pack(fill="x", padx=24)
    progress = ttk.Progressbar(window, mode="indeterminate")
    progress.pack(fill="x", padx=24, pady=16)
    progress.start(30)
    details = tk.Text(window, height=9, wrap="word", bg="#0b1219", fg="#d9e4ed",
                      relief="flat", font=("Segoe UI", 10), state="disabled")
    details.pack(fill="both", expand=True, padx=24)

    def close() -> None:
        cancel.set()
        window.destroy()

    ttk.Button(window, text="Close startup assistant", command=close).pack(anchor="e", padx=24, pady=12)
    window.protocol("WM_DELETE_WINDOW", close)

    def worker() -> None:
        try:
            run_startup(lambda text: messages.put(("progress", text)), cancel,
                        setup=options.setup, _interface_lease=interface_lease)
            messages.put(("ready", ""))
        except Exception as exc:
            if isinstance(exc, RepairableStartupError) and not cancel.is_set():
                messages.put((f"repair:{exc.exit_code}", str(exc)))
                return
            messages.put(("error", str(exc) if isinstance(exc, (StartupError, OSError)) else f"Startup check failed ({type(exc).__name__}). Review the startup logs."))

    def drain() -> None:
        while True:
            try:
                kind, detail = messages.get_nowait()
            except queue.Empty:
                break
            if kind == "ready":
                outcome["code"] = 0
                window.after(250, close)
                return
            if kind in {f"repair:{code}" for code in REPAIR_EXIT_CODES} and not cancel.is_set():
                outcome["code"] = int(kind.split(":", 1)[1])
                details.configure(state="normal")
                details.insert("end", detail + "\n\nThe launcher will attempt one verified repair after this assistant closes.\n")
                details.configure(state="disabled")
                progress.stop()
                window.after(250, close)
                return
            details.configure(state="normal")
            details.insert("end", detail + "\n\n")
            details.see("end")
            details.configure(state="disabled")
            if kind == "error":
                progress.stop()
                window.title("Angerona Safe Startup - needs attention")
        window.after(100, drain)

    # A cancelled window must allow the worker to reap its disposable probe.
    # A daemon could disappear before handling cancel, leaving a hung probe.
    window.after(100, lambda: threading.Thread(target=worker, name="AngeronaStartup", daemon=False).start())
    window.after(100, drain)
    try:
        window.mainloop()
    finally:
        interface_lease.close()
    return outcome["code"]


if __name__ == "__main__":
    raise SystemExit(main())
