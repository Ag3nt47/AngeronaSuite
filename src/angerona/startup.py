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
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from typing import Callable


class StartupError(RuntimeError):
    """A startup condition requiring a visible, actionable explanation."""


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
    for path in (root, root / "logs", root / "tmp"):
        _plain_path(path)
        path.mkdir(parents=True, exist_ok=True)
        _plain_path(path)
        if not path.is_dir():
            raise StartupError(f"Startup storage is not a directory: {path}")
    if shutil.disk_usage(root).free < 128 * 1024 * 1024:
        raise StartupError("Less than 128 MB is free on the startup data drive. Free space and retry.")
    fd, name = tempfile.mkstemp(prefix="startup-check-", dir=root / "tmp")
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(b"Angerona startup storage check\n")
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        Path(name).unlink(missing_ok=True)


class StartupLease:
    """OS lease prevents two helpers from launching competing dashboards."""

    def __init__(self, root: Path):
        path = root / "startup-helper.lock"
        _plain_path(path)
        self.stream = path.open("a+b")
        try:
            if self.stream.tell() == 0:
                self.stream.write(b"\0")
                self.stream.flush()
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

    def close(self) -> None:
        self.stream.close()  # The OS releases the lease; never delete its file.


@dataclass(frozen=True)
class LaunchPlan:
    root: Path
    storage: Path
    command: tuple[str, ...]
    frozen: bool


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


def child_environment(plan: LaunchPlan) -> dict[str, str]:
    from angerona.core.privilege import _minimal_environment

    # Do not inherit even the generic sidecar overrides: the helper owns all
    # runtime coordinates and must not propagate an inherited response command.
    environment = _minimal_environment({})
    environment.update({
        "TEMP": str(plan.storage / "tmp"), "TMP": str(plan.storage / "tmp"),
        "PYINSTALLER_RESET_ENVIRONMENT": "1",
    })
    if not plan.frozen:
        environment.update({
            "ANGERONA_DATA": str(plan.storage),
            "ANGERONA_DIAG_DIR": str(plan.storage / "diagnostics"),
            "ANGERONA_STORAGE_AUTOMIGRATE": "0",
        })
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


_PROBE = (
    "import sys,sysconfig,importlib.metadata as m; "
    "assert sys.version_info[:2]==(3,12) and sysconfig.get_platform()=='win-amd64', 'CPython 3.12 x64 required'; "
    "assert m.version('pip')=='26.2.1', 'Reviewed pip required'; "
    "import angerona,PySide6,psutil,yaml,dotenv,cryptography,requests; "
    "from PySide6.QtWidgets import QApplication; app=QApplication([]); "
    "app.processEvents(); print('Startup dependencies and Qt are ready')"
)


def probe_source(plan: LaunchPlan, environment: dict[str, str], cancel: threading.Event) -> None:
    if plan.frozen:
        return  # Main executable independently verifies package/UAC and imports Qt.
    probe_env = dict(environment, QT_QPA_PLATFORM="offscreen")
    with _log_file(plan.storage, "startup-preflight.log") as log:
        process = subprocess.Popen(
            [plan.command[0], "-c", _PROBE], cwd=plan.root, env=probe_env,
            stdin=subprocess.DEVNULL, stdout=log, stderr=log,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        deadline = time.monotonic() + 30
        while process.poll() is None:
            if cancel.wait(0.1) or time.monotonic() >= deadline:
                # Only this disposable import probe is terminated, never a dashboard.
                process.kill()
                process.wait(timeout=5)
                raise StartupError("The dependency check was cancelled or timed out. See startup-preflight.log; run Repair-Angerona-Python.bat if the runtime is damaged.")
        if process.returncode != 0:
            raise StartupError("The Python/Qt startup check failed. See startup-preflight.log and run Repair-Angerona-Python.bat. Your settings and evidence were preserved.")


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


def run_startup(report: Callable[[str], None], cancel: threading.Event, *, setup: bool = False) -> Path:
    report("Checking the installation and Windows startup authority...")
    plan = platform_plan()
    report("Preparing startup folders and checking available disk space...")
    prepare_storage(plan.storage)
    lease = StartupLease(plan.storage)
    try:
        report(f"Startup logs: {plan.storage / 'logs'}")
        environment = child_environment(plan)
        report("Checking dependencies in a separate process...")
        probe_source(plan, environment, cancel)
        if cancel.is_set():
            raise StartupError("Startup cancelled before launching the dashboard.")
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
    options = parser.parse_args()
    try:
        _configure_tk_environment()
        import tkinter as tk
        from tkinter import ttk

        window = _startup_window(tk)
    except Exception as exc:
        message = (
            f"The startup interface could not open ({type(exc).__name__}). "
            "Repair the signed installation, or use Repair-Angerona-Python.bat "
            "for a source checkout. The dashboard was not started."
        )
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
            run_startup(lambda text: messages.put(("progress", text)), cancel, setup=options.setup)
            messages.put(("ready", ""))
        except Exception as exc:
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
    window.mainloop()
    return outcome["code"]


if __name__ == "__main__":
    raise SystemExit(main())
