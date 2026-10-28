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
from angerona.core.startup_diagnostics import (
    StartupDiagnostics, canonical_storage, process_identity, safe_text,
)

_STARTUP_CONTEXT = threading.local()
STARTUP_INTERFACE_FAILURE = 84


def _record_startup_failure(error: BaseException, phase: str, *, exit_code: int | None = None) -> str:
    """Always disclose handled failures, including the Tk return-code path."""
    try:
        phase = getattr(_STARTUP_CONTEXT, "phase", None) or phase
        storage = getattr(_STARTUP_CONTEXT, "storage", None) or canonical_storage()
        message = StartupDiagnostics(storage).failure(
            phase, error, exit_code=getattr(error, "exit_code", 1) if exit_code is None else exit_code)
    except Exception as diagnostic_error:
        message = (f"Startup failed in {safe_text(phase, 64)}: {safe_text(error)}\n"
                   f"Diagnostic persistence unavailable: {type(diagnostic_error).__name__}: "
                   f"{safe_text(diagnostic_error, 512)}. Keep the launcher stderr log.")
    if sys.stderr is not None:
        try:
            print(message, file=sys.stderr, flush=True)
        except (OSError, ValueError):
            pass  # The independent parent still retains the nonzero outcome.
    return message


class StartupError(RuntimeError):
    """A startup condition requiring a visible, actionable explanation."""


class OperatorStopped(StartupError):
    """An authenticated operator stop intentionally superseded this launch."""


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
    rendering: str = "default"


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
    _STARTUP_CONTEXT.storage = plan.storage
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
    if os.environ.get("ANGERONA_SUPERVISED_RECOVERY") == "1":
        environment["ANGERONA_SUPERVISED_RECOVERY"] = "1"
    if plan.rendering == "software":
        environment["QT_OPENGL"] = "software"
        environment["QT_QUICK_BACKEND"] = "software"
    elif plan.rendering != "default":
        raise StartupError("Unknown startup renderer strategy; no dashboard was started.")
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


_PROBE = """import sys, sysconfig, importlib.metadata as m, json, re
if sys.version_info[:2] != (3, 12) or sysconfig.get_platform() != 'win-amd64':
    print('ANGERONA_RUNTIME '+json.dumps({'expected':'CPython 3.12 win-amd64','actual':str(sys.version_info[:3])+' '+sysconfig.get_platform()}),flush=True)
    raise SystemExit(81)
try:
    from pathlib import Path
    raw=Path('constraints-release.txt').read_bytes()
    if len(raw)>262144:
        raise ValueError('Reviewed dependency list exceeds its bounded size')
    checked=0; mismatches=0
    for line in raw.decode('utf-8').splitlines():
        if line.strip() and not line.lstrip().startswith('#'):
            if checked>=256 or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}==[A-Za-z0-9_.+!-]{1,128}',line.strip()):
                raise ValueError('Reviewed dependency list is malformed or exceeds its entry limit')
            name, version = line.strip().split('==')
            try:
                actual=m.version(name)
            except m.PackageNotFoundError:
                actual='<not installed>'
            if not isinstance(actual,str): actual='<invalid version metadata>'
            checked+=1
            mismatch=actual!=version
            mismatches+=int(mismatch)
            print('ANGERONA_DEPENDENCY '+json.dumps({'package':name,'expected':version,'actual':actual[:256],'match':not mismatch,'actual_truncated':len(actual)>256}),flush=True)
    print('ANGERONA_DEPENDENCY_SUMMARY '+json.dumps({'checked':checked,'mismatches':mismatches}),flush=True)
    if mismatches:
        print('Reviewed dependency versions do not match; expected and actual values are above.',flush=True)
        raise SystemExit(82)
    import angerona, psutil, yaml, dotenv, cryptography, requests
except (ImportError, m.PackageNotFoundError) as exc:
    print(type(exc).__name__, str(exc)[:2048], flush=True)
    raise SystemExit(82)
except Exception as exc:
    import traceback
    print('ANGERONA_PROBE_ERROR '+json.dumps({'exception_type':type(exc).__name__,'reason':str(exc)[:2048],'traceback':''.join(traceback.format_exception(type(exc),exc,exc.__traceback__,limit=8))[:8192]}),flush=True)
    raise SystemExit(1)
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
_PIP_CHECK = """import contextlib,sys
from pip._internal.commands.check import CheckCommand
class BoundedOutput:
    def __init__(self, target): self.target=target; self.remaining=65536; self.omitted=False
    encoding='utf-8'
    def isatty(self): return False
    def write(self,text):
        value=str(text)
        kept=value[:self.remaining]
        if kept: self.target.write(kept); self.remaining-=len(kept)
        if len(kept)<len(value) and not self.omitted:
            self.target.write('\\n[startup pip output limit reached; further text omitted]\\n'); self.omitted=True
        return len(value)
    def flush(self): self.target.flush()
sink=BoundedOutput(sys.stdout)
with contextlib.redirect_stdout(sink),contextlib.redirect_stderr(sink):
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
    diagnostics = StartupDiagnostics(plan.storage)
    diagnostics.record("preflight", "started", strategy=plan.rendering, root=str(plan.root),
                       executable=plan.command[0], **process_identity())
    deadline = time.monotonic() + 30
    with _log_file(plan.storage, "startup-preflight.log") as log:
        for index, (phase, arguments) in enumerate((
            ("Dependencies", ["-c", _PROBE]),
            ("Dependencies", ["-c", _PIP_CHECK]),
            ("GuiRuntime", ["-c", _QT_PROBE]),
        )):
            detail_phase = ("dependency-pins", "dependency-consistency", "gui-runtime")[index]
            _STARTUP_CONTEXT.phase = detail_phase
            if cancel.is_set() or time.monotonic() >= deadline:
                raise StartupError("The dependency check was cancelled or timed out. No dashboard was started.")
            process = subprocess.Popen(
                [plan.command[0], *arguments], cwd=plan.root, env=probe_env,
                stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            diagnostics.record(detail_phase, "started", attempt=index + 1,
                               process_role="probe-bootstrap", **process_identity(process))
            while process.poll() is None:
                if cancel.wait(0.1) or time.monotonic() >= deadline:
                    # Only this disposable probe is terminated, never a dashboard.
                    process.kill()
                    process.wait(timeout=5)
                    diagnostics.record(detail_phase, "cancelled" if cancel.is_set() else "timed-out",
                                       exit_code=process.returncode, **process_identity(process))
                    raise StartupError("The dependency check was cancelled or timed out. See startup-preflight.log; no dashboard was started.")
            if cancel.is_set():
                raise StartupError("Startup cancelled before launching the dashboard.")
            code = process.returncode
            log.flush()
            details = {} if code == 0 else {"output_tail": _probe_failure_tail(plan.storage / "logs" / "startup-preflight.log")}
            diagnostics.record(detail_phase, "passed" if code == 0 else "failed", attempt=index + 1,
                               exit_code=code, **process_identity(process), **details)
            if index == 0:
                _record_dependency_audit(diagnostics, plan.storage / "logs" / "startup-preflight.log")
            if code != 0:
                repair_code = code if code in REPAIR_EXIT_CODES else None
                if phase == "GuiRuntime" and (code & 0xFFFFFFFF) in _QT_NATIVE_FAILURES:
                    repair_code = 83
                message = "The Python/Qt startup check failed. See startup-preflight.log. Your settings and evidence were preserved."
                if repair_code is not None:
                    raise RepairableStartupError(repair_code, message)
                raise StartupError(message)


def _record_dependency_audit(diagnostics: StartupDiagnostics, path: Path) -> None:
    """Interpret only the fixed probe's bounded metadata rows as advisory data."""
    try:
        _plain_path(path)
        with path.open("rb") as stream:
            raw = stream.read(128 * 1024 + 1)
        omitted = len(raw) > 128 * 1024
        checked = 0
        mismatches = []
        for line in raw[:128 * 1024].decode("utf-8", "replace").splitlines()[:512]:
            if not line.startswith("ANGERONA_DEPENDENCY "):
                continue
            value = json.loads(line[len("ANGERONA_DEPENDENCY "):])
            if not isinstance(value, dict) or type(value.get("match")) is not bool:
                continue
            if not all(isinstance(value.get(key), str) for key in ("package", "expected", "actual")):
                continue
            checked += 1
            if not value["match"]:
                mismatches.append(f"{value['package']}: expected={value['expected']}, actual={value['actual']}")
        coverage = "probe output truncated" if omitted else "bounded fixed-probe rows"
        if len(mismatches) > 24:
            coverage += f"; {len(mismatches) - 24} mismatches omitted from this summary; see preflight log"
        if not checked:
            coverage = "no fixed-probe dependency rows were emitted"
        diagnostics.record("dependency-audit", "failed" if mismatches else "checked" if checked else "unavailable",
                           packages_checked=checked, mismatches_total=len(mismatches), mismatches=mismatches,
                           coverage=coverage)
    except (OSError, ValueError, TypeError) as exc:
        diagnostics.record("dependency-audit", "unavailable", exception_type=type(exc).__name__, reason=str(exc))


def _probe_failure_tail(path: Path) -> str:
    try:
        _plain_path(path)
        with path.open("rb") as stream:
            stream.seek(0, os.SEEK_END)
            stream.seek(max(0, stream.tell() - 4096))
            return safe_text(stream.read(4096).decode("utf-8", "replace"), 4096)
    except (OSError, StartupError) as exc:
        return "Probe output unavailable: " + type(exc).__name__


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
                   cancel: threading.Event, timeout: float = 120) -> int:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cancel.is_set():
            raise StartupError("Startup monitoring closed. The dashboard process was left running; do not launch another copy while it opens.")
        pid = listener.receive()
        if pid is not None and _ready_process(pid, process, plan, started):
            return pid
        code = process.poll()
        if code is not None and (not plan.frozen or code != 0):
            raise StartupError(f"Angerona exited before confirming its dashboard (code {code}). It may already be running; check the tray. Otherwise inspect startup-dashboard.log and the crash log before retrying.")
    raise StartupError("The dashboard did not respond within 120 seconds. Startup will not retry or start another copy. Check the existing dashboard, startup-dashboard.log and the crash log.")


def run_startup(report: Callable[[str], None], cancel: threading.Event, *, setup: bool = False,
                check_only: bool = False, _interface_lease: StartupLease | None = None,
                software_renderer: bool = False) -> Path:
    report("Checking the installation and Windows startup authority...")
    _STARTUP_CONTEXT.phase = "installation-authority"
    plan = platform_plan()
    _STARTUP_CONTEXT.storage = plan.storage
    plan = replace(plan, rendering="software" if software_renderer else "default")
    report("Preparing startup folders and checking available disk space...")
    _STARTUP_CONTEXT.phase = "storage-capacity"
    prepare_storage(plan.storage)
    diagnostics = StartupDiagnostics(plan.storage)
    diagnostics.record("storage", "verified", root=str(plan.root), executable=plan.command[0],
                       strategy=plan.rendering, **process_identity())
    if _interface_lease is not None and type(_interface_lease) is not StartupLease:
        raise StartupError("Startup helper custody requires an actual retained OS lease.")
    _STARTUP_CONTEXT.phase = "startup-lease"
    lease = _interface_lease.borrow(plan.storage) if _interface_lease is not None else StartupLease(plan.storage)
    try:
        _assert_no_pending_repair(plan)
        report(f"Startup logs: {plan.storage / 'logs'}")
        from angerona.core.data_paths import _fixed_volume_available

        _STARTUP_CONTEXT.phase = "temporary-storage"
        plan = replace(plan, temporary=select_temporary(
            plan.storage, plan.root, validate=_plain_path,
            fixed=_fixed_volume_available if sys.platform == "win32" else lambda _root: True,
            inherited=dict(os.environ),
        ))
        diagnostics.record("temporary-storage", "verified", strategy=plan.rendering)
        environment = child_environment(plan)
        report("Checking dependencies in a separate process...")
        probe_source(plan, environment, cancel)
        diagnostics.record("preflight", "verified", strategy=plan.rendering)
        if cancel.is_set():
            raise StartupError("Startup cancelled before launching the dashboard.")
        if check_only:
            report("All source startup checks passed. No dashboard was requested.")
            return plan.storage
        from angerona.resilience.shutdown_token import (
            clear_standdown_for_storage, standdown_active_for_storage,
        )
        if os.environ.get("ANGERONA_SUPERVISED_RECOVERY") == "1":
            if standdown_active_for_storage(plan.storage):
                raise OperatorStopped("Authenticated STOP is active; automatic startup remains stopped.")
        else:
            # A user launch may resume only after its complete preflight. A
            # check-only run and every automatic retry leave STOP untouched.
            clear_standdown_for_storage(plan.storage)
        # The helper has consumed this explicit resume exactly once. Its
        # child must honor a NEW stop written during construction or warmup.
        environment["ANGERONA_SUPERVISED_RECOVERY"] = "1"
        listener = ReadyListener()
        try:
            command = [*plan.command, "--chill", f"--startup-ready={listener.endpoint}"]
            if setup:
                command.append("--setup")
            report("Opening the dashboard in Chill Mode...")
            _STARTUP_CONTEXT.phase = "dashboard-launch"
            started = time.time()
            with _log_file(plan.storage, "startup-dashboard.log") as log:
                process = subprocess.Popen(
                    command, cwd=plan.root, env=environment, stdin=subprocess.DEVNULL,
                    stdout=log, stderr=log,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            diagnostics.record("dashboard", "launched-awaiting-readiness", strategy=plan.rendering,
                               dashboard_log=str(plan.storage / "logs" / "startup-dashboard.log"),
                               process_role="dashboard-launcher",
                               **process_identity(process))
            report("Waiting for the dashboard to paint and respond...")
            _STARTUP_CONTEXT.phase = "dashboard-readiness"
            try:
                ready_pid = wait_dashboard(listener, process, plan, started, cancel)
            except StartupError:
                if standdown_active_for_storage(plan.storage):
                    raise OperatorStopped("Authenticated STOP was requested during startup; no retry will reopen the dashboard.") from None
                raise
            identity = (process_identity(process) if ready_pid == process.pid else
                        {"pid": ready_pid, "coverage": "Ready PID verified; raw native birth not retained for redirected/elevated child"})
            diagnostics.record("dashboard", "readiness-verified", strategy=plan.rendering,
                               process_role="core-dashboard", bootstrap_pid=process.pid, **identity)
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
    _STARTUP_CONTEXT.storage = None
    _STARTUP_CONTEXT.phase = "startup-interface-authority"
    parser = argparse.ArgumentParser(description="Angerona Safe Startup")
    parser.add_argument("--setup", action="store_true", help="Open setup after the dashboard starts")
    parser.add_argument("--chill", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--check-only", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--software-renderer", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--no-startup-window", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--automatic-start", action="store_true", help=argparse.SUPPRESS)
    options = parser.parse_args()
    # This marker controls only this assistant window's lifetime. It never
    # authorizes a repair/retry and child_environment does not forward it.
    supervised = os.environ.get("ANGERONA_STARTUP_SUPERVISED") == "1"
    automatic = options.automatic_start or os.environ.get("ANGERONA_SUPERVISED_RECOVERY") == "1"
    if automatic:
        os.environ["ANGERONA_SUPERVISED_RECOVERY"] = "1"
        if not options.check_only:
            try:
                plan = platform_plan()
                from angerona.resilience.shutdown_token import standdown_active_for_storage
                if standdown_active_for_storage(plan.storage):
                    print("Authenticated STOP is active; automatic startup remains stopped.")
                    return 86 if supervised else 0
            except Exception as exc:
                _record_startup_failure(exc, "automatic-stop-admission", exit_code=85)
                return 85
    strategy = {"software_renderer": True} if options.software_renderer else {}
    if options.check_only:
        _STARTUP_CONTEXT.phase = "source-check-only"
        try:
            run_startup(print, threading.Event(), check_only=True, **strategy)
            return 0
        except RepairableStartupError as exc:
            _record_startup_failure(exc, "source-check-only")
            return exc.exit_code
        except (StartupError, OSError) as exc:
            _record_startup_failure(exc, "source-check-only")
            return 1
        except Exception as exc:
            _record_startup_failure(exc, "source-check-only")
            return 1
    if options.no_startup_window:
        _STARTUP_CONTEXT.phase = "no-startup-window"
        try:
            run_startup(print, threading.Event(), setup=options.setup, **strategy)
            return 0
        except OperatorStopped:
            return 86 if supervised else 0
        except RepairableStartupError as exc:
            _record_startup_failure(exc, "no-startup-window")
            return exc.exit_code
        except Exception as exc:
            _record_startup_failure(exc, "no-startup-window")
            return 1
    try:
        interface_lease = _interface_lease()
    except (StartupError, OSError) as exc:
        _record_startup_failure(exc, "startup-interface-authority")
        return 1
    try:
        _STARTUP_CONTEXT.phase = "startup-interface"
        _configure_tk_environment()
        import tkinter as tk
        from tkinter import ttk

        window = _startup_window(tk)
    except Exception as exc:
        interface_lease.close()
        frozen = bool(getattr(sys, "frozen", False))
        code = 1 if frozen else STARTUP_INTERFACE_FAILURE
        _record_startup_failure(exc, "startup-interface", exit_code=code)
        message = (
            f"The startup interface could not open ({type(exc).__name__}). " +
            ("Repair the signed installation. No dashboard was started by this failed interface."
             if frozen else "The verified source supervisor can retry without the startup window; "
             "the same dependency, Qt and dashboard-readiness checks still apply. "
             "No dashboard was started by this failed interface.")
        )
        if sys.stderr is not None:
            print(message, file=sys.stderr, flush=True)
        if frozen and sys.platform == "win32":
            import ctypes
            ctypes.windll.user32.MessageBoxW(None, message, "Angerona Safe Startup", 0x10)
        return code
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
        _STARTUP_CONTEXT.storage = getattr(interface_lease, "root", None)
        _STARTUP_CONTEXT.phase = "startup-worker"
        try:
            run_startup(lambda text: messages.put(("progress", text)), cancel,
                        setup=options.setup, _interface_lease=interface_lease, **strategy)
            messages.put(("ready", ""))
        except OperatorStopped as exc:
            messages.put(("operator-stopped", str(exc)))
        except Exception as exc:
            detail = _record_startup_failure(exc, "startup-worker")
            if isinstance(exc, RepairableStartupError) and not cancel.is_set():
                messages.put((f"repair:{exc.exit_code}", detail))
                return
            messages.put(("error", detail))

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
            if kind == "operator-stopped":
                outcome["code"] = 86 if supervised else 0
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
                if supervised:
                    # The worker has unwound its probe/lease before queuing
                    # this error. Non-daemon ownership still prevents an
                    # interpreter exit while that worker is finishing.
                    outcome["code"] = 1
                    window.after(250, close)
                    return
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
