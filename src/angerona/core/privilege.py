"""Administrator-privilege handling.

Angerona needs an elevated token for full-system telemetry (process internals,
ETW kernel providers, protected file paths). On launch we check whether we are
already elevated; if not, we relaunch ourselves through the UAC prompt. On
non-Windows (developer machines) these are graceful no-ops.
"""
from __future__ import annotations

import ctypes
import hashlib
import os
import struct
import subprocess
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PureWindowsPath


_WINDOWS_COPIED_ENVIRONMENT = (
    "COMPUTERNAME",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
    "SESSIONNAME",
    "USERDOMAIN",
    "USERNAME",
)
_POSIX_COPIED_ENVIRONMENT = (
    "DESKTOP_SESSION",
    "DISPLAY",
    "HOME",
    "LANG",
    "LOGNAME",
    "PATH",
    "SHELL",
    "TERM",
    "USER",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_CURRENT_DESKTOP",
    "XDG_DATA_HOME",
    "XDG_RUNTIME_DIR",
    "XDG_SESSION_TYPE",
    "XDG_STATE_HOME",
)
_SAFE_ANGERONA_CHILD_ENVIRONMENT = frozenset({
    "ANGERONA_ACL_PATH",
    "ANGERONA_BLACKBOX_ENABLED",
    "ANGERONA_CORE_CMD",
    "ANGERONA_DATA",
    "ANGERONA_DIAG_DIR",
    "ANGERONA_PY",
    "ANGERONA_SCANNER_UI",
    "ANGERONA_STORAGE_AUTOMIGRATE",
})
_SECRET_ENVIRONMENT_MARKERS = (
    "API_KEY",
    "AUTHORIZATION",
    "CREDENTIAL",
    "MAIL_PASSWORD",
    "PASSWORD",
    "PRIVATE_KEY",
    "SECRET",
    "TOKEN",
    "WEBHOOK",
)
_PROXY_ENVIRONMENT = frozenset({
    "ALL_PROXY", "FTP_PROXY", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
})
_PATH_OR_CODE_LOADING_ENVIRONMENT = frozenset({
    "APPDATA",
    "CLASSPATH",
    "COMSPEC",
    "DOTNET_ADDITIONAL_DEPS",
    "DOTNET_SHARED_STORE",
    "DOTNET_STARTUP_HOOKS",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "LOCALAPPDATA",
    "NODE_OPTIONS",
    "PATH",
    "PATHEXT",
    "PSMODULEPATH",
    "QML2_IMPORT_PATH",
    "QT_PLUGIN_PATH",
    "QT_QPA_PLATFORM_PLUGIN_PATH",
    "SYSTEMROOT",
    "TCL_LIBRARY",
    "TK_LIBRARY",
    "WINDIR",
})


class ElevationState(str, Enum):
    """Outcome when an elevation helper returns to its caller."""

    NOT_REQUIRED = "not-required"
    EFFECTIVE_ADMINISTRATOR = "effective-administrator"
    CANCELLED_OR_DENIED = "cancelled-or-denied"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class ElevationResult:
    """Typed, non-authoritative description of a UAC attempt."""

    state: ElevationState
    reason: str

    @property
    def effective_administrator(self) -> bool:
        return self.state is ElevationState.EFFECTIVE_ADMINISTRATOR


_WATCHDOG_CONTEXT_KEYS = (
    "ANGERONA_EXTERNAL_WATCHDOG",
    "ANGERONA_WATCHDOG_MMAP",
    "ANGERONA_WATCHDOG_TOKEN",
    "ANGERONA_WD_DATADIR",
)


def _environment_value(source: Mapping[str, str], name: str) -> str:
    """Read a Windows environment name without trusting its original casing."""
    if name in source:
        return str(source[name])
    wanted = name.casefold()
    for key, value in source.items():
        if str(key).casefold() == wanted:
            return str(value)
    return ""


def _windows_api_directory(name: str) -> Path:
    """Return a Windows-owned directory without consulting the environment."""
    if sys.platform != "win32":
        raise OSError(f"{name} is available only on Windows")
    function = getattr(ctypes.windll.kernel32, name)
    function.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
    function.restype = ctypes.c_uint
    buffer = ctypes.create_unicode_buffer(32768)
    length = int(function(buffer, len(buffer)))
    if length <= 0 or length >= len(buffer) or not buffer.value:
        raise ctypes.WinError(ctypes.get_last_error())
    value = Path(buffer.value)
    if not PureWindowsPath(str(value)).is_absolute():
        raise OSError(f"{name} returned a non-absolute path")
    return value


def trusted_windows_directories() -> tuple[Path, Path]:
    """Return ``(Windows, System32)`` from WinAPI, never ``SystemRoot``."""
    return (
        _windows_api_directory("GetWindowsDirectoryW"),
        _windows_api_directory("GetSystemDirectoryW"),
    )


def trusted_powershell_path() -> Path:
    """Return the inbox Windows PowerShell path rooted in trusted System32."""
    _windows, system = trusted_windows_directories()
    return system / "WindowsPowerShell" / "v1.0" / "powershell.exe"


def _windows_known_folder(csidl: int) -> Path:
    """Resolve a machine folder with the Shell API, not an inherited variable."""
    if sys.platform != "win32":
        raise OSError("Windows known folders are available only on Windows")
    function = ctypes.windll.shell32.SHGetFolderPathW
    function.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_uint,
        ctypes.c_wchar_p,
    ]
    function.restype = ctypes.c_long
    buffer = ctypes.create_unicode_buffer(32768)
    result = int(function(None, csidl, None, 0, buffer))
    if result != 0 or not buffer.value:
        raise OSError(f"SHGetFolderPathW failed for CSIDL {csidl:#x}")
    value = Path(buffer.value)
    if not PureWindowsPath(str(value)).is_absolute():
        raise OSError("SHGetFolderPathW returned a non-absolute path")
    return value


def trusted_program_data_path() -> Path:
    """Return the machine-wide ProgramData directory from the Shell API."""
    return _windows_known_folder(0x23)  # CSIDL_COMMON_APPDATA


def _process_image_path(pid: int) -> Path:
    """Resolve a process image through WinAPI without PATH/tool lookup."""
    kernel = ctypes.windll.kernel32
    open_process = kernel.OpenProcess
    open_process.argtypes = [ctypes.c_uint, ctypes.c_bool, ctypes.c_uint]
    open_process.restype = ctypes.c_void_p
    handle = open_process(0x1000, False, int(pid))  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        query = kernel.QueryFullProcessImageNameW
        query.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint,
            ctypes.c_wchar_p,
            ctypes.POINTER(ctypes.c_uint),
        ]
        query.restype = ctypes.c_bool
        buffer = ctypes.create_unicode_buffer(32768)
        size = ctypes.c_uint(len(buffer))
        if not query(handle, 0, buffer, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        return Path(buffer.value).resolve(strict=True)
    finally:
        kernel.CloseHandle(handle)


def _expected_watchdog_path() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve(strict=True).parent / "angerona_watchdog.exe"
    return Path(__file__).resolve().parents[3] / "frz" / "angerona_watchdog.exe"


def _authenticode_valid(path: Path) -> bool:
    """Verify a fixed native binary with trusted PowerShell and a clean env."""
    try:
        powershell = trusted_powershell_path()
        if not powershell.is_file() or not path.is_file() or path.is_symlink():
            return False
        environment = _minimal_environment(os.environ)
        environment["ANGERONA_NATIVE_PATH"] = str(path)
        result = subprocess.run(
            [
                str(powershell),
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "if ((Get-AuthenticodeSignature -LiteralPath "
                "$env:ANGERONA_NATIVE_PATH).Status -eq 'Valid') {exit 0}; exit 1",
            ],
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _validated_watchdog_context(candidate: Mapping[str, str]) -> dict[str, str]:
    """Retain a genuine signed parent's per-launch heartbeat channel only."""
    if _environment_value(candidate, "ANGERONA_EXTERNAL_WATCHDOG") != "1":
        return {}
    token = _environment_value(candidate, "ANGERONA_WATCHDOG_TOKEN")
    mmap_text = _environment_value(candidate, "ANGERONA_WATCHDOG_MMAP")
    data_text = _environment_value(candidate, "ANGERONA_WD_DATADIR")
    try:
        token_raw = bytes.fromhex(token)
        if len(token_raw) != 32:
            return {}
        mmap_input = Path(mmap_text)
        data_input = Path(data_text)
        if not mmap_input.is_absolute() or mmap_input.is_symlink():
            return {}
        if not data_input.is_absolute() or data_input.is_symlink():
            return {}
        mmap_path = mmap_input.resolve(strict=True)
        data_path = data_input.resolve(strict=True)
        if mmap_path.parent != data_path or mmap_path.name != "frz_watchdog.mmap":
            return {}
        expected = _expected_watchdog_path().resolve(strict=True)
        parent_pid = os.getppid()
        if _process_image_path(parent_pid) != expected:
            return {}
        if not _authenticode_valid(expected):
            return {}
    except (OSError, ValueError, struct.error):
        return {}

    # The child can begin importing just before the watchdog publishes its first
    # beat, or while the file still contains the preceding launch's token proof.
    # Wait briefly for a matching atomic record instead of breaking legitimate
    # authenticated supervision during that normal startup race.
    deadline = time.monotonic() + 0.75
    while time.monotonic() <= deadline:
        try:
            if mmap_path.stat().st_size == 32:
                record = mmap_path.read_bytes()
                magic, ts_ns, watchdog_pid, proof, counter, flags = struct.unpack(
                    "<IQIQII", record
                )
                age = time.time() - (ts_ns / 1e9)
                expected_proof = int.from_bytes(
                    hashlib.sha256(
                        token_raw + struct.pack("<I", counter)
                    ).digest()[:8],
                    "little",
                )
                if (
                    magic == 0x41574447
                    and flags == 1
                    and watchdog_pid == parent_pid
                    and abs(age) <= 5.0
                    and proof == expected_proof
                ):
                    break
        except (OSError, struct.error):
            pass
        time.sleep(0.05)
    else:
        return {}
    return {
        "ANGERONA_EXTERNAL_WATCHDOG": "1",
        "ANGERONA_WATCHDOG_MMAP": str(mmap_path),
        "ANGERONA_WATCHDOG_TOKEN": token,
        "ANGERONA_WD_DATADIR": str(data_path),
    }


def _minimal_environment(source: Mapping[str, str]) -> dict[str, str]:
    """Build an OS/runtime environment without launch-time code or secret inputs."""
    if sys.platform == "win32":
        windows, system = trusted_windows_directories()
        environment = {
            name: value
            for name in _WINDOWS_COPIED_ENVIRONMENT
            if (value := _environment_value(source, name))
        }
        executable_dir = str(Path(sys.executable).resolve().parent)
        path_entries = (
            executable_dir,
            str(system),
            str(windows),
            str(system / "Wbem"),
            str(system / "WindowsPowerShell" / "v1.0"),
        )
        environment.update({
            "ComSpec": str(system / "cmd.exe"),
            "PATH": os.pathsep.join(dict.fromkeys(path_entries)),
            "PATHEXT": ".COM;.EXE;.BAT;.CMD",
            "SystemDrive": PureWindowsPath(str(windows)).drive,
            "SystemRoot": str(windows),
            "WINDIR": str(windows),
        })
        try:
            environment["ProgramData"] = str(trusted_program_data_path())
        except OSError:
            # The Windows directory is already WinAPI-derived. This conventional
            # sibling is safer than accepting a caller-supplied ProgramData.
            environment["ProgramData"] = str(windows.parent / "ProgramData")
        for key, csidl in (
            ("ProgramFiles", 0x26),          # CSIDL_PROGRAM_FILES
            ("ProgramFiles(x86)", 0x2A),    # CSIDL_PROGRAM_FILESX86
            ("CommonProgramFiles", 0x2B),   # CSIDL_PROGRAM_FILES_COMMON
        ):
            try:
                environment[key] = str(_windows_known_folder(csidl))
            except OSError:
                pass
        if "ProgramFiles" in environment:
            environment["ProgramW6432"] = environment["ProgramFiles"]
        for key, csidl in (
            ("APPDATA", 0x1A),       # CSIDL_APPDATA
            ("LOCALAPPDATA", 0x1C),  # CSIDL_LOCAL_APPDATA
            ("USERPROFILE", 0x28),   # CSIDL_PROFILE
        ):
            try:
                environment[key] = str(_windows_known_folder(csidl))
            except OSError:
                pass
        profile = environment.get("USERPROFILE", "")
        if profile:
            pure_profile = PureWindowsPath(profile)
            environment["HOMEDRIVE"] = pure_profile.drive
            environment["HOMEPATH"] = str(pure_profile)[len(pure_profile.drive):]
    else:
        environment = {
            name: value
            for name in _POSIX_COPIED_ENVIRONMENT
            if (value := _environment_value(source, name))
        }
        for name, value in source.items():
            if str(name).startswith("LC_") and value:
                environment[str(name)] = str(value)
    # These values are defensive constants, not inherited Python controls.
    environment["PYTHONNOUSERSITE"] = "1"
    environment["PYTHONUTF8"] = "1"
    return environment


def _validate_child_override(name: object, value: object) -> tuple[str, str]:
    key = str(name)
    text = str(value)
    if not key or "\x00" in key or "=" in key or "\x00" in text:
        raise ValueError("invalid child environment entry")
    upper = key.upper()
    if upper in _PATH_OR_CODE_LOADING_ENVIRONMENT:
        raise ValueError(f"refusing path/code-loading child entry: {key}")
    if upper in _PROXY_ENVIRONMENT or any(
        marker in upper for marker in _SECRET_ENVIRONMENT_MARKERS
    ):
        raise ValueError(f"refusing sensitive child environment entry: {key}")
    if upper.startswith("PYTHON") and upper not in {
        "PYTHONNOUSERSITE", "PYTHONUTF8",
    }:
        raise ValueError(f"refusing Python path/control entry: {key}")
    if upper.startswith("ANGERONA_") and upper not in _SAFE_ANGERONA_CHILD_ENVIRONMENT:
        raise ValueError(f"refusing unapproved Angerona child entry: {key}")
    return key, text


def sanitized_child_environment(
    overrides: Mapping[str, object] | None = None,
    *,
    source: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return a minimal child environment with no provider/connector secrets.

    Only the runtime coordination values required by Angerona's local sidecars
    cross the process boundary. Callers cannot accidentally add a credential,
    proxy, Python import control, or an unreviewed ``ANGERONA_*`` value.
    """
    inherited = os.environ if source is None else source
    environment = _minimal_environment(inherited)
    for name in _SAFE_ANGERONA_CHILD_ENVIRONMENT:
        value = _environment_value(inherited, name)
        if value:
            environment[name] = value
    for name, value in (overrides or {}).items():
        key, text = _validate_child_override(name, value)
        environment[key] = text
    return environment


def sanitize_privileged_bootstrap_environment() -> None:
    """Discard medium-token environment authority before Windows UAC startup."""
    if sys.platform != "win32":
        return
    watchdog_context = {
        name: value
        for name in _WATCHDOG_CONTEXT_KEYS
        if (value := _environment_value(os.environ, name))
    }
    # The source launcher owns one non-secret readiness coordinate. Preserve it
    # only when it is the exact source-install runtime marker; never copy it to
    # generic sidecars or accept another elevated write location.
    startup_ready = _environment_value(os.environ, "ANGERONA_STARTUP_READY")
    if startup_ready:
        try:
            expected = (
                Path(__file__).resolve().parents[3].parent
                / "AngeronaData" / "logs" / "dashboard-ready.signal"
            ).resolve()
            if Path(startup_ready).resolve() != expected:
                startup_ready = ""
        except (OSError, ValueError):
            startup_ready = ""
    environment = _minimal_environment(os.environ)
    os.environ.clear()
    os.environ.update(environment)
    if startup_ready:
        os.environ["ANGERONA_STARTUP_READY"] = startup_ready
    # The signed external watchdog's per-launch token is the sole credential
    # retained. It is restored only when the heartbeat proves the token, names
    # this process's real parent PID, comes from the expected binary path, and
    # that exact parent binary has valid Authenticode. It is never copied to the
    # generic sidecar environment built above.
    os.environ.update(_validated_watchdog_context(watchdog_context))


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False  # not Windows, or call unavailable


def ensure_admin() -> ElevationResult:
    """Relaunch if needed and return a typed result only when no handoff occurs."""
    if sys.platform != "win32":
        return ElevationResult(ElevationState.NOT_REQUIRED, "not running on Windows")
    # ShellExecute does not accept an explicit environment block. Replace this
    # process's inherited block before UAC so the elevated instance cannot
    # receive caller-controlled paths, Python controls, credentials, or
    # resilience commands. Also sanitize already-elevated direct launches.
    sanitize_privileged_bootstrap_environment()
    if is_admin():
        return ElevationResult(
            ElevationState.EFFECTIVE_ADMINISTRATOR,
            "effective Administrator token is present",
        )
    try:
        target = str(Path(sys.executable).resolve(strict=True))
        if getattr(sys, "frozen", False):
            # Packaged .exe: relaunch the exe itself with the original args.
            arguments = list(sys.argv[1:])
            working_directory = str(Path(target).parent)
        else:
            # Dev: relaunch the interpreter as `python -m angerona <args>`.
            arguments = ["-m", "angerona", *sys.argv[1:]]
            # Put the package's absolute ``src`` root on sys.path without
            # preserving an inherited PYTHONPATH or attacker-chosen CWD.
            working_directory = str(Path(__file__).resolve().parents[2])
        params = subprocess.list2cmdline(arguments)
        # ShellExecuteW verb 'runas' triggers the UAC consent dialog.
        shell_execute = ctypes.windll.shell32.ShellExecuteW
        shell_execute.argtypes = [
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_int,
        ]
        shell_execute.restype = ctypes.c_void_p
        result = int(shell_execute(
            None, "runas", target, params, working_directory, 1
        ) or 0)
        if result <= 32:
            return ElevationResult(
                ElevationState.CANCELLED_OR_DENIED,
                "the UAC request was cancelled, denied, or could not start",
            )
    except Exception:
        return ElevationResult(
            ElevationState.FAILED,
            "the UAC request failed before an elevated child was started",
        )
    raise SystemExit(0)  # the elevated instance takes over
