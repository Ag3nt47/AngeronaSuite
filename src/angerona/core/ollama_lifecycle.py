"""Bounded lifecycle helpers for Angerona's loopback Ollama service.

Only validated model identifiers are placed into fixed Ollama API payloads.
Callers cannot provide API paths, URLs, executable Modelfiles, or shell text.
"""
from __future__ import annotations

import os
import math
import re
import stat
import subprocess
import sys
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

from angerona.core.url_policy import (
    OLLAMA_SERVICE_POLICY,
    local_json_request,
    local_service_url,
)


_MODEL_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_MODEL_TAG = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
# Ollama's official Inno Setup AppId, not a registry-wide executable search.
_OLLAMA_UNINSTALL_KEY = (
    "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\"
    "{44E83376-CE68-45EB-8FC1-393500EB558C}_is1"
)
_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class OllamaAttestationError(RuntimeError):
    """Raised when Angerona cannot bind Ollama to an expected local process."""


@dataclass(frozen=True, slots=True)
class OllamaServiceAttestation:
    pid: int
    executable: str
    create_time: float
    port: int


def _windows_install_location(value: object) -> PureWindowsPath | None:
    """Accept a bounded local-drive directory, without shell/path expansion."""
    if not isinstance(value, str) or not 3 <= len(value) <= 1024:
        return None
    if re.fullmatch(r"[A-Za-z]:\\[^<>:\"|?*\x00-\x1f/]*", value) is None:
        return None
    # Inspect the original components: pathlib removes '.' and duplicate slashes.
    components = value[3:].removesuffix("\\").split("\\")
    if any(
        not component or component in {".", ".."}
        or component != component.strip() or component.endswith(".")
        or PureWindowsPath(component).is_reserved()
        for component in components
    ):
        return None
    path = PureWindowsPath(value)
    if not path.is_absolute():
        return None
    return path


def _windows_fixed_drive(anchor: str) -> bool:
    """Reject mapped network drives as well as UNC/device path spellings."""
    try:
        import ctypes

        get_drive_type = ctypes.windll.kernel32.GetDriveTypeW
        get_drive_type.argtypes = [ctypes.c_wchar_p]
        get_drive_type.restype = ctypes.c_uint
        return int(get_drive_type(anchor)) == 3  # DRIVE_FIXED
    except (AttributeError, OSError, ValueError):
        return False


def _registered_ollama_paths() -> tuple[Path, ...]:
    """Discover custom installs; registry metadata never confers image trust."""
    try:
        import winreg
    except ImportError:
        return ()
    candidates: list[Path] = []
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
            try:
                with winreg.OpenKey(
                    hive, _OLLAMA_UNINSTALL_KEY, 0, winreg.KEY_READ | view
                ) as key:
                    values = {
                        name: winreg.QueryValueEx(key, name)
                        for name in ("DisplayName", "Publisher", "InstallLocation")
                    }
                if any(
                    kind != winreg.REG_SZ or not isinstance(value, str)
                    for value, kind in values.values()
                ):
                    continue
                display_name = values["DisplayName"][0]
                if (
                    len(display_name) > 128
                    or re.fullmatch(r"Ollama(?: version [0-9][0-9A-Za-z.+-]{0,63})?", display_name)
                    is None
                    or values["Publisher"][0] != "Ollama"
                ):
                    continue
                location = _windows_install_location(values["InstallLocation"][0])
                if location is not None and _windows_fixed_drive(location.anchor):
                    candidates.append(Path(str(location / "ollama.exe")))
            except (OSError, ValueError, TypeError):
                continue
    return tuple(dict.fromkeys(candidates))


def _expected_ollama_paths() -> tuple[Path, ...]:
    """Return known/registered installs without PATH or environment overrides."""
    candidates: list[Path]
    if sys.platform == "win32":
        from angerona.core.privilege import _windows_known_folder

        candidates = []
        try:
            local_app_data = _windows_known_folder(0x1C)  # CSIDL_LOCAL_APPDATA
            candidates.extend((
                local_app_data / "Programs" / "Ollama" / "ollama.exe",
                local_app_data / "Ollama" / "ollama.exe",
            ))
        except OSError:
            pass
        for csidl in (0x26, 0x2A):  # Program Files / Program Files (x86)
            try:
                candidates.append(_windows_known_folder(csidl) / "Ollama" / "ollama.exe")
            except OSError:
                pass
        candidates.extend(_registered_ollama_paths())
    elif sys.platform == "darwin":
        candidates = [
            Path("/Applications/Ollama.app/Contents/Resources/ollama"),
            Path("/Applications/Ollama.app/Contents/MacOS/Ollama"),
            Path("/usr/local/bin/ollama"),
            Path("/opt/homebrew/bin/ollama"),
        ]
    else:
        candidates = [
            Path("/usr/bin/ollama"),
            Path("/usr/local/bin/ollama"),
            Path("/opt/ollama/bin/ollama"),
            Path("/snap/bin/ollama"),
        ]
    return tuple(candidates)


@lru_cache(maxsize=16)
def _windows_image_signature_valid(
    path_text: str, device: int, inode: int, size: int, modified_ns: int, changed_ns: int
) -> bool:
    # All identity fields intentionally participate in the bounded cache key.
    del device, inode, size, modified_ns, changed_ns
    from angerona.core.privilege import (
        sanitized_child_environment,
        trusted_powershell_path,
        trusted_windows_directories,
    )

    try:
        powershell = trusted_powershell_path()
        _windows, system = trusted_windows_directories()
        if not powershell.is_file():
            return False
        environment = sanitized_child_environment(source={})
        environment["ANGERONA_NATIVE_PATH"] = path_text
        result = subprocess.run(
            [
                str(powershell), "-NoProfile", "-NonInteractive", "-Command",
                "$ErrorActionPreference='Stop';"
                "$s=Microsoft.PowerShell.Security\\Get-AuthenticodeSignature "
                "-LiteralPath $env:ANGERONA_NATIVE_PATH;"
                "if($s.Status -ne 'Valid' -or $null -eq $s.SignerCertificate){exit 1};"
                "$p=$s.SignerCertificate.GetNameInfo("
                "[System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false);"
                "if([string]::Equals($p,'Ollama Inc.',"
                "[System.StringComparison]::OrdinalIgnoreCase)){exit 0};exit 1",
            ],
            cwd=str(system), env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=15, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError, ValueError):
        return False


def _image_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(info.st_dev), int(info.st_ino), int(info.st_size),
        int(info.st_mtime_ns), int(info.st_ctime_ns),
    )


def _unredirected_image(path: Path) -> bool:
    """Reject symbolic links and Windows junctions in every image component."""
    for component in (path, *path.parents):
        info = component.lstat()
        if stat.S_ISLNK(info.st_mode) or (
            int(getattr(info, "st_file_attributes", 0)) & _REPARSE_ATTRIBUTE
        ):
            return False
    return True


def _trusted_ollama_image(path: Path) -> bool:
    """Require a recognized installation and an authenticated platform image."""
    try:
        if sys.platform == "win32" and not _unredirected_image(path):
            return False
        image = path.resolve(strict=True)
        info = image.stat()
        if not stat.S_ISREG(info.st_mode) or path.is_symlink():
            return False
        expected = {
            candidate.resolve(strict=True)
            for candidate in _expected_ollama_paths()
            if candidate.is_file() and not candidate.is_symlink()
            and (sys.platform != "win32" or _unredirected_image(candidate))
        }
        if image not in expected:
            return False
        if sys.platform == "win32":
            identity = _image_identity(info)
            return (
                _windows_image_signature_valid(str(image), *identity)
                and _unredirected_image(path)
                and path.resolve(strict=True) == image
                and _image_identity(image.stat()) == identity
            )
        # On POSIX there is no portable Authenticode equivalent in the Python
        # runtime. Accept only a root-owned image that group/other cannot write.
        return info.st_uid == 0 and not (stat.S_IMODE(info.st_mode) & 0o022)
    except (OSError, PermissionError, ValueError):
        return False


def _owned_ollama_listeners():
    """Read kernel-reported sockets of known same-user POSIX installations.

    macOS forbids a non-root system-wide socket table. This fallback never
    treats a responding HTTP server, process name, or launched PID as proof:
    the candidate itself must own a LISTEN socket and later pass attestation.
    Unrelated sandboxed applications need not grant process inspection access.
    """
    import psutil

    expected = {
        path.resolve(strict=True)
        for path in _expected_ollama_paths()
        if path.is_file() and _unredirected_image(path)
    }
    if not expected:
        return []
    deadline = time.monotonic() + 2.0
    listeners = []
    for index, process in enumerate(psutil.process_iter(["pid", "name"])):
        if index >= 4096 or time.monotonic() >= deadline:
            raise OllamaAttestationError("Local AI process discovery exceeded its bound.")
        if str(process.info.get("name", "")).casefold() not in {"ollama", "ollama.exe"}:
            continue
        try:
            if int(process.uids().effective) != os.getuid():
                continue
            image = Path(process.exe()).resolve(strict=True)
            if image not in expected:
                continue
            created = float(process.create_time())
            connections = process.net_connections(kind="tcp")
            if (not process.is_running() or float(process.create_time()) != created
                    or Path(process.exe()).resolve(strict=True) != image):
                raise OllamaAttestationError("Local AI process identity changed.")
            for connection in connections:
                if str(getattr(connection, "status", "")).upper() != "LISTEN":
                    continue
                if len(listeners) >= 4096:
                    raise OllamaAttestationError("Local AI listener discovery exceeded its bound.")
                listeners.append(SimpleNamespace(
                    status=connection.status, laddr=connection.laddr, pid=process.pid,
                ))
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            continue
        except (psutil.AccessDenied, OSError) as exc:
            raise OllamaAttestationError("Local AI process ownership is unavailable.") from exc
    return listeners


def _ollama_tcp_listeners():
    import psutil

    try:
        return psutil.net_connections(kind="tcp")
    except psutil.AccessDenied:
        if sys.platform not in {"darwin", "linux"}:
            raise
        return _owned_ollama_listeners()


def _ollama_listener_pids(port: int, address: str = "127.0.0.1") -> set[int]:
    """Identify the owner of the exact pinned HTTP endpoint, never just its port."""
    try:
        import ipaddress

        wanted = ipaddress.ip_address(address)
        if not wanted.is_loopback:
            return set()
        listeners: set[int] = set()
        for connection in _ollama_tcp_listeners():
            if str(getattr(connection, "status", "")).upper() != "LISTEN":
                continue
            local = getattr(connection, "laddr", None)
            if not local or int(getattr(local, "port", local[1])) != port:
                continue
            bound = ipaddress.ip_address(str(getattr(local, "ip", local[0])).split("%", 1)[0])
            # An IPv6 wildcard may also accept IPv4 connections; the socket
            # table does not expose IPV6_V6ONLY. Never discard that ambiguity
            # and then attest an unrelated loopback owner on the same port.
            if bound.is_unspecified and (bound.version == 6 or wanted.version == 4):
                raise OllamaAttestationError("local Ollama endpoint has a wildcard listener")
            if bound != wanted:
                continue
            pid = getattr(connection, "pid", None)
            if type(pid) is not int or pid <= 0:
                raise OllamaAttestationError("local Ollama endpoint owner is unavailable")
            listeners.add(pid)
        return listeners
    except (ImportError, OSError, PermissionError):
        return set()


def attest_ollama_service(
    host: str = "http://localhost:11434",
) -> OllamaServiceAttestation:
    """Bind the configured loopback listener to the expected Ollama image.

    Failure is an availability result, never a reason to send inference to an
    unauthenticated process that merely won the loopback port race.
    """
    pinned = urlsplit(local_service_url(host))
    port = int(pinned.port or (443 if pinned.scheme == "https" else 80))
    pids = _ollama_listener_pids(port, str(pinned.hostname))
    if len(pids) != 1:
        raise OllamaAttestationError(
            "local Ollama listener ownership is unavailable or ambiguous"
        )
    pid = next(iter(pids))
    try:
        import psutil

        process = psutil.Process(pid)
        first_time = float(process.create_time())
        reported_image = Path(process.exe())
        first_image = reported_image.resolve(strict=True)
        if not _trusted_ollama_image(reported_image):
            raise OllamaAttestationError("local Ollama executable is not trusted")
        if (
            not process.is_running()
            or float(process.create_time()) != first_time
            or Path(process.exe()).resolve(strict=True) != first_image
        ):
            raise OllamaAttestationError("local Ollama process identity changed")
    except OllamaAttestationError:
        raise
    except (ImportError, OSError, PermissionError, ValueError) as exc:
        raise OllamaAttestationError(
            "local Ollama process identity is unavailable"
        ) from exc
    return OllamaServiceAttestation(pid, str(first_image), first_time, port)


@dataclass(frozen=True, slots=True)
class OllamaStartupStatus:
    """Completed startup stages, not an estimate of remaining wall-clock time.

    Daemon readiness does not authorize a model or report model readiness.
    The separate model-integrity/readiness checks retain that authority.
    """

    state: str = "idle"
    stage: str = "Not requested"
    percent: int = 0
    detail: str = "Local AI service has not been checked."
    daemon_ready: bool = False
    model_ready: bool = False


class _StartupAttempt:
    def __init__(self) -> None:
        self.status = OllamaStartupStatus("starting", "Starting", 0)
        self.done = threading.Event()


_startup_lock = threading.RLock()
_startup_attempts: OrderedDict[str, _StartupAttempt] = OrderedDict()
_startup_launch_lock = threading.Lock()
_STARTUP_LIMIT = 16


def _startup_key(host: str) -> str:
    """Canonicalize known loopback spellings without DNS or filesystem I/O."""
    if (not isinstance(host, str) or len(host) > 256 or host != host.strip()
            or any(ord(character) < 32 for character in host)):
        raise ValueError("Invalid local AI service address.")
    parsed = urlsplit(host)
    if (parsed.scheme != "http" or parsed.username is not None
            or parsed.password is not None or parsed.path not in {"", "/"}
            or parsed.query or parsed.fragment):
        raise ValueError("Automatic startup requires a plain loopback HTTP address.")
    address = parsed.hostname
    if address not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("Automatic startup requires localhost, 127.0.0.1, or ::1.")
    port = 80 if parsed.port is None else parsed.port
    if not 1 <= port <= 65535:
        raise ValueError("Invalid local AI service port.")
    literal = "[::1]" if address == "::1" else "127.0.0.1"
    return f"http://{literal}:{port}"


def startup_snapshot(host: str = "http://localhost:11434") -> OllamaStartupStatus:
    """Return cached progress only; safe for GUI refreshes and diagnostic views."""
    try:
        key = _startup_key(host)
    except ValueError:
        return OllamaStartupStatus("failed", "Invalid address", 0,
                                   "Automatic startup requires a local HTTP endpoint.")
    with _startup_lock:
        attempt = _startup_attempts.get(key)
        return attempt.status if attempt is not None else OllamaStartupStatus()


def _claim_startup(key: str) -> tuple[_StartupAttempt, bool]:
    with _startup_lock:
        attempt = _startup_attempts.get(key)
        if attempt is not None and not attempt.done.is_set():
            return attempt, False
        if key not in _startup_attempts and len(_startup_attempts) >= _STARTUP_LIMIT:
            for old_key, old_attempt in list(_startup_attempts.items()):
                if old_attempt.done.is_set():
                    del _startup_attempts[old_key]
                    break
            else:
                raise ValueError("Too many local AI startup requests are in progress.")
        attempt = _StartupAttempt()
        _startup_attempts[key] = attempt
        _startup_attempts.move_to_end(key)
        return attempt, True


def _notify_startup(attempt, state, stage, percent, detail, progress=None):
    status = OllamaStartupStatus(state, stage, percent, detail, state == "ready")
    with _startup_lock:
        attempt.status = status
    if progress is not None:
        try:
            progress(status)
        except Exception:
            # A UI callback cannot abort a service operation or erase its result.
            pass
    return status


def _startup_port_present(host: str) -> bool:
    """Detect occupied ports, including wildcard listeners we cannot attest."""
    parsed = urlsplit(host)
    for connection in _ollama_tcp_listeners():
        address = getattr(connection, "laddr", None)
        if (str(getattr(connection, "status", "")).upper() == "LISTEN"
                and address and int(getattr(address, "port", address[1])) == parsed.port):
            return True
    # Windows may delay refusing a connection to an unused port beyond a short
    # socket timeout. A completed OS listener table is the availability probe;
    # the subsequent mandatory ownership attestation handles bind races.
    return False


def _startup_environment(host: str) -> dict[str, str]:
    from angerona.core.privilege import sanitized_child_environment

    # Do not forward API credentials, proxy controls, load paths, or arbitrary
    # OLLAMA_* policy overrides. Retain the operator's explicit model storage.
    environment = sanitized_child_environment()
    for name in tuple(environment):
        if name.upper().startswith("ANGERONA_"):
            del environment[name]
    environment.update({
        "OLLAMA_HOST": host,
        "OLLAMA_NO_CLOUD": "1",
        "OLLAMA_KEEP_ALIVE": "0" if chill_active() else "5m",
        "OLLAMA_MAX_LOADED_MODELS": "1",
        "OLLAMA_NUM_PARALLEL": "1",
    })
    model_directory = os.environ.get("OLLAMA_MODELS", "")
    if (model_directory and len(model_directory) <= 4096
            and not any(ord(character) < 32 for character in model_directory)
            and Path(model_directory).is_absolute()):
        environment["OLLAMA_MODELS"] = model_directory
    if sys.platform != "win32":
        environment["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
    return environment


def _spawn_ollama_service(host: str, deadline: float, *, verified=None):
    """Launch a sealed known image with fixed arguments and no elevation."""
    from angerona.core.executable_trust import _open_sealed
    from angerona.core.privilege import is_admin
    from angerona.core.source_sandbox import _hold_plain_directories

    elevated = is_admin()
    if sys.platform != "win32" and (elevated or os.geteuid() == 0):
        raise ValueError("Start Ollama from a normal user session; automatic AI startup cannot run elevated.")
    for candidate in _expected_ollama_paths():
        if time.monotonic() >= deadline:
            raise TimeoutError
        if not candidate.is_file() or not _unredirected_image(candidate):
            continue
        with ExitStack() as stack:
            stack.enter_context(_hold_plain_directories(candidate.parent))
            held = stack.enter_context(_open_sealed(candidate))
            identity = _image_identity(os.fstat(held.fileno()))
            named_identity = _image_identity(candidate.stat())
            # On CPython 3.12/Windows stat() exposes birth time as st_ctime,
            # while fstat() can expose change time. Compare each API with its
            # own baseline; shared device/inode/size/mtime bind the two views.
            if identity[:4] != named_identity[:4]:
                raise OllamaAttestationError("Local AI executable identity changed.")
            if not _trusted_ollama_image(candidate):
                continue
            if sys.platform != "win32" and any(
                parent.stat().st_uid != 0 or stat.S_IMODE(parent.stat().st_mode) & 0o022
                for parent in candidate.parents
            ):
                continue
            if (_image_identity(candidate.stat()) != named_identity
                    or _image_identity(os.fstat(held.fileno())) != identity):
                raise OllamaAttestationError("Local AI executable identity changed.")
            if time.monotonic() >= deadline:
                raise TimeoutError
            if verified is not None:
                verified()
            if time.monotonic() >= deadline:
                raise TimeoutError
            if elevated:
                from angerona.core.ollama_windows_token import launch_medium_ollama

                return launch_medium_ollama(candidate, host, deadline=deadline,
                                            check_cancelled=verified)
            kwargs = {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)}
            if sys.platform != "win32":
                kwargs = {"start_new_session": True}
            return subprocess.Popen(
                [str(candidate), "serve"], cwd=str(candidate.parent),
                env=_startup_environment(host), stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                close_fds=True, **kwargs,
            )
    raise ValueError("No trusted Ollama installation was found. Install Ollama using its official installer.")


def _run_startup(key, attempt, *, stop_event=None, progress=None, timeout=30.0):
    deadline = time.monotonic() + timeout
    stop = stop_event if stop_event is not None else threading.Event()
    acquired = False
    child = None

    def update(stage, percent, detail):
        return _notify_startup(attempt, "starting", stage, percent, detail, progress)

    def verified():
        update("Installation verified", 45, "Known Ollama executable passed its platform trust checks.")
        if stop.is_set():
            raise InterruptedError

    try:
        while not acquired:
            if stop.is_set():
                raise InterruptedError
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            acquired = _startup_launch_lock.acquire(timeout=min(0.1, remaining))
        update("Address verified", 10, "Configured service is restricted to loopback.")
        occupied = _startup_port_present(key)
        update("Listener checked", 25, "Checking service ownership and availability.")
        if not occupied:
            if stop.is_set():
                raise InterruptedError
            child = _spawn_ollama_service(
                key, deadline, verified=verified,
            )
            update("Service launched", 60, "Trusted local Ollama service was started; waiting for its listener.")
        while True:
            if stop.is_set():
                raise InterruptedError
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            if occupied or _startup_port_present(key):
                attest_ollama_service(key)
                if stop.is_set():
                    raise InterruptedError
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                update("Listener verified", 80, "Local Ollama process identity is verified; checking inventory.")
                try:
                    list_models(key, timeout=min(2.0, remaining))
                except OllamaAttestationError:
                    raise
                except (OSError, TimeoutError):
                    # An authenticated daemon may still be starting its API.
                    pass
                else:
                    if stop.is_set():
                        raise InterruptedError
                    if time.monotonic() >= deadline:
                        raise TimeoutError
                    return _notify_startup(
                        attempt, "ready", "Service ready", 100,
                        "Ollama service is ready. Model approval and readiness are checked separately.",
                        progress,
                    )
            if child is not None and child.poll() is not None:
                raise ValueError("Ollama exited before its local API became ready.")
            stop.wait(min(0.2, max(0.0, deadline - time.monotonic())))
    except InterruptedError:
        return _notify_startup(attempt, "cancelled", "Cancelled", attempt.status.percent,
                               "Local AI startup check was cancelled.", progress)
    except TimeoutError:
        return _notify_startup(attempt, "failed", "Timed out", attempt.status.percent,
                               "Ollama did not become ready within the startup deadline.", progress)
    except OllamaAttestationError:
        return _notify_startup(attempt, "failed", "Ownership check failed", attempt.status.percent,
                               "The local AI listener could not be verified; automatic startup stopped.", progress)
    except ValueError as exc:
        # Only our fixed validation messages are safe to display. Model/API
        # errors must not copy attacker-controlled response text into the UI.
        detail = str(exc) if str(exc) in {
            "Start Ollama from a normal user session; automatic AI startup cannot run elevated.",
            "Start Ollama from a normal user session; its linked medium user token is unavailable.",
            "No trusted Ollama installation was found. Install Ollama using its official installer.",
            "Ollama exited before its local API became ready.",
        } else "Local AI startup validation failed."
        return _notify_startup(attempt, "failed", "Startup unavailable", attempt.status.percent, detail, progress)
    except Exception:
        return _notify_startup(attempt, "failed", "Startup unavailable", attempt.status.percent,
                               "Local AI startup could not complete. Check the Ollama installation and service.", progress)
    finally:
        if acquired:
            _startup_launch_lock.release()
        attempt.done.set()


def _startup_timeout(value: float) -> float:
    seconds = float(value)
    if not math.isfinite(seconds) or seconds <= 0:
        raise ValueError("Invalid startup timeout.")
    return min(120.0, max(0.1, seconds))


def ensure_ollama_service(
    host: str = "http://localhost:11434", *, stop_event=None,
    progress: Callable[[OllamaStartupStatus], None] | None = None, timeout: float = 30.0,
) -> OllamaStartupStatus:
    """Check/start the daemon once, coalescing concurrent callers.

    Run on a worker, never the GUI thread. This does not install Ollama, pull
    models, load models, change startup registration, or take response actions.
    """
    try:
        timeout = _startup_timeout(timeout)
        key = _startup_key(host)
        attempt, owner = _claim_startup(key)
    except (ValueError, TypeError):
        return OllamaStartupStatus("failed", "Invalid request", 0,
                                   "Automatic local AI startup request is invalid or busy.")
    if owner:
        return _run_startup(key, attempt, stop_event=stop_event, progress=progress, timeout=timeout)
    deadline = time.monotonic() + timeout
    while not attempt.done.wait(0.1):
        if stop_event is not None and stop_event.is_set():
            return OllamaStartupStatus("cancelled", "Cancelled", attempt.status.percent,
                                       "Local AI startup wait was cancelled.")
        if time.monotonic() >= deadline:
            return attempt.status
    if progress is not None:
        try:
            progress(attempt.status)
        except Exception:
            pass
    return attempt.status


def request_ollama_start(
    host: str = "http://localhost:11434", *, stop_event=None, timeout: float = 30.0,
) -> OllamaStartupStatus:
    """Schedule one bounded startup worker, with no continuing idle polling."""
    try:
        timeout = _startup_timeout(timeout)
        key = _startup_key(host)
        attempt, owner = _claim_startup(key)
    except (ValueError, TypeError):
        return OllamaStartupStatus("failed", "Invalid request", 0,
                                   "Automatic local AI startup request is invalid or busy.")
    if owner:
        worker = threading.Thread(
            target=_run_startup, args=(key, attempt),
            kwargs={"stop_event": stop_event, "timeout": timeout},
            name="OllamaStartup", daemon=True,
        )
        try:
            worker.start()
        except RuntimeError:
            _notify_startup(attempt, "failed", "Startup unavailable", 0,
                            "The local AI startup worker could not start.")
            attempt.done.set()
    return attempt.status


def validate_model_ref(value: str, *, digest_required: bool = False) -> str:
    """Return one normalized Ollama model reference or fail closed.

    Governed packs intentionally use a smaller grammar than Ollama itself: a
    single local name plus either a tag or an immutable SHA-256 manifest
    digest. Registry namespaces and URL-like syntax are not accepted.
    """
    if not isinstance(value, str) or value != value.strip():
        raise ValueError("model reference must be a trimmed string")
    if not value or len(value) > 136 or any(ord(ch) < 33 for ch in value):
        raise ValueError("model reference is empty, oversized, or malformed")
    if "@" in value:
        if value.count("@") != 1:
            raise ValueError("model digest reference is malformed")
        name, digest = value.split("@", 1)
        if not _MODEL_NAME.fullmatch(name) or not _SHA256.fullmatch(digest):
            raise ValueError("model digest reference is invalid")
        return value
    if digest_required:
        raise ValueError("model reference must include an immutable SHA-256 digest")
    if value.count(":") > 1:
        raise ValueError("model tag reference is malformed")
    name, separator, tag = value.partition(":")
    if not _MODEL_NAME.fullmatch(name):
        raise ValueError("model name is invalid")
    if separator and not _MODEL_TAG.fullmatch(tag):
        raise ValueError("model tag is invalid")
    return value


def _exchange(
    host: str,
    path: str,
    *,
    payload: dict[str, Any] | None = None,
    method: str | None = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    return local_json_request(
        host,
        path,
        payload=payload,
        method=method,
        timeout=timeout,
        response_maximum=16 * 1024 * 1024,
        policy=OLLAMA_SERVICE_POLICY,
    )


def list_models(host: str = "http://localhost:11434", timeout: float = 5.0) -> list[dict]:
    """Return a bounded copy of locally installed Ollama model descriptors."""
    models = _exchange(host, "/api/tags", timeout=timeout).get("models", [])
    if not isinstance(models, list) or len(models) > 10_000:
        raise ValueError("Ollama returned an invalid model list")
    if any(not isinstance(item, dict) for item in models):
        raise ValueError("Ollama returned an invalid model descriptor")
    return [dict(item) for item in models]


def show_model(
    model: str,
    host: str = "http://localhost:11434",
    timeout: float = 10.0,
) -> dict[str, Any]:
    return _exchange(
        host,
        "/api/show",
        payload={"model": validate_model_ref(model)},
        timeout=timeout,
    )


def pull_model(
    model: str,
    host: str = "http://localhost:11434",
    timeout: float = 3600.0,
) -> dict[str, Any]:
    """Pull only an immutable digest-qualified model reference."""
    return _exchange(
        host,
        "/api/pull",
        payload={"model": validate_model_ref(model, digest_required=True), "stream": False},
        timeout=timeout,
    )


def create_model(
    destination: str,
    source: str,
    host: str = "http://localhost:11434",
    timeout: float = 3600.0,
) -> dict[str, Any]:
    """Create a local alias from a validated source without a Modelfile."""
    return _exchange(
        host,
        "/api/create",
        payload={
            "model": validate_model_ref(destination),
            "from": validate_model_ref(source),
            "stream": False,
        },
        timeout=timeout,
    )


def copy_model(
    source: str,
    destination: str,
    host: str = "http://localhost:11434",
    timeout: float = 30.0,
) -> dict[str, Any]:
    return _exchange(
        host,
        "/api/copy",
        payload={
            "source": validate_model_ref(source),
            "destination": validate_model_ref(destination),
        },
        timeout=timeout,
    )


def delete_model(
    model: str,
    host: str = "http://localhost:11434",
    timeout: float = 30.0,
) -> dict[str, Any]:
    return _exchange(
        host,
        "/api/delete",
        payload={"model": validate_model_ref(model)},
        method="DELETE",
        timeout=timeout,
    )


def chill_active() -> bool:
    """Return whether Angerona is in its quiet, low-resource profile."""
    return os.environ.get("ANGERONA_CHILL_ACTIVE", "").strip().casefold() in {
        "1", "true", "yes", "on",
    }


def effective_keep_alive(configured: str | int | float = "30m") -> str | int | float:
    """Do not pin a local model in memory while quiet Chill is active.

    Ollama accepts ``0`` as an immediate-unload lease. Interactive ARIA calls
    still work normally; the model is simply released after the answer.
    """
    return 0 if chill_active() else configured


def _json_request(url: str, payload: dict | None, timeout: float) -> dict:
    """Compatibility adapter for older tests and shutdown callers."""
    marker = "/api/"
    index = url.find(marker)
    if index <= 0:
        raise ValueError("Ollama URL must contain a fixed API path")
    path = url[index:]
    if path not in {"/api/ps", "/api/generate"}:
        raise ValueError("Ollama compatibility request path is not permitted")
    return _exchange(url[:index], path, payload=payload, timeout=timeout)


def unload_angerona_models(
    host: str = "http://localhost:11434",
    configured_model: str = "llama3",
    timeout: float = 1.5,
) -> list[str]:
    """Immediately unload resident llama3/configured models from local Ollama.

    Only models reported by ``/api/ps`` are touched, so shutdown never loads a
    missing model merely to unload it.  Ollama itself stays available for other
    local applications; the CPU/GPU-heavy model runner is released.
    """
    base = host.rstrip("/")
    wanted = (configured_model or "llama3").split(":", 1)[0].casefold()
    try:
        running = _json_request(f"{base}/api/ps", None, timeout).get("models", [])
    except Exception:
        return []

    unloaded: list[str] = []
    for item in running:
        name = str(item.get("name") or item.get("model") or "").strip()
        family = name.split(":", 1)[0].casefold()
        if not name or (family != wanted and not family.startswith("llama3")):
            continue
        try:
            _json_request(
                f"{base}/api/generate",
                {
                    "model": validate_model_ref(name),
                    "prompt": "",
                    "stream": False,
                    "keep_alive": 0,
                },
                timeout,
            )
            unloaded.append(name)
        except Exception:
            continue
    return unloaded
