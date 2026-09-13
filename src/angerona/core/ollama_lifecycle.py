"""Bounded lifecycle helpers for Angerona's loopback Ollama service.

Only validated model identifiers are placed into fixed Ollama API payloads.
Callers cannot provide API paths, URLs, executable Modelfiles, or shell text.
"""
from __future__ import annotations

import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path, PureWindowsPath
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


def _ollama_listener_pids(port: int) -> set[int]:
    try:
        import psutil

        listeners: set[int] = set()
        for connection in psutil.net_connections(kind="tcp"):
            if str(getattr(connection, "status", "")).upper() != "LISTEN":
                continue
            address = getattr(connection, "laddr", None)
            if not address or int(getattr(address, "port", address[1])) != port:
                continue
            host = str(getattr(address, "ip", address[0])).split("%", 1)[0]
            if host not in {"127.0.0.1", "::1"}:
                continue
            pid = getattr(connection, "pid", None)
            if isinstance(pid, int) and pid > 0:
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
    pids = _ollama_listener_pids(port)
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
