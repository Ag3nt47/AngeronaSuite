"""Fail-closed process and transport boundary for GitHub publication helpers.

The boundary deliberately does not inherit the caller's executable search path,
Git configuration environment, proxy settings, TLS overrides, or ask-pass
programs.  On Windows, Git and Git Credential Manager are selected beneath the
machine-wide Git for Windows installation recorded in HKLM.  The credential
manager is the only publication credential boundary; it may return an already
stored operating-system credential, but interactive acquisition and ambient
credential helpers are disabled.
"""

from __future__ import annotations

import ctypes
import os
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from tools.windows_publication_runtime import (
    StagedWindowsRuntime,
    WindowsRuntimeError,
    stage_pinned_runtime,
)


CANONICAL_GITHUB_ORIGIN = "https://github.com/Ag3nt47/AngeronaSuite.git"
_MAX_ERROR_TEXT = 500
_WINDOWS_REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class PublicationTransportError(RuntimeError):
    """Raised when executable or subprocess transport custody is not proven."""


@dataclass(frozen=True)
class _FileIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int


def _file_identity(path: Path) -> _FileIdentity:
    try:
        details = path.stat()
    except OSError as exc:
        raise PublicationTransportError(
            f"trusted publication executable is unavailable: {path}"
        ) from exc
    attributes = int(getattr(details, "st_file_attributes", 0))
    if attributes & _WINDOWS_REPARSE or not path.is_file():
        raise PublicationTransportError(
            f"trusted publication executable is not a regular file: {path}"
        )
    return _FileIdentity(
        int(details.st_dev),
        int(details.st_ino),
        int(details.st_size),
        int(details.st_mtime_ns),
    )


def _resolve_beneath(root: Path, relative: Path, *, label: str) -> Path:
    try:
        root_details = root.lstat()
        resolved_root = root.resolve(strict=True)
        candidate = (resolved_root / relative).resolve(strict=True)
    except OSError as exc:
        raise PublicationTransportError(f"{label} is unavailable") from exc
    if root != resolved_root or (
        int(getattr(root_details, "st_file_attributes", 0)) & _WINDOWS_REPARSE
    ):
        raise PublicationTransportError(f"{label} installation root is an alias")
    if not candidate.is_relative_to(resolved_root):
        raise PublicationTransportError(f"{label} escapes its trusted installation")
    current = candidate
    while current != resolved_root:
        try:
            details = current.lstat()
        except OSError as exc:
            raise PublicationTransportError(f"{label} identity is unavailable") from exc
        if int(getattr(details, "st_file_attributes", 0)) & _WINDOWS_REPARSE:
            raise PublicationTransportError(f"{label} traverses a reparse point")
        current = current.parent
    return candidate


def _windows_directory() -> Path:
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        query = kernel32.GetWindowsDirectoryW
        query.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
        query.restype = ctypes.c_uint
        buffer = ctypes.create_unicode_buffer(32768)
        length = int(query(buffer, len(buffer)))
    except (AttributeError, OSError, TypeError, ValueError) as exc:
        raise PublicationTransportError("trusted Windows directory query failed") from exc
    if length <= 0 or length >= len(buffer) or not buffer.value:
        raise PublicationTransportError("trusted Windows directory is unavailable")
    try:
        directory = Path(buffer.value).resolve(strict=True)
    except OSError as exc:
        raise PublicationTransportError("trusted Windows directory is unavailable") from exc
    if not directory.is_absolute():
        raise PublicationTransportError("trusted Windows directory is not absolute")
    return directory


def _machine_git_for_windows() -> StagedWindowsRuntime:
    try:
        import winreg

        access = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\GitForWindows",
            0,
            access,
        ) as key:
            raw_root, value_type = winreg.QueryValueEx(key, "InstallPath")
    except (ImportError, OSError, TypeError, ValueError) as exc:
        raise PublicationTransportError(
            "machine-wide Git for Windows installation is unavailable"
        ) from exc
    if value_type not in {winreg.REG_SZ, winreg.REG_EXPAND_SZ}:
        raise PublicationTransportError("machine Git installation path has wrong type")
    if not isinstance(raw_root, str) or not raw_root or "%" in raw_root:
        raise PublicationTransportError("machine Git installation path is not literal")
    install_root = Path(raw_root)
    if not install_root.is_absolute():
        raise PublicationTransportError("machine Git installation path is not absolute")
    try:
        return stage_pinned_runtime(install_root)
    except WindowsRuntimeError as exc:
        raise PublicationTransportError(str(exc)) from exc


def _trusted_posix_git() -> tuple[Path, Path, None]:
    candidates = (Path("/usr/bin/git"), Path("/usr/local/bin/git"))
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
            details = resolved.stat()
        except OSError:
            continue
        parents_trusted = all(
            parent.stat().st_uid == 0
            and not parent.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            for parent in (resolved.parent, *resolved.parents[1:])
        )
        if (
            resolved.is_file()
            and details.st_uid == 0
            and not details.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            and parents_trusted
        ):
            return resolved.parent, resolved, None
    raise PublicationTransportError("no root-owned fixed-path Git executable is available")


def _reject_ambient_git_authority(environment: Mapping[str, str]) -> None:
    forbidden: list[str] = []
    for name, value in environment.items():
        if not value:
            continue
        normalized = name.upper()
        # --no-pager makes GIT_PAGER unreachable, and an inherited disabled
        # terminal prompt is already the exact value this boundary installs.
        if normalized == "GIT_PAGER" or (
            normalized == "GIT_TERMINAL_PROMPT" and value == "0"
        ):
            continue
        if normalized.startswith("GIT_") or normalized == "SSH_ASKPASS":
            forbidden.append(name)
    forbidden.sort()
    if forbidden:
        raise PublicationTransportError(
            "ambient Git authority is forbidden: " + ", ".join(forbidden)
        )


def _minimal_git_environment(
    install_root: Path,
    *,
    staged: StagedWindowsRuntime | None = None,
) -> dict[str, str]:
    environment = {
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GCM_INTERACTIVE": "Never",
        "LANG": "C",
        "LC_ALL": "C",
    }
    if os.name == "nt":
        if staged is None:
            raise PublicationTransportError("pinned Windows Git runtime is unavailable")
        windows = _windows_directory()
        system32 = _resolve_beneath(
            windows,
            Path("System32"),
            label="Windows System32",
        )
        command = _resolve_beneath(
            windows,
            Path("System32") / "cmd.exe",
            label="Windows command processor",
        )
        trusted_path = (
            staged.root / "cmd",
            staged.root / "mingw64" / "bin",
            staged.git_exec_path,
            staged.shell_path,
            system32,
        )
        if any(not item.is_dir() for item in trusted_path):
            raise PublicationTransportError("trusted Git runtime path is incomplete")
        environment.update({
            "COMSPEC": str(command),
            "GIT_EXEC_PATH": str(staged.git_exec_path),
            "PATH": os.pathsep.join(str(item) for item in trusted_path),
            "SystemRoot": str(windows),
            "TEMP": str(staged.scratch_root),
            "TMP": str(staged.scratch_root),
            "WINDIR": str(windows),
        })
    else:
        environment["PATH"] = os.pathsep.join(
            dict.fromkeys((str(install_root), "/usr/bin", "/bin"))
        )
    return environment


def _shell_quote_helper(credential_helper: Path) -> str:
    """Build one exact absolute helper command for Git's POSIX-shell parser.

    Git only recognizes an unquoted absolute helper path as a literal command.
    A safely quoted path starts with a quote instead, so Git would otherwise
    prefix it with ``git credential-``.  The documented ``!`` form selects an
    explicit shell command while the single quotes keep the trusted absolute
    path (including spaces and metacharacters) one literal token.
    """

    helper = credential_helper.as_posix()
    if not credential_helper.is_absolute() or any(
        character in helper for character in ("\0", "\r", "\n")
    ):
        raise PublicationTransportError("Git Credential Manager path is invalid")
    return "!'" + helper.replace("'", "'\\''") + "'"


def _configuration_arguments(*, credential_helper: Path | None) -> list[str]:
    null_path = os.devnull.replace("\\", "/")
    origin = CANONICAL_GITHUB_ORIGIN
    exact_http = f"http.{origin}"
    arguments = [
        "-c", f"core.hooksPath={null_path}",
        "-c", "core.fsmonitor=false",
        "-c", "core.askPass=",
        "-c", "core.sshCommand=",
        "-c", "core.gitProxy=",
        "-c", "protocol.allow=never",
        "-c", "protocol.https.allow=always",
        "-c", f"url.{origin}.insteadOf={origin}",
        "-c", f"url.{origin}.pushInsteadOf={origin}",
        "-c", "http.proxy=",
        "-c", "http.sslVerify=true",
        "-c", "http.extraHeader=",
        "-c", "http.cookieFile=",
        "-c", "http.saveCookies=false",
        "-c", "http.followRedirects=initial",
        "-c", f"{exact_http}.proxy=",
        "-c", f"{exact_http}.sslVerify=true",
        "-c", f"{exact_http}.extraHeader=",
        "-c", "credential.helper=",
        "-c", "credential.https://github.com.helper=",
        "-c", "credential.interactive=never",
        "-c", "credential.https://github.com.useHttpPath=true",
    ]
    if os.name == "nt":
        arguments.extend([
            "-c", "http.sslBackend=schannel",
            "-c", "http.schannelUseSSLCAInfo=false",
            "-c", "http.schannelCheckRevoke=true",
        ])
    if credential_helper is not None:
        # Empty entries above reset all lower-priority helper lists.  The exact
        # machine-installation manager is then the sole allowed helper.
        helper = _shell_quote_helper(credential_helper)
        arguments.extend([
            "-c", f"credential.helper={helper}",
            "-c", f"credential.https://github.com.helper={helper}",
        ])
    return arguments


@dataclass
class TrustedGitBoundary:
    """One identity-bound Git executable and fresh allowlisted environment."""

    executable: Path
    executable_identity: _FileIdentity
    credential_helper: Path | None
    credential_helper_identity: _FileIdentity | None
    environment_items: tuple[tuple[str, str], ...]
    execution_directory: Path
    staged_runtime: StagedWindowsRuntime | None = None
    _closed: bool = False

    @property
    def environment(self) -> dict[str, str]:
        return dict(self.environment_items)

    def revalidate(self) -> None:
        if self._closed:
            raise PublicationTransportError("trusted publication runtime is closed")
        if self.staged_runtime is not None:
            try:
                self.staged_runtime.revalidate()
            except WindowsRuntimeError as exc:
                raise PublicationTransportError(str(exc)) from exc
        if _file_identity(self.executable) != self.executable_identity:
            raise PublicationTransportError("trusted Git executable changed during use")
        if self.credential_helper is not None:
            if _file_identity(self.credential_helper) != self.credential_helper_identity:
                raise PublicationTransportError(
                    "trusted Git Credential Manager changed during use"
                )

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self.staged_runtime is not None:
            try:
                self.staged_runtime.close()
            except WindowsRuntimeError as exc:
                raise PublicationTransportError(str(exc)) from exc

    def __del__(self) -> None:
        if not getattr(self, "_closed", True):
            try:
                self.close()
            except Exception:
                pass

    def run(
        self,
        root: Path,
        arguments: Sequence[str],
        *,
        text: bool,
        timeout: float,
    ) -> subprocess.CompletedProcess[str] | subprocess.CompletedProcess[bytes]:
        if not root.is_absolute():
            raise PublicationTransportError("Git working root must be absolute")
        if not 1.0 <= timeout <= 300.0:
            raise PublicationTransportError("Git timeout is outside the trusted bound")
        if any(not isinstance(item, str) or "\0" in item for item in arguments):
            raise PublicationTransportError("Git argument is not a bounded text token")
        self.revalidate()
        command = [
            str(self.executable),
            "--no-pager",
            *_configuration_arguments(
                credential_helper=self.credential_helper
            ),
            "-C",
            str(root),
            *arguments,
        ]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=text,
                check=False,
                stdin=subprocess.DEVNULL,
                cwd=str(self.execution_directory),
                env=self.environment,
                timeout=timeout,
                creationflags=(
                    getattr(subprocess, "CREATE_NO_WINDOW", 0)
                    if os.name == "nt"
                    else 0
                ),
            )
        except subprocess.TimeoutExpired:
            raise PublicationTransportError("trusted Git process timed out") from None
        except OSError:
            raise PublicationTransportError("trusted Git process failed") from None
        self.revalidate()
        return result


def resolve_trusted_git_boundary(
    *,
    source_environment: Mapping[str, str] | None = None,
) -> TrustedGitBoundary:
    """Resolve and bind Git without accepting caller executable authority."""

    source = os.environ if source_environment is None else source_environment
    _reject_ambient_git_authority(source)
    staged: StagedWindowsRuntime | None = None
    if sys.platform == "win32":
        staged = _machine_git_for_windows()
        install_root = staged.root
        git = staged.executable
        helper = staged.credential_helper
    else:
        install_root, git, helper = _trusted_posix_git()
    try:
        environment = _minimal_git_environment(install_root, staged=staged)
        boundary = TrustedGitBoundary(
            executable=git,
            executable_identity=_file_identity(git),
            credential_helper=helper,
            credential_helper_identity=(
                _file_identity(helper) if helper is not None else None
            ),
            environment_items=tuple(sorted(environment.items())),
            execution_directory=staged.root if staged is not None else install_root,
            staged_runtime=staged,
        )
        if staged is not None:
            # Even the version proof crosses only the completed sealed boundary;
            # no Git image runs while profile/source staging is still in flight.
            result = boundary.run(
                staged.root,
                ("--version", "--build-options"),
                text=True,
                timeout=15.0,
            )
            lines = result.stdout.splitlines()
            expected_version = f"git version {staged.git_version}"
            expected_build = f"built from commit: {staged.git_build_commit}"
            if (
                result.returncode != 0
                or not lines
                or lines[0] != expected_version
                or expected_build not in lines
            ):
                raise PublicationTransportError(
                    "staged Git version/build does not match the reviewed profile"
                )
            boundary.revalidate()
        return boundary
    except Exception:
        if staged is not None and not staged.closed:
            try:
                staged.close()
            except WindowsRuntimeError:
                pass
        raise


def bounded_error(result: subprocess.CompletedProcess[str] | subprocess.CompletedProcess[bytes]) -> str:
    """Return bounded diagnostic text without reflecting arbitrary amounts of output."""

    raw = result.stderr or result.stdout
    if isinstance(raw, bytes):
        detail = raw.decode("utf-8", errors="replace")
    else:
        detail = raw
    return detail.strip()[:_MAX_ERROR_TEXT]
