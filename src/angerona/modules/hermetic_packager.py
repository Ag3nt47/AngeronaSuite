"""hermetic_packager.py — Monolithic Packaging Reporter (Code: HERMETIC).

Purpose
    Track the build status of the HERMETIC monolithic binary — a single signed
    executable produced by PyOxidizer that embeds the Python interpreter,
    all dependencies, and every Angerona module as memory-loaded bytecode.

    Benefits of the hermetic binary
    ──────────────────────────────
    • Eliminates loose .py scripts that can be monkey-patched or swapped by
      a local attacker who has write access to the Python installation.
    • The interpreter, stdlib, and modules are loaded entirely from in-process
      memory (no filesystem traversal at import time).
    • Code signing allows Windows Defender / AppLocker to whitelist *only*
      the signed binary — blocking unsigned injection.
    • A single frozen executable is significantly harder to profile or patch
      than editable source files.

    This module does NOT build the binary at runtime (build is offline).
    Instead it:
      1. Checks whether the binary exists and validates its authenticode
         signature (Windows only).
      2. Emits a health warning if running as loose .py files so the operator
         knows the hardened mode is not active.
      3. Exposes a ``trigger_build()`` helper that opens a terminal to run
         ``hermetic/build-hermetic.bat`` — review-gated, never auto-executes.
      4. Reports the binary path, size, and signature status to the dashboard.

Drop-in contract
    BaseModule subclass + CODE/NAME/state/health_pct/self_test + register().
"""
from __future__ import annotations

import ctypes
import hmac
import os
import pathlib
import re
import stat
import subprocess
import sys
from typing import BinaryIO

from angerona.core.data_paths import project_root
from angerona.core.module_base import BaseModule, Severity

_BUILD_BAT = project_root() / "hermetic" / "build-hermetic.bat"
_BIN_CANDIDATES = [
    pathlib.Path(sys.executable).parent / "angerona.exe",
    project_root() / "dist" / "angerona.exe",
    pathlib.Path(sys.executable).parent / "angerona",          # Linux/macOS hermetic
]
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_BUILD_SCRIPT_BYTES = 2 * 1024 * 1024


def _find_binary() -> pathlib.Path | None:
    for p in _BIN_CANDIDATES:
        if p.exists():
            return p
    return None


def _is_frozen() -> bool:
    """Packaging hint only; never treated as process-image authority."""
    return getattr(sys, "frozen", False) or hasattr(sys, "_MEIPASS")


def _current_process_image() -> pathlib.Path:
    """Resolve the image Windows says created this process, not Python metadata."""
    if sys.platform == "win32":
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        query = kernel.GetModuleFileNameW
        query.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32]
        query.restype = ctypes.c_uint32
        buffer = ctypes.create_unicode_buffer(32768)
        length = int(query(None, buffer, len(buffer)))
        if not 0 < length < len(buffer):
            raise OSError(ctypes.get_last_error(), "current process image query failed")
        return pathlib.Path(buffer.value).resolve(strict=True)
    try:
        proc_image = pathlib.Path("/proc/self/exe")
        if proc_image.exists():
            return proc_image.resolve(strict=True)
    except OSError:
        pass
    return pathlib.Path(sys.executable).resolve(strict=True)


def _check_signature(path: pathlib.Path) -> tuple[bool, str, str, str]:
    """Read a bounded Authenticode identity through the trusted OS toolchain."""
    from angerona.core.executable_trust import _authenticode_identity

    status, publisher, thumbprint = _authenticode_identity(path)
    return status.casefold() == "valid", status, publisher, thumbprint


def _image_path_protected(path: pathlib.Path) -> bool:
    from angerona.core.executable_trust import (
        _is_link_or_reparse,
        _protected_path,
        _reject_reparse_components,
    )

    try:
        _reject_reparse_components(path)
        info = path.stat()
        return bool(
            path.is_file()
            and not _is_link_or_reparse(path)
            and stat.S_ISREG(info.st_mode)
            and int(getattr(info, "st_nlink", 1)) == 1
            and _protected_path(path)
        )
    except (OSError, RuntimeError, ValueError):
        return False


def _acquire_build_script(path: pathlib.Path) -> tuple[BinaryIO, str, tuple[int, ...]]:
    """Hold the exact reviewed batch object with replacement denied."""
    from angerona.core.executable_trust import (
        ExecutableTrustError,
        _hash_stream,
        _identity,
        _is_link_or_reparse,
        _open_sealed,
        _reject_reparse_components,
    )

    try:
        absolute = path.absolute()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ExecutableTrustError("hermetic build script is unavailable") from exc
    if os.path.normcase(os.path.normpath(str(absolute))) != os.path.normcase(
        os.path.normpath(str(resolved))
    ):
        raise ExecutableTrustError("hermetic build script path does not resolve exactly")
    _reject_reparse_components(resolved)
    if _is_link_or_reparse(resolved):
        raise ExecutableTrustError("hermetic build script is link/reparse-backed")
    stream = _open_sealed(resolved)
    try:
        opened = os.fstat(stream.fileno())
        current = resolved.stat()
        identity = _identity(opened)
        if (
            not stat.S_ISREG(opened.st_mode)
            or int(getattr(opened, "st_nlink", 1)) != 1
            or not 0 < int(opened.st_size) <= _MAX_BUILD_SCRIPT_BYTES
            or identity != _identity(current)
        ):
            raise ExecutableTrustError(
                "hermetic build script is not one stable bounded file"
            )
        digest = _hash_stream(stream, opened.st_size)
        if identity != _identity(resolved.stat()):
            raise ExecutableTrustError("hermetic build script changed while hashing")
        return stream, digest, identity
    except Exception:
        stream.close()
        raise


class HermeticPackagerModule(BaseModule):
    CODE = "HERMETIC"
    NAME = "Monolithic Packaging"

    name = "Monolithic Packaging"
    description = (
        "Monitors whether Angerona is running as a signed, monolithic hermetic "
        "binary (PyOxidizer).  Loose .py execution is flagged as a hardening gap. "
        "Exposes trigger_build() for review-gated rebuild — never auto-executes."
    )
    category = "Resilience"
    version = "1.13.0"
    enabled_by_default = True

    _POLL = 300.0   # recheck every 5 minutes

    def __init__(self) -> None:
        super().__init__()
        self._binary: pathlib.Path | None = None
        self._sig_status: str = "unchecked"
        self._publisher: str = ""
        self._thumbprint: str = ""
        self._image_authority: str = "unchecked"
        self._is_hermetic: bool = False
        self._build_jobs: list[tuple[subprocess.Popen, BinaryIO, str]] = []

    # ── dual-contract ────────────────────────────────────────────────────────
    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    # ── public API ────────────────────────────────────────────────────────────
    def build_review(self) -> dict[str, object]:
        """Return the exact digest an operator must confirm before execution."""
        try:
            stream, digest, identity = _acquire_build_script(_BUILD_BAT)
            stream.close()
            return {
                "ready": True,
                "path": str(_BUILD_BAT.resolve(strict=True)),
                "sha256": digest,
                "size": identity[2],
            }
        except Exception as exc:
            return {
                "ready": False,
                "path": str(_BUILD_BAT),
                "sha256": "",
                "reason": str(exc)[:500],
            }

    def _reap_build_jobs(self, *, stop: bool = False) -> None:
        retained: list[tuple[subprocess.Popen, BinaryIO, str]] = []
        for process, custody, digest in self._build_jobs:
            try:
                running = process.poll() is None
            except OSError:
                running = False
            if stop and running:
                try:
                    process.terminate()
                    process.wait(timeout=3.0)
                except (OSError, subprocess.SubprocessError):
                    try:
                        process.kill()
                    except OSError:
                        pass
                running = False
            if running:
                retained.append((process, custody, digest))
            else:
                try:
                    custody.close()
                except OSError:
                    pass
        self._build_jobs = retained

    def trigger_build(
        self, *, approved: bool = False, expected_sha256: str = ""
    ) -> bool:
        """Launch only the exact digest the operator explicitly reviewed."""
        review = self.build_review()
        expected = str(expected_sha256 or "").strip().casefold()
        if not approved or not _SHA256.fullmatch(expected):
            self.emit(
                "Hermetic build requires explicit approval of the displayed exact "
                "script digest; nothing was executed.",
                Severity.LOW,
                build_review=review,
                execution_authorized=False,
            )
            return False
        if not review.get("ready") or not hmac.compare_digest(
            str(review.get("sha256") or ""), expected
        ):
            self.emit(
                "Hermetic build script does not match the approved digest; "
                "execution was refused.",
                Severity.MEDIUM,
                build_review=review,
                approved_sha256=expected,
                execution_authorized=False,
            )
            return False
        if sys.platform != "win32":
            self.emit(
                "Interactive hermetic build launch is available only on Windows.",
                Severity.LOW,
                build_review=review,
                execution_authorized=False,
            )
            return False
        custody: BinaryIO | None = None
        try:
            from angerona.core.executable_trust import _protected_path
            from angerona.core.privilege import (
                sanitized_child_environment,
                trusted_windows_directories,
            )

            custody, actual, _identity = _acquire_build_script(_BUILD_BAT)
            if not hmac.compare_digest(actual, expected):
                raise PermissionError("build script changed after operator review")
            _windows, system = trusted_windows_directories()
            command = (system / "cmd.exe").resolve(strict=True)
            if not _protected_path(command):
                raise PermissionError("trusted Windows command processor is unavailable")
            process = subprocess.Popen(
                [str(command), "/d", "/q", "/k", str(_BUILD_BAT.resolve())],
                stdin=subprocess.DEVNULL,
                cwd=str(_BUILD_BAT.parent.resolve()),
                env=sanitized_child_environment(source={}),
                close_fds=True,
                creationflags=(
                    getattr(subprocess, "CREATE_NEW_CONSOLE", 0x10)
                    | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                ),
            )
            self._build_jobs.append((process, custody, actual))
            custody = None
            self.emit(
                "Opened the exact reviewed hermetic build script in a minimal, "
                "non-elevated Windows environment.",
                Severity.INFO,
                build_script=str(_BUILD_BAT.resolve()),
                build_sha256=actual,
                build_pid=process.pid,
                execution_authorized=True,
            )
            return True
        except Exception as exc:
            self.last_error = str(exc)
            self.emit(
                f"Hermetic build launch refused: {exc}",
                Severity.MEDIUM,
                build_review=review,
                execution_authorized=False,
            )
            return False
        finally:
            if custody is not None:
                custody.close()

    # ── assessment ────────────────────────────────────────────────────────────
    def _assess(self) -> tuple[int, str]:
        self._is_hermetic = _is_frozen()

        if self._is_hermetic:
            try:
                self._binary = _current_process_image()
            except OSError as exc:
                self._binary = None
                self._image_authority = f"OS image query failed: {exc}"
                return (35, self._image_authority)
            if sys.platform == "win32":
                protected = _image_path_protected(self._binary)
                signed, status, publisher, thumbprint = _check_signature(self._binary)
                self._sig_status = status
                self._publisher = publisher
                self._thumbprint = thumbprint
                from angerona.core.windows_package_identity import (
                    verify_current_msix_authority,
                )

                package = verify_current_msix_authority()
                self._image_authority = package.reason
                if protected and signed and package.trusted:
                    return (
                        100,
                        f"OS image, protected path, Authenticode, and exact MSIX "
                        f"authority verified ({self._binary.name})",
                    )
                factors = (
                    f"protected={protected}, signature={status}, "
                    f"package={package.reason}"
                )
                if protected and signed:
                    return (75, f"Hermetic image verified locally; {factors}")
                if protected:
                    return (60, f"Hermetic OS image lacks publisher proof; {factors}")
                return (40, f"Frozen metadata lacks protected image custody; {factors}")
            self._sig_status = "unsupported"
            self._image_authority = "non-Windows package publisher proof unavailable"
            return (
                65,
                f"Hermetic OS image identified ({self._binary}); independent "
                "publisher/package proof unavailable on this platform",
            )

        self._binary = _find_binary()

        if self._binary:
            # Binary exists but we're running as .py — partial credit
            if os.name == "nt":
                signed, status, publisher, thumbprint = _check_signature(self._binary)
                self._sig_status = status
                self._publisher = publisher
                self._thumbprint = thumbprint
                note = f"signed={status}" if signed else f"unsigned ({status})"
                return (
                    55,
                    f"Running as .py (hardening gap) — hermetic binary present ({note}).  "
                    "Consider running angerona.exe.",
                )
            return (50, "Running as .py — hermetic binary present but inactive")

        # No binary, running as loose source
        self._sig_status = "n/a"
        return (
            30,
            "Running as loose .py files — HERMETIC binary not built.  "
            "Run hermetic/build-hermetic.bat to harden.",
        )

    # ── lifecycle ─────────────────────────────────────────────────────────────
    def run(self) -> None:
        pct, note = self._assess()
        self.set_health(pct, note)
        sev = Severity.INFO if pct >= 80 else Severity.LOW if pct >= 50 else Severity.MEDIUM
        self.emit(f"HERMETIC: {note}", sev,
                  hermetic=self._is_hermetic,
                  binary=str(self._binary) if self._binary else None,
                  signature=self._sig_status,
                  publisher=self._publisher,
                  certificate_thumbprint=self._thumbprint,
                  image_authority=self._image_authority)

        while not self.stopping:
            self.sleep(self._POLL)
            self._reap_build_jobs()
            pct, note = self._assess()
            self.set_health(pct, note)
        self._reap_build_jobs(stop=True)

    def self_test(self) -> tuple[bool, str]:
        pct, note = self._assess()
        build_bat_present = _BUILD_BAT.exists()
        return (
            True,  # always passes — reports status, not a binary correctness check
            f"Assessment: {note} | "
            f"build-hermetic.bat={'found' if build_bat_present else 'missing'} | "
            f"hermetic={self._is_hermetic}",
        )


def register() -> HermeticPackagerModule:
    return HermeticPackagerModule()
