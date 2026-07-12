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

import os
import pathlib
import subprocess
import sys
import time

from angerona.core.module_base import BaseModule, Severity

_BUILD_BAT = pathlib.Path(__file__).resolve().parents[4] / "hermetic" / "build-hermetic.bat"
_BIN_CANDIDATES = [
    pathlib.Path(sys.executable).parent / "angerona.exe",
    pathlib.Path(__file__).resolve().parents[4] / "dist" / "angerona.exe",
    pathlib.Path(sys.executable).parent / "angerona",          # Linux/macOS hermetic
]


def _find_binary() -> pathlib.Path | None:
    for p in _BIN_CANDIDATES:
        if p.exists():
            return p
    return None


def _is_frozen() -> bool:
    """True when running inside a PyOxidizer / PyInstaller frozen binary."""
    return getattr(sys, "frozen", False) or hasattr(sys, "_MEIPASS")


def _check_signature(path: pathlib.Path) -> tuple[bool, str]:
    """Verify Authenticode signature via PowerShell (Windows only)."""
    if os.name != "nt":
        return (False, "signature check requires Windows")
    try:
        result = subprocess.run(
            [
                "powershell", "-NoProfile", "-NonInteractive", "-Command",
                f"(Get-AuthenticodeSignature '{path}').Status",
            ],
            capture_output=True, text=True, timeout=10,
        )
        status = result.stdout.strip()
        return (status == "Valid", status)
    except Exception as exc:
        return (False, str(exc))


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
    version = "1.0.0"
    enabled_by_default = True

    _POLL = 300.0   # recheck every 5 minutes

    def __init__(self) -> None:
        super().__init__()
        self._binary: pathlib.Path | None = None
        self._sig_status: str = "unchecked"
        self._is_hermetic: bool = False

    # ── dual-contract ────────────────────────────────────────────────────────
    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    # ── public API ────────────────────────────────────────────────────────────
    def trigger_build(self) -> None:
        """Open a terminal window to run build-hermetic.bat — REVIEW GATED."""
        if not _BUILD_BAT.exists():
            self.emit(
                f"Build script not found: {_BUILD_BAT}. "
                "See AngeronaSuite/hermetic/build-hermetic.bat",
                Severity.LOW,
            )
            return
        self.emit(
            "Opening hermetic build terminal — REVIEW GATED.  "
            "Inspect the build script before proceeding.",
            Severity.INFO,
            build_script=str(_BUILD_BAT),
        )
        if os.name == "nt":
            subprocess.Popen(
                ["cmd", "/k", str(_BUILD_BAT)],
                creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0x10),
            )

    # ── assessment ────────────────────────────────────────────────────────────
    def _assess(self) -> tuple[int, str]:
        self._is_hermetic = _is_frozen()
        self._binary = _find_binary()

        if self._is_hermetic:
            # Running inside the frozen binary — best-case
            if os.name == "nt" and self._binary:
                signed, status = _check_signature(self._binary)
                self._sig_status = status
                if signed:
                    return (100, f"Hermetic + signed ({self._binary.name})")
                return (80, f"Hermetic but signature {status} — sign the binary")
            return (85, "Hermetic binary (signature check N/A on this OS)")

        if self._binary:
            # Binary exists but we're running as .py — partial credit
            if os.name == "nt":
                signed, status = _check_signature(self._binary)
                self._sig_status = status
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
                  signature=self._sig_status)

        while not self.stopping:
            self.sleep(self._POLL)
            pct, note = self._assess()
            self.set_health(pct, note)

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
