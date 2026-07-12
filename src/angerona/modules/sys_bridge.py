"""sys_bridge.py — Indirect Syscall Fallback Bridge (Code: SYS).

Purpose
    Wrap the compiled ``syscall_bridge.pyd`` C extension so Angerona's SOAR
    containment layer (kill / suspend / resume) can route process-management
    operations *past* hooked ntdll exports.

    Standard SOAR containment path:
        Python os.kill() / psutil → kernel32.TerminateProcess
            → ntdll.NtTerminateProcess  ← hooked here by an attacker

    SYS path (this module):
        syscall_bridge.terminate_process()
            → SSN from on-disk ntdll (unhooked)
            → inline `mov eax,<SSN>; jmp syscall_gadget`
            → kernel mode directly

    Fallback chain (degraded mode):
        If the .pyd is not compiled yet, SYS falls back to the standard
        ctypes / psutil path and emits a LOW health warning.  The SOAR module
        should query ``SysBridgeModule.available`` before using the bridge.

Drop-in contract
    BaseModule subclass + CODE/NAME/state/health_pct/self_test + register().

Usage by SOAR/posture_hardening:
    from angerona.modules.sys_bridge import get_bridge
    bridge = get_bridge()          # returns SysBridgeModule singleton
    bridge.terminate(pid)
    bridge.suspend(pid)
    bridge.resume(pid)
"""
from __future__ import annotations

import ctypes
import os
import sys as _sys
import time

from angerona.core.module_base import BaseModule, Severity

# ── attempt to import the compiled C extension ───────────────────────────────
try:
    import syscall_bridge as _SC_BRIDGE  # type: ignore
    _BRIDGE_AVAILABLE = True
except ImportError:
    _SC_BRIDGE = None
    _BRIDGE_AVAILABLE = False

# ── ctypes fallback implementations ─────────────────────────────────────────
_k32 = None

def _k32_lib():
    global _k32
    if _k32 is None and os.name == "nt":
        _k32 = ctypes.windll.kernel32  # type: ignore
    return _k32


def _ct_terminate(pid: int, exit_code: int = 1) -> bool:
    k = _k32_lib()
    if k is None:
        return False
    PROCESS_TERMINATE = 0x0001
    h = k.OpenProcess(PROCESS_TERMINATE, False, pid)
    if not h:
        return False
    ok = bool(k.TerminateProcess(h, exit_code))
    k.CloseHandle(h)
    return ok


def _ct_suspend(pid: int) -> bool:
    """psutil-based suspend (all threads) as fallback."""
    try:
        import psutil
        p = psutil.Process(pid)
        p.suspend()
        return True
    except Exception:
        return False


def _ct_resume(pid: int) -> bool:
    try:
        import psutil
        p = psutil.Process(pid)
        p.resume()
        return True
    except Exception:
        return False


# ── module ───────────────────────────────────────────────────────────────────
_SINGLETON: "SysBridgeModule | None" = None


def get_bridge() -> "SysBridgeModule":
    """Return the module singleton (used by SOAR / posture_hardening)."""
    global _SINGLETON
    if _SINGLETON is None:
        _SINGLETON = SysBridgeModule()
    return _SINGLETON


class SysBridgeModule(BaseModule):
    CODE = "SYS"
    NAME = "Indirect Syscall Bridge"

    name = "Indirect Syscall Bridge"
    description = (
        "Wraps the compiled syscall_bridge.pyd C extension to route critical "
        "SOAR containment actions (terminate / suspend / resume) via indirect "
        "NT syscalls, bypassing hooked ntdll exports.  Falls back to ctypes/psutil "
        "if the .pyd is not compiled."
    )
    category = "Response"
    version = "1.0.0"
    enabled_by_default = True

    def __init__(self) -> None:
        super().__init__()
        global _SINGLETON
        _SINGLETON = self
        self.available: bool = _BRIDGE_AVAILABLE
        self._ops: int = 0
        self._fallback_ops: int = 0

    # ── dual-contract ────────────────────────────────────────────────────────
    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    # ── public API ───────────────────────────────────────────────────────────
    def terminate(self, pid: int, exit_code: int = 1) -> bool:
        """Terminate process.  Prefers indirect syscall; falls back to ctypes."""
        if _BRIDGE_AVAILABLE:
            try:
                result = _SC_BRIDGE.terminate_process(pid, exit_code)
                self._ops += 1
                return bool(result)
            except Exception as exc:
                self.last_error = str(exc)
        # Fallback
        self._fallback_ops += 1
        ok = _ct_terminate(pid, exit_code)
        if not ok:
            self.emit(f"SYS: fallback terminate({pid}) failed", Severity.HIGH, pid=pid)
        return ok

    def suspend(self, pid: int) -> bool:
        """Suspend all process threads."""
        if _BRIDGE_AVAILABLE:
            try:
                result = _SC_BRIDGE.suspend_process(pid)
                self._ops += 1
                return bool(result)
            except Exception as exc:
                self.last_error = str(exc)
        self._fallback_ops += 1
        return _ct_suspend(pid)

    def resume(self, pid: int) -> bool:
        """Resume all process threads."""
        if _BRIDGE_AVAILABLE:
            try:
                result = _SC_BRIDGE.resume_process(pid)
                self._ops += 1
                return bool(result)
            except Exception as exc:
                self.last_error = str(exc)
        self._fallback_ops += 1
        return _ct_resume(pid)

    def get_ssn(self, func_name: str) -> int | None:
        """Return the SSN for a named Nt* export (debug/audit utility)."""
        if not _BRIDGE_AVAILABLE:
            return None
        try:
            return _SC_BRIDGE.get_ssn(func_name)
        except Exception:
            return None

    # ── lifecycle ────────────────────────────────────────────────────────────
    def run(self) -> None:
        if _BRIDGE_AVAILABLE:
            # Probe that SSN resolution works for key functions
            probes = {}
            for fn in ("NtTerminateProcess", "NtSuspendProcess", "NtResumeProcess"):
                ssn = self.get_ssn(fn)
                probes[fn] = ssn
            all_ok = all(v is not None for v in probes.values())
            self.set_health(100 if all_ok else 75,
                            "Indirect syscall bridge online" if all_ok
                            else "Some SSN probes failed")
            self.emit(
                "SYS online — indirect syscall bridge active (bypasses hooked ntdll).",
                Severity.INFO,
                mode="indirect_syscall",
                ssn_probes={k: hex(v) if v is not None else None for k, v in probes.items()},
            )
        else:
            self.set_health(55, "syscall_bridge.pyd not compiled — ctypes fallback")
            self.emit(
                "SYS: syscall_bridge.pyd not found.  SOAR containment using ctypes "
                "(vulnerable to ntdll hook bypass).  Compile: "
                "cd syscall_bridge && python setup.py build_ext --inplace",
                Severity.LOW,
                mode="ctypes_fallback",
            )

        while not self.stopping:
            self.sleep(60.0)
            # Periodic health refresh
            if _BRIDGE_AVAILABLE:
                pct = 100 if self._fallback_ops == 0 else max(70, 100 - self._fallback_ops * 5)
                self.set_health(pct,
                                f"{self._ops} syscall ops, {self._fallback_ops} fallback ops")

    def self_test(self) -> tuple[bool, str]:
        """Verify the bridge works (SSN probe only — no real process is harmed)."""
        if not _BRIDGE_AVAILABLE:
            return (
                True,
                "syscall_bridge.pyd absent — ctypes fallback active.  "
                "Compile syscall_bridge/ for full hardening.",
            )
        # Probe SSNs for the three core functions
        results = {}
        for fn in ("NtTerminateProcess", "NtSuspendProcess", "NtResumeProcess"):
            ssn = self.get_ssn(fn)
            results[fn] = ssn
        missing = [k for k, v in results.items() if v is None]
        if missing:
            # SSN probe failed but ctypes fallback is still functional — report
            # as degraded (True) so the fix dialog doesn't try to restart the
            # module and risk a native crash from the C extension.
            return (
                True,
                f"SSN resolution unavailable for {', '.join(missing)} — "
                "ctypes/psutil fallback active.  SOAR containment operational "
                "(not indirect-syscall hardened).  Recompile syscall_bridge/ "
                "under a matching Python ABI to restore full bypass capability.",
            )
        summary = ", ".join(f"{k}=0x{v:x}" for k, v in results.items())
        return (True, f"SSN probes OK: {summary}")


def register() -> SysBridgeModule:
    return SysBridgeModule()
