"""sys_bridge.py — authenticated native-bridge boundary (Code: SYS).

Purpose
    Provide a safe process-control fallback while reserving a private native
    bridge boundary for a future release-manifest-sealed broker.  An ambient
    top-level ``syscall_bridge`` import is never attempted.

    Standard SOAR containment path:
        Python os.kill() / psutil → kernel32.TerminateProcess
            → ntdll.NtTerminateProcess  ← hooked here by an attacker

Fallback chain (degraded mode):
        Until a fixed private namespace, release-manifest digest/publisher and
        broker ABI are all available, SYS uses explicit-prototype ctypes/psutil
        calls and reports degraded health.  The SOAR module should query
        ``SysBridgeModule.available`` before claiming indirect-syscall coverage.

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

from angerona.core.module_base import BaseModule, Severity

# Native loading deliberately stays off unless Angerona gains a fixed private
# package namespace, release-manifest publisher/digest validation, no-reparse
# object binding and an authenticated broker ABI.  Importing a top-level module
# from ambient ``sys.path`` is never an acceptable availability probe.
_SC_BRIDGE = None
_BRIDGE_AVAILABLE = False
_BRIDGE_REASON = (
    "native bridge unavailable: no release-manifest-sealed private broker; "
    "explicit ctypes/psutil fallback active"
)

# ── ctypes fallback implementations ─────────────────────────────────────────
_k32 = None

def _k32_lib():
    global _k32
    if _k32 is None and os.name == "nt":
        # LOAD_LIBRARY_SEARCH_SYSTEM32 avoids current-directory/PATH DLL search.
        try:
            kernel = ctypes.WinDLL(
                "kernel32.dll", use_last_error=True, winmode=0x00000800
            )
        except (AttributeError, OSError, TypeError):
            return None
        kernel.OpenProcess.argtypes = [
            ctypes.c_uint32,
            ctypes.c_int,
            ctypes.c_uint32,
        ]
        kernel.OpenProcess.restype = ctypes.c_void_p
        kernel.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        kernel.TerminateProcess.restype = ctypes.c_int
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel.CloseHandle.restype = ctypes.c_int
        _k32 = kernel
    return _k32


def _ct_terminate(pid: int, exit_code: int = 1) -> bool:
    if type(pid) is not int or not 1 <= pid <= 0xFFFFFFFF:
        return False
    if type(exit_code) is not int or not 0 <= exit_code <= 0xFFFFFFFF:
        return False
    k = _k32_lib()
    if k is None:
        return False
    PROCESS_TERMINATE = 0x0001
    h = k.OpenProcess(PROCESS_TERMINATE, False, pid)
    if not h:
        return False
    try:
        return bool(k.TerminateProcess(h, exit_code))
    finally:
        k.CloseHandle(h)


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
        "Uses explicit-prototype ctypes/psutil process controls and exposes a "
        "truthful unavailable state for the native indirect-syscall bridge until "
        "a fixed private, release-manifest-sealed broker is installed."
    )
    category = "Response"
    version = "1.13.0"
    enabled_by_default = True

    def __init__(self) -> None:
        super().__init__()
        global _SINGLETON
        _SINGLETON = self
        self.available: bool = _BRIDGE_AVAILABLE
        self._ops: int = 0
        self._fallback_ops: int = 0
        if not self.available:
            self.set_health(55, _BRIDGE_REASON)

    # ── dual-contract ────────────────────────────────────────────────────────
    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    # ── public API ───────────────────────────────────────────────────────────
    def terminate(self, pid: int, exit_code: int = 1) -> bool:
        """Terminate a process through the safe fallback boundary."""
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
            self.set_health(55, _BRIDGE_REASON)
            self.emit(
                "SYS: native bridge is not admitted. SOAR containment uses the "
                "explicit ctypes/psutil fallback and does not claim hook-bypass coverage.",
                Severity.LOW,
                mode="ctypes_fallback",
                native_bridge_admitted=False,
                native_bridge_reason=_BRIDGE_REASON,
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
                "No sealed private native bridge admitted; explicit ctypes/psutil "
                "fallback active and health is truthfully degraded.",
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
