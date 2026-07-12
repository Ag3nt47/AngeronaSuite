"""Memory Injection Scanner — G2-B.

Detects T1055 (Process Injection) by scanning every running process for
anonymous, executable, writable memory regions that are not backed by any
file on disk — the classic hallmark of shellcode injected into a victim process.

Technique — VirtualQueryEx loop:
  For each running PID we call ctypes VirtualQueryEx() in a loop, stepping
  through the process virtual address space in MEMORY_BASIC_INFORMATION chunks.
  If a region is:
    • Protect == PAGE_EXECUTE_READWRITE (0x40)  → classic injectable shellcode
    • Protect == PAGE_EXECUTE_WRITECOPY (0x80)  → rarer but seen with .NET trampolines
    • Type    == MEM_PRIVATE (0x20000)           → not file-backed (no mapped DLL)
    • State   == MEM_COMMIT  (0x1000)            → actually resident in RAM
  that is flagged as suspicious.

False-positive mitigations:
  • JIT runtimes (Python, Node, CLR, JVM) legitimately allocate RWX regions.
    Known safe processes are in the _JIT_SAFE_NAMES allowlist.
  • We skip our own PID (the Angerona process) to avoid self-flagging.
  • We require RegionSize ≥ 4096 bytes (ignores transient 1-page stubs).
  • Re-alerts for the same (pid, base_address) pair are suppressed for 60s.

Privilege note:
  Opening remote processes with PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
  requires at least User-level rights for owned processes, and SeDebugPrivilege
  for system processes.  Missing privilege is caught per-PID and silently
  skipped (not an error; the scanner still covers what it can reach).

Fallback:
  If ctypes / OpenProcess fails entirely (non-Windows), the module parks in an
  idle loop and emits a one-time MEDIUM notice.
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes
import os
import sys
import time
from typing import Optional

from angerona.core.module_base import BaseModule, Severity

# ── Windows constants ─────────────────────────────────────────────────────────
PAGE_EXECUTE_READWRITE  = 0x40
PAGE_EXECUTE_WRITECOPY  = 0x80
_RWX_PROTECTIONS        = frozenset({PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY})
MEM_COMMIT              = 0x1000
MEM_PRIVATE             = 0x20000
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ           = 0x0010
_OPEN_FLAGS               = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ

# JIT runtimes that legitimately produce anonymous RWX pages.
# Lower-cased for case-insensitive comparison.
_JIT_SAFE_NAMES: frozenset[str] = frozenset({
    "python.exe", "pythonw.exe",
    "node.exe",
    "java.exe", "javaw.exe",
    "dotnet.exe",
    "mono.exe",
    "ruby.exe",
    "v8.exe",
    "chrome.exe", "firefox.exe", "msedge.exe",  # browser JITs
})

# Minimum suspicious region size (bytes).  1-page stubs are common in JIT/CLR.
_MIN_REGION_BYTES = 4096

# Suppress repeat alerts for the same (pid, base_addr) for this many seconds.
_DEDUP_TTL = 60.0

# Ensure proper 64-bit padding/alignment for VirtualQueryEx
if sys.maxsize > 2**32:
    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        """ctypes mapping of MEMORY_BASIC_INFORMATION64."""
        _fields_ = [
            ("BaseAddress",       ctypes.c_uint64),
            ("AllocationBase",    ctypes.c_uint64),
            ("AllocationProtect", ctypes.wintypes.DWORD),
            ("__alignment1",      ctypes.wintypes.DWORD),
            ("RegionSize",        ctypes.c_uint64),
            ("State",             ctypes.wintypes.DWORD),
            ("Protect",           ctypes.wintypes.DWORD),
            ("Type",              ctypes.wintypes.DWORD),
            ("__alignment2",      ctypes.wintypes.DWORD),
        ]
else:
    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        """ctypes mapping of MEMORY_BASIC_INFORMATION32."""
        _fields_ = [
            ("BaseAddress",       ctypes.wintypes.DWORD),
            ("AllocationBase",    ctypes.wintypes.DWORD),
            ("AllocationProtect", ctypes.wintypes.DWORD),
            ("RegionSize",        ctypes.wintypes.DWORD),
            ("State",             ctypes.wintypes.DWORD),
            ("Protect",           ctypes.wintypes.DWORD),
            ("Type",              ctypes.wintypes.DWORD),
        ]


def _try_load_kernel32() -> Optional[ctypes.WinDLL]:
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        
        # Explicitly define signatures to prevent ctypes from guessing and 
        # truncating 64-bit handles/sizes into 32-bit integers.
        k32.VirtualQueryEx.argtypes = [
            ctypes.wintypes.HANDLE,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t
        ]
        k32.VirtualQueryEx.restype = ctypes.c_size_t
        
        k32.GetCurrentProcess.argtypes = []
        k32.GetCurrentProcess.restype = ctypes.wintypes.HANDLE
        
        k32.OpenProcess.argtypes = [
            ctypes.wintypes.DWORD, 
            ctypes.wintypes.BOOL, 
            ctypes.wintypes.DWORD
        ]
        k32.OpenProcess.restype = ctypes.wintypes.HANDLE
        
        return k32
    except Exception:
        return None


class MemInjectScannerModule(BaseModule):
    CODE = "MINJ"
    NAME = "Memory Injection Scanner"
    name = "Memory Injection Scanner"
    description = (
        "Scans running process address spaces via VirtualQueryEx for anonymous "
        "RWX memory regions that indicate T1055 injection (shellcode, process "
        "hollowing, reflective DLL loading)."
    )
    category = "Memory"

    # SUPER EFFICIENT: Increased interval to 30 seconds to cut CPU/RAM overhead in half.
    # Shellcode/beacons generally remain resident, so 30s provides excellent detection density.
    _SCAN_INTERVAL = 30.0

    # VAS scan step — VirtualQueryEx advances by RegionSize each iteration,
    # but we cap the loop at this many bytes above the last base to avoid
    # scanning absolutely all 128 TB of 64-bit VAS when a handle error keeps
    # returning the same region.
    _MAX_ADDRESS = 0x7FFFFFFF0000   # stay below kernel space on 64-bit Windows

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    def __init__(self) -> None:
        super().__init__()
        self._k32: Optional[ctypes.WinDLL] = None
        self._self_pid = os.getpid()
        # (pid, base_address) → last_alert_ts
        self._seen: dict[tuple[int, int], float] = {}

    def run(self) -> None:
        self._k32 = _try_load_kernel32()
        if self._k32 is None:
            self.set_health(0, "kernel32.dll unavailable — not Windows?")
            self.emit(
                "MemInjectScanner: kernel32.dll not available. "
                "This module requires Windows. Running idle.",
                Severity.MEDIUM,
            )
            while not self.stopping:
                self.sleep(60.0)
            return

        self.set_health(100, "")
        self.emit("Memory Injection Scanner active — VirtualQueryEx mode.", Severity.INFO)

        while not self.stopping:
            self._scan_all_pids()
            self._evict_stale_dedup()
            self.sleep(self._SCAN_INTERVAL)

    def _scan_all_pids(self) -> None:
        """Enumerate running PIDs via lightweight native API and scan each one."""
        # Use native C-API to batch-pull all PIDs and Names at once. 
        # This completely eliminates heavy psutil.Process() object creation during idle scanning.
        processes = self._get_active_processes()

        for pid, proc_name in processes.items():
            if self.stopping:
                return
            if pid == self._self_pid:
                continue
            # Early JIT exclusion before even opening a process handle
            if proc_name and proc_name.lower() in _JIT_SAFE_NAMES:
                continue
                
            self._scan_pid(pid, proc_name)

    def _get_active_processes(self) -> dict[int, str]:
        """Returns a map of {pid: process_name} using native Windows API."""
        TH32CS_SNAPPROCESS = 0x00000002

        class PROCESSENTRY32(ctypes.Structure):
            _fields_ = [
                ("dwSize",              ctypes.wintypes.DWORD),
                ("cntUsage",            ctypes.wintypes.DWORD),
                ("th32ProcessID",       ctypes.wintypes.DWORD),
                ("th32DefaultHeapID",   ctypes.POINTER(ctypes.c_ulong)),
                ("th32ModuleID",        ctypes.wintypes.DWORD),
                ("cntThreads",          ctypes.wintypes.DWORD),
                ("th32ParentProcessID", ctypes.wintypes.DWORD),
                ("pcPriClassBase",      ctypes.c_long),
                ("dwFlags",             ctypes.wintypes.DWORD),
                ("szExeFile",           ctypes.c_char * 260),
            ]

        proc_map: dict[int, str] = {}
        try:
            snap = self._k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            if snap == ctypes.wintypes.HANDLE(-1).value:
                return proc_map
            
            entry = PROCESSENTRY32()
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
            
            if self._k32.Process32First(snap, ctypes.byref(entry)):
                while True:
                    try:
                        name = entry.szExeFile.decode('utf-8', errors='ignore')
                    except Exception:
                        name = ""
                    proc_map[entry.th32ProcessID] = name
                    
                    if not self._k32.Process32Next(snap, ctypes.byref(entry)):
                        break
            self._k32.CloseHandle(snap)
        except Exception:
            pass
        return proc_map

    def _scan_pid(self, pid: int, proc_name: str) -> None:
        """Walk the VAS of a single PID, looking for suspicious RWX regions."""
        handle = None
        try:
            handle = self._k32.OpenProcess(_OPEN_FLAGS, False, pid)
            if not handle:
                return   # access denied or already exited

            mbi = MEMORY_BASIC_INFORMATION()
            mbi_size = ctypes.sizeof(mbi)
            addr: int = 0

            while addr < self._MAX_ADDRESS:
                ret = self._k32.VirtualQueryEx(
                    handle,
                    ctypes.c_void_p(addr),
                    ctypes.byref(mbi),
                    mbi_size,
                )
                if ret == 0:
                    break   # end of accessible VAS for this process

                region_base = mbi.BaseAddress
                region_size = mbi.RegionSize

                if (
                    mbi.State   == MEM_COMMIT
                    and mbi.Type    == MEM_PRIVATE
                    and mbi.Protect in _RWX_PROTECTIONS
                    and region_size >= _MIN_REGION_BYTES
                ):
                    self._alert(pid, proc_name, region_base, region_size, mbi.Protect)

                # Advance — if RegionSize is 0 we'd loop forever
                if region_size == 0:
                    break
                addr = region_base + region_size

        except Exception:
            pass
        finally:
            if handle:
                try:
                    self._k32.CloseHandle(handle)
                except Exception:
                    pass

    # ── Enrichment helpers ────────────────────────────────────────────────────
    def _enrich_process(self, pid: int) -> dict:
        """CRITICAL WHEN NEEDED: Heavy psutil enrichment only runs upon detection."""
        ctx: dict = {}
        try:
            import psutil
            p = psutil.Process(pid)
            with p.oneshot():
                ctx["exe"]       = p.exe()
                ctx["cmdline"]   = " ".join(p.cmdline()[:8])
                ctx["username"]  = p.username()
                ctx["status"]    = p.status()
                ctx["threads"]   = p.num_threads()
                age_s = time.time() - p.create_time()
                ctx["age_s"]     = int(age_s)
                ctx["age_human"] = (f"{int(age_s // 3600)}h{int(age_s % 3600 // 60)}m"
                                    if age_s >= 3600
                                    else f"{int(age_s // 60)}m{int(age_s % 60)}s")
                try:
                    parent = p.parent()
                    ctx["parent"] = f"{parent.name()}(pid={parent.pid})"
                except Exception:
                    ctx["parent"] = "unknown"
                try:
                    ctx["children"] = len(p.children())
                except Exception:
                    pass
                try:
                    ctx["dll_count"] = len(p.memory_maps())
                except Exception:
                    pass
                try:
                    conns = p.connections(kind="inet")
                    remote = {f"{c.raddr.ip}:{c.raddr.port}"
                              for c in conns if c.raddr}
                    ctx["connections"] = list(remote)[:8]
                except Exception:
                    pass
                try:
                    minfo = p.memory_info()
                    ctx["rss_kb"] = minfo.rss // 1024
                    ctx["vms_mb"] = minfo.vms // (1024 * 1024)
                except Exception:
                    pass
        except Exception:
            pass
        return ctx

    @staticmethod
    def _predict_technique(proc_name, size, protect, ctx):
        """Human-readable prediction of the likely injection technique."""
        name = (proc_name or "").lower()
        connections = ctx.get("connections", [])
        children = ctx.get("children", 0)
        dll_count = ctx.get("dll_count", 0)
        prot_rwx = protect == PAGE_EXECUTE_READWRITE

        if any(t in name for t in ("svchost", "lsass", "winlogon", "csrss")):
            hint = "high-value system process targeted — likely privilege escalation vector"
        elif connections:
            hint = "process has external network connections — possible C2 beacon carrier"
        elif children > 3:
            hint = "process spawned multiple children — possible process hollowing pivot"
        elif dll_count and dll_count < 5:
            hint = "very few loaded modules — possible hollowed/packed binary"
        elif size > 1_048_576:
            hint = "large anonymous region (>1 MB) — consistent with reflective DLL loading"
        elif not prot_rwx:
            hint = "PAGE_EXECUTE_WRITECOPY — .NET/CLR trampoline or managed injection"
        else:
            hint = "anonymous RWX shellcode stub — consistent with shellcode staging"

        techniques = ["T1055 (Process Injection)"]
        if "svchost" in name or "lsass" in name:
            techniques += ["T1055.001 (DLL Injection)", "T1078.003 (Valid Accounts: Local)"]
        if size > 1_048_576:
            techniques += ["T1055.001 (Reflective DLL Injection)"]
        if children > 3:
            techniques += ["T1055.012 (Process Hollowing)"]
        if connections:
            techniques += ["T1071 (Application Layer Protocol)"]

        return f"{hint} | Techniques: {', '.join(techniques)}"

    # ── Alert ─────────────────────────────────────────────────────────────────
    def _alert(self, pid, proc_name, base, size, protect):
        key = (pid, base)
        now = time.time()
        if now - self._seen.get(key, 0.0) < _DEDUP_TTL:
            return
        self._seen[key] = now

        prot_name = (
            "PAGE_EXECUTE_READWRITE" if protect == PAGE_EXECUTE_READWRITE
            else "PAGE_EXECUTE_WRITECOPY"
        )
        name_str = proc_name or f"PID {pid}"

        # Deep enrichment triggered only upon detection
        ctx = self._enrich_process(pid)
        prediction = self._predict_technique(proc_name, size, protect, ctx)

        parts = [
            f"Suspicious RWX memory in {name_str} (PID={pid})",
            f"Region: 0x{base:X}–0x{base + size:X}  size={size // 1024}KB  protect={prot_name}",
        ]
        if ctx.get("exe"):
            parts.append(f"Executable: {ctx['exe']}")
        if ctx.get("username"):
            parts.append(f"Running as: {ctx['username']}")
        if ctx.get("parent"):
            parts.append(f"Parent: {ctx['parent']}")
        if ctx.get("age_human"):
            parts.append(f"Process age: {ctx['age_human']}")
        if ctx.get("connections"):
            parts.append(f"Active connections: {', '.join(ctx['connections'])}")
        if ctx.get("dll_count") is not None:
            parts.append(f"Loaded modules: {ctx['dll_count']}")
        parts.append(f"Predicted: {prediction}")

        self.emit(
            "\n".join(parts),
            Severity.HIGH,
            pid=pid,
            proc_name=proc_name,
            exe=ctx.get("exe", ""),
            cmdline=ctx.get("cmdline", ""),
            username=ctx.get("username", ""),
            parent=ctx.get("parent", ""),
            base_address=hex(base),
            region_size=size,
            protection=prot_name,
            process_age_s=ctx.get("age_s"),
            threads=ctx.get("threads"),
            dll_count=ctx.get("dll_count"),
            connections=ctx.get("connections", []),
            rss_kb=ctx.get("rss_kb"),
            predicted_technique=prediction,
            mitre_tags=["T1055", "T1055.001", "T1055.003", "T1055.012"],
        )

    def _evict_stale_dedup(self):
        """Remove expired dedup entries to prevent unbounded growth."""
        cutoff = time.time() - _DEDUP_TTL
        stale  = [k for k, ts in self._seen.items() if ts < cutoff]
        for k in stale:
            del self._seen[k]

    def self_test(self):
        if self.status != "running":
            return super().self_test()   # not started yet — graceful "stopped" status
        if self._k32 is None:
            return False, "kernel32 not loaded"
        try:
            mbi  = MEMORY_BASIC_INFORMATION()
            ret  = self._k32.VirtualQueryEx(
                self._k32.GetCurrentProcess(),
                ctypes.c_void_p(0),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi),
            )
            if ret > 0:
                return True, "VirtualQueryEx functional"
            return False, "VirtualQueryEx returned 0 on own process"
        except Exception as exc:
            return False, str(exc)


def register():
    return MemInjectScannerModule()