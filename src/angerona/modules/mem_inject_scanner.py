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
    An exact path+digest policy binding may lower this weak signal to MEDIUM,
    but the process is still scanned and still produces an event.
  • We skip our own PID (the Angerona process) to avoid self-flagging.
  • We require RegionSize ≥ 4096 bytes (ignores transient 1-page stubs).
  • Re-alerts for the same (pid, base_address) pair are suppressed for 60s.

Privilege note:
  Opening remote processes with PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
  requires at least User-level rights for owned processes, and SeDebugPrivilege
  for system processes. Missing privilege is measured as denied coverage and
  keeps health below 100 rather than silently presenting a green sensor.

Fallback:
  If ctypes / OpenProcess fails entirely (non-Windows), the module parks in an
  idle loop and emits a one-time MEDIUM notice.
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes
import hmac
import os
import sys
import time
from dataclasses import dataclass
from typing import Optional

from angerona.core.module_base import BaseModule, Severity
from angerona.core.process_allowlist import (
    executable_sha256 as _executable_sha256,
    policy_snapshot as _process_policy_snapshot,
)

# ── Windows constants ─────────────────────────────────────────────────────────
PAGE_EXECUTE_READWRITE  = 0x40
PAGE_EXECUTE_WRITECOPY  = 0x80
_RWX_PROTECTIONS        = frozenset({PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY})
MEM_COMMIT              = 0x1000
MEM_PRIVATE             = 0x20000
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ           = 0x0010
_OPEN_FLAGS               = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ

# JIT runtimes / Chromium-Electron apps that legitimately produce anonymous RWX
# pages (V8, CLR, JVM, LuaJIT, etc.). Lower-cased for case-insensitive compare.
# NOTE: this is a false-positive DAMPER for the weak "RWX-alone" signal, not a
# trust grant — RWX here is expected behaviour for these apps. Real trust of a
# specific binary path still goes through core.process_allowlist (Settings ▸
# Trusted Processes / Resolve Center ▸ Allow). LOLBins (powershell/cmd/rundll32/
# mshta/regsvr32) are deliberately NOT listed — they are common injection hosts.
_JIT_SAFE_NAMES: frozenset[str] = frozenset({
    # language runtimes
    "python.exe", "pythonw.exe", "node.exe", "java.exe", "javaw.exe",
    "dotnet.exe", "mono.exe", "ruby.exe", "perl.exe", "v8.exe", "deno.exe", "bun.exe",
    # browsers (V8/SpiderMonkey JIT)
    "chrome.exe", "firefox.exe", "msedge.exe", "brave.exe", "opera.exe",
    "vivaldi.exe", "chromium.exe", "iexplore.exe",
    # Chromium/Electron desktop apps — heavy V8 JIT, many RWX regions per process
    "claude.exe", "electron.exe", "code.exe", "code - insiders.exe", "cursor.exe",
    "discord.exe", "slack.exe", "teams.exe", "ms-teams.exe", "msteams.exe",
    "msedgewebview2.exe", "spotify.exe", "signal.exe", "whatsapp.exe",
    "telegram.exe", "obsidian.exe", "notion.exe", "figma.exe", "gitkraken.exe",
    "postman.exe", "1password.exe", "steam.exe", "steamwebhelper.exe",
    "epicgameslauncher.exe",
})


class PROCESSENTRY32W(ctypes.Structure):
    """HANDLE-safe Toolhelp process record for both 32- and 64-bit Python."""

    _fields_ = [
        ("dwSize", ctypes.wintypes.DWORD),
        ("cntUsage", ctypes.wintypes.DWORD),
        ("th32ProcessID", ctypes.wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", ctypes.wintypes.DWORD),
        ("cntThreads", ctypes.wintypes.DWORD),
        ("th32ParentProcessID", ctypes.wintypes.DWORD),
        ("pcPriClassBase", ctypes.wintypes.LONG),
        ("dwFlags", ctypes.wintypes.DWORD),
        ("szExeFile", ctypes.c_wchar * 260),
    ]


class FILETIME(ctypes.Structure):
    _fields_ = [
        ("dwLowDateTime", ctypes.wintypes.DWORD),
        ("dwHighDateTime", ctypes.wintypes.DWORD),
    ]


@dataclass(frozen=True, slots=True)
class _ProcessEnumeration:
    processes: dict[int, str]
    complete: bool
    error: str = ""


@dataclass(frozen=True, slots=True)
class _PidScanResult:
    opened: bool
    scanned: bool
    outcome: str


@dataclass(frozen=True, slots=True)
class ProcessCoverage:
    enumerated: int = 0
    opened: int = 0
    scanned: int = 0
    denied: int = 0
    failed: int = 0
    skipped: int = 0
    enumeration_complete: bool = False
    enumeration_error: str = ""

    @property
    def health(self) -> int:
        eligible = self.enumerated - self.skipped
        if not self.enumeration_complete or eligible <= 0:
            return 0
        return max(0, min(100, int((self.scanned * 100) / eligible)))

    @property
    def detail(self) -> str:
        state = "complete" if self.enumeration_complete else "incomplete"
        detail = (
            f"coverage {self.health}%: enumerated={self.enumerated}, "
            f"opened={self.opened}, scanned={self.scanned}, denied={self.denied}, "
            f"failed={self.failed}, skipped={self.skipped}; enumeration={state}"
        )
        if self.enumeration_error:
            detail += f" ({self.enumeration_error[:160]})"
        return detail

# Minimum suspicious region size (bytes).  1-page stubs are common in JIT/CLR.
_MIN_REGION_BYTES = 4096

# Per-PROCESS alert cooldown. A JIT-heavy app can hold dozens of anonymous RWX
# regions across several PIDs; alerting per region produced hundreds of near-
# identical alerts and froze the GUI. We now emit at most one aggregated alert
# per process per this window.
_DEDUP_TTL = 300.0

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

        k32.CreateToolhelp32Snapshot.argtypes = [
            ctypes.wintypes.DWORD,
            ctypes.wintypes.DWORD,
        ]
        k32.CreateToolhelp32Snapshot.restype = ctypes.wintypes.HANDLE

        k32.Process32FirstW.argtypes = [
            ctypes.wintypes.HANDLE,
            ctypes.POINTER(PROCESSENTRY32W),
        ]
        k32.Process32FirstW.restype = ctypes.wintypes.BOOL
        k32.Process32NextW.argtypes = [
            ctypes.wintypes.HANDLE,
            ctypes.POINTER(PROCESSENTRY32W),
        ]
        k32.Process32NextW.restype = ctypes.wintypes.BOOL
        k32.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
        k32.CloseHandle.restype = ctypes.wintypes.BOOL
        k32.QueryFullProcessImageNameW.argtypes = [
            ctypes.wintypes.HANDLE,
            ctypes.wintypes.DWORD,
            ctypes.wintypes.LPWSTR,
            ctypes.POINTER(ctypes.wintypes.DWORD),
        ]
        k32.QueryFullProcessImageNameW.restype = ctypes.wintypes.BOOL
        k32.GetProcessTimes.argtypes = [
            ctypes.wintypes.HANDLE,
            ctypes.POINTER(FILETIME),
            ctypes.POINTER(FILETIME),
            ctypes.POINTER(FILETIME),
            ctypes.POINTER(FILETIME),
        ]
        k32.GetProcessTimes.restype = ctypes.wintypes.BOOL
        
        return k32
    except Exception:
        return None


class MemInjectScannerModule(BaseModule):
    CODE = "MINJ"
    NAME = "Memory Injection Scanner"
    name = "Memory Injection Scanner"
    version = "1.13.0"
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
        # pid → last aggregated-alert ts (per-process cooldown; also throttles the
        # heavy psutil enrichment so it can't run every scan for the same process)
        self._seen: dict[int, float] = {}
        self._coverage = ProcessCoverage()

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

        self.emit("Memory Injection Scanner active — VirtualQueryEx mode.", Severity.INFO)

        while not self.stopping:
            self._coverage = self._scan_all_pids()
            self.set_health(self._coverage.health, self._coverage.detail)
            self._evict_stale_dedup()
            self.sleep(self._SCAN_INTERVAL)

    def _scan_all_pids(self) -> ProcessCoverage:
        """Scan every enumerated PID and return an honest coverage receipt."""
        # Use native C-API to batch-pull all PIDs and Names at once. 
        # This completely eliminates heavy psutil.Process() object creation during idle scanning.
        enumeration = self._get_active_processes()
        processes = enumeration.processes
        process_policy = _process_policy_snapshot()
        opened = scanned = denied = failed = skipped = processed = 0

        for pid, proc_name in processes.items():
            if self.stopping:
                failed += max(0, len(processes) - processed)
                break
            if pid == self._self_pid:
                skipped += 1
                processed += 1
                continue
            # A basename is never scan authority. JIT names are used only after
            # a suspicious region is observed to tune the alert's severity.
            result = self._scan_pid(pid, proc_name, process_policy)
            processed += 1
            opened += int(result.opened)
            scanned += int(result.scanned)
            if result.outcome == "denied":
                denied += 1
            elif result.outcome == "failed":
                failed += 1

        return ProcessCoverage(
            enumerated=len(processes),
            opened=opened,
            scanned=scanned,
            denied=denied,
            failed=failed,
            skipped=skipped,
            enumeration_complete=enumeration.complete and not self.stopping,
            enumeration_error=enumeration.error,
        )

    def _get_active_processes(self) -> _ProcessEnumeration:
        """Return a typed Toolhelp process inventory; partial reads stay visible."""
        TH32CS_SNAPPROCESS = 0x00000002
        proc_map: dict[int, str] = {}
        snap = None
        try:
            snap = self._k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            invalid = ctypes.c_void_p(-1).value
            if not snap or int(snap) == invalid:
                return _ProcessEnumeration({}, False, "snapshot creation failed")
            
            entry = PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
            
            if not self._k32.Process32FirstW(snap, ctypes.byref(entry)):
                return _ProcessEnumeration({}, False, "first process record unavailable")
            while True:
                proc_map[int(entry.th32ProcessID)] = str(entry.szExeFile or "")
                ctypes.set_last_error(0)
                if not self._k32.Process32NextW(snap, ctypes.byref(entry)):
                    error = ctypes.get_last_error()
                    if error != 18:  # ERROR_NO_MORE_FILES
                        return _ProcessEnumeration(
                            proc_map, False, f"process enumeration error {error}"
                        )
                    break
            if not proc_map:
                return _ProcessEnumeration({}, False, "no process records returned")
            return _ProcessEnumeration(proc_map, True)
        except Exception as exc:
            return _ProcessEnumeration(
                proc_map, False, f"{type(exc).__name__} during process enumeration"
            )
        finally:
            if snap and int(snap) != ctypes.c_void_p(-1).value:
                try:
                    self._k32.CloseHandle(snap)
                except Exception:
                    pass

    def _scan_pid(
        self, pid: int, proc_name: str, process_policy=None
    ) -> _PidScanResult:
        """Walk the VAS of a single PID, looking for suspicious RWX regions."""
        handle = None
        try:
            ctypes.set_last_error(0)
            handle = self._k32.OpenProcess(_OPEN_FLAGS, False, pid)
            if not handle:
                return _PidScanResult(
                    False,
                    False,
                    "denied" if ctypes.get_last_error() == 5 else "failed",
                )
            mbi = MEMORY_BASIC_INFORMATION()
            mbi_size = ctypes.sizeof(mbi)
            addr: int = 0
            regions: list[tuple[int, int, int]] = []   # (base, size, protect)
            queried = 0

            while addr < self._MAX_ADDRESS:
                ctypes.set_last_error(0)
                ret = self._k32.VirtualQueryEx(
                    handle,
                    ctypes.c_void_p(addr),
                    ctypes.byref(mbi),
                    mbi_size,
                )
                if ret == 0:
                    if ctypes.get_last_error() not in (0, 87):
                        return _PidScanResult(True, False, "failed")
                    break   # end of accessible VAS for this process
                queried += 1

                region_base = mbi.BaseAddress
                region_size = mbi.RegionSize

                if (
                    mbi.State   == MEM_COMMIT
                    and mbi.Type    == MEM_PRIVATE
                    and mbi.Protect in _RWX_PROTECTIONS
                    and region_size >= _MIN_REGION_BYTES
                ):
                    regions.append((region_base, region_size, mbi.Protect))
                    if len(regions) >= 64:
                        break   # already ample evidence; stop walking 128TB of VAS

                # Advance — if RegionSize is 0 we'd loop forever
                next_address = int(region_base) + int(region_size)
                if region_size == 0 or next_address <= addr:
                    return _PidScanResult(True, False, "failed")
                addr = next_address

            # One aggregated alert per process (not one per region) — this is what
            # turned a JIT app's dozens of RWX regions into an alert storm.
            if regions:
                # Resolve/hash the executable from this still-open process
                # object only after a suspicious region exists. Ordinary
                # processes pay no image-hash cost and no PID lookup can grant
                # a pre-scan exclusion.
                bound_image = self._bound_image_identity(handle)
                self._alert(
                    pid,
                    proc_name,
                    regions,
                    process_policy,
                    bound_image=bound_image,
                )
            if queried <= 0:
                return _PidScanResult(True, False, "failed")
            return _PidScanResult(True, True, "scanned")

        except Exception:
            return _PidScanResult(bool(handle), False, "failed")
        finally:
            if handle:
                try:
                    self._k32.CloseHandle(handle)
                except Exception:
                    pass

    # ── Enrichment helpers ────────────────────────────────────────────────────
    def _bound_image_identity(self, process_handle: int) -> dict[str, object]:
        """Resolve the image path from the exact opened process object."""
        try:
            buffer = ctypes.create_unicode_buffer(32768)
            size = ctypes.wintypes.DWORD(len(buffer))
            if not self._k32.QueryFullProcessImageNameW(
                process_handle, 0, buffer, ctypes.byref(size)
            ):
                return {}
            path = os.path.normcase(os.path.normpath(buffer.value))
            if not path or not os.path.isabs(path):
                return {}
            created = FILETIME()
            exited = FILETIME()
            kernel = FILETIME()
            user = FILETIME()
            if not self._k32.GetProcessTimes(
                process_handle,
                ctypes.byref(created),
                ctypes.byref(exited),
                ctypes.byref(kernel),
                ctypes.byref(user),
            ):
                return {}
            windows_ticks = (
                int(created.dwHighDateTime) << 32
            ) | int(created.dwLowDateTime)
            created_epoch = (windows_ticks - 116444736000000000) / 10_000_000
            if created_epoch <= 0:
                return {}
            return {
                "exe": path,
                "image_sha256": _executable_sha256(path),
                "image_identity_bound": True,
                "process_create_time": created_epoch,
            }
        except (AttributeError, OSError, TypeError, ValueError):
            return {}

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
                ctx["process_create_time"] = float(p.create_time())
                age_s = time.time() - ctx["process_create_time"]
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
    @staticmethod
    def _trusted_jit_image(
        proc_name: str,
        path: str,
        image_sha256: str,
        process_policy,
    ) -> bool:
        """Accept a JIT damper only for an exact executable path+digest."""
        if (
            not path
            or not image_sha256
            or (proc_name or "").casefold() not in _JIT_SAFE_NAMES
        ):
            return False
        normalized = os.path.normcase(os.path.normpath(path))
        expected = ""
        for row in process_policy or ():
            if len(row) >= 3 and row[1] == normalized and row[2]:
                expected = str(row[2]).casefold()
                break
        if not expected:
            return False
        return hmac.compare_digest(image_sha256, expected)

    def _alert(
        self,
        pid,
        proc_name,
        regions,
        process_policy=None,
        *,
        bound_image: Optional[dict[str, object]] = None,
    ):
        now = time.time()
        if now - self._seen.get(pid, 0.0) < _DEDUP_TTL:
            return
        # Start the per-process cooldown up front so an allowlisted or repeat
        # process isn't re-enriched (heavy psutil) on every 30s scan.
        self._seen[pid] = now

        # Largest region drives the technique prediction and the headline detail.
        base, size, protect = max(regions, key=lambda r: r[1])
        region_count = len(regions)
        prot_name = (
            "PAGE_EXECUTE_READWRITE" if protect == PAGE_EXECUTE_READWRITE
            else "PAGE_EXECUTE_WRITECOPY"
        )
        name_str = proc_name or f"PID {pid}"

        # Deep enrichment triggered only upon detection
        ctx = self._enrich_process(pid)
        if bound_image:
            ctx.update(bound_image)
        trusted_jit = self._trusted_jit_image(
            proc_name,
            str(ctx.get("exe") or ""),
            str(ctx.get("image_sha256") or ""),
            process_policy,
        )
        prediction = self._predict_technique(proc_name, size, protect, ctx)

        parts = [
            f"Suspicious RWX memory in {name_str} (PID={pid}) — "
            f"{region_count} anonymous RWX region(s)",
            f"Largest: 0x{base:X}–0x{base + size:X}  size={size // 1024}KB  protect={prot_name}",
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
            Severity.MEDIUM if trusted_jit else Severity.HIGH,
            pid=pid,
            proc_name=proc_name,
            exe=ctx.get("exe", ""),
            cmdline=ctx.get("cmdline", ""),
            username=ctx.get("username", ""),
            parent=ctx.get("parent", ""),
            base_address=hex(base),
            region_size=size,
            region_count=region_count,
            protection=prot_name,
            process_age_s=ctx.get("age_s"),
            threads=ctx.get("threads"),
            dll_count=ctx.get("dll_count"),
            connections=ctx.get("connections", []),
            rss_kb=ctx.get("rss_kb"),
            predicted_technique=prediction,
            mitre_tags=["T1055", "T1055.001", "T1055.003", "T1055.012"],
            process_create_time=ctx.get("process_create_time"),
            active_attack=True,
            detector_policy="rwx-memory-indicator-alert-only",
            exact_identity_jit_damper=trusted_jit,
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
