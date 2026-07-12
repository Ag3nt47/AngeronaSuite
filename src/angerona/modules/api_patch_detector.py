"""api_patch_detector.py — API Patch & Anti-Blinding Detector (Code: APID).

Purpose
    Detect whether malware in the simulation has inline-hooked ("blinded")
    AngeronaSuite's own user-mode sensors by patching the prologues of critical
    ``ntdll.dll`` / ``kernel32.dll`` exports.

Method (read-only, defensive)
    1. Read the pristine DLLs straight from ``C:\\Windows\\System32\\`` on disk and
       parse their export table to locate each watched function's byte prologue.
    2. Resolve the SAME functions in our own loaded address space
       (GetModuleHandle → GetProcAddress) and read their live prologue bytes.
    3. If the live prologue differs from disk AND begins with a known inline-hook
       stub — ``E9`` (rel JMP), ``FF 25`` (indirect JMP), or ``68 … C3``
       (push/ret) — raise a CRITICAL integrity alert to
       ``shared_logs/soar_events.json``.

    This module never writes to another process, never installs or removes a
    hook, and never unmaps memory. It only reads and compares.

Drop-in contract: BaseModule subclass + CODE/NAME/state/health_pct/self_test +
module-level register().
"""
from __future__ import annotations

import ctypes
import json
import os
import struct
import threading
import time
from pathlib import Path

from angerona.core.module_base import BaseModule, Severity

_SYS32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
_WATCH = {
    "ntdll.dll": ["NtProtectVirtualMemory", "NtWriteVirtualMemory",
                  "NtReadVirtualMemory", "NtCreateThreadEx", "NtMapViewOfSection",
                  "NtQuerySystemInformation", "NtResumeThread"],
    "kernel32.dll": ["CreateRemoteThread", "WriteProcessMemory",
                     "VirtualProtectEx", "LoadLibraryA", "LoadLibraryW",
                     "GetProcAddress"],
}
_PROLOGUE = 16


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


# ── minimal PE export-table parser (stdlib struct only) ──────────────────────
class _PE:
    def __init__(self, data: bytes) -> None:
        self.data = data
        if data[:2] != b"MZ":
            raise ValueError("not a PE (no MZ)")
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            raise ValueError("no PE signature")
        coff = e_lfanew + 4
        self.n_sections = struct.unpack_from("<H", data, coff + 2)[0]
        opt = coff + 20
        self.magic = struct.unpack_from("<H", data, opt)[0]     # 0x10b=PE32, 0x20b=PE32+
        # export dir is data directory entry 0; the DataDirectory array sits at a
        # different optional-header offset per format: PE32+ (0x20b) at +112,
        # PE32 (0x10b) at +96. (ImageBase is 8 bytes in PE32+, shifting the rest.)
        dd = opt + (112 if self.magic == 0x20b else 96)
        self.exp_rva, self.exp_size = struct.unpack_from("<II", data, dd)
        sec = opt + struct.unpack_from("<H", data, coff + 16)[0]  # SizeOfOptionalHeader
        self.sections = []
        for i in range(self.n_sections):
            base = sec + i * 40
            vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, base + 8)
            self.sections.append((vaddr, vsize, rawptr, rawsize))

    def rva_to_off(self, rva: int) -> int | None:
        for vaddr, vsize, rawptr, rawsize in self.sections:
            if vaddr <= rva < vaddr + max(vsize, rawsize):
                return rawptr + (rva - vaddr)
        return None

    def exports(self) -> dict[str, int]:
        """name -> function RVA."""
        out: dict[str, int] = {}
        if not self.exp_rva:
            return out
        off = self.rva_to_off(self.exp_rva)
        if off is None:
            return out
        n_names = struct.unpack_from("<I", self.data, off + 24)[0]
        funcs_rva = struct.unpack_from("<I", self.data, off + 28)[0]
        names_rva = struct.unpack_from("<I", self.data, off + 32)[0]
        ords_rva = struct.unpack_from("<I", self.data, off + 36)[0]
        fo, no, oo = (self.rva_to_off(funcs_rva), self.rva_to_off(names_rva),
                      self.rva_to_off(ords_rva))
        if None in (fo, no, oo):
            return out
        for i in range(n_names):
            name_rva = struct.unpack_from("<I", self.data, no + i * 4)[0]
            name_off = self.rva_to_off(name_rva)
            if name_off is None:
                continue
            end = self.data.index(b"\x00", name_off)
            name = self.data[name_off:end].decode("ascii", "ignore")
            ordn = struct.unpack_from("<H", self.data, oo + i * 2)[0]
            frva = struct.unpack_from("<I", self.data, fo + ordn * 4)[0]
            out[name] = frva
        return out

    def prologue(self, name: str, exports: dict[str, int]) -> bytes | None:
        rva = exports.get(name)
        if rva is None:
            return None
        off = self.rva_to_off(rva)
        if off is None:
            return None
        return self.data[off:off + _PROLOGUE]


def _looks_hooked(mem: bytes) -> str | None:
    if not mem:
        return None
    if mem[0] == 0xE9:
        return "E9 rel-JMP"
    if mem[:2] == b"\xff\x25":
        return "FF25 indirect-JMP"
    if mem[0] == 0x68 and 0xC3 in mem[:8]:
        return "68…C3 push-ret"
    return None


class ApiPatchDetectorModule(BaseModule):
    CODE = "APID"
    NAME = "API Patch / Anti-Blinding Detector"
    name = "API Patch / Anti-Blinding Detector"
    description = ("Reads pristine ntdll/kernel32 from disk and compares export "
                   "prologues against live memory to catch inline sensor hooks.")
    category = "Integrity"
    version = "1.0.0"
    enabled_by_default = True

    _INTERVAL = 30.0

    def __init__(self) -> None:
        super().__init__()
        self.state_lock = threading.Lock()
        self._soar = _repo_root() / "shared_logs" / "soar_events.json"
        self._disk_cache: dict[str, dict[str, bytes]] = {}
        self._flagged: set[str] = set()

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    # ── disk baseline ────────────────────────────────────────────────────────
    def _disk_prologues(self, dll: str) -> dict[str, bytes]:
        if dll in self._disk_cache:
            return self._disk_cache[dll]
        result: dict[str, bytes] = {}
        try:
            data = Path(_SYS32, dll).read_bytes()
            pe = _PE(data)
            exports = pe.exports()
            for fn in _WATCH[dll]:
                pr = pe.prologue(fn, exports)
                if pr:
                    result[fn] = pr
        except Exception as exc:
            self.last_error = f"{dll}: {exc}"
        self._disk_cache[dll] = result
        return result

    # ── live memory ────────────────────────────────────────────────────────
    def _mem_prologue(self, dll: str, fn: str) -> bytes | None:
        if os.name != "nt":
            return None
        try:
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            k32.GetModuleHandleW.restype = ctypes.c_void_p
            k32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
            h = k32.GetModuleHandleW(dll)
            if not h:
                k32.LoadLibraryW.restype = ctypes.c_void_p
                k32.LoadLibraryW.argtypes = [ctypes.c_wchar_p]
                h = k32.LoadLibraryW(dll)
            if not h:
                return None
            k32.GetProcAddress.restype = ctypes.c_void_p
            k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
            addr = k32.GetProcAddress(ctypes.c_void_p(h), fn.encode("ascii"))
            if not addr:
                return None
            return ctypes.string_at(addr, _PROLOGUE)
        except Exception as exc:
            self.last_error = f"mem {dll}!{fn}: {exc}"
            return None

    def scan_once(self) -> list[dict]:
        """Compare disk vs live prologues; return a list of hook findings."""
        findings: list[dict] = []
        checked = 0
        for dll in _WATCH:
            disk = self._disk_prologues(dll)
            for fn, disk_bytes in disk.items():
                mem = self._mem_prologue(dll, fn)
                if mem is None:
                    continue
                checked += 1
                if mem == disk_bytes:
                    continue
                indicator = _looks_hooked(mem)
                if indicator is None:
                    continue   # differs but not a known hook stub → ignore (reloc/hotpatch)
                findings.append({
                    "dll": dll, "function": fn, "indicator": indicator,
                    "disk": disk_bytes[:8].hex(), "memory": mem[:8].hex(),
                })
        self._last_checked = checked
        return findings

    def _raise_alert(self, finding: dict) -> None:
        key = f"{finding['dll']}!{finding['function']}"
        if key in self._flagged:
            return
        self._flagged.add(key)
        ev = {"ts": time.time(), "type": "SENSOR_INTEGRITY_HOOK", "severity": "Critical",
              "code": self.CODE, "detail": finding,
              "recommend": "isolate host + dump hooking module; sensors may be blinded",
              "auto_applied": False}
        try:
            self._soar.parent.mkdir(parents=True, exist_ok=True)
            with self.state_lock, open(self._soar, "a", encoding="utf-8") as f:
                f.write(json.dumps(ev) + "\n")
        except Exception as exc:
            self.last_error = str(exc)
        self.emit(f"🚨 Inline hook on {key} ({finding['indicator']}) — possible sensor "
                  f"blinding.", Severity.CRITICAL, **finding)

    # ── lifecycle ────────────────────────────────────────────────────────────
    def run(self) -> None:
        try:
            os.nice(10)   # low priority (POSIX); harmless no-op resolution on Windows
        except Exception:
            pass
        if os.name != "nt":
            self.set_health(60, "non-Windows: disk parse only, no live compare")
        self.emit("APID online — watching ntdll/kernel32 export integrity.", Severity.INFO)
        while not self.stopping:
            try:
                findings = self.scan_once()
                for f in findings:
                    self._raise_alert(f)
                if not findings:
                    self.set_health(100, f"{getattr(self,'_last_checked',0)} exports clean")
                else:
                    self.set_health(20, f"{len(findings)} hooked export(s)")
            except Exception as exc:
                self.last_error = str(exc)
                self.set_health(50, "scan error")
            self.sleep(self._INTERVAL)

    def self_test(self) -> tuple[bool, str]:
        """Verify the parser resolves real exports from the on-disk ntdll."""
        disk = self._disk_prologues("ntdll.dll")
        if os.name != "nt":
            return True, "non-Windows: parser path only (skipped live compare)"
        if disk:
            return True, f"parsed {len(disk)} ntdll export prologue(s) from disk"
        return False, f"could not parse ntdll exports ({self.last_error})"


def register() -> ApiPatchDetectorModule:
    return ApiPatchDetectorModule()
