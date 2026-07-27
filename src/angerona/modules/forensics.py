"""Incident forensics capture.

When another module flags a HIGH/CRITICAL event tied to a process, this module
performs a non-blocking forensic capture on that PID: cleartext strings from
live memory, its network sockets, and the user's shell history. Evidence is
written to a per-case folder under the app data dir (not C:\\ root).

Ported from the original Angerona ``forensics.py``. Disabled by default because
reading another process's memory is intrusive and requires Administrator.
"""
from __future__ import annotations

import ctypes
import os
import re
import time
from pathlib import Path
from typing import Dict, Tuple

from angerona.core.module_base import BaseModule, Severity
from angerona.core.win import run_hidden

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
_CAPTURE_TTL_S = 24 * 60 * 60
_CAPTURE_MAX = 2_048


def _evidence_root() -> Path:
    from angerona.core.config import _data_dir
    base = Path(_data_dir()) / "forensics"
    base.mkdir(parents=True, exist_ok=True)
    return base


class ForensicsModule(BaseModule):
    name = "Forensics Capture"
    description = "On serious events, captures memory strings, sockets, and shell history for the suspect PID."
    category = "Forensics"
    enabled_by_default = False

    def __init__(self) -> None:
        super().__init__()
        self._captured: Dict[Tuple[int, float | None], float] = {}
        self._last_ts = 0.0

    @staticmethod
    def _process_identity(pid: int, details: dict) -> Tuple[int, float | None]:
        """Prefer a process birth time so PID reuse cannot inherit old state."""
        for key in ("create_time", "process_create_time", "start_time"):
            try:
                value = details.get(key)
                if value is not None:
                    return pid, float(value)
            except (TypeError, ValueError):
                pass
        try:
            import psutil
            return pid, float(psutil.Process(pid).create_time())
        except Exception:
            return pid, None

    def _capture_needed(self, pid: int, details: dict, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        cutoff = now - _CAPTURE_TTL_S
        self._captured = {
            identity: seen_at for identity, seen_at in self._captured.items()
            if seen_at >= cutoff
        }
        if len(self._captured) > _CAPTURE_MAX:
            newest = sorted(
                self._captured.items(), key=lambda item: item[1], reverse=True
            )
            self._captured = dict(newest[:_CAPTURE_MAX])
        identity = self._process_identity(pid, details)
        if identity in self._captured:
            return False
        self._captured[identity] = now
        return True

    def run(self) -> None:
        self.emit("Forensics capture armed (watching for serious events).", Severity.INFO)
        while not self.stopping:
            self.sleep(5)
            if self._bus is None:
                continue
            for ev in self._bus.recent(25):
                if ev.ts <= self._last_ts or ev.severity < Severity.HIGH:
                    continue
                if ev.module == self.name:
                    continue
                self._last_ts = max(self._last_ts, ev.ts)
                pid = ev.details.get("pid")
                if (
                    isinstance(pid, int) and
                    self._capture_needed(pid, ev.details or {})
                ):
                    self._capture(pid)

    # ── Capture pipeline ─────────────────────────────────────────────────────
    def _capture(self, pid: int) -> None:
        case_dir = _evidence_root() / f"Case_{pid}"
        case_dir.mkdir(parents=True, exist_ok=True)
        self.emit(f"Forensic capture started on PID {pid}.", Severity.MEDIUM, pid=pid)
        self._dump_memory_strings(pid, case_dir)
        self._audit_sockets(pid, case_dir)
        self._harvest_shell_history(case_dir)
        self.emit(f"Forensic capture complete → {case_dir}", Severity.INFO, pid=pid, path=str(case_dir))

    def _dump_memory_strings(self, pid: int, case_dir: Path) -> None:
        from ctypes import wintypes  # Windows-only; imported lazily for portability
        k32 = ctypes.windll.kernel32
        k32.OpenProcess.restype = wintypes.HANDLE
        k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k32.VirtualQueryEx.restype = ctypes.c_size_t
        k32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
        k32.ReadProcessMemory.restype = wintypes.BOOL
        k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                          ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        k32.CloseHandle.argtypes = [wintypes.HANDLE]

        handle = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
        if not handle:
            self.emit(f"Memory access denied for PID {pid} (protected token).", Severity.LOW, pid=pid)
            return

        class MBI(ctypes.Structure):
            _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                        ("AllocationProtect", ctypes.c_ulong), ("RegionSize", ctypes.c_size_t),
                        ("State", ctypes.c_ulong), ("Protect", ctypes.c_ulong), ("Type", ctypes.c_ulong)]

        rx = re.compile(br"[ -~]{4,}")
        mbi = MBI()
        addr = 0
        out = case_dir / "mem_strings.txt"
        try:
            with open(out, "w", encoding="utf-8", errors="ignore") as f:
                while k32.VirtualQueryEx(handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) > 0:
                    if self.stopping:
                        break
                    if mbi.State == MEM_COMMIT and mbi.RegionSize:
                        buf = ctypes.create_string_buffer(mbi.RegionSize)
                        read = ctypes.c_size_t(0)
                        if k32.ReadProcessMemory(handle, mbi.BaseAddress, buf, mbi.RegionSize, ctypes.byref(read)):
                            for m in rx.findall(buf.raw[:read.value]):
                                f.write(m.decode("ascii", errors="ignore") + "\n")
                    addr += mbi.RegionSize or 0x1000
        except Exception as exc:
            self.last_error = str(exc)
        finally:
            k32.CloseHandle(handle)

    def _audit_sockets(self, pid: int, case_dir: Path) -> None:
        out = case_dir / "network_sockets.txt"
        try:
            # A-05: no shell — run netstat as an argv list and filter in Python.
            res = run_hidden(["netstat", "-ano"], capture_output=True, text=True)
            needle = str(int(pid))   # coerce; the PID is the last column of each row
            rows = [ln for ln in (res.stdout or "").splitlines()
                    if ln.split() and ln.split()[-1] == needle]
            data = ("\n".join(rows) + "\n") if rows else "No tracked endpoints at capture time.\n"
        except Exception:
            data = "No tracked endpoints at capture time.\n"
        out.write_text(data, encoding="utf-8")

    def _harvest_shell_history(self, case_dir: Path) -> None:
        hist = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt")
        if os.path.exists(hist):
            try:
                (case_dir / "shell_history.txt").write_text(
                    Path(hist).read_text(encoding="utf-8", errors="ignore"), encoding="utf-8")
            except Exception as exc:
                self.last_error = str(exc)
