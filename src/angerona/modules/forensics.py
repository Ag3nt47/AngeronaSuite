"""Incident forensics capture.

When another module flags a HIGH/CRITICAL event tied to a process, this module
performs a bounded forensic capture on that exact PID: cleartext strings from
live memory and its network sockets. Unrelated user shell history is excluded.
Evidence is written to a per-case folder under the app data dir (not C:\\ root).

Ported from the original Angerona ``forensics.py``. Disabled by default because
reading another process's memory is intrusive and requires Administrator.
"""
from __future__ import annotations

import ctypes
import json
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
_MEMORY_READ_BUDGET = 64 * 1024 * 1024
_MEMORY_CHUNK_BYTES = 1024 * 1024
_MEMORY_OUTPUT_BUDGET = 8 * 1024 * 1024
_SOCKET_OUTPUT_BUDGET = 512 * 1024
_EVIDENCE_ROOT_BUDGET = 1024 * 1024 * 1024
_EVIDENCE_CASE_LIMIT = 128
_EVIDENCE_WALK_LIMIT = 20_000


def _evidence_root() -> Path:
    from angerona.core.config import _data_dir
    base = Path(_data_dir()) / "forensics"
    base.mkdir(parents=True, exist_ok=True)
    return base


class ForensicsModule(BaseModule):
    name = "Forensics Capture"
    description = (
        "On serious events, captures bounded memory strings and sockets for the "
        "exact suspect process; unrelated shell history is excluded."
    )
    category = "Forensics"
    adaptive_throttle_allowed = True
    adaptive_throttle_max = 2.0
    version = "1.12.1"
    enabled_by_default = False

    def __init__(self) -> None:
        super().__init__()
        self._captured: Dict[Tuple[int, float | None], float] = {}

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

    def self_test(self) -> tuple[bool, str]:
        """Validate PID-generation dedupe without reading process memory or disk."""
        original = self._captured
        try:
            self._captured = {}
            first = self._capture_needed(4242, {"process_create_time": 100.0}, now=200.0)
            duplicate = self._capture_needed(
                4242, {"process_create_time": 100.0}, now=201.0
            )
            reused = self._capture_needed(4242, {"process_create_time": 101.0}, now=202.0)
            expired = self._capture_needed(
                4242,
                {"process_create_time": 100.0},
                now=200.0 + _CAPTURE_TTL_S + 1.0,
            )
            ok = first and not duplicate and reused and expired and len(self._captured) <= _CAPTURE_MAX
        finally:
            self._captured = original
        return (
            ok,
            "offline PID-generation, TTL, and capacity gates passed"
            if ok else "forensic capture identity/retention contract failed",
        )

    def run(self) -> None:
        self.emit("Forensics capture armed (watching for serious events).", Severity.INFO)
        while not self.stopping:
            self.sleep(5, cycle_complete=False)
            if self._bus is None:
                self.mark_cycle_complete()
                continue
            events, _overflow = self.poll_bus_events(priority=True)
            for ev in events:
                if ev.severity < Severity.HIGH:
                    continue
                if ev.module == self.name:
                    continue
                pid = ev.details.get("pid")
                if (
                    isinstance(pid, int) and
                    self._capture_needed(pid, ev.details or {})
                ):
                    identity = self._process_identity(pid, ev.details or {})
                    self._capture(pid, expected_create_time=identity[1])
            self.mark_cycle_complete()

    # ── Capture pipeline ─────────────────────────────────────────────────────
    @staticmethod
    def _root_capacity(root: Path) -> tuple[bool, int, int, str]:
        """Refuse new evidence before a bounded root can exhaust the disk."""
        from angerona.core.data_paths import _is_reparse_point

        try:
            if root.is_symlink() or _is_reparse_point(root):
                return False, 0, 0, "evidence root is a link/reparse point"
            total = 0
            files = 0
            cases = 0
            for current, directories, names in os.walk(root, followlinks=False):
                current_path = Path(current)
                safe_directories: list[str] = []
                for name in directories:
                    child = current_path / name
                    if child.is_symlink() or _is_reparse_point(child):
                        return False, total, cases, f"unsafe evidence subtree: {child}"
                    safe_directories.append(name)
                directories[:] = safe_directories
                if current_path.parent == root and current_path.name.startswith("Case_"):
                    cases += 1
                for name in names:
                    files += 1
                    if files > _EVIDENCE_WALK_LIMIT:
                        return False, total, cases, "evidence inventory limit reached"
                    candidate = current_path / name
                    info = candidate.lstat()
                    if candidate.is_symlink() or _is_reparse_point(candidate):
                        return False, total, cases, f"unsafe evidence object: {candidate}"
                    total += max(0, int(info.st_size))
                    if total >= _EVIDENCE_ROOT_BUDGET:
                        return False, total, cases, "evidence byte budget exhausted"
            if cases >= _EVIDENCE_CASE_LIMIT:
                return False, total, cases, "evidence case budget exhausted"
            return True, total, cases, "capacity available"
        except Exception as exc:
            return False, 0, 0, f"evidence capacity unavailable: {exc}"

    @staticmethod
    def _write_receipt(case_dir: Path, receipt: dict) -> None:
        destination = case_dir / "capture_receipt.json"
        temporary = case_dir / ".capture_receipt.tmp"
        payload = json.dumps(receipt, sort_keys=True, indent=2) + "\n"
        with open(temporary, "x", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)

    def _capture(self, pid: int, expected_create_time: float | None = None) -> None:
        root = _evidence_root()
        allowed, usage, cases, capacity_reason = self._root_capacity(root)
        if not allowed:
            self.set_health(25, capacity_reason)
            self.emit(
                f"Forensic capture refused for PID {pid}: {capacity_reason}.",
                Severity.HIGH,
                pid=pid,
                evidence_bytes=usage,
                evidence_cases=cases,
            )
            return
        stamp = int(time.time_ns())
        case_dir = root / f"Case_{pid}_{stamp}"
        case_dir.mkdir(parents=False, exist_ok=False)
        try:
            case_dir.chmod(0o700)
        except OSError:
            pass
        self.emit(f"Forensic capture started on PID {pid}.", Severity.MEDIUM, pid=pid)
        memory = self._dump_memory_strings(
            pid, case_dir, expected_create_time=expected_create_time
        )
        sockets = self._audit_sockets(pid, case_dir)
        receipt = {
            "schema": 1,
            "pid": pid,
            "expected_create_time": expected_create_time,
            "created_at": time.time(),
            "memory": memory,
            "sockets": sockets,
            "shell_history": {
                "collected": False,
                "reason": "excluded: not attributable to the suspect process",
            },
            "budgets": {
                "memory_read_bytes": _MEMORY_READ_BUDGET,
                "memory_output_bytes": _MEMORY_OUTPUT_BUDGET,
                "socket_output_bytes": _SOCKET_OUTPUT_BUDGET,
                "evidence_root_bytes": _EVIDENCE_ROOT_BUDGET,
                "evidence_case_limit": _EVIDENCE_CASE_LIMIT,
            },
        }
        try:
            self._write_receipt(case_dir, receipt)
            receipt_written = True
        except Exception as exc:
            receipt_written = False
            self.last_error = str(exc)
        complete = bool(memory.get("complete") and sockets.get("complete") and receipt_written)
        self.set_health(
            100 if complete else 55,
            "bounded capture complete" if complete else "capture incomplete; inspect receipt",
        )
        self.emit(
            f"Forensic capture {'complete' if complete else 'incomplete'} → {case_dir}",
            Severity.INFO if complete else Severity.MEDIUM,
            pid=pid,
            path=str(case_dir),
            receipt_written=receipt_written,
            complete=complete,
        )

    def _dump_memory_strings(
        self,
        pid: int,
        case_dir: Path,
        *,
        expected_create_time: float | None = None,
    ) -> dict:
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
            return {"complete": False, "reason": "process open denied", "read_bytes": 0}

        class MBI(ctypes.Structure):
            _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                        ("AllocationProtect", ctypes.c_ulong), ("RegionSize", ctypes.c_size_t),
                        ("State", ctypes.c_ulong), ("Protect", ctypes.c_ulong), ("Type", ctypes.c_ulong)]

        rx = re.compile(br"[ -~]{4,}")
        mbi = MBI()
        addr = 0
        out = case_dir / "mem_strings.txt"
        read_total = 0
        written_total = 0
        regions = 0
        truncated = False
        try:
            if expected_create_time is not None:
                creation = wintypes.FILETIME()
                exit_time = wintypes.FILETIME()
                kernel_time = wintypes.FILETIME()
                user_time = wintypes.FILETIME()
                k32.GetProcessTimes.restype = wintypes.BOOL
                k32.GetProcessTimes.argtypes = [
                    wintypes.HANDLE,
                    ctypes.POINTER(wintypes.FILETIME),
                    ctypes.POINTER(wintypes.FILETIME),
                    ctypes.POINTER(wintypes.FILETIME),
                    ctypes.POINTER(wintypes.FILETIME),
                ]
                if not k32.GetProcessTimes(
                    handle,
                    ctypes.byref(creation),
                    ctypes.byref(exit_time),
                    ctypes.byref(kernel_time),
                    ctypes.byref(user_time),
                ):
                    return {
                        "complete": False,
                        "reason": "process creation time unavailable",
                        "read_bytes": 0,
                    }
                ticks = (int(creation.dwHighDateTime) << 32) | int(
                    creation.dwLowDateTime
                )
                opened_create_time = (ticks - 116444736000000000) / 10_000_000
                if abs(opened_create_time - expected_create_time) > 0.01:
                    return {
                        "complete": False,
                        "reason": "process identity changed before capture",
                        "read_bytes": 0,
                        "opened_create_time": opened_create_time,
                    }
            with open(out, "xb") as f:
                while k32.VirtualQueryEx(handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) > 0:
                    if self.stopping:
                        truncated = True
                        break
                    if mbi.State == MEM_COMMIT and mbi.RegionSize:
                        regions += 1
                        region_size = max(0, int(mbi.RegionSize))
                        region_base = int(mbi.BaseAddress or addr)
                        region_offset = 0
                        while region_offset < region_size:
                            remaining = _MEMORY_READ_BUDGET - read_total
                            if remaining <= 0:
                                truncated = True
                                break
                            chunk_size = min(
                                _MEMORY_CHUNK_BYTES,
                                region_size - region_offset,
                                remaining,
                            )
                            buf = ctypes.create_string_buffer(chunk_size)
                            read = ctypes.c_size_t(0)
                            if k32.ReadProcessMemory(
                                handle,
                                ctypes.c_void_p(region_base + region_offset),
                                buf,
                                chunk_size,
                                ctypes.byref(read),
                            ):
                                read_total += int(read.value)
                                for match in rx.findall(buf.raw[: read.value]):
                                    line = bytes(match) + b"\n"
                                    if written_total + len(line) > _MEMORY_OUTPUT_BUDGET:
                                        truncated = True
                                        break
                                    f.write(line)
                                    written_total += len(line)
                            region_offset += chunk_size
                            if truncated:
                                break
                    next_addr = addr + max(0x1000, int(mbi.RegionSize or 0))
                    if next_addr <= addr:
                        truncated = True
                        break
                    addr = next_addr
                    if truncated:
                        break
                f.flush()
                os.fsync(f.fileno())
        except Exception as exc:
            self.last_error = str(exc)
            return {
                "complete": False,
                "reason": str(exc)[:240],
                "read_bytes": read_total,
                "written_bytes": written_total,
                "regions": regions,
            }
        finally:
            k32.CloseHandle(handle)
        return {
            "complete": not truncated,
            "reason": "budget reached" if truncated else "complete",
            "read_bytes": read_total,
            "written_bytes": written_total,
            "regions": regions,
            "path": str(out),
        }

    def _audit_sockets(self, pid: int, case_dir: Path) -> dict:
        out = case_dir / "network_sockets.txt"
        try:
            # A-05: no shell — run netstat as an argv list and filter in Python.
            res = run_hidden(
                ["netstat", "-ano"],
                capture_output=True,
                text=True,
                timeout=5.0,
            )
            needle = str(int(pid))   # coerce; the PID is the last column of each row
            rows = [ln for ln in (res.stdout or "").splitlines()
                    if ln.split() and ln.split()[-1] == needle]
            data = ("\n".join(rows) + "\n") if rows else "No tracked endpoints at capture time.\n"
            encoded = data.encode("utf-8", "replace")
            truncated = len(encoded) > _SOCKET_OUTPUT_BUDGET
            encoded = encoded[:_SOCKET_OUTPUT_BUDGET]
            with open(out, "xb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            return {
                "complete": not truncated,
                "reason": "output budget reached" if truncated else "complete",
                "written_bytes": len(encoded),
                "rows": len(rows),
                "path": str(out),
            }
        except Exception as exc:
            self.last_error = str(exc)
            return {
                "complete": False,
                "reason": str(exc)[:240],
                "written_bytes": 0,
            }
