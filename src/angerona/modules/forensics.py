"""Opt-in bounded process strings/socket capture into encrypted evidence.

Missing original identity, crypto or permissions means held coverage. No
current-PID substitution, plaintext fallback, full-dump or response authority.
"""
from __future__ import annotations

import ctypes
import ipaddress
import json
import math
import ntpath
import os
import re
import secrets
import shutil
import struct
import time
from pathlib import Path

from angerona.core.eventbus import Event, is_remote_observe_only
from angerona.core.forensic_vault import (
    DirectoryPins, ForensicVaultError, ForensicVaultWriter, MAX_VAULT_BYTES, verify_key_wrapping,
    require_capture_custody, retain_retirement_hold, retirement_snapshot,
)
from angerona.core.module_base import BaseModule, Severity
from angerona.core.threat import is_active_threat
from angerona.core.windows_process_lease import _Native as _ProcessNative

_EPOCH = 116444736000000000
_CAPTURE_TTL_S = 86400
_CAPTURE_MAX = 2048
_HELD_REPEAT_S = 900.0
_HELD_KEYS_MAX = 64
_MEMORY_READ_BUDGET = 64 * 1024 * 1024
_MEMORY_CHUNK_BYTES = 1024 * 1024
_MEMORY_OUTPUT_BUDGET = 8 * 1024 * 1024
_SOCKET_OUTPUT_BUDGET = 512 * 1024
_EVIDENCE_ROOT_BUDGET = 1024 * 1024 * 1024
_EVIDENCE_CASE_LIMIT = 128
_EVIDENCE_WALK_LIMIT = 20_000
_CAPTURE_SECONDS = 10.0
_FINALIZE_SECONDS = 5.0
_MAX_REGIONS = 16_384
_SOCKET_TABLE_BYTES = 2 * 1024 * 1024
_SOCKET_ROWS = 16_384
_BIRTH_SECONDS = ("create_time", "process_create_time", "start_time")
_BIRTH_TICKS = ("process_birth_ticks", "native_birth_ticks")
_PROTECTED = frozenset({"lsass.exe", "csrss.exe", "smss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "svchost.exe", "ntoskrnl.exe", "system", "registry", "msmpeng.exe",
    "mpdefendercoreservice.exe", "angerona.exe", "angerona-blackbox.exe"})


def _identity(pid: int, details: dict) -> tuple[int, float, int | None]:
    if type(pid) is not int or not 4 < pid <= 0xFFFFFFFF or type(details) is not dict:
        raise ValueError("invalid forensic process identity")
    seconds = []
    for key in _BIRTH_SECONDS:
        if key in details:
            value = details[key]
            if type(value) not in {int, float} or not math.isfinite(value) or value <= 0:
                raise ValueError("original process birth is missing or invalid")
            seconds.append(float(value))
    if seconds and any(value != seconds[0] for value in seconds):
        raise ValueError("original process birth aliases conflict")
    ticks = []
    for key in _BIRTH_TICKS:
        if key in details:
            value = details[key]
            if type(value) is str and 1 <= len(value) <= 20 and value.isascii() and value.isdecimal():
                if value != str(int(value)):
                    raise ValueError("noncanonical native birth")
                value = int(value)
            if type(value) is not int or not _EPOCH < value <= 0xFFFFFFFFFFFFFFFF:
                raise ValueError("original native birth is invalid")
            ticks.append(value)
    if ticks and any(value != ticks[0] for value in ticks):
        raise ValueError("original native birth aliases conflict")
    native = ticks[0] if ticks else None
    if native is not None:
        native_seconds = (native - _EPOCH) / 10_000_000
        # Seconds are only a lossy annotation, never used to synthesize ticks.
        if seconds and abs(seconds[0] - native_seconds) > max(math.ulp(native_seconds) * 16, 0.000004):
            raise ValueError("seconds and exact native birth conflict")
        return pid, native_seconds, native
    if not seconds:
        raise ValueError("original event supplied no process birth")
    return pid, seconds[0], None


def _evidence_root() -> Path:
    from angerona.core.config import _data_dir
    base = Path(_data_dir()) / "forensics"
    with DirectoryPins(base.parent):
        base.mkdir(mode=0o700, exist_ok=True)
    return base


class _NativeCapture(_ProcessNative):
    def __init__(self):
        super().__init__()
        from ctypes import wintypes
        class MemoryInfo(ctypes.Structure):
            _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD), ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD), ("Protect", wintypes.DWORD), ("Type", wintypes.DWORD)]
        self._memory_info = MemoryInfo
        self.api.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
        self.api.VirtualQueryEx.restype = ctypes.c_size_t
        self.api.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                              ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        self.api.ReadProcessMemory.restype = wintypes.BOOL
        self._iphlp = ctypes.WinDLL("iphlpapi", use_last_error=True, winmode=0x800)
        signature = [ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL,
                     wintypes.ULONG, wintypes.ULONG, wintypes.ULONG]
        for name in ("GetExtendedTcpTable", "GetExtendedUdpTable"):
            function = getattr(self._iphlp, name)
            function.argtypes, function.restype = signature, wintypes.DWORD

    def is_system(self, handle):
        from ctypes import wintypes
        api = ctypes.WinDLL("advapi32", use_last_error=True, winmode=0x800)
        api.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
        api.OpenProcessToken.restype = wintypes.BOOL
        api.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                            wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        api.GetTokenInformation.restype = wintypes.BOOL
        api.IsWellKnownSid.argtypes = [ctypes.c_void_p, ctypes.c_int]
        api.IsWellKnownSid.restype = wintypes.BOOL
        api.IsValidSid.argtypes = [ctypes.c_void_p]
        api.IsValidSid.restype = wintypes.BOOL
        token = wintypes.HANDLE()
        if not api.OpenProcessToken(handle, 0x8, ctypes.byref(token)):
            raise ValueError("process owner token unavailable")
        try:
            size = wintypes.DWORD()
            api.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
            if not ctypes.sizeof(ctypes.c_void_p) + 4 <= size.value <= 4096:
                raise ValueError("process owner token size unavailable")
            buffer = ctypes.create_string_buffer(size.value)
            if not api.GetTokenInformation(token, 1, buffer, size, ctypes.byref(size)):
                raise ValueError("process owner token unavailable")
            sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p)).contents.value
            if not sid or not api.IsValidSid(sid):
                raise ValueError("process owner SID unavailable")
            return bool(api.IsWellKnownSid(sid, 22))  # WinLocalSystemSid
        finally:
            self.close(token)

    def region(self, handle, address):
        info = self._memory_info()
        result = self.api.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(info), ctypes.sizeof(info))
        if not result:
            if address > 0 and ctypes.get_last_error() == 87:
                return None  # normal end of the accessible address range
            raise ValueError("native memory query unavailable")
        if result != ctypes.sizeof(info):
            raise ValueError("native memory region size is unavailable")
        return int(info.BaseAddress or 0), int(info.RegionSize), int(info.State), int(info.Protect)

    def memory(self, handle, address, size):
        buffer, read = ctypes.create_string_buffer(size), ctypes.c_size_t()
        ok = self.api.ReadProcessMemory(handle, ctypes.c_void_p(address), buffer, size, ctypes.byref(read))
        actual = min(size, int(read.value))
        return buffer.raw[:actual], bool(ok and actual == size)

    def socket_rows(self, pid, check):
        from ctypes import wintypes
        output = []
        for protocol, af, layout in (("tcp", 2, "<6I"), ("tcp", 23, "<16sII16sIIII"),
                                     ("udp", 2, "<3I"), ("udp", 23, "<16sIII")):
            check()
            function = getattr(self._iphlp, "GetExtendedTcpTable" if protocol == "tcp" else "GetExtendedUdpTable")
            size = wintypes.DWORD()
            code = function(None, ctypes.byref(size), False, af, 5 if protocol == "tcp" else 1, 0)
            if code not in (0, 122) or not 4 <= size.value <= _SOCKET_TABLE_BYTES:
                raise ValueError("native socket table unavailable or exceeds budget")
            buffer = ctypes.create_string_buffer(size.value)
            capacity = int(size.value)
            code = function(buffer, ctypes.byref(size), False, af, 5 if protocol == "tcp" else 1, 0)
            check()
            if code != 0 or not 4 <= size.value <= capacity:
                raise ValueError("native socket table changed or is unavailable")
            raw = buffer.raw[:size.value]
            count = struct.unpack_from("<I", raw)[0]
            row_size = struct.calcsize(layout)
            if count > _SOCKET_ROWS or 4 + count * row_size > len(raw):
                raise ValueError("native socket table row budget/shape invalid")
            for index in range(count):
                check()
                row = struct.unpack_from(layout, raw, 4 + index * row_size)
                if row[-1] != pid:
                    continue
                if af == 2:
                    if protocol == "tcp":
                        state, local, port, remote, remote_port, _owner = row
                    else:
                        local, port, _owner = row
                    record = {"protocol": protocol, "family": "ipv4",
                              "local_ip": str(ipaddress.ip_address(local.to_bytes(4, "little"))),
                              "local_port": int.from_bytes(port.to_bytes(4, "little")[:2], "big")}
                    if protocol == "tcp":
                        record.update(state=state, remote_ip=str(ipaddress.ip_address(remote.to_bytes(4, "little"))),
                                      remote_port=int.from_bytes(remote_port.to_bytes(4, "little")[:2], "big"))
                else:
                    record = {"protocol": protocol, "family": "ipv6", "local_ip": str(ipaddress.ip_address(row[0])),
                              "local_scope": int.from_bytes(row[1].to_bytes(4, "little"), "big"),
                              "local_port": int.from_bytes(row[2].to_bytes(4, "little")[:2], "big")}
                    if protocol == "tcp":
                        record.update(remote_ip=str(ipaddress.ip_address(row[3])),
                                      remote_scope=int.from_bytes(row[4].to_bytes(4, "little"), "big"),
                                      remote_port=int.from_bytes(row[5].to_bytes(4, "little")[:2], "big"), state=row[6])
                output.append(record)
        return output


class _CaptureHandle:
    """One retained native read/query object; never termination authority."""
    def __init__(self, pid, ticks, deadline, *, _native=None, _clock=time.monotonic):
        self.native = _native or _NativeCapture()
        self._clock, self.deadline = _clock, deadline
        self._last_now = _clock()
        self.handle = None
        self._close_attempted = False
        self._close_failed = False
        self.pid, self.ticks = pid, ticks
        if (type(self._last_now) not in {int, float} or not math.isfinite(self._last_now) or self._last_now < 0
                or type(deadline) not in {int, float} or not math.isfinite(deadline) or deadline <= self._last_now):
            raise ValueError("forensic capture clock/deadline unavailable")
        if (type(pid) is not int or not 4 < pid <= 0xFFFFFFFF or type(ticks) is not int
                or not _EPOCH < ticks <= 0xFFFFFFFFFFFFFFFF or pid == os.getpid()):
            raise ValueError("exact original native birth is required")
        try:
            self.handle = self.native.open(pid, 0x1000 | 0x0400 | 0x0010 | 0x00100000, False)
            self.identity = self.native.identity(self.handle)
            image = self.identity.image.casefold()
            if (self.identity.pid != pid or self.identity.birth_ticks != ticks
                    or ntpath.basename(image) in _PROTECTED or "\\windows\\" in image
                    or "angerona" in image or self.native.is_system(self.handle) is not False):
                raise ValueError("process identity differs or protected process is excluded")
            self.check()
        except BaseException:
            self.close()
            raise

    def check_deadline(self):
        now = self._clock()
        if (type(now) not in {int, float} or not math.isfinite(now) or now < self._last_now
                or now >= self.deadline):
            raise ValueError("forensic capture deadline expired or clock regressed")
        self._last_now = now
        if self.handle is None or self._close_attempted:
            raise ValueError("forensic process custody is closed")

    def check(self):
        self.check_deadline()
        if self.native.wait(self.handle, 0) is not False or self.native.identity(self.handle) != self.identity:
            raise ValueError("original process exited or native identity changed")
        self.check_deadline()

    def close(self):
        if self._close_failed:
            raise ForensicVaultError("forensic process handle retirement remains unverified")
        if self.handle is not None:
            self._close_attempted = True
            handle = self.handle
            try:
                if self.native.close(handle) is False:
                    raise OSError("native close did not succeed")
            except BaseException as exc:
                self._close_failed = True
                retain_retirement_hold(self, "process")
                raise ForensicVaultError("forensic process handle retirement unavailable") from exc
            self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


class ForensicsModule(BaseModule):
    name = "Forensics Capture"
    description = "Opt-in encrypted bounded process strings/sockets; exact original native birth and authenticated active local evidence required."
    category = "Forensics"
    adaptive_throttle_allowed = True
    adaptive_throttle_max = 2.0
    version = "1.15.0"
    enabled_by_default = False

    def __init__(self):
        super().__init__()
        self._captured = {}

    @staticmethod
    def _process_identity(pid, details):
        pid, seconds, _ticks = _identity(pid, details)
        return pid, seconds

    def _capture_needed(self, pid, details, now=None):
        try:
            identity = _identity(pid, details)
            now = time.time() if now is None else now
            if not math.isfinite(now):
                return False
        except (ValueError, TypeError):
            return False
        self._captured = {key: seen for key, seen in self._captured.items() if seen >= now - _CAPTURE_TTL_S}
        key = (identity[0], identity[2] if identity[2] is not None else identity[1])
        if key in self._captured:
            return False
        if len(self._captured) >= _CAPTURE_MAX:
            self._captured = dict(sorted(self._captured.items(), key=lambda item: item[1], reverse=True)[:_CAPTURE_MAX - 1])
        self._captured[key] = now
        return True

    def _admit(self, event):
        require_capture_custody()
        if type(event) is not Event:
            raise ValueError("original authenticated EventBus evidence required")
        bus = self._bus
        details = getattr(event, "details", None)
        now, stamp = time.time(), getattr(event, "ts", None)
        if (bus is None or getattr(bus, "integrity_enabled", False) is not True or bus.verify(event) is not True
                or is_remote_observe_only(event) or not is_active_threat(event) or event.module == self.name
                or type(details) is not dict or details.get("raw_sensor_evidence") is True
                # Opt out of intrusive reads only; these annotations do not
                # downgrade the original alert or disable any response policy.
                or any(details.get(key) is True for key in ("drill", "self_test", "selftest", "simulation", "practice"))
                or not (details.get("active_attack") is True or details.get("active_exploitation") is True
                        or details.get("disposition") == "active")
                or type(stamp) not in {int, float} or not math.isfinite(stamp) or not -1 <= now - stamp <= 30):
            raise ValueError("fresh authenticated active local evidence required; capture held")
        identity = _identity(details.get("pid"), details)
        if identity[2] is None:
            raise ValueError("exact native process birth missing in original event; seconds-only capture held")
        if identity[1] > stamp + 0.001:
            raise ValueError("original process birth is later than its evidence")
        return identity

    def _held(self, reason, pid=None):
        self.set_health(45, reason)
        # Every High observation that is not active evidence reaches this
        # path. Health always reflects the latest reason; the bus alert for an
        # identical reason and process is repeated at most every 15 minutes and
        # carries the number of identical holds it stands for.
        now = time.monotonic()
        recent = getattr(self, "_held_recent", None)
        if recent is None:
            recent = self._held_recent = {}
        key = (str(reason), pid)
        last, suppressed = recent.get(key, (None, 0))
        if last is not None and 0 <= now - last < _HELD_REPEAT_S:
            recent[key] = (last, suppressed + 1)
            return
        if len(recent) >= _HELD_KEYS_MAX:
            for stale in sorted(recent, key=lambda item: recent[item][0])[:_HELD_KEYS_MAX // 2]:
                del recent[stale]
        recent[key] = (now, 0)
        self.emit("Forensic capture held: " + reason, Severity.MEDIUM, pid=pid,
                  complete=False, disposition="health", response_authorized=False,
                  repeats_since_last_report=suppressed,
                  forensic_retirement=retirement_snapshot())

    @staticmethod
    def forensic_capture_snapshot():
        """Cached, capture-only retirement status for inspectors/diagnostics."""
        return retirement_snapshot()

    def run(self):
        self.set_health(60, "enabled; native capture/crypto/source coverage has not yet been verified")
        self.emit("Encrypted forensic capture opt-in active; exact native identity and active evidence required.", Severity.INFO)
        while not self.stopping:
            self.sleep(5, cycle_complete=False)
            if self._bus is not None:
                events, overflow = self.poll_bus_events(priority=True)
                if overflow:
                    self._held("event delivery gap; lost events were not captured")
                for event in events:
                    if event.module == self.name or event.severity < Severity.HIGH:
                        continue
                    try:
                        pid, seconds, ticks = self._admit(event)
                        if self._capture_needed(pid, event.details):
                            result = self._capture(pid, expected_create_time=seconds, event=event)
                            if not result.get("complete"):
                                self._captured.pop((pid, ticks), None)
                    except Exception as exc:
                        self._held(str(exc)[:180])
            self.mark_cycle_complete()

    @staticmethod
    def _root_capacity(root):
        from angerona.core.data_paths import _is_reparse_point
        try:
            total = cases = walked = 0
            if root.is_symlink() or _is_reparse_point(root):
                return False, 0, 0, "evidence root is an alias"
            for current, directories, names in os.walk(root, followlinks=False):
                for name in (*directories, *names):
                    walked += 1
                    if walked > _EVIDENCE_WALK_LIMIT:
                        return False, total, cases, "evidence inventory budget exhausted"
                    path = Path(current) / name
                    info = path.lstat()
                    if path.is_symlink() or _is_reparse_point(path) or (not path.is_dir() and info.st_nlink != 1):
                        return False, total, cases, "unsafe evidence object"
                    if path.is_dir():
                        if path.parent == root and name.startswith("Case_"):
                            cases += 1
                    else:
                        total += max(0, info.st_size)
                    if total + MAX_VAULT_BYTES > _EVIDENCE_ROOT_BUDGET or cases >= _EVIDENCE_CASE_LIMIT:
                        return False, total, cases, "evidence byte/case budget exhausted"
            if shutil.disk_usage(root).free < MAX_VAULT_BYTES + 64 * 1024 * 1024:
                return False, total, cases, "evidence free-space reserve exhausted"
            return True, total, cases, "capacity available"
        except Exception:
            return False, 0, 0, "evidence capacity unavailable"

    def _capture(self, pid, expected_create_time=None, *, event=None):
        result = {"complete": False, "reason": "capture held", "encrypted": False}
        try:
            target = self._admit(event)
            if target[0] != pid or type(expected_create_time) not in {int, float} or expected_create_time != target[1]:
                raise ValueError("capture target differs from the original event")
            deadline = time.monotonic() + _CAPTURE_SECONDS
            root = _evidence_root()
            with DirectoryPins(root):
                allowed, _usage, _cases, reason = self._root_capacity(root)
                if not allowed:
                    raise ForensicVaultError(reason)
                verify_key_wrapping()  # unavailable crypto must not consume retained case slots
                case_dir = root / f"Case_{pid}_{secrets.token_hex(12)}"
                case_dir.mkdir(mode=0o700, exist_ok=False)
                path = case_dir / "evidence.afv"
                with ForensicVaultWriter(path, pid=pid, birth_ticks=target[2],
                                         deadline=deadline + _FINALIZE_SECONDS) as writer:
                    memory = {"complete": False, "reason": "not started"}
                    sockets = {"complete": False, "reason": "not started"}
                    error = ""
                    native_image = None
                    try:
                        self._admit(event)
                        with _CaptureHandle(pid, target[2], deadline) as retained:
                            native_image = retained.identity.image
                            memory = {"complete": False, "reason": "collector started; trustworthy completion unavailable",
                                      "read_bytes": None, "attempted_bytes": None}
                            memory = self._dump_memory_strings(retained, writer, event=event)
                            sockets = {"complete": False, "reason": "collector started; trustworthy completion unavailable",
                                       "rows": None, "written_bytes": None}
                            sockets = self._audit_sockets(retained, writer, event=event)
                            retained.check()
                            self._admit(event)
                    except Exception as exc:
                        error = type(exc).__name__
                    receipt = {"complete": bool(memory["complete"] and sockets["complete"] and not error),
                        "memory": memory, "sockets": sockets, "failure_type": error,
                        "native_pid": pid, "native_birth_ticks": target[2],
                        "native_image": native_image,
                        "source_event": {"module": event.module, "ts": event.ts,
                                         "hmac_sig": event.hmac_sig, "mesh_sig": event.mesh_sig,
                                         "mesh_peer": event.mesh_peer,
                                         "authentication": "live-source-mesh" if self._bus.mesh_required else "local-HMAC",
                                         "original_preserved": "EventBus/recorder; no original alert was modified"},
                        "shell_history": {"collected": False, "reason": "excluded: not attributable to the suspect process"},
                        "not_full_memory_dump": True, "deadline_seconds": _CAPTURE_SECONDS,
                        "native_time_limit": "cooperative; kernel calls cannot be forcibly preempted",
                        "response_authorized": False}
                    writer.finish(receipt)
                    result = {"complete": receipt["complete"], "encrypted": True,
                        "reason": "bounded capture complete" if receipt["complete"] else "partial capture; inspect authenticated receipt",
                        "path": str(path)}
            self.set_health(100 if result["complete"] else 55, result["reason"])
            self.emit("Encrypted forensic capture " + ("finished" if result["complete"] else "retained partial evidence"),
                Severity.INFO if result["complete"] else Severity.MEDIUM, **result,
                disposition="observation", response_authorized=False)
        except Exception as exc:
            result["complete"] = False
            result["reason"] = str(exc)[:180]
            result["forensic_retirement"] = retirement_snapshot()
            self._held(result["reason"], pid)
        return result

    def _dump_memory_strings(self, retained, writer, *, event):
        address = attempted = read_total = written = failures = regions = skipped = 0
        limited = False
        pattern = re.compile(br"[ -~]{4,}")
        while regions < _MAX_REGIONS:
            retained.check()
            self._admit(event)
            if self.stopping:
                limited = True
                break
            region = retained.native.region(retained.handle, address)
            if region is None:
                break
            base, size, state, protection = region
            regions += 1
            if (type(size) is not int or type(base) is not int or size <= 0 or base < address
                    or not address < base + size <= 0xFFFFFFFFFFFFFFFF):
                raise ValueError("invalid native memory region")
            offset = 0
            if state == 0x1000 and not protection & (0x100 | 0x01):
                while offset < size:
                    retained.check()
                    if self.stopping or attempted >= _MEMORY_READ_BUDGET:
                        limited = True
                        break
                    amount = min(_MEMORY_CHUNK_BYTES, size - offset, _MEMORY_READ_BUDGET - attempted)
                    attempted += amount
                    raw, complete = retained.native.memory(retained.handle, base + offset, amount)
                    retained.check()
                    if type(raw) is not bytes or len(raw) > amount:
                        raise ValueError("invalid native memory result")
                    failures += not complete
                    read_total += len(raw)
                    pending = bytearray()
                    for match in pattern.finditer(raw):
                        line = match.group() + b"\n"
                        if written + len(line) > _MEMORY_OUTPUT_BUDGET:
                            limited = True
                            break
                        if len(pending) + len(line) > 60 * 1024:
                            writer.append("memory", bytes(pending))
                            pending.clear()
                        if len(line) > 60 * 1024:
                            writer.append("memory", line)
                        else:
                            pending.extend(line)
                        written += len(line)
                    writer.append("memory", bytes(pending))
                    offset += amount
                    if limited:
                        break
            elif state == 0x1000:
                skipped += 1
            address = base + size
            if limited:
                break
        retained.check()
        self._admit(event)
        return {"complete": not limited and failures == 0 and skipped == 0 and regions < _MAX_REGIONS,
            "read_bytes": read_total, "attempted_bytes": attempted, "written_bytes": written,
            "failed_reads": failures, "regions": regions, "skipped_committed_regions": skipped,
            "limited": limited or regions >= _MAX_REGIONS}

    def _audit_sockets(self, retained, writer, *, event):
        retained.check()
        self._admit(event)
        rows = retained.native.socket_rows(retained.pid, retained.check_deadline)
        retained.check()
        self._admit(event)
        encoded = bytearray()
        limited = False
        for row in rows:
            line = json.dumps(row, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n"
            if len(encoded) + len(line) > _SOCKET_OUTPUT_BUDGET:
                limited = True
                break
            encoded.extend(line)
        writer.append("sockets", bytes(encoded))
        return {"complete": not limited, "written_bytes": len(encoded), "rows": len(rows), "limited": limited,
            "coverage": "owner-PID tables while exact process remained alive; not socket-handle ownership proof"}

    def self_test(self):
        from angerona.core.forensic_vault import read_vault
        import tempfile
        raw = _EPOCH + 100 * 10_000_000
        original = self._captured
        try:
            self._captured = {}
            if not self._capture_needed(4242, {"process_create_time": 100.0}, now=200.0):
                return False, "birth-bound dedup positive failed"
            if self._capture_needed(4242, {}, now=201.0) or self._capture_needed(4242, {"create_time": float("nan")}, now=201.0):
                return False, "missing/nonfinite birth was admitted"
            if _identity(4242, {"process_birth_ticks": str(raw)})[2] != raw:
                return False, "native raw birth decoder failed"
            wrap = lambda key, _entropy: b"offline-fixture:" + key
            unwrap = lambda blob, _entropy: blob[len(b"offline-fixture:"):]
            with tempfile.TemporaryDirectory(prefix="angerona-forensic-vault-selftest-") as temp:
                path = Path(temp) / "fixture.afv"
                with ForensicVaultWriter(path, pid=4242, birth_ticks=raw, deadline=time.monotonic() + 5,
                                         _protect=wrap, _unprotect=unwrap) as writer:
                    writer.append("memory", b"benign-encryption-fixture\n")
                    writer.finish({"complete": False, "fixture": True})
                if b"benign-encryption-fixture" in path.read_bytes() or read_vault(path, _unprotect=unwrap)["records"]["memory"] != b"benign-encryption-fixture\n":
                    return False, "encrypted evidence roundtrip failed"
            return True, "offline identity/refusal/encryption fixture passed; host DPAPI/native reads/source coverage not verified"
        except Exception as exc:
            return False, f"forensic fixture unavailable: {type(exc).__name__}"
        finally:
            self._captured = original


def register():
    return ForensicsModule()
