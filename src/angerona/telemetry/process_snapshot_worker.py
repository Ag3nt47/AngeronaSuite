"""Owned process inventory worker; observations never authorize host actions.

Only inherited binary stdio carries the ephemeral bootstrap key. The worker has
no endpoint, installation credential, Qt dependency or response dispatcher.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import queue
import secrets
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import BinaryIO, Sequence

from angerona.core.engine_transport import decode
from angerona.telemetry.sensors import ProcessSnapshot

PROTOCOL = "angerona-process-inventory-v1"
MAX_FRAME = 8 * 1024 * 1024
MAX_CONTROL = 4096
_DOMAIN = b"angerona-process-inventory-v1\0"
_FIELDS = {"processes", "collected_at", "complete", "enumerated", "skipped",
           "unreadable", "identity_incomplete", "error", "enumeration_complete"}
_ROW_FIELDS = {"pid", "name", "exe", "username", "cmdline", "create_time", "ppid"}


class InventoryWorkerError(RuntimeError):
    pass


class InventoryCustodyCloseError(InventoryWorkerError):
    pass


def on_gui_thread() -> bool:
    """Inspect already loaded Qt only; do not import/start Qt for a sensor."""
    qt = sys.modules.get("PySide6.QtCore")
    if qt is None:
        return False
    app = qt.QCoreApplication.instance()
    return app is not None and qt.QThread.currentThread() == app.thread()


def unavailable(reason: str) -> ProcessSnapshot:
    return ProcessSnapshot((), time.time(), False, 0, 0, 0, 0,
                           "process inventory worker unavailable: " + reason[:120], False)


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = stream.read(size - len(data))
        if not chunk:
            raise EOFError("inventory stream closed")
        data.extend(chunk)
    return bytes(data)


def _receive(stream: BinaryIO, limit: int = MAX_FRAME) -> dict:
    size = struct.unpack("!I", _read_exact(stream, 4))[0]
    if not 0 < size <= limit:
        raise InventoryWorkerError("inventory frame byte limit")
    return decode(_read_exact(stream, size))


def _send(stream: BinaryIO, value: dict, limit: int = MAX_FRAME) -> None:
    payload = _bounded_canonical(value, limit)
    if not 0 < len(payload) <= limit:
        raise InventoryWorkerError("inventory frame byte limit")
    data = struct.pack("!I", len(payload)) + payload
    view = memoryview(data)
    while view:
        count = stream.write(view)
        if type(count) is not int or not 0 < count <= len(view):
            raise InventoryWorkerError("inventory write incomplete")
        view = view[count:]
    stream.flush()


def _wrap(body: dict, key: bytes, direction: bytes) -> dict:
    return {"body": body, "mac": hmac.new(key, _DOMAIN + direction + _bounded_canonical(body),
                                          hashlib.sha256).hexdigest()}


def _verify(message: dict, key: bytes, direction: bytes) -> dict:
    if (set(message) != {"body", "mac"} or type(message["body"]) is not dict
            or type(message["mac"]) is not str or len(message["mac"]) != 64):
        raise InventoryWorkerError("inventory envelope schema")
    body = message["body"]
    expected = _wrap(body, key, direction)["mac"]
    if not hmac.compare_digest(message["mac"], expected):
        raise InventoryWorkerError("inventory authentication failed")
    return body


def _hex(value: object, length: int) -> bool:
    return type(value) is str and len(value) == length and all(c in "0123456789abcdef" for c in value)


def _number(value: object, *, positive: bool = False) -> bool:
    try:
        return type(value) in (int, float) and math.isfinite(value) and (not positive or value > 0)
    except OverflowError:
        return False


def _bounded_canonical(value: object, limit: int = MAX_FRAME) -> bytes:
    output = bytearray()
    encoder = json.JSONEncoder(ensure_ascii=True, allow_nan=False, sort_keys=True,
                               separators=(",", ":"))
    for chunk in encoder.iterencode(value):
        raw = chunk.encode("ascii")
        if len(output) + len(raw) > limit:
            raise InventoryWorkerError("inventory frame byte limit")
        output.extend(raw)
    return bytes(output)


def encode_snapshot(snapshot: ProcessSnapshot) -> dict:
    result = {name: getattr(snapshot, name) for name in _FIELDS if name != "processes"}
    result["processes"] = [{**row, "cmdline": (list(row["cmdline"])
                                               if row["cmdline"] is not None else None)}
                           for row in snapshot.processes]
    # Validate both directions, including local collector adapter changes.
    decode_snapshot(result)
    return result


def decode_snapshot(value: dict) -> ProcessSnapshot:
    from types import MappingProxyType
    if type(value) is not dict or set(value) != _FIELDS:
        raise InventoryWorkerError("inventory receipt schema")
    if not _number(value["collected_at"], positive=True):
        raise InventoryWorkerError("inventory receipt time")
    for name in ("complete", "enumeration_complete"):
        if type(value[name]) is not bool:
            raise InventoryWorkerError("inventory receipt boolean")
    for name in ("enumerated", "skipped", "unreadable", "identity_incomplete"):
        if type(value[name]) is not int or not 0 <= value[name] <= 65_537:
            raise InventoryWorkerError("inventory receipt counter")
    if type(value["error"]) is not str or len(value["error"]) > 500:
        raise InventoryWorkerError("inventory receipt error")
    rows = value["processes"]
    if type(rows) is not list or len(rows) > 65_536 or len(rows) > value["enumerated"]:
        raise InventoryWorkerError("inventory receipt row bound")
    if (value["unreadable"] > len(rows) or value["identity_incomplete"] > len(rows)
            or (value["complete"] and (not value["enumeration_complete"] or any(
                value[n] for n in ("skipped", "unreadable", "identity_incomplete"))))):
        raise InventoryWorkerError("inventory receipt coverage contradiction")
    output = []
    seen = set()
    for row in rows:
        if type(row) is not dict or set(row) != _ROW_FIELDS:
            raise InventoryWorkerError("inventory row schema")
        pid = row["pid"]
        if type(pid) is not int or not 0 <= pid <= 0xFFFFFFFF or pid in seen:
            raise InventoryWorkerError("inventory row PID")
        seen.add(pid)
        parent = row["ppid"]
        if parent is not None and (type(parent) is not int or not 0 <= parent <= 0xFFFFFFFF):
            raise InventoryWorkerError("inventory row parent")
        for name in ("name", "exe", "username"):
            item = row[name]
            if item is not None and (type(item) is not str or len(item) > 65_536):
                raise InventoryWorkerError("inventory row string")
        birth = row["create_time"]
        if birth is not None and not _number(birth, positive=True):
            raise InventoryWorkerError("inventory row birth")
        command = row["cmdline"]
        if command is not None and (type(command) is not list or len(command) > 65_536
                or any(type(arg) is not str or len(arg) > 65_536 for arg in command)):
            raise InventoryWorkerError("inventory row command")
        copied = dict(row)
        copied["cmdline"] = tuple(command) if command is not None else None
        output.append(MappingProxyType(copied))
    return ProcessSnapshot(tuple(output), value["collected_at"], value["complete"],
                           value["enumerated"], value["skipped"], value["unreadable"],
                           value["identity_incomplete"], value["error"],
                           value["enumeration_complete"])


class _Pin:
    """Exact owned Windows kernel object, or the unreaped direct POSIX child."""
    def __init__(self, pid: int, *, process: subprocess.Popen | None = None):
        self.pid, self.process = pid, process
        self.handle = None
        self.closed = False
        self.close_failed = False
        self.proof = None
        if os.name == "nt":
            from angerona.core.windows_process_lease import _Native
            self.native = _Native()
            self.handle = self.native.open(pid, 0x1000 | 0x100000 | 0x100 | 1, False)
            self.identity = self.native.object_identity(self.handle)
            if process is not None and self.identity != self.native.object_identity(int(process._handle)):
                self.native.close(self.handle)
                self.handle = None
                raise InventoryWorkerError("spawned process object changed")
            self.birth = str(self.identity[1])
        else:
            import psutil
            self.native = None
            self.birth = psutil.Process(pid).create_time().hex()
            self.identity = (pid, self.birth)

    def alive(self) -> bool:
        if self.closed:
            return False
        if self.native:
            if self.native.object_identity(self.handle) != self.identity:
                raise InventoryWorkerError("owned process identity changed")
            return not self.native.wait(self.handle, 0)
        return self.process is not None and self.process.poll() is None

    def retire(self, timeout: float, *, terminate: bool) -> bool:
        if self.close_failed:
            return False
        if self.closed:
            return True
        if self.native:
            if self.alive() and terminate:
                try:
                    self.native.terminate(self.handle, 1)
                except RuntimeError:
                    # A redirector can exit naturally after its child. A
                    # failed call is terminal only when this exact object is
                    # signaled; permission/uncertain failures otherwise hold.
                    if not self.native.wait(self.handle, max(0, int(timeout * 1000))):
                        raise
            if not self.native.wait(self.handle, max(0, int(timeout * 1000))):
                return False
            if self.native.object_identity(self.handle) != self.identity:
                raise InventoryWorkerError("owned terminal identity changed")
            self.proof = {"pid": self.pid, "birth": self.birth, "wait_signaled": True,
                          "exit_code": self.native.exit_code(self.handle)}
            handle, self.handle = self.handle, None
            try:
                self.native.close(handle)
            except RuntimeError:
                self.close_failed = True
                return False
            self.proof["handle_closed"] = True
        else:
            if self.process is None:
                raise InventoryWorkerError("unowned POSIX process")
            if self.process.poll() is None and terminate:
                self.process.terminate()
            try:
                code = self.process.wait(timeout=max(0.001, timeout))
            except subprocess.TimeoutExpired:
                if not terminate:
                    return False
                self.process.kill()
                try:
                    code = self.process.wait(timeout=max(0.001, timeout))
                except subprocess.TimeoutExpired:
                    return False
            self.proof = {"pid": self.pid, "birth": self.birth, "wait_signaled": True,
                          "exit_code": code}
        self.closed = True
        return True

    def release_unadmitted(self) -> None:
        if self.handle is not None:
            handle, self.handle = self.handle, None
            self.native.close(handle)
        self.closed = True


class _Job:
    """Unnamed noninheritable Windows lifetime boundary; no global job lookup."""
    def __init__(self):
        self.handle = None
        self.close_failed = False
        if os.name != "nt":
            return
        import ctypes as c
        from ctypes import wintypes as w
        class Basic(c.Structure):
            _fields_ = [("PerProcessUserTimeLimit", c.c_longlong),
                        ("PerJobUserTimeLimit", c.c_longlong), ("LimitFlags", w.DWORD),
                        ("MinimumWorkingSetSize", c.c_size_t), ("MaximumWorkingSetSize", c.c_size_t),
                        ("ActiveProcessLimit", w.DWORD), ("Affinity", c.c_size_t),
                        ("PriorityClass", w.DWORD), ("SchedulingClass", w.DWORD)]
        class Io(c.Structure):
            _fields_ = [(name, c.c_ulonglong) for name in ("ReadOperationCount", "WriteOperationCount",
                "OtherOperationCount", "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]
        class Extended(c.Structure):
            _fields_ = [("BasicLimitInformation", Basic), ("IoInfo", Io),
                        ("ProcessMemoryLimit", c.c_size_t), ("JobMemoryLimit", c.c_size_t),
                        ("PeakProcessMemoryUsed", c.c_size_t), ("PeakJobMemoryUsed", c.c_size_t)]
        self.c, self.w = c, w
        self.api = c.WinDLL("kernel32", use_last_error=True)
        for name, args, result in (
            ("CreateJobObjectW", [c.c_void_p, w.LPCWSTR], w.HANDLE),
            ("SetInformationJobObject", [w.HANDLE, c.c_int, c.c_void_p, w.DWORD], w.BOOL),
            ("AssignProcessToJobObject", [w.HANDLE, w.HANDLE], w.BOOL),
            ("IsProcessInJob", [w.HANDLE, w.HANDLE, c.POINTER(w.BOOL)], w.BOOL),
            ("QueryInformationJobObject", [w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.c_void_p], w.BOOL),
            ("CloseHandle", [w.HANDLE], w.BOOL)):
            fn = getattr(self.api, name); fn.argtypes = args; fn.restype = result
        self.handle = self.api.CreateJobObjectW(None, None)
        if not self.handle:
            raise InventoryWorkerError("inventory job creation failed")
        info = Extended(); info.BasicLimitInformation.LimitFlags = 0x2000 | 0x8
        # A console-mode venv redirector may own one conhost in addition to the
        # actual interpreter. There is still only one collector lifetime.
        info.BasicLimitInformation.ActiveProcessLimit = 3
        if not self.api.SetInformationJobObject(self.handle, 9, c.byref(info), c.sizeof(info)):
            self.close()
            raise InventoryWorkerError("inventory job policy failed")

    def assign(self, pin: _Pin) -> None:
        if self.handle is None:
            return
        member = self.w.BOOL()
        if not self.api.IsProcessInJob(pin.handle, self.handle, self.c.byref(member)):
            raise InventoryWorkerError("inventory job membership failed")
        if not member.value and not self.api.AssignProcessToJobObject(self.handle, pin.handle):
            raise InventoryWorkerError("inventory job assignment failed")

    def close(self) -> None:
        if self.close_failed:
            raise InventoryWorkerError("inventory job close unproven")
        if self.handle is not None:
            handle, self.handle = self.handle, None
            if not self.api.CloseHandle(handle):
                self.close_failed = True
                raise InventoryWorkerError("inventory job close failed")

    def members(self) -> list[int]:
        if self.handle is None:
            return []
        c, w = self.c, self.w
        class Ids(c.Structure):
            _fields_ = [("assigned", w.DWORD), ("count", w.DWORD),
                        ("ids", c.c_size_t * 8)]
        ids = Ids()
        if not self.api.QueryInformationJobObject(self.handle, 3, c.byref(ids), c.sizeof(ids), None):
            raise InventoryWorkerError("inventory job members unavailable")
        if ids.assigned > 3 or ids.count > 3:
            raise InventoryWorkerError("inventory job member bound")
        return [int(value) for value in ids.ids[:ids.count]]

    def contains(self, pin: _Pin) -> bool:
        if self.handle is None:
            return False
        member = self.w.BOOL()
        if not self.api.IsProcessInJob(pin.handle, self.handle, self.c.byref(member)):
            raise InventoryWorkerError("inventory job membership unavailable")
        return bool(member.value)


def _resume_owned_primary(pin: _Pin, *, _api=None) -> None:
    """Resume only the sole thread of our newly created suspended process.

    Python closes CreateProcess's initial thread handle. Toolhelp supplies its
    sole pre-execution thread; native object and owner checks bind that handle
    before ResumeThread. No running process is suspended or injected here.
    """
    import ctypes as c
    from ctypes import wintypes as w
    class Entry(c.Structure):
        _fields_ = [("size", w.DWORD), ("usage", w.DWORD), ("tid", w.DWORD),
                    ("owner", w.DWORD), ("base", w.LONG), ("delta", w.LONG),
                    ("flags", w.DWORD)]
    api = c.WinDLL("kernel32", use_last_error=True) if _api is None else _api
    for name, args, result in (
        ("CreateToolhelp32Snapshot", [w.DWORD, w.DWORD], w.HANDLE),
        ("Thread32First", [w.HANDLE, c.POINTER(Entry)], w.BOOL),
        ("Thread32Next", [w.HANDLE, c.POINTER(Entry)], w.BOOL),
        ("OpenThread", [w.DWORD, w.BOOL, w.DWORD], w.HANDLE),
        ("GetProcessIdOfThread", [w.HANDLE], w.DWORD),
        ("ResumeThread", [w.HANDLE], w.DWORD),
        ("CloseHandle", [w.HANDLE], w.BOOL)):
        fn=getattr(api,name);fn.argtypes=args;fn.restype=result
    if not pin.alive():
        raise InventoryWorkerError("suspended inventory process retired")
    snapshot = api.CreateToolhelp32Snapshot(4, 0)
    if not snapshot or snapshot == c.c_void_p(-1).value:
        raise InventoryWorkerError("inventory initial thread snapshot failed")
    thread = None
    try:
        entry=Entry();entry.size=c.sizeof(entry)
        present=api.Thread32First(snapshot,c.byref(entry)); tids=[]; count=0
        while present:
            count+=1
            if count>65_536:
                raise InventoryWorkerError("inventory initial thread bound")
            if entry.owner == pin.pid:
                tids.append(int(entry.tid))
            entry.size=c.sizeof(entry)
            present=api.Thread32Next(snapshot,c.byref(entry))
        if c.get_last_error()!=18 or len(tids)!=1:
            raise InventoryWorkerError("inventory initial thread ambiguous")
        thread=api.OpenThread(0x0800|0x0002,False,tids[0])
        if not thread or api.GetProcessIdOfThread(thread)!=pin.pid or not pin.alive():
            raise InventoryWorkerError("inventory initial thread ownership changed")
        if api.ResumeThread(thread)!=1:
            raise InventoryWorkerError("inventory initial suspend count changed")
    finally:
        # Never retry a CloseHandle failure against a possibly recycled value.
        failed=False
        if thread:
            failed=not bool(api.CloseHandle(thread))
        if not api.CloseHandle(snapshot):
            failed=True
        if failed:
            raise InventoryCustodyCloseError("inventory initial thread custody close failed")


def _birth_of(pid: int) -> str:
    if os.name == "nt":
        from angerona.core.windows_process_lease import _Native
        native = _Native(); handle = native.open(pid, 0x1000 | 0x100000, False)
        try:
            if native.wait(handle, 0):
                raise InventoryWorkerError("inventory parent retired")
            return str(native.object_identity(handle)[1])
        finally:
            native.close(handle)
    import psutil
    return psutil.Process(pid).create_time().hex()


def _own_birth() -> str:
    return _birth_of(os.getpid())


def _arm_parent_lifetime(binding: dict) -> None:
    for prefix in ("parent", "wrapper"):
        pid, birth = binding[prefix + "_pid"], binding[prefix + "_birth"]
        if type(pid) is not int or pid <= 0 or type(birth) is not str or len(birth) > 80:
            raise InventoryWorkerError("inventory parent identity schema")
        if _birth_of(pid) != birth:
            raise InventoryWorkerError("inventory parent generation changed")
    if os.name == "nt":
        if os.getppid() not in (binding["parent_pid"], binding["wrapper_pid"]):
            raise InventoryWorkerError("inventory parent relationship changed")
        return  # Parent owns the noninheritable Windows kill-on-close job.
    if not sys.platform.startswith("linux") or os.getppid() != binding["parent_pid"]:
        raise InventoryWorkerError("inventory parent lifetime unsupported")
    # Linux's parent-death signal belongs to the creating thread. The parent
    # IPC thread remains retained for the entire child lifetime. Arm then
    # recheck to cover a parent exit between bootstrap and this syscall.
    import ctypes
    import signal
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                           ctypes.c_ulong, ctypes.c_ulong]
    libc.prctl.restype = ctypes.c_int
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
        raise InventoryWorkerError("inventory parent death signal unavailable")
    if (os.getppid() != binding["parent_pid"]
            or _birth_of(binding["parent_pid"]) != binding["parent_birth"]):
        raise InventoryWorkerError("inventory parent changed during admission")


@dataclass
class _Request:
    sequence: int
    nonce: str
    done: threading.Event = field(default_factory=threading.Event)
    result: ProcessSnapshot | None = None


class ProcessSnapshotProvider:
    """One worker lifetime. Failures hold coverage until this owner is retired.

    Constructor and cached lifecycle reads perform no provider I/O. Lifecycle
    and request operations refuse Qt's thread before acquiring a provider lock.
    A caller must retain this object and retry stop() until it returns True.
    """
    def __init__(self, command: Sequence[str] | None = None, *, startup_timeout: float = 5.0,
                 request_timeout: float = 15.0):
        for value in (startup_timeout, request_timeout):
            if not _number(value, positive=True) or value > 60:
                raise ValueError("invalid inventory deadline")
        self.command = tuple(command) if command is not None else tuple(
            [sys.executable] + ([] if getattr(sys, "frozen", False) else ["-m", "angerona"])
            + ["--process-snapshot-worker"])
        if not self.command or any(type(arg) is not str or not arg for arg in self.command):
            raise ValueError("invalid inventory command")
        self.startup_timeout, self.request_timeout = float(startup_timeout), float(request_timeout)
        self._lock = threading.Lock()
        self._operation = threading.Lock()
        self._retirement = threading.Lock()
        self._started = self._stopping = self._ready = self._retired = False
        self._reason = "not-started"
        self._startup = threading.Event()
        self._queue = queue.Queue(maxsize=1)
        self._thread = self._process = self._wrapper = self._child = self._job = None
        self._key = self._session = None
        self._parent_binding = None
        self._sequence = 0
        self._pending = None
        self._proofs = []
        self._extra_pins = []
        self._launching = False
        self._retirement_error = None
        self._failure = None
        self._popen_close_failed = False
        self._starting_thread = False
        self._auxiliary_close_unproven = False

    def lifecycle_snapshot(self) -> dict:
        with self._lock:
            return {"advisory_only": True, "ready": self._ready, "retired": self._retired,
                    "state": self._reason, "child_pid": self._child.pid if self._child else None,
                    "child_birth": self._child.birth if self._child else None,
                    "wrapper_pid": self._wrapper.pid if self._wrapper else None,
                    "retirement_error": self._retirement_error,
                    "error": self._failure,
                    "auxiliary_close_unproven": self._auxiliary_close_unproven,
                    "retirement_proofs": [dict(p) for p in self._proofs]}

    def _fail(self, reason: str) -> None:
        with self._lock:
            self._ready = False
            self._stopping = True
            # A deadline can close the pipe and produce a second exception on
            # the IPC worker. Preserve the first failure instead of replacing
            # it with that cleanup consequence or the later retired state.
            if self._failure is None:
                self._failure = reason[:120]
            if not self._retired:
                self._reason = self._failure
            pending = self._pending
        self._startup.set()
        if pending is not None:
            pending.done.set()

    def _unavailable_reason_locked(self) -> str:
        if self._failure and self._reason != self._failure:
            return f"{self._failure}; state={self._reason}"[:120]
        return self._failure or self._reason

    def start(self) -> bool:
        if on_gui_thread():
            return False
        try:
            with self._lock:
                if self._started:
                    return self._ready
                if self._stopping:
                    return False
                self._started = True
                self._reason = "starting"
                thread = threading.Thread(target=self._run, name="ProcessInventoryIPC", daemon=False)
                self._thread = thread
                self._starting_thread = True
        except Exception as exc:
            self._fail(type(exc).__name__)
            self.stop(timeout=1.0)
            return False
        try:
            thread.start()
        except Exception as exc:
            self._fail(type(exc).__name__)
        finally:
            with self._lock:
                self._starting_thread = False
        if not thread.is_alive():
            self.stop(timeout=1.0)
            return False
        if not self._startup.wait(self.startup_timeout):
            self._fail("startup-deadline")
            self.stop(timeout=1.0)
            return False
        with self._lock:
            return self._ready

    def snapshot(self) -> ProcessSnapshot:
        if on_gui_thread():
            return unavailable("GUI-thread admission refused")
        deadline = time.monotonic() + self.request_timeout
        if not self._operation.acquire(timeout=self.request_timeout):
            return unavailable("request admission deadline")
        try:
            with self._lock:
                if not self._ready or self._stopping:
                    return unavailable(self._unavailable_reason_locked())
                self._sequence += 1
                request = _Request(self._sequence, secrets.token_hex(16))
                self._pending = request
            self._queue.put_nowait(request)
            if not request.done.wait(max(0.0, deadline - time.monotonic())):
                self._fail("request-deadline")
                self.stop(timeout=1.0)
                return unavailable("request-deadline")
            with self._lock:
                valid = self._ready and not self._stopping and self._pending is request
                self._pending = None
                reason = self._unavailable_reason_locked()
            return request.result if valid and request.result is not None else unavailable(reason)
        finally:
            self._operation.release()

    def _admit_child(self, hello: dict) -> None:
        import psutil
        pid, birth = hello.get("child_pid"), hello.get("child_birth")
        if type(pid) is not int or pid <= 0 or type(birth) is not str or len(birth) > 80:
            raise InventoryWorkerError("inventory child identity schema")
        if pid == self._wrapper.pid:
            child = self._wrapper
        elif os.name == "nt":
            child = _Pin(pid)
        else:
            raise InventoryWorkerError("unexpected inventory child")
        try:
            observed = psutil.Process(pid)
            if (child.birth != birth or not child.alive()
                    or (pid != self._wrapper.pid and observed.ppid() != self._wrapper.pid)
                    or observed.cmdline()[1:] != list(self.command[1:])):
                raise InventoryWorkerError("inventory child ownership mismatch")
            expected_images = {os.path.normcase(os.path.realpath(self.command[0])),
                               os.path.normcase(os.path.realpath(getattr(sys, "_base_executable", sys.executable)))}
            if os.name == "nt" and os.path.basename(self.command[0]).casefold() == "pythonw.exe":
                base = os.path.dirname(getattr(sys, "_base_executable", sys.executable))
                expected_images.add(os.path.normcase(os.path.realpath(os.path.join(base, "pythonw.exe"))))
            if os.path.normcase(os.path.realpath(observed.exe())) not in expected_images:
                raise InventoryWorkerError("inventory child image mismatch")
            self._job.assign(child)
        except BaseException:
            if child is not self._wrapper:
                child.release_unadmitted()
            raise
        with self._lock:
            self._child = child

    def _run(self) -> None:
        try:
            with self._lock:
                if self._stopping:
                    return
                self._launching = True
            job = _Job()
            with self._lock:
                self._job = job
            process = subprocess.Popen(self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL, bufsize=0, close_fds=True,
                                       creationflags=((subprocess.CREATE_NO_WINDOW | 0x4) if os.name == "nt" else 0))
            with self._lock:
                self._process = process
            wrapper = _Pin(process.pid, process=process)
            with self._lock:
                self._process, self._wrapper = process, wrapper
                cancelled = self._stopping
            job.assign(wrapper)
            with self._lock:
                cancelled = cancelled or self._stopping
            if not cancelled and os.name == "nt":
                _resume_owned_primary(wrapper)
            with self._lock:
                self._launching = False
            if cancelled:
                return
            self._key, self._session = secrets.token_bytes(32), secrets.token_hex(16)
            self._parent_binding = {"parent_pid": os.getpid(), "parent_birth": _own_birth(),
                                    "wrapper_pid": wrapper.pid, "wrapper_birth": wrapper.birth}
            _send(process.stdin, {"protocol": PROTOCOL, "kind": "bootstrap", "key": self._key.hex(),
                                  "session": self._session, **self._parent_binding}, MAX_CONTROL)
            envelope = _receive(process.stdout, MAX_CONTROL)
            hello = _verify(envelope, self._key, b"hello\0")
            if (set(hello) != {"protocol", "kind", "session", "child_pid", "child_birth"} | set(self._parent_binding)
                    or hello["protocol"] != PROTOCOL or hello["kind"] != "hello"
                    or hello["session"] != self._session
                    or any(type(hello[k]) is not type(v) or hello[k] != v
                           for k, v in self._parent_binding.items())):
                raise InventoryWorkerError("inventory hello binding")
            self._admit_child(hello)
            with self._lock:
                if self._stopping:
                    return
                self._ready, self._reason = True, "ready"
            self._startup.set()
            while True:
                with self._lock:
                    if self._stopping:
                        break
                try:
                    request = self._queue.get(timeout=0.1)
                except queue.Empty:
                    continue
                if request is None:
                    break
                binding = {"protocol": PROTOCOL, "session": self._session,
                           **self._parent_binding,
                           "child_pid": self._child.pid, "child_birth": self._child.birth,
                           "sequence": request.sequence, "nonce": request.nonce}
                _send(process.stdin, _wrap({**binding, "kind": "snapshot"}, self._key, b"request\0"), MAX_CONTROL)
                body = _verify(_receive(process.stdout), self._key, b"response\0")
                if (set(body) != set(binding) | {"kind", "snapshot"}
                        or any(type(body[k]) is not type(v) or body[k] != v for k, v in binding.items())
                        or body["kind"] != "snapshot-result" or not self._child.alive()):
                    raise InventoryWorkerError("inventory response binding")
                request.result = decode_snapshot(body["snapshot"])
                request.done.set()
        except BaseException as exc:
            if isinstance(exc, InventoryCustodyCloseError):
                with self._lock:
                    self._auxiliary_close_unproven = True
            self._fail(type(exc).__name__)
        finally:
            with self._lock:
                self._launching = False
            self._startup.set()
            self._retire(1.0)

    def _retire(self, timeout: float) -> bool:
        if not self._retirement.acquire(timeout=max(0.001, timeout)):
            return False
        try:
            deadline = time.monotonic() + timeout
            if self._popen_close_failed:
                return False
            with self._lock:
                child, wrapper, process, job = self._child, self._wrapper, self._process, self._job
                if self._launching or self._starting_thread:
                    return False
            # Discover only members of our unnamed kernel job. This also pins a
            # redirector's child when startup failed before hello admission.
            if job is not None and job.handle is not None:
                known = {p.pid for p in [child, wrapper, *self._extra_pins] if p is not None}
                for pid in job.members():
                    if pid in known:
                        continue
                    pin = _Pin(pid)
                    if not job.contains(pin):
                        pin.release_unadmitted()
                        raise InventoryWorkerError("inventory job member changed")
                    self._extra_pins.append(pin)
            pins = [p for p in self._extra_pins if p is not child and p is not wrapper]
            if child is not None and child is not wrapper:
                pins.append(child)
            if wrapper is not None:
                pins.append(wrapper)
            if process is not None and wrapper is None:
                # Popen retains its original process object even if opening an
                # additional least-rights pin failed. Never find/kill by name.
                if process.poll() is None:
                    process.terminate()
            for pin in pins:
                if not pin.retire(max(0.001, deadline - time.monotonic()), terminate=True):
                    return False
                with self._lock:
                    if pin.proof not in self._proofs:
                        self._proofs.append(dict(pin.proof))
            if job is not None and job.handle is not None:
                if job.members():
                    return False
                job.close()
            if process is not None:
                try:
                    process.wait(timeout=max(0.001, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    return False
                for stream in (process.stdin, process.stdout):
                    if stream is not None:
                        stream.close()
                if os.name == "nt":
                    try:
                        process._handle.Close()
                    except OSError:
                        self._popen_close_failed = True
                        return False
            with self._lock:
                # A launch may still be in progress after a startup timeout.
                if self._thread is not threading.current_thread() and self._thread is not None and self._thread.is_alive():
                    return False
                if self._auxiliary_close_unproven:
                    self._reason = "auxiliary-custody-close-unproven"
                    return False
                self._ready, self._retired = False, True
                self._reason = "retired"
            return True
        except (OSError, RuntimeError, ValueError) as exc:
            self._retirement_error = type(exc).__name__
            return False
        finally:
            self._retirement.release()

    def stop(self, timeout: float = 3.0) -> bool:
        if on_gui_thread():
            return False
        if not _number(timeout, positive=True) or timeout > 60:
            raise ValueError("invalid inventory retirement deadline")
        with self._lock:
            self._stopping, self._ready = True, False
            thread, pending = self._thread, self._pending
            if not self._retired:
                self._reason = "stopping"
        self._startup.set()
        if pending is not None:
            pending.done.set()
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            pass
        deadline = time.monotonic() + timeout
        self._retire(min(1.0, timeout))
        if thread is not None and thread is not threading.current_thread() and thread.is_alive():
            thread.join(timeout=max(0.0, deadline - time.monotonic()))
        return self._retire(max(0.001, deadline - time.monotonic()))


def worker_main() -> int:
    """Internal pre-Qt entry point; no installation state or sensors start here."""
    from angerona.telemetry.sensors import _collect_process_snapshot
    with os.fdopen(os.dup(0), "rb", buffering=0) as source, os.fdopen(os.dup(1), "wb", buffering=0) as sink:
        try:
            bootstrap = _receive(source, MAX_CONTROL)
            parent_fields = {"parent_pid", "parent_birth", "wrapper_pid", "wrapper_birth"}
            if (set(bootstrap) != {"protocol", "kind", "key", "session"} | parent_fields
                    or bootstrap["protocol"] != PROTOCOL or bootstrap["kind"] != "bootstrap"
                    or not _hex(bootstrap["key"], 64) or not _hex(bootstrap["session"], 32)):
                return 2
            parent_binding = {name: bootstrap[name] for name in parent_fields}
            _arm_parent_lifetime(parent_binding)
            key, session = bytes.fromhex(bootstrap["key"]), bootstrap["session"]
            identity = {"protocol": PROTOCOL, "session": session,
                        **parent_binding,
                        "child_pid": os.getpid(), "child_birth": _own_birth()}
            _send(sink, _wrap({**identity, "kind": "hello"}, key, b"hello\0"), MAX_CONTROL)
            sequence = 0
            while True:
                body = _verify(_receive(source, MAX_CONTROL), key, b"request\0")
                if (set(body) != set(identity) | {"kind", "sequence", "nonce"}
                        or any(type(body[k]) is not type(v) or body[k] != v for k, v in identity.items())
                        or body["kind"] != "snapshot" or type(body["sequence"]) is not int
                        or body["sequence"] != sequence + 1 or not _hex(body["nonce"], 32)):
                    return 2
                sequence = body["sequence"]
                receipt = _collect_process_snapshot()
                response = {**identity, "kind": "snapshot-result", "sequence": sequence,
                            "nonce": body["nonce"], "snapshot": encode_snapshot(receipt)}
                _send(sink, _wrap(response, key, b"response\0"))
        except EOFError:
            return 0
        except (OSError, RuntimeError, ValueError, TypeError, RecursionError):
            return 2
