"""Persistent UGCAP subprocess over inherited, mesh-authenticated anonymous pipes.

The launcher's user token is inherited; no elevation, OS enclave, or privilege
drop is claimed. The initial verified mesh flag authenticates this control plane
only. It does not attest the source tree or authorize general telemetry.

Passphrases travel only inside encrypted application packets. Caller-owned
bytearrays remain caller-owned; temporary mutable copies are wiped best effort.
Python/base64/crypto can retain immutable copies, so perfect erasure is not
claimed. stderr is discarded and protocol errors never include exception text.
"""
from __future__ import annotations

import base64
from collections import OrderedDict
import ctypes
from enum import Enum
import json
import math
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import threading
import time

from angerona.core.enclave_mesh import (
    CrossProcessMeshChannel, MAX_PAYLOAD, MeshError, MeshPipe, canonical, decode_frame,
)

from angerona.core.ugcap_job_witness import JobMemberWitness, NativeJobMemberAPI

_REQUEST = "ugcap.request"
_RESPONSE = "ugcap.response"
_MAX_BOOTSTRAP = 64 * 1024
_TOKEN = re.compile(r"[0-9a-f]{32}\Z")
_KEY_NAME = re.compile(r"Angerona\.UGCAP\.[A-Za-z0-9_-]{1,96}\Z")
_COMMANDS = frozenset({"status", "provision", "initialize", "verify", "restore", "lock", "shutdown"})
_SECRET_COMMANDS = frozenset({"initialize", "verify", "restore"})
_BASE_FIELDS = frozenset({"repo_root", "vault_path", "key_name"})
_ERRORS = frozenset({"invalid_request", "hardware_unavailable", "authentication_failed",
                     "coverage_incomplete", "stale_report", "operation_failed", "response_too_large"})


class UGCAPWorkerError(RuntimeError):
    """Sanitized worker failure; no credentials or child exception text."""


class UGCAPWorkerUnavailable(UGCAPWorkerError):
    pass


class StartupStage(str, Enum):
    CUSTODY = "custody"
    MESH = "mesh-bootstrap"
    LAUNCH = "launch"
    JOB = "job-custody"
    RESUME = "resume"
    PREPARE = "prepare-write"
    PREPARED = "prepared-read"
    BOOTSTRAP = "bootstrap-write"
    READY = "protected-ready"


class StartupReason(str, Enum):
    TIMEOUT = "timeout"
    MESH = "mesh-rejected"
    IO = "io-unavailable"
    REJECTED = "startup-rejected"
    INTERRUPTED = "interrupted"
    UNEXPECTED = "unexpected"


def _startup_reason(exc):
    if isinstance(exc, TimeoutError):
        return StartupReason.TIMEOUT
    if isinstance(exc, MeshError):
        return StartupReason.MESH
    if isinstance(exc, (OSError, EOFError)):
        return StartupReason.IO
    if isinstance(exc, UGCAPWorkerUnavailable):
        return StartupReason.REJECTED
    return StartupReason.UNEXPECTED if isinstance(exc, Exception) else StartupReason.INTERRUPTED


def _wipe(value):
    if isinstance(value, bytearray):
        value[:] = b"\0" * len(value)


def _public_path(value) -> str:
    if (not isinstance(value, str) or not 1 <= len(value) <= 32768 or "\0" in value
            or value.startswith(("\\\\", "//")) or not Path(value).is_absolute()
            or ".." in Path(value).parts):
        raise UGCAPWorkerError("invalid_request")
    return str(Path(value).absolute())


def _payload(command, payload) -> dict:
    if not isinstance(command, str) or command not in _COMMANDS or not isinstance(payload, dict):
        raise UGCAPWorkerError("invalid_request")
    fields = set(payload)
    if command == "shutdown":
        if fields:
            raise UGCAPWorkerError("invalid_request")
    elif command in {"initialize", "verify"}:
        if fields != _BASE_FIELDS:
            raise UGCAPWorkerError("invalid_request")
    elif command == "restore":
        if fields != _BASE_FIELDS | {"paths", "report_id"}:
            raise UGCAPWorkerError("invalid_request")
        paths = payload["paths"]
        if (not isinstance(paths, list) or not 1 <= len(paths) <= 128
                or not isinstance(payload["report_id"], str) or not _TOKEN.fullmatch(payload["report_id"])):
            raise UGCAPWorkerError("invalid_request")
        # Do not import vault/source-recovery code into the desktop merely to
        # validate a request. The worker applies its full scope policy again.
        if any(not isinstance(path, str) or not 1 <= len(path) <= 2048
               or any(char in path for char in ("\\", ":", "\0"))
               or any(part in {"", ".", ".."} for part in path.split("/")) for path in paths):
            raise UGCAPWorkerError("invalid_request")
    elif command == "provision":
        if not {"key_name"} <= fields <= {"repo_root", "key_name"}:
            raise UGCAPWorkerError("invalid_request")
    elif fields and fields != _BASE_FIELDS:
        raise UGCAPWorkerError("invalid_request")
    result = dict(payload)
    for name in ("repo_root", "vault_path"):
        if name in result:
            result[name] = _public_path(result[name])
    if "key_name" in result and (not isinstance(result["key_name"], str) or not _KEY_NAME.fullmatch(result["key_name"])):
        raise UGCAPWorkerError("invalid_request")
    if "paths" in result:
        result["paths"] = list(result["paths"])
    return result


def _application(value) -> bytes:
    encoded = canonical(value)
    if len(encoded) > MAX_PAYLOAD:
        raise UGCAPWorkerError("response_too_large")
    return encoded


def _request(command, payload, secret=None):
    clean = _payload(command, payload)
    if command in _SECRET_COMMANDS:
        if not isinstance(secret, bytearray) or not 12 <= len(secret) <= 4096:
            raise UGCAPWorkerError("invalid_request")
    elif secret is not None:
        raise UGCAPWorkerError("invalid_request")
    return {"version": 1, "request_id": secrets.token_hex(16), "nonce": secrets.token_hex(16),
            "command": command, "payload": clean,
            "secret": base64.b64encode(secret).decode("ascii") if secret is not None else None}


def _validate_request(value):
    if (not isinstance(value, dict) or set(value) != {"version", "request_id", "nonce", "command", "payload", "secret"}
            or type(value["version"]) is not int or value["version"] != 1
            or not isinstance(value["request_id"], str) or not _TOKEN.fullmatch(value["request_id"])
            or not isinstance(value["nonce"], str) or not _TOKEN.fullmatch(value["nonce"])
            or not isinstance(value["command"], str)):
        raise UGCAPWorkerError("invalid_request")
    clean = _payload(value["command"], value["payload"])
    secret = None
    if value["command"] in _SECRET_COMMANDS:
        if not isinstance(value["secret"], str) or len(value["secret"]) > 5464:
            raise UGCAPWorkerError("invalid_request")
        try:
            secret = bytearray(base64.b64decode(value["secret"], validate=True))
            if not 12 <= len(secret) <= 4096:
                raise ValueError
        except (ValueError, UnicodeError):
            _wipe(secret)
            raise UGCAPWorkerError("invalid_request") from None
    elif value["secret"] is not None:
        raise UGCAPWorkerError("invalid_request")
    return clean, secret


def _response(request, *, result=None, error=None):
    return {"version": 1, "request_id": request["request_id"], "nonce": request["nonce"],
            "command": request["command"], "ok": error is None, "result": result,
            "error": error}


def _compact(result):
    if not isinstance(result, dict):
        raise UGCAPWorkerError("operation_failed")
    # The receipt retains the verified map once. Raw observations and backups
    # remain in the vault process; they never enter the dashboard/control IPC.
    clean = {key: value for key, value in result.items()
             if key not in {"observations", "backups", "verified_files"}}
    if isinstance(clean.get("last_report"), dict):
        clean["last_report"] = _compact(clean["last_report"])
    return clean


def _error_code(exc):
    # Map known exception *types*, never their potentially sensitive messages.
    name = type(exc).__name__
    return {"HardwareUnavailable": "hardware_unavailable", "HardwareIntegrityError": "authentication_failed",
            "VaultAuthenticationError": "authentication_failed", "VaultCoverageError": "coverage_incomplete",
            "StaleReportError": "stale_report"}.get(name, "operation_failed")


class _VaultExecutor:
    def __init__(self):
        self._vaults = OrderedDict()

    def _vault(self, payload):
        from angerona.core.ugcap import UGCAPVault
        from angerona.core.ugcap_hardware import WindowsTPMHardware
        context = tuple(payload[name] for name in ("repo_root", "vault_path", "key_name"))
        if context not in self._vaults:
            if len(self._vaults) >= 8:
                _old, vault = self._vaults.popitem(last=False)
                vault.lock()
            self._vaults[context] = UGCAPVault(context[0], context[1], WindowsTPMHardware(context[2]))
        self._vaults.move_to_end(context)
        return self._vaults[context]

    def execute(self, command, payload, secret):
        if command == "status":
            result = self._vault(payload).snapshot() if payload else {"status": "ready", "cached_vaults": len(self._vaults)}
            result.update(worker_process=True, os_enclave=False, token="launching-user",
                          hardware={"backend": "windows_tpm", "platform_supported": sys.platform == "win32",
                                    "probed": False, "detail": "No TPM access during status"})
            return result
        if command == "provision":
            from angerona.core.ugcap_hardware import WindowsTPMHardware
            return {"status": "provisioned", **WindowsTPMHardware(payload["key_name"]).provision()}
        if command == "shutdown":
            self.close()
            return {"status": "shutdown"}
        if command == "lock":
            if payload:
                return self._vault(payload).lock()
            for vault in self._vaults.values():
                vault.lock()
            return {"status": "locked"}
        vault = self._vault(payload)
        if command == "initialize":
            return vault.initialize(secret)
        if command == "verify":
            return vault.verify(secret)
        if command == "restore":
            return vault.restore(secret, payload["paths"], expected_report_id=payload["report_id"])
        raise UGCAPWorkerError("invalid_request")

    def close(self):
        for vault in self._vaults.values():
            vault.lock()
        self._vaults.clear()


def _create_worker_job():
    """Create private job custody before attaching the suspended daemon."""
    from ctypes import wintypes
    class Basic(ctypes.Structure):
        _fields_ = [("process_time", ctypes.c_int64), ("job_time", ctypes.c_int64),
                    ("flags", wintypes.DWORD), ("minimum", ctypes.c_size_t), ("maximum", ctypes.c_size_t),
                    ("processes", wintypes.DWORD), ("affinity", ctypes.c_size_t),
                    ("priority", wintypes.DWORD), ("scheduling", wintypes.DWORD)]
    class IO(ctypes.Structure):
        _fields_ = [(name, ctypes.c_uint64) for name in ("read", "write", "other", "read_bytes", "write_bytes", "other_bytes")]
    class Extended(ctypes.Structure):
        _fields_ = [("basic", Basic), ("io", IO), ("process_memory", ctypes.c_size_t),
                    ("job_memory", ctypes.c_size_t), ("peak_process", ctypes.c_size_t), ("peak_job", ctypes.c_size_t)]
    class Accounting(ctypes.Structure):
        _fields_ = [("user", ctypes.c_int64), ("kernel", ctypes.c_int64),
                    ("period_user", ctypes.c_int64), ("period_kernel", ctypes.c_int64),
                    ("faults", wintypes.DWORD), ("total", wintypes.DWORD),
                    ("active", wintypes.DWORD), ("terminated", wintypes.DWORD)]
    kernel = ctypes.WinDLL("kernel32", use_last_error=True, winmode=0x800)
    create = kernel.CreateJobObjectW
    create.argtypes, create.restype = [ctypes.c_void_p, wintypes.LPCWSTR], wintypes.HANDLE
    configure = kernel.SetInformationJobObject
    configure.argtypes, configure.restype = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD], wintypes.BOOL
    assign = kernel.AssignProcessToJobObject
    assign.argtypes, assign.restype = [wintypes.HANDLE, wintypes.HANDLE], wintypes.BOOL
    terminate = kernel.TerminateJobObject
    terminate.argtypes, terminate.restype = [wintypes.HANDLE, wintypes.UINT], wintypes.BOOL
    query = kernel.QueryInformationJobObject
    query.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                      wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    query.restype = wintypes.BOOL
    close = kernel.CloseHandle
    close.argtypes, close.restype = [wintypes.HANDLE], wintypes.BOOL
    def attach(handle, process_handle):
        info = Extended()
        info.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        return bool(configure(handle, 9, ctypes.byref(info), ctypes.sizeof(info))) and bool(assign(handle, process_handle))
    def active_processes(handle):
        accounting = Accounting()
        if not query(handle, 1, ctypes.byref(accounting), ctypes.sizeof(accounting), None):
            raise OSError("UGCAP job retirement query is unavailable")
        return int(accounting.active)
    members = JobMemberWitness(NativeJobMemberAPI())
    job = create(None, None)
    if not job:
        raise OSError("UGCAP job custody unavailable")
    return _StartupJob(job, lambda handle: bool(terminate(handle, 1)),
                       active_processes, lambda handle: bool(close(handle)), assign=attach, members=members)


def _custody(data_root):
    from angerona.core.engine_transport import private_directory, verify_private
    from angerona.core.hardening import ensure_sensitive_parent, key_acl_required
    from angerona.core.secure_store import _path_traverses_reparse
    root = Path(data_root).absolute()
    if _path_traverses_reparse(root) or not root.is_dir():
        raise UGCAPWorkerUnavailable("Protected worker runtime root is unavailable")
    if os.name == "nt" and key_acl_required():
        ensure_sensitive_parent(root / "ugcap-worker", required=True)
    else:
        verify_private(root, directory=True)
    private_directory(root / "ugcap-worker")
    return root


_PREPARED = b"Angerona.UGCAP.prepared.v1\n"


def _retain_startup_thread():
    """Duplicate this very worker's pseudo-handle before it performs IO."""
    if os.name != "nt":
        return None
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True, winmode=0x800)
    process, current = kernel.GetCurrentProcess, kernel.GetCurrentThread
    process.argtypes = current.argtypes = []
    process.restype = current.restype = wintypes.HANDLE
    duplicate = kernel.DuplicateHandle
    duplicate.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.HANDLE,
                         ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    duplicate.restype = wintypes.BOOL
    retained = wintypes.HANDLE()
    # CancelSynchronousIo needs THREAD_TERMINATE; native retirement needs
    # SYNCHRONIZE. This handle is private, non-inherited and never ID-resolved.
    if not duplicate(process(), current(), process(), ctypes.byref(retained), 0x00100001, False, 0):
        raise OSError("UGCAP startup thread custody is unavailable")
    return int(retained.value)


def _cancel_startup_thread(handle):
    if handle is None:
        return
    kernel = ctypes.WinDLL("kernel32", use_last_error=True, winmode=0x800)
    cancel = kernel.CancelSynchronousIo
    cancel.argtypes, cancel.restype = [ctypes.c_void_p], ctypes.c_int
    # ERROR_NOT_FOUND is a normal cancel-before-issue/completion race.
    # Cancellation is a request; join/native completion remain mandatory.
    cancel(handle)


def _startup_thread_finished(handle, timeout):
    if handle is None:
        return True
    kernel = ctypes.WinDLL("kernel32", use_last_error=True, winmode=0x800)
    wait = kernel.WaitForSingleObject
    wait.argtypes, wait.restype = [ctypes.c_void_p, ctypes.c_uint32], ctypes.c_uint32
    return wait(handle, max(0, min(2000, int(timeout * 1000)))) == 0


def _close_startup_thread(handle):
    if handle is None:
        return True
    kernel = ctypes.WinDLL("kernel32", use_last_error=True, winmode=0x800)
    close = kernel.CloseHandle
    close.argtypes, close.restype = [ctypes.c_void_p], ctypes.c_int
    return bool(close(handle))


class _StartupJob:
    """Retain a live job through termination/zero proof, then close it once.

    Native calls are cooperative: their own kernel latency cannot be preempted
    by this Python deadline. Timeout or unknown keeps custody and blocks reuse.
    """
    def __init__(self, handle, terminate, active_processes, close, *, assign=None, members=None):
        self._lock = threading.Lock()
        self._retire_lock = threading.Lock()
        self._process_retire_lock = threading.Lock()
        self._owned_process = None
        self._process_kill_attempted = False
        self._handle = handle
        self._terminate = terminate
        self._active_processes = active_processes
        self._close = close
        self._assign = assign
        self._members = members
        self._members_ready = False
        self._terminate_attempted = False
        self._terminated = False
        self._zero_confirmed = False
        self._close_attempted = False
        self._closed = False

    def assign(self, process):
        with self._retire_lock:
            with self._lock:
                if self._terminate_attempted or self._close_attempted or self._assign is None:
                    raise OSError("UGCAP job assignment is unavailable")
                if self._owned_process is not None and self._owned_process is not process:
                    raise OSError("UGCAP job process custody does not match")
                self._owned_process = process
                handle = self._handle
            if self._assign(handle, int(process._handle)) is not True:
                raise OSError("UGCAP job assignment is unavailable")

    def capture_members(self, deadline):
        remaining = max(0.0, deadline - time.monotonic())
        if not self._retire_lock.acquire(timeout=remaining):
            return False
        try:
            with self._lock:
                if self._terminate_attempted or self._close_attempted or self._members is None:
                    return False
                handle = self._handle
            return self._members.capture(handle, deadline)
        finally:
            self._retire_lock.release()

    def retire_process(self, process, timeout):
        """Retire the retained Windows Popen handle, independently of job zero.

        A suspended process may never have joined the job. No PID resolution or
        process-name discovery is permitted, and an unknown kill is not retried.
        """
        deadline = time.monotonic() + max(0.0, timeout)
        if not self._process_retire_lock.acquire(timeout=max(0.0, timeout)):
            return False
        try:
            with self._lock:
                if self._owned_process is not None and self._owned_process is not process:
                    return False
                self._owned_process = process
            if process is None:
                return True
            try:
                if process.poll() is not None:
                    return True
                with self._lock:
                    kill = not self._process_kill_attempted
                    self._process_kill_attempted = True
                if kill:
                    # Windows Popen.kill uses its retained process handle.
                    # Latch before calling: exceptions can follow native work.
                    process.kill()
                process.wait(timeout=max(0.0, deadline - time.monotonic()))
                return process.poll() is not None
            except BaseException:
                return False
        finally:
            self._process_retire_lock.release()

    def retire(self, timeout):
        """Prepare terminal proof; the job stays open until all other IO retires."""
        deadline = time.monotonic() + max(0.0, timeout)
        if not self._retire_lock.acquire(timeout=max(0.0, timeout)):
            return False
        try:
            with self._lock:
                if self._close_attempted:
                    return self._closed
                handle = self._handle
                terminate = not self._terminate_attempted
            if terminate:
                try:
                    if self._members is not None:
                        self._members.capture(handle, deadline)
                except BaseException:
                    pass  # Unknown remains latched by the witness; still stop the job.
                with self._lock:
                    self._terminate_attempted = True
                try:
                    terminated = self._terminate(handle) is True
                except BaseException:
                    terminated = False
                with self._lock:
                    self._terminated = terminated
            with self._lock:
                if not self._terminated:
                    return False
            while True:
                try:
                    active = self._active_processes(handle)
                except BaseException:
                    return False
                if type(active) is not int or active < 0:
                    return False
                if active == 0:
                    with self._lock:
                        self._zero_confirmed = True
                    if self._members is None:
                        return False
                    total_before = self._members.check_total(handle)
                    signaled = self._members.wait_terminated(deadline)
                    total_after = self._members.check_total(handle)
                    with self._lock:
                        self._members_ready = (total_before and signaled and total_after
                                               and time.monotonic() < deadline)
                        return self._members_ready
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                time.sleep(min(.01, remaining))
        finally:
            self._retire_lock.release()

    def finalize(self, timeout):
        """Close once after the caller has also proved exact Popen and IO exit."""
        deadline = time.monotonic() + max(0.0, timeout)
        if not self._retire_lock.acquire(timeout=max(0.0, timeout)):
            return False
        try:
            with self._lock:
                if self._close_attempted:
                    return self._closed
                if not self._members_ready or not self._zero_confirmed or self._members is None:
                    return False
                handle = self._handle
            if time.monotonic() >= deadline:
                return False
            try:
                active = self._active_processes(handle)
                if (type(active) is not int or active != 0 or not self._members.check_total(handle)
                        or time.monotonic() >= deadline):
                    return False
            except BaseException:
                return False
            with self._lock:
                self._handle = None
                self._close_attempted = True
            try:
                closed = self._close(handle) is True
            except BaseException:
                closed = False
            with self._lock:
                self._closed = closed
            return closed
        finally:
            self._retire_lock.release()

    @property
    def confirmed_closed(self):
        with self._lock:
            return self._zero_confirmed and self._members_ready and self._closed


class _StartupIO:
    """Retain exact thread/stream/buffer custody until native IO retirement."""
    def __init__(self):
        self._lock = threading.Lock()
        self._join_lock = threading.Lock()
        self._cancelled = threading.Event()
        self._workers = []

    def perform(self, operation, deadline):
        complete, result, failed = threading.Event(), [], []
        record = {"thread": None, "handle": None, "entered": threading.Event(), "start_uncertain": False, "close_outcome": None}
        def run():
            record["entered"].set()
            try:
                handle = _retain_startup_thread()
                with self._lock:
                    record["handle"] = handle
                    cancelled = self._cancelled.is_set()
                if cancelled or time.monotonic() >= deadline:
                    failed.append(True)
                    return
                result.append(operation())
            except BaseException:
                # Even SystemExit/KeyboardInterrupt text must never escape an
                # IO helper thread's traceback; only a fixed failure is public.
                failed.append(True)
            finally:
                complete.set()
        thread = threading.Thread(target=run, name="UGCAP-startup-io", daemon=False)
        record["thread"] = thread
        with self._lock:
            if self._cancelled.is_set():
                raise EOFError("UGCAP startup transport is retired")
            if time.monotonic() >= deadline:
                raise TimeoutError("UGCAP startup transport deadline expired")
            self._workers.append(record)
            try:
                thread.start()
            except BaseException as exc:
                # A main-thread interrupt during Thread.start's native-start
                # wait may leave a late worker. Keep custody until entry/exit
                # is observed; an ordinary pre-start error issued no IO.
                record["start_uncertain"] = not isinstance(exc, Exception)
                raise
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not complete.wait(remaining):
            raise TimeoutError("UGCAP startup transport deadline expired")
        if not self.join(max(0.0, deadline - time.monotonic())):
            raise TimeoutError("UGCAP startup transport retirement is pending")
        if failed:
            raise OSError("UGCAP startup transport failed")
        return result[0]

    def cancel(self):
        with self._lock:
            self._cancelled.set()
            for record in self._workers:
                handle = record["handle"]
                if handle is not None:
                    try:
                        # Serialize with handle closure. A retained kernel
                        # handle remains this generation even after thread exit.
                        _cancel_startup_thread(handle)
                    except (OSError, AttributeError):
                        pass

    def join(self, timeout):
        deadline = time.monotonic() + max(0.0, timeout)
        if not self._join_lock.acquire(timeout=max(0.0, timeout)):
            return False
        try:
            with self._lock:
                workers = tuple(self._workers)
            for record in workers:
                worker = record["thread"]
                if record["start_uncertain"] and not record["entered"].is_set():
                    return False
                while worker.is_alive():
                    if worker is threading.current_thread():
                        return False
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return False
                    if self._cancelled.is_set():
                        self.cancel()  # Cover cancellation just before IO issue.
                    worker.join(min(.02, remaining))
                with self._lock:
                    handle = record["handle"]
                    close_outcome = record["close_outcome"]
                if handle is None:
                    if close_outcome is False:
                        return False
                    continue
                try:
                    if not _startup_thread_finished(handle, max(0.0, deadline - time.monotonic())):
                        return False
                    with self._lock:
                        # An interrupt/exception may follow a successful native
                        # close. Consume the numeric value before the call and
                        # latch unknown, so neither cancel nor retry reuses it.
                        record["handle"] = None
                        record["close_outcome"] = False
                        try:
                            record["close_outcome"] = _close_startup_thread(handle) is True
                        except BaseException:
                            pass
                        if not record["close_outcome"]:
                            return False
                except (OSError, AttributeError):
                    return False
            return True
        finally:
            self._join_lock.release()


def _startup_write(process, wire):
    process.stdin.write(wire)
    process.stdin.flush()


class UGCAPDaemonClient:
    def __init__(self, data_root, *, launch_factory=None, startup_timeout=10.0,
                 rotation_seconds=10.0, clock=time.monotonic):
        self.data_root = Path(data_root)
        self._launch = launch_factory or subprocess.Popen
        self._startup_timeout = max(1.0, min(float(startup_timeout), 30.0))
        self._rotation_seconds, self._clock = rotation_seconds, clock
        self._state_lock = threading.RLock()
        self._operation_lock = threading.Lock()
        self._process = self._job = self._pipe = self._startup_io = None
        self._retiring_startup = None
        self._closed = False
        self._reports = {}
        self._starts = 0
        self._startup_failure = None

    def _command(self):
        if getattr(sys, "frozen", False):
            return [sys.executable, "--ugcap-worker"]
        source = str(Path(__file__).resolve().parents[2])
        bootstrap = (f"import sys;sys.path.insert(0,{source!r});"
                     "from angerona.core.ugcap_worker import worker_main;raise SystemExit(worker_main())")
        return [sys.executable, "-I", "-c", bootstrap]

    def _detach(self):
        with self._state_lock:
            values = self._process, self._job, self._pipe, self._startup_io
            self._process = self._job = self._pipe = self._startup_io = None
            self._reports.clear()
            return values

    @staticmethod
    def _stop_owned(process, job, pipe, startup=None):
        # A separate cooperative cleanup grace does not extend or reset the
        # startup/application deadline. Native calls cannot be hard-preempted.
        deadline = time.monotonic() + 2.0
        auxiliary_retired = True
        if startup is not None:
            try:
                startup.cancel()
            except BaseException:
                auxiliary_retired = False
        if pipe is not None:
            try:
                pipe.close()
            except BaseException:
                auxiliary_retired = False
        if job is not None:
            job_retired = job.retire(max(0.0, deadline - time.monotonic()))
        else:
            # POSIX keeps its existing exact process-group cleanup. A Windows
            # child with no assigned job has never been resumed by this client.
            from angerona.resilience._selftest_environment import _stop_process_custody
            _stop_process_custody(process, None)
            job_retired = True
        if job is not None:
            # Job zero cannot prove an unassigned suspended launcher is gone.
            # This exact object still owns its native process handle.
            process_retired = job.retire_process(process, max(0.0, deadline - time.monotonic()))
        else:
            try:
                process_retired = process is None or process.poll() is not None
            except Exception:
                process_retired = False
        threads_retired = startup is None or startup.join(max(0.0, deadline - time.monotonic()))
        if not auxiliary_retired or not threads_retired or not process_retired or not job_retired:
            return False  # Retain handles/streams/buffers; refuse new work.
        if job is not None and not job.finalize(max(0.0, deadline - time.monotonic())):
            return False
        if process is not None:
            for stream in (process.stdin, process.stdout):
                try:
                    stream.close()
                except (OSError, ValueError):
                    pass
        return True

    def _retire_owned(self, values):
        if all(value is None for value in values):
            return True
        # Retain custody before callbacks, poll(), cancellation or native IO
        # cleanup can fail. An exception is unknown retirement, never success.
        with self._state_lock:
            self._retiring_startup = values
        try:
            retired = self._stop_owned(*values)
        except BaseException:
            retired = False
        with self._state_lock:
            if retired and self._retiring_startup == values:
                self._retiring_startup = None
        return retired

    def _ensure(self, deadline):
        started = time.monotonic()
        startup_deadline = min(deadline, started + self._startup_timeout)
        with self._state_lock:
            if self._closed:
                raise UGCAPWorkerUnavailable("UGCAP client is closed")
            retiring = self._retiring_startup
            if (self._process is not None and self._process.poll() is None
                    and self._pipe is not None and not self._pipe.snapshot()["closed"]
                    and self._pipe.endpoint.snapshot()["session_expires"] - self._clock() > 180):
                return self._pipe
        if retiring is not None and not self._retire_owned(retiring):
            raise UGCAPWorkerUnavailable("UGCAP startup cleanup is pending")
        if not self._retire_owned(self._detach()):
            raise UGCAPWorkerUnavailable("UGCAP startup cleanup is pending")
        process = job = channel = parent = startup = None
        stage = StartupStage.CUSTODY
        try:
            root = _custody(self.data_root)
            nonce = secrets.token_hex(16)
            from angerona.core.persistent_engine import _child_environment
            environment = _child_environment()
            environment["ANGERONA_DATA"] = str(root)
            kwargs = dict(stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          close_fds=True, env=environment)
            if os.name == "nt":
                kwargs["creationflags"] = (getattr(subprocess, "CREATE_NO_WINDOW", 0)
                                             | getattr(subprocess, "CREATE_SUSPENDED", 0x4))
            else:
                kwargs["start_new_session"] = True
            stage = StartupStage.LAUNCH
            process = self._launch(self._command(), **kwargs)
            if os.name == "nt":
                stage = StartupStage.JOB
                job = _create_worker_job()
                job.assign(process)
                if not job.capture_members(startup_deadline):
                    raise UGCAPWorkerUnavailable("UGCAP initial native job coverage is unavailable")
                from angerona.resilience._selftest_environment import _resume_windows_process
                stage = StartupStage.RESUME
                _resume_windows_process(process)
            startup = _StartupIO()
            with self._state_lock:
                if self._closed:
                    raise UGCAPWorkerUnavailable("UGCAP client is closed")
                self._process, self._job, self._startup_io = process, job, startup
            # Only nonsecret preparation metadata crosses this phase. It grants
            # no identity, attestation or operation authority; the mesh is still
            # required before any passphrase/request can be transmitted.
            stage = StartupStage.PREPARE
            prepare = canonical({"version": 1, "kind": "prepare", "data_root": str(root), "client_nonce": nonce}) + b"\n"
            startup.perform(lambda: _startup_write(process, prepare), startup_deadline)
            stage = StartupStage.PREPARED
            prepared = startup.perform(lambda: process.stdout.readline(128), startup_deadline)
            if prepared != _PREPARED:
                raise UGCAPWorkerUnavailable("UGCAP worker preparation was not acknowledged")
            if job is not None and not job.capture_members(startup_deadline):
                raise UGCAPWorkerUnavailable("UGCAP prepared native job coverage is unavailable")
            # Mint short-lived epochs only after child imports and root custody
            # have completed. Expired epochs remain strictly rejected.
            stage = StartupStage.MESH
            if time.monotonic() >= startup_deadline:
                raise TimeoutError("UGCAP startup deadline expired")
            parent, child = CrossProcessMeshChannel.create_pair(verified=True, rotation_seconds=self._rotation_seconds)
            bootstrap = {"version": 1, "mesh": child, "data_root": str(root), "client_nonce": nonce}
            wire = canonical(bootstrap) + b"\n"
            if len(wire) > _MAX_BOOTSTRAP:
                raise UGCAPWorkerUnavailable("UGCAP bootstrap exceeded its budget")
            stage = StartupStage.BOOTSTRAP
            startup.perform(lambda: _startup_write(process, wire), startup_deadline)
            bootstrap.clear()
            child.clear()
            with self._state_lock:
                if self._closed:
                    raise UGCAPWorkerUnavailable("UGCAP client is closed")
                channel = MeshPipe(parent, process.stdout, process.stdin, allowed_purposes={_REQUEST, _RESPONSE})
                self._process, self._job, self._pipe = process, job, channel
                self._startup_io = None
                self._starts += 1
            stage = StartupStage.READY
            remaining = startup_deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("UGCAP startup deadline expired")
            ready = decode_frame(channel.receive(_RESPONSE, timeout=remaining))
            if (set(ready) != {"version", "kind", "client_nonce", "session"}
                    or type(ready["version"]) is not int or ready["version"] != 1 or ready["kind"] != "ready"
                    or ready["client_nonce"] != nonce or ready["session"] != parent.session):
                raise UGCAPWorkerUnavailable("UGCAP worker did not establish the expected session")
            return channel
        except BaseException as exc:
            self._record_startup_failure(stage, exc, process, started)
            detached = self._detach()
            self._retire_owned(detached if detached[0] is process else (process, job, channel, startup))
            if channel is None and parent is not None:
                parent.close()
            if not isinstance(exc, Exception):
                raise
            raise UGCAPWorkerUnavailable("UGCAP worker startup could not establish its protected channel") from None

    def _record_startup_failure(self, stage, exc, process, started):
        # Fixed enums and numeric status only: never exception text, stderr,
        # paths, nonces, bootstrap certificates/private keys or passphrases.
        try:
            code = process.poll() if process is not None else None
        except Exception:
            code = None
        with self._state_lock:
            self._startup_failure = {"stage": stage.value, "reason": _startup_reason(exc).value,
                "elapsed_seconds": max(0.0, time.monotonic() - started),
                "child_exit_code": code if type(code) is int else None}

    @staticmethod
    def _accept_response(raw, request):
        response = decode_frame(raw)
        if (set(response) != {"version", "request_id", "nonce", "command", "ok", "result", "error"}
                or type(response["version"]) is not int or response["version"] != 1
                or response["request_id"] != request["request_id"] or response["nonce"] != request["nonce"]
                or response["command"] != request["command"] or type(response["ok"]) is not bool):
            raise UGCAPWorkerUnavailable("UGCAP response correlation failed")
        if response["ok"]:
            if not isinstance(response["result"], dict) or response["error"] is not None:
                raise UGCAPWorkerUnavailable("UGCAP response schema failed")
            return response["result"]
        if response["result"] is not None or response["error"] not in _ERRORS:
            raise UGCAPWorkerUnavailable("UGCAP error response schema failed")
        raise UGCAPWorkerError("UGCAP worker rejected operation: " + response["error"])

    def execute(self, command: str, payload: dict, *, secret: bytearray | None = None, timeout=150.0) -> dict:
        if type(timeout) not in {int, float} or not math.isfinite(timeout) or not .1 <= timeout <= 180:
            raise ValueError("UGCAP timeout must be between0.1 and180 seconds")
        borrowed = bytearray(secret) if isinstance(secret, bytearray) else None
        request = None
        deadline = time.monotonic() + timeout
        if not self._operation_lock.acquire(timeout=timeout):
            _wipe(borrowed)
            raise UGCAPWorkerUnavailable("UGCAP worker is busy")
        try:
            request = _request(command, payload, borrowed)
            channel = self._ensure(deadline)
            context = tuple(request["payload"].get(name, "") for name in ("repo_root", "vault_path", "key_name"))
            if command == "restore" and self._reports.get(request["payload"]["report_id"]) != context:
                raise UGCAPWorkerError("UGCAP worker rejected operation: stale_report")
            channel.send(_application(request), _REQUEST, timeout=max(.1, deadline - time.monotonic()))
            result = self._accept_response(channel.receive(_RESPONSE, timeout=max(.1, deadline - time.monotonic())), request)
            if command == "verify" and isinstance(result.get("report_id"), str):
                self._reports.clear()
                if result.get("status") == "drift":
                    self._reports[result["report_id"]] = context
            elif command in {"lock", "initialize", "provision", "restore"}:
                self._reports.clear()
            if command == "shutdown":
                process = self._process
                process.stdin.close()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
                self._retire_owned(self._detach())
            return result
        except UGCAPWorkerUnavailable:
            self._retire_owned(self._detach())
            raise
        except UGCAPWorkerError:
            raise
        except Exception:
            self._retire_owned(self._detach())
            raise UGCAPWorkerUnavailable("UGCAP worker transport or operation timed out or failed") from None
        finally:
            if request is not None:
                request["secret"] = None
                request.clear()
            _wipe(borrowed)
            self._operation_lock.release()

    def close(self):
        with self._state_lock:
            self._closed = True
        if self._operation_lock.acquire(blocking=False):
            try:
                with self._state_lock:
                    pipe, process = self._pipe, self._process
                if pipe is not None and process is not None and process.poll() is None:
                    try:
                        request = _request("shutdown", {})
                        pipe.send(_application(request), _REQUEST, timeout=1)
                        self._accept_response(pipe.receive(_RESPONSE, timeout=1), request)
                        process.stdin.close()
                        process.wait(timeout=2)
                    except Exception:
                        pass
            finally:
                self._operation_lock.release()
        self._retire_owned(self._detach())
        with self._state_lock:
            retiring = self._retiring_startup
        if retiring is not None:
            self._retire_owned(retiring)

    def snapshot(self):
        with self._state_lock:
            return {"running": self._process is not None and self._process.poll() is None,
                    "closed": self._closed, "starts": self._starts, "os_enclave": False,
                    "startup_failure": dict(self._startup_failure) if self._startup_failure else None,
                    "startup_cleanup_pending": self._retiring_startup is not None,
                    "channel": self._pipe.snapshot() if self._pipe is not None else None}


def serve(reader, writer, *, executor=None) -> int:
    """Subprocess server; injectable executor is a test seam, never a wire field."""
    pipe = None
    engine = executor or _VaultExecutor()
    try:
        raw = reader.readline(_MAX_BOOTSTRAP + 1)
        if len(raw) > _MAX_BOOTSTRAP or not raw.endswith(b"\n"):
            return 2
        preparation = decode_frame(raw)
        if (set(preparation) != {"version", "kind", "data_root", "client_nonce"}
                or type(preparation["version"]) is not int or preparation["version"] != 1
                or preparation["kind"] != "prepare" or not isinstance(preparation["client_nonce"], str)
                or not _TOKEN.fullmatch(preparation["client_nonce"])):
            return 2
        _custody(preparation["data_root"])
        writer.write(_PREPARED)
        writer.flush()
        raw = reader.readline(_MAX_BOOTSTRAP + 1)
        if len(raw) > _MAX_BOOTSTRAP or not raw.endswith(b"\n"):
            return 2
        initial = decode_frame(raw)
        if (set(initial) != {"version", "mesh", "data_root", "client_nonce"}
                or initial.get("data_root") != preparation["data_root"]
                or initial.get("client_nonce") != preparation["client_nonce"]
                or type(initial["version"]) is not int or initial["version"] != 1
                or not isinstance(initial["client_nonce"], str) or not _TOKEN.fullmatch(initial["client_nonce"])):
            return 2
        endpoint = CrossProcessMeshChannel.from_bootstrap(initial["mesh"], verified=True)
        pipe = MeshPipe(endpoint, reader, writer, allowed_purposes={_REQUEST, _RESPONSE})
        pipe.send(_application({"version": 1, "kind": "ready", "client_nonce": initial["client_nonce"],
                                "session": endpoint.session}), _RESPONSE)
        initial.clear()
        preparation.clear()
        raw = b""
        seen = OrderedDict()
        while True:
            request = None
            secret = None
            try:
                raw = pipe.receive(_REQUEST, timeout=3600)
                request = decode_frame(raw)
                clean, secret = _validate_request(request)
                identities = "request:" + request["request_id"], "nonce:" + request["nonce"]
                if any(identity in seen for identity in identities):
                    raise UGCAPWorkerError("invalid_request")
                for identity in identities:
                    seen[identity] = None
                while len(seen) > 1024:
                    seen.popitem(last=False)
                try:
                    execute = engine.execute if hasattr(engine, "execute") else engine
                    result = _compact(execute(request["command"], clean, secret))
                    response = _response(request, result=result)
                    try:
                        encoded = _application(response)
                    except (UGCAPWorkerError, MeshError):
                        encoded = _application(_response(request, error="response_too_large"))
                except Exception as exc:
                    encoded = _application(_response(request, error=_error_code(exc)))
                pipe.send(encoded, _RESPONSE)
                if request["command"] == "shutdown":
                    return 0
            finally:
                _wipe(secret)
                if request is not None:
                    request["secret"] = None
                    request.clear()
                raw = b""
    except Exception:
        return 2
    finally:
        if hasattr(engine, "close"):
            engine.close()
        if pipe is not None:
            pipe.close()


def worker_main() -> int:
    return serve(sys.stdin.buffer, sys.stdout.buffer)


if __name__ == "__main__":
    raise SystemExit(worker_main())
