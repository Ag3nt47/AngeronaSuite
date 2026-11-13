"""Core-owned local Red Team process and exact marker write capability.

This module never accepts a pathname, signing key or response proof from the
child. The Core engine creates each new marker and keeps publisher authority.
"""
from __future__ import annotations

import base64
from contextlib import suppress
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import secrets
import socket
import stat
import subprocess
import sys
import threading
import time

from angerona.core.privilege import sanitized_child_environment
from angerona.core.windows_child_job import OwnedWindowsChild, WindowsChildJob
from angerona.shark.red_team_ipc import (
    CORE_KINDS, MAX_ARTIFACT, MAX_FRAME, PRESENTATION_SECONDS, VERIFICATION_SECONDS, WHOLE_STARTUP_SECONDS,
    ToolChannel, ToolProtocolError, ToolStartupObservations, bootstrap, open_hello, send_descriptor,
)
from angerona.telemetry.process_snapshot_worker import (
    _Pin, _own_birth, _receive, _resume_owned_primary, _send,
)
from PySide6.QtCore import QObject, QTimer, Signal, Slot


_STARTUP_PHASES = frozenset({"created", "source-seal", "native-spawn", "job-assignment",
    "native-resume", "bootstrap-send", "hello-receive", "native-admission",
    "initialization", "await-ui-ready", "ready"})
_STARTUP_OPERATIONS = frozenset({"reader", "queue-read", "channel-send",
    "descriptor-send", "descriptor-close", "queue-task-done"})
_STARTUP_CONTEXTS = frozenset({"reader-error", "writer-error", "stop-requested", "prior-stop"})
_STARTUP_STOP_ORIGINS = frozenset({"writer-failure", "authenticated-tool-close", "suite-shutdown"})
_STARTUP_WRITER_ERRORS = frozenset({"Exception", "OSError", "BrokenPipeError",
    "ConnectionAbortedError", "ConnectionResetError", "EOFError", "PermissionError",
    "RuntimeError", "TimeoutError", "ToolProtocolError", "TypeError", "ValueError",
    "OverflowError", "BufferError", "KeyboardInterrupt", "SystemExit"})


def _plain_file(info):
    return (stat.S_ISREG(info.st_mode) and int(info.st_nlink) == 1
            and not getattr(info, "st_file_attributes", 0) & 0x400)


def _file_id(info):
    return int(info.st_dev), int(info.st_ino)


def _windows_read_pin(path, *, share):
    import ctypes
    import msvcrt
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                       ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
    create.restype = ctypes.c_void_p
    handle = create(str(path), 0x80000000, share, None, 3, 0x00200000, None)
    if handle in (None, ctypes.c_void_p(-1).value):
        raise OSError(ctypes.get_last_error(), "Exact marker read custody unavailable")
    try:
        return msvcrt.open_osfhandle(int(handle), os.O_RDONLY | os.O_BINARY)
    except BaseException:
        kernel.CloseHandle(ctypes.c_void_p(handle))
        raise


def duplicate_write_capability(descriptor, child):
    """Duplicate data-write + metadata-read only to the admitted child object."""
    import ctypes
    import msvcrt
    from angerona.core.windows_process_lease import _Native
    if os.name != "nt" or type(child) is not _Pin or not child.alive():
        raise ToolProtocolError("Admitted marker executor unavailable")
    native = _Native()
    target = native.open(child.pid, 0x101040, False)  # query, synchronize, DUP_HANDLE
    try:
        if native.object_identity(target) != child.identity or native.wait(target, 0):
            raise ToolProtocolError("Marker executor native generation changed")
        output = ctypes.c_void_p()
        duplicate = ctypes.WinDLL("kernel32", use_last_error=True).DuplicateHandle
        duplicate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                              ctypes.POINTER(ctypes.c_void_p), ctypes.c_uint32,
                              ctypes.c_int, ctypes.c_uint32]
        duplicate.restype = ctypes.c_int
        if not duplicate(ctypes.c_void_p(-1), ctypes.c_void_p(msvcrt.get_osfhandle(descriptor)),
                         ctypes.c_void_p(target), ctypes.byref(output), 0x40000000 | 0x80, False, 0):
            raise OSError(ctypes.get_last_error(), "Marker write capability duplication failed")
        if native.object_identity(target) != child.identity or native.wait(target, 0):
            # The duplicated capability belonged only to the now-exited child;
            # never guess/retry its numeric handle in another process generation.
            raise ToolProtocolError("Marker executor retired during capability transfer")
        return int(output.value)
    finally:
        native.close(target)


class ReservedMarkerWriter:
    """Consume a CREATE_NEW Core writeFD and return its verified read-only pin.

    A caller must set its local creation descriptor to None BEFORE handing it
    here. There is no descriptor ownership ambiguity on an exception. Failed
    partial files remain for review; no pathname deletion is attempted.
    """

    def __init__(self, owner):
        if type(owner) is not RedTeamToolOwner:
            raise ToolProtocolError("Exact marker owner required")
        self.owner = owner

    def complete_new_marker(self, creation_fd, path, payload):
        if type(creation_fd) is not int or creation_fd < 0 or type(payload) is not bytes or not 0 < len(payload) <= MAX_ARTIFACT:
            raise ToolProtocolError("Core marker creation capability unavailable")
        reservation = read_pin = None
        creation_owned = True
        remote_handoff = False
        try:
            initial = os.fstat(creation_fd)
            named = Path(path).lstat()
            if (not _plain_file(initial) or not _plain_file(named) or initial.st_size != 0
                    or _file_id(initial) != _file_id(named)):
                raise ToolProtocolError("Core marker reservation identity unavailable")
            if os.name == "nt":
                # Creation must request read/write only, without DELETE access.
                # Deny-delete reservation overlaps creation and final read pin.
                reservation = _windows_read_pin(path, share=0x1 | 0x2)
            else:
                reservation = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            if _file_id(os.fstat(reservation)) != _file_id(initial):
                raise ToolProtocolError("Marker reservation names a different object")
            reservation_id = secrets.token_hex(16)
            # Duplication can create remote custody before a later identity or
            # query-handle close fails. Treat that whole operation as uncertain
            # handoff until exact native retirement is proved.
            remote_handoff = True
            remote_handle = (duplicate_write_capability(creation_fd, self.owner._child)
                             if os.name == "nt" else None)
            # POSIX SCM_RIGHTS duplicates this live write description, without a
            # public socket or a writable pathname in the child command.
            request = self.owner.request_marker(reservation_id, remote_handle, payload,
                descriptor=creation_fd if os.name != "nt" else None)
            creation_owned = False
            os.close(creation_fd)
            ack = request.wait(5.0)
            if (type(ack) is not dict or set(ack) != {"reservation_id", "closed", "bytes_written"}
                    or ack["reservation_id"] != reservation_id or ack["closed"] is not True
                    or type(ack["bytes_written"]) is not int or ack["bytes_written"] != len(payload)):
                raise ToolProtocolError("Marker writer did not close its exact capability")
            read_pin = (_windows_read_pin(path, share=0x1) if os.name == "nt" else
                        os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)))
            before = os.fstat(read_pin)
            named = Path(path).lstat()
            if (not _plain_file(before) or not _plain_file(named) or _file_id(before) != _file_id(initial)
                    or _file_id(named) != _file_id(initial) or before.st_size != len(payload)):
                raise ToolProtocolError("Completed marker identity or byte count differs")
            os.lseek(read_pin, 0, os.SEEK_SET)
            actual = bytearray()
            while len(actual) <= len(payload):
                part = os.read(read_pin, min(65536, len(payload) + 1 - len(actual)))
                if not part:
                    break
                actual.extend(part)
            after = os.fstat(read_pin)
            if (bytes(actual) != payload or _file_id(after) != _file_id(before)
                    or (after.st_size, after.st_mtime_ns) != (before.st_size, before.st_mtime_ns)
                    or _file_id(Path(path).lstat()) != _file_id(initial)):
                raise ToolProtocolError("Completed marker bytes or held identity differ")
            os.lseek(read_pin, 0, os.SEEK_SET)
            # Retain the result until releasing the overlapping reservation
            # succeeds. A close error cannot hide an otherwise returned pin.
            reservation_fd, reservation = reservation, None
            os.close(reservation_fd)
            result, read_pin = read_pin, None
            return result
        except BaseException:
            if remote_handoff:
                # An unacknowledged duplicated write handle must not outlive
                # its reservation. Retire only this exact retained helper Job;
                # do not guess a possibly reused remote numeric handle.
                self.owner.abort_lifetime()
                if not self.owner.stop(5.0) and reservation is not None:
                    # Keep deny-delete custody until a later exact native
                    # retirement succeeds. Uncertainty cannot release the
                    # reservation while a child write capability may remain.
                    with self.owner._lock:
                        self.owner._marker_reservations.append(reservation)
                    reservation = None
            raise
        finally:
            if creation_owned:
                os.close(creation_fd)
            if read_pin is not None:
                os.close(read_pin)
            if reservation is not None:
                os.close(reservation)


class ToolRequest:
    def __init__(self):
        self.done = threading.Event()
        self.result = None
        self.failed = False

    def wait(self, timeout):
        if not self.done.wait(timeout) or self.failed:
            raise ToolProtocolError("Tool request did not complete in its original lifetime")
        return self.result


@dataclass(frozen=True)
class _ProbeRecord:
    probe_id: str
    token: str
    run_id: str
    plan_sha256: str
    plan_step_id: str
    prepared: object
    engine: object
    validation_lease: object
    pin: object
    identity: object


class ToolProbe:
    """Core-held identity of one independently executed fixed idle target."""
    def __init__(self, owner, record):
        self.owner, self.record = owner, record
        self.pid = record.identity.pid

    def poll(self):
        pin = self.record.pin
        if pin.closed:
            proof = pin.proof or {}
            return proof.get("exit_code", 1)
        if pin.alive():
            return None
        return pin.native.exit_code(pin.handle) if pin.native else pin.process.poll()

    def terminate(self):
        self.owner.retire_probe(self.record.probe_id)

    kill = terminate

    def wait(self, timeout=None):
        deadline = time.monotonic() + (3.0 if timeout is None else max(.001, timeout))
        while self.poll() is None:
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired("owned inert Red Team probe", timeout)
            time.sleep(.01)
        return self.poll()


class RedTeamToolOwner:
    """Explicit tool lifetime, never a watchdog-restarted component.

    Callbacks dispatch Core GUI work through queued Qt signals, not this reader.
    start(), stop() and marker execution belong to background owners only.
    """

    def __init__(self, receive, *, command=None, source_digest=None, initialize=None, native_diagnostic_hold=None):
        self.command = tuple(command or ([sys.executable, "--red-team-tool-worker"] if getattr(sys, "frozen", False)
            else [sys.executable, "-I", "-m", "angerona", "--red-team-tool-worker"]))
        self.receive = receive
        self.initialize = initialize
        self.source_digest = source_digest
        self._startup_attempt = secrets.token_hex(16)
        self._startup_diag_lock = threading.Lock()
        self._startup_failure = None
        self._startup_progress = ()
        self._startup_terminal = ""
        self._startup_terminal_record = None
        self._startup_stop_observed = False
        self._startup_stop_origin = "unknown"
        self._startup_source_seal_present = False
        self._startup_source_checked = False
        self._startup_receipt_queued = False
        self._startup_final_receipt_queued = False
        self._startup_exit_code = None
        started = time.monotonic_ns()
        if type(started) is not int or not 0 < started < (1 << 64) - int(WHOLE_STARTUP_SECONDS * 1e9):
            raise ToolProtocolError("Original startup monotonic clock is unavailable")
        self._startup_started_ns = self._startup_clock_ns = started
        self._bootstrap_deadline_ns = started + int(VERIFICATION_SECONDS * 1e9)
        self._whole_deadline_ns = started + int(WHOLE_STARTUP_SECONDS * 1e9)
        self._presentation_started_ns = None
        self._stderr_reader = None
        self._stderr_close_started = self._stderr_close_held = False
        self._startup_stderr = ToolStartupObservations()
        self._startup_stderr_error = ""
        self._startup_native_pins = []
        self._startup_native_rows = []
        self._startup_native_capture_attempted = False
        self._startup_native_capture_error = ""
        self._startup_native_capture_lock = threading.Lock()
        self._startup_native_close_held = False
        self._native_diagnostic_hold = native_diagnostic_hold if native_diagnostic_hold is not None else threading.Event()
        self._native_termination_dispatched = False
        self._pipe_close_started = set()
        self._pipe_close_held = False
        self._job = self._wrapper = self._child = self._process = self._native_owner = None
        self._key = self._binding = self._channel = None
        self._fd_socket = None
        self._queue = queue.Queue(maxsize=64)
        self._pending = {}
        self._lock = threading.RLock()
        self._retirement = threading.Lock()
        self._launch_complete = threading.Event()
        self._popen_closed = False
        self._popen_close_failed = False
        self._retirement_phase = "not-started"
        self._retirement_error = ""
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._ui_ready = threading.Event()
        self._retired = threading.Event()
        self._reader = self._writer = None
        self._error = ""
        self._close_ready = False
        self._proofs = []
        self._epoch = secrets.token_hex(16)
        self._probes = {}
        self._marker_reservations = []
        self._phase = "created"

    def _startup_observation(self, status, error_type="", *, operation="", message_kind="", context_code=""):
        """Publish the first bounded terminal in memory; no diagnostic I/O."""
        phase = self._phase
        with self._startup_diag_lock:
            if status == "progress":
                if len(self._startup_progress) < 16:
                    self._startup_progress += (phase,)
                return
            if status not in {"failed", "ready", "stopped"} or self._startup_terminal:
                return
            if status == "failed" and self._ui_ready.is_set():
                return
            safe_type = (error_type if type(error_type) is str
                and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,79}", error_type) else "Exception") if error_type else ""
            self._startup_terminal_record = dict(status=status,
                phase=phase if type(phase) is str and phase in _STARTUP_PHASES else "unknown",
                error_type=safe_type,
                operation=operation if type(operation) is str and operation in _STARTUP_OPERATIONS else "unknown",
                message_kind=message_kind if type(message_kind) is str and message_kind in CORE_KINDS else "unknown",
                context_code=context_code if type(context_code) is str and context_code in _STARTUP_CONTEXTS else "unknown")
            if status == "failed":
                self._startup_failure = dict(attempt=self._startup_attempt,
                    phase=phase, exception_type=safe_type)
            self._startup_terminal = status

    def _startup_stop_requested(self, origin="unknown"):
        """Retain first known request origin; it is not an inferred failure cause."""
        with self._startup_diag_lock:
            if not self._startup_stop_observed:
                self._startup_stop_observed = True
                self._startup_stop_origin = origin if type(origin) is str and origin in _STARTUP_STOP_ORIGINS else "unknown"
        if not self._ui_ready.is_set():
            self._startup_observation("stopped", context_code="stop-requested")

    def _observe_writer_failure(self, error, operation, message_kind):
        # Never retain the frame, payload, key or exception message. Unknown
        # exception class names are not accepted as diagnostic free text.
        error_type = type(error).__name__
        if error_type not in _STARTUP_WRITER_ERRORS:
            error_type = "Exception"
        self._startup_observation("failed", error_type, operation=operation,
            message_kind=message_kind, context_code="writer-error")

    def _startup_phase(self, phase):
        self._phase = phase
        self._startup_observation("progress")

    def startup_timeout_reason(self):
        """Original independent stage caps; child observations cannot renew them."""
        if self._ui_ready.is_set():
            return None
        with self._startup_diag_lock:
            try:
                now = time.monotonic_ns()
            except Exception:
                return "StartupClockUnavailable"
            if type(now) is not int or not self._startup_clock_ns <= now < 1 << 64:
                return "StartupClockUnavailable"
            self._startup_clock_ns = now
            if now >= self._whole_deadline_ns:
                return "StartupAttemptTimeout"
            if self._presentation_started_ns is None:
                return "BootstrapReadinessTimeout" if now >= self._bootstrap_deadline_ns else None
            return ("UiReadinessTimeout" if now - self._presentation_started_ns
                    >= int(PRESENTATION_SECONDS * 1e9) else None)

    def _assert_startup_current(self):
        reason = self.startup_timeout_reason()
        if reason is not None:
            self._startup_observation("failed", reason)
            raise ToolProtocolError("Original standalone startup deadline expired or is unavailable")
        if self._stop.is_set():
            raise ToolProtocolError("Standalone startup was cancelled")

    def _start_presentation_budget(self):
        self._assert_startup_current()
        with self._startup_diag_lock:
            now = time.monotonic_ns()
            if (type(now) is not int or not self._startup_clock_ns <= now < self._bootstrap_deadline_ns
                    or now >= self._whole_deadline_ns):
                raise ToolProtocolError("Verified startup admission missed its original deadline")
            self._startup_clock_ns = now
            self._presentation_started_ns = now

    def _read_startup_stderr(self):
        try:
            stream = self._process.stderr
            while True:
                raw = stream.read(1024)
                if not raw:
                    return
                elapsed = max(0, min(int(WHOLE_STARTUP_SECONDS * 1000),
                    (time.monotonic_ns() - self._startup_started_ns) // 1_000_000))
                if not self._startup_stderr.feed(raw, received_after_ms=elapsed):
                    self._error = "StartupDiagnosticOutputLimit"
                    self._startup_observation("failed", self._error)
                    self.abort_lifetime()
                    return
        except Exception as error:
            self._startup_stderr_error = type(error).__name__ if type(error) in {OSError, ValueError, RuntimeError} else "Exception"
            if not self._stop.is_set():
                self._error = "StartupDiagnosticReaderUnavailable"
                self._startup_observation("failed", self._error)
                self.abort_lifetime()

    def start(self):
        with self._lock:
            if self._reader is not None:
                return
            self._reader = threading.Thread(target=self._run, name="RedTeamToolIPC", daemon=False)
            self._reader.start()

    def request(self, kind, payload):
        if not self._ready.is_set() or self._stop.is_set():
            raise ToolProtocolError("Tool endpoint is not admitted")
        request = ToolRequest()
        self._queue.put((kind, payload, "", request, None), timeout=.25)
        return request

    def send(self, kind, payload, *, reply_to=""):
        if self._stop.is_set() or self._retired.is_set():
            return False
        try:
            self._queue.put_nowait((kind, payload, reply_to, None, None))
            return True
        except queue.Full:
            return False

    def request_marker(self, reservation_id, handle, payload, *, descriptor=None):
        if not self._ready.is_set() or self._stop.is_set() or self._retired.is_set():
            raise ToolProtocolError("Marker executor is not admitted")
        request = ToolRequest()
        data = dict(reservation_id=reservation_id, handle=handle,
                    content_b64=base64.b64encode(payload).decode("ascii"))
        copied = os.dup(descriptor) if descriptor is not None else None
        try:
            if copied is not None:
                os.set_inheritable(copied, False)
            self._queue.put(("write-marker", data, "", request, copied), timeout=.25)
        except BaseException:
            if copied is not None:
                os.close(copied)
            raise
        return request

    def _native_current(self):
        return bool(self._child is not None and self._child.alive() and self._wrapper is not None
                    and self._wrapper.alive() and (self._job is not None or os.name != "nt")
                    and not self._stop.is_set())

    def abort_lifetime(self):
        self._startup_stop_requested()
        self._stop.set()
        self._ready.clear()
        if self._native_owner is not None:
            try:
                self._terminate_owned_native(3.0)
            except (OSError, RuntimeError, ValueError):
                self._error = "NativeRetirementUnavailable"

    def _capture_startup_native_cut(self, operation_deadline):
        """Optional observations only; original native prepare already succeeded."""
        if self._startup_native_capture_attempted:
            return
        self._startup_native_capture_attempted = True
        if self._native_diagnostic_hold.is_set():
            self._startup_native_capture_error = "DiagnosticNativeCollectionHeld"
            return
        snapshot = getattr(self._native_owner, "tree_retirement_members_snapshot", None)
        if not callable(snapshot):
            self._startup_native_capture_error = "NativeDiagnosticMembersUnavailable"
            return
        view = snapshot()
        if not view.get("cut_recorded") or view.get("members") is None:
            self._startup_native_capture_error = "NativeDiagnosticCutUnavailable"
            return
        deadline = min(operation_deadline - .1, time.monotonic() + .25)
        if time.monotonic() >= deadline:
            self._startup_native_capture_error = "NativeDiagnosticBudgetGap"
            return
        from angerona.core.windows_process_lease import _Native
        native = _Native()
        for member in view["members"]:
            if time.monotonic() >= deadline or self._native_diagnostic_hold.is_set():
                self._startup_native_capture_error = "NativeDiagnosticBudgetGap"
                break
            row = dict(pid=member["pid"], birth_ticks=member["birth_ticks"],
                image=None, exit_code=None, handle_closed=False, early_exit_history_gap=True)
            self._startup_native_rows.append(row)
            pin = None
            try:
                pin = native.open(row["pid"], 0x101000, False)
                if native.object_identity(pin) != (row["pid"], int(row["birth_ticks"])):
                    raise ToolProtocolError("Diagnostic native generation changed")
                if not native.wait(pin, 0) and time.monotonic() < deadline:
                    identity = native.identity(pin)
                    if (identity.pid, identity.birth_ticks) != (row["pid"], int(row["birth_ticks"])):
                        raise ToolProtocolError("Diagnostic native image generation changed")
                    row["image"] = identity.image
                self._startup_native_pins.append((native, pin, row))
                pin = None
            except (OSError, RuntimeError, ValueError) as error:
                row["error_type"] = type(error).__name__
                self._startup_native_capture_error = "NativeDiagnosticPinUnavailable"
            finally:
                if pin is not None:
                    try:
                        native.close(pin)
                        row["handle_closed"] = True
                    except Exception:
                        self._startup_native_close_held = True
                        self._native_diagnostic_hold.set()

    def _terminate_owned_native(self, timeout):
        operation_deadline = time.monotonic() + timeout
        if not self._startup_native_capture_lock.acquire(timeout=max(.001, timeout)):
            raise ToolProtocolError("Native startup retirement observation is busy")
        try:
            if self._native_termination_dispatched:
                return
            # Mandatory native custody errors retain the existing hold. No
            # optional observation may turn a valid owned stop into a blocker.
            remaining = operation_deadline - time.monotonic()
            if remaining <= 0:
                raise ToolProtocolError("Original native startup retirement budget expired")
            self._native_owner.prepare_tree_retirement(timeout=min(3.0, remaining))
            try:
                self._capture_startup_native_cut(operation_deadline)
            except Exception:
                self._startup_native_capture_error = "NativeDiagnosticCaptureUnavailable"
            self._native_owner.terminate()
            self._native_termination_dispatched = True
        finally:
            self._startup_native_capture_lock.release()

    def _close_startup_native_pins(self):
        if not self._startup_native_pins:
            return
        while self._startup_native_pins:
            native, pin, row = self._startup_native_pins.pop(0)
            try:
                row["identity_unchanged"] = native.object_identity(pin) == (row["pid"], int(row["birth_ticks"]))
                row["signaled"] = native.wait(pin, 0)
                if row["identity_unchanged"] and row["signaled"]:
                    row["exit_code"] = native.exit_code(pin)
                else:
                    row["error_type"] = "NativeDiagnosticSignalUnavailable"
            except Exception:
                row["error_type"] = "NativeDiagnosticExitUnavailable"
            finally:
                try:
                    native.close(pin)
                    row["handle_closed"] = True
                except Exception:
                    self._startup_native_close_held = True
                    self._native_diagnostic_hold.set()

    def _admit_child(self, binding):
        import psutil
        child = self._wrapper if binding.child_pid == self._wrapper.pid else _Pin(binding.child_pid)
        try:
            observed = psutil.Process(child.pid)
            allowed = {os.path.normcase(os.path.realpath(self.command[0])),
                os.path.normcase(os.path.realpath(getattr(sys, "_base_executable", sys.executable)))}
            if (child.birth != binding.child_birth or not child.alive()
                    or child is not self._wrapper and observed.ppid() != self._wrapper.pid
                    or observed.cmdline()[1:] != list(self.command[1:])
                    or os.path.normcase(os.path.realpath(observed.exe())) not in allowed):
                raise ToolProtocolError("Tool actual child native invocation differs")
            if self._job is not None:
                from angerona.core.windows_process_lease import _Native
                if not self._native_owner.contains_native_process(_Native().identity(child.handle)):
                    raise ToolProtocolError("Tool actual child did not inherit its retained Job")
        except BaseException:
            if child is not self._wrapper:
                child.release_unadmitted()
            raise
        self._child = child

    def _run(self):
        child_socket = None
        try:
            if self._stop.is_set():
                return
            self._startup_phase("source-seal")
            self._assert_startup_current()
            environment = sanitized_child_environment()
            if not getattr(sys, "frozen", False):
                from angerona.resilience.source_guard import SourceGuard
                expected = self.source_digest or environment.get("ANGERONA_PEER_SOURCE_DIGEST")
                self._startup_source_seal_present = type(expected) is str and bool(expected)
                if type(expected) is not str or re.fullmatch(r"[0-9a-f]{64}", expected) is None:
                    raise ToolProtocolError("The existing Core source seal is required")
                SourceGuard.capture(Path(__file__).absolute().parents[3], expected_digest=expected,
                    deadline=self._bootstrap_deadline_ns / 1_000_000_000,
                    check_cancelled=self._stop.is_set)
                self._startup_source_checked = True
                environment["ANGERONA_PEER_SOURCE_DIGEST"] = expected
            if self._stop.is_set():
                return
            self._assert_startup_current()
            self._startup_phase("native-spawn")
            self._job = WindowsChildJob(kill_on_close=True) if os.name == "nt" else None
            if self._stop.is_set():
                return
            inherited = ()
            if os.name != "nt":
                self._fd_socket, child_socket = socket.socketpair()
                child_socket.set_inheritable(True)
                inherited = (child_socket.fileno(),)
            options = dict(stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                bufsize=0, close_fds=True, env=environment,
                creationflags=(subprocess.CREATE_NO_WINDOW | 0x4) if os.name == "nt" else 0)
            if inherited:
                options["pass_fds"] = inherited
                options["start_new_session"] = True
            self._process = subprocess.Popen(self.command, **options)
            self._wrapper = _Pin(self._process.pid, process=self._process)
            self._startup_phase("job-assignment")
            if self._job is not None:
                self._job.assign(int(self._process._handle))
                import win32api
                import win32con
                # Popen, native owner and query pins own distinct handles.
                # Closing one owner can never double-close a reused handle.
                duplicate = win32api.DuplicateHandle(win32api.GetCurrentProcess(), int(self._process._handle),
                    win32api.GetCurrentProcess(), 0, False, win32con.DUPLICATE_SAME_ACCESS)
                self._native_owner = OwnedWindowsChild(duplicate, self._process.pid, self._job)
            self._stderr_reader = threading.Thread(target=self._read_startup_stderr,
                name="RedTeamToolStartupDiagnostics", daemon=False)
            try:
                self._stderr_reader.start()
            except BaseException:
                if self._stderr_reader.ident is None and not self._stderr_reader.is_alive():
                    self._stderr_reader = None
                raise
            if os.name == "nt":
                self._startup_phase("native-resume")
                _resume_owned_primary(self._wrapper)
            self._key = secrets.token_bytes(32)
            initial = bootstrap(self._key, secrets.token_hex(16), os.getpid(), _own_birth(),
                self._wrapper.pid, self._wrapper.birth, startup_deadline_ns=self._bootstrap_deadline_ns,
                fd_channel=child_socket.fileno() if child_socket else None)
            self._startup_phase("bootstrap-send")
            _send(self._process.stdin, initial, 4096)
            if child_socket:
                child_socket.close()
                child_socket = None
            expected = {name: initial[name] for name in ("session", "parent_pid", "parent_birth", "wrapper_pid", "wrapper_birth")}
            self._startup_phase("hello-receive")
            self._binding = open_hello(_receive(self._process.stdout, 4096), self._key, expected)
            self._assert_startup_current()
            self._startup_phase("native-admission")
            self._admit_child(self._binding)
            self._assert_startup_current()
            self._channel = ToolChannel(self._process.stdout, self._process.stdin, self._binding,
                self._key, side="core", alive=self._native_current)
            # Initialization is the first authenticated Core frame, even when
            # show/status requests were queued while native admission ran.
            if self.initialize is None:
                raise ToolProtocolError("Core initialization is required")
            self._startup_phase("initialization")
            self._channel.send("initialize", self.initialize)
            self._start_presentation_budget()
            self._writer = threading.Thread(target=self._write_loop, name="RedTeamToolWriter", daemon=False)
            self._writer.start()
            self._ready.set()
            self._launch_complete.set()
            self._startup_phase("await-ui-ready")
            self.receive("tool-ready", {"child_pid": self._child.pid, "child_birth": self._child.birth}, "")
            while not self._stop.is_set():
                body = self._channel.receive()
                if body["reply_to"]:
                    with self._lock:
                        request = self._pending.pop(body["reply_to"], None)
                    if request is None or body["kind"] not in {"reply", "marker-written", "probe-started", "probe-ended"}:
                        raise ToolProtocolError("Unexpected tool reply")
                    request.result = body["payload"]
                    request.done.set()
                else:
                    if body["kind"] == "ui-ready":
                        payload = body["payload"]
                        if (set(payload) != {"window_title"} or type(payload["window_title"]) is not str
                                or not 1 <= len(payload["window_title"]) <= 200):
                            raise ToolProtocolError("Tool presentation readiness schema unavailable")
                        self._assert_startup_current()
                        self._ui_ready.set()
                        self._phase = "ready"
                        self._startup_observation("ready")
                    self.receive(body["kind"], body["payload"], body["nonce"])
        except BaseException as error:
            self._error = type(error).__name__
            if not self._ui_ready.is_set():
                if self._stop.is_set():
                    self._startup_stop_requested()
                else:
                    self._startup_observation("failed", self._error,
                        operation="reader", context_code="reader-error")
                if self._process is not None:
                    with suppress(OSError):
                        self._startup_exit_code = self._process.poll()
        finally:
            self._launch_complete.set()
            self._startup_stop_requested()
            self._stop.set()
            self._ready.clear()
            with self._lock:
                for request in self._pending.values():
                    request.failed = True
                    request.done.set()
                self._pending.clear()
            while True:
                try:
                    _kind, _payload, _reply_to, request, descriptor = self._queue.get_nowait()
                except queue.Empty:
                    break
                if request is not None:
                    request.failed = True
                    request.done.set()
                if descriptor is not None:
                    os.close(descriptor)
                self._queue.task_done()
            if child_socket:
                child_socket.close()
            # Native lifetime is retained until explicit stop() proves every
            # descendant exit. A failed reader never self-deletes its owner.

    def _write_loop(self):
        operation, message_kind = "queue-read", "unknown"
        try:
            while not self._stop.is_set():
                operation, message_kind = "queue-read", "unknown"
                try:
                    kind, payload, reply_to, request, descriptor = self._queue.get(timeout=.1)
                except queue.Empty:
                    continue
                message_kind = kind if type(kind) is str and kind in CORE_KINDS else "unknown"
                try:
                    # Serialize pending admission with the reader's lookup so
                    # a fast child reply cannot outrun request registration.
                    operation = "channel-send"
                    with self._lock:
                        nonce = self._channel.send(kind, payload, reply_to=reply_to)
                        if request is not None:
                            self._pending[nonce] = request
                    if descriptor is not None:
                        operation = "descriptor-send"
                        send_descriptor(self._fd_socket, descriptor, payload["reservation_id"])
                except BaseException as error:
                    # Preserve the first typed send failure even if later
                    # owned cleanup itself reports another error.
                    self._observe_writer_failure(error, operation, message_kind)
                    raise
                finally:
                    if descriptor is not None:
                        operation = "descriptor-close"
                        os.close(descriptor)
                    operation = "queue-task-done"
                    self._queue.task_done()
        except BaseException as error:
            self._error = type(error).__name__
            self._observe_writer_failure(error, operation, message_kind)
            self._startup_stop_requested("writer-failure")
            self._stop.set()

    def lifecycle_snapshot(self):
        return dict(ready=self._ready.is_set(), ui_ready=self._ui_ready.is_set(),
            stopped=self._stop.is_set(), retired=self._retired.is_set(),
            error=self._error, phase=self._phase, epoch=self._epoch,
            retirement_phase=self._retirement_phase, retirement_error=self._retirement_error,
            startup_failure=dict(self._startup_failure) if self._startup_failure else None,
            startup_attempt=self._startup_attempt, startup_terminal=self._startup_terminal,
            startup_terminal_record=dict(self._startup_terminal_record) if self._startup_terminal_record else None,
            startup_stop_origin=self._startup_stop_origin,
            startup_stop_origin_known=self._startup_stop_origin != "unknown",
            startup_progress=self._startup_progress,
            startup_source_seal_present=self._startup_source_seal_present,
            startup_source_checked=self._startup_source_checked,
            startup_exit_code=self._startup_exit_code,
            startup_child_diagnostics=self._startup_stderr.snapshot(),
            startup_stderr_error=self._startup_stderr_error,
            startup_native_capture_error=self._startup_native_capture_error,
            startup_native_members=tuple(dict(row) for row in self._startup_native_rows),
            startup_native_cut_attempted=self._startup_native_capture_attempted,
            startup_native_diagnostic_close_gap=self._native_diagnostic_hold.is_set(),
            child_pid=self._child.pid if self._child else None,
            child_birth=self._child.birth if self._child else None,
            workers_retired=all(thread is None or not thread.is_alive()
                for thread in (self._reader, self._writer, self._stderr_reader)),
            retirement_proofs=tuple(dict(row) for row in self._proofs))

    def capture_scope(self, *, timeout=1.0):
        if not self._lock.acquire(timeout=timeout):
            raise ToolProtocolError("Tool ownership admission unavailable")
        try:
            if self._retired.is_set():
                return self, self._epoch, "retired"
            if (not self._ready.is_set() or self._stop.is_set()
                    or type(self._native_owner) is not OwnedWindowsChild
                    or type(self._job) is not WindowsChildJob or self._job._handle is None
                    or self._native_owner._job is not self._job
                    or self._native_owner._process is None
                    or type(self._child) is not _Pin or type(self._wrapper) is not _Pin
                    or self._native_owner.pid != self._wrapper.pid
                    or any(pin.closed or pin.close_failed or pin.handle is None
                           for pin in (self._child, self._wrapper))):
                raise ToolProtocolError("Configured tool native custody unavailable")
            return (self, self._epoch, self._native_owner, self._child, self._wrapper,
                self._job, id(self._job._handle), self._job._handle,
                id(self._child.handle), self._child.handle,
                id(self._wrapper.handle), self._wrapper.handle,
                id(self._native_owner._process), self._native_owner._process)
        finally:
            self._lock.release()

    def start_probe(self, engine, token):
        """Only the exact Core engine owner may admit the fixed child target."""
        from angerona.shark.red_team import RedTeamEngine
        from angerona.modules.purple_guard import RedTeamValidationLease, _lease_authority
        from angerona.core.windows_process_lease import _Native
        from angerona.shark.simulation_session import PreparedRun, validate_prepared_run
        if (type(engine) is not RedTeamEngine or engine._thread is not threading.current_thread()
                or type(token) is not str or re.fullmatch(r"ANGERONA_REDTEAM_[0-9a-f]{8}", token) is None
                or not self._native_current() or os.name != "nt"):
            raise ToolProtocolError("Exact independent probe execution is unavailable")
        prepared, lease = engine._prepared_run, engine._validation_lease
        active = engine._active_plan_entry
        if (type(prepared) is not PreparedRun or not validate_prepared_run(prepared, kind="red_team")
                or type(lease) is not RedTeamValidationLease or type(active) is not dict
                or active.get("key") != "random_processes" or prepared.run_id != engine.run_id
                or not active.get("plan_step_id") or active not in engine._expected_plan):
            raise ToolProtocolError("Probe does not belong to the current prepared plan")
        state = _lease_authority(lease)
        with state.lock:
            challenge = (state.process_challenges or {}).get(token)
            if (state.released or not state.consumed or state.bound_run_id != engine.run_id
                    or type(challenge) is not dict or challenge.get("state") != "enrolled"):
                raise ToolProtocolError("Probe token has no current issuer enrollment")
        RedTeamValidationLease.assert_live_producers(lease, run_id=engine.run_id)
        manager = state.manager
        from angerona.core.werfault_guard import MAX_OWNED_PROCESSES, read_owned_process_snapshot
        roster = read_owned_process_snapshot(manager.owned_process_identities,
            not_before=time.monotonic(), clock=time.monotonic)
        if len(roster.rows) + 2 > MAX_OWNED_PROCESSES:
            raise ToolProtocolError("Owned process capacity is busy; this individual probe is unavailable")
        probe_id = secrets.token_hex(16)
        reply = self.request("start-probe", {"probe_id": probe_id, "token": token}).wait(5)
        if (type(reply) is not dict or set(reply) != {"probe_id", "pid", "birth"}
                or reply["probe_id"] != probe_id or type(reply["pid"]) is not int):
            raise ToolProtocolError("Independent probe response schema unavailable")
        pin = None
        admitted = False
        try:
            import psutil
            pin = _Pin(reply["pid"])
            if pin.pid in {os.getpid(), self._wrapper.pid, self._child.pid} or pin.birth != reply["birth"]:
                raise ToolProtocolError("Independent probe is a protected root or different generation")
            process = psutil.Process(pin.pid)
            expected = ([str(Path(sys.executable).resolve()), "--red-team-inert-probe", token]
                if getattr(sys, "frozen", False) else
                [str(Path(getattr(sys, "_base_executable", sys.executable)).resolve(strict=True)),
                 "-I", "-S", "-c", "import time; time.sleep(30)", token])
            if (process.ppid() != self._child.pid or process.cmdline() != expected
                    or os.path.normcase(process.exe()) != os.path.normcase(expected[0])):
                raise ToolProtocolError("Independent probe native parent/image/fixed invocation differs")
            native = _Native()
            identity = native.identity(pin.handle)
            if not self._native_owner.contains_native_process(identity):
                raise ToolProtocolError("Independent probe is not an actual retained Job member")
            record = _ProbeRecord(probe_id, token, engine.run_id, prepared.plan_sha256,
                str(active.get("plan_step_id")), prepared, engine, lease, pin, identity)
            with self._lock:
                if not self._native_current() or any(not item.pin.closed and item.pin.alive() for item in self._probes.values()):
                    raise ToolProtocolError("Only one live admitted probe is allowed")
                self._probes[probe_id] = record
                admitted = True
            pin = None
            return ToolProbe(self, record)
        finally:
            if pin is not None:
                pin.release_unadmitted()
            if not admitted:
                # Retire by the Core-created capability ID in the child-owned
                # Popen registry, never by an unadmitted returned PID.
                try:
                    self.request("retire-probe", {"probe_id": probe_id}).wait(3)
                except (OSError, RuntimeError, ValueError, queue.Full):
                    self.abort_lifetime()

    def validate_probe_identity(self, identity, *, token, run_id, lease, plan_sha256=None):
        """Read-only Core registry check; child claims cannot create a row."""
        from angerona.shark.red_team import RedTeamEngine
        from angerona.modules.purple_guard import RedTeamValidationLease, _lease_authority
        from angerona.core.windows_process_lease import ProcessObjectIdentity
        if (type(identity) is not ProcessObjectIdentity or not self._native_current()
                or identity.pid in {os.getpid(), self._wrapper.pid, self._child.pid}):
            return False
        with self._lock:
            records = tuple(self._probes.values())
        for record in records:
            if type(record) is not _ProbeRecord:
                return False
            engine = record.engine
            active = getattr(engine, "_active_plan_entry", None)
            if (type(engine) is not RedTeamEngine
                    or record.identity != identity or record.token != token
                    or record.run_id != run_id or record.validation_lease is not lease
                    or engine._prepared_run is not record.prepared or engine._validation_lease is not lease
                    or engine.run_id != run_id or engine._cancel.is_set()
                    or type(active) is not dict or active.get("key") != "random_processes"
                    or active.get("plan_step_id") != record.plan_step_id
                    or active not in engine._expected_plan
                    or record.prepared.plan_sha256 != record.plan_sha256
                    or plan_sha256 is not None and plan_sha256 != record.plan_sha256
                    or record.pin.closed or not record.pin.alive() or not self._native_current()):
                continue
            try:
                import psutil
                state = _lease_authority(lease)
                with state.lock:
                    challenge = (state.process_challenges or {}).get(token)
                    if (state.released or not state.consumed or state.bound_run_id != run_id
                            or type(challenge) is not dict or challenge.get("state") != "bound"
                            or challenge.get("pid") != identity.pid):
                        return False
                RedTeamValidationLease.assert_live_producers(lease, run_id=run_id)
                process = psutil.Process(identity.pid)
                expected = ([str(Path(sys.executable).resolve()), "--red-team-inert-probe", token]
                    if getattr(sys, "frozen", False) else
                    [str(Path(getattr(sys, "_base_executable", sys.executable)).resolve(strict=True)),
                     "-I", "-S", "-c", "import time; time.sleep(30)", token])
                return (process.ppid() == self._child.pid and process.cmdline() == expected
                    and os.path.normcase(process.exe()) == os.path.normcase(expected[0])
                    and record.pin.alive() and self._native_current()
                    and self._native_owner.contains_native_process(identity) is True)
            except (OSError, RuntimeError, ValueError):
                return False
        return False

    def retire_probe(self, probe_id):
        with self._lock:
            record = self._probes.get(probe_id)
        if record is None:
            raise ToolProtocolError("Probe is not in the Core admission registry")
        if not record.pin.closed and record.pin.alive():
            # This is exact cleanup of our admitted inert child, not a host
            # response or containment receipt. Do not assign catch credit.
            self.request("retire-probe", {"probe_id": probe_id}).wait(3)
        if not record.pin.retire(3, terminate=False):
            raise ToolProtocolError("Exact inert probe retirement is unavailable")
        with self._lock:
            if record.pin.closed and self._probes.get(probe_id) is record:
                self._probes.pop(probe_id)
        return True

    def observe_owned_process_identities(self, *, timeout=1.0):
        if not self._ready.is_set() or self._stop.is_set() or self._native_owner is None:
            raise ToolProtocolError("Complete tool native ownership is unavailable")
        return self._native_owner.observe_owned_process_identities(role="redteam-tool", timeout=timeout)

    def stop(self, timeout=3):
        """Only this explicit admitted tool/Job. Never stop or relaunch Core."""
        self._startup_stop_requested()
        self._stop.set()
        self._ready.clear()
        if not self._retirement.acquire(timeout=timeout):
            return False
        try:
            if self._retired.is_set():
                return True
            if self._popen_close_failed:
                return False
            deadline = time.monotonic() + timeout
            if self._reader is not None and not self._launch_complete.is_set():
                # Startup can be waiting for hello. Kill only the newly owned
                # retained Job/Popen objects, then let its owner finish binding
                # or failing before any lifetime fields are closed.
                if self._native_owner is not None:
                    self._terminate_owned_native(max(.001, deadline - time.monotonic()))
                elif self._job is not None:
                    self._job.terminate()
                if self._native_owner is None and self._process is not None and self._process.poll() is None:
                    self._process.terminate()
                if not self._launch_complete.wait(max(0, deadline - time.monotonic())):
                    return False
            return self._stop_native_lifetime(max(.001, deadline - time.monotonic()))
        except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired):
            return False
        finally:
            self._retirement.release()

    def _stop_native_lifetime(self, timeout):
        deadline = time.monotonic() + timeout
        try:
            if self._native_owner is not None:
                self._retirement_phase = "tree-capture"
                # The wrapper may already have exited while an associated
                # process survives. The retained Job's retirement transition
                # remains required even when all members exited naturally.
                self._retirement_phase = "tree-terminate"
                self._terminate_owned_native(timeout)
            self._retirement_phase = "probe-retire"
            for record in tuple(self._probes.values()):
                if not record.pin.retire(max(.001, deadline - time.monotonic()), terminate=False):
                    return False
            for pin in (self._child, self._wrapper):
                self._retirement_phase = "native-pin-retire"
                if pin is None or pin.closed:
                    continue
                if not pin.retire(max(.001, deadline - time.monotonic()), terminate=True):
                    return False
                self._proofs.append(dict(pin.proof))
            if self._process is not None:
                self._process.wait(timeout=max(.001, deadline - time.monotonic()))
                if os.name == "nt" and not self._popen_closed:
                    try:
                        self._process._handle.Close()
                    except OSError:
                        self._popen_close_failed = True
                        return False
                    self._popen_closed = True
            if self._native_owner is not None:
                self._retirement_phase = "tree-wait"
                self._native_owner.wait_tree(timeout=max(.001, deadline - time.monotonic()))
            for thread in (self._writer, self._reader, self._stderr_reader):
                self._retirement_phase = "worker-retire"
                if thread is not None and thread is not threading.current_thread():
                    if thread.ident is None and not thread.is_alive():
                        continue
                    thread.join(max(0, deadline - time.monotonic()))
                    if thread.is_alive():
                        return False
            if self._process is not None:
                self._retirement_phase = "pipe-close"
                if self._pipe_close_held:
                    return False
                for name in ("stdin", "stdout", "stderr"):
                    stream = getattr(self._process, name, None)
                    if stream is not None and name not in self._pipe_close_started:
                        self._pipe_close_started.add(name)
                        try:
                            stream.close()
                        except (OSError, ValueError):
                            self._pipe_close_held = True
                            return False
            self._close_startup_native_pins()
            if self._native_owner is not None:
                self._retirement_phase = "tree-close"
                self._native_owner.close()
            elif self._job is not None:
                self._job.wait_empty(timeout=max(.001, deadline - time.monotonic()))
                self._job.close()
            if self._fd_socket:
                self._fd_socket.close()
            with self._lock:
                for descriptor in self._marker_reservations:
                    os.close(descriptor)
                self._marker_reservations.clear()
            self._retired.set()
            self._retirement_phase = "retired"
            self._retirement_error = ""
            return True
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            self._retirement_error = type(error).__name__
            return False


class _LaunchButton:
    def __init__(self, bridge):
        self.bridge = bridge
    def setEnabled(self, value):  # noqa: N802 - Qt compatibility facade
        self.bridge._display("button-enabled", [value is True])


class RedTeamBridge(QObject):
    """Small Core view facade; all real widgets are in the separate tool."""
    _incoming = Signal(object, str, object, str)
    _task_finished = Signal(object, object)

    def __init__(self, parent, default_target=None):
        super().__init__(parent)
        self.parent_view = parent
        self.default_target = str(default_target or (parent.config.data_dir / "drill-sandbox"))
        self.owner = None
        self.marker_writer = None
        self.launch_btn = _LaunchButton(self)
        self._pending_flag = self._cancelled_flag = False
        self._closing = False
        self._native_diagnostic_hold = threading.Event()
        self._starting_at = 0.0
        self._task_lock = threading.Lock()
        self._tasks = []
        self._stop_thread = None
        self._reports = set()
        self._initial_displays = []
        self._failure_cancelled = False
        from angerona.core.startup_diagnostics import StartupDiagnostics
        self._startup_recorder = StartupDiagnostics(Path(parent.config.data_dir))
        self._startup_receipts = queue.Queue(maxsize=8)
        self._startup_diag_worker = None
        self._startup_last_receipt = None
        self._startup_write_states = {}
        self._startup_write_lock = threading.Lock()
        self._startup_receipt_gap = False
        self._startup_notice = None
        self._incoming.connect(self._handle_incoming)
        self._task_finished.connect(self._deliver_task)
        self._timer = QTimer(self)
        self._timer.setInterval(200)
        self._timer.timeout.connect(self._poll_close)
        parent._shark_narration.connect(self._narration)

    @property
    def _run_pending(self):
        return self._pending_flag

    @_run_pending.setter
    def _run_pending(self, value):
        self._pending_flag = value is True
        self._display("flag", ["run-pending", self._pending_flag])

    @property
    def _run_cancelled(self):
        return self._cancelled_flag

    @_run_cancelled.setter
    def _run_cancelled(self, value):
        self._cancelled_flag = value is True
        self._display("flag", ["run-cancelled", self._cancelled_flag])

    def _start(self):
        if getattr(self.parent_view, "_termination_started", False):
            return
        if self.owner is not None and not self.owner._retired.is_set():
            return
        if self.owner is not None and not self.custody_released():
            self._timer.start()
            return
        self._closing = False
        self._failure_cancelled = False
        self._starting_at = time.monotonic()
        from angerona import __version__ as suite_version
        initial = dict(data_dir=str(self.parent_view.config.data_dir), default_target=self.default_target,
            stylesheet=self.parent_view._qss(), version=suite_version)
        owner = RedTeamToolOwner(lambda kind, payload, nonce:
            self._incoming.emit((owner, owner._epoch), kind, payload, nonce), initialize=initial,
            native_diagnostic_hold=self._native_diagnostic_hold)
        self.owner = owner
        self.marker_writer = ReservedMarkerWriter(self.owner)
        # Exact engine references remain in Core. They receive only the fixed
        # marker writer and cannot accept an arbitrary child-provided command.
        self.parent_view.red_team_engine._independent_executor = self.owner
        self.parent_view.red_team_engine._marker_writer = self.marker_writer
        self.parent_view.shark_engine._marker_writer = self.marker_writer
        for payload in self._initial_displays:
            self.owner.send("display", payload)
        self._initial_displays.clear()
        self.owner.start()
        self._timer.start()

    def _queue_startup_receipt(self, owner, state):
        if not state.get("startup_terminal") or owner._startup_receipt_queued:
            return
        owner._startup_receipt_queued = True
        failure = state.get("startup_failure") or {}
        terminal = state.get("startup_terminal_record") or {}
        fields = dict(attempt=state["startup_attempt"], strategy=terminal.get("phase", failure.get("phase", state["phase"])),
            receipt_kind="startup",
            exception_type=failure.get("exception_type", ""), pid=os.getpid(),
            process_role="core-red-team-tool", actual=list(state["startup_progress"]),
            expected=["existing Core source seal", "owned native handshake", "independent Qt presentation"],
            reason=("Standalone tool startup failed; review the fixed phase and error type."
                    if state["startup_terminal"] == "failed" else
                    "Standalone tool presentation became ready." if state["startup_terminal"] == "ready" else
                    "Standalone startup stopped before presentation; request origin is recorded without a cause inference."),
            coverage=(f"source_seal_present={state['startup_source_seal_present']};"
                f"source_checked={state['startup_source_checked']};"
                "Phase observations grant no detection/report/response authority; no frame or key data captured."))
        fields["startup_terminal_record"] = state.get("startup_terminal_record")
        fields["startup_stop_origin"] = state.get("startup_stop_origin", "unknown")
        fields["startup_stop_origin_known"] = state.get("startup_stop_origin_known", False)
        fields["child_diagnostics"] = state.get("startup_child_diagnostics", {})
        fields["startup_budgets_seconds"] = dict(verification=VERIFICATION_SECONDS,
            presentation=PRESENTATION_SECONDS, whole=WHOLE_STARTUP_SECONDS)
        if type(state.get("startup_exit_code")) is int:
            fields["exit_code"] = state["startup_exit_code"]
        self._set_startup_write_state(state["startup_attempt"], "pending")
        try:
            self._startup_receipts.put_nowait((state["startup_terminal"], fields))
        except queue.Full:
            self._startup_receipt_gap = True
            self._set_startup_write_state(state["startup_attempt"], "held")

    def _queue_startup_final_receipt(self, owner, state):
        if not state["retired"] or owner._startup_final_receipt_queued:
            return
        owner._startup_final_receipt_queued = True
        members = [{key: row.get(key) for key in ("pid", "birth_ticks", "exit_code", "signaled",
            "identity_unchanged", "handle_closed", "error_type")} for row in state.get("startup_native_members", ())]
        fields = dict(attempt=state["startup_attempt"], receipt_kind="retirement", pid=os.getpid(),
            process_role="core-red-team-tool", strategy="owned-retirement",
            actual=["Native owner reported complete retirement; exact captured member observations below."],
            expected=["Original retained Job cut, signals, reader EOF and once-only closure"],
            child_diagnostics=state.get("startup_child_diagnostics", {}), native_members=members,
            native_cut_attempted=state.get("startup_native_cut_attempted", False),
            diagnostic_close_gap=state.get("startup_native_diagnostic_close_gap", False),
            startup_terminal_record=state.get("startup_terminal_record"),
            startup_stop_origin=state.get("startup_stop_origin", "unknown"),
            startup_stop_origin_known=state.get("startup_stop_origin_known", False),
            native_capture_error=state.get("startup_native_capture_error", ""),
            reason="Owned startup retirement observations; historical early exits remain uncollected.",
            coverage="Diagnostic snapshots grant no admission, response or catch authority; missing details remain unknown.")
        key = state["startup_attempt"] + ":retirement"
        self._set_startup_write_state(key, "pending")
        try:
            self._startup_receipts.put_nowait(("retired", fields))
        except queue.Full:
            self._startup_receipt_gap = True
            self._set_startup_write_state(key, "held")

    @staticmethod
    def _startup_receipt_key(fields):
        return fields["attempt"] + (":retirement" if fields.get("receipt_kind") == "retirement" else "")

    @staticmethod
    def _startup_persist_fields(fields):
        """Use the real logger's existing24-item/256-char closed projection.

        New private queue metadata is never assumed to be an accepted logger
        field. No raw stderr, paths, IPC frames or diagnostic handles enter it.
        """
        retained = {name: value for name, value in fields.items() if name in {
            "attempt", "strategy", "exception_type", "pid", "process_role", "expected", "reason", "exit_code"}}
        kind = "retirement" if fields.get("receipt_kind") == "retirement" else "startup"
        child = fields.get("child_diagnostics", {})
        actual = [f"receipt={kind}; verification_s={VERIFICATION_SECONDS:g}; "
            f"presentation_s={PRESENTATION_SECONDS:g}; whole_s={WHOLE_STARTUP_SECONDS:g}"]
        actual.append("child advisory counters: " + ";".join(
            f"{key}={child.get(key, 0)}" for key in ("raw_bytes", "lines", "omitted_bytes", "omitted_records",
                "malformed_lines", "oversized_lines")))
        terminal = fields.get("startup_terminal_record") or {}
        actual.append("original terminal: "
            f"status={terminal.get('status', 'unknown')}; phase={terminal.get('phase', 'unknown')}; "
            f"error={terminal.get('error_type', '')}; "
            f"stop_origin={fields.get('startup_stop_origin', 'unknown')}; "
            f"origin_known={fields.get('startup_stop_origin_known', False)}")
        actual.append("original terminal context: "
            f"operation={terminal.get('operation', 'unknown')}; "
            f"kind={terminal.get('message_kind', 'unknown')}; "
            f"code={terminal.get('context_code', 'unknown')}")
        omitted = {"child": 0, "native": 0}

        def append_rows(label, rows):
            current, current_count = "", 0
            for row in rows:
                candidate = (current + " | " if current else label + ": ") + row
                if len(candidate) <= 256:
                    current, current_count = candidate, current_count + 1
                    continue
                if current:
                    if len(actual) < 22:
                        actual.append(current)
                    else:
                        omitted[label] += current_count
                current, current_count = label + ": " + row, 1
                if len(current) > 256:
                    omitted[label] += 1
                    current, current_count = "", 0
            if current:
                if len(actual) < 22:
                    actual.append(current)
                else:
                    omitted[label] += current_count

        append_rows("child", [f"{row['phase']}/{row['status']}/{row['error_type'] or '-'} "
            f"child_ms={row['elapsed_ms']} recv_ms={row['received_after_ms']}"
            for row in child.get("records", ())])
        actual.append("native diagnostic: "
            f"cut_attempted={fields.get('native_cut_attempted', False)}; "
            f"readonly_close_gap={fields.get('diagnostic_close_gap', False)}; "
            f"capture_error={fields.get('native_capture_error', '')}; earlier exits UNKNOWN")
        append_rows("native", [f"pid={row['pid']} birth={row['birth_ticks']} exit={row.get('exit_code')} "
            f"sig={row.get('signaled')} same={row.get('identity_unchanged')} closed={row.get('handle_closed')} "
            f"error={row.get('error_type') or '-'}"
            for row in fields.get("native_members", ())])
        actual.append(f"projection omissions: child_rows={omitted['child']}; native_rows={omitted['native']}; "
            f"unrecognized_lines={child.get('unrecognized_lines', 0)}; partial_line={child.get('partial_line', False)}; "
            f"raw_budget_exhausted={child.get('exhausted', False)}")
        retained["actual"] = actual
        retained["coverage"] = (fields.get("coverage", "") +
            " Child records are unverified advisory claims; native rows cover only the retained current cut. "
            "The explicit projection omission counts apply; no key/frame/path/raw stderr was retained.")
        retained["output_tail"] = "Original Core phases: " + " > ".join(fields.get("actual", ()))
        return retained

    def _set_startup_write_state(self, attempt, status):
        # No filesystem or callback work happens under this short memory lock.
        with self._startup_write_lock:
            values = dict(self._startup_write_states)
            if attempt not in values and len(values) >= 16:
                values.pop(next(iter(values)))
            values[attempt] = status
            self._startup_write_states = values
        self._startup_last_receipt = (attempt, status)

    def _ensure_startup_recorder(self):
        """One bounded owned writer; no disk/native work in the Qt timer."""
        if self._startup_receipts.empty() or (self._startup_diag_worker is not None
                and self._startup_diag_worker.is_alive()):
            return
        def record():
            while True:
                try:
                    status, fields = self._startup_receipts.get_nowait()
                except queue.Empty:
                    return
                try:
                    written = self._startup_recorder.record("red-team-tool-startup", status,
                        **self._startup_persist_fields(fields))
                    self._set_startup_write_state(self._startup_receipt_key(fields), "written" if written else "held")
                except Exception:
                    self._set_startup_write_state(self._startup_receipt_key(fields), "held")
                finally:
                    self._startup_receipts.task_done()
        worker = threading.Thread(target=record, name="RedTeamStartupDiagnostics", daemon=False)
        self._startup_diag_worker = worker
        with self._task_lock:
            self._tasks = [task for task in self._tasks if task.is_alive()]
            self._tasks.append(worker)
        try:
            worker.start()
        except RuntimeError:
            self._startup_receipt_gap = True
            # A failed optional writer must not strand queued observations or
            # block suite STOP. An ambiguous started worker remains tracked.
            if not worker.is_alive():
                while True:
                    try:
                        _status, fields = self._startup_receipts.get_nowait()
                    except queue.Empty:
                        break
                    self._set_startup_write_state(self._startup_receipt_key(fields), "held")
                    self._startup_receipts.task_done()

    def _notify_startup_failure(self, owner, state):
        inbox = getattr(self.parent_view, "_notifications", None)
        failure = state.get("startup_failure")
        if inbox is None:
            return
        if not failure:
            if state.get("ui_ready"):
                inbox.remove("red-team-tool-startup")
            return
        notice = (owner, tuple(sorted(failure.items())))
        if self._startup_notice == notice:
            return
        self._startup_notice = notice
        inbox.upsert("red-team-tool-startup", "Red Team tool needs attention",
            f"The separate tool did not open. Phase: {failure['phase']}; "
            f"error type: {failure['exception_type']}. Review its private startup receipt. "
            "Sensors and policies were not changed; retry waits for exact owned cleanup.",
            lambda expected=owner: self._review_startup_failure(expected), review_label="Review startup")

    def _review_startup_failure(self, owner):
        from PySide6.QtWidgets import QDialog, QHBoxLayout, QLabel, QPlainTextEdit, QPushButton, QVBoxLayout
        from angerona.gui.window_controls import work_window_registry
        from angerona.gui.window_fit import install_window_fit
        def build():
            window = QDialog(self.parent_view)
            window.setWindowTitle("Angerona — Red Team startup review")
            window.setModal(False)
            window.resize(650, 410)
            layout = QVBoxLayout(window)
            layout.addWidget(QLabel("Standalone tool startup needs attention", window))
            window._startup_details = QPlainTextEdit(window)
            window._startup_details.setReadOnly(True)
            layout.addWidget(window._startup_details, 1)
            buttons = QHBoxLayout()
            retry = QPushButton("Retry tool", window)
            retry.clicked.connect(lambda: self._retry_startup_owner(window._startup_owner))
            close = QPushButton("Close", window)
            close.clicked.connect(window.close)
            buttons.addWidget(retry); buttons.addStretch(); buttons.addWidget(close)
            layout.addLayout(buttons)
            window._startup_retry = retry
            install_window_fit(window)
            return window
        window = work_window_registry(self.parent_view).show("red-team-startup-review", build)
        window._startup_owner = owner
        state = owner.lifecycle_snapshot()
        failure = state.get("startup_failure") or {}
        child = state.get("startup_child_diagnostics", {})
        child_lines = "\n".join(
            f"  {row['phase']}: {row['status']} · child {row['elapsed_ms']} ms · "
            f"Core received {row['received_after_ms']} ms"
            + (f" · {row['error_type']}" if row["error_type"] else "")
            for row in child.get("records", ())) or "  No accepted child phase was observed."
        native_lines = "\n".join(
            f"  PID {row['pid']} · birth {row['birth_ticks']} · "
            f"exit {row.get('exit_code', 'unknown')} · handle closed {row.get('handle_closed', False)}"
            for row in state.get("startup_native_members", ())) or "  No member details; absence is not an empty-tree proof."
        window._startup_details.setPlainText(
            f"Attempt: {state['startup_attempt']}\nPhase: {failure.get('phase', state['phase'])}\n"
            f"Error type: {failure.get('exception_type', 'not supplied')}\n"
            f"Owned execution retirement complete: {state['retired']}\n"
            f"Optional diagnostic close gap: {state.get('startup_native_diagnostic_close_gap', False)}\n"
            f"Private receipt: {self._startup_recorder.path}\n"
            f"This attempt's receipt: {self._startup_write_states.get(state['startup_attempt'], 'pending')}\n"
            f"Retirement supplement: {self._startup_write_states.get(state['startup_attempt'] + ':retirement', 'pending')}\n"
            f"Receipt capacity/worker gap observed: {self._startup_receipt_gap}\n\n"
            f"Startup budgets: verification/bootstrap {VERIFICATION_SECONDS:g}s; "
            f"then presentation {PRESENTATION_SECONDS:g}s; whole attempt {WHOLE_STARTUP_SECONDS:g}s.\n\n"
            f"Child phases (advisory only)\n{child_lines}\n"
            f"Discard/truncation counts: bytes {child.get('omitted_bytes', 0)}; "
            f"records {child.get('omitted_records', 0)}; malformed {child.get('malformed_lines', 0)}; "
            f"oversized {child.get('oversized_lines', 0)}.\n\n"
            f"Captured native members (earlier exits remain unknown)\n{native_lines}\n\n"
            "Written means the bounded diagnostic projection was saved; omissions are counted.\n"
            "This review grants no trust, scanner or response authority. A retry repeats "
            "the existing source-seal, native Job and authenticated IPC checks.")
        window._startup_retry.setEnabled(owner is self.owner and state["retired"]
            and not getattr(self.parent_view, "_termination_started", False))

    def _retry_startup_owner(self, owner):
        if (owner is self.owner and owner._retired.is_set()
                and not getattr(self.parent_view, "_termination_started", False)):
            self.show()

    def show(self):
        if getattr(self.parent_view, "_termination_started", False):
            return
        self._start()
        if self.owner is not None:
            self.owner.send("show", {})

    showNormal = show  # noqa: N815 - Qt compatibility facade

    def isMinimized(self):  # noqa: N802
        return False

    def raise_(self):
        if self.owner is not None:
            self.owner.send("show", {})

    activateWindow = raise_  # noqa: N815

    def select_tab(self, label):
        key = {"Device Security Lab": "device-lab", "History": "history", "Run": "run", "GitHub Tools": "github-tools"}.get(label)
        if key and self.owner is not None:
            self.owner.send("select-tab", {"tab": key})

    def _display(self, event, values):
        payload = {"event": event, "values": json.loads(json.dumps(values, allow_nan=False))}
        if self.owner is not None:
            self.owner.send("display", payload)
        elif len(self._initial_displays) < 64:
            self._initial_displays.append(payload)

    def set_launch_status(self, result, cfg=None):
        self._pending_flag = result.get("status") in {"queued", "preparing", "accepted"}
        self._display("launch-status", [result, cfg])

    def bind_performance_session(self, session_id, generation, plans):
        self._display("bind-session", [session_id, generation, plans])

    def record_session_lifecycle(self, projection):
        from angerona.gui.red_team_console import SessionLifecycleProjection
        if type(projection) is not SessionLifecycleProjection:
            return False
        self._display("session-lifecycle", [asdict(projection)])
        return True

    def record_performance_snapshot(self, snapshot):
        from angerona.shark.simulation_session import RunPerformanceSnapshot
        if type(snapshot) is not RunPerformanceSnapshot:
            return False
        self._display("performance", [asdict(snapshot)])
        return True

    def update_execution_progress(self, snapshots):
        self._display("execution", [snapshots])
        return True

    def record_verified_report(self, kind, run_id, payload, *, error=""):
        self._reports.add(run_id)
        self._display("verified-report", [kind, run_id, payload, error])

    def finish_run(self):
        self._display("finish", [])

    def record_cleanup_failure(self, message):
        self._display("cleanup-failure", [str(message)[:2048]])

    def _render_execution_progress(self):
        self._display("render-progress", [])

    @Slot(str)
    def _narration(self, text):
        if self.owner is not None:
            self.owner.send("narration", {"text": str(text)[:16384]})

    def _background(self, nonce, operation):
        with self._task_lock:
            self._tasks = [worker for worker in self._tasks if worker.is_alive()]
            if self._closing or len(self._tasks) >= 2:
                if self.owner is not None:
                    self.owner.send("reply", {"ok": False, "reason": "Core tool readers are busy or closing"}, reply_to=nonce)
                return
            owner = self.owner
            def work():
                try:
                    value = {"ok": True, "result": operation()}
                except (OSError, RuntimeError, ValueError, TypeError, KeyError) as exc:
                    value = {"ok": False, "reason": (type(exc).__name__ + ": " + str(exc))[:500]}
                self._task_finished.emit((owner, nonce), value)
            worker = threading.Thread(target=work, name="RedTeamCoreReview", daemon=False)
            self._tasks.append(worker)
            worker.start()

    @Slot(object, object)
    def _deliver_task(self, binding, result):
        owner, nonce = binding
        if owner is self.owner and not owner._retired.is_set():
            owner.send("reply", result, reply_to=nonce)

    @Slot(object, str, object, str)
    def _handle_incoming(self, binding, kind, payload, nonce):
        owner = self.owner
        if (type(payload) is not dict or type(binding) is not tuple or len(binding) != 2
                or type(owner) is not RedTeamToolOwner or binding != (owner, owner._epoch)
                or not owner._ready.is_set() or owner._stop.is_set() or owner._retired.is_set()):
            return
        try:
            if kind in {"tool-ready", "ui-ready"}:
                return
            if kind == "launch":
                if set(payload) != {"config"} or type(payload["config"]) is not dict:
                    raise ToolProtocolError("Unsupported launch request")
                cfg = payload["config"]
                expected = {"run_shark", "run_redteam", "intensity", "campaign", "comprehensive", "target_dir", "custom", "auto_remediate", "analogy", "complexity"}
                if set(cfg) != expected or cfg["intensity"] not in {"Low", "Medium", "High", "Extreme"}:
                    raise ToolProtocolError("Launch choices do not match the fixed local UI schema")
                if any(type(cfg[key]) is not bool for key in ("run_shark", "run_redteam", "campaign", "comprehensive", "auto_remediate", "analogy")):
                    raise ToolProtocolError("Launch choices need explicit booleans")
                if self._closing:
                    raise ToolProtocolError("Tool is closing")
                self.parent_view._run_simulation(cfg)
            elif kind in {"stop", "cancel", "close"}:
                if payload:
                    raise ToolProtocolError("Unexpected lifecycle arguments")
                if kind == "cancel":
                    self.parent_view._cancel_simulation_launch()
                else:
                    self.parent_view._stop_simulation()
                if kind == "close":
                    owner._startup_stop_requested("authenticated-tool-close")
                    self._closing = True
                    self._timer.start()
            elif kind == "readiness":
                if set(payload) != {"require_process"} or type(payload["require_process"]) is not bool:
                    raise ToolProtocolError("Readiness request schema unavailable")
                from angerona.core.drill_readiness import assess_drill_response
                result = assess_drill_response(self.parent_view.manager, require_process=payload["require_process"])
                self.owner.send("readiness-result", result)
            elif kind == "history-list":
                if payload:
                    raise ToolProtocolError("History list accepts no path")
                from angerona.gui.aar_history import list_history
                root = Path(self.parent_view.config.data_dir) / "aar_history"
                def listing():
                    value = list_history(root)
                    return {"rows": [list(row) for row in value.rows], "limited": value.limited}
                self._background(nonce, listing)
            elif kind == "history-read":
                if set(payload) != {"name"} or type(payload["name"]) is not str or len(payload["name"]) > 100:
                    raise ToolProtocolError("History member name unavailable")
                from angerona.gui.aar_history import load_verified_history_text
                root = Path(self.parent_view.config.data_dir) / "aar_history"
                self._background(nonce, lambda: load_verified_history_text(root, payload["name"])[:512 * 1024])
            elif kind == "device-lab":
                self._handle_device_request(payload, nonce)
            else:
                raise ToolProtocolError("Unsupported child request")
        except (OSError, RuntimeError, ValueError, TypeError, KeyError) as exc:
            reason = (type(exc).__name__ + ": " + str(exc))[:500]
            if nonce:
                self.owner.send("reply", {"ok": False, "reason": reason}, reply_to=nonce)
            self.record_cleanup_failure("Standalone tool request held: " + reason)

    def _handle_device_request(self, payload, nonce):
        if set(payload) != {"operation", "args", "kwargs"} or type(payload["args"]) is not list or type(payload["kwargs"]) is not dict:
            raise ToolProtocolError("Device review schema unavailable")
        operation, args, kwargs = payload["operation"], payload["args"], payload["kwargs"]
        allowed = {"create-enrollment", "confirm-enrollment", "confirm-local-enrollment", "list-enrollments", "collect-local-observations", "assess"}
        if operation not in allowed or len(args) > 3 or len(kwargs) > 4:
            raise ToolProtocolError("Device review operation unavailable")
        def work():
            from angerona.core.device_security_lab import DeviceSecurityLab
            service = getattr(self, "_device_service", None)
            if service is None:
                service = DeviceSecurityLab(Path(self.parent_view.config.data_dir) / "device-security-lab")
                self._device_service = service
            if operation == "create-enrollment":
                record, challenge = service.create_enrollment(*args, **kwargs)
                return [record.to_dict(), challenge.to_dict()]
            if operation == "confirm-enrollment":
                return service.confirm_enrollment(*args, **kwargs).to_dict()
            if operation == "confirm-local-enrollment":
                return service.confirm_local_enrollment(*args, **kwargs).to_dict()
            if operation == "list-enrollments":
                return [record.to_dict() for record in service.list_enrollments()]
            if operation == "collect-local-observations":
                return service.collect_local_observations(*args, **kwargs)
            return service.assess(*args, **kwargs).to_dict()
        self._background(nonce, work)

    def _session_released(self):
        from angerona.gui.simulation_launch import session_custody_released
        if not self._startup_receipts.empty():
            return False
        parent = self.parent_view
        session = getattr(parent, "_simulation_session", None)
        preparing = getattr(parent, "_sim_launch_job", None)
        if preparing is not None:
            return False
        if session is not None and not session_custody_released(session):
            return False
        for engine in (parent.red_team_engine, parent.shark_engine):
            worker = getattr(engine, "_thread", None)
            if worker is not None and worker.is_alive():
                return False
        with self._task_lock:
            if any(worker.is_alive() for worker in self._tasks):
                return False
        return not any(worker.is_alive() for worker in getattr(parent, "_aar_report_threads", {}).values())

    def _poll_close(self):
        owner = self.owner
        if owner is None:
            self._timer.stop()
            return
        state = owner.lifecycle_snapshot()
        timeout_reason = owner.startup_timeout_reason()
        if not state["ui_ready"] and not state["retired"] and timeout_reason is not None:
            owner._startup_observation("failed", timeout_reason)
            state = owner.lifecycle_snapshot()
            self._closing = True
        self._queue_startup_receipt(owner, state)
        self._queue_startup_final_receipt(owner, state)
        self._ensure_startup_recorder()
        self._notify_startup_failure(owner, state)
        if state["stopped"]:
            self._closing = True
            if not self._failure_cancelled:
                self._failure_cancelled = True
                self.parent_view._stop_simulation()
        if not self._closing or not self._session_released():
            return
        if self._stop_thread is not None and self._stop_thread.is_alive():
            return
        if state["retired"]:
            self._timer.stop()
            return
        owner.send("close-ready", {})
        def stop():
            # Give the authenticated close frame a short opportunity to paint
            # and retire naturally; any later termination is this exact Job.
            time.sleep(.2)
            owner.stop(5)
        self._stop_thread = threading.Thread(target=stop, name="RedTeamToolRetirement", daemon=False)
        self._stop_thread.start()

    def request_shutdown(self):
        if self.owner is not None:
            self.owner._startup_stop_requested("suite-shutdown")
        self._closing = True
        self._timer.start()

    def owned_workers(self):
        result = [self._stop_thread]
        if self.owner is not None:
            result.extend((self.owner._reader, self.owner._writer, self.owner._stderr_reader))
        with self._task_lock:
            result.extend(self._tasks)
        return tuple(worker for worker in result if worker is not None)

    def custody_released(self):
        return (self._startup_receipts.empty()
            and (self.owner is None or (self.owner._retired.is_set()
                and self.owner._startup_final_receipt_queued))
            and all(not worker.is_alive() for worker in self.owned_workers()))

    def capture_owned_process_scope(self, *, timeout=1.0):
        owner = self.owner
        if owner is None:
            return self, None
        return self, owner.capture_scope(timeout=timeout)

    def observe_owned_process_identities(self, *, captured, timeout=1.0):
        if captured != self.capture_owned_process_scope(timeout=timeout):
            raise ToolProtocolError("Tool ownership lifetime changed before observation")
        if captured[1] is None or captured[1][2] == "retired":
            return ()
        return self.owner.observe_owned_process_identities(timeout=timeout)

    def validate_probe_identity(self, identity, **binding):
        return bool(self.owner is not None and self.owner.validate_probe_identity(identity, **binding))
