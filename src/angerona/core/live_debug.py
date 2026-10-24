"""Opt-in, outward-only diagnostic views for a local interactive reviewer.

The Windows pipe is read-only to clients and authenticates its server using the
OS-reported PID. It never accepts commands or exports installation credentials.
Source signatures are provenance metadata; a redacted view is not the original
signed event and must never be submitted to a response engine as evidence.
"""
from __future__ import annotations

from collections import deque
from contextlib import contextmanager, ExitStack
import copy
from itertools import islice
import json
import math
import os
from pathlib import Path
import queue
import re
import secrets
import stat
import threading
import time
from urllib.parse import urlsplit, urlunsplit

PROTOCOL = "angerona-live-debug-v1"
MAX_FRAME_BYTES = 32 * 1024
MAX_TEXT = 8192
MAX_CLIENTS = 4
LOG_READ_BYTES = 64 * 1024
LOG_INITIAL_BYTES = 128 * 1024
LOG_RECORDS_PER_TURN = 128
LOG_TURN_SECONDS = 0.005
LOG_CYCLE_SECONDS = 0.010
LOG_BACKLOG_WAIT_SECONDS = 0.005
LOG_SOURCES = (
    "diagnostics/crash.log", "logs/crash.log",
    "diagnostics/not_responding.log", "diagnostics/blackbox_not_responding.log",
    "diagnostics/runtime_alerts.log", "logs/blackbox.log",
    "diagnostics/resilience_scanner_crash.log", "diagnostics/resilience_watchdog_crash.log",
    "diagnostics/blackbox_startup.log", "blackbox_startup.log",
)
_SAFE_DETAILS = frozenset({
    "rule", "rule_id", "finding_code", "classification", "disposition", "tamper_kind",
    "active_attack", "response_authorized", "response_authority", "assessment",
    "pid", "ppid", "create_time", "process_name", "process_path", "source_file",
    "source_line", "file_path", "path", "target_path", "sha256", "expected_hash",
    "actual_hash", "old_sha256", "new_sha256", "reason", "error", "error_type",
    "coverage", "coverage_state", "collection_state", "coverage_reason", "surface",
    "source", "status", "action", "outcome", "incident_id", "event_id", "scope",
    "spyware_confirmed", "advisory_only", "unknown", "truncated", "continuity",
    "process_create_time", "process_identity_complete", "kind", "finding_kind",
    "observed_severity", "single_rule_host_fallback",
    "detector_policy", "coverage_diagnostics", "evidence", "expected", "observed", "function",
    "expected_source_file", "expected_source_line", "source_hash", "code_hash", "expected_code_hash",
})
_TAMPER_KINDS = frozenset({
    "runtime-callable-drift", "source-file-drift", "coverage-unavailable",
})
_HASH_FIELDS = frozenset({"sha256", "expected_hash", "actual_hash", "old_sha256", "new_sha256",
                          "source_hash", "code_hash", "expected_code_hash"})
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)(\b(?:api[_ -]?key|access[_ -]?key|secret|password|passphrase|passwd|"
    r"token|authorization|cookie|session[_ -]?id|credential|private[_ -]?key)"
    r"\b[\"']?\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;}]+)"
)
_BEARER = re.compile(r"(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9+/=_\-.]+")
_SECRET_FLAG = re.compile(
    r"(?i)((?:--?|/)(?:password|passphrase|passwd|token|api[_-]?key|secret|credential)\b"
    r"(?:\s+|[:=]))(?:\"[^\"]*\"|'[^']*'|[^\s,;}]+)"
)
_PROVIDER_KEY = re.compile(r"\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{12,}|"
                           r"xox[baprs]-[A-Za-z0-9-]{12,}|eyJ[A-Za-z0-9_-]{15,}(?:\.[A-Za-z0-9_-]+){1,2})")
_OPAQUE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9+/=_-]{40,}(?![A-Za-z0-9])")
_URL = re.compile(r"https?://[^\s<>\"']+", re.I)
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")


class LiveDebugError(RuntimeError):
    pass


def endpoint_for_pid(pid: int) -> str:
    if type(pid) is not int or not 1 <= pid <= 0xFFFFFFFF:
        raise ValueError("A positive Windows process ID is required")
    return rf"\\.\pipe\Angerona.LiveDebug.{pid}"


def sanitize_text(value: object, limit: int = MAX_TEXT) -> str:
    """Bounded best-effort free-text redaction; unknown details are not exported."""
    text = value if isinstance(value, str) else type(value).__name__
    text = text[:MAX_TEXT]
    if "-----BEGIN " in text and "PRIVATE KEY" in text:
        return "[private key material omitted]"
    text = _CONTROL.sub("", text)
    text = _SECRET_ASSIGNMENT.sub(r"\1[redacted]", text)
    text = _SECRET_FLAG.sub(r"\1[redacted]", text)
    text = _BEARER.sub("[authorization redacted]", text)
    text = _PROVIDER_KEY.sub("[credential redacted]", text)

    def safe_url(match):
        try:
            parts = urlsplit(match.group())
            host = parts.hostname or ""
            if ":" in host:
                host = "[" + host + "]"
            if parts.port:
                host += ":" + str(parts.port)
            return urlunsplit((parts.scheme, host, parts.path, "", ""))
        except ValueError:
            return "[URL redacted]"

    text = _URL.sub(safe_url, text)
    text = _OPAQUE.sub("[opaque value redacted]", text)
    return text[:max(0, min(int(limit), MAX_TEXT))]


def _encode(value: dict) -> bytes:
    raw = json.dumps(value, ensure_ascii=True, separators=(",", ":"),
                     allow_nan=False).encode("ascii") + b"\n"
    if len(raw) > MAX_FRAME_BYTES:
        raise LiveDebugError("Diagnostic view exceeds frame bound")
    return raw


def _decode(raw: bytes) -> dict:
    if not raw or len(raw) > MAX_FRAME_BYTES:
        raise LiveDebugError("Invalid diagnostic frame size")
    try:
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate field")
                result[key] = value
            return result
        value = json.loads(raw, object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise LiveDebugError("Invalid diagnostic JSON") from exc
    if not isinstance(value, dict) or value.get("protocol") != PROTOCOL:
        raise LiveDebugError("Unknown diagnostic protocol")
    remaining = 512

    def bounded(item, depth=0):
        nonlocal remaining
        remaining -= 1
        if remaining < 0 or depth > 8:
            raise LiveDebugError("Diagnostic structure exceeds its bound")
        if isinstance(item, str):
            if len(item) > MAX_TEXT or _CONTROL.search(item):
                raise LiveDebugError("Diagnostic string exceeds its bound or contains controls")
        elif isinstance(item, dict):
            for key, child in item.items():
                bounded(key, depth + 1)
                bounded(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                bounded(child, depth + 1)
        elif type(item) is float and not math.isfinite(item):
            raise LiveDebugError("Diagnostic number must be finite")

    bounded(value)
    return value


def _birth(pid: int) -> float:
    import psutil
    return float(psutil.Process(pid).create_time())


def _pipe_attributes():
    import pywintypes
    import win32security
    from .engine_transport import _windows_identity
    from .privilege import is_admin
    sid = win32security.ConvertSidToStringSid(_windows_identity())
    attributes = pywintypes.SECURITY_ATTRIBUTES()
    attributes.bInheritHandle = False
    # GR does not include FILE_CREATE_PIPE_INSTANCE. Do not grant generic write
    # to an ordinary client: Windows aliases that right with pipe creation.
    # An ordinary-user producer must itself open further outbound instances,
    # which Windows checks using GENERIC_WRITE. Direction remains server->client
    # only, and readers must bind the OS server PID. Elevated producers retain
    # the narrower ordinary-client GR grant.
    user_rights = "GR" if is_admin() else "GRGW"
    attributes.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        f"D:P(A;;{user_rights};;;{sid})(A;;GA;;;SY)(A;;GA;;;BA)", 1)
    return attributes


def _cancel_pipe_io(handle):
    # Several supported pywin32 builds expose CancelIo but not CancelIoEx.
    # The latter is required when the GUI asks another thread to stop reading.
    import ctypes
    cancel = ctypes.WinDLL("kernel32", use_last_error=True).CancelIoEx
    cancel.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
    cancel.restype = ctypes.c_int
    if not cancel(int(handle), None):
        error = ctypes.get_last_error()
        if error not in (6, 1168):  # closed handle / no pending operation
            raise ctypes.WinError(error)


class _Pipe:
    """One overlapped pipe handle. A close cancels pending I/O before teardown."""

    def __init__(self, handle):
        self.handle = handle
        self.closed = threading.Event()
        self._io_lock = threading.RLock()
        self._handle_closed = False

    def _wait(self, overlap, timeout: float):
        import win32event
        import win32file
        deadline = time.monotonic() + max(0.0, timeout)
        while not self.closed.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            if win32event.WaitForSingleObject(overlap.hEvent, max(1, min(100, int(remaining * 1000)))) == 0:
                return win32file.GetOverlappedResult(self.handle, overlap, False)
        # Keep OVERLAPPED and its buffer alive until the kernel acknowledges
        # cancellation. GetOverlappedResult(True) completes the cancellation.
        try:
            _cancel_pipe_io(self.handle)
        except Exception:
            pass
        try:
            completed = win32file.GetOverlappedResult(self.handle, overlap, True)
        except Exception:
            pass
        else:
            # Completion can win a race with cancellation. Preserve any bytes
            # already read instead of silently losing a fragment of the stream.
            return completed
        if self.closed.is_set():
            raise LiveDebugError("Diagnostic pipe closed")
        raise TimeoutError("Diagnostic pipe I/O deadline exceeded")

    @staticmethod
    def _overlap():
        import pywintypes
        import win32event
        overlap = pywintypes.OVERLAPPED()
        overlap.hEvent = win32event.CreateEvent(None, True, False, None)
        return overlap

    def _retire_overlap(self, overlap, issued=True):
        """Keep OVERLAPPED/buffers alive even when Ctrl+C interrupts the wait."""
        import win32file
        try:
            if issued:
                try:
                    win32file.GetOverlappedResult(self.handle, overlap, False)
                except Exception as exc:
                    if getattr(exc, "winerror", None) == 996:  # ERROR_IO_INCOMPLETE
                        try:
                            _cancel_pipe_io(self.handle)
                        except Exception:
                            pass
                        try:
                            win32file.GetOverlappedResult(self.handle, overlap, True)
                        except Exception:
                            pass
        finally:
            overlap.hEvent.Close()

    def connect_server(self, timeout: float):
        with self._io_lock:
            try:
                return self._connect_server(timeout)
            except (LiveDebugError, TimeoutError):
                raise
            except Exception as exc:
                raise LiveDebugError("Diagnostic pipe connection failed") from exc

    def _connect_server(self, timeout: float):
        import win32pipe
        overlap = self._overlap()
        issued = False
        try:
            try:
                issued = True
                code = win32pipe.ConnectNamedPipe(self.handle, overlap)
            except Exception as exc:
                if getattr(exc, "winerror", None) == 535:  # already connected
                    issued = False
                    return
                if getattr(exc, "winerror", None) != 997:  # ERROR_IO_PENDING
                    issued = False
                    raise
                code = 997
            # pywin32 returns these accepted Win32 status codes as integers.
            # ERROR_PIPE_CONNECTED did not submit this OVERLAPPED at all;
            # waiting/draining it blocks forever, even after CancelIoEx.
            if code in (0, 535):  # completed synchronously / already connected
                issued = False
                return
            if code != 997:
                issued = False
                raise LiveDebugError("Unexpected diagnostic pipe connection status")
            self._wait(overlap, timeout)
        finally:
            self._retire_overlap(overlap, issued)

    def write(self, raw: bytes, timeout: float = 3.0):
        # A retained-history reader may spend more than one second persisting
        # the preceding native buffer on an inspected Windows volume. Each
        # client has its own bounded worker; cancellation still interrupts this
        # wait, while a stalled reader is disconnected after the deadline.
        with self._io_lock:
            try:
                return self._write(raw, timeout)
            except (LiveDebugError, TimeoutError):
                raise
            except Exception as exc:
                raise LiveDebugError("Diagnostic pipe write failed") from exc

    def _write(self, raw: bytes, timeout: float):
        import win32file
        overlap = self._overlap()
        issued = False
        try:
            try:
                issued = True
                _code, _data = win32file.WriteFile(self.handle, raw, overlap)
            except Exception as exc:
                issued = getattr(exc, "winerror", None) == 997
                raise
            count = self._wait(overlap, timeout)
            if count != len(raw):
                raise LiveDebugError("Incomplete diagnostic pipe write")
        finally:
            self._retire_overlap(overlap, issued)

    def read(self, timeout: float) -> bytes:
        with self._io_lock:
            try:
                return self._read(timeout)
            except (LiveDebugError, TimeoutError):
                raise
            except Exception as exc:
                raise LiveDebugError("Diagnostic pipe read failed") from exc

    def _read(self, timeout: float) -> bytes:
        import win32file
        overlap = self._overlap()
        buffer = win32file.AllocateReadBuffer(MAX_FRAME_BYTES)
        issued = False
        try:
            try:
                issued = True
                win32file.ReadFile(self.handle, buffer, overlap)
            except Exception as exc:
                issued = getattr(exc, "winerror", None) == 997
                raise
            count = self._wait(overlap, timeout)
            return bytes(buffer[:count])
        finally:
            self._retire_overlap(overlap, issued)

    def cancel(self):
        self.closed.set()
        try:
            if not self._handle_closed:
                _cancel_pipe_io(self.handle)
        except Exception:
            pass

    def close(self, timeout: float | None = None) -> bool:
        self.cancel()
        acquired = (self._io_lock.acquire() if timeout is None
                    else self._io_lock.acquire(timeout=max(0.0, timeout)))
        if not acquired:
            # The I/O owner retains its handle, OVERLAPPED and buffer. It will
            # close them only after the kernel acknowledges completion.
            return False
        try:
            if not self._handle_closed:
                try:
                    self.handle.Close()
                except Exception:
                    pass
                self._handle_closed = True
            return True
        finally:
            self._io_lock.release()


class _NamedPipeServer:
    def __init__(self, service):
        self.service = service
        self.stop_event = threading.Event()
        self.pipes: list[_Pipe] = []
        self.threads: list[threading.Thread] = []

    def start(self):
        if os.name != "nt":
            raise LiveDebugError("External live diagnostics currently require Windows")
        import win32file
        import win32pipe
        try:
            for index in range(MAX_CLIENTS):
                pipe = _Pipe(win32pipe.CreateNamedPipe(
                    self.service.endpoint,
                    0x2 | win32file.FILE_FLAG_OVERLAPPED | (0x80000 if index == 0 else 0),
                    0x8, MAX_CLIENTS, 64 * 1024, 0, 1000, _pipe_attributes(),
                ))
                self.pipes.append(pipe)
            for index, pipe in enumerate(self.pipes):
                thread = threading.Thread(target=self._serve, args=(pipe,),
                                          name=f"LiveDebugPipe-{index}", daemon=False)
                self.threads.append(thread)
                thread.start()
        except BaseException:
            self.stop()
            raise

    def _serve(self, pipe):
        try:
            self._serve_client_loop(pipe)
        finally:
            # The owner retires OVERLAPPED/buffers before closing its handle.
            # Non-daemon ownership also prevents interpreter teardown from
            # discarding a genuinely outstanding kernel operation.
            pipe.close()

    def _serve_client_loop(self, pipe):
        import win32pipe
        while not self.stop_event.is_set():
            connected = False
            try:
                try:
                    pipe.connect_server(1.0)
                except TimeoutError:
                    continue
                connected = True
                self.service._client_delta(1)
                pipe.write(_encode(self.service._hello()))
                cursor = 0
                last_heartbeat = time.monotonic()
                while not self.stop_event.is_set():
                    snapshot = self.service.recent(cursor, limit=100)
                    if snapshot["gap"]:
                        pipe.write(_encode(dict(
                            protocol=PROTOCOL, kind="gap", run_id=self.service.run_id,
                            seq=snapshot["first_seq"] - 1, ts=time.time(),
                            reason="retention", lost_records=snapshot["gap"], after=cursor,
                        )))
                    for record in snapshot["records"]:
                        pipe.write(_encode(record))
                    cursor = snapshot["cursor"]
                    if time.monotonic() - last_heartbeat >= 2.0:
                        pipe.write(_encode(dict(
                            protocol=PROTOCOL, kind="heartbeat", run_id=self.service.run_id,
                            seq=cursor, ts=time.time(), status=self.service.status(),
                        )))
                        last_heartbeat = time.monotonic()
                    self.stop_event.wait(0.05)
            except (OSError, LiveDebugError, TimeoutError):
                pass
            finally:
                if connected:
                    self.service._client_delta(-1)
                if not self.stop_event.is_set():
                    try:
                        win32pipe.DisconnectNamedPipe(pipe.handle)
                    except Exception:
                        pass

    def stop(self, timeout: float = 3.0):
        deadline = time.monotonic() + max(0.0, timeout)
        self.stop_event.set()
        for pipe in self.pipes:
            pipe.cancel()
        for thread in self.threads:
            if thread.ident is not None and thread is not threading.current_thread():
                thread.join(max(0.0, deadline - time.monotonic()))
        clean = not any(thread.is_alive() for thread in self.threads)
        for pipe in self.pipes:
            if not pipe.close(timeout=max(0.0, deadline - time.monotonic())):
                clean = False
        return clean


class LiveDebugClient:
    """Worker-only reader; OS server PID is mandatory, birth binding optional."""

    def __init__(self, endpoint: str, expected_pid: int, expected_birth: float | None = None):
        if endpoint != endpoint_for_pid(expected_pid):
            raise LiveDebugError("Endpoint does not match the expected server PID")
        self.endpoint, self.expected_pid = endpoint, expected_pid
        self.expected_birth = expected_birth
        self._pipe = None
        self._buffer = bytearray()
        self._run_id = None
        self._cursor = 0
        self._process_handle = None
        self.server_birth = None

    def connect(self, timeout: float = 3.0):
        try:
            return self._connect(timeout)
        except LiveDebugError:
            raise
        except Exception as exc:
            raise LiveDebugError("Diagnostic pipe could not connect to the expected local process") from exc

    def _connect(self, timeout: float):
        if os.name != "nt":
            raise LiveDebugError("External live diagnostics currently require Windows")
        import win32con
        import win32api
        import win32file
        import win32pipe
        import win32process
        if self._pipe is not None:
            return
        # No impersonation capability is granted to a potentially spoofed peer.
        win32pipe.WaitNamedPipe(self.endpoint, max(1, min(30_000, int(timeout * 1000))))
        handle = win32file.CreateFile(
            self.endpoint, win32con.GENERIC_READ, 0, None, win32con.OPEN_EXISTING,
            win32file.FILE_FLAG_OVERLAPPED | 0x100000, None,  # SECURITY_SQOS_PRESENT / anonymous
        )
        try:
            actual_pid = win32pipe.GetNamedPipeServerProcessId(handle)
            if actual_pid != self.expected_pid:
                raise LiveDebugError("OS diagnostic server PID does not match")
            self._process_handle = win32api.OpenProcess(0x1000 | 0x100000, False, actual_pid)
            self.server_birth = win32process.GetProcessTimes(self._process_handle)["CreationTime"].timestamp()
            if self.expected_birth is not None:
                if not math.isfinite(float(self.expected_birth)):
                    raise LiveDebugError("Invalid expected server birth time")
                if abs(self.server_birth - float(self.expected_birth)) > 0.001:
                    raise LiveDebugError("Diagnostic server process identity changed")
            self._pipe = _Pipe(handle)
        except Exception:
            handle.Close()
            if self._process_handle is not None:
                self._process_handle.Close()
                self._process_handle = None
            raise

    def _accept(self, record: dict) -> dict:
        kind = record.get("kind")
        run_id = record.get("run_id")
        sequence = record.get("seq")
        timestamp = record.get("ts")
        if (not isinstance(kind, str)
                or kind not in {"hello", "heartbeat", "event", "diagnostic", "coverage", "gap"}
                or not isinstance(run_id, str) or not re.fullmatch(r"[0-9a-f]{32}", run_id)
                or type(sequence) is not int or not 0 <= sequence <= 0x7FFFFFFFFFFFFFFF
                or type(timestamp) not in (int, float) or not math.isfinite(timestamp)):
            raise LiveDebugError("Invalid diagnostic record identity")
        if self._run_id is None:
            if kind != "hello" or type(record.get("pid")) is not int or record.get("pid") != self.expected_pid:
                raise LiveDebugError("Diagnostic stream must begin with matching identity")
            actual_birth = record.get("birth")
            if (type(actual_birth) not in (float, int) or not math.isfinite(actual_birth)
                    or (self.server_birth is not None and abs(actual_birth - self.server_birth) > 0.001)):
                raise LiveDebugError("Diagnostic hello identity changed")
            self._run_id = run_id
        elif run_id != self._run_id or kind == "hello":
            raise LiveDebugError("Diagnostic run changed; reconnect explicitly")
        elif kind != "heartbeat":
            if sequence <= self._cursor:
                raise LiveDebugError("Replayed diagnostic record")
            if kind != "gap" and sequence != self._cursor + 1:
                raise LiveDebugError("Diagnostic cursor skipped without a gap record")
            self._cursor = sequence
        if kind in {"hello", "heartbeat"}:
            status = record.get("status")
            if not isinstance(status, dict):
                raise LiveDebugError("Diagnostic status must be an object")
            for name in ("cursor", "queue_dropped", "client_count"):
                if name not in status and name != "cursor":
                    continue
                if type(status.get(name)) is not int or not 0 <= status[name] <= 0x7FFFFFFFFFFFFFFF:
                    raise LiveDebugError("Invalid diagnostic status counter")
        return record

    def read(self, timeout: float = 0.25) -> dict | None:
        if self._pipe is None:
            raise LiveDebugError("Diagnostic client is not connected")
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            newline = self._buffer.find(b"\n")
            if newline >= 0:
                raw = bytes(self._buffer[:newline])
                del self._buffer[:newline + 1]
                return self._accept(_decode(raw))
            if len(self._buffer) >= MAX_FRAME_BYTES:
                raise LiveDebugError("Diagnostic frame exceeds its byte limit")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            try:
                chunk = self._pipe.read(remaining)
            except TimeoutError:
                return None
            if not chunk:
                raise LiveDebugError("Diagnostic server disconnected")
            self._buffer.extend(chunk)

    def close(self):
        if self._pipe is not None:
            self._pipe.close()
            self._pipe = None
        if self._process_handle is not None:
            self._process_handle.Close()
            self._process_handle = None
        self._buffer.clear()
        self._run_id = None
        self._cursor = 0

    def cancel(self):
        """Signal pending I/O cancellation without waiting or closing handles."""
        pipe = self._pipe
        if pipe is not None:
            pipe.cancel()


class LiveDebugService:
    def __init__(self, bus, data_dir: Path, *, enabled: bool = False,
                 queue_size: int = 512, history_size: int = 2000, export_logs: bool = True):
        self.bus, self.data_dir, self.enabled = bus, Path(data_dir).absolute(), bool(enabled)
        self.endpoint = endpoint_for_pid(os.getpid())
        self.run_id = secrets.token_hex(16)
        self.birth = _birth(os.getpid())
        self.export_logs = bool(export_logs)
        self._queue: queue.Queue = queue.Queue(maxsize=max(1, min(4096, int(queue_size))))
        self._history: deque[dict] = deque(maxlen=max(1, min(10_000, int(history_size))))
        self._lock = threading.RLock()
        self._lifecycle_lock = threading.RLock()
        self._starting = False
        self._stop = threading.Event()
        self._thread = None
        self._server = None
        self._running = False
        self._cursor = 0
        self._dropped = 0
        self._reported_dropped = 0
        self._client_count = 0
        self._error = ""
        self._shutdown_pending = False
        self._logs: dict[str, dict] = {}
        self._log_source_cursor = 0

    def status(self) -> dict:
        with self._lock:
            return dict(enabled=self.enabled, running=self._running, endpoint=self.endpoint,
                        starting=self._starting,
                        pid=os.getpid(), birth=self.birth, run_id=self.run_id, cursor=self._cursor,
                        first_seq=self._history[0]["seq"] if self._history else self._cursor + 1,
                        queue_dropped=self._dropped, client_count=self._client_count,
                        error=self._error, transport="windows-outbound-named-pipe",
                        shutdown_pending=self._shutdown_pending,
                        history_size=self._history.maxlen, queued=self._queue.qsize())

    def _hello(self):
        return dict(protocol=PROTOCOL, kind="hello", run_id=self.run_id, seq=0, ts=time.time(),
                    pid=os.getpid(), birth=self.birth, status=self.status(),
                    redacted=True, advisory_only=True)

    def _client_delta(self, count):
        with self._lock:
            self._client_count = max(0, self._client_count + count)

    def start(self) -> bool:
        # Native startup may block outside the view lock. Serialize ownership
        # without preventing stop from signalling cancellation immediately.
        if not self._lifecycle_lock.acquire(blocking=False):
            return False
        try:
            with self._lock:
                if self._running:
                    return True
                if not self.enabled or self._stop.is_set():
                    return False
                self._starting = True
            self._server = _NamedPipeServer(self)
            self._server.start()
            with self._lock:
                cancelled = self._stop.is_set()
                if not cancelled:
                    self._running = True
                    self._thread = threading.Thread(target=self._run, name="LiveDebugViews", daemon=True)
            if not cancelled:
                self.bus.subscribe(self.submit, delivery_budget_ms=1.0)
                self._thread.start()
            if cancelled or self._stop.is_set():
                self.stop()
                return False
            self._append(dict(kind="coverage", source="eventbus", state="live",
                              reason="Live events from activation; older ledger history is not exported."))
            return True
        except BaseException as exc:
            self._error = type(exc).__name__ + ": " + sanitize_text(str(exc), 240)
            self.stop()
            if not isinstance(exc, Exception):
                raise
            return False
        finally:
            with self._lock:
                self._starting = False
            self._lifecycle_lock.release()

    def submit(self, event) -> bool:
        with self._lock:
            if not self._running or self._stop.is_set():
                return False
            try:
                self._queue.put_nowait(("event", event))
                return True
            except queue.Full:
                self._dropped += 1
                return False

    def submit_diagnostic(self, source: str, text: str) -> bool:
        with self._lock:
            if not self._running or self._stop.is_set():
                return False
            try:
                self._queue.put_nowait(("diagnostic", (str(source)[:160], str(text)[:MAX_TEXT])))
                return True
            except queue.Full:
                self._dropped += 1
                return False

    def recent(self, cursor: int = 0, limit: int = 200) -> dict:
        if type(cursor) is not int or cursor < 0:
            raise ValueError("Cursor must be a nonnegative integer")
        limit = max(1, min(1000, int(limit)))
        with self._lock:
            first = self._history[0]["seq"] if self._history else self._cursor + 1
            selected = list(islice((record for record in self._history if record["seq"] > cursor), limit))
            last = self._cursor
        # Records are owned by the exporter and never edited after admission.
        # Copy just the requested page after releasing the producer handoff lock.
        records = copy.deepcopy(selected)
        return dict(records=records, cursor=records[-1]["seq"] if records else cursor,
                    first_seq=first, last_seq=last, gap=max(0, first - cursor - 1))

    def _append(self, record):
        record = dict(record, protocol=PROTOCOL, run_id=self.run_id,
                      seq=0x7FFFFFFFFFFFFFFF, ts=time.time(), redacted=True, advisory_only=True)
        try:
            _encode(record)
        except (LiveDebugError, ValueError, TypeError):
            record = dict(protocol=PROTOCOL, run_id=self.run_id, seq=0,
                          ts=time.time(), kind="gap", reason="oversized-or-invalid-view",
                          dropped_events=1, advisory_only=True)
        with self._lock:
            self._cursor += 1
            record["seq"] = self._cursor
            self._history.append(record)

    def _event_view(self, event):
        details = event.details if isinstance(getattr(event, "details", None), dict) else {}
        selected = {}
        for key in _SAFE_DETAILS:
            value = details.get(key)
            if value is None:
                continue
            if key == "process_identity_complete" and type(value) is not bool:
                continue
            if key == "tamper_kind" and (type(value) is not str or value not in _TAMPER_KINDS):
                continue
            if type(value) in (bool, int):
                selected[key] = value
            elif type(value) is float and math.isfinite(value):
                selected[key] = value
            elif isinstance(value, str):
                selected[key] = (value.lower() if key in _HASH_FIELDS and re.fullmatch(r"[0-9a-fA-F]{64}", value)
                                 else sanitize_text(value, 512))
            elif isinstance(value, dict) and key in {"coverage", "coverage_diagnostics"}:
                coverage = {}
                for surface, evidence in islice(value.items(), 16):
                    if not isinstance(surface, str):
                        continue
                    if isinstance(evidence, dict):
                        row = {}
                        for name in ("status", "state", "error", "error_type", "reason", "collected", "total", "denied"):
                            scalar = evidence.get(name)
                            if type(scalar) in (bool, int):
                                row[name] = scalar
                            elif isinstance(scalar, str):
                                row[name] = sanitize_text(scalar, 240)
                        coverage[sanitize_text(surface, 80)] = row
                    elif isinstance(evidence, str):
                        coverage[sanitize_text(surface, 80)] = sanitize_text(evidence, 240)
                selected[key] = coverage
            elif isinstance(value, dict) and key == "evidence":
                evidence = {}
                for name in ("source", "id", "path", "file_path", "process_path", "command", "rule", "surface"):
                    scalar = value.get(name)
                    if isinstance(scalar, str):
                        evidence[name] = sanitize_text(scalar, 512)
                selected[key] = evidence
        signed = bool(getattr(event, "hmac_sig", ""))
        try:
            archived = signed and bool(self.bus.integrity_enabled) and bool(self.bus.verify_archived(event))
            live = archived and bool(self.bus.verify(event))
        except Exception:
            archived = live = False
        signature = str(getattr(event, "hmac_sig", ""))
        if not re.fullmatch(r"[0-9a-f]{64}", signature):
            signature = ""
        mesh_signature = str(getattr(event, "mesh_sig", ""))
        if not re.fullmatch(r"[0-9a-f]{128}", mesh_signature):
            mesh_signature = ""
        severity = getattr(getattr(event, "severity", None), "name", "UNKNOWN")
        timestamp = getattr(event, "ts", None)
        return dict(kind="event", module=sanitize_text(getattr(event, "module", ""), 160),
                    message=sanitize_text(getattr(event, "message", "")), severity=severity,
                    event_ts=timestamp if type(timestamp) in (float, int) and math.isfinite(timestamp) else None,
                    details=selected, omitted_detail_count=max(0, len(details) - len(selected)),
                    original_hmac=signature, original_mesh_signature=mesh_signature,
                    original_mesh_peer=sanitize_text(getattr(event, "mesh_peer", ""), 160),
                    original_integrity_verified=archived, live_receipt_verified_at_export=live,
                    verification_scope="original event only; redacted view is advisory")

    def _run(self):
        while not self._stop.is_set():
            with self._lock:
                lost = self._dropped - self._reported_dropped
                self._reported_dropped = self._dropped
            if lost:
                self._append(dict(kind="gap", reason="ingestion-overflow", dropped_events=lost))
            for _index in range(32):
                try:
                    backlog = any(state.get("backlog", False) for state in tuple(self._logs.values()))
                    wait = LOG_BACKLOG_WAIT_SECONDS if backlog else 0.05
                    kind, payload = self._queue.get(timeout=wait if _index == 0 else 0)
                except queue.Empty:
                    break
                try:
                    if kind == "event":
                        self._append(self._event_view(payload))
                    else:
                        source, text = payload
                        self._append(dict(kind="diagnostic", source=sanitize_text(source, 160),
                                          message=sanitize_text(text)))
                except Exception as exc:
                    self._append(dict(kind="gap", reason="view-failed", error_type=type(exc).__name__,
                                      dropped_events=1))
            if self.export_logs:
                self._poll_logs()

    def _poll_logs(self):
        """Cooperative Python slices; filesystem calls cannot be preempted here."""
        deadline = time.monotonic() + LOG_CYCLE_SECONDS
        for _index in range(len(LOG_SOURCES)):
            if self._stop.is_set() or time.monotonic() >= deadline:
                break
            relative = LOG_SOURCES[self._log_source_cursor]
            self._log_source_cursor = (self._log_source_cursor + 1) % len(LOG_SOURCES)
            now = time.monotonic()
            state = self._logs.get(relative)
            if state is not None and not state.get("backlog", False) and state.get("next_poll", 0) > now:
                continue
            self._tail_log(relative, deadline=min(deadline, now + LOG_TURN_SECONDS))
            # A new event can arrive during a log turn. Hand it back to the
            # event lane before processing another source, rather than draining
            # ten busy files in one uninterrupted operation.
            if not self._queue.empty():
                break

    @contextmanager
    def _open_log(self, relative):
        path = self.data_dir / relative
        if relative not in LOG_SOURCES:
            raise PermissionError("Diagnostic source is not allowlisted")
        with ExitStack() as stack:
            if os.name == "nt":
                import msvcrt
                import win32con
                import win32file

                def hold(target, directory):
                    handle = win32file.CreateFile(
                        str(target), 0x81 if directory else win32con.GENERIC_READ,
                        3 if directory else 7, None, win32con.OPEN_EXISTING,
                        0x00200000 | (0x02000000 if directory else 0), None)
                    stack.callback(handle.Close)
                    info = win32file.GetFileInformationByHandle(handle)
                    if info[0] & 0x400 or bool(info[0] & 0x10) != directory:
                        raise PermissionError("Diagnostic links are not followed")
                    actual = win32file.GetFinalPathNameByHandle(handle, 0)
                    if actual.startswith("\\\\?\\"):
                        actual = actual[4:]
                    if os.path.normcase(os.path.abspath(actual)) != os.path.normcase(str(target)):
                        raise PermissionError("Diagnostic handle leaves its expected path")
                    if not directory and info[7] != 1:
                        raise PermissionError("Diagnostic file has multiple links")
                    return handle

                # Retaining each parent without share-delete prevents a parent
                # replacement while the final path and file are inspected/read.
                for parent in (*reversed(path.parent.parents), path.parent):
                    hold(parent, True)
                handle = hold(path, False)
                descriptor = msvcrt.open_osfhandle(int(handle), os.O_RDONLY | os.O_BINARY)
                handle.Detach()
            else:
                # Walk from the root through directory descriptors. No pathname
                # lookup after the chain is pinned can follow a parent symlink.
                directory_fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
                stack.callback(os.close, directory_fd)
                for component in path.parts[1:-1]:
                    directory_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                           dir_fd=directory_fd)
                    stack.callback(os.close, directory_fd)
                descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
            stream = stack.enter_context(os.fdopen(descriptor, "rb"))
            held = os.fstat(stream.fileno())
            if not stat.S_ISREG(held.st_mode) or held.st_nlink != 1:
                raise PermissionError("Diagnostic file identity is unsafe")
            yield stream, held

    def _tail_log(self, relative, *, deadline=None):
        if deadline is None:
            deadline = time.monotonic() + LOG_TURN_SECONDS
        state = self._logs.setdefault(relative, dict(identity=None, offset=0, pending=b"", coverage="",
                                                     skipping=False, skip_reason="", more=False,
                                                     backlog=False, next_poll=0.0))
        try:
            # Resume already-pinned bytes before reading another chunk. Only
            # one 64-KiB read plus at most an 8-KiB partial line can be retained.
            if b"\n" not in state["pending"] and len(state["pending"]) <= MAX_TEXT:
                if state["identity"] is None:
                    # Negative metadata checks disclose no contents. A positive
                    # path always passes the complete held-handle custody walk.
                    (self.data_dir / relative).lstat()
                with self._open_log(relative) as (stream, info):
                    identity = (info.st_dev, info.st_ino)
                    if state["identity"] != identity or info.st_size < state["offset"]:
                        initial = state["identity"] is None
                        discarded = len(state["pending"])
                        state.update(identity=identity,
                                     offset=max(0, info.st_size - LOG_INITIAL_BYTES) if initial else 0,
                                     pending=b"", skipping=False, skip_reason="")
                        if state["offset"] or not initial:
                            self._append(dict(kind="gap", source=relative,
                                              reason="initial-log-tail" if initial else "log-rotated-or-truncated",
                                              skipped_bytes=state["offset"], buffered_bytes_discarded=discarded,
                                              partial_line_omitted=bool(state["offset"])))
                        if state["offset"]:
                            state["skipping"] = True
                            state["skip_reason"] = "initial-partial-log-line"
                    stream.seek(state["offset"])
                    raw = stream.read(LOG_READ_BYTES)
                    state["offset"] += len(raw)
                    state["more"] = info.st_size > state["offset"]
                state["pending"] += raw
            if state["coverage"] != "available":
                self._append(dict(kind="coverage", source=relative, state="available"))
                state["coverage"] = "available"
            pending = state["pending"]
            position = emitted = 0
            while position < len(pending) and emitted < LOG_RECORDS_PER_TURN:
                # A cold native open may consume the cooperative time slice.
                # Still parse one bounded record from the pinned bytes so even
                # consistently slow metadata cannot prevent forward progress.
                if emitted and time.monotonic() >= deadline:
                    break
                newline = pending.find(b"\n", position)
                if state["skipping"]:
                    end = newline + 1 if newline >= 0 else len(pending)
                    self._append(dict(kind="gap", source=relative, reason=state["skip_reason"],
                                      skipped_bytes=end - position))
                    emitted += 1
                    position = end
                    if newline >= 0:
                        state["skipping"] = False
                        state["skip_reason"] = ""
                    continue
                # Count a whole contiguous blank run using bounded C-level byte
                # scans. A 64-KiB newline burst becomes one counted notice, not
                # 65,536 Python/JSON allocations or retained blank records.
                if pending[position] in b" \t\r\n":
                    suffix = pending[position:]
                    leading = len(suffix) - len(suffix.lstrip(b" \t\r\n"))
                    last_blank = pending.rfind(b"\n", position, position + leading)
                    if last_blank >= position:
                        end = last_blank + 1
                        self._append(dict(kind="coverage", source=relative, state="blank-lines-coalesced",
                                          blank_lines=pending.count(b"\n", position, end),
                                          blank_bytes=end - position))
                        emitted += 1
                        position = end
                        continue
                if newline < 0:
                    if len(pending) - position > MAX_TEXT:
                        self._append(dict(kind="gap", source=relative, reason="oversized-log-line",
                                          skipped_bytes=len(pending) - position))
                        position = len(pending)
                        state["skipping"] = True
                        state["skip_reason"] = "oversized-log-line"
                    break
                if newline - position > MAX_TEXT:
                    self._append(dict(kind="gap", source=relative, reason="oversized-log-line",
                                      skipped_bytes=newline + 1 - position))
                else:
                    self._append(dict(kind="diagnostic", source=relative,
                                      message=sanitize_text(pending[position:newline].decode("utf-8", "replace"))))
                emitted += 1
                position = newline + 1
            state["pending"] = pending[position:]
            state["backlog"] = (state["more"] or b"\n" in state["pending"] or len(state["pending"]) > MAX_TEXT)
            state["next_poll"] = 0.0 if state["backlog"] else time.monotonic() + 0.25
        except Exception as exc:
            code = getattr(exc, "winerror", None)
            error = ("not-created" if isinstance(exc, FileNotFoundError) or code in (2, 3)
                     else "PermissionError" if code == 5 else type(exc).__name__)
            if state["coverage"] != error:
                self._append(dict(kind="coverage", source=relative,
                                  state="not-created" if error == "not-created" else "unavailable",
                                  error_type="" if error == "not-created" else error))
                state["coverage"] = error
            state["backlog"] = False
            state["next_poll"] = time.monotonic() + 1.0

    def stop(self, timeout: float = 3.0):
        deadline = time.monotonic() + max(0.0, timeout)
        self._stop.set()
        with self._lock:
            self._running = False
        if not self._lifecycle_lock.acquire(timeout=max(0.0, deadline - time.monotonic())):
            with self._lock:
                self._shutdown_pending = True
                self._error = "Diagnostic startup remains worker-owned; shutdown is pending"
            return False
        try:
            return self._stop_owned(deadline)
        finally:
            self._lifecycle_lock.release()

    def _stop_owned(self, deadline):
        self.bus.unsubscribe(self.submit)
        transport_clean = True
        if self._server is not None:
            transport_clean = self._server.stop(max(0.0, deadline - time.monotonic())) is not False
        with self._lock:
            self._shutdown_pending = not transport_clean
            if not transport_clean:
                self._error = "Diagnostic pipe shutdown exceeded its deadline; native I/O remains worker-owned"
        if (self._thread is not None and self._thread.ident is not None
                and self._thread is not threading.current_thread()):
            self._thread.join(max(0.0, deadline - time.monotonic()))
            if self._thread.is_alive():
                with self._lock:
                    self._error = "Exporter worker exceeded its shutdown deadline"
                    self._shutdown_pending = True
        while True:
            drained = 0
            try:
                self._queue.get_nowait()
                drained = 1
            except queue.Empty:
                break
            if drained:
                with self._lock:
                    self._dropped += 1
        with self._lock:
            unreported = self._dropped - self._reported_dropped
            self._reported_dropped = self._dropped
        if unreported:
            self._append(dict(kind="gap", reason="service-stopped", dropped_events=unreported))
        log_states = tuple(self._logs.values())
        buffered = sum(len(state["pending"]) for state in log_states)
        backlogged = sum(bool(state.get("backlog")) for state in log_states)
        if buffered or backlogged:
            self._append(dict(kind="gap", reason="service-stopped-log-backlog",
                              buffered_log_bytes=buffered, sources_with_backlog=backlogged))
        return not self._shutdown_pending
