"""Bounded OS-authenticated status for an independently installed service.

The desktop receives counts and lifecycle state, never the service's HMAC key,
SQLite file, settings, event text or a mutating operation. The separate ordinary
user EngineServer/EngineControl API is not reused as a service control surface.
The native pipe transport authenticates an actual Windows user token, and the
protected installer policy is reread for each request to honor revocation.
"""
from __future__ import annotations

import ctypes
from itertools import islice
import math
from pathlib import Path
import re
import secrets
import threading
import time

from .engine_transport import canonical, decode
from .native_pipe_custody import RetainedPipe
from .native_broker_custody import NativeCustodyOwner, RetainedBrokerPipeServer, native_broker_retirement_held
from .privileged_pipe import (
    BrokerPipeError, CLIENT_ACCESS, MAX_CLIENTS, PROTOCOL, PrivilegedPipeClient,
    _read_frame, _response_receipt, _sid, _write_frame,
)
from .windows_engine_custody import (
    ServiceCustodyCleanupError, active_engine_custody, verify_protection_service_process,
)

ENDPOINT = r"\\.\pipe\Angerona.Protection.Status.v1"
POLICY_SCHEMA = "angerona.protection.console-policy.v1"
STATUS_SCHEMA = "angerona.protection.status.v1"
MAX_POLICY = 16 * 1024
MAX_STATUS = 4096
MAX_MODULES = 256
_USER_SID = re.compile(r"S-1-(?:5-21|12-1)-(?:[0-9]+-){3}[0-9]+\Z")
_STATUS_FIELDS = frozenset({"schema", "service", "version", "state", "transport", "authority",
    "protection_verified", "coverage_reason", "mode", "modules", "mutating_operations",
    "event_text_available", "storage_access_available"})
# A failed SCM graph must not garbage-collect an ambiguous native owner while
# its diagnostic exception unwinds. One service graph is admitted per process;
# a held owner prevents replacement listeners until process teardown.
_RETIREMENT_HOLD = None
_POLICY_RETIREMENT_HOLD = ()
_POLICY_READ_LOCK = threading.Lock()
_CLIENT_RETIREMENT_HOLDS = []
_CLIENT_SLOTS = threading.BoundedSemaphore(MAX_CLIENTS)


class ServiceClientCleanupError(BrokerPipeError):
    """A request's native owner remains retained; thread exit is not cleanup."""


class _ServiceStatusPipe(RetainedPipe):
    """Same status wire; all OVERLAPPED, event and buffer owners are retained."""


class _ServiceStatusPipeServer(RetainedBrokerPipeServer):
    """Existing authenticated wire with retained pipe and peer-token custody."""
    def _native_hold(self):
        self.error = self.error or "Protection status overlapped native retirement remains unproven"
        self.stop_event.set()
        for pipe in self.pipes:
            try:
                pipe.cancel()
            except BaseException:
                pass  # Retained resource owners remain available to stop().

def parse_console_policy(value: dict) -> frozenset[str]:
    if (type(value) is not dict or set(value) != {"schema", "allowed_user_sids"}
            or value["schema"] != POLICY_SCHEMA or type(value["allowed_user_sids"]) is not list
            or not 1 <= len(value["allowed_user_sids"]) <= 64):
        raise PermissionError("Protection console policy requires an explicit bounded OS-user enrollment")
    users = value["allowed_user_sids"]
    if any(type(sid) is not str or not _USER_SID.fullmatch(sid) or _sid(sid) != sid for sid in users):
        raise PermissionError("Protection console enrollment must name canonical individual Windows user SIDs")
    if len(set(users)) != len(users):
        raise PermissionError("Protection console enrollment has duplicate users")
    return frozenset(users)


def _policy_identity(handle):
    from ctypes import wintypes

    class FileIdInfo(ctypes.Structure):
        _fields_ = [("volume", ctypes.c_ulonglong), ("identifier", ctypes.c_ubyte * 16)]
    function = ctypes.WinDLL("kernel32", use_last_error=True).GetFileInformationByHandleEx
    function.argtypes = (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD)
    function.restype = wintypes.BOOL
    value = FileIdInfo()
    if not function(int(handle), 18, ctypes.byref(value), ctypes.sizeof(value)):
        raise PermissionError("Protection enrollment native file identity is unavailable")
    return value.volume, bytes(value.identifier)


def _close_policy_handles(handles):
    global _POLICY_RETIREMENT_HOLD

    uncertain = []
    for handle in reversed(handles):
        try:
            handle.Close()
        except Exception:
            uncertain.append(handle)
            try:
                handle.Detach()  # Preserve uncertainty without a numeric retry.
            except Exception:
                pass  # The retained object prevents premature destructor retry.
    if uncertain:
        _POLICY_RETIREMENT_HOLD = tuple(uncertain)
        raise PermissionError("Protection enrollment handle retirement remains unproven")


def read_console_policy(custody) -> frozenset[str]:
    """Single native owner, bounded ReadFile, no CRT ownership transfer."""
    with _POLICY_READ_LOCK:
        if _POLICY_RETIREMENT_HOLD:
            raise PermissionError("Protection enrollment handle retirement is held")
        return _read_console_policy(custody)


def _read_console_policy(custody) -> frozenset[str]:
    import win32con
    import win32file

    path = custody.root / "console-policy.json"
    custody.verify_private_path(path)
    handle = win32file.CreateFile(str(path), win32con.GENERIC_READ, win32con.FILE_SHARE_READ,
        None, win32con.OPEN_EXISTING, win32con.FILE_ATTRIBUTE_NORMAL | win32file.FILE_FLAG_OPEN_REPARSE_POINT, None)
    owned = [handle]
    try:
        before = win32file.GetFileInformationByHandle(handle)
        if before[0] & (0x10 | 0x400) or before[7] != 1 or (before[5] << 32 | before[6]) > MAX_POLICY:
            raise PermissionError("Protection console enrollment has unsafe file metadata")
        identity = _policy_identity(handle)
        code, raw = win32file.ReadFile(handle, MAX_POLICY + 1)
        after = win32file.GetFileInformationByHandle(handle)
        if (code != 0 or type(raw) is not bytes
                or (after[0], after[1], after[3], after[4:]) != (before[0], before[1], before[3], before[4:])):
            raise PermissionError("Protection console enrollment changed during its pinned read")
        custody.verify_private_path(path)
        named = win32file.CreateFile(str(path), 0x80, win32con.FILE_SHARE_READ,  # FILE_READ_ATTRIBUTES
            None, win32con.OPEN_EXISTING, win32con.FILE_ATTRIBUTE_NORMAL | win32file.FILE_FLAG_OPEN_REPARSE_POINT, None)
        owned.append(named)
        if _policy_identity(named) != identity:
            raise PermissionError("Protection console enrollment name differs from its pinned native object")
    finally:
        _close_policy_handles(owned)
    if len(raw) > MAX_POLICY:
        raise PermissionError("Protection console policy exceeds its byte bound")
    return parse_console_policy(decode(raw))


class ServiceStatusControl:
    """Headless lifecycle observer with a closed status-only request catalog."""
    def __init__(self, custody, *, _read_policy=None, _server_factory=None):
        if custody is not active_engine_custody():
            raise PermissionError("Protection status requires the actual admitted service owner")
        self._custody = custody
        self._read_policy = _read_policy or read_console_policy
        self._server_factory = _server_factory or _ServiceStatusPipeServer
        self._server = None
        self._manager = self._config = None
        self.state = "starting"
        self.transport_state = "not-provisioned"
        self.retention = self.runtime_metrics = None
        self._retirement_error = False
        self.graph_retirement_pending = False
        self._server_stop_attempted = False

    def start(self) -> bool:
        if native_broker_retirement_held():
            self._hold_retirement()
        if (_RETIREMENT_HOLD is not None or self._server is not None or self._retirement_error
                or self.state != "starting"):
            raise RuntimeError("Protection status native owner is already active or held")
        try:
            users = self._read_policy(self._custody)
        except Exception:
            # Optional console enrollment never blocks the independently
            # verified protection graph and never repairs rejected policy.
            self.transport_state = "policy-unavailable"
            if _POLICY_RETIREMENT_HOLD:
                self._hold_retirement()
            return False
        server = self._server_factory(self.dispatch, server_sid=self._custody.service_sid,
                                      allowed_sids=users, endpoint=ENDPOINT)
        self._server = server
        self._server_stop_attempted = False
        try:
            server.start()
        except Exception:
            self._server_stop_attempted = True
            try:
                retired = server.stop()
            except BaseException:
                self._hold_retirement()
                raise RuntimeError("Protection status startup I/O retirement remains unproven")
            if retired is not True:
                self._hold_retirement()
                raise RuntimeError("Protection status startup I/O retirement remains unproven")
            self._server = None
            self.transport_state = "transport-unavailable"
            return False
        self.transport_state = "os-authenticated-read-only"
        return True

    def _hold_retirement(self):
        global _RETIREMENT_HOLD

        self._retirement_error = True
        _RETIREMENT_HOLD = self

    def attach(self, manager, _bus, config, _chill):
        self._manager, self._config = manager, config

    def ready(self):
        self.state = "ready"

    def dispatch(self, request: dict, peer) -> dict:
        if (type(request) is not dict or request != {"operation": "status"}
                or self.state not in {"starting", "ready"}
                or self._custody is not active_engine_custody()):
            raise PermissionError("Protection console supports only current read-only status")
        try:
            allowed = self._read_policy(self._custody)
        except BaseException:
            if _POLICY_RETIREMENT_HOLD:
                self._hold_retirement()
            raise
        if peer.user_sid not in allowed:
            raise PermissionError("OS user is absent or revoked from protected console enrollment")
        from angerona import __version__

        modules = getattr(self._manager, "modules", {})
        rows = tuple(islice(modules.values(), MAX_MODULES))
        enabled = tuple(row for row in rows if getattr(row, "enabled", False) is True)
        result = dict(schema=STATUS_SCHEMA, service="AngeronaProtection", version=__version__,
            state=self.state, transport="os-authenticated-read-only", authority=[],
            protection_verified=False,
            coverage_reason="Module progress is separate from verified detector coverage",
            mode="chill" if getattr(self._config, "runtime_chill_active", False) is True else "full" if self.state == "ready" else "starting",
            modules=dict(discovered=len(modules), sampled=len(rows), truncated=len(modules) > MAX_MODULES,
                         enabled=len(enabled), running=sum(getattr(row, "status", "") == "running" for row in enabled)),
            mutating_operations=[], event_text_available=False, storage_access_available=False)
        if len(canonical(result)) > MAX_STATUS:
            raise PermissionError("Protection status exceeded its response bound")
        return result

    def close(self):
        if native_broker_retirement_held():
            self._hold_retirement()
        self.state = "stopping"
        if _POLICY_RETIREMENT_HOLD:
            self._hold_retirement()
        server = self._server
        if server is not None and not self._server_stop_attempted:
            self._server_stop_attempted = True
            try:
                retired = server.stop()
            except BaseException:
                self._hold_retirement()
                raise RuntimeError("Protection status native I/O retirement remains unproven")
            if retired is not True:
                self._hold_retirement()
                raise RuntimeError("Protection status native I/O retirement remains unproven")
            self._server = None
        if self._retirement_error:
            raise RuntimeError("Protection status native I/O retirement remains unproven")
        if native_broker_retirement_held():
            self._hold_retirement()
            raise RuntimeError("Protection status native I/O retirement remains unproven")
        self.state = "stopped"


class _ServiceStatusNativeClient(PrivilegedPipeClient):
    """The existing fixed wire with explicit client resource-retirement proof."""
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.cleanup_proven = True
        self._poisoned = False
        self._pipe = self._process = self._raw_handle = None
        self._verifier_unproven = False
        self._slot_owned = False
        self._request_lock = threading.Lock()

    def _finish_owned_request(self):
        if self._poisoned:
            return False
        uncertain = self._verifier_unproven or native_broker_retirement_held()
        if self._pipe is not None:
            try:
                retired = self._pipe.close(timeout=3.0)
            except BaseException:
                retired = False
            if retired is True:
                self._pipe = None
            else:
                uncertain = True
        for field in ("_process", "_raw_handle"):
            handle = getattr(self, field)
            if handle is not None:
                try:
                    handle.Close()
                except BaseException:
                    uncertain = True
                    try:
                        handle.Detach()
                    except BaseException:
                        pass  # Retain the object; never retry its number.
                else:
                    setattr(self, field, None)
        self.cleanup_proven = not uncertain
        if uncertain:
            self._poisoned = True
            _CLIENT_RETIREMENT_HOLDS.append(self)
        elif self._slot_owned:
            self._slot_owned = False
            _CLIENT_SLOTS.release()
        return self.cleanup_proven

    def exchange(self, request, timeout=3.0):
        if self._poisoned or _CLIENT_RETIREMENT_HOLDS or native_broker_retirement_held():
            raise ServiceClientCleanupError("Protection status client native cleanup remains held")
        if not self._request_lock.acquire(blocking=False):
            raise BrokerPipeError("Protection status client already owns an active request")
        try:
            if not _CLIENT_SLOTS.acquire(blocking=False):
                raise BrokerPipeError("Protection status client request capacity is held")
            self._slot_owned = True
            self.cleanup_proven = False
            try:
                return self._exchange_status(request, timeout)
            except ServiceCustodyCleanupError:
                self._verifier_unproven = True
                raise
            finally:
                if not self._finish_owned_request():
                    raise ServiceClientCleanupError("Protection status client native cleanup remains unproven")
        finally:
            self._request_lock.release()

    def _exchange_status(self, request, timeout):
        # Reserve native admission before FFI. A failing create/open without a
        # published handle must not turn into an unsupported clean claim.
        with NativeCustodyOwner() as owner:
            return self._exchange_owned_status(request, timeout, owner)

    def _exchange_owned_status(self, request, timeout, owner):
        import os
        import win32api
        import win32file
        import win32pipe
        import win32process
        import win32event

        if os.name != "nt":
            raise BrokerPipeError("Protection status transport requires Windows")
        if (type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 30
                or type(request) is not dict or request != {"operation": "status"}
                or not isinstance(self.endpoint, str) or not self.endpoint.startswith("\\\\.\\pipe\\")
                or len(self.endpoint) > 240):
            raise BrokerPipeError("Invalid bounded local protection status request")
        win32pipe.WaitNamedPipe(self.endpoint, max(1, min(30000, int(timeout * 1000))))
        handle = owner.open(win32file.CreateFile, self.endpoint, CLIENT_ACCESS, 0, None, 3,
            win32file.FILE_FLAG_OVERLAPPED | 0x100000 | 0x10000, None)
        self._raw_handle = handle
        owner.rows.clear()  # Exact handle is retained before ownership transfer.
        pipe = self._pipe = _ServiceStatusPipe(handle)
        self._raw_handle = None
        pid = win32pipe.GetNamedPipeServerProcessId(handle)
        if self.expected_pid is not None and pid != self.expected_pid:
            raise BrokerPipeError("Protection status PID differs from expected native identity")
        process = self._process = owner.open(win32api.OpenProcess, 0x00101000, False, pid)
        owner.rows.clear()
        birth = win32process.GetProcessTimes(process)["CreationTime"].timestamp()
        if (self.expected_birth is not None and (type(self.expected_birth) not in (int, float)
                or not math.isfinite(self.expected_birth) or abs(birth - self.expected_birth) > 0.001)):
            raise BrokerPipeError("Protection status creation time differs from expected native identity")
        self._server_verifier(process, pid)
        if win32event.WaitForSingleObject(process, 0) != 258:
            raise BrokerPipeError("Verified protection status process exited")
        self.server_identity = dict(pid=pid, birth=birth)
        nonce = secrets.token_hex(16)
        _write_frame(pipe, dict(protocol=PROTOCOL, nonce=nonce, request=request), timeout)
        deadline = time.monotonic() + timeout
        response = _read_frame(pipe, timeout)
        if (set(response) != {"protocol", "nonce", "ok", "result"}
                or response["protocol"] != PROTOCOL or response["nonce"] != nonce
                or response["ok"] is not True or not isinstance(response["result"], dict)):
            raise BrokerPipeError("Protection status response identity/schema mismatch")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Protection status response receipt deadline exceeded")
        _write_frame(pipe, _response_receipt(response), remaining)
        return response["result"]


class EngineServiceStatusClient:
    """Read-only worker client; native server proof precedes every payload."""
    def __init__(self):
        self._client = _ServiceStatusNativeClient(endpoint=ENDPOINT,
                                                   _server_verifier=verify_protection_service_process)

    @property
    def cleanup_proven(self) -> bool:
        """Memory-only; a retired Python worker alone cannot establish this."""
        return (getattr(self._client, "cleanup_proven", False) is True
                and not _CLIENT_RETIREMENT_HOLDS and not native_broker_retirement_held())

    @property
    def cleanup_state(self) -> str:
        return ("unproven" if getattr(self._client, "_poisoned", False) or _CLIENT_RETIREMENT_HOLDS
                or native_broker_retirement_held() else "retired" if self.cleanup_proven else "pending")

    def status(self) -> dict:
        result = self._client.exchange({"operation": "status"})
        if not self.cleanup_proven:
            raise ServiceClientCleanupError("Protection status client native cleanup remains unproven")
        if (type(result) is not dict or set(result) != _STATUS_FIELDS or result.get("schema") != STATUS_SCHEMA
                or len(canonical(result)) > MAX_STATUS or result.get("authority") != []
                or result.get("mutating_operations") != [] or result.get("storage_access_available") is not False
                or result.get("event_text_available") is not False or result.get("protection_verified") is not False
                or result.get("service") != "AngeronaProtection"
                or result.get("transport") != "os-authenticated-read-only"
                or result.get("state") not in {"starting", "ready"}
                or result.get("mode") not in {"starting", "chill", "full"}
                or type(result.get("version")) is not str or len(result["version"]) > 32
                or type(result.get("coverage_reason")) is not str or len(result["coverage_reason"]) > 160):
            raise PermissionError("Protection service returned an invalid bounded status result")
        modules = result.get("modules")
        if (type(modules) is not dict or set(modules) != {"discovered", "sampled", "truncated", "enabled", "running"}
                or type(modules["truncated"]) is not bool
                or any(type(modules[name]) is not int or not 0 <= modules[name] <= 100_000
                       for name in ("discovered", "sampled", "enabled", "running"))
                or not 0 <= modules["running"] <= modules["enabled"] <= modules["sampled"] <= MAX_MODULES
                or modules["sampled"] > modules["discovered"]):
            raise PermissionError("Protection service returned invalid bounded module counts")
        return result
