"""OS-authenticated local broker transport, separate from desktop HMAC IPC.

Production clients require the fixed SCM service and immutable MSIX identity.
There is no source-elevation flag, registry supplied by a peer, generic RPC,
pickle, shell or network listener. Direct test composition can exercise the
native transport with an inert backend; it grants no service deployment right.
"""
from __future__ import annotations

import ctypes
import hashlib
from dataclasses import dataclass
import math
import os
from pathlib import Path
import re
import secrets
import struct
import threading
import time

from .engine_transport import canonical, decode
from .live_debug import _Pipe, LiveDebugError

PROTOCOL = "angerona-os-broker-pipe-v1"
SERVICE_NAME = "AngeronaResponseBroker"
ENDPOINT = r"\\.\pipe\Angerona.ResponseBroker.v1"
_LOCAL_PREFIX = "\\\\.\\pipe\\"
MAX_FRAME = 32 * 1024
MAX_CLIENTS = 4
CLIENT_ACCESS = 0x00120083  # read/write data, read attrs/control, synchronize; NOT create-instance.
_NONCE = re.compile(r"[0-9a-f]{32}\Z")


class BrokerPipeError(RuntimeError):
    pass


class PeerAuthenticationError(BrokerPipeError):
    def __init__(self, message, *, fatal=False):
        super().__init__(message)
        self.fatal = fatal


@dataclass(frozen=True)
class NativePeer:
    user_sid: str
    logon_sid: str
    authentication_id: str
    pid: int
    birth: float


def _sid(value):
    import win32security
    if not isinstance(value, str) or len(value) > 184:
        raise ValueError("Invalid broker SID")
    try:
        canonical_sid = win32security.ConvertSidToStringSid(win32security.ConvertStringSidToSid(value))
    except Exception as exc:
        raise ValueError("Invalid broker SID") from exc
    if canonical_sid != value or value in {"S-1-1-0", "S-1-5-7", "S-1-5-11", "S-1-5-32-545"}:
        raise ValueError("Broker requires canonical, explicitly enrolled user/service SIDs")
    return value


def _attributes(server_sid, allowed_sids):
    import pywintypes
    import win32security
    security = pywintypes.SECURITY_ATTRIBUTES()
    security.bInheritHandle = False
    clients = "".join(f"(A;;0x{CLIENT_ACCESS:x};;;{sid})" for sid in sorted(allowed_sids))
    security.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        f"D:P(A;;GA;;;{server_sid})(A;;GA;;;SY)" + clients, 1)
    return security


def _read_frame(pipe, timeout=3.0):
    deadline = time.monotonic() + timeout
    data = bytearray()
    size = None
    while size is None or len(data) < size + 4:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Broker frame deadline exceeded")
        chunk = pipe.read(remaining)
        if not chunk:
            raise BrokerPipeError("Broker pipe closed during frame")
        data.extend(chunk)
        if size is None and len(data) >= 4:
            size = struct.unpack("!I", data[:4])[0]
            if not 1 <= size <= MAX_FRAME:
                raise BrokerPipeError("Broker frame exceeds byte bound")
        if len(data) > MAX_FRAME + 4 or (size is not None and len(data) > size + 4):
            raise BrokerPipeError("Trailing or oversized broker frame")
    return decode(bytes(data[4:]))


def _write_frame(pipe, value, timeout=3.0):
    raw = canonical(value)
    if not 1 <= len(raw) <= MAX_FRAME:
        raise BrokerPipeError("Broker frame exceeds byte bound")
    pipe.write(struct.pack("!I", len(raw)) + raw, timeout=timeout)
    return raw


def _response_receipt(response, *, raw=None):
    # This acknowledges bytes on this connection. It confers no execution or
    # response authority and is never passed to the backend dispatcher.
    if raw is None:
        raw = canonical(response)
    return dict(protocol=PROTOCOL, nonce=response["nonce"],
                received_sha256=hashlib.sha256(raw).hexdigest())


def _write_response_until_received(pipe, response, timeout=3.0):
    # A completed WriteFile only queues bytes. DisconnectNamedPipe discards
    # unread bytes, while synchronous FlushFileBuffers could wait indefinitely.
    # Retain the connection until a bounded nonce/digest receipt; write and
    # receipt together share the existing response-write deadline.
    deadline = time.monotonic() + timeout
    raw = _write_frame(pipe, response, timeout)
    expected = _response_receipt(response, raw=raw)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Broker response receipt deadline exceeded")
    receipt = _read_frame(pipe, remaining)
    if receipt != expected:
        raise BrokerPipeError("Broker response receipt identity/schema mismatch")


def _impersonate(handle):
    native = ctypes.WinDLL("advapi32", use_last_error=True).ImpersonateNamedPipeClient
    native.argtypes, native.restype = [ctypes.c_void_p], ctypes.c_bool
    if not native(int(handle)):
        raise PeerAuthenticationError("Native pipe impersonation failed")


def _revert():
    native = ctypes.WinDLL("advapi32", use_last_error=True).RevertToSelf
    native.argtypes, native.restype = [], ctypes.c_bool
    if not native():
        raise PeerAuthenticationError("Native pipe identity reversion failed; service stopping", fatal=True)


def _capture_peer(handle):
    """Called after the complete request read, on that instance's owner thread.

    The callback is never called while impersonating. A reversion failure is
    fatal to the listener/service; continuing under a client token is unsafe.
    """
    import win32api
    import win32pipe
    import win32process
    import win32security
    import win32event
    process = token = None
    try:
        _impersonate(handle)
        try:
            token = win32security.OpenThreadToken(win32api.GetCurrentThread(), 8, True)
            user = win32security.ConvertSidToStringSid(
                win32security.GetTokenInformation(token, win32security.TokenUser)[0])
            groups = win32security.GetTokenInformation(token, win32security.TokenGroups)
            logons = [win32security.ConvertSidToStringSid(sid) for sid, flags in groups
                      if flags & 0xC0000000 == 0xC0000000]
            if len(logons) != 1 or not user.startswith("S-1-") or user == "S-1-5-7":
                raise PeerAuthenticationError("Peer interactive logon identity unavailable")
            statistics = win32security.GetTokenInformation(token, win32security.TokenStatistics)
            authentication = str(statistics["AuthenticationId"])
        finally:
            try:
                if token is not None:
                    token.Close()
            finally:
                _revert()
        # Process attribution is additional evidence; the impersonated token,
        # not a username/PID field in JSON, defines the authenticated subject.
        pid = win32pipe.GetNamedPipeClientProcessId(handle)
        process = win32api.OpenProcess(0x00101000, False, pid)
        birth = win32process.GetProcessTimes(process)["CreationTime"].timestamp()
        if win32event.WaitForSingleObject(process, 0) != 258:
            raise PeerAuthenticationError("Peer process exited during identity capture")
        return NativePeer(_sid(user), logons[0], authentication, pid, birth)
    except PeerAuthenticationError:
        raise
    except Exception as exc:
        raise PeerAuthenticationError("OS peer identity could not be verified") from exc
    finally:
        if process is not None:
            process.Close()


def _native_package_string(function_name, process):
    function = getattr(ctypes.WinDLL("kernel32", use_last_error=True), function_name)
    function.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32), ctypes.c_wchar_p]
    function.restype = ctypes.c_long
    count = ctypes.c_uint32()
    if function(int(process), ctypes.byref(count), None) != 122 or not 2 <= count.value <= 4096:
        raise BrokerPipeError("Server process package identity unavailable")
    buffer = ctypes.create_unicode_buffer(count.value)
    if function(int(process), ctypes.byref(count), buffer) != 0:
        raise BrokerPipeError("Server process package identity unavailable")
    return buffer.value


def _package_path(full_name):
    function = ctypes.WinDLL("kernel32", use_last_error=True).GetPackagePathByFullName
    function.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_uint32), ctypes.c_wchar_p]
    function.restype = ctypes.c_long
    count = ctypes.c_uint32()
    if function(full_name, ctypes.byref(count), None) != 122 or not 2 <= count.value <= 32768:
        raise BrokerPipeError("Installed server package path unavailable")
    buffer = ctypes.create_unicode_buffer(count.value)
    if function(full_name, ctypes.byref(count), buffer) != 0:
        raise BrokerPipeError("Installed server package path unavailable")
    return Path(buffer.value)


def _process_image(process):
    function = ctypes.WinDLL("kernel32", use_last_error=True).QueryFullProcessImageNameW
    function.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_uint32)]
    function.restype = ctypes.c_bool
    count = ctypes.c_uint32(32768)
    buffer = ctypes.create_unicode_buffer(count.value)
    if not function(int(process), 0, buffer, ctypes.byref(count)):
        raise BrokerPipeError("Server process image unavailable")
    return Path(buffer.value)


def verify_service_process(process, pid):
    """Production client proof: live OS process + fixed SCM + pinned package."""
    from . import windows_package_identity as pins
    if not pins.EXPECTED_PACKAGE_FAMILY_NAME or not pins.EXPECTED_PACKAGE_PUBLISHER_ID:
        raise BrokerPipeError("Independent installed broker publisher/package pins are not provisioned")
    import win32service
    scm = service = None
    try:
        scm = win32service.OpenSCManager(None, None, 1)
        service = win32service.OpenService(scm, SERVICE_NAME, 0x20005)
        status = win32service.QueryServiceStatusEx(service)
        if status.get("ProcessId") != pid or status.get("CurrentState") != win32service.SERVICE_RUNNING:
            raise BrokerPipeError("Pipe server is not the fixed running SCM broker")
        from .response_service_host import verify_service_registration
        verify_service_registration(service, pid)
    finally:
        if service is not None:
            win32service.CloseServiceHandle(service)
        if scm is not None:
            win32service.CloseServiceHandle(scm)
    family = _native_package_string("GetPackageFamilyName", process)
    full = _native_package_string("GetPackageFullName", process)
    package_name = pins.EXPECTED_PACKAGE_FAMILY_NAME.rsplit("_", 1)[0]
    if (family != pins.EXPECTED_PACKAGE_FAMILY_NAME
            or not full.startswith(package_name + "_")
            or not full.endswith("_" + pins.EXPECTED_PACKAGE_PUBLISHER_ID)):
        raise BrokerPipeError("Server process MSIX identity does not match immutable publisher pins")
    package = _package_path(full)
    image = _process_image(process)
    if not image.is_relative_to(package):
        raise BrokerPipeError("Server process image is outside its OS-bound installed package")
    from .response_service_host import verify_protected_path, native_service_sid, verify_service_token
    service_sid = native_service_sid()
    verify_service_token(process, service_sid)
    verify_protected_path(package, service_sid, directory=True)
    verify_protected_path(image, service_sid, directory=False)


class PrivilegedPipeServer:
    def __init__(self, dispatch, *, server_sid, allowed_sids, endpoint=ENDPOINT):
        if os.name != "nt":
            raise BrokerPipeError("Native broker transport requires Windows")
        if not callable(dispatch) or not isinstance(endpoint, str) or not endpoint.startswith(_LOCAL_PREFIX) or len(endpoint) > 240:
            raise ValueError("Invalid fixed broker transport composition")
        self.dispatch = dispatch
        self.server_sid = _sid(server_sid)
        self.allowed_sids = frozenset(_sid(value) for value in allowed_sids)
        if not 1 <= len(self.allowed_sids) <= 64:
            raise ValueError("An explicit bounded operator SID allowlist is required")
        self.endpoint = endpoint
        self.stop_event = threading.Event()
        self.pipes, self.threads = [], []
        self.error = ""
        self.accepted = self.rejected = 0
        self._dispatch_lock = threading.RLock()

    def start(self):
        import win32file
        import win32pipe
        if self.pipes or self.stop_event.is_set():
            raise BrokerPipeError("Broker listener cannot be restarted")
        try:
            for index in range(MAX_CLIENTS):
                handle = win32pipe.CreateNamedPipe(self.endpoint,
                    3 | win32file.FILE_FLAG_OVERLAPPED | (0x80000 if index == 0 else 0),
                    0x8, MAX_CLIENTS, MAX_FRAME + 4, MAX_FRAME + 4, 1000,
                    _attributes(self.server_sid, self.allowed_sids))
                self.pipes.append(_Pipe(handle))
            for index, pipe in enumerate(self.pipes):
                thread = threading.Thread(target=self._serve, args=(pipe,), name=f"ResponseBrokerPipe-{index}", daemon=False)
                self.threads.append(thread)
                thread.start()
        except BaseException:
            self.stop()
            raise

    def _serve(self, pipe):
        import win32pipe
        try:
            while not self.stop_event.is_set():
                connected = False
                try:
                    try:
                        pipe.connect_server(0.5)
                    except TimeoutError:
                        continue
                    connected = True
                    frame = _read_frame(pipe)
                    if (set(frame) != {"protocol", "nonce", "request"} or frame["protocol"] != PROTOCOL
                            or not isinstance(frame["nonce"], str) or not _NONCE.fullmatch(frame["nonce"])
                            or not isinstance(frame["request"], dict)):
                        raise BrokerPipeError("Invalid broker request envelope")
                    peer = _capture_peer(pipe.handle)
                    if peer.user_sid not in self.allowed_sids:
                        raise PeerAuthenticationError("OS principal is outside the protected operator policy")
                    with self._dispatch_lock:
                        if self.stop_event.is_set():
                            break
                        result = self.dispatch(frame["request"], peer)
                        self.accepted += 1
                    _write_response_until_received(pipe, dict(protocol=PROTOCOL, nonce=frame["nonce"], ok=True, result=result))
                except PeerAuthenticationError as exc:
                    self.rejected += 1
                    if exc.fatal:
                        self.error = "Native identity reversion failed; service process must exit"
                        self.stop_event.set()
                        for owned in self.pipes:
                            owned.cancel()
                except (Exception,) as exc:
                    self.rejected += 1
                    if not isinstance(exc, (BrokerPipeError, LiveDebugError, OSError, TimeoutError, ValueError, PermissionError)):
                        self.error = "Broker exchange failed: " + type(exc).__name__
                finally:
                    if connected and not self.stop_event.is_set():
                        try:
                            win32pipe.DisconnectNamedPipe(pipe.handle)
                        except Exception:
                            pass
        finally:
            pipe.close()  # Native I/O/buffers retire on their non-daemon owner.

    def stop(self, timeout=3.0):
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
        if not clean and not self.error:
            self.error = "Broker shutdown pending native I/O retirement"
        return clean


class PrivilegedPipeClient:
    """Worker-only one-request connection; service proof precedes every payload."""
    def __init__(self, *, endpoint=ENDPOINT, expected_pid=None, expected_birth=None, _server_verifier=None):
        self.endpoint = endpoint
        self.expected_pid, self.expected_birth = expected_pid, expected_birth
        self._server_verifier = _server_verifier or verify_service_process
        self.server_identity = None

    def exchange(self, request, timeout=3.0):
        if os.name != "nt":
            raise BrokerPipeError("Native broker transport requires Windows")
        import win32api
        import win32file
        import win32pipe
        import win32process
        import win32event
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 30:
            raise ValueError("Broker timeout must be finite and at most 30 seconds")
        if not isinstance(request, dict) or len(canonical(request)) > MAX_FRAME - 512:
            raise BrokerPipeError("Invalid bounded broker request")
        if (not isinstance(self.endpoint, str) or not self.endpoint.startswith(_LOCAL_PREFIX)
                or len(self.endpoint) > 240):
            raise BrokerPipeError("Only a local native pipe endpoint is permitted")
        win32pipe.WaitNamedPipe(self.endpoint, max(1, min(30000, int(timeout * 1000))))
        handle = win32file.CreateFile(self.endpoint, CLIENT_ACCESS, 0, None, 3,
            win32file.FILE_FLAG_OVERLAPPED | 0x100000 | 0x10000, None)  # SQOS + identification only.
        pipe, process = _Pipe(handle), None
        try:
            pid = win32pipe.GetNamedPipeServerProcessId(handle)
            if self.expected_pid is not None and pid != self.expected_pid:
                raise BrokerPipeError("OS broker PID differs from expected identity")
            process = win32api.OpenProcess(0x00101000, False, pid)
            birth = win32process.GetProcessTimes(process)["CreationTime"].timestamp()
            if (self.expected_birth is not None and (type(self.expected_birth) not in (int, float)
                    or not math.isfinite(self.expected_birth) or abs(birth - self.expected_birth) > 0.001)):
                raise BrokerPipeError("OS broker creation time differs from expected identity")
            self._server_verifier(process, pid)
            if win32event.WaitForSingleObject(process, 0) != 258:
                raise BrokerPipeError("Verified broker process has exited")
            self.server_identity = dict(pid=pid, birth=birth)
            nonce = secrets.token_hex(16)
            _write_frame(pipe, dict(protocol=PROTOCOL, nonce=nonce, request=request), timeout)
            response_deadline = time.monotonic() + timeout
            response = _read_frame(pipe, timeout)
            if (set(response) != {"protocol", "nonce", "ok", "result"}
                    or response["protocol"] != PROTOCOL or response["nonce"] != nonce
                    or response["ok"] is not True or not isinstance(response["result"], dict)):
                raise BrokerPipeError("Broker response identity/schema mismatch")
            remaining = response_deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Broker response receipt deadline exceeded")
            _write_frame(pipe, _response_receipt(response), remaining)
            return response["result"]
        finally:
            pipe.close()  # Synchronous caller owns retirement; never free a pending OVERLAPPED.
            if process is not None:
                process.Close()
