"""Bounded, mutually authenticated local IPC for the ordinary-user engine.

The private discovery record is a same-user credential, not a privilege grant.
No pickle, HTTP, shell, dynamic method dispatch, or arbitrary file requests are
accepted. Every connection has two fresh nonces and server proof before a
client-authenticated request; version 1 is not accepted.
"""
from __future__ import annotations

import errno
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import socket
import stat
import struct
import threading
import time
from typing import Callable

PROTOCOL = "angerona-local-engine-v2"
MAX_REQUEST = 8192
MAX_RESPONSE = 1024 * 1024
TIMEOUT = 3.0
PREAUTH_TIMEOUT = 1.0
MAX_HELLO = 512
MAX_PREAUTH = 8
MAX_EXCHANGES = 4
_HELLO_DOMAIN = b"engine-v2-server-hello\0"
_REQUEST_DOMAIN = b"engine-v2-request\0"
_RESPONSE_DOMAIN = b"engine-v2-response\0"


class EngineError(RuntimeError):
    pass


def canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False,
                          sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise EngineError("Invalid engine message") from exc


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EngineError("Duplicate engine message field")
        result[key] = value
    return result


def decode(raw: bytes) -> dict:
    try:
        value = json.loads(raw, object_pairs_hook=_unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise EngineError("Invalid engine JSON") from exc
    if not isinstance(value, dict):
        raise EngineError("Engine message must be an object")
    return value


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise EngineError("Engine exchange deadline exceeded")
    return remaining


def _read(sock: socket.socket, count: int, *, deadline: float | None = None) -> bytes:
    output = bytearray()
    deadline = time.monotonic() + TIMEOUT if deadline is None else deadline
    while len(output) < count:
        sock.settimeout(_remaining(deadline))
        chunk = sock.recv(count - len(output))
        if not chunk:
            raise EngineError("Engine connection closed")
        _remaining(deadline)
        output.extend(chunk)
    return bytes(output)


def receive(sock: socket.socket, limit: int, *, deadline: float | None = None) -> dict:
    deadline = time.monotonic() + TIMEOUT if deadline is None else deadline
    size = struct.unpack("!I", _read(sock, 4, deadline=deadline))[0]
    if not 1 <= size <= limit:
        raise EngineError("Engine message exceeds its byte limit")
    return decode(_read(sock, size, deadline=deadline))


def send(sock: socket.socket, message: dict, limit: int, *, deadline: float | None = None) -> None:
    payload = canonical(message)
    if len(payload) > limit:
        raise EngineError("Engine message exceeds its byte limit")
    sock.settimeout(_remaining(time.monotonic() + TIMEOUT if deadline is None else deadline))
    sock.sendall(struct.pack("!I", len(payload)) + payload)
    if deadline is not None:
        _remaining(deadline)


def _nonce(value: object, length: int) -> bool:
    return type(value) is str and len(value) == length and all(char in "0123456789abcdef" for char in value)


def _mac(key: bytes, domain: bytes, body: dict) -> str:
    return hmac.new(key, domain + canonical(body), hashlib.sha256).hexdigest()


def _verify(message: dict, key: bytes, domain: bytes) -> dict:
    if set(message) != {"body", "mac"} or not isinstance(message["body"], dict):
        raise EngineError("Invalid authenticated envelope")
    signature = message["mac"]
    if (not _nonce(signature, 64)
            or not hmac.compare_digest(signature, _mac(key, domain, message["body"]))):
        raise EngineError("Engine authentication failed")
    return message["body"]


def _wrap(body: dict, key: bytes, domain: bytes) -> dict:
    return {"body": body, "mac": _mac(key, domain, body)}


def _windows_identity():
    import win32api
    import win32security
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), 8)
    try:
        return win32security.GetTokenInformation(token, win32security.TokenUser)[0]
    finally:
        token.Close()


def verify_private(path: Path, *, directory: bool = False) -> None:
    info = path.lstat()
    if (stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 0x400
            or (not directory and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1))
            or (directory and not stat.S_ISDIR(info.st_mode))):
        raise EngineError("Unsafe engine state path")
    if os.name != "nt":
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise EngineError("Engine state must be private to this user")
        return
    import win32security
    descriptor = win32security.GetFileSecurity(
        str(path), win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION)
    identity = _windows_identity()
    if descriptor.GetSecurityDescriptorOwner() != identity:
        raise EngineError("Engine state owner does not match this user")
    acl = descriptor.GetSecurityDescriptorDacl()
    if acl is None:
        raise EngineError("Engine state has no DACL")
    trusted = {win32security.ConvertSidToStringSid(identity), "S-1-5-18", "S-1-5-32-544"}
    for index in range(acl.GetAceCount()):
        ace = acl.GetAce(index)
        if ace[0][0] != win32security.ACCESS_DENIED_ACE_TYPE:
            if (ace[0][0] != win32security.ACCESS_ALLOWED_ACE_TYPE
                    or win32security.ConvertSidToStringSid(ace[2]) not in trusted):
                raise EngineError("Engine state grants access outside this user boundary")


def _windows_private_attributes(*, directory: bool = False):
    import pywintypes
    import win32security
    sid = win32security.ConvertSidToStringSid(_windows_identity())
    inherit = "OICI" if directory else ""
    attributes = pywintypes.SECURITY_ATTRIBUTES()
    attributes.bInheritHandle = False
    attributes.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        f"O:{sid}D:P(A;{inherit};FA;;;{sid})(A;{inherit};FA;;;SY)(A;{inherit};FA;;;BA)", 1)
    return attributes


def private_directory(path: Path) -> Path:
    if not path.exists():
        if os.name == "nt":
            import pywintypes
            import win32file
            try:
                win32file.CreateDirectory(str(path), _windows_private_attributes(directory=True))
            except pywintypes.error as exc:
                if exc.winerror != 183:
                    raise
        else:
            path.mkdir(mode=0o700, exist_ok=True)
    verify_private(path, directory=True)
    return path


def create_private_file(path: Path) -> int:
    """Exclusively create a user-owned binary file; return its verified writable fd.

    Windows inherits a directory's DACL, but selects the file owner from the
    token. Elevated tokens can default to Administrators instead of TokenUser,
    so supply both the owner and protected DACL atomically at creation.
    """
    verify_private(path.parent, directory=True)
    flags = os.O_WRONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
    if os.name == "nt":
        import msvcrt
        import pywintypes
        import win32con
        import win32file
        try:
            handle = win32file.CreateFile(
                str(path), win32con.GENERIC_WRITE, win32con.FILE_SHARE_READ,
                _windows_private_attributes(), win32con.CREATE_NEW,
                win32con.FILE_ATTRIBUTE_NORMAL, None)
        except pywintypes.error as exc:
            if exc.winerror in (80, 183):
                raise FileExistsError(errno.EEXIST, "Private engine state already exists", str(path)) from exc
            raise
        try:
            descriptor = msvcrt.open_osfhandle(int(handle), flags)
            handle.Detach()  # The CRT descriptor now owns the native handle.
        finally:
            handle.Close()
    else:
        descriptor = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        verify_private(path)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def write_discovery(directory: Path, record: dict) -> None:
    verify_private(directory, directory=True)
    path = directory / (".endpoint-" + secrets.token_hex(12))
    descriptor = create_private_file(path)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical(record))
            stream.flush()
            os.fsync(stream.fileno())
        verify_private(path)
        os.replace(path, directory / "endpoint.json")
    finally:
        path.unlink(missing_ok=True)


def read_discovery(directory: Path) -> dict:
    verify_private(directory, directory=True)
    path = directory / "endpoint.json"
    verify_private(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        before = path.lstat()
        held = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino) != (held.st_dev, held.st_ino):
            raise EngineError("Engine discovery changed during read")
        raw = stream.read(4097)
    if len(raw) > 4096:
        raise EngineError("Oversized engine discovery")
    record = decode(raw)
    if set(record) != {"protocol", "port", "instance", "key", "pid", "created"}:
        raise EngineError("Invalid engine discovery schema")
    if (record["protocol"] != PROTOCOL or type(record["port"]) is not int
            or not 1 <= record["port"] <= 65535 or type(record["pid"]) is not int
            or record["pid"] <= 0 or not isinstance(record["created"], (int, float))):
        raise EngineError("Invalid engine discovery identity")
    for key, size in (("key", 64), ("instance", 32)):
        if not isinstance(record[key], str) or len(record[key]) != size:
            raise EngineError("Invalid engine discovery credential")
        try:
            bytes.fromhex(record[key])
        except ValueError as exc:
            raise EngineError("Invalid engine discovery credential") from exc
    return record


class EngineServer:
    """Finite unauthenticated admission is separate from authenticated dispatch.

    Loopback floods can still deny availability. This boundary limits retained
    resources and prevents idle peers from occupying the four dispatch slots.
    """

    def __init__(self, directory: Path, dispatch: Callable[[dict], dict]):
        self.directory = private_directory(directory)
        self.dispatch = dispatch
        self.instance = secrets.token_hex(16)
        self.key = secrets.token_bytes(32)
        self.stop_event = threading.Event()
        self._lock = threading.RLock()
        self._clients: set[socket.socket] = set()
        self._unclosed_clients: set[socket.socket] = set()
        self._closing_clients: set[socket.socket] = set()
        self._workers: set[threading.Thread] = set()
        self._preauth_active = self._dispatch_active = 0
        self._rejected = self._worker_failures = 0
        self.last_error = ""
        self._retirement_error = ""
        self._listener_failed = False
        self._listener_close_attempted = False
        self.preauth_slots = threading.BoundedSemaphore(MAX_PREAUTH)
        self.slots = threading.BoundedSemaphore(MAX_EXCHANGES)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if os.name == "nt":
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            self.socket.bind(("127.0.0.1", 0))
            self.socket.listen(MAX_PREAUTH)
            self.socket.settimeout(0.25)
        except BaseException:
            self.socket.close()
            raise
        self.thread = threading.Thread(target=self._loop, name="EngineIPC", daemon=True)

    def admission_snapshot(self) -> dict:
        with self._lock:
            pending = sum(thread.is_alive() for thread in self._workers)
            listener_pending = self.stop_event.is_set() and self.thread.is_alive()
            busy = (self._preauth_active >= MAX_PREAUTH or self._dispatch_active >= MAX_EXCHANGES
                    or bool(self._closing_clients))
            if self._retirement_error or self._worker_failures or self._listener_failed:
                reason = self._retirement_error or self.last_error
            else:
                reason = "Engine admission capacity is busy; retry is required" if busy else ""
            return {"state": "held" if self._retirement_error else
                    "closing" if self.stop_event.is_set() and (pending or self._closing_clients or listener_pending) else
                    "closed" if self.stop_event.is_set() else
                    "degraded" if self._worker_failures or self._listener_failed else "busy" if busy else "ready",
                    "preauth_pending": self._preauth_active,
                    "authenticated_pending": self._dispatch_active,
                    "preauth_limit": MAX_PREAUTH, "dispatch_limit": MAX_EXCHANGES,
                    "rejected": self._rejected, "worker_start_failures": self._worker_failures,
                    "retirement_pending": pending, "listener_pending": listener_pending,
                    "closing_connections": len(self._closing_clients),
                    "unclosed_connections": len(self._unclosed_clients),
                    "reason": reason}

    def _retire_client(self, client: socket.socket, *, shutdown: bool = False) -> None:
        with self._lock:
            if (client not in self._clients or client in self._unclosed_clients
                    or client in self._closing_clients):
                return  # One exact object owner; unknown close is never retried.
            self._closing_clients.add(client)
        try:
            if shutdown:
                try:
                    client.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            client.close()
        except OSError:
            with self._lock:
                self._clients.add(client)
                self._unclosed_clients.add(client)
                self._retirement_error = "Engine connection retirement is unconfirmed; admission is held"
                self.stop_event.set()
        else:
            with self._lock:
                self._clients.discard(client)
        finally:
            with self._lock:
                self._closing_clients.discard(client)

    def start(self) -> None:
        import psutil
        try:
            write_discovery(self.directory, {
                "protocol": PROTOCOL, "port": self.socket.getsockname()[1],
                "instance": self.instance, "key": self.key.hex(), "pid": os.getpid(),
                "created": psutil.Process().create_time(),
            })
            self.thread.start()
        except BaseException:
            self.close()
            raise

    def _loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                client, _address = self.socket.accept()
            except socket.timeout:
                continue
            except OSError:
                if not self.stop_event.is_set():
                    with self._lock:
                        self._listener_failed = True
                        self.last_error = "Engine listener exited unexpectedly; control admission is unavailable"
                break
            with self._lock:
                self._clients.add(client)
            deadline = time.monotonic() + PREAUTH_TIMEOUT
            if not self.preauth_slots.acquire(blocking=False):
                with self._lock:
                    self._rejected += 1
                    self.last_error = "Engine pre-auth admission is busy; retry is required"
                self._retire_client(client)
                continue
            with self._lock:
                if self.stop_event.is_set():
                    self.preauth_slots.release()
                    self._retire_client(client)
                    break
                self._clients.add(client)
                self._preauth_active += 1
                worker = None
                try:
                    worker = threading.Thread(target=self._serve, args=(client, deadline),
                                              name="EngineExchange", daemon=True)
                    self._workers.add(worker)
                    worker.start()
                except Exception:
                    if worker is not None:
                        self._workers.discard(worker)
                    self._preauth_active -= 1
                    self.preauth_slots.release()
                    self._worker_failures += 1
                    self.last_error = "Engine admission worker could not start; exchange refused"
                    self._retire_client(client)

    def _serve(self, client: socket.socket, deadline: float | None = None) -> None:
        preauth_owned, dispatch_owned = True, False
        try:
            deadline = time.monotonic() + PREAUTH_TIMEOUT if deadline is None else deadline
            hello = receive(client, MAX_HELLO, deadline=deadline)
            if (set(hello) != {"protocol", "instance", "nonce"}
                    or hello["protocol"] != PROTOCOL or hello["instance"] != self.instance
                    or not _nonce(hello["nonce"], 32) or self.stop_event.is_set()):
                raise EngineError("Engine admission identity mismatch")
            challenge = secrets.token_hex(32)
            server_proof = dict(hello, challenge=challenge)
            send(client, _wrap(server_proof, self.key, _HELLO_DOMAIN), MAX_REQUEST, deadline=deadline)
            request = _verify(receive(client, MAX_REQUEST, deadline=deadline), self.key, _REQUEST_DOMAIN)
            if (set(request) != {"instance", "challenge", "nonce", "request"}
                    or request["instance"] != self.instance or request["challenge"] != challenge
                    or request["nonce"] != hello["nonce"] or not isinstance(request["request"], dict)):
                raise EngineError("Engine exchange identity mismatch")
            with self._lock:
                if self.stop_event.is_set():
                    raise EngineError("Engine admission is closing")
                dispatch_owned = self.slots.acquire(blocking=False)
                if dispatch_owned:
                    self._dispatch_active += 1
                else:
                    self._rejected += 1
                self._preauth_active -= 1
                self.preauth_slots.release()
                preauth_owned = False
            if not dispatch_owned:
                body = {"ok": False, "error": "Engine authenticated dispatch is busy; retry is required"}
            else:
                try:
                    result = self.dispatch(request["request"])
                    body = {"ok": True, "result": result}
                except (EngineError, ValueError, KeyError):
                    body = {"ok": False, "error": "Request rejected: invalid operation or parameters"}
                except Exception:
                    body = {"ok": False, "error": "Engine operation failed; inspect engine health"}
            body.update(instance=self.instance, nonce=request["nonce"], challenge=challenge)
            send(client, _wrap(body, self.key, _RESPONSE_DOMAIN), MAX_RESPONSE)
        except (OSError, EngineError):
            with self._lock:
                self._rejected += 1
        finally:
            self._retire_client(client)
            with self._lock:
                if preauth_owned:
                    self._preauth_active -= 1
                    self.preauth_slots.release()
                if dispatch_owned:
                    self._dispatch_active -= 1
                    self.slots.release()
                self._workers.discard(threading.current_thread())

    def close(self) -> None:
        self.stop_event.set()
        with self._lock:
            close_listener = not self._listener_close_attempted
            self._listener_close_attempted = True
        if close_listener:
            try:
                self.socket.close()
            except OSError:
                self._retirement_error = "Engine listener retirement is unconfirmed"
        with self._lock:
            clients = [client for client in self._clients if client not in self._unclosed_clients]
        for client in clients:
            self._retire_client(client, shutdown=True)
        deadline = time.monotonic() + 1.0
        current = threading.current_thread()
        if self.thread.ident is not None and self.thread is not current:
            self.thread.join(timeout=max(0.0, deadline - time.monotonic()))
        with self._lock:
            workers = list(self._workers)
        for worker in workers:
            if worker is not current:
                worker.join(timeout=max(0.0, deadline - time.monotonic()))
        try:
            if read_discovery(self.directory)["instance"] == self.instance:
                (self.directory / "endpoint.json").unlink()
        except (OSError, EngineError):
            pass


def exchange(directory: Path, request: dict) -> dict:
    record = read_discovery(directory)
    import psutil
    try:
        process = psutil.Process(record["pid"])
        if abs(process.create_time() - record["created"]) > 0.01:
            raise EngineError("Engine PID identity has changed")
    except psutil.Error as exc:
        raise EngineError("Engine process is no longer available") from exc
    key = bytes.fromhex(record["key"])
    nonce = secrets.token_hex(16)
    try:
        with socket.create_connection(("127.0.0.1", record["port"]), timeout=TIMEOUT) as client:
            deadline = time.monotonic() + PREAUTH_TIMEOUT
            send(client, {"protocol": PROTOCOL, "instance": record["instance"], "nonce": nonce},
                 MAX_HELLO, deadline=deadline)
            hello = _verify(receive(client, MAX_REQUEST, deadline=deadline), key, _HELLO_DOMAIN)
            if (set(hello) != {"protocol", "instance", "nonce", "challenge"}
                    or hello["protocol"] != PROTOCOL or hello["instance"] != record["instance"]
                    or hello["nonce"] != nonce or not _nonce(hello["challenge"], 64)):
                raise EngineError("Engine server proof identity mismatch")
            send(client, _wrap({"instance": record["instance"], "challenge": hello["challenge"],
                                "nonce": nonce, "request": request}, key, _REQUEST_DOMAIN),
                 MAX_REQUEST, deadline=deadline)
            body = _verify(receive(client, MAX_RESPONSE), key, _RESPONSE_DOMAIN)
    except OSError as exc:
        raise EngineError("Engine is unavailable; protection status is unknown") from exc
    if (body.get("instance") != record["instance"] or body.get("nonce") != nonce
            or body.get("challenge") != hello["challenge"] or type(body.get("ok")) is not bool):
        raise EngineError("Engine response identity mismatch")
    if not body["ok"]:
        raise EngineError(str(body.get("error", "Engine request failed")))
    if not isinstance(body.get("result"), dict):
        raise EngineError("Engine response result is invalid")
    return body["result"]
