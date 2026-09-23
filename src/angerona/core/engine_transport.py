"""Bounded, mutually authenticated local IPC for the ordinary-user engine.

The private discovery record is a same-user credential, not a privilege grant.
No pickle, HTTP, shell, dynamic method dispatch, or arbitrary file requests are
accepted. Every connection has a fresh server challenge and one response.
"""
from __future__ import annotations

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

PROTOCOL = "angerona-local-engine-v1"
MAX_REQUEST = 8192
MAX_RESPONSE = 1024 * 1024
TIMEOUT = 3.0


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


def _read(sock: socket.socket, count: int) -> bytes:
    output = bytearray()
    deadline = time.monotonic() + TIMEOUT
    while len(output) < count:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise EngineError("Engine read deadline exceeded")
        sock.settimeout(remaining)
        chunk = sock.recv(count - len(output))
        if not chunk:
            raise EngineError("Engine connection closed")
        output.extend(chunk)
    return bytes(output)


def receive(sock: socket.socket, limit: int) -> dict:
    size = struct.unpack("!I", _read(sock, 4))[0]
    if not 1 <= size <= limit:
        raise EngineError("Engine message exceeds its byte limit")
    return decode(_read(sock, size))


def send(sock: socket.socket, message: dict, limit: int) -> None:
    payload = canonical(message)
    if len(payload) > limit:
        raise EngineError("Engine message exceeds its byte limit")
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def _mac(key: bytes, domain: bytes, body: dict) -> str:
    return hmac.new(key, domain + canonical(body), hashlib.sha256).hexdigest()


def _verify(message: dict, key: bytes, domain: bytes) -> dict:
    if set(message) != {"body", "mac"} or not isinstance(message["body"], dict):
        raise EngineError("Invalid authenticated envelope")
    signature = message["mac"]
    if (not isinstance(signature, str) or len(signature) != 64
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


def private_directory(path: Path) -> Path:
    if not path.exists():
        if os.name == "nt":
            import pywintypes
            import win32file
            import win32security
            sid = win32security.ConvertSidToStringSid(_windows_identity())
            attributes = pywintypes.SECURITY_ATTRIBUTES()
            attributes.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
                f"O:{sid}D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", 1)
            try:
                win32file.CreateDirectory(str(path), attributes)
            except pywintypes.error as exc:
                if exc.winerror != 183:
                    raise
        else:
            path.mkdir(mode=0o700, exist_ok=True)
    verify_private(path, directory=True)
    return path


def write_discovery(directory: Path, record: dict) -> None:
    verify_private(directory, directory=True)
    path = directory / (".endpoint-" + secrets.token_hex(12))
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
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
    """At most four authenticated exchanges; one request per connection."""

    def __init__(self, directory: Path, dispatch: Callable[[dict], dict]):
        self.directory = private_directory(directory)
        self.dispatch = dispatch
        self.instance = secrets.token_hex(16)
        self.key = secrets.token_bytes(32)
        self.stop_event = threading.Event()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if os.name == "nt":
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(4)
        self.socket.settimeout(0.25)
        self.slots = threading.BoundedSemaphore(4)
        self.thread = threading.Thread(target=self._loop, name="EngineIPC", daemon=True)

    def start(self) -> None:
        import psutil
        write_discovery(self.directory, {
            "protocol": PROTOCOL, "port": self.socket.getsockname()[1],
            "instance": self.instance, "key": self.key.hex(), "pid": os.getpid(),
            "created": psutil.Process().create_time(),
        })
        self.thread.start()

    def _loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                client, _address = self.socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not self.slots.acquire(blocking=False):
                client.close()
                continue
            threading.Thread(target=self._serve, args=(client,),
                             name="EngineExchange", daemon=True).start()

    def _serve(self, client: socket.socket) -> None:
        try:
            with client:
                client.settimeout(TIMEOUT)
                challenge = secrets.token_hex(32)
                send(client, {"protocol": PROTOCOL, "instance": self.instance,
                              "challenge": challenge}, MAX_REQUEST)
                request = _verify(receive(client, MAX_REQUEST), self.key, b"request\0")
                if (set(request) != {"instance", "challenge", "nonce", "request"}
                        or request["instance"] != self.instance
                        or request["challenge"] != challenge
                        or not isinstance(request["nonce"], str) or len(request["nonce"]) != 32
                        or not isinstance(request["request"], dict)):
                    raise EngineError("Engine exchange identity mismatch")
                try:
                    result = self.dispatch(request["request"])
                    body = {"ok": True, "result": result}
                except (EngineError, ValueError, KeyError):
                    body = {"ok": False, "error": "Request rejected: invalid operation or parameters"}
                except Exception:
                    body = {"ok": False, "error": "Engine operation failed; inspect engine health"}
                body.update(instance=self.instance, nonce=request["nonce"], challenge=challenge)
                send(client, _wrap(body, self.key, b"response\0"), MAX_RESPONSE)
        except (OSError, EngineError):
            pass
        finally:
            self.slots.release()

    def close(self) -> None:
        self.stop_event.set()
        self.socket.close()
        if self.thread.ident is not None:
            self.thread.join(timeout=1.0)
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
            hello = receive(client, MAX_REQUEST)
            if (set(hello) != {"protocol", "instance", "challenge"}
                    or hello["protocol"] != PROTOCOL or hello["instance"] != record["instance"]
                    or not isinstance(hello["challenge"], str) or len(hello["challenge"]) != 64):
                raise EngineError("Engine challenge identity mismatch")
            send(client, _wrap({"instance": record["instance"], "challenge": hello["challenge"],
                                "nonce": nonce, "request": request}, key, b"request\0"), MAX_REQUEST)
            body = _verify(receive(client, MAX_RESPONSE), key, b"response\0")
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
