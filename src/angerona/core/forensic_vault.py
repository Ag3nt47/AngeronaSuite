"""Bounded authenticated forensic evidence; current-user DPAPI wrapped keys.

Automatic capture writes ciphertext only. Explicit operator export is the sole
plaintext path. This protects copied evidence at rest, not against the same
compromised user or kernel, and does not guarantee erasure of Python RAM copies.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import math
import os
import secrets
import shutil
import stat
import struct
import threading
import time
from pathlib import Path

MAGIC = b"ANGERONA-FORENSIC-VAULT-1\n"
SCHEMA = "angerona.forensic-vault.v1"
MAX_HEADER = 24 * 1024
MAX_FRAME = 64 * 1024
MAX_FRAMES = 2048
MAX_PLAINTEXT = 9 * 1024 * 1024
MAX_VAULT_BYTES = 10 * 1024 * 1024
MIN_FREE_BYTES = 64 * 1024 * 1024
_KINDS = {"memory": 1, "sockets": 2, "receipt": 3}
_ENTROPY = b"Angerona/forensic-vault/current-user/v1\0"
_RETIREMENT_HOLDS: dict[int, tuple[object, str]] = {}
_RETIREMENT_LOCK = threading.Lock()


class ForensicVaultError(RuntimeError):
    """Evidence encryption, custody, capacity or verification is unavailable."""


def retain_retirement_hold(owner: object, kind: str) -> None:
    """Keep one ambiguous owner for diagnostics, never retry its raw handle.

    A failed close can mean the numeric value has already been recycled. Only
    automatic forensic capture is inhibited; normal Core exit remains allowed
    and lets the OS retire any still-owned handles.
    """
    if kind not in {"directory", "process", "artifact"}:
        raise ValueError("unsupported forensic custody kind")
    with _RETIREMENT_LOCK:
        _RETIREMENT_HOLDS.setdefault(id(owner), (owner, kind))


def retirement_snapshot() -> dict:
    """Memory-only coverage facts, with no handles, paths or native probes."""
    with _RETIREMENT_LOCK:
        kinds = tuple(kind for _owner, kind in _RETIREMENT_HOLDS.values())
    return {"capture_held": bool(kinds), "ambiguous_owners": len(kinds),
            "resource_kinds": tuple(sorted(set(kinds))),
            "reason": "Forensic native handle retirement is unverified; restart Angerona before another capture" if kinds else "",
            "scope": "Forensic capture only; does not hold other modules or normal shutdown"}


def require_capture_custody() -> None:
    state = retirement_snapshot()
    if state["capture_held"]:
        raise ForensicVaultError(state["reason"])


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _json(raw: bytes) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ForensicVaultError("duplicate evidence metadata")
            result[key] = value
        return result
    try:
        result = json.loads(raw.decode("ascii"), object_pairs_hook=unique,
                            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ForensicVaultError("invalid evidence metadata") from exc
    if type(result) is not dict:
        raise ForensicVaultError("evidence metadata is not an object")
    return result


def _unsafe(info) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def _file_identity(info) -> tuple:
    return info.st_dev, info.st_ino


class DirectoryPins:
    """Pin every existing directory; Windows handles deny rename/delete."""

    def __init__(self, directory: Path):
        self.path = Path(os.path.abspath(directory))
        self._held: list = []
        self._named: list = []
        self._kernel = None
        self._ambiguous_handles: tuple = ()
        self._close_failed = False
        parts = (*reversed(self.path.parents), self.path)
        if len(parts) > 40 or len(str(self.path)) > 4096:
            raise ForensicVaultError("evidence directory depth/path budget exceeded")
        try:
            if os.name == "nt":
                import ctypes
                from ctypes import wintypes
                self._kernel = ctypes.WinDLL("kernel32", use_last_error=True)
                self._kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                    ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
                self._kernel.CreateFileW.restype = wintypes.HANDLE
                self._kernel.CloseHandle.argtypes = [wintypes.HANDLE]
                self._kernel.CloseHandle.restype = wintypes.BOOL
                self._kernel.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
                self._kernel.GetFileInformationByHandle.restype = wintypes.BOOL
                self._kernel.GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                                                     ctypes.c_void_p, wintypes.DWORD]
                self._kernel.GetFileInformationByHandleEx.restype = wintypes.BOOL
            for part in parts:
                before = part.lstat()
                if not stat.S_ISDIR(before.st_mode) or _unsafe(before):
                    raise ForensicVaultError("evidence directory is an alias or non-directory")
                if self._kernel is not None:
                    import ctypes
                    # Include LIST_DIRECTORY. Attribute-only opens can be
                    # exempt from Windows' rename/delete sharing checks.
                    handle = self._kernel.CreateFileW(str(part), 0x1 | 0x80, 0x1 | 0x2, None, 3,
                                                     0x02000000 | 0x00200000, None)
                    if handle in (None, ctypes.c_void_p(-1).value):
                        raise ForensicVaultError("evidence directory custody unavailable")
                    self._held.append(handle)
                    info = ctypes.create_string_buffer(52)
                    if not self._kernel.GetFileInformationByHandle(handle, info):
                        raise ForensicVaultError("evidence directory handle cannot be verified")
                    attrs = struct.unpack_from("<I", info.raw)[0]
                    file_id = ctypes.create_string_buffer(24)
                    if not self._kernel.GetFileInformationByHandleEx(handle, 18, file_id, 24):
                        raise ForensicVaultError("evidence directory full file identity unavailable")
                    volume, object_id = struct.unpack("<Q16s", file_id.raw)
                    identity = (volume, int.from_bytes(object_id, "little"))
                    if attrs & 0x400 or not attrs & 0x10 or identity != _file_identity(before):
                        raise ForensicVaultError("evidence directory changed during native pin")
                self._named.append((part, _file_identity(before)))
                self.check()
        except BaseException:
            self.close()
            raise

    def check(self) -> None:
        for path, identity in self._named:
            current = path.lstat()
            if _unsafe(current) or not stat.S_ISDIR(current.st_mode) or _file_identity(current) != identity:
                raise ForensicVaultError("evidence directory identity changed")

    def close(self) -> None:
        if self._close_failed:
            raise ForensicVaultError("evidence directory handle retirement remains unverified")
        held, self._held = self._held, []
        ambiguous = []
        if self._kernel is not None:
            for handle in reversed(held):
                try:
                    if not self._kernel.CloseHandle(handle):
                        ambiguous.append(handle)
                except BaseException:
                    ambiguous.append(handle)
        if ambiguous:
            self._ambiguous_handles = tuple(ambiguous)
            self._close_failed = True
            retain_retirement_hold(self, "directory")
            raise ForensicVaultError("evidence directory handle retirement unavailable")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


def _protected_key(key: bytes, entropy: bytes, protect=None, unprotect=None) -> bytes:
    if protect is None or unprotect is None:
        from angerona.modules.hardware_crypto import protect as wrap, unprotect as unwrap
        protect, unprotect = protect or wrap, unprotect or unwrap
    wrapped = protect(key, entropy)
    if type(wrapped) is not bytes or not 1 <= len(wrapped) <= 16 * 1024:
        raise ForensicVaultError("current-user DPAPI key wrapping unavailable; capture held")
    restored = unprotect(wrapped, entropy)
    if type(restored) is not bytes or not hmac.compare_digest(restored, key):
        raise ForensicVaultError("current-user DPAPI key recovery did not verify; capture held")
    return wrapped


def verify_key_wrapping() -> None:
    """Probe required crypto without creating a case or touching source data."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = secrets.token_bytes(32)
    AESGCM(key)
    _protected_key(key, _ENTROPY + b"availability-probe")


class ForensicVaultWriter:
    """Exclusive ciphertext stream with bounded frames and terminal receipt."""

    def __init__(self, path: Path, *, pid: int, birth_ticks: int, deadline: float,
                 _protect=None, _unprotect=None, _clock=time.monotonic):
        if (type(pid) is not int or not 0 < pid <= 0xFFFFFFFF or type(birth_ticks) is not int
                or not 116444736000000000 < birth_ticks <= 0xFFFFFFFFFFFFFFFF):
            raise ForensicVaultError("invalid native evidence identity")
        self.path = Path(os.path.abspath(path))
        self._clock, self.deadline = _clock, deadline
        self._last_now = _clock()
        if (type(self._last_now) not in {int, float} or not math.isfinite(self._last_now)
                or self._last_now < 0 or type(deadline) not in {int, float}
                or not math.isfinite(deadline) or self._last_now >= deadline):
            raise ForensicVaultError("invalid evidence clock or deadline")
        self._file = None
        self._pins = None
        self._count = 0
        self._plain_bytes = 0
        self._written = 0
        self._hash = hashlib.sha256()
        self._finished = False
        self._poisoned = False
        self._close_attempted = False
        self._ambiguous_stream = None
        self._key = secrets.token_bytes(32)
        self._prefix = secrets.token_bytes(8)
        case_id = secrets.token_hex(16)
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            entropy = _ENTROPY + case_id.encode("ascii")
            wrapped = _protected_key(self._key, entropy, _protect, _unprotect)
            header = {"schema": SCHEMA, "case_id": case_id, "pid": pid, "birth_ticks": birth_ticks,
                      "key_wrap": "DPAPI-current-user", "wrapped_key": base64.b64encode(wrapped).decode("ascii"),
                      "nonce_prefix": self._prefix.hex(), "not_full_memory_dump": True}
            raw = _canonical(header)
            if len(raw) > MAX_HEADER:
                raise ForensicVaultError("encrypted evidence header exceeds budget")
            self._cipher = AESGCM(self._key)
            self.header = header
            self._aad = hashlib.sha256(raw).digest()
            self._pins = DirectoryPins(self.path.parent)
            self._check()
            descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
                                 | getattr(os, "O_NOFOLLOW", 0), 0o600)
            self._file = os.fdopen(descriptor, "wb", buffering=0)
            self._identity = _file_identity(os.fstat(self._file.fileno()))
            self._check_file()
            self._write(MAGIC + struct.pack(">I", len(raw)) + raw)
        except BaseException:
            self.close()
            raise

    def _check(self):
        now = self._clock()
        if (type(now) not in {int, float} or not math.isfinite(now) or now < self._last_now
                or type(self.deadline) not in {int, float} or not math.isfinite(self.deadline) or now >= self.deadline):
            raise ForensicVaultError("evidence deadline expired or clock regressed")
        self._last_now = now
        if self._pins is not None:
            self._pins.check()
        if shutil.disk_usage(self.path.parent).free < MIN_FREE_BYTES + MAX_VAULT_BYTES:
            raise ForensicVaultError("evidence free-space reserve unavailable")

    def _check_file(self):
        self._check()
        held, named = os.fstat(self._file.fileno()), self.path.lstat()
        if (not stat.S_ISREG(held.st_mode) or held.st_nlink != 1 or named.st_nlink != 1
                or _unsafe(held) or _unsafe(named) or _file_identity(held) != self._identity
                or _file_identity(named) != self._identity):
            raise ForensicVaultError("encrypted evidence artifact custody changed")

    def _write(self, raw):
        self._check_file()
        if self._written + len(raw) > MAX_VAULT_BYTES:
            raise ForensicVaultError("encrypted evidence byte budget exhausted")
        if self._file.write(raw) != len(raw):
            raise ForensicVaultError("short encrypted evidence write")
        self._written += len(raw)

    def append(self, kind: str, data: bytes):
        if self._poisoned:
            raise ForensicVaultError("encrypted evidence writer is poisoned; partial ciphertext retained")
        if self._finished or kind not in _KINDS or kind == "receipt" or type(data) is not bytes:
            raise ForensicVaultError("invalid encrypted evidence frame")
        for offset in range(0, len(data), MAX_FRAME - 1):
            chunk = data[offset:offset + MAX_FRAME - 1]
            if self._plain_bytes + len(chunk) > MAX_PLAINTEXT or self._count >= MAX_FRAMES - 1:
                raise ForensicVaultError("encrypted evidence frame/plaintext budget exhausted")
            self._frame(bytes([_KINDS[kind]]) + chunk)
            self._plain_bytes += len(chunk)

    def _frame(self, plain: bytes):
        if self._poisoned:
            raise ForensicVaultError("encrypted evidence writer is poisoned; partial ciphertext retained")
        # Reserve this nonce before any encryption/write attempt. An exception
        # can leave ciphertext on disk without advancing the completed count;
        # that key/nonce must never encrypt a later terminal or retry frame.
        self._poisoned = True
        sequence = struct.pack(">I", self._count)
        ciphertext = self._cipher.encrypt(self._prefix + sequence, plain, self._aad + sequence)
        frame = struct.pack(">I", len(ciphertext)) + ciphertext
        self._write(frame)
        self._hash.update(frame)
        self._count += 1
        self._poisoned = False

    def finish(self, receipt: dict) -> dict:
        if self._poisoned:
            raise ForensicVaultError("encrypted evidence writer is poisoned; partial ciphertext retained")
        if self._finished or type(receipt) is not dict or type(receipt.get("complete")) is not bool:
            raise ForensicVaultError("invalid terminal evidence receipt")
        terminal = {"schema": SCHEMA, "frames": self._count, "ciphertext_sha256": self._hash.hexdigest(),
                    "plaintext_bytes": self._plain_bytes, "capture": receipt}
        raw = _canonical(terminal)
        if len(raw) > MAX_FRAME - 1:
            raise ForensicVaultError("terminal evidence receipt exceeds budget")
        self._frame(bytes([_KINDS["receipt"]]) + raw)
        self._check_file()
        self._file.flush()
        os.fsync(self._file.fileno())
        self._check_file()
        self._finished = True
        return terminal

    def close(self):
        if self._close_attempted:
            if self._ambiguous_stream is not None:
                raise ForensicVaultError("evidence artifact retirement remains unverified")
            return
        self._close_attempted = True
        try:
            if self._file is not None:
                stream, self._file = self._file, None
                try:
                    stream.close()
                except BaseException as exc:
                    self._ambiguous_stream = stream
                    retain_retirement_hold(self, "artifact")
                    raise ForensicVaultError("evidence artifact retirement unavailable") from exc
        finally:
            try:
                if self._pins is not None:
                    pins, self._pins = self._pins, None
                    pins.close()
            finally:
                self._key = b""
                self._cipher = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


def read_vault(path: Path, *, _unprotect=None) -> dict:
    """Authenticate a bounded entire vault before returning plaintext in RAM."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from angerona.modules.hardware_crypto import unprotect
    path = Path(os.path.abspath(path))
    with DirectoryPins(path.parent):
        before = path.lstat()
        if _unsafe(before) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_VAULT_BYTES:
            raise ForensicVaultError("unsafe or oversized evidence artifact")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            held = os.fstat(stream.fileno())
            if _file_identity(held) != _file_identity(before):
                raise ForensicVaultError("evidence artifact changed before verification")
            raw = stream.read(MAX_VAULT_BYTES + 1)
            after = os.fstat(stream.fileno())
            named = path.lstat()
            if (len(raw) > MAX_VAULT_BYTES or len(raw) != held.st_size or held.st_size != after.st_size
                    or held.st_mtime_ns != after.st_mtime_ns or _file_identity(named) != _file_identity(held)
                    or named.st_size != after.st_size or named.st_mtime_ns != after.st_mtime_ns
                    or named.st_nlink != 1 or _unsafe(named)):
                raise ForensicVaultError("evidence artifact changed during verification")
    try:
        if not raw.startswith(MAGIC):
            raise ForensicVaultError("not an encrypted forensic vault")
        offset = len(MAGIC)
        header_length = struct.unpack_from(">I", raw, offset)[0]
        offset += 4
        if not 1 <= header_length <= MAX_HEADER:
            raise ForensicVaultError("invalid evidence header size")
        header_raw = raw[offset:offset + header_length]
        offset += header_length
        header = _json(header_raw)
        if (set(header) != {"schema", "case_id", "pid", "birth_ticks", "key_wrap", "wrapped_key", "nonce_prefix", "not_full_memory_dump"}
                or header["schema"] != SCHEMA or header["key_wrap"] != "DPAPI-current-user"
                or type(header["case_id"]) is not str or len(header["case_id"]) != 32
                or any(char not in "0123456789abcdef" for char in header["case_id"])):
            raise ForensicVaultError("unsupported forensic vault header")
        if (type(header["pid"]) is not int or not 0 < header["pid"] <= 0xFFFFFFFF
                or type(header["birth_ticks"]) is not int
                or not 116444736000000000 < header["birth_ticks"] <= 0xFFFFFFFFFFFFFFFF
                or header["not_full_memory_dump"] is not True):
            raise ForensicVaultError("invalid forensic vault process identity")
        key = (_unprotect or unprotect)(base64.b64decode(header["wrapped_key"], validate=True),
                                      _ENTROPY + header["case_id"].encode("ascii"))
        if type(key) is not bytes or len(key) != 32:
            raise ForensicVaultError("current-user DPAPI evidence key unavailable")
        prefix = bytes.fromhex(header["nonce_prefix"])
        if len(prefix) != 8:
            raise ForensicVaultError("invalid evidence nonce prefix")
        cipher, aad = AESGCM(key), hashlib.sha256(header_raw).digest()
        digest = hashlib.sha256()
        records = {"memory": bytearray(), "sockets": bytearray()}
        count = total = 0
        terminal = None
        while offset < len(raw):
            if count >= MAX_FRAMES:
                raise ForensicVaultError("evidence frame count exceeds budget")
            start = offset
            length = struct.unpack_from(">I", raw, offset)[0]
            offset += 4
            if not 17 <= length <= MAX_FRAME + 16 or offset + length > len(raw):
                raise ForensicVaultError("truncated or oversized encrypted frame")
            sequence = struct.pack(">I", count)
            plain = cipher.decrypt(prefix + sequence, raw[offset:offset + length], aad + sequence)
            offset += length
            if plain[0] == _KINDS["receipt"]:
                terminal = _json(plain[1:])
                if (terminal.get("schema") != SCHEMA or terminal.get("frames") != count
                        or terminal.get("ciphertext_sha256") != digest.hexdigest()
                        or terminal.get("plaintext_bytes") != total or offset != len(raw)
                        or type(terminal.get("capture")) is not dict
                        or type(terminal["capture"].get("complete")) is not bool):
                    raise ForensicVaultError("terminal evidence receipt is inconsistent")
                break
            kind = next((name for name in ("memory", "sockets") if _KINDS[name] == plain[0]), None)
            total += len(plain) - 1
            if kind is None or total > MAX_PLAINTEXT:
                raise ForensicVaultError("unknown or excessive evidence content")
            records[kind].extend(plain[1:])
            digest.update(raw[start:offset])
            count += 1
        if terminal is None:
            raise ForensicVaultError("capture has no authenticated terminal receipt")
        return {"header": header, "receipt": terminal, "records": {name: bytes(value) for name, value in records.items()}}
    except ForensicVaultError:
        raise
    except Exception as exc:
        raise ForensicVaultError("encrypted evidence authentication failed") from exc


def export_vault(path: Path, destination: Path, *, operator_confirmed: bool = False) -> dict:
    """User-initiated plaintext export only, after full authentication in RAM."""
    if operator_confirmed is not True:
        raise ForensicVaultError("explicit confirmation of sensitive plaintext export is required")
    verified = read_vault(path)
    destination = Path(os.path.abspath(destination))
    with DirectoryPins(destination.parent):
        destination.mkdir(mode=0o700, exist_ok=False)
        with DirectoryPins(destination):
            outputs = {"memory-strings.txt": verified["records"]["memory"],
                       "sockets.jsonl": verified["records"]["sockets"],
                       "capture-receipt.json": _canonical(verified["receipt"]) + b"\n"}
            for name, data in outputs.items():
                descriptor = os.open(destination / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                     | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600)
                with os.fdopen(descriptor, "wb") as stream:
                    if stream.write(data) != len(data):
                        raise ForensicVaultError("sensitive export write was incomplete; partial output retained")
                    stream.flush()
                    os.fsync(stream.fileno())
    return {"exported": True, "destination": str(destination), "complete_capture": verified["receipt"]["capture"]["complete"]}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Authenticate encrypted forensic evidence; explicitly export sensitive plaintext.")
    parser.add_argument("vault", type=Path)
    parser.add_argument("--export", type=Path, metavar="NEW_DIRECTORY")
    parser.add_argument("--confirm-sensitive-plaintext", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.export is not None:
            result = export_vault(args.vault, args.export, operator_confirmed=args.confirm_sensitive_plaintext)
        else:
            verified = read_vault(args.vault)
            result = {"verified": True, "header": {key: value for key, value in verified["header"].items()
                                                   if key not in {"wrapped_key", "nonce_prefix"}}, "receipt": verified["receipt"]}
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except Exception as exc:
        print(f"Forensic review held: {type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
