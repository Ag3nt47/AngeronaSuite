"""Offline, hardware-bound integrity baseline and explicit source recovery.

The baseline is enrolled only by initialize(). Every operation requires the
passphrase and a fresh hardware unseal; neither credential nor derived key is
retained. Audit history is encrypted and tamper-evident, not rollback-proof
without a separately trusted witness. Python cannot promise complete secret
erasure or protection against a compromised kernel, interpreter, or administrator.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import stat
import sys
import threading
import time
from typing import Any, Callable
import uuid
import zlib

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from angerona.core.backup_restore import _relative

SCHEMA = "angerona.ugcap/v1"
PBKDF2_ITERATIONS = 600_000
MAX_FILES = 10_000
MAX_ENTRIES = 50_000
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_PAYLOAD_BYTES = 192 * 1024 * 1024
MAX_CONTAINER_BYTES = 260 * 1024 * 1024
MAX_AUDIT_BYTES = 8 * 1024 * 1024
MAX_AUDIT_RECORD_BYTES = 256 * 1024
MAX_AUDIT_RECORDS = 2_048
MAX_RESTORE_PATHS = 128
OPERATION_TIMEOUT_SECONDS = 120
PROTECTED_SCOPES = (
    "src", "tools", "native", "kernel", "syscall_bridge", "rules", "modules",
    "config", "playbooks", "detection-packages", "assets", "installer", "bin", "docs", "tests",
)
EXCLUSIONS = frozenset({
    ".git", ".venv", "venv", "frz", "hermetic", "runtime-data", "shared_logs",
    "shared-ipc", "diagnostics", ".tmp", "__pycache__", ".pytest_cache",
    ".ruff_cache", ".hypothesis", "node_modules", ".env", ".ugcap-recovery",
})
ROOT_SUFFIXES = frozenset({
    ".py", ".pyw", ".bat", ".cmd", ".ps1", ".sh", ".toml", ".json",
    ".yaml", ".yml", ".ini", ".cfg", ".txt", ".md", ".lock", ".exe",
    ".dll", ".pyd", ".so", ".dylib", ".sys", ".bin",
})
BINARY_SUFFIXES = frozenset({".exe", ".dll", ".pyd", ".so", ".dylib", ".sys"})


class UGCAPError(RuntimeError):
    """The vault operation failed closed."""


class VaultAuthenticationError(UGCAPError):
    """Passphrase, hardware binding, or authenticated vault content is invalid."""


class VaultCoverageError(UGCAPError):
    """The selected protected scope could not be captured completely."""


class StaleReportError(UGCAPError):
    """Recovery approval no longer names the exact current verification."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode(value: Any, maximum: int) -> bytes:
    if not isinstance(value, str) or len(value) > ((maximum + 2) // 3) * 4:
        raise VaultAuthenticationError("vault field exceeds its byte budget")
    try:
        result = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise VaultAuthenticationError("invalid vault encoding") from exc
    if len(result) > maximum:
        raise VaultAuthenticationError("vault field exceeds its byte budget")
    return result


def _wipe(value: bytearray | None) -> None:
    if value is not None:
        value[:] = b"\x00" * len(value)


def _linked(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        int(getattr(info, "st_file_attributes", 0))
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _path_chain(path: Path) -> None:
    for component in reversed((path, *path.parents)):
        try:
            info = component.lstat()
        except FileNotFoundError:
            continue
        if _linked(info):
            raise UGCAPError(f"symbolic-link or reparse path refused: {component}")


def _identity(info: os.stat_result) -> tuple:
    # Windows fstat/lstat expose different ctime semantics on supported Python
    # versions. Compare ctime only between observations of the retained fd.
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_nlink)


def _safe_relative(value: str) -> str:
    try:
        relative = _relative(value).as_posix()
    except (ValueError, TypeError) as exc:
        raise UGCAPError("unsafe protected relative path") from exc
    if relative != value or any(part.casefold() in EXCLUSIONS for part in relative.split("/")):
        raise UGCAPError("unsafe or excluded protected path")
    return relative


def _volume_id(path: Path) -> str:
    if sys.platform != "win32":
        return f"device:{path.stat().st_dev}"
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    get_mount = kernel.GetVolumePathNameW
    get_mount.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    get_mount.restype = wintypes.BOOL
    get_volume = kernel.GetVolumeNameForVolumeMountPointW
    get_volume.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    get_volume.restype = wintypes.BOOL
    mount, volume = ctypes.create_unicode_buffer(32768), ctypes.create_unicode_buffer(1024)
    if not get_mount(str(path), mount, len(mount)) or not get_volume(mount.value, volume, len(volume)):
        raise UGCAPError("could not prove the secondary volume identity")
    return volume.value.casefold()


class UGCAPVault:
    """One immutable encrypted baseline file on independently validated media."""

    def __init__(
        self, repo_root: str | Path, vault_path: str | Path, hardware: Any, *,
        hash_factory: Callable[[], Any] | None = None,
        media_validator: Callable[[Path, Path], Any] | None = None,
        clock: Callable[[], float] = time.time,
        protected_scopes: tuple[str, ...] = PROTECTED_SCOPES,
    ) -> None:
        self.repo_root = Path(os.path.abspath(Path(repo_root).expanduser()))
        self.vault_path = Path(os.path.abspath(Path(vault_path).expanduser()))
        self.audit_path = self.vault_path.with_name(self.vault_path.name + ".audit")
        self.hardware = hardware
        self._hash_factory = hash_factory
        self._media_validator = media_validator
        self._clock = clock
        self.protected_scopes = tuple(sorted({_safe_relative(value) for value in protected_scopes}))
        self._operation_lock = threading.Lock()
        self._state_lock = threading.RLock()
        self._cancel = threading.Event()
        self._last_report: dict | None = None
        self._busy = False
        self._deadline = 0.0
        if not self.protected_scopes:
            raise UGCAPError("at least one explicit protected scope is required")

    def _hasher(self):
        if self._hash_factory is not None:
            return self._hash_factory()
        try:
            from blake3 import blake3
        except ImportError as exc:
            raise UGCAPError("BLAKE3 is required; no substitute hash is accepted") from exc
        return blake3()

    def _hash(self, value: bytes) -> str:
        hasher = self._hasher()
        hasher.update(value)
        return hasher.hexdigest()

    def _check(self) -> None:
        if self._cancel.is_set():
            raise UGCAPError("vault operation cancelled by Lock")
        if self._clock() > self._deadline:
            raise UGCAPError("vault operation exceeded its time budget")

    @contextmanager
    def _operation(self):
        if not self._operation_lock.acquire(blocking=False):
            raise UGCAPError("another vault operation is active")
        self._cancel.clear()
        self._deadline = self._clock() + OPERATION_TIMEOUT_SECONDS
        with self._state_lock:
            self._busy = True
        try:
            self._check()
            yield
        finally:
            with self._state_lock:
                self._busy = False
            self._operation_lock.release()

    def _media(self) -> dict:
        _path_chain(self.repo_root)
        _path_chain(self.vault_path)
        _path_chain(self.audit_path)
        if not self.repo_root.is_dir() or not self.vault_path.parent.is_dir():
            raise UGCAPError("repository and secondary-media parent must already exist")
        try:
            self.vault_path.relative_to(self.repo_root)
        except ValueError:
            pass
        else:
            raise UGCAPError("vault storage must be outside the protected repository")
        if self._media_validator is not None:
            result = self._media_validator(self.repo_root, self.vault_path)
            if not result or isinstance(result, dict) and result.get("validated") is False:
                raise UGCAPError("secondary-media validation refused the vault")
            return dict(result) if isinstance(result, dict) else {"volume_id": "injected-media-validator"}
        source, destination = _volume_id(self.repo_root), _volume_id(self.vault_path.parent)
        if source == destination:
            raise UGCAPError("vault requires a different independently identified volume")
        return {"volume_id": destination, "repository_volume_id": source, "validated": True}

    def _read(self, path: Path, limit: int) -> bytes:
        self._check()
        _path_chain(path)
        flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_NONBLOCK", 0))
        descriptor = os.open(str(path), flags)
        try:
            before = os.fstat(descriptor)
            if _linked(before) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise UGCAPError("only single ordinary files may enter the vault")
            if before.st_size > limit:
                raise VaultCoverageError("file exceeds its protected byte budget")
            chunks, total = [], 0
            while chunk := os.read(descriptor, min(1024 * 1024, limit - total + 1)):
                self._check()
                total += len(chunk)
                if total > limit:
                    raise VaultCoverageError("file grew beyond its protected byte budget")
                chunks.append(chunk)
            after = os.fstat(descriptor)
            _path_chain(path)
            if (_identity(before) != _identity(after) or before.st_ctime_ns != after.st_ctime_ns
                    or _identity(after) != _identity(path.lstat())):
                raise UGCAPError("file changed identity while being read")
            return b"".join(chunks)
        finally:
            os.close(descriptor)

    def _in_scope(self, relative: str) -> bool:
        path = _safe_relative(relative)
        return any(path == scope or path.startswith(scope + "/") for scope in self.protected_scopes) or (
            "/" not in path and (Path(path).suffix.casefold() in ROOT_SUFFIXES
                                  or ".so." in path.casefold() or path == "LICENSE")
        )

    def _scan(self, *, backups: bool = False) -> tuple[dict, list[dict], dict]:
        files, errors = {}, []
        total = entries = 0

        def walk(directory: Path) -> None:
            nonlocal entries, total
            self._check()
            _path_chain(directory)
            with os.scandir(directory) as listing:
                for entry in listing:
                    self._check()
                    entries += 1
                    if entries > MAX_ENTRIES:
                        raise VaultCoverageError("directory enumeration exceeded its entry budget")
                    if entry.name.casefold() in EXCLUSIONS:
                        continue
                    path = Path(entry.path)
                    relative = path.relative_to(self.repo_root).as_posix()
                    scoped_directory = any(relative == scope or relative.startswith(scope + "/")
                                           or scope.startswith(relative + "/") for scope in self.protected_scopes)
                    if not scoped_directory and not self._in_scope(relative):
                        continue
                    try:
                        _safe_relative(relative)
                        info = entry.stat(follow_symlinks=False)
                        if _linked(info):
                            raise UGCAPError("linked or reparse protected entry refused")
                        if stat.S_ISDIR(info.st_mode):
                            if not scoped_directory:
                                continue
                            walk(path)
                            continue
                        if not self._in_scope(relative):
                            continue
                        if not stat.S_ISREG(info.st_mode):
                            raise UGCAPError("non-regular protected entry refused")
                        if len(files) >= MAX_FILES:
                            raise VaultCoverageError("protected file count exceeded its budget")
                        data = self._read(path, min(MAX_FILE_BYTES, MAX_TOTAL_BYTES - total))
                        total += len(data)
                        row = {"path": relative, "size": len(data), "blake3": self._hash(data),
                               "mode": stat.S_IMODE(info.st_mode) & 0o777}
                        if backups:
                            row["data"] = _encode(data)
                        files[relative] = row
                    except (OSError, UGCAPError, ValueError) as exc:
                        errors.append({"path": relative, "error": str(exc)[:500]})

        try:
            walk(self.repo_root)
        except (OSError, UGCAPError) as exc:
            errors.append({"path": ".", "error": str(exc)[:500]})
        return files, errors, {"complete": not errors, "files_scanned": len(files),
                               "bytes_scanned": total, "errors": len(errors)}

    @staticmethod
    def _password(passcode: str | bytes | bytearray) -> bytearray:
        if isinstance(passcode, str):
            value = bytearray(passcode.encode("utf-8"))
        elif isinstance(passcode, (bytes, bytearray)):
            value = bytearray(passcode)
        else:
            raise UGCAPError("passphrase must be text or a byte buffer")
        if not 12 <= len(value) <= 4096:
            _wipe(value)
            raise UGCAPError("use a passphrase of 12 to 4096 UTF-8 bytes")
        return value

    def _key(self, passcode: str | bytes | bytearray, header: dict, secret: bytes) -> bytearray:
        password = self._password(passcode)
        stretched = None
        try:
            stretched = bytearray(hashlib.pbkdf2_hmac(
                "sha256", password, _decode(header["salt"], 16), PBKDF2_ITERATIONS, dklen=32,
            ))
            self._check()
            return bytearray(HKDF(algorithm=hashes.SHA256(), length=32,
                                 salt=_decode(header["hkdf_salt"], 16),
                                 info=SCHEMA.encode()).derive(bytes(stretched) + secret))
        finally:
            _wipe(password)
            _wipe(stretched)

    def _write_exclusive(self, path: Path, payload: bytes) -> None:
        self._check()
        from angerona.core.source_sandbox import _hold_plain_directories
        with _hold_plain_directories(path.parent):
            _path_chain(path)
            parent_fd = None
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            if os.name == "nt":
                descriptor = os.open(str(path), flags, 0o600)
            else:
                parent_fd = self._open_directory(path.parent)
                descriptor = os.open(path.name, flags, 0o600, dir_fd=parent_fd)
            try:
                with os.fdopen(descriptor, "wb") as stream:
                    before = os.fstat(stream.fileno())
                    if _linked(before) or before.st_nlink != 1 or not stat.S_ISREG(before.st_mode):
                        raise UGCAPError("exclusive vault object is not a single ordinary file")
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
                    self._check()
                    if _identity(os.fstat(stream.fileno())) != _identity(path.lstat()):
                        raise UGCAPError("exclusive vault publication changed identity")
                    _path_chain(path)
            finally:
                if parent_fd is not None:
                    os.close(parent_fd)

    @staticmethod
    def _open_directory(path: Path) -> int:
        """Open every POSIX component relative to a retained no-follow dirfd."""
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        current = os.open(path.anchor, flags)
        try:
            for part in path.parts[1:]:
                child = os.open(part, flags, dir_fd=current)
                os.close(current)
                current = child
            return current
        except Exception:
            os.close(current)
            raise

    def _audit_paths(self) -> list[Path]:
        paths, entries = {}, 0
        prefix = self.audit_path.name + "."
        with os.scandir(self.audit_path.parent) as listing:
            for entry in listing:
                self._check()
                entries += 1
                if entries > MAX_ENTRIES:
                    raise UGCAPError("secondary-media listing exceeded its budget")
                if entry.name.startswith(prefix):
                    suffix = entry.name[len(prefix):]
                    if len(suffix) != 8 or not suffix.isascii() or not suffix.isdigit():
                        raise VaultAuthenticationError("unexpected vault audit sidecar")
                    sequence = int(suffix)
                    if sequence < 1 or sequence >= MAX_AUDIT_RECORDS:
                        raise VaultAuthenticationError("vault audit sequence exceeded its budget")
                    paths[sequence] = Path(entry.path)
        if set(paths) != set(range(1, len(paths) + 1)):
            raise VaultAuthenticationError("vault audit has a missing middle record")
        return [self.audit_path] + [paths[number] for number in range(1, len(paths) + 1)]

    def _audit_load(self, key: bytearray, generation: str) -> list[dict]:
        try:
            records, previous, total = [], "0" * 64, 0
            for sequence, path in enumerate(self._audit_paths()):
                encoded = self._read(path, MAX_AUDIT_RECORD_BYTES)
                total += len(encoded)
                if total > MAX_AUDIT_BYTES:
                    raise ValueError("audit byte budget exceeded")
                envelope = json.loads(encoded)
                if set(envelope) != {"nonce", "ciphertext"}:
                    raise ValueError("invalid audit fields")
                plain = AESGCM(bytes(key)).decrypt(
                    _decode(envelope["nonce"], 12), _decode(envelope["ciphertext"], MAX_AUDIT_RECORD_BYTES),
                    (SCHEMA + ":audit:" + generation).encode(),
                )
                row = json.loads(plain)
                core = {name: value for name, value in row.items() if name != "digest"}
                if (row.get("sequence") != sequence or row.get("previous") != previous
                        or not hmac.compare_digest(str(row.get("digest")), self._hash(_canonical(core)))):
                    raise ValueError("audit chain mismatch")
                previous = row["digest"]
                records.append(row)
            return records
        except (OSError, ValueError, TypeError, KeyError, AttributeError, InvalidTag) as exc:
            raise VaultAuthenticationError("encrypted vault audit failed authentication") from exc

    def _audit_append(self, key: bytearray, generation: str, action: str, details: dict, *, initial: bool = False) -> list[dict]:
        records = [] if initial else self._audit_load(key, generation)
        if len(records) >= MAX_AUDIT_RECORDS:
            raise UGCAPError("vault audit capacity reached; explicit migration is required")
        row = {"sequence": len(records), "previous": records[-1]["digest"] if records else "0" * 64,
               "action": action, "at": self._clock(), "details": details}
        row["digest"] = self._hash(_canonical(row))
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(bytes(key)).encrypt(nonce, _canonical(row), (SCHEMA + ":audit:" + generation).encode())
        envelope = _canonical({"nonce": _encode(nonce), "ciphertext": _encode(ciphertext)})
        if len(envelope) > MAX_AUDIT_RECORD_BYTES:
            raise UGCAPError("vault audit record exceeded its byte budget")
        # Every record is an immutable exclusive create. No existing audit file
        # is replaced, so a raced destination can only refuse the publication.
        path = self.audit_path if initial else self.audit_path.with_name(self.audit_path.name + f".{len(records):08d}")
        if not initial and sum(item.stat().st_size for item in self._audit_paths()) + len(envelope) > MAX_AUDIT_BYTES:
            raise UGCAPError("vault audit exceeded its total byte budget")
        self._write_exclusive(path, envelope)
        return [*records, row]

    def initialize(self, passcode: str | bytes | bytearray) -> dict:
        with self._operation():
            media = self._media()
            vault_exists, audit_exists = os.path.lexists(self.vault_path), os.path.lexists(self.audit_path)
            if audit_exists or len(self._audit_paths()) != 1:
                raise UGCAPError("an existing vault or audit may never be overwritten by enrollment")
            if vault_exists:
                # A failed initial audit leaves authenticated pending enrollment.
                # Only this explicit action may resume it, preserving every
                # baseline byte and requiring a fresh exact full-scope match.
                key = None
                try:
                    header, files, key = self._unlock(passcode, require_audit=False)
                    fresh = self._diff(files)
                    if not fresh["coverage"]["complete"] or any(fresh["changes"].values()):
                        raise VaultCoverageError("pending enrollment differs from the pristine baseline; review is required")
                    self._audit_append(key, header["generation"], "initialized.resumed", fresh["coverage"], initial=True)
                    return {"status": "initialized", "resumed": True, "generation": header["generation"],
                            "vault_path": str(self.vault_path), "coverage": fresh["coverage"],
                            "hardware": header["hardware"], "restart_required": False}
                finally:
                    _wipe(key)
            # Check BLAKE3 and passphrase before inventory or hardware enrollment.
            self._hasher()
            check_password = self._password(passcode)
            _wipe(check_password)
            files, errors, coverage = self._scan(backups=True)
            if errors or not files:
                raise VaultCoverageError("baseline enrollment requires complete non-empty coverage: " + str(errors[:3]))
            secret, key = bytearray(secrets.token_bytes(32)), None
            try:
                identity = self.hardware.identity()
                sealed = self.hardware.seal(bytes(secret))
                if not isinstance(identity, dict) or not identity or not isinstance(sealed, dict) or not sealed:
                    raise UGCAPError("hardware binding did not return an explicit identity and sealed descriptor")
                header = {"schema": SCHEMA, "generation": uuid.uuid4().hex,
                          "created_at": self._clock(), "hash": "BLAKE3-256", "cipher": "AES-256-GCM",
                          "compression": "zlib", "kdf": "PBKDF2-HMAC-SHA256+HKDF-SHA256",
                          "iterations": PBKDF2_ITERATIONS, "salt": _encode(secrets.token_bytes(16)),
                          "hkdf_salt": _encode(secrets.token_bytes(16)), "nonce": _encode(secrets.token_bytes(12)),
                          "hardware": identity, "sealed": sealed, "media": media,
                          "repository": str(self.repo_root), "protected_scopes": list(self.protected_scopes),
                          "exclusions": sorted(EXCLUSIONS)}
                if len(_canonical(header)) > 128 * 1024:
                    raise UGCAPError("hardware descriptor exceeded its budget")
                proof = bytearray(self.hardware.unseal(sealed, secrets.token_bytes(32)))
                try:
                    if not hmac.compare_digest(proof, secret):
                        raise VaultAuthenticationError("hardware failed the enrollment unseal round trip")
                finally:
                    _wipe(proof)
                key = self._key(passcode, header, bytes(secret))
                plain = _canonical({"files": list(files.values()), "total_bytes": coverage["bytes_scanned"]})
                if len(plain) > MAX_PAYLOAD_BYTES:
                    raise VaultCoverageError("pristine backup manifest exceeded its budget")
                self._validate_manifest(json.loads(plain))
                encrypted = AESGCM(bytes(key)).encrypt(_decode(header["nonce"], 12), zlib.compress(plain), _canonical(header))
                envelope = _canonical({"header": header, "ciphertext": _encode(encrypted)})
                if len(envelope) > MAX_CONTAINER_BYTES:
                    raise VaultCoverageError("encrypted vault exceeded its budget")
                self._write_exclusive(self.vault_path, envelope)
                self._audit_append(key, header["generation"], "initialized", coverage, initial=True)
                with self._state_lock:
                    self._last_report = None
                return {"status": "initialized", "generation": header["generation"], "vault_path": str(self.vault_path),
                        "coverage": coverage, "hardware": identity, "restart_required": False}
            finally:
                _wipe(secret)
                _wipe(key)

    def _unlock(self, passcode: str | bytes | bytearray, *, require_audit: bool = True) -> tuple[dict, dict, bytearray]:
        media = self._media()
        key = secret = None
        try:
            envelope = json.loads(self._read(self.vault_path, MAX_CONTAINER_BYTES))
            if not isinstance(envelope, dict) or set(envelope) != {"header", "ciphertext"}:
                raise ValueError("invalid vault fields")
            header = envelope["header"]
            expected_fields = {"schema", "generation", "created_at", "hash", "cipher", "compression", "kdf", "iterations",
                               "salt", "hkdf_salt", "nonce", "hardware", "sealed", "media", "repository",
                               "protected_scopes", "exclusions"}
            if (not isinstance(header, dict) or set(header) != expected_fields or len(_canonical(header)) > 128 * 1024
                    or header["schema"] != SCHEMA or header["hash"] != "BLAKE3-256" or header["cipher"] != "AES-256-GCM"
                    or header["compression"] != "zlib" or header["kdf"] != "PBKDF2-HMAC-SHA256+HKDF-SHA256"
                    or type(header["iterations"]) is not int or header["iterations"] != PBKDF2_ITERATIONS
                    or len(header["generation"]) != 32 or header["repository"] != str(self.repo_root)
                    or header["protected_scopes"] != list(self.protected_scopes) or header["exclusions"] != sorted(EXCLUSIONS)
                    or header["media"] != media or header["hardware"] != self.hardware.identity()):
                raise ValueError("vault policy, media, or hardware identity mismatch")
            for field, length in (("salt", 16), ("hkdf_salt", 16), ("nonce", 12)):
                if len(_decode(header[field], length)) != length:
                    raise ValueError("invalid cryptographic parameter length")
            secret = bytearray(self.hardware.unseal(header["sealed"], secrets.token_bytes(32)))
            if len(secret) != 32:
                raise ValueError("hardware unseal returned an invalid secret")
            key = self._key(passcode, header, bytes(secret))
            compressed = AESGCM(bytes(key)).decrypt(_decode(header["nonce"], 12), _decode(envelope["ciphertext"], MAX_CONTAINER_BYTES), _canonical(header))
            inflater = zlib.decompressobj()
            plain = inflater.decompress(compressed, MAX_PAYLOAD_BYTES + 1)
            if (len(plain) > MAX_PAYLOAD_BYTES or not inflater.eof or inflater.unconsumed_tail or inflater.unused_data):
                raise ValueError("invalid or excessive compressed pristine backup")
            payload = json.loads(plain)
            files = self._validate_manifest(payload)
            if require_audit:
                self._audit_load(key, header["generation"])
            self._check()
            return header, files, key
        except UGCAPError:
            _wipe(key)
            raise
        except Exception as exc:
            _wipe(key)
            raise VaultAuthenticationError("vault authentication failed; passphrase, hardware, policy, or content differs") from exc
        finally:
            _wipe(secret)

    def _validate_manifest(self, payload: Any) -> dict:
        if not isinstance(payload, dict) or set(payload) != {"files", "total_bytes"} or not isinstance(payload["files"], list):
            raise VaultAuthenticationError("invalid pristine manifest")
        if not 1 <= len(payload["files"]) <= MAX_FILES:
            raise VaultAuthenticationError("invalid pristine file count")
        files, total, folded = {}, 0, set()
        for row in payload["files"]:
            self._check()
            if not isinstance(row, dict) or set(row) != {"path", "size", "blake3", "mode", "data"}:
                raise VaultAuthenticationError("invalid pristine file fields")
            path = _safe_relative(row["path"])
            if not self._in_scope(path) or path.casefold() in folded:
                raise VaultAuthenticationError("duplicate or out-of-scope pristine path")
            if (type(row["size"]) is not int or not 0 <= row["size"] <= MAX_FILE_BYTES
                    or type(row["mode"]) is not int or not 0 <= row["mode"] <= 0o777):
                raise VaultAuthenticationError("invalid pristine file size or mode")
            data = _decode(row["data"], MAX_FILE_BYTES)
            if len(data) != row["size"] or not hmac.compare_digest(self._hash(data), str(row["blake3"])):
                raise VaultAuthenticationError("pristine backup digest mismatch")
            total += len(data)
            if total > MAX_TOTAL_BYTES:
                raise VaultAuthenticationError("pristine file total exceeded its budget")
            folded.add(path.casefold())
            files[path] = row
        if payload["total_bytes"] != total:
            raise VaultAuthenticationError("pristine byte count mismatch")
        return files

    def _diff(self, files: dict) -> dict:
        current, errors, coverage = self._scan()
        return {"changes": {"added": sorted(set(current) - set(files)),
                            "missing": sorted(set(files) - set(current)),
                            "modified": sorted(path for path in set(files) & set(current)
                                               if files[path]["blake3"] != current[path]["blake3"]),
                            "read_errors": errors}, "coverage": coverage,
                "observations": {path: {"blake3": row["blake3"], "size": row["size"]}
                                 for path, row in current.items()}}

    def verify(self, passcode: str | bytes | bytearray) -> dict:
        with self._operation():
            key = None
            try:
                header, files, key = self._unlock(passcode)
                report = self._diff(files)
                report.update({"report_id": uuid.uuid4().hex, "generation": header["generation"],
                               "vault_path": str(self.vault_path), "repository": str(self.repo_root),
                               "created_at": self._clock(), "hardware": header["hardware"], "restart_required": False})
                changed = any(report["changes"][name] for name in ("added", "missing", "modified"))
                report["status"] = "incomplete" if not report["coverage"]["complete"] else "drift" if changed else "verified"
                try:
                    audit_records = self._audit_append(key, header["generation"], "verified", {"report_id": report["report_id"],
                                       "status": report["status"], "diff_blake3": self._hash(_canonical(report["changes"]))})
                    report["audit"] = {"recorded": True, "rollback_proof": False}
                except (OSError, UGCAPError) as exc:
                    report["status"] = "incomplete"
                    report["coverage"]["complete"] = False
                    report["coverage"]["audit_errors"] = 1
                    report["audit"] = {"recorded": False, "error": str(exc)[:500], "rollback_proof": False}
                self._check()
                if report["status"] == "verified":
                    manifest = {path: {"blake3": row["blake3"], "size": row["size"]} for path, row in files.items()}
                    report["source_manifest_digest"] = self._hash(_canonical(manifest))
                    # Public, bounded hashes only. No file paths, source, vault
                    # passcodes or hardware material crosses the witness wire.
                    report["witness_checkpoint"] = {
                        "vault_id": header["generation"],
                        "baseline_id": report["source_manifest_digest"],
                        "chain_length": len(audit_records),
                        "chain_hash": audit_records[-1]["digest"],
                        "anchors": [{"length": row["sequence"] + 1, "hash": row["digest"]}
                                    for row in audit_records[-128:]],
                    }
                    report["verified_files"] = {path: row["blake3"] for path, row in files.items()}
                    report["verification_receipt"] = {
                        "generation": header["generation"], "report_id": report["report_id"],
                        "source_manifest_digest": report["source_manifest_digest"],
                        "verified_files": dict(report["verified_files"]),
                        "repository": str(self.repo_root), "vault_path": str(self.vault_path),
                    }
                with self._state_lock:
                    self._last_report = json.loads(_canonical(report))
                return report
            finally:
                _wipe(key)

    def _stage(self, target: Path, data: bytes, mode: int = 0o600) -> Path:
        from angerona.core.engine_transport import create_private_file, private_directory
        from angerona.core.source_sandbox import _hold_plain_directories
        _path_chain(target)
        if not target.parent.is_dir():
            raise UGCAPError("missing-parent recovery requires explicit offline directory restoration")
        with _hold_plain_directories(self.repo_root, target.parent):
            recovery = private_directory(target.parent / ".ugcap-recovery")
            working = private_directory(recovery / uuid.uuid4().hex)
            identity = (working.stat().st_dev, working.stat().st_ino)
            with _hold_plain_directories(recovery, working):
                if (working.stat().st_dev, working.stat().st_ino) != identity:
                    raise UGCAPError("private staging directory changed identity")
                staged = working / "pristine.stage"
                descriptor = create_private_file(staged)
                with os.fdopen(descriptor, "wb") as stream:
                    if os.name != "nt":
                        os.fchmod(stream.fileno(), 0o600 | (mode & 0o100))
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                if not hmac.compare_digest(self._hash(self._read(staged, MAX_FILE_BYTES)), self._hash(data)):
                    raise UGCAPError("staged recovery failed byte verification")
                return staged

    def _pinned_digest(self, pinned) -> str:
        if os.name == "nt":
            descriptor = pinned.duplicate_custody_descriptor()
        else:
            # The POSIX move implementation retains this no-follow inode fd.
            # No path reopen is used while authorizing a staged publication.
            descriptor = os.dup(pinned._impl._fd)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_FILE_BYTES:
                raise UGCAPError("pinned recovery object exceeded its custody budget")
            hasher, total = self._hasher(), 0
            os.lseek(descriptor, 0, os.SEEK_SET)
            while chunk := os.read(descriptor, 1024 * 1024):
                self._check()
                total += len(chunk)
                if total > MAX_FILE_BYTES:
                    raise UGCAPError("pinned recovery object grew beyond its byte budget")
                hasher.update(chunk)
            if _identity(before) != _identity(os.fstat(descriptor)):
                raise UGCAPError("pinned recovery object changed while hashing")
            return hasher.hexdigest()
        finally:
            os.close(descriptor)

    def _publish_stage(self, staged: Path, target: Path, observed: dict | None, expected: str, result: dict) -> None:
        from angerona.core.source_sandbox import _hold_plain_directories
        from angerona.modules.adversary_combat import _PinnedFileMove
        with _hold_plain_directories(self.repo_root, target.parent, staged.parent):
            _path_chain(target)
            with _PinnedFileMove(staged) as replacement:
                replacement.require_single_link()
                if self._pinned_digest(replacement) != expected:
                    raise UGCAPError("pinned pristine stage changed after verification")
                if replacement.crosses_volume(target):
                    raise UGCAPError("recovery publication may not cross filesystem volumes")
                if observed is None:
                    if os.path.lexists(target):
                        raise StaleReportError("missing restore target reappeared after approval")
                    result["recovery_required"] = True
                    if os.name == "nt":
                        replacement.rename_to(target)  # kernel no-replace operation
                    else:
                        destination_fd = self._open_directory(target.parent)
                        try:
                            info = os.fstat(destination_fd)
                            if (info.st_dev, info.st_ino) != (target.parent.stat().st_dev, target.parent.stat().st_ino):
                                raise UGCAPError("missing restore parent changed identity")
                            implementation = replacement._impl
                            if not implementation._source_name_matches():
                                raise UGCAPError("pinned staging name lost custody")
                            implementation._rename_noreplace(implementation._parent_fd, staged.name, destination_fd, target.name)
                            published = os.stat(target.name, dir_fd=destination_fd, follow_symlinks=False)
                            retained = os.fstat(implementation._fd)
                            if (published.st_dev, published.st_ino) != (retained.st_dev, retained.st_ino):
                                result["recovery_required"] = True
                                raise UGCAPError("missing publication did not preserve pinned identity")
                            if (info.st_dev, info.st_ino) != (target.parent.stat().st_dev, target.parent.stat().st_ino):
                                result["recovery_required"] = True
                                raise UGCAPError("published recovery parent was renamed; review is required")
                            os.fsync(destination_fd)
                        finally:
                            os.close(destination_fd)
                else:
                    if os.name != "nt":
                        raise UGCAPError("conditional replacement of modified files requires offline POSIX recovery")
                    with _PinnedFileMove(target) as original:
                        original.require_single_link()
                        if self._pinned_digest(original) != observed["blake3"]:
                            raise StaleReportError("pinned restore target changed bytes after approval")
                        displaced = staged.parent / "displaced.original"
                        if original.crosses_volume(displaced):
                            raise UGCAPError("displaced original must retain same-volume custody")
                        result["recovery_required"] = True
                        original.rename_to(displaced)
                        result["recovery_artifacts"].append(str(displaced))
                        try:
                            replacement.rename_to(target)  # cannot overwrite a raced new target
                        except Exception:
                            result["recovery_required"] = True
                            raise
                replacement.require_single_link()
                if self._pinned_digest(replacement) != expected:
                    result["recovery_required"] = True
                    raise UGCAPError("published recovery failed retained-handle verification")
                result["recovery_required"] = False

    def restore(self, passcode: str | bytes | bytearray, paths: list[str], *, expected_report_id: str) -> dict:
        with self._operation():
            key, stages = None, []
            try:
                with self._state_lock:
                    approved = json.loads(_canonical(self._last_report)) if self._last_report else None
                if (not approved or approved["report_id"] != expected_report_id or approved["status"] != "drift"
                        or not approved["coverage"]["complete"]):
                    raise StaleReportError("restore requires the exact last complete drift report")
                if not isinstance(paths, list) or not paths or len(paths) > MAX_RESTORE_PATHS:
                    raise UGCAPError("explicitly select at least one bounded restore path")
                selected = list(dict.fromkeys(_safe_relative(path) for path in paths))
                changed = set().union(*(set(approved["changes"][kind]) for kind in ("added", "missing", "modified")))
                if not set(selected) <= changed:
                    raise StaleReportError("selected path was not in the approved diff")
                header, files, key = self._unlock(passcode)
                fresh = self._diff(files)
                if (header["generation"] != approved["generation"] or not fresh["coverage"]["complete"]
                        or fresh["changes"] != approved["changes"] or fresh["observations"] != approved["observations"]):
                    raise StaleReportError("protected files or vault generation changed after verification")
                result = {"status": "restored", "report_id": expected_report_id, "generation": header["generation"],
                          "restored": [], "deferred": [], "non_restorable": [], "errors": [], "restart_required": False,
                          "recovery_required": False, "recovery_artifacts": [],
                          "capabilities": {"modified_restore": "pinned-displacement" if os.name == "nt" else "offline-only",
                                           "missing_restore": "no-replace-publication"}}
                for relative in selected:
                    if relative not in files:
                        result["non_restorable"].append(relative)
                    else:
                        original = _decode(files[relative]["data"], MAX_FILE_BYTES)
                        magic = original[:4]
                        if (Path(relative).suffix.casefold() in BINARY_SUFFIXES
                                or ".so." in Path(relative).name.casefold()
                                or magic.startswith(b"MZ") or magic == b"\x7fELF"
                                or magic in {b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
                                             b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}):
                            result["deferred"].append(relative)
                            continue
                        if os.name != "nt" and relative in approved["changes"]["modified"]:
                            result["deferred"].append(relative)
                            continue
                        target = self.repo_root / relative
                        if not target.parent.is_dir():
                            result["deferred"].append(relative)
                            continue
                        if target.exists() and (target.lstat().st_nlink != 1 or not target.is_file()):
                            raise UGCAPError("restore target is not a single ordinary file")
                        staged = self._stage(target, original, files[relative]["mode"])
                        stages.append((relative, staged))
                self._audit_append(key, header["generation"], "restore.intent", {"report_id": expected_report_id, "selected": selected})
                for relative, staged in stages:
                    try:
                        self._check()
                        target = self.repo_root / relative
                        _path_chain(target)
                        observed = approved["observations"].get(relative)
                        self._publish_stage(staged, target, observed, files[relative]["blake3"], result)
                        result["restored"].append(relative)
                    except (OSError, UGCAPError) as exc:
                        result["errors"].append({"path": relative, "error": str(exc)[:500]})
                        break
                result["restart_required"] = bool(result["restored"] or result["deferred"])
                if result["errors"] or result["non_restorable"]:
                    result["status"] = "partial"
                elif result["deferred"]:
                    result["status"] = "deferred"
                self._audit_append(key, header["generation"], "restore.completed", result)
                with self._state_lock:
                    self._last_report = None
                return result
            finally:
                _wipe(key)

    def lock(self) -> dict:
        self._cancel.set()
        with self._state_lock:
            self._last_report = None
        return self.snapshot()

    def snapshot(self) -> dict:
        with self._state_lock:
            return {"initialized": self.vault_path.is_file() and self.audit_path.is_file(),
                    "pending_enrollment": self.vault_path.is_file() and not self.audit_path.exists(),
                    "locked": True, "busy": self._busy,
                    "vault_path": str(self.vault_path), "repository": str(self.repo_root),
                    "last_report": json.loads(_canonical(self._last_report)) if self._last_report else None,
                    "protected_scopes": list(self.protected_scopes), "exclusions": sorted(EXCLUSIONS),
                    "limits": {"files": MAX_FILES, "file_bytes": MAX_FILE_BYTES, "total_bytes": MAX_TOTAL_BYTES,
                               "operation_seconds": OPERATION_TIMEOUT_SECONDS, "restore_paths": MAX_RESTORE_PATHS},
                    "detail": "Passphrase and hardware unseal required per operation. Encrypted audit is tamper-evident, "
                              "not rollback-proof without an independent witness. Initial audit failure requires explicit "
                              "Initialize to resume an unchanged authenticated pending baseline. Python memory wiping is best-effort."}
