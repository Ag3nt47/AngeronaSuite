"""Authenticated forensic copies for SpywareGuard, with explicit key injection.

This backend preserves evidence; it does not stop processes or remove the source.
The caller must supply a 32-byte key from Angerona's protected credential store.
Keys never enter this container, a configuration file, or a command line. A
successful copy is deliberately labelled ``encrypted_copy``, never containment.
Restoration is explicit, creates a new private file, and cannot overwrite a file.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import hmac
from itertools import islice
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import struct
import threading
import time
from typing import Iterator

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from angerona.core.engine_transport import create_private_file, private_directory, verify_private
from angerona.core.secure_store import _path_traverses_reparse
from angerona.core.source_sandbox import _hold_plain_directories, _validate_chain
from angerona.modules.adversary_combat import _PinnedFileMove

_MAGIC = b"ANGERONA-SPYWARE-QUARANTINE\x01"
_SUFFIX = ".aq"
_ID = re.compile(r"[a-f0-9]{32}\Z")
_SHA256 = re.compile(r"[a-fA-F0-9]{64}\Z")
_MAX_METADATA = 4096
_MAX_LIST = 100
_CHUNK = 256 * 1024
_LIMITATIONS = (
    "Encrypted forensic copies preserve the plaintext source; containment is separate.",
    "Source removal is unsupported because no portable exact-handle deletion API is exposed.",
    "Listing authenticates metadata; complete payload integrity is checked during restore.",
)


class QuarantineError(ValueError):
    """The requested evidence operation could not prove its safety or integrity."""


def _identity(info) -> tuple:
    # Python's Windows lstat/fstat can disagree on whether st_ctime means
    # creation or change time. Birth time is consistent across both APIs;
    # the exclusive source handle prevents concurrent writes on Windows.
    stamp = getattr(info, "st_birthtime_ns", info.st_ctime_ns) if os.name == "nt" else info.st_ctime_ns
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, stamp)


def _regular(info) -> None:
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or getattr(info, "st_file_attributes", 0) & 0x400):
        raise QuarantineError("Evidence must be a regular, single-link, non-reparse file")


def _receipt_id(value: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise QuarantineError("Invalid quarantine receipt identifier")
    return value


def _duplicate_descriptor(pinned) -> int:
    # The current POSIX move implementation has no public duplicate method.
    # Duplicate the retained descriptor instead of reopening a pathname.
    if os.name == "nt":
        return pinned.duplicate_custody_descriptor()
    return os.dup(pinned._impl._fd)


def _json(raw: bytes) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise QuarantineError("Duplicate encrypted metadata field")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise QuarantineError("Invalid encrypted metadata") from exc
    if not isinstance(value, dict):
        raise QuarantineError("Invalid encrypted metadata")
    return value


class EncryptedQuarantine:
    """Bounded AES-256-GCM evidence storage; supplied root and key are mandatory.

    ``root.parent`` must exist. Existing roots and restore destination parents
    must already be private to the current OS account. Neither is silently
    hardened. Only encrypted archive creation is automatic.
    """

    def __init__(self, root: Path, key: bytes, *, max_file_bytes: int = 64 * 1024 * 1024,
                 read_timeout: float = 10.0, max_entries: int = 1000) -> None:
        if not isinstance(key, bytes) or len(key) != 32:
            raise QuarantineError("An explicitly supplied 32-byte protected-store key is required")
        if type(max_file_bytes) is not int or not 1 <= max_file_bytes <= 256 * 1024 * 1024:
            raise QuarantineError("Invalid quarantine file byte limit")
        if (isinstance(read_timeout, bool) or not isinstance(read_timeout, (int, float))
                or not math.isfinite(read_timeout) or not 0 < read_timeout <= 60):
            raise QuarantineError("Invalid quarantine read deadline")
        if type(max_entries) is not int or not 1 <= max_entries <= 10000:
            raise QuarantineError("Invalid quarantine inventory limit")
        self.root = Path(os.path.abspath(os.fspath(root)))
        if not self.root.name or _path_traverses_reparse(self.root):
            raise QuarantineError("Quarantine root traverses a link or reparse point")
        _validate_chain(self.root.parent)
        with _hold_plain_directories(self.root.parent):
            private_directory(self.root)
        self.max_file_bytes = max_file_bytes
        self.read_timeout = float(read_timeout)
        self.max_entries = max_entries
        self._cipher = AESGCM(key)
        self._lock = threading.RLock()

    @contextmanager
    def _custody(self) -> Iterator[None]:
        if _path_traverses_reparse(self.root):
            raise QuarantineError("Quarantine root traverses a link or reparse point")
        with _hold_plain_directories(self.root):
            verify_private(self.root, directory=True)
            before = self.root.lstat()
            yield
            after = self.root.lstat()
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise QuarantineError("Quarantine directory changed identity")
            verify_private(self.root, directory=True)

    @contextmanager
    def _source(self, path: Path):
        path = Path(os.path.abspath(os.fspath(path)))
        if _path_traverses_reparse(path):
            raise QuarantineError("Evidence path traverses a link or reparse point")
        _regular(path.lstat())
        with _PinnedFileMove(path) as pinned:
            pinned.require_single_link()
            with os.fdopen(_duplicate_descriptor(pinned), "rb") as stream:
                before = os.fstat(stream.fileno())
                _regular(before)
                self._unchanged(path, stream, before, pinned)
                yield path, pinned, stream, before
                self._unchanged(path, stream, before, pinned)

    @staticmethod
    def _unchanged(path: Path, stream, before, pinned) -> None:
        held, named = os.fstat(stream.fileno()), path.lstat()
        _regular(held)
        _regular(named)
        pinned.require_single_link()
        if (_identity(before) != _identity(held) or _identity(before) != _identity(named)
                or _path_traverses_reparse(path)):
            raise QuarantineError("Evidence changed identity or content during operation")

    def _read(self, stream, count: int, deadline: float) -> bytes:
        output = bytearray()
        while len(output) < count:
            if time.monotonic() >= deadline:
                raise QuarantineError("Evidence read deadline exceeded")
            chunk = stream.read(min(_CHUNK, count - len(output)))
            if not chunk:
                raise QuarantineError("Evidence ended before its declared size")
            output.extend(chunk)
        if time.monotonic() >= deadline:
            raise QuarantineError("Evidence read deadline exceeded")
        return bytes(output)

    def _inventory(self, *, require_capacity: bool = False) -> list[Path]:
        # Count every entry, including incomplete encrypted writes, so clutter
        # cannot turn a background listing into an unbounded directory walk.
        with os.scandir(self.root) as entries:
            paths = [self.root / entry.name for entry in islice(entries, self.max_entries + 1)]
        if len(paths) > self.max_entries:
            raise QuarantineError("Quarantine inventory exceeds its entry limit")
        if require_capacity and len(paths) >= self.max_entries:
            raise QuarantineError("Quarantine inventory is full")
        return sorted(path for path in paths if path.suffix == _SUFFIX and _ID.fullmatch(path.stem))

    def _write_new(self, destination: Path, raw: bytes) -> None:
        """Publish only a complete new file; never overwrite an existing object."""
        if _path_traverses_reparse(destination.parent):
            raise QuarantineError("Destination traverses a link or reparse point")
        with _hold_plain_directories(destination.parent):
            verify_private(destination.parent, directory=True)
            if os.path.lexists(destination):
                raise FileExistsError("Quarantine destination already exists")
            pending = destination.parent / (".quarantine-pending-" + secrets.token_hex(16))
            descriptor = create_private_file(pending)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
                written = os.fstat(stream.fileno())
            # On error retain the private staging object, rather than risk a
            # pathname unlink against an object whose identity has changed.
            with _PinnedFileMove(pending) as pinned:
                with os.fdopen(_duplicate_descriptor(pinned), "rb") as stream:
                    held = os.fstat(stream.fileno())
                    if _identity(written) != _identity(held) or held.st_size != len(raw):
                        raise QuarantineError("Private staging object changed before publication")
                    saved = self._read(stream, len(raw), time.monotonic() + self.read_timeout)
                    if not hmac.compare_digest(hashlib.sha256(saved).digest(), hashlib.sha256(raw).digest()):
                        raise QuarantineError("Private staging bytes changed before publication")
                    self._unchanged(pending, stream, held, pinned)
                    pinned.rename_to(destination)
                    moved = os.fstat(stream.fileno())
                    # A POSIX rename can legitimately advance inode ctime.
                    # Its file identity, bytes, size and mtime must survive.
                    if _identity(held)[:4] != _identity(moved)[:4]:
                        raise QuarantineError("Private staging object changed during publication")
                    self._unchanged(destination, stream, moved, pinned)
            verify_private(destination)

    def _metadata(self, stream, receipt_id: str, file_size: int, deadline: float):
        prefix = self._read(stream, len(_MAGIC) + 16, deadline)
        if prefix[:len(_MAGIC)] != _MAGIC:
            raise QuarantineError("Invalid encrypted quarantine format")
        nonce = prefix[len(_MAGIC):len(_MAGIC) + 12]
        metadata_size = struct.unpack("!I", prefix[-4:])[0]
        if not 16 <= metadata_size <= _MAX_METADATA:
            raise QuarantineError("Encrypted metadata exceeds its byte limit")
        encrypted = self._read(stream, metadata_size, deadline)
        aad = _MAGIC + receipt_id.encode("ascii")
        try:
            metadata = _json(self._cipher.decrypt(nonce, encrypted, aad))
        except InvalidTag as exc:
            raise QuarantineError("Encrypted metadata authentication failed") from exc
        if (set(metadata) != {"receipt_id", "status", "sha256", "size_bytes", "created_at"}
                or metadata["receipt_id"] != receipt_id or metadata["status"] != "encrypted_copy"
                or not isinstance(metadata["sha256"], str) or not _SHA256.fullmatch(metadata["sha256"])
                or type(metadata["size_bytes"]) is not int
                or not 0 <= metadata["size_bytes"] <= self.max_file_bytes
                or not isinstance(metadata["created_at"], (int, float))
                or not math.isfinite(metadata["created_at"])):
            raise QuarantineError("Invalid authenticated quarantine metadata")
        expected = len(_MAGIC) + 16 + metadata_size + 12 + metadata["size_bytes"] + 16
        if file_size != expected:
            raise QuarantineError("Encrypted payload size differs from authenticated metadata")
        return metadata, aad + encrypted

    @staticmethod
    def _receipt(metadata: dict, *, verified: bool) -> dict:
        return {**metadata, "source_removed": False, "plaintext_remains": True,
                "payload_verified": verified,
                "integrity": "authenticated" if verified else "metadata_authenticated_payload_unverified"}

    def seal_file(self, path: Path, expected_sha256: str, *, remove_source: bool = False) -> dict:
        """Encrypt an exact hash-matched regular file, preserving its source."""
        if remove_source is not False:
            raise QuarantineError("Source removal is unsupported; encrypted copies preserve plaintext")
        if not isinstance(expected_sha256, str) or not _SHA256.fullmatch(expected_sha256):
            raise QuarantineError("An expected SHA-256 is required")
        with self._lock, self._custody():
            self._inventory(require_capacity=True)
            with self._source(path) as (source, pinned, stream, before):
                if not 0 <= before.st_size <= self.max_file_bytes:
                    raise QuarantineError("Evidence exceeds its file byte limit")
                raw = self._read(stream, before.st_size, time.monotonic() + self.read_timeout)
                digest = hashlib.sha256(raw).hexdigest()
                if not hmac.compare_digest(digest, expected_sha256.lower()):
                    raise QuarantineError("Evidence does not match its expected SHA-256")
                self._unchanged(source, stream, before, pinned)
                receipt_id = secrets.token_hex(16)
                metadata = {"receipt_id": receipt_id, "status": "encrypted_copy", "sha256": digest,
                            "size_bytes": len(raw), "created_at": time.time()}
                metadata_raw = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode("ascii")
                aad = _MAGIC + receipt_id.encode("ascii")
                metadata_nonce, payload_nonce = secrets.token_bytes(12), secrets.token_bytes(12)
                encrypted_metadata = self._cipher.encrypt(metadata_nonce, metadata_raw, aad)
                payload = self._cipher.encrypt(payload_nonce, raw, aad + encrypted_metadata)
                container = (_MAGIC + metadata_nonce + struct.pack("!I", len(encrypted_metadata))
                             + encrypted_metadata + payload_nonce + payload)
                self._write_new(self.root / (receipt_id + _SUFFIX), container)
                self._unchanged(source, stream, before, pinned)
            return self._receipt(metadata, verified=True)

    def _open_archive(self, receipt_id: str, *, payload: bool):
        path = self.root / (_receipt_id(receipt_id) + _SUFFIX)
        verify_private(path)
        with self._source(path) as (_path, _pinned, stream, before):
            if before.st_size > self.max_file_bytes + _MAX_METADATA + len(_MAGIC) + 44:
                raise QuarantineError("Encrypted container exceeds its byte limit")
            deadline = time.monotonic() + self.read_timeout
            metadata, aad = self._metadata(stream, receipt_id, before.st_size, deadline)
            if not payload:
                return metadata, None
            nonce = self._read(stream, 12, deadline)
            ciphertext = self._read(stream, metadata["size_bytes"] + 16, deadline)
            try:
                raw = self._cipher.decrypt(nonce, ciphertext, aad)
            except InvalidTag as exc:
                raise QuarantineError("Encrypted payload authentication failed") from exc
            if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), metadata["sha256"]):
                raise QuarantineError("Restored evidence SHA-256 mismatch")
            return metadata, raw

    def restore(self, receipt_id: str, destination: Path) -> dict:
        """Explicitly restore to a new file in an existing private directory."""
        _receipt_id(receipt_id)
        destination = Path(os.path.abspath(os.fspath(destination)))
        if not destination.name or _path_traverses_reparse(destination):
            raise QuarantineError("Restore destination traverses a link or reparse point")
        with self._lock, self._custody():
            metadata, raw = self._open_archive(receipt_id, payload=True)
            self._write_new(destination, raw)
            return {"receipt_id": receipt_id, "status": "restored", "sha256": metadata["sha256"],
                    "size_bytes": metadata["size_bytes"], "payload_verified": True,
                    "archive_retained": True, "destination": str(destination)}

    def list_receipts(self, *, limit: int = _MAX_LIST) -> list[dict]:
        """Read at most 100 authenticated metadata records; no payload decryption."""
        if type(limit) is not int or not 1 <= limit <= _MAX_LIST:
            raise QuarantineError("Receipt list limit must be between 1 and 100")
        with self._lock, self._custody():
            results = []
            for path in self._inventory()[:limit]:
                try:
                    metadata, _raw = self._open_archive(path.stem, payload=False)
                    results.append(self._receipt(metadata, verified=False))
                except (OSError, ValueError, RuntimeError):
                    results.append({"receipt_id": path.stem, "status": "integrity_error",
                                    "payload_verified": False})
            return results

    def snapshot(self, *, limit: int = _MAX_LIST) -> dict:
        with self._lock, self._custody():
            inventory = self._inventory()
            items = self.list_receipts(limit=limit)
            return {"backend": "AES-256-GCM", "mode": "encrypted_forensic_copy",
                    "source_removal_supported": False, "archive_count": len(inventory),
                    "items": items, "truncated": len(inventory) > len(items),
                    "max_file_bytes": self.max_file_bytes, "max_entries": self.max_entries,
                    "read_timeout_seconds": self.read_timeout, "limitations": list(_LIMITATIONS)}
