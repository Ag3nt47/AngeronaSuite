"""Encrypted streaming backup and approval-gated offline restore."""
from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import math
import os
import re
import shutil
import sqlite3
import stat
import tarfile
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Iterable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from angerona.core.atomic_io import replace_with_retry

MAGIC = b"ANGERONA-BACKUP\x01"
MAX_ITEMS = 256
MAX_ITEM_BYTES = 5 * 1024 * 1024 * 1024
MAX_TOTAL_BYTES = 20 * 1024 * 1024 * 1024
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{2,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PRIVACY = {"internal", "sensitive", "restricted"}
_KINDS = {"file", "sqlite"}


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _digest(path: Path) -> tuple[str, int]:
    hasher = hashlib.sha256()
    size = 0
    with open(path, "rb") as stream:
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            hasher.update(chunk)
    return hasher.hexdigest(), size


def _relative(value: str) -> PurePosixPath:
    path = PurePosixPath(str(value).replace("\\", "/"))
    if (
        path.is_absolute() or not path.parts or len(path.parts) > 24
        or any(part in {"", ".", ".."} for part in path.parts)
        or ":" in path.parts[0]
    ):
        raise ValueError("backup path must be a safe relative path")
    if len(path.as_posix()) > 500:
        raise ValueError("backup path exceeds 500 characters")
    return path


def _has_reparse_component(root: Path, relative: PurePosixPath) -> bool:
    try:
        root_info = root.lstat()
        if stat.S_ISLNK(root_info.st_mode) or (
            getattr(root_info, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        ):
            return True
    except FileNotFoundError:
        return False
    current = root
    for part in relative.parts:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            return False
        if stat.S_ISLNK(info.st_mode) or (
            getattr(info, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        ):
            return True
    return False


def _derive_key(master_key: bytes, salt: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        info=b"angerona-backup-stream-v1",
    ).derive(master_key)


@dataclass(frozen=True)
class BackupSelection:
    relative_path: str
    kind: str = "file"
    privacy_class: str = "sensitive"
    required: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "relative_path", _relative(
            self.relative_path
        ).as_posix())
        if self.kind not in _KINDS:
            raise ValueError("unsupported backup item kind")
        if self.privacy_class not in _PRIVACY:
            raise ValueError("invalid backup privacy class")


@dataclass(frozen=True)
class BackupItem:
    relative_path: str
    kind: str
    privacy_class: str
    sha256: str
    size_bytes: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "relative_path", _relative(
            self.relative_path
        ).as_posix())
        if self.kind not in _KINDS or self.privacy_class not in _PRIVACY:
            raise ValueError("invalid backup item metadata")
        if not _SHA256.fullmatch(self.sha256):
            raise ValueError("invalid backup item digest")
        if not 0 <= int(self.size_bytes) <= MAX_ITEM_BYTES:
            raise ValueError("backup item exceeds byte budget")


@dataclass(frozen=True)
class BackupManifest:
    schema: str
    backup_id: str
    source_scope: str
    created_at: float
    items: tuple[BackupItem, ...]
    total_bytes: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "items", tuple(self.items))
        if self.schema != "angerona.backup/v1":
            raise ValueError("unsupported backup schema")
        if not _ID.fullmatch(self.backup_id) or not _ID.fullmatch(self.source_scope):
            raise ValueError("invalid backup identity")
        if not math.isfinite(float(self.created_at)) or self.created_at < 0:
            raise ValueError("invalid backup timestamp")
        if not 1 <= len(self.items) <= MAX_ITEMS:
            raise ValueError("backup item count is invalid")
        if len({item.relative_path.casefold() for item in self.items}) != len(self.items):
            raise ValueError("backup contains duplicate paths")
        expected = sum(item.size_bytes for item in self.items)
        if expected != int(self.total_bytes) or expected > MAX_TOTAL_BYTES:
            raise ValueError("backup total byte budget is invalid")

    def canonical(self) -> bytes:
        return _canonical(asdict(self))


@dataclass(frozen=True)
class BackupReceipt:
    backup_id: str
    archive_sha256: str
    manifest_sha256: str
    item_count: int
    total_bytes: int
    created_at: float
    receipt_hmac: str


@dataclass(frozen=True)
class VerifiedBackup:
    archive_path: str
    archive_sha256: str
    manifest: BackupManifest
    manifest_sha256: str


@dataclass(frozen=True)
class RestorePlan:
    plan_id: str
    archive_path: str
    archive_sha256: str
    manifest_sha256: str
    target_root: str
    requested_by: str
    created_at: float
    expires_at: float
    item_paths: tuple[str, ...]
    plan_hmac: str


@dataclass(frozen=True)
class RestoreAuthorization:
    plan_id: str
    plan_hmac: str
    approvers: tuple[str, str]
    authorized_at: float
    authorization_hmac: str


@dataclass(frozen=True)
class RestoreReceipt:
    plan_id: str
    archive_sha256: str
    restored_items: int
    rollback_scope: str
    completed_at: float
    receipt_hmac: str


class _EncryptingWriter(io.RawIOBase):
    def __init__(self, stream: BinaryIO, encryptor: Any) -> None:
        self.stream = stream
        self.encryptor = encryptor
        self.position = 0

    def writable(self) -> bool:
        return True

    def write(self, value: bytes) -> int:
        encoded = self.encryptor.update(value)
        if encoded:
            self.stream.write(encoded)
        self.position += len(value)
        return len(value)

    def tell(self) -> int:
        return self.position


class _DecryptingReader(io.RawIOBase):
    def __init__(self, stream: BinaryIO, decryptor: Any, remaining: int) -> None:
        self.stream = stream
        self.decryptor = decryptor
        self.remaining = int(remaining)
        self.done = False

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        if self.done:
            return b""
        if self.remaining <= 0:
            self._finish()
            return b""
        wanted = self.remaining if size is None or size < 0 else min(size, self.remaining)
        chunk = self.stream.read(wanted)
        if not chunk:
            raise ValueError("encrypted backup is truncated")
        self.remaining -= len(chunk)
        result = self.decryptor.update(chunk)
        if self.remaining == 0:
            result += self._finish()
        return result

    def _finish(self) -> bytes:
        if self.done:
            return b""
        self.done = True
        try:
            return self.decryptor.finalize()
        except Exception as exc:
            raise ValueError("encrypted backup authentication failed") from exc


class EncryptedBackupManager:
    def __init__(self, encryption_key: bytes, audit_key: bytes, *, clock=time.time) -> None:
        if len(encryption_key) < 32 or len(audit_key) < 32:
            raise ValueError("backup encryption and audit keys must be at least 32 bytes")
        self._encryption_key = bytes(encryption_key)
        self._audit_key = bytes(audit_key)
        self._clock = clock

    def create(
        self,
        archive_path: Path,
        source_root: Path,
        selections: Iterable[BackupSelection],
        *,
        backup_id: str,
        source_scope: str = "standalone",
    ) -> BackupReceipt:
        selections = tuple(selections)
        if not 1 <= len(selections) <= MAX_ITEMS:
            raise ValueError("backup selection count is invalid")
        if len({item.relative_path.casefold() for item in selections}) != len(selections):
            raise ValueError("backup selections contain duplicate paths")
        source_root = Path(source_root).resolve(strict=True)
        archive_path = Path(archive_path).resolve()
        try:
            archive_path.relative_to(source_root)
        except ValueError:
            pass
        else:
            raise ValueError("encrypted backup must be stored outside the data root")
        if archive_path.exists():
            raise FileExistsError(archive_path)
        archive_path.parent.mkdir(parents=True, exist_ok=True)

        with tempfile.TemporaryDirectory(
            prefix=".angerona-backup-", dir=source_root,
        ) as temporary:
            stage_root = Path(temporary)
            staged: list[tuple[BackupItem, Path]] = []
            for index, selection in enumerate(selections):
                relative = _relative(selection.relative_path)
                source = source_root.joinpath(*relative.parts)
                if _has_reparse_component(source_root, relative):
                    raise ValueError("backup refuses symlink or reparse-point input")
                if not source.exists():
                    if selection.required:
                        raise FileNotFoundError(source)
                    continue
                if not source.is_file():
                    raise ValueError("backup selections must be regular files")
                destination = stage_root / f"{index:08d}.bin"
                if selection.kind == "sqlite":
                    self._snapshot_sqlite(source, destination)
                else:
                    self._snapshot_file(source, destination)
                digest, size = _digest(destination)
                if size > MAX_ITEM_BYTES:
                    raise ValueError("backup item exceeds byte budget")
                staged.append((
                    BackupItem(
                        relative.as_posix(), selection.kind,
                        selection.privacy_class, digest, size,
                    ),
                    destination,
                ))
            if not staged:
                raise ValueError("backup contains no available selected items")
            manifest = BackupManifest(
                "angerona.backup/v1", backup_id, source_scope,
                float(self._clock()), tuple(item for item, _path in staged),
                sum(item.size_bytes for item, _path in staged),
            )
            self._write_archive(archive_path, manifest, staged)

        archive_digest, _archive_size = _digest(archive_path)
        manifest_digest = hashlib.sha256(manifest.canonical()).hexdigest()
        core = {
            "backup_id": backup_id, "archive_sha256": archive_digest,
            "manifest_sha256": manifest_digest, "item_count": len(manifest.items),
            "total_bytes": manifest.total_bytes, "created_at": manifest.created_at,
        }
        return BackupReceipt(
            **core, receipt_hmac=hmac.new(
                self._audit_key, _canonical(core), hashlib.sha256
            ).hexdigest(),
        )

    def verify_receipt(self, receipt: BackupReceipt) -> bool:
        value = asdict(receipt)
        signature = value.pop("receipt_hmac")
        return hmac.compare_digest(
            signature,
            hmac.new(self._audit_key, _canonical(value), hashlib.sha256).hexdigest(),
        )

    def verify(self, archive_path: Path) -> VerifiedBackup:
        archive_path = Path(archive_path).resolve(strict=True)
        archive_digest, _size = _digest(archive_path)
        manifest = self._scan_archive(archive_path)
        return VerifiedBackup(
            str(archive_path), archive_digest, manifest,
            hashlib.sha256(manifest.canonical()).hexdigest(),
        )

    def plan_restore(
        self,
        archive_path: Path,
        target_root: Path,
        *,
        plan_id: str,
        requested_by: str,
        ttl_seconds: int = 900,
    ) -> RestorePlan:
        if not _ID.fullmatch(plan_id) or not _ID.fullmatch(requested_by):
            raise ValueError("invalid restore identity")
        if not 60 <= int(ttl_seconds) <= 3600:
            raise ValueError("restore plan lifetime must be between 60 and 3600 seconds")
        verified = self.verify(archive_path)
        target_root = Path(target_root).resolve()
        created = float(self._clock())
        core = {
            "plan_id": plan_id,
            "archive_path": verified.archive_path,
            "archive_sha256": verified.archive_sha256,
            "manifest_sha256": verified.manifest_sha256,
            "target_root": str(target_root),
            "requested_by": requested_by,
            "created_at": created,
            "expires_at": created + int(ttl_seconds),
            "item_paths": tuple(item.relative_path for item in verified.manifest.items),
        }
        return RestorePlan(
            **core, plan_hmac=hmac.new(
                self._audit_key, _canonical(core), hashlib.sha256
            ).hexdigest(),
        )

    def authorize_restore(
        self, plan: RestorePlan, approvers: tuple[str, str],
    ) -> RestoreAuthorization:
        self._verify_plan(plan)
        approvers = tuple(approvers)
        if (
            len(approvers) != 2 or len(set(approvers)) != 2
            or plan.requested_by in approvers
            or any(not _ID.fullmatch(item) for item in approvers)
        ):
            raise PermissionError(
                "restore requires two distinct non-requester approvers"
            )
        core = {
            "plan_id": plan.plan_id, "plan_hmac": plan.plan_hmac,
            "approvers": approvers, "authorized_at": float(self._clock()),
        }
        return RestoreAuthorization(
            **core, authorization_hmac=hmac.new(
                self._audit_key, _canonical(core), hashlib.sha256
            ).hexdigest(),
        )

    def apply_restore(
        self,
        plan: RestorePlan,
        authorization: RestoreAuthorization,
        *,
        app_offline: bool,
    ) -> RestoreReceipt:
        if not app_offline:
            raise PermissionError("restore requires Angerona services to be offline")
        self._verify_plan(plan)
        self._verify_authorization(plan, authorization)
        if float(self._clock()) >= plan.expires_at:
            raise PermissionError("restore plan has expired")
        archive = Path(plan.archive_path)
        digest, _size = _digest(archive)
        if not hmac.compare_digest(digest, plan.archive_sha256):
            raise ValueError("restore archive changed after planning")

        target_root = Path(plan.target_root)
        target_root.mkdir(parents=True, exist_ok=True)
        if _has_reparse_component(target_root, PurePosixPath("__probe__")):
            raise ValueError("restore refuses a reparse-point target root")
        stage_root = target_root / f".restore-staging-{plan.plan_id}"
        rollback_parent = target_root / ".restore-rollback"
        if rollback_parent.exists() and _has_reparse_component(
            target_root, PurePosixPath(".restore-rollback")
        ):
            raise ValueError("restore refuses a reparse-point rollback root")
        rollback_root = rollback_parent / plan.plan_id
        if stage_root.exists() or rollback_root.exists():
            raise FileExistsError("restore staging or rollback scope already exists")
        stage_root.mkdir()
        installed: list[tuple[Path, Path | None]] = []
        try:
            manifest = self._scan_archive(archive, output_root=stage_root)
            if (
                hashlib.sha256(manifest.canonical()).hexdigest()
                != plan.manifest_sha256
            ):
                raise ValueError("restore manifest changed after planning")
            for item in manifest.items:
                relative = _relative(item.relative_path)
                if _has_reparse_component(target_root, relative):
                    raise ValueError("restore target traverses a reparse point")
                staged = stage_root.joinpath(*relative.parts)
                target = target_root.joinpath(*relative.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                previous: Path | None = None
                if target.exists():
                    if target.is_symlink() or not target.is_file():
                        raise ValueError("restore target is not a regular file")
                    previous = rollback_root.joinpath(*relative.parts)
                    previous.parent.mkdir(parents=True, exist_ok=True)
                    replace_with_retry(target, previous)
                # Register the rollback step immediately after the old target
                # moves. If antivirus or storage fails on the next replacement,
                # the exception path can still put the original file back.
                installed.append((target, previous))
                replace_with_retry(staged, target)
        except Exception:
            self._rollback(installed)
            raise
        finally:
            shutil.rmtree(stage_root, ignore_errors=True)

        core = {
            "plan_id": plan.plan_id,
            "archive_sha256": plan.archive_sha256,
            "restored_items": len(installed),
            "rollback_scope": str(
                PurePosixPath(".restore-rollback") / plan.plan_id
            ),
            "completed_at": float(self._clock()),
        }
        return RestoreReceipt(
            **core, receipt_hmac=hmac.new(
                self._audit_key, _canonical(core), hashlib.sha256
            ).hexdigest(),
        )

    def verify_restore_receipt(self, receipt: RestoreReceipt) -> bool:
        value = asdict(receipt)
        signature = value.pop("receipt_hmac")
        return hmac.compare_digest(
            signature,
            hmac.new(self._audit_key, _canonical(value), hashlib.sha256).hexdigest(),
        )

    @staticmethod
    def _snapshot_file(source: Path, destination: Path) -> None:
        with open(source, "rb") as incoming, open(destination, "xb") as outgoing:
            shutil.copyfileobj(incoming, outgoing, length=1024 * 1024)
            outgoing.flush()
            os.fsync(outgoing.fileno())
        os.chmod(destination, stat.S_IRUSR | stat.S_IWUSR)

    @staticmethod
    def _snapshot_sqlite(source: Path, destination: Path) -> None:
        source_uri = source.resolve().as_uri() + "?mode=ro"
        incoming = sqlite3.connect(source_uri, uri=True, timeout=3)
        outgoing = sqlite3.connect(str(destination))
        try:
            incoming.backup(outgoing)
            outgoing.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            outgoing.commit()
        finally:
            outgoing.close()
            incoming.close()
        os.chmod(destination, stat.S_IRUSR | stat.S_IWUSR)

    def _write_archive(
        self,
        path: Path,
        manifest: BackupManifest,
        staged: list[tuple[BackupItem, Path]],
    ) -> None:
        salt, nonce = os.urandom(16), os.urandom(12)
        header = _canonical({
            "schema": "angerona.backup-stream/v1",
            "backup_id": manifest.backup_id,
            "salt": _b64(salt), "nonce": _b64(nonce),
        })
        if len(header) > 4096:
            raise ValueError("backup header exceeds byte budget")
        key = _derive_key(self._encryption_key, salt)
        encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
        encryptor.authenticate_additional_data(header)
        temporary = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
        try:
            with open(temporary, "xb") as output:
                output.write(MAGIC)
                output.write(len(header).to_bytes(4, "big"))
                output.write(header)
                writer = _EncryptingWriter(output, encryptor)
                with tarfile.open(fileobj=writer, mode="w|") as archive:
                    self._add_bytes(
                        archive, "manifest.json", manifest.canonical(),
                    )
                    for index, (_item, staged_path) in enumerate(staged):
                        info = tarfile.TarInfo(f"data/{index:08d}.bin")
                        info.size = staged_path.stat().st_size
                        info.mode = 0o600
                        info.mtime = int(manifest.created_at)
                        with open(staged_path, "rb") as stream:
                            archive.addfile(info, stream)
                final = encryptor.finalize()
                if final:
                    output.write(final)
                output.write(encryptor.tag)
                output.flush()
                os.fsync(output.fileno())
            replace_with_retry(temporary, path)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    @staticmethod
    def _add_bytes(archive: tarfile.TarFile, name: str, value: bytes) -> None:
        info = tarfile.TarInfo(name)
        info.size = len(value)
        info.mode = 0o600
        info.mtime = 0
        archive.addfile(info, io.BytesIO(value))

    def _open_archive(
        self, path: Path,
    ) -> tuple[BinaryIO, _DecryptingReader, bytes]:
        stream = open(path, "rb")
        try:
            if stream.read(len(MAGIC)) != MAGIC:
                raise ValueError("not an Angerona encrypted backup")
            length_bytes = stream.read(4)
            if len(length_bytes) != 4:
                raise ValueError("encrypted backup header is truncated")
            header_length = int.from_bytes(length_bytes, "big")
            if not 1 <= header_length <= 4096:
                raise ValueError("encrypted backup header length is invalid")
            header = stream.read(header_length)
            value = json.loads(header)
            if value.get("schema") != "angerona.backup-stream/v1":
                raise ValueError("unsupported encrypted backup container")
            salt, nonce = _unb64(value["salt"]), _unb64(value["nonce"])
            if len(salt) != 16 or len(nonce) != 12:
                raise ValueError("invalid encrypted backup parameters")
            cipher_start = stream.tell()
            total_size = path.stat().st_size
            ciphertext_size = total_size - cipher_start - 16
            if ciphertext_size <= 0:
                raise ValueError("encrypted backup payload is missing")
            stream.seek(total_size - 16)
            tag = stream.read(16)
            stream.seek(cipher_start)
            key = _derive_key(self._encryption_key, salt)
            decryptor = Cipher(
                algorithms.AES(key), modes.GCM(nonce, tag)
            ).decryptor()
            decryptor.authenticate_additional_data(header)
            return stream, _DecryptingReader(
                stream, decryptor, ciphertext_size
            ), header
        except Exception:
            stream.close()
            raise

    def _scan_archive(
        self, path: Path, *, output_root: Path | None = None,
    ) -> BackupManifest:
        stream, reader, header = self._open_archive(path)
        del header
        try:
            with tarfile.open(fileobj=reader, mode="r|") as archive:
                member = archive.next()
                if (
                    member is None or member.name != "manifest.json"
                    or not member.isfile() or not 1 <= member.size <= 1024 * 1024
                ):
                    raise ValueError("backup manifest entry is invalid")
                manifest_stream = archive.extractfile(member)
                if manifest_stream is None:
                    raise ValueError("backup manifest cannot be read")
                raw = json.loads(manifest_stream.read())
                raw["items"] = tuple(BackupItem(**item) for item in raw["items"])
                manifest = BackupManifest(**raw)
                header_backup_id = json.loads(
                    self._read_header(path)
                ).get("backup_id")
                if header_backup_id != manifest.backup_id:
                    raise ValueError("backup header identity does not match manifest")
                for index, item in enumerate(manifest.items):
                    member = archive.next()
                    expected_name = f"data/{index:08d}.bin"
                    if (
                        member is None or member.name != expected_name
                        or not member.isfile() or member.size != item.size_bytes
                    ):
                        raise ValueError("backup payload entry is invalid")
                    incoming = archive.extractfile(member)
                    if incoming is None:
                        raise ValueError("backup payload cannot be read")
                    output = None
                    if output_root is not None:
                        relative = _relative(item.relative_path)
                        destination = output_root.joinpath(*relative.parts)
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        output = open(destination, "xb")
                    try:
                        hasher = hashlib.sha256()
                        size = 0
                        while chunk := incoming.read(1024 * 1024):
                            size += len(chunk)
                            if size > item.size_bytes:
                                raise ValueError("backup payload exceeds manifest size")
                            hasher.update(chunk)
                            if output is not None:
                                output.write(chunk)
                        if size != item.size_bytes or not hmac.compare_digest(
                            hasher.hexdigest(), item.sha256
                        ):
                            raise ValueError("backup payload digest mismatch")
                        if output is not None:
                            output.flush()
                            os.fsync(output.fileno())
                    finally:
                        if output is not None:
                            output.close()
                if archive.next() is not None:
                    raise ValueError("backup contains an unexpected extra entry")
            while reader.read(1024 * 1024):
                pass
            if not reader.done:
                reader._finish()
            return manifest
        finally:
            stream.close()

    @staticmethod
    def _read_header(path: Path) -> bytes:
        with open(path, "rb") as stream:
            if stream.read(len(MAGIC)) != MAGIC:
                raise ValueError("not an Angerona encrypted backup")
            size = int.from_bytes(stream.read(4), "big")
            return stream.read(size)

    def _verify_plan(self, plan: RestorePlan) -> None:
        value = asdict(plan)
        signature = value.pop("plan_hmac")
        if not hmac.compare_digest(
            signature,
            hmac.new(self._audit_key, _canonical(value), hashlib.sha256).hexdigest(),
        ):
            raise ValueError("restore plan authentication failed")

    def _verify_authorization(
        self, plan: RestorePlan, authorization: RestoreAuthorization,
    ) -> None:
        value = asdict(authorization)
        signature = value.pop("authorization_hmac")
        if (
            authorization.plan_id != plan.plan_id
            or authorization.plan_hmac != plan.plan_hmac
            or len(set(authorization.approvers)) != 2
            or plan.requested_by in authorization.approvers
            or not hmac.compare_digest(
                signature,
                hmac.new(
                    self._audit_key, _canonical(value), hashlib.sha256
                ).hexdigest(),
            )
        ):
            raise PermissionError("restore authorization is invalid")

    @staticmethod
    def _rollback(installed: list[tuple[Path, Path | None]]) -> None:
        for target, previous in reversed(installed):
            try:
                if target.exists():
                    target.unlink()
                if previous is not None and previous.exists():
                    replace_with_retry(previous, target)
            except OSError:
                # The original error remains authoritative. A retained rollback
                # artifact is safer than hiding the restore failure.
                pass
