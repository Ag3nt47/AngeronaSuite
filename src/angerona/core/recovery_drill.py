"""Real encrypted-backup restore drills in newly created private directories.

This exercises EncryptedBackupManager's existing AES-GCM archive and extractor.
It does not authorize live restores, fabricate reviewer approvals, or certify
independent/offline recovery. Source files are read-only; decrypted test copies
remain in the private drill directory so later verification can reread them.
"""
from __future__ import annotations

import contextlib
from dataclasses import asdict
import hashlib
import hmac
from itertools import islice
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time
from typing import Iterable

from cryptography.exceptions import InvalidTag

from .backup_restore import BackupSelection, EncryptedBackupManager
from .engine_transport import canonical, create_private_file, decode, private_directory, verify_private
from .executable_trust import _open_sealed
from .source_sandbox import _absolute, _hold_plain_directories, _validate_chain, _validate_regular_file

SCHEMA = "angerona.recovery-drill/v1"
MAX_FILES = 64
MAX_FILE_BYTES = 16 * 1024**2
MAX_TOTAL_BYTES = 64 * 1024**2
MAX_ARCHIVE_BYTES = MAX_TOTAL_BYTES + 2 * 1024**2
_DOMAIN = b"Angerona-Recovery-Drill-v1\0"
_ITEM = re.compile(r"^item[0-9]{4}\.bin$")
ENCRYPTION_SECRET = "ANGERONA_RECOVERY_DRILL_ENCRYPTION_KEY"
AUDIT_SECRET = "ANGERONA_RECOVERY_DRILL_AUDIT_KEY"


def _keys(encryption_key: bytes, audit_key: bytes) -> None:
    if (not isinstance(encryption_key, bytes) or len(encryption_key) != 32
            or not isinstance(audit_key, bytes) or len(audit_key) != 32
            or hmac.compare_digest(encryption_key, audit_key)):
        raise ValueError("Drill encryption and audit keys must be distinct 32-byte values")


def _identity(info) -> tuple:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def _read_file(path: Path, *, maximum: int, destination: Path | None = None,
               continue_work=None) -> tuple[str, int]:
    """Bounded read/copy, denying linked inputs and checking held identity."""
    with _hold_plain_directories(path.parent):
        _validate_regular_file(path)
        before = path.lstat()
        if before.st_nlink != 1 or not 0 <= before.st_size <= maximum:
            raise ValueError("Drill input is linked or exceeds its byte limit")
        with _open_sealed(path) as incoming:
            opened = os.fstat(incoming.fileno())
            if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                    or _identity(opened) != _identity(before)):
                raise ValueError("Drill input changed before its read")
            hasher = hashlib.sha256()
            total = 0
            with contextlib.ExitStack() as stack:
                outgoing = stack.enter_context(destination.open("xb")) if destination else None
                while chunk := incoming.read(min(1024**2, maximum + 1 - total)):
                    if continue_work is not None and continue_work() is not True:
                        raise InterruptedError("Recovery work cancelled or workspace held")
                    total += len(chunk)
                    if total > maximum:
                        raise ValueError("Drill input grew past its byte limit")
                    hasher.update(chunk)
                    if outgoing is not None:
                        outgoing.write(chunk)
                if outgoing is not None:
                    outgoing.flush()
                    os.fsync(outgoing.fileno())
            if (total != before.st_size or _identity(os.fstat(incoming.fileno())) != _identity(before)
                    or _identity(path.lstat()) != _identity(before)):
                raise ValueError("Drill input changed during its read")
        return hasher.hexdigest(), total


def _verify_files(root: Path, items: list[dict]) -> None:
    with _hold_plain_directories(root):
        if {path.name for path in islice(root.iterdir(), MAX_FILES + 1)} != {item["stored_name"] for item in items}:
            raise ValueError("Restored file inventory changed")
        for item in items:
            digest, size = _read_file(root / item["stored_name"], maximum=MAX_FILE_BYTES)
            if size != item["size_bytes"] or not hmac.compare_digest(digest, item["sha256"]):
                raise ValueError("Restored file hash verification failed")


def _new_private(parent: Path, name: str) -> Path:
    path = parent / name
    if os.path.lexists(path):
        raise FileExistsError("Drill destination already exists")
    private_directory(path)
    return path


def run_drill(source_root: Path, relative_paths: Iterable[str], output_parent: Path, *,
              encryption_key: bytes, audit_key: bytes, fixture: bool = False) -> dict:
    """Snapshot selected files, encrypt, authenticate, restore and reread all bytes.

    Limits: 64 explicitly selected regular files, 16 MiB per file, 64 MiB total.
    Existing destination paths and live files are never overwritten.
    """
    _keys(encryption_key, audit_key)
    if isinstance(relative_paths, (str, bytes)):
        raise ValueError("Recovery drill selections must be an explicit sequence of paths")
    paths = tuple(islice(relative_paths, MAX_FILES + 1))
    if not 1 <= len(paths) <= MAX_FILES:
        raise ValueError("Select between 1 and 64 files for the restore drill")
    selections = [BackupSelection(path) for path in paths]
    if len({item.relative_path.casefold() for item in selections}) != len(selections):
        raise ValueError("Duplicate recovery drill selections")
    source_root, output_parent = _absolute(source_root), _absolute(output_parent)
    _validate_chain(source_root)
    _validate_chain(output_parent)
    if not source_root.is_dir() or not output_parent.is_dir():
        raise ValueError("Drill source and output parent must be existing directories")
    started = time.time()
    identity = secrets.token_hex(16)
    manager = EncryptedBackupManager(encryption_key, audit_key)
    with _hold_plain_directories(source_root, output_parent):
        root = _new_private(output_parent, "drill-" + identity)
        snapshots = _new_private(root, "snapshots")
        restored = _new_private(root, "restored")
        items = []
        with _hold_plain_directories(root, snapshots, restored):
            total = 0
            for index, selection in enumerate(selections):
                name = f"item{index:04d}.bin"
                source = source_root.joinpath(*Path(selection.relative_path).parts)
                digest, size = _read_file(source, maximum=min(MAX_FILE_BYTES, MAX_TOTAL_BYTES - total),
                                          destination=snapshots / name)
                total += size
                items.append({"label": selection.relative_path, "stored_name": name,
                              "sha256": digest, "size_bytes": size})
            archive = root / "backup.angerona"
            backup = manager.create(archive, snapshots,
                                    [BackupSelection(item["stored_name"]) for item in items],
                                    backup_id="drill-" + identity,
                                    source_scope="inert-fixture" if fixture else "selected-file-snapshots")
            if not manager.verify_receipt(backup):
                raise ValueError("Backup receipt authentication failed")
            with _open_sealed(archive):
                verified = manager.verify(archive)
                _match_manifest(verified, items, backup.archive_sha256, backup.manifest_sha256)
                # Deliberately use the existing authenticated extractor only
                # against this fresh, empty, pinned private directory. This
                # does not invoke the approval-gated live replacement path.
                manager._scan_archive(archive, output_root=restored)
                _verify_files(restored, items)
                negative = root / "tampered-negative-control.angerona"
                try:
                    _read_file(archive, maximum=MAX_ARCHIVE_BYTES, destination=negative)
                    with negative.open("r+b") as stream:
                        stream.seek(-1, os.SEEK_END)
                        value = stream.read(1)
                        stream.seek(-1, os.SEEK_END)
                        stream.write(bytes([value[0] ^ 1]))
                        stream.flush()
                        os.fsync(stream.fileno())
                    try:
                        manager.verify(negative)
                    except ValueError as exc:
                        # The existing backup reader wraps AES-GCM InvalidTag
                        # with its public ValueError. An unrelated I/O/parser
                        # failure is not a successful tamper-detection proof.
                        if not isinstance(exc.__cause__, InvalidTag):
                            raise
                        tamper_rejected = True
                    else:
                        raise ValueError("Encrypted archive tampering was not rejected")
                finally:
                    negative.unlink(missing_ok=True)
                # Receipt creation performs fresh archive AND restored reads;
                # a historical extraction result alone cannot establish PASS.
                fresh = manager.verify(archive)
                _match_manifest(fresh, items, backup.archive_sha256, backup.manifest_sha256)
                _verify_files(restored, items)
                completed = time.time()
                payload = {
                    "schema": SCHEMA, "drill_id": identity, "status": "passed",
                    "started_at": started, "completed_at": completed,
                    "restore_verified_at": completed, "file_count": len(items),
                    "total_bytes": total, "files": items,
                    "backup_receipt": asdict(backup),
                    "checks": {"encrypted_archive_authenticated": True,
                               "restored_files_reread": True,
                               "tampered_archive_rejected": tamper_rejected},
                    "scope": {"source": "inert-fixture" if fixture else "explicitly-selected-files",
                              "live_paths_modified": False, "independent_failure_domain": False,
                              "same_volume": source_root.stat().st_dev == root.stat().st_dev,
                              "offline_or_offsite_proven": False,
                              "key_recovery": "Requires the original encryption and audit keys",
                              "plaintext_test_copies_retained": True},
                }
                envelope = {"payload": payload, "hmac_sha256": hmac.new(
                    audit_key, _DOMAIN + canonical(payload), hashlib.sha256).hexdigest()}
                receipt_fd = create_private_file(root / "receipt.json")
                with os.fdopen(receipt_fd, "wb") as receipt_stream:
                    receipt_stream.write(canonical(envelope))
                    receipt_stream.flush()
                    os.fsync(receipt_stream.fileno())
            # Only flat files we created inside our private snapshot directory
            # are removed. The backup and test restore remain independently readable.
            for item in items:
                (snapshots / item["stored_name"]).unlink()
        snapshots.rmdir()
    return {"directory": str(root), "receipt": payload}


def _match_manifest(verified, items, archive_digest, manifest_digest):
    expected = {(item["stored_name"], item["sha256"], item["size_bytes"]) for item in items}
    observed = {(item.relative_path, item.sha256, item.size_bytes) for item in verified.manifest.items}
    if (observed != expected or len(verified.manifest.items) != len(items)
            or verified.archive_sha256 != archive_digest or verified.manifest_sha256 != manifest_digest):
        raise ValueError("Encrypted backup changed or does not match the selected snapshots")


def verify_drill(root: Path, *, encryption_key: bytes, audit_key: bytes) -> dict:
    """Authenticate the receipt and reread the current archive/restored files."""
    _keys(encryption_key, audit_key)
    root = _absolute(root)
    _validate_chain(root)
    verify_private(root, directory=True)
    with _hold_plain_directories(root, root / "restored"):
        receipt_path = root / "receipt.json"
        verify_private(receipt_path)
        _validate_regular_file(receipt_path)
        with _open_sealed(receipt_path) as stream:
            raw = stream.read(128 * 1024 + 1)
        if len(raw) > 128 * 1024:
            raise ValueError("Oversized recovery drill receipt")
        envelope = decode(raw)
        if set(envelope) != {"payload", "hmac_sha256"} or not isinstance(envelope["payload"], dict):
            raise ValueError("Invalid recovery drill receipt schema")
        payload, signature = envelope["payload"], envelope["hmac_sha256"]
        if (not isinstance(signature, str) or not hmac.compare_digest(signature, hmac.new(
                audit_key, _DOMAIN + canonical(payload), hashlib.sha256).hexdigest())):
            raise ValueError("Recovery drill receipt authentication failed")
        if payload.get("schema") != SCHEMA or payload.get("status") != "passed":
            raise ValueError("Receipt is not a passed supported recovery drill")
        items = payload.get("files")
        if not isinstance(items, list) or not 1 <= len(items) <= MAX_FILES:
            raise ValueError("Invalid recovery drill file inventory")
        for item in items:
            if (not isinstance(item, dict) or set(item) != {"label", "stored_name", "sha256", "size_bytes"}
                    or not isinstance(item["stored_name"], str) or not _ITEM.fullmatch(item["stored_name"])
                    or type(item["size_bytes"]) is not int or not 0 <= item["size_bytes"] <= MAX_FILE_BYTES
                    or not isinstance(item["sha256"], str) or not re.fullmatch("[0-9a-f]{64}", item["sha256"])):
                raise ValueError("Invalid recovery drill file entry")
        if len({item["stored_name"] for item in items}) != len(items):
            raise ValueError("Duplicate recovery drill file entry")
        if sum(item["size_bytes"] for item in items) > MAX_TOTAL_BYTES:
            raise ValueError("Recovery drill exceeds byte budget")
        archive = root / "backup.angerona"
        _read_file(archive, maximum=MAX_ARCHIVE_BYTES)
        manager = EncryptedBackupManager(encryption_key, audit_key)
        with _open_sealed(archive):
            verified = manager.verify(archive)
            backup = payload["backup_receipt"]
            _match_manifest(verified, items, backup["archive_sha256"], backup["manifest_sha256"])
            _verify_files(root / "restored", items)
        return {"valid": True, "checked_at": time.time(), "file_count": len(items),
                "total_bytes": sum(item["size_bytes"] for item in items),
                "scope": payload["scope"], "drill_id": payload["drill_id"]}


def fixture_drill(output_parent: Path, *, encryption_key: bytes, audit_key: bytes) -> dict:
    """Create a tiny inert selection, exercise real crypto/I/O, then remove inputs."""
    output_parent = _absolute(output_parent)
    _validate_chain(output_parent)
    with _hold_plain_directories(output_parent):
        source = _new_private(output_parent, ".fixture-" + secrets.token_hex(16))
        names = ("example.txt", "preferences.json", "bytes.bin")
        contents = (b"Angerona inert recovery drill. No executable content.\n",
                    b'{"fixture":true,"version":1}\n', bytes(range(256)) * 4)
        try:
            for name, content in zip(names, contents):
                with (source / name).open("xb") as stream:
                    stream.write(content)
            return run_drill(source, names, output_parent, encryption_key=encryption_key,
                             audit_key=audit_key, fixture=True)
        finally:
            for name in names:
                (source / name).unlink(missing_ok=True)
            source.rmdir()


def protected_keys(*, create: bool = False, data_root: Path | None = None) -> tuple[bytes, bytes]:
    """Load dedicated drill keys from the existing current-user OS secret store."""
    from .data_paths import data_dir
    from .secure_store import secret_transaction

    root = Path(data_root) if data_root is not None else data_dir()
    with secret_transaction(root):
        return _protected_keys_locked(create=create, data_root=root)


def _protected_keys_locked(*, create: bool, data_root: Path) -> tuple[bytes, bytes]:
    from .file_lease import ExclusiveFileLease
    from .secure_store import read_secret_values, write_secret_map
    root = Path(data_root)
    with ExclusiveFileLease(root / "recovery-drill-keys.lock"):
        values = read_secret_values((ENCRYPTION_SECRET, AUDIT_SECRET), root, strict=True)
        if not values and create:
            values = {ENCRYPTION_SECRET: secrets.token_hex(32), AUDIT_SECRET: secrets.token_hex(32)}
            write_secret_map(values, root)
            if read_secret_values((ENCRYPTION_SECRET, AUDIT_SECRET), root, strict=True) != values:
                raise RuntimeError("Recovery drill keys did not survive protected-store verification")
        if set(values) != {ENCRYPTION_SECRET, AUDIT_SECRET}:
            raise ValueError("Recovery drill keys are missing or incomplete; existing keys were not replaced")
        try:
            encryption, audit = bytes.fromhex(values[ENCRYPTION_SECRET]), bytes.fromhex(values[AUDIT_SECRET])
        except ValueError as exc:
            raise ValueError("Stored recovery drill keys are invalid") from exc
        _keys(encryption, audit)
        return encryption, audit


RESTORE_PROOF_SCHEMA = "angerona.isolated-recovery-proof/v1"
_RESTORE_DOMAIN = b"Angerona-Isolated-Recovery-Proof-v1\0"


def _restore_inventory(root, items, continue_work):
    """Reread every actual extracted byte and reject additional files/aliases."""
    expected = {item.relative_path: item for item in items}
    seen, entries = set(), 0
    for directory, folders, files in os.walk(root, followlinks=False):
        if continue_work() is not True:
            raise InterruptedError("Recovery work cancelled or workspace held")
        _validate_chain(Path(directory))
        for name in (*folders, *files):
            entries += 1
            if entries > 1088:
                raise ValueError("Isolated restore inventory exceeds its entry budget")
            _validate_chain(Path(directory) / name)
        for name in files:
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            if relative not in expected:
                raise ValueError("Unexpected isolated restore file")
            item = expected[relative]
            digest, size = _read_file(path, maximum=MAX_FILE_BYTES, continue_work=continue_work)
            if size != item.size_bytes or not hmac.compare_digest(digest, item.sha256):
                raise ValueError("Isolated restored file hash verification failed")
            seen.add(relative)
    if seen != set(expected):
        raise ValueError("Isolated restored inventory is incomplete")
    return [{"path": name, "size_bytes": expected[name].size_bytes,
             "sha256": expected[name].sha256} for name in sorted(seen)]


def _external_backup_manager(encryption_key, audit_key, continue_work):
    """Use the existing parser with drill bounds before logical payload reads."""
    def check():
        if continue_work() is not True:
            raise InterruptedError("Recovery work cancelled or workspace held")

    class Reader:
        def __init__(self, reader):
            self.reader = reader

        def read(self, size=-1):
            check()
            return self.reader.read(size)

        def __getattr__(self, name):
            return getattr(self.reader, name)

    class Manager(EncryptedBackupManager):
        def _open_archive(self, path):
            check()
            stream, reader, header = super()._open_archive(path)
            return stream, Reader(reader), header

        def _scan_archive(self, path, *, output_root=None):
            return super()._scan_archive(path, output_root=output_root,
                max_files=MAX_FILES, max_file_bytes=MAX_FILE_BYTES,
                max_total_bytes=MAX_TOTAL_BYTES, max_path_parts=16,
                reject_sparse=True, continue_work=continue_work)

    return Manager(encryption_key, audit_key)


def restore_external_archive(archive_path, output_parent, *, encryption_key, audit_key,
                             archive_sha256, manifest_sha256, evidence_sha256,
                             source_revision, archive_size_bytes, continue_work=lambda: True):
    """Restore an explicitly selected authenticated archive into a NEW private root.

    The workflow separately verifies the signed copy statement. This proof binds
    its exact envelope digest, archive, manifest, actual extraction/reread and
    measured elapsed time. It never authorizes replacement of a live path.
    """
    _keys(encryption_key, audit_key)
    if type(archive_size_bytes) is not int or not 1 <= archive_size_bytes <= MAX_ARCHIVE_BYTES:
        raise ValueError("Signed archive size exceeds isolated restore bounds")
    for value in (archive_sha256, manifest_sha256, evidence_sha256):
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("Invalid isolated restore binding digest")
    if not isinstance(source_revision, str) or not re.fullmatch(r"[0-9a-f]{40,64}", source_revision):
        raise ValueError("Invalid isolated restore source revision")

    def check():
        if continue_work() is not True:
            raise InterruptedError("Recovery work cancelled or workspace held")

    check()
    archive_path, output_parent = _absolute(archive_path), _absolute(output_parent)
    _validate_chain(archive_path)
    _validate_chain(output_parent)
    verify_private(output_parent, directory=True)
    started, began = time.time(), time.monotonic()
    identity = secrets.token_hex(16)
    with _hold_plain_directories(archive_path.parent, output_parent):
        root = _new_private(output_parent, "restore-" + identity)
        saved_archive = root / "backup.angerona"
        digest, _size = _read_file(archive_path, maximum=MAX_ARCHIVE_BYTES,
                                 destination=saved_archive, continue_work=continue_work)
        if _size != archive_size_bytes or not hmac.compare_digest(digest, archive_sha256):
            raise ValueError("Selected archive differs from the enrolled signed statement")
        manager = _external_backup_manager(encryption_key, audit_key, continue_work)
        with _open_sealed(saved_archive):
            verified = manager.verify(saved_archive)
            manifest = verified.manifest
            if (verified.archive_sha256 != archive_sha256 or verified.manifest_sha256 != manifest_sha256
                    or not 1 <= len(manifest.items) <= MAX_FILES or manifest.total_bytes > MAX_TOTAL_BYTES
                    or any(item.size_bytes > MAX_FILE_BYTES or len(Path(item.relative_path).parts) > 16
                           for item in manifest.items)):
                raise ValueError("Archive manifest differs from signed evidence or exceeds drill bounds")
            restored = _new_private(root, "restored")
            parents = {restored}
            for item in manifest.items:
                check()
                path = restored
                for part in Path(item.relative_path).parts[:-1]:
                    check()
                    path = path / part
                    private_directory(path)
                    parents.add(path)
            with _hold_plain_directories(root, *sorted(parents)):
                check()
                manager._scan_archive(saved_archive, output_root=restored)
                inventory = _restore_inventory(restored, manifest.items, continue_work)
                fresh = manager.verify(saved_archive)
                if fresh.archive_sha256 != digest or fresh.manifest_sha256 != manifest_sha256:
                    raise ValueError("Archive changed during the isolated restore")
                check()
                payload = {"schema": RESTORE_PROOF_SCHEMA, "restore_id": identity,
                    "status": "passed", "started_at": started, "completed_at": time.time(),
                    "duration_seconds": time.monotonic() - began,
                    "source_revision": source_revision, "archive_sha256": digest,
                    "archive_size_bytes": archive_size_bytes,
                    "manifest_sha256": manifest_sha256, "evidence_sha256": evidence_sha256,
                    "inventory": inventory, "actual_restored_bytes_reread": True,
                    "live_paths_modified": False, "physical_independence_proven": False,
                    "plaintext_test_copies_retained": True}
                proof = {"payload": payload, "hmac_sha256": hmac.new(
                    audit_key, _RESTORE_DOMAIN + canonical(payload), hashlib.sha256).hexdigest()}
                descriptor = create_private_file(root / "restore-proof.json")
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(canonical(proof))
                    stream.flush()
                    os.fsync(stream.fileno())
    return {"directory": str(root), "proof": payload}


def verify_external_restore(root, *, encryption_key, audit_key, continue_work=lambda: True):
    """Validate the separate restore proof and freshly reread its actual output."""
    import math

    _keys(encryption_key, audit_key)
    root = _absolute(root)
    _validate_chain(root)
    verify_private(root, directory=True)
    with _hold_plain_directories(root, root / "restored"):
        path = root / "restore-proof.json"
        verify_private(path)
        with _open_sealed(path) as stream:
            raw = stream.read(128 * 1024 + 1)
        if len(raw) > 128 * 1024:
            raise ValueError("Isolated restore proof exceeds its byte bound")
        envelope = decode(raw)
        if set(envelope) != {"payload", "hmac_sha256"} or not isinstance(envelope["payload"], dict):
            raise ValueError("Isolated restore proof schema is invalid")
        payload, signature = envelope["payload"], envelope["hmac_sha256"]
        fields = {"schema", "restore_id", "status", "started_at", "completed_at", "duration_seconds",
                  "source_revision", "archive_sha256", "archive_size_bytes", "manifest_sha256", "evidence_sha256", "inventory",
                  "actual_restored_bytes_reread", "live_paths_modified", "physical_independence_proven",
                  "plaintext_test_copies_retained"}
        if (set(payload) != fields or not isinstance(signature, str) or not re.fullmatch("[0-9a-f]{64}", signature)
                or not hmac.compare_digest(signature, hmac.new(audit_key,
                    _RESTORE_DOMAIN + canonical(payload), hashlib.sha256).hexdigest())
                or payload["schema"] != RESTORE_PROOF_SCHEMA or payload["status"] != "passed"
                or payload["actual_restored_bytes_reread"] is not True
                or payload["live_paths_modified"] is not False or payload["physical_independence_proven"] is not False
                or payload["plaintext_test_copies_retained"] is not True
                or not isinstance(payload["restore_id"], str) or not re.fullmatch("[0-9a-f]{32}", payload["restore_id"])):
            raise ValueError("Isolated restore proof authentication or scope is invalid")
        for name in ("started_at", "completed_at", "duration_seconds"):
            value = payload[name]
            if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                raise ValueError("Isolated restore measurement is invalid")
        if payload["completed_at"] < payload["started_at"]:
            raise ValueError("Isolated restore clock ordering is invalid")
        if (not isinstance(payload["source_revision"], str)
                or not re.fullmatch("[0-9a-f]{40,64}", payload["source_revision"])
                or any(not isinstance(payload[name], str) or not re.fullmatch("[0-9a-f]{64}", payload[name])
                       for name in ("archive_sha256", "manifest_sha256", "evidence_sha256"))):
            raise ValueError("Isolated restore proof identity is invalid")
        if not isinstance(payload["inventory"], list) or not 1 <= len(payload["inventory"]) <= MAX_FILES:
            raise ValueError("Isolated restore proof inventory is invalid")
        if continue_work() is not True:
            raise InterruptedError("Recovery work cancelled or workspace held")
        archive = root / "backup.angerona"
        _digest, size = _read_file(archive, maximum=MAX_ARCHIVE_BYTES, continue_work=continue_work)
        if size != payload["archive_size_bytes"] or type(payload["archive_size_bytes"]) is not int:
            raise ValueError("Isolated restore archive size no longer matches its proof")
        with _open_sealed(archive):
            verified = _external_backup_manager(encryption_key, audit_key, continue_work).verify(archive)
            if (verified.archive_sha256 != payload["archive_sha256"]
                    or verified.manifest_sha256 != payload["manifest_sha256"]
                    or len(verified.manifest.items) > MAX_FILES
                    or verified.manifest.total_bytes > MAX_TOTAL_BYTES):
                raise ValueError("Isolated restore archive no longer matches its proof")
            inventory = _restore_inventory(root / "restored", verified.manifest.items, continue_work)
            if inventory != payload["inventory"]:
                raise ValueError("Isolated restore output no longer matches its proof")
        return {"valid": True, "checked_at": time.time(), "proof": payload}
