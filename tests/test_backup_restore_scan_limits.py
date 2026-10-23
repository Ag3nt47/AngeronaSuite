from __future__ import annotations

import hashlib
import hmac
import io
import json
from pathlib import Path
import tarfile
import time

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from angerona.core import backup_restore as backup
from angerona.core import recovery_drill as drill
from angerona.core.engine_transport import canonical, private_directory


ENCRYPTION, AUDIT = b"e" * 32, b"a" * 32


def sparse_archive(tmp_path, logical_bytes):
    """Real authenticated ciphertext, with one physically tiny GNU sparse member."""
    digest = hashlib.sha256()
    for _ in range(logical_bytes // (1024 * 1024)):
        digest.update(bytes(1024 * 1024))
    manifest = backup.BackupManifest("angerona.backup/v1", "sparse-fixture-001", "inert-test", time.time(),
        (backup.BackupItem("inert.bin", "file", "restricted", digest.hexdigest(), logical_bytes),), logical_bytes)
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        info = tarfile.TarInfo("manifest.json")
        data = manifest.canonical()
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
        info = tarfile.TarInfo("data/00000000.bin")
        info.size = 1
        info.pax_headers = {"GNU.sparse.map": f"{logical_bytes - 1},1", "GNU.sparse.size": str(logical_bytes)}
        archive.addfile(info, io.BytesIO(b"\0"))
    salt, nonce = b"s" * 16, b"n" * 12
    header = backup._canonical(dict(schema="angerona.backup-stream/v1", backup_id=manifest.backup_id,
        salt=backup._b64(salt), nonce=backup._b64(nonce)))
    encryptor = Cipher(algorithms.AES(backup._derive_key(ENCRYPTION, salt)), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(header)
    wire = (backup.MAGIC + len(header).to_bytes(4, "big") + header + encryptor.update(raw.getvalue())
        + encryptor.finalize() + encryptor.tag)
    path = tmp_path / "sparse.angerona"
    path.write_bytes(wire)
    return path, manifest


@pytest.mark.parametrize("entrypoint", ["parser", "external-verify", "external-restore"])
def test_manifest_limit_rejects_sparse_expansion_before_payload_access(tmp_path, monkeypatch, entrypoint):
    path, manifest = sparse_archive(tmp_path, 32 * 1024 * 1024)
    original = tarfile.TarFile.extractfile
    payload_accesses = []

    def extractfile(archive, member):
        if member.name.startswith("data/"):
            payload_accesses.append(member.name)
            raise AssertionError("over-budget payload must not be opened")
        return original(archive, member)

    monkeypatch.setattr(tarfile.TarFile, "extractfile", extractfile)
    with pytest.raises(ValueError, match="scan limits"):
        if entrypoint == "parser":
            backup.EncryptedBackupManager(ENCRYPTION, AUDIT)._scan_archive(path, max_file_bytes=drill.MAX_FILE_BYTES)
        elif entrypoint == "external-verify":
            drill._external_backup_manager(ENCRYPTION, AUDIT, lambda: True).verify(path)
        else:
            drill.restore_external_archive(path, private_directory(tmp_path / "out"),
                encryption_key=ENCRYPTION, audit_key=AUDIT,
                archive_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                manifest_sha256=hashlib.sha256(manifest.canonical()).hexdigest(), evidence_sha256="f" * 64,
                source_revision="a" * 40, archive_size_bytes=path.stat().st_size)
    assert not payload_accesses


def test_sparse_encoding_rejected_within_drill_limit_and_generic_default_preserved(tmp_path):
    path, manifest = sparse_archive(tmp_path, 1024 * 1024)
    manager = backup.EncryptedBackupManager(ENCRYPTION, AUDIT)
    assert manager.verify(path).manifest == manifest
    with pytest.raises(ValueError, match="payload entry"):
        drill._external_backup_manager(ENCRYPTION, AUDIT, lambda: True).verify(path)


def test_logical_sparse_chunk_cancellation_does_not_depend_on_physical_io(tmp_path, monkeypatch):
    path, _manifest = sparse_archive(tmp_path, 8 * 1024 * 1024)
    original = tarfile.TarFile.extractfile
    reads = []

    class Reader:
        def __init__(self, stream):
            self.stream = stream

        def read(self, size=-1):
            data = self.stream.read(size)
            reads.append(len(data))
            return data

    def extractfile(archive, member):
        stream = original(archive, member)
        return Reader(stream) if member.name.startswith("data/") else stream

    monkeypatch.setattr(tarfile.TarFile, "extractfile", extractfile)
    with pytest.raises(InterruptedError, match="cancelled"):
        backup.EncryptedBackupManager(ENCRYPTION, AUDIT)._scan_archive(path, continue_work=lambda: not reads)
    assert reads == [1024 * 1024]


@pytest.mark.parametrize("limits", [{"max_files": 1}, {"max_total_bytes": 1}, {"max_path_parts": 1}])
def test_other_stricter_manifest_limits_reject_before_payload_access(tmp_path, monkeypatch, limits):
    source = tmp_path / "source"
    (source / "nested").mkdir(parents=True)
    (source / "nested/a").write_bytes(b"first")
    (source / "b").write_bytes(b"second")
    path = tmp_path / "ordinary.angerona"
    manager = backup.EncryptedBackupManager(ENCRYPTION, AUDIT)
    manager.create(path, source, [backup.BackupSelection("nested/a"), backup.BackupSelection("b")],
                   backup_id="ordinary-limits-001", source_scope="inert-test")
    original = tarfile.TarFile.extractfile

    def extractfile(archive, member):
        assert not member.name.startswith("data/"), "manifest limits must precede payload work"
        return original(archive, member)

    monkeypatch.setattr(tarfile.TarFile, "extractfile", extractfile)
    with pytest.raises(ValueError, match="scan limits"):
        manager._scan_archive(path, **limits)


def _ordinary_restore(tmp_path):
    source = tmp_path / "ordinary-source"
    source.mkdir()
    (source / "inert.bin").write_bytes(b"inert fixture")
    path = tmp_path / "ordinary.angerona"
    manager = backup.EncryptedBackupManager(ENCRYPTION, AUDIT)
    receipt = manager.create(path, source, [backup.BackupSelection("inert.bin")],
        backup_id="ordinary-fixture-001", source_scope="inert-test")
    result = drill.restore_external_archive(path, private_directory(tmp_path / "out"),
        encryption_key=ENCRYPTION, audit_key=AUDIT, archive_sha256=receipt.archive_sha256,
        manifest_sha256=receipt.manifest_sha256, evidence_sha256="f" * 64,
        source_revision="a" * 40, archive_size_bytes=path.stat().st_size)
    return Path(result["directory"])


def test_external_recheck_uses_strict_parser_even_for_authenticated_local_proof(tmp_path, monkeypatch):
    root = _ordinary_restore(tmp_path)
    sparse, manifest = sparse_archive(tmp_path, 32 * 1024 * 1024)
    wire = sparse.read_bytes()
    (root / "backup.angerona").write_bytes(wire)
    proof_path = root / "restore-proof.json"
    proof = json.loads(proof_path.read_bytes())
    proof["payload"].update(archive_sha256=hashlib.sha256(wire).hexdigest(), archive_size_bytes=len(wire),
                            manifest_sha256=hashlib.sha256(manifest.canonical()).hexdigest())
    proof["hmac_sha256"] = hmac.new(AUDIT, drill._RESTORE_DOMAIN + canonical(proof["payload"]), hashlib.sha256).hexdigest()
    proof_path.write_bytes(canonical(proof))
    original = tarfile.TarFile.extractfile

    def extractfile(archive, member):
        assert not member.name.startswith("data/"), "recheck must enforce bounds before payload work"
        return original(archive, member)

    monkeypatch.setattr(tarfile.TarFile, "extractfile", extractfile)
    with pytest.raises(ValueError, match="scan limits"):
        drill.verify_external_restore(root, encryption_key=ENCRYPTION, audit_key=AUDIT)


def test_external_recheck_cancels_between_logical_payload_reads(tmp_path, monkeypatch):
    root = _ordinary_restore(tmp_path)
    original = tarfile.TarFile.extractfile
    reads = []

    class Reader:
        def __init__(self, stream):
            self.stream = stream

        def read(self, size=-1):
            data = self.stream.read(size)
            reads.append(len(data))
            return data

    def extractfile(archive, member):
        stream = original(archive, member)
        return Reader(stream) if member.name.startswith("data/") else stream

    monkeypatch.setattr(tarfile.TarFile, "extractfile", extractfile)
    with pytest.raises(InterruptedError, match="cancelled"):
        drill.verify_external_restore(root, encryption_key=ENCRYPTION, audit_key=AUDIT, continue_work=lambda: not reads)
    assert reads == [len(b"inert fixture")]
