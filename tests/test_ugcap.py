from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import secrets
import zlib

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from angerona.core.ugcap import (
    PBKDF2_ITERATIONS, StaleReportError, UGCAPError, UGCAPVault,
    VaultAuthenticationError, VaultCoverageError,
)

PASSCODE = "test-only-passphrase-with-hardware"


class HardwareFixture:
    """Injected hardware boundary; real AES protects the sealed test secret."""

    def __init__(self, identity="fixture-tpm"):
        self.name = identity
        self.key = secrets.token_bytes(32)
        self.challenges = []

    def identity(self):
        return {"provider": "injected-test-provider", "key_id": self.name}

    def seal(self, secret):
        nonce = secrets.token_bytes(12)
        blob = AESGCM(self.key).encrypt(nonce, secret, self.name.encode())
        return {"nonce": base64.b64encode(nonce).decode(), "ciphertext": base64.b64encode(blob).decode()}

    def unseal(self, descriptor, challenge):
        assert isinstance(challenge, bytes) and len(challenge) == 32
        self.challenges.append(challenge)
        return AESGCM(self.key).decrypt(base64.b64decode(descriptor["nonce"]),
                                       base64.b64decode(descriptor["ciphertext"]), self.name.encode())


@pytest.fixture
def fixture_vault(tmp_path):
    root, media = tmp_path / "repo", tmp_path / "secondary-media"
    root.mkdir()
    media.mkdir()
    (root / "src").mkdir()
    (root / "src" / "main.py").write_bytes(b"PRISTINE_SOURCE_SENTINEL = True\n")
    (root / "README.md").write_bytes(b"fixture documentation\n")
    hardware = HardwareFixture()
    vault = UGCAPVault(root, media / "angerona.ugcap", hardware,
                      media_validator=lambda *_: {"volume_id": "fixture-secondary", "validated": True})
    return vault, root, hardware


def test_explicit_enrollment_encryption_and_fresh_hardware_proof(fixture_vault):
    vault, root, hardware = fixture_vault
    assert not vault.snapshot()["initialized"]
    assert not vault.vault_path.exists()
    result = vault.initialize(bytearray(PASSCODE.encode()))
    assert result["status"] == "initialized"
    assert result["coverage"]["files_scanned"] == 2
    assert b"PRISTINE_SOURCE_SENTINEL" not in vault.vault_path.read_bytes()
    assert b"initialized" not in vault.audit_path.read_bytes()
    assert PBKDF2_ITERATIONS >= 600_000
    report = vault.verify(PASSCODE.encode())
    assert report["status"] == "verified"
    assert report["coverage"]["complete"]
    assert report["audit"] == {"recorded": True, "rollback_proof": False}
    assert len(hardware.challenges) == 2 and len(set(hardware.challenges)) == 2
    assert vault.snapshot()["locked"]
    assert vault.snapshot()["last_report"]["report_id"] == report["report_id"]
    with pytest.raises(UGCAPError, match="never be overwritten"):
        vault.initialize(PASSCODE)


def test_modification_addition_missing_and_explicit_restore(fixture_vault):
    vault, root, _hardware = fixture_vault
    vault.initialize(PASSCODE)
    (root / "src" / "main.py").write_bytes(b"tampered\n")
    (root / "README.md").unlink()
    (root / "src" / "added.py").write_bytes(b"added threat fixture\n")
    report = vault.verify(PASSCODE)
    assert report["status"] == "drift"
    assert report["changes"] == {"added": ["src/added.py"], "missing": ["README.md"],
                                  "modified": ["src/main.py"], "read_errors": []}
    result = vault.restore(PASSCODE, ["src/main.py", "README.md"], expected_report_id=report["report_id"])
    assert result["status"] == ("restored" if os.name == "nt" else "deferred")
    assert result["restart_required"]
    assert (root / "src" / "main.py").read_bytes() == (b"PRISTINE_SOURCE_SENTINEL = True\n" if os.name == "nt" else b"tampered\n")
    assert (root / "README.md").read_bytes() == b"fixture documentation\n"
    assert (root / "src" / "added.py").is_file()
    assert not list(root.rglob(".ugcap-stage-*"))
    with pytest.raises(StaleReportError):
        vault.restore(PASSCODE, ["src/main.py"], expected_report_id=report["report_id"])


def test_wrong_passphrase_and_hardware_mismatch_never_restore(fixture_vault):
    vault, root, hardware = fixture_vault
    vault.initialize(PASSCODE)
    with pytest.raises(VaultAuthenticationError):
        vault.verify("wrong-passphrase-for-this-test")
    hardware.name = "different-hardware"
    with pytest.raises(VaultAuthenticationError):
        vault.verify(PASSCODE)
    hardware.name = "fixture-tpm"
    hardware.key = secrets.token_bytes(32)  # same display identity is insufficient
    with pytest.raises(VaultAuthenticationError):
        vault.verify(PASSCODE)
    assert (root / "src" / "main.py").read_bytes().startswith(b"PRISTINE")


@pytest.mark.parametrize("target", ["ciphertext", "salt", "iterations", "sealed", "audit"])
def test_container_parameters_and_audit_are_authenticated(fixture_vault, target):
    vault, _root, _hardware = fixture_vault
    vault.initialize(PASSCODE)
    if target == "audit":
        value = json.loads(vault.audit_path.read_bytes())
        raw = bytearray(base64.b64decode(value["ciphertext"]))
        raw[0] ^= 1
        value["ciphertext"] = base64.b64encode(raw).decode()
        vault.audit_path.write_text(json.dumps(value))
    else:
        value = json.loads(vault.vault_path.read_bytes())
        if target == "ciphertext":
            raw = bytearray(base64.b64decode(value["ciphertext"]))
            raw[-1] ^= 1
            value["ciphertext"] = base64.b64encode(raw).decode()
        elif target == "iterations":
            value["header"]["iterations"] = 1
        elif target == "salt":
            value["header"]["salt"] = base64.b64encode(b"x" * 16).decode()
        else:
            value["header"]["sealed"]["ciphertext"] = base64.b64encode(b"x" * 48).decode()
        vault.vault_path.write_text(json.dumps(value))
    with pytest.raises(VaultAuthenticationError):
        vault.verify(PASSCODE)


def test_restore_binds_current_bytes_even_when_modified_path_set_is_unchanged(fixture_vault):
    vault, root, _hardware = fixture_vault
    vault.initialize(PASSCODE)
    target = root / "src" / "main.py"
    target.write_bytes(b"first suspicious change")
    report = vault.verify(PASSCODE)
    target.write_bytes(b"second suspicious change")
    with pytest.raises(StaleReportError, match="changed after verification"):
        vault.restore(PASSCODE, ["src/main.py"], expected_report_id=report["report_id"])
    assert target.read_bytes() == b"second suspicious change"


@pytest.mark.parametrize("path", ["../outside.py", "src/../main.py", "C:/escape.py", "/absolute.py", "src/main.py:ads", ".git/config", "src//main.py"])
def test_restore_refuses_traversal_and_non_report_paths(fixture_vault, path):
    vault, root, _hardware = fixture_vault
    vault.initialize(PASSCODE)
    (root / "src" / "main.py").write_bytes(b"changed")
    report = vault.verify(PASSCODE)
    with pytest.raises(UGCAPError):
        vault.restore(PASSCODE, [path], expected_report_id=report["report_id"])
    assert (root / "src" / "main.py").read_bytes() == b"changed"


def test_added_and_binary_files_require_manual_offline_review(fixture_vault):
    vault, root, _hardware = fixture_vault
    (root / "src" / "helper.dll").write_bytes(b"original binary")
    vault.initialize(PASSCODE)
    (root / "src" / "helper.dll").write_bytes(b"changed binary")
    (root / "src" / "new.py").write_bytes(b"unknown addition")
    report = vault.verify(PASSCODE)
    result = vault.restore(PASSCODE, ["src/helper.dll", "src/new.py"], expected_report_id=report["report_id"])
    assert result["deferred"] == ["src/helper.dll"]
    assert result["non_restorable"] == ["src/new.py"]
    assert result["restart_required"]
    assert (root / "src" / "helper.dll").read_bytes() == b"changed binary"
    assert (root / "src" / "new.py").read_bytes() == b"unknown addition"


def test_readonly_audit_media_allows_incomplete_diagnostics_but_blocks_restore(fixture_vault, monkeypatch):
    vault, root, _hardware = fixture_vault
    vault.initialize(PASSCODE)
    (root / "src" / "main.py").write_bytes(b"changed")

    def readonly(*_args):
        raise PermissionError("fixture secondary media is read-only")

    monkeypatch.setattr(vault, "_write_exclusive", readonly)
    report = vault.verify(PASSCODE)
    assert report["status"] == "incomplete"
    assert not report["coverage"]["complete"]
    assert not report["audit"]["recorded"]
    with pytest.raises(StaleReportError):
        vault.restore(PASSCODE, ["src/main.py"], expected_report_id=report["report_id"])


def test_unreadable_file_is_incomplete_and_cannot_be_enrolled(fixture_vault, monkeypatch):
    vault, _root, _hardware = fixture_vault
    real_read = vault._read

    def unreadable(path, limit):
        if path.name == "main.py":
            raise PermissionError("fixture source access refused")
        return real_read(path, limit)

    monkeypatch.setattr(vault, "_read", unreadable)
    with pytest.raises(VaultCoverageError, match="complete non-empty coverage"):
        vault.initialize(PASSCODE)
    assert not vault.vault_path.exists()


def test_hardlinks_refused_and_excluded_runtime_never_enrolled(fixture_vault):
    vault, root, _hardware = fixture_vault
    (root / "runtime-data").mkdir()
    (root / "runtime-data" / "secret.txt").write_bytes(b"RUNTIME_SECRET")
    source = root / "src" / "main.py"
    os.link(source, root / "src" / "alias.py")
    with pytest.raises(VaultCoverageError):
        vault.initialize(PASSCODE)
    (root / "src" / "alias.py").unlink()
    vault.initialize(PASSCODE)
    header, files, key = None, None, None
    with vault._operation():
        header, files, key = vault._unlock(PASSCODE)
    key[:] = b"\0" * len(key)
    assert header["hash"] == "BLAKE3-256"
    assert "runtime-data/secret.txt" not in files
    assert "src/main.py" in files


def test_symlink_or_reparse_never_enrolled(fixture_vault):
    vault, root, _hardware = fixture_vault
    try:
        (root / "src" / "alias.py").symlink_to(root / "src" / "main.py")
    except OSError:
        pytest.skip("creating symlinks requires Windows developer mode or privilege")
    with pytest.raises(VaultCoverageError):
        vault.initialize(PASSCODE)


def test_volume_identity_guard_and_inside_repository_refusal(fixture_vault):
    vault, root, hardware = fixture_vault
    same_volume = UGCAPVault(root, vault.vault_path, hardware)
    with pytest.raises(UGCAPError, match="different independently identified volume"):
        same_volume.initialize(PASSCODE)
    inside = UGCAPVault(root, root / "inside.ugcap", hardware, media_validator=lambda *_: True)
    with pytest.raises(UGCAPError, match="outside the protected repository"):
        inside.initialize(PASSCODE)


def test_operation_deadline_and_lock_invalidate_authority(fixture_vault, monkeypatch):
    vault, root, _hardware = fixture_vault
    vault.initialize(PASSCODE)
    (root / "src" / "main.py").write_bytes(b"changed")
    report = vault.verify(PASSCODE)
    vault.lock()
    assert vault.snapshot()["last_report"] is None
    with pytest.raises(StaleReportError):
        vault.restore(PASSCODE, ["src/main.py"], expected_report_id=report["report_id"])
    now = [0.0]

    def advance():
        now[0] += 121
        return now[0]

    monkeypatch.setattr(vault, "_clock", advance)
    with pytest.raises(UGCAPError, match="time budget"):
        vault.verify(PASSCODE)


@pytest.mark.parametrize("limit,value", [("MAX_FILE_BYTES", 8), ("MAX_TOTAL_BYTES", 8), ("MAX_FILES", 1), ("MAX_ENTRIES", 1)])
def test_file_limits_refuse_incomplete_baseline(fixture_vault, monkeypatch, limit, value):
    vault, _root, _hardware = fixture_vault
    monkeypatch.setattr("angerona.core.ugcap." + limit, value)
    with pytest.raises(VaultCoverageError):
        vault.initialize(PASSCODE)
    assert not vault.vault_path.exists()


def _rewrite_authenticated_payload(vault, mutate):
    """Authorized test key builds an invalid inner manifest, not a live vault."""
    with vault._operation():
        header, files, key = vault._unlock(PASSCODE)
        try:
            payload = {"files": list(files.values()), "total_bytes": sum(row["size"] for row in files.values())}
            plain = mutate(payload)
            if isinstance(plain, dict):
                plain = json.dumps(plain).encode()
            nonce = secrets.token_bytes(12)
            header["nonce"] = base64.b64encode(nonce).decode()
            from angerona.core.ugcap import _canonical
            encrypted = AESGCM(bytes(key)).encrypt(nonce, zlib.compress(plain), _canonical(header))
            vault.vault_path.write_bytes(_canonical({"header": header, "ciphertext": base64.b64encode(encrypted).decode()}))
        finally:
            key[:] = b"\0" * len(key)


def test_authenticated_inner_manifest_still_rejects_path_traversal(fixture_vault):
    vault, root, _hardware = fixture_vault
    vault.initialize(PASSCODE)

    def traverse(payload):
        payload["files"][0]["path"] = "../escape.py"
        return payload

    _rewrite_authenticated_payload(vault, traverse)
    with pytest.raises(UGCAPError):
        vault.verify(PASSCODE)
    assert not (root.parent / "escape.py").exists()


def test_bounded_decompression_refuses_authenticated_bomb(fixture_vault, monkeypatch):
    vault, _root, _hardware = fixture_vault
    vault.initialize(PASSCODE)
    _rewrite_authenticated_payload(vault, lambda _payload: b"X" * 100_000)
    monkeypatch.setattr("angerona.core.ugcap.MAX_PAYLOAD_BYTES", 512)
    with pytest.raises(VaultAuthenticationError):
        vault.verify(PASSCODE)


def test_blake3_dependency_failure_has_no_hash_fallback(fixture_vault, monkeypatch):
    import builtins
    vault, _root, _hardware = fixture_vault
    real_import = builtins.__import__

    def without_blake3(name, *args, **kwargs):
        if name == "blake3":
            raise ImportError("fixture dependency unavailable")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", without_blake3)
    with pytest.raises(UGCAPError, match="no substitute hash"):
        vault.initialize(PASSCODE)
    assert not vault.vault_path.exists()


def test_renamed_executable_and_versioned_shared_library_are_deferred(fixture_vault):
    vault, root, _hardware = fixture_vault
    (root / "src" / "renamed.dat").write_bytes(b"\x7fELFpristine")
    (root / "libexample.so.1").write_bytes(b"ELF fixture")
    vault.initialize(PASSCODE)
    (root / "src" / "renamed.dat").write_bytes(b"tampered")
    (root / "libexample.so.1").write_bytes(b"tampered")
    report = vault.verify(PASSCODE)
    result = vault.restore(PASSCODE, ["src/renamed.dat", "libexample.so.1"], expected_report_id=report["report_id"])
    assert result["status"] == "deferred"
    assert result["restored"] == []
    assert set(result["deferred"]) == {"src/renamed.dat", "libexample.so.1"}


def test_tamper_evident_audit_does_not_claim_rollback_proof(fixture_vault):
    vault, _root, _hardware = fixture_vault
    vault.initialize(PASSCODE)
    previous = vault.audit_path.read_bytes()
    vault.verify(PASSCODE)
    vault.audit_path.with_name(vault.audit_path.name + ".00000001").unlink()
    vault.audit_path.write_bytes(previous)
    report = vault.verify(PASSCODE)
    assert report["status"] == "verified"
    assert not report["audit"]["rollback_proof"]
    assert "not rollback-proof" in vault.snapshot()["detail"]


def test_pending_initial_audit_resumes_only_explicitly_without_rebaselining(fixture_vault, monkeypatch):
    vault, root, _hardware = fixture_vault
    real_write = vault._write_exclusive

    def fail_initial_audit(path, payload):
        if path == vault.audit_path:
            raise PermissionError("fixture initial audit unavailable")
        return real_write(path, payload)

    monkeypatch.setattr(vault, "_write_exclusive", fail_initial_audit)
    with pytest.raises(PermissionError):
        vault.initialize(PASSCODE)
    original = vault.vault_path.read_bytes()
    generation = json.loads(original)["header"]["generation"]
    assert vault.snapshot()["pending_enrollment"]
    with pytest.raises(VaultAuthenticationError):
        vault.verify(PASSCODE)  # verify never silently repairs pending enrollment
    monkeypatch.setattr(vault, "_write_exclusive", real_write)
    (root / "src" / "added.py").write_bytes(b"unapproved new file")
    with pytest.raises(VaultCoverageError, match="pending enrollment differs"):
        vault.initialize(PASSCODE)
    (root / "src" / "added.py").unlink()
    result = vault.initialize(PASSCODE)
    assert result["resumed"]
    assert result["generation"] == generation
    assert vault.vault_path.read_bytes() == original
    assert vault.verify(PASSCODE)["status"] == "verified"


def test_casefold_collisions_refuse_enrollment_before_writing(fixture_vault, monkeypatch):
    vault, _root, _hardware = fixture_vault
    with vault._operation():
        files, errors, coverage = vault._scan(backups=True)
    files["readme.md"] = {**files["README.md"], "path": "readme.md"}
    coverage["bytes_scanned"] += files["readme.md"]["size"]
    monkeypatch.setattr(vault, "_scan", lambda **_kwargs: (files, errors, coverage))
    with pytest.raises(VaultAuthenticationError, match="duplicate"):
        vault.initialize(PASSCODE)
    assert not vault.vault_path.exists()


def test_verified_receipt_is_detached_and_absent_for_drift(fixture_vault):
    vault, root, _hardware = fixture_vault
    vault.initialize(PASSCODE)
    report = vault.verify(PASSCODE)
    receipt = report["verification_receipt"]
    assert receipt["generation"] == report["generation"]
    assert len(receipt["source_manifest_digest"]) == 64
    assert receipt["verified_files"]["src/main.py"] == report["observations"]["src/main.py"]["blake3"]
    receipt["verified_files"]["src/main.py"] = "forged by report consumer"
    assert vault.snapshot()["last_report"]["verification_receipt"]["verified_files"]["src/main.py"] != "forged by report consumer"
    (root / "src" / "main.py").write_bytes(b"changed")
    assert "verification_receipt" not in vault.verify(PASSCODE)


def test_missing_restore_cannot_overwrite_raced_new_target(fixture_vault, monkeypatch):
    if os.name != "nt":
        pytest.skip("Windows handle-pinned no-replace path; POSIX exercises dirfd path separately")
    from angerona.modules.adversary_combat import _PinnedFileMove
    vault, root, _hardware = fixture_vault
    vault.initialize(PASSCODE)
    target = root / "README.md"
    target.unlink()
    report = vault.verify(PASSCODE)
    real_rename = _PinnedFileMove.rename_to

    def raced(pinned, destination):
        if pinned.path.name == "pristine.stage" and destination == target:
            target.write_bytes(b"unapproved replacement")
        return real_rename(pinned, destination)

    monkeypatch.setattr(_PinnedFileMove, "rename_to", raced)
    result = vault.restore(PASSCODE, ["README.md"], expected_report_id=report["report_id"])
    assert result["status"] == "partial"
    assert result["errors"]
    assert target.read_bytes() == b"unapproved replacement"


def test_windows_modified_target_remains_pinned_until_displacement(fixture_vault, monkeypatch):
    if os.name != "nt":
        pytest.skip("Windows exclusive retained-handle regression")
    vault, root, _hardware = fixture_vault
    vault.initialize(PASSCODE)
    target = root / "src" / "main.py"
    target.write_bytes(b"approved changed source")
    report = vault.verify(PASSCODE)
    real_digest = vault._pinned_digest
    guarded = []

    def attempted_swap(pinned):
        digest = real_digest(pinned)
        if pinned.path == target:
            with pytest.raises(OSError):
                target.rename(target.with_name("swapped.py"))
            with pytest.raises(OSError):
                target.parent.rename(target.parent.with_name("swapped-src"))
            guarded.append(True)
        return digest

    monkeypatch.setattr(vault, "_pinned_digest", attempted_swap)
    result = vault.restore(PASSCODE, ["src/main.py"], expected_report_id=report["report_id"])
    assert result["status"] == "restored"
    assert guarded
    assert result["recovery_artifacts"]
    assert Path(result["recovery_artifacts"][0]).read_bytes() == b"approved changed source"
    assert vault.verify(PASSCODE)["status"] == "verified"


@pytest.mark.parametrize("suffix", ["00000003", "malformed"])
def test_immutable_audit_rejects_gaps_and_malformed_sidecars(fixture_vault, suffix):
    vault, _root, _hardware = fixture_vault
    vault.initialize(PASSCODE)
    vault.audit_path.with_name(vault.audit_path.name + "." + suffix).write_bytes(vault.audit_path.read_bytes())
    with pytest.raises(VaultAuthenticationError):
        vault.verify(PASSCODE)


def test_posix_fifo_substitution_cannot_block_read(fixture_vault):
    if os.name == "nt":
        pytest.skip("POSIX FIFO/O_NONBLOCK regression")
    import time
    vault, root, _hardware = fixture_vault
    pipe = root / "src" / "pipe.py"
    os.mkfifo(pipe)
    started = time.monotonic()
    with vault._operation(), pytest.raises(UGCAPError, match="ordinary files"):
        vault._read(pipe, 1024)
    assert time.monotonic() - started < 2
