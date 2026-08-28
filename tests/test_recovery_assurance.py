from __future__ import annotations

import base64
import json
from dataclasses import asdict, replace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from angerona.core.recovery_assurance import (
    RecoveryAssurancePolicy,
    RecoveryCopyStatement,
    assess_recovery_assurance,
    load_recovery_evidence_directory,
    verify_recovery_envelope,
)
from angerona.modules.immutable_recovery_guard import ImmutableRecoveryGuardModule
import angerona.core.recovery_assurance as recovery_assurance


NOW = 2_000_000.0
REVISION = "a" * 40


def _statement(index: int, **overrides) -> RecoveryCopyStatement:
    values = {
        "schema": "angerona.recovery-copy/v1",
        "copy_id": f"copy-{index:03d}",
        "failure_domain": f"domain-{index:03d}",
        "media_class": "external-drive",
        "source_revision": REVISION,
        "archive_sha256": "b" * 64,
        "manifest_sha256": "c" * 64,
        "created_at": NOW - 60,
        "verified_at": NOW - 30,
        "restore_tested_at": NOW - 20,
        "size_bytes": 1000,
        "online": True,
        "writable": True,
        "immutable": False,
        "separate_identity": index > 1,
        "encrypted": True,
        "offsite": index == 2,
        "air_gapped": False,
    }
    values.update(overrides)
    return RecoveryCopyStatement(**values)


def _envelope(statement: RecoveryCopyStatement, key, signer="vault-authority") -> bytes:
    signature = base64.urlsafe_b64encode(
        key.sign(statement.canonical())
    ).decode().rstrip("=")
    return json.dumps({
        "signer_id": signer,
        "statement": asdict(statement),
        "signature": signature,
    }).encode()


@pytest.fixture
def signer():
    private = {
        name: Ed25519PrivateKey.generate()
        for name in ("vault-authority", "offline-authority")
    }
    public = {
        name: key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
        for name, key in private.items()
    }
    return private, public


def test_signed_three_copy_policy_requires_real_offline_and_immutable_copy(signer):
    keys, trust = signer
    statements = (
        _statement(1),
        _statement(2),
        _statement(
            3, media_class="offline-media", online=False, writable=False,
            immutable=True, air_gapped=True,
        ),
    )
    verified = tuple(
        verify_recovery_envelope(
            _envelope(
                item,
                keys["vault-authority" if index < 2 else "offline-authority"],
                "vault-authority" if index < 2 else "offline-authority",
            ),
            trust,
        )
        for index, item in enumerate(statements)
    )
    result = assess_recovery_assurance(
        verified, RecoveryAssurancePolicy(), now=NOW, source_revision=REVISION,
    )
    assert result.healthy
    assert result.offline_copies == result.immutable_copies == 1
    assert result.failure_domains == 3
    assert result.signing_authorities == 2


def test_online_f_mirror_never_satisfies_offline_or_immutable_policy(signer):
    keys, trust = signer
    copies = tuple(
        verify_recovery_envelope(
            _envelope(_statement(index), keys["vault-authority"]), trust,
        )
        for index in range(1, 4)
    )
    result = assess_recovery_assurance(
        copies, RecoveryAssurancePolicy(), now=NOW, source_revision=REVISION,
    )
    assert not result.healthy
    assert result.offline_copies == result.immutable_copies == 0
    assert any("offline" in finding for finding in result.findings)


def test_recovery_envelope_rejects_unknown_signer_tamper_and_duplicate_keys(signer):
    keys, trust = signer
    key = keys["vault-authority"]
    statement = _statement(1)
    assert verify_recovery_envelope(_envelope(statement, key), trust)
    with pytest.raises(ValueError, match="not trusted"):
        verify_recovery_envelope(_envelope(statement, key), {})
    raw = json.loads(_envelope(statement, key))
    raw["statement"]["archive_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="signature"):
        verify_recovery_envelope(json.dumps(raw).encode(), trust)
    duplicate = _envelope(statement, key).decode().replace(
        '"signer_id": "vault-authority",',
        '"signer_id": "vault-authority", "signer_id": "vault-authority",',
    )
    with pytest.raises(ValueError, match="duplicate"):
        verify_recovery_envelope(duplicate.encode(), trust)


def test_loader_is_bounded_and_guard_self_test_is_fail_closed(tmp_path, signer):
    keys, trust = signer
    key = keys["vault-authority"]
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "one.json").write_bytes(_envelope(_statement(1), key))
    copies, errors = load_recovery_evidence_directory(evidence, trust)
    assert len(copies) == 1 and not errors
    okay, detail = ImmutableRecoveryGuardModule().self_test()
    assert okay and "fail-closed" in detail


def test_loader_stops_at_directory_entry_budget(tmp_path, signer, monkeypatch):
    _keys, trust = signer
    evidence = tmp_path / "evidence"
    evidence.mkdir()

    class Entry:
        def __init__(self, index):
            self.name = f"noise-{index}.txt"

    class Directory:
        def __init__(self):
            self.yielded = 0

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def __iter__(self):
            for index in range(recovery_assurance.MAX_EVIDENCE_DIRECTORY_ENTRIES + 100):
                self.yielded += 1
                yield Entry(index)

    directory = Directory()
    monkeypatch.setattr(recovery_assurance.os, "scandir", lambda _root: directory)
    copies, errors = load_recovery_evidence_directory(evidence, trust)

    assert not copies
    assert errors == ("recovery evidence directory entry count exceeds its bound",)
    assert directory.yielded == recovery_assurance.MAX_EVIDENCE_DIRECTORY_ENTRIES + 1


def test_loader_reads_evidence_through_the_bounded_descriptor_path(
    tmp_path, signer, monkeypatch,
):
    keys, trust = signer
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "valid.json").write_bytes(
        _envelope(_statement(1), keys["vault-authority"])
    )

    monkeypatch.setattr(
        recovery_assurance.Path,
        "read_bytes",
        lambda _self: (_ for _ in ()).throw(AssertionError("unbounded read")),
    )
    copies, errors = load_recovery_evidence_directory(evidence, trust)

    assert len(copies) == 1
    assert not errors


def test_recovery_statement_rejects_impossible_media_claims():
    with pytest.raises(ValueError, match="air-gapped"):
        _statement(1, air_gapped=True, online=True)
    with pytest.raises(ValueError, match="immutable"):
        _statement(1, immutable=True, writable=True)


def test_future_dated_or_mixed_archive_cohorts_never_report_healthy(signer):
    keys, trust = signer
    authority_names = (
        "vault-authority",
        "vault-authority",
        "offline-authority",
    )

    def verified(statements):
        return tuple(
            verify_recovery_envelope(
                _envelope(item, keys[authority_names[index]], authority_names[index]),
                trust,
            )
            for index, item in enumerate(statements)
        )

    posture = {
        "media_class": "offline-media",
        "online": False,
        "writable": False,
        "immutable": True,
        "air_gapped": True,
        "offsite": True,
        "separate_identity": True,
    }
    future = verified(tuple(
        _statement(
            index,
            created_at=NOW + 10_000,
            verified_at=NOW + 10_010,
            restore_tested_at=NOW + 10_020,
            **posture,
        )
        for index in range(1, 4)
    ))
    future_result = assess_recovery_assurance(
        future, RecoveryAssurancePolicy(), now=NOW, source_revision=REVISION,
    )
    assert not future_result.healthy
    assert future_result.verified_copies == 0
    assert any("future" in finding for finding in future_result.findings)

    mixed = verified(tuple(
        _statement(
            index,
            archive_sha256=f"{index:064x}",
            manifest_sha256=f"{index + 100:064x}",
            **posture,
        )
        for index in range(1, 4)
    ))
    mixed_result = assess_recovery_assurance(
        mixed, RecoveryAssurancePolicy(), now=NOW, source_revision=REVISION,
    )
    assert not mixed_result.healthy
    assert mixed_result.verified_copies == 1
    assert any("minimum current" in finding for finding in mixed_result.findings)
