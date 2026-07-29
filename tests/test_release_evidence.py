import hashlib
import json

import pytest

from angerona.core.release_evidence import (
    REQUIRED_RELEASE_CHECKS,
    QualityCheckEvidence,
    build_evidence_pack,
    verify_evidence_pack,
    write_evidence_pack,
)


def _checks(*, failing=""):
    return tuple(
        QualityCheckEvidence.from_output(
            check_id,
            command=("python", "-m", check_id),
            exit_code=1 if check_id == failing else 0,
            duration_seconds=1.25,
            output=b"password=super-secret\nC:\\Users\\SampleUser\\project",
        )
        for check_id in REQUIRED_RELEASE_CHECKS
    )


def test_release_evidence_is_complete_content_addressed_and_redacted(tmp_path):
    pack = build_evidence_pack(
        version="1.9.4", commit_sha="a" * 40, source_date_epoch=100,
        checks=_checks(),
    )
    assert pack.manifest.gate_status == "pass"
    assert verify_evidence_pack(pack)
    assert "super-secret" not in pack.canonical().decode()
    path = tmp_path / "evidence.json"
    write_evidence_pack(path, pack)
    raw = json.loads(path.read_text(encoding="utf-8"))
    assert raw["publisher_signature_state"] == "external-required"
    assert raw["manifest_sha256"] == hashlib.sha256(
        pack.manifest.canonical()
    ).hexdigest()


def test_release_evidence_fails_gate_and_rejects_missing_checks():
    pack = build_evidence_pack(
        version="1.9.4", commit_sha="a" * 40, source_date_epoch=100,
        checks=_checks(failing="unit-tests"),
    )
    assert pack.manifest.gate_status == "fail"
    with pytest.raises(ValueError, match="incomplete"):
        build_evidence_pack(
            version="1.9.4", commit_sha="a" * 40, source_date_epoch=100,
            checks=_checks()[:-1],
        )


def test_check_evidence_has_fixed_commands_and_bounded_status():
    with pytest.raises(ValueError, match="unregistered"):
        QualityCheckEvidence.from_output(
            "arbitrary-shell", command=("cmd", "/c", "whoami"),
            exit_code=0, duration_seconds=1, output=b"",
        )
    with pytest.raises(ValueError, match="passing"):
        QualityCheckEvidence(
            "bytecode", "pass", 1, 1, "a" * 64, "", "b" * 64,
        )
