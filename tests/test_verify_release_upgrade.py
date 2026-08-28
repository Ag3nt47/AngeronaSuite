from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools.build_release_authorization import (
    build_payload_manifest,
    finalize_release_authorization,
    prepare_release_statement,
    sign_release_statement,
)
from tools.verify_release_upgrade import verify_portable_upgrade


def _key_material() -> tuple[str, str]:
    key = Ed25519PrivateKey.generate()
    seed = base64.urlsafe_b64encode(key.private_bytes_raw()).decode().rstrip("=")
    public = base64.urlsafe_b64encode(
        key.public_key().public_bytes_raw()
    ).decode().rstrip("=")
    return seed, public


def _release(root: Path, version: str, issued_at: float, roots=None) -> dict:
    root.mkdir()
    (root / "Angerona.exe").write_bytes(("app-" + version).encode())
    (root / "AngeronaBlackBox.exe").write_bytes(b"black-box")
    (root / "AngeronaReleaseVerifier.exe").write_bytes(b"verifier")
    (root / "Angerona-SBOM.json").write_bytes(b"{}")
    manifest = root / "release-payload-manifest.json"
    build_payload_manifest(payload_root=root, output=manifest)
    (root / "release-payload.cat").write_bytes(b"catalog")
    provenance = root / "release-build-provenance.json"
    statement = root / "release-statement.json"
    authorization = root / "release-authorization.json"
    trust = root / "release-trust.json"
    prepared = prepare_release_statement(
        artifact=root / "Angerona.exe",
        sbom=root / "Angerona-SBOM.json",
        payload_manifest=manifest,
        payload_catalog=root / "release-payload.cat",
        provenance_output=provenance,
        statement_output=statement,
        version=version,
        platform="windows-x64",
        source_revision="a" * 40,
        invocation_id="test-release",
        issued_at=issued_at,
    )
    roots = roots or [_key_material(), _key_material()]
    policy_document = {
        "schema": "angerona.release-root-policy/v1",
        "product": "Angerona",
        "version": 1,
        "threshold": 2,
        "keys": [
            {"signer_id": "release-a", "public_key": roots[0][1]},
            {"signer_id": "release-b", "public_key": roots[1][1]},
        ],
    }
    policy = root / "root-policy.json"
    policy.write_text(
        json.dumps(policy_document, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    signatures = []
    for index, signer_id in enumerate(("release-a", "release-b")):
        response = root / f"{signer_id}.json"
        sign_release_statement(
            statement_path=statement,
            signature_output=response,
            signer=(signer_id, "SEED"),
            expected_public_key_variable="PUBLIC",
            environment={"SEED": roots[index][0], "PUBLIC": roots[index][1]},
        )
        signatures.append(response)
    finalize_release_authorization(
        statement_path=statement,
        signature_paths=signatures,
        authorization_output=authorization,
        trust_output=trust,
        root_policy_path=policy,
        root_policy_sha256=hashlib.sha256(policy.read_bytes()).hexdigest(),
    )
    return {"root": root, "statement": prepared, "roots": roots}


def test_portable_upgrade_verifies_threshold_and_advances_floor_before_write(tmp_path):
    installed = _release(tmp_path / "installed", "1.10.0", 1_000_000)
    candidate = _release(
        tmp_path / "candidate", "1.11.0", 1_000_100, installed["roots"]
    )
    floor_path = candidate["root"] / "release-floor.json"
    floor = verify_portable_upgrade(
        candidate_root=candidate["root"],
        installed_root=installed["root"],
        floor_output=floor_path,
        now=1_000_200,
    )
    assert floor.highest_version == "1.11.0"
    assert floor.highest_sequence == candidate["statement"].sequence
    assert json.loads(floor_path.read_text())["statement_sha256"] == (
        candidate["statement"].sha256
    )


def test_portable_upgrade_rejects_authentic_downgrade_without_floor_output(tmp_path):
    installed = _release(tmp_path / "installed", "1.11.0", 1_000_000)
    candidate = _release(
        tmp_path / "candidate", "1.10.9", 1_000_100, installed["roots"]
    )
    floor_path = candidate["root"] / "release-floor.json"
    with pytest.raises(ValueError, match="downgrade|rollback floor"):
        verify_portable_upgrade(
            candidate_root=candidate["root"],
            installed_root=installed["root"],
            floor_output=floor_path,
            now=1_000_200,
        )
    assert not floor_path.exists()


def test_portable_upgrade_rejects_signature_or_root_replacement(tmp_path):
    installed = _release(tmp_path / "installed", "1.10.0", 1_000_000)
    candidate = _release(tmp_path / "candidate", "1.11.0", 1_000_100)
    with pytest.raises(ValueError, match="trust-root rotation"):
        verify_portable_upgrade(
            candidate_root=candidate["root"],
            installed_root=installed["root"],
            floor_output=candidate["root"] / "release-floor.json",
            now=1_000_200,
        )
