from __future__ import annotations

import base64
import json
from dataclasses import asdict, replace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from angerona.core.update_authority import (
    AuthenticatedReleaseFloor,
    ReleaseAuthorizationStatement,
    UpdateAuthorityPolicy,
    verify_release_authorization,
)
from angerona.modules.release_transparency_guard import ReleaseTransparencyGuardModule


ROOT = __import__("pathlib").Path(__file__).resolve().parents[1]


NOW = 2_000_000.0
BUILDER = "https://github.com/Ag3nt47/AngeronaSuite/.github/workflows/release.yml"


def _statement(**overrides):
    values = {
        "schema": "angerona.release-authorization/v2",
        "product": "Angerona",
        "version": "2.0.0",
        "sequence": 20,
        "platform": "windows-x64",
        "artifact_sha256": "a" * 64,
        "sbom_sha256": "b" * 64,
        "payload_manifest_sha256": "e" * 64,
        "payload_catalog_sha256": "f" * 64,
        "provenance_sha256": "c" * 64,
        "source_revision": "d" * 40,
        "builder_id": BUILDER,
        "issued_at": NOW - 60,
        "expires_at": NOW + 3600,
    }
    values.update(overrides)
    return ReleaseAuthorizationStatement(**values)


def _keys():
    private = {name: Ed25519PrivateKey.generate() for name in ("release-a", "release-b", "release-c")}
    public = {
        name: key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
        for name, key in private.items()
    }
    return private, public


def _envelope(statement, private, signers=("release-a", "release-b")):
    return json.dumps({
        "statement": asdict(statement),
        "signatures": [
            {
                "signer_id": signer,
                "signature": base64.urlsafe_b64encode(
                    private[signer].sign(statement.canonical())
                ).decode().rstrip("="),
            }
            for signer in signers
        ],
    }).encode()


def _verify(raw, public, **overrides):
    values = {
        "now": NOW,
        "expected_platform": "windows-x64",
        "expected_artifact_sha256": "a" * 64,
        "expected_sbom_sha256": "b" * 64,
        "expected_payload_manifest_sha256": "e" * 64,
        "expected_payload_catalog_sha256": "f" * 64,
        "expected_provenance_sha256": "c" * 64,
        "installed_version": "1.10.3",
    }
    values.update(overrides)
    return verify_release_authorization(
        raw, public, UpdateAuthorityPolicy(), **values,
    )


def test_threshold_authorization_binds_artifact_builder_sbom_provenance_and_revision():
    private, public = _keys()
    statement = _statement()
    result = _verify(_envelope(statement, private), public)
    assert result.valid
    assert result.verified_signers == ("release-a", "release-b")
    assert result.statement.sbom_sha256 == "b" * 64
    assert result.statement.payload_manifest_sha256 == "e" * 64
    assert result.statement.payload_catalog_sha256 == "f" * 64
    assert result.statement.provenance_sha256 == "c" * 64
    assert result.statement.source_revision == "d" * 40


@pytest.mark.parametrize(
    "kwargs",
    (
        {"signature_threshold": True},
        {"maximum_validity_seconds": True},
        {"maximum_future_skew_seconds": False},
    ),
)
def test_update_authority_policy_rejects_boolean_numeric_fields(kwargs):
    with pytest.raises(ValueError):
        UpdateAuthorityPolicy(**kwargs)


@pytest.mark.parametrize(
    "change, expected",
    (
        ({"artifact_sha256": "f" * 64}, "artifact digest"),
        ({"sbom_sha256": "f" * 64}, "SBOM digest"),
        ({"payload_manifest_sha256": "a" * 64}, "payload manifest digest"),
        ({"payload_catalog_sha256": "a" * 64}, "payload catalog digest"),
        ({"provenance_sha256": "f" * 64}, "provenance digest"),
        ({"builder_id": "https://example.invalid/builder"}, "builder identity"),
        ({"expires_at": NOW - 1}, "expired"),
        ({"issued_at": NOW + 301, "expires_at": NOW + 600}, "not yet valid"),
        ({"version": "1.0.0"}, "downgrade"),
        ({"sequence": 9}, "sequence"),
    ),
)
def test_authorization_rejects_wrong_target_expiry_future_time_and_rollback(change, expected):
    private, public = _keys()
    statement = _statement(**change)
    result = _verify(
        _envelope(statement, private), public,
        highest_sequence=10, highest_version="1.10.3",
    )
    assert not result.valid
    assert any(expected in error for error in result.errors)


def test_threshold_and_metadata_tamper_fail_closed():
    private, public = _keys()
    statement = _statement()
    assert not _verify(_envelope(statement, private, ("release-a",)), public).valid
    raw = json.loads(_envelope(statement, private))
    raw["statement"]["sbom_sha256"] = "e" * 64
    result = _verify(json.dumps(raw).encode(), public)
    assert not result.valid and not result.verified_signers

    # Two signer labels backed by the same key are one authority, not a quorum.
    aliased = dict(public)
    aliased["release-b"] = public["release-a"]
    alias_private = dict(private)
    alias_private["release-b"] = private["release-a"]
    result = _verify(_envelope(statement, alias_private), aliased)
    assert not result.valid
    assert result.verified_signers == ("release-a",)


def test_authenticated_floor_rejects_rollback_equivocation_and_tamper(tmp_path):
    private, public = _keys()
    first = _verify(_envelope(_statement(), private), public)
    store = AuthenticatedReleaseFloor(tmp_path / "floor.json", b"k" * 32)
    floor = store.advance(first)
    assert store.load() == floor
    equivocation = _verify(
        _envelope(_statement(artifact_sha256="e" * 64), private), public,
        expected_artifact_sha256="e" * 64,
    )
    with pytest.raises(ValueError, match="equivocation"):
        store.advance(equivocation)
    raw = json.loads((tmp_path / "floor.json").read_text())
    raw["highest_version"] = "9.9.9"
    (tmp_path / "floor.json").write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="authentication"):
        store.load()


def test_release_guard_self_test_never_authorizes_malformed_metadata():
    okay, detail = ReleaseTransparencyGuardModule().self_test()
    assert okay and "fail closed" in detail


def test_operator_verifier_binds_hash_filename_repository_and_attestation():
    text = (ROOT / "Verify-Angerona-Release.ps1").read_text(encoding="utf-8")
    assert "Ag3nt47/AngeronaSuite" in text
    assert "Get-FileHash -LiteralPath $stagedArtifact -Algorithm SHA256" in text
    assert "attestation verify $stagedArtifact --repo $repository" in text
    assert "FileAttributes]::ReparsePoint" in text
    assert "GitHub CLI is required" in text
    assert "Get-AuthenticodeSignature -LiteralPath $stagedArtifact" in text
    assert "ANGERONA_PUBLISHER_CERT_SHA256" in text
    assert "Start-Process -FilePath $stagedArtifact" in text
