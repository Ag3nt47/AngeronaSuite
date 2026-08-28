from __future__ import annotations

import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from angerona.core.update_authority import (
    UpdateAuthorityPolicy,
    file_sha256,
    verify_payload_manifest,
    verify_release_authorization,
)
from angerona.modules.release_transparency_guard import (
    ReleaseTransparencyGuardModule,
)
from tools.build_release_authorization import (
    build_payload_manifest,
    finalize_release_authorization,
    prepare_release_statement,
    sign_release_statement,
    version_sequence,
)


def _seed() -> str:
    key = Ed25519PrivateKey.generate()
    return base64.urlsafe_b64encode(key.private_bytes_raw()).decode().rstrip("=")


def _public(seed: str) -> str:
    raw = base64.urlsafe_b64decode(seed + "=" * (-len(seed) % 4))
    key = Ed25519PrivateKey.from_private_bytes(raw)
    return base64.urlsafe_b64encode(
        key.public_key().public_bytes_raw()
    ).decode().rstrip("=")


def _root_policy(path, seeds) -> tuple[object, str]:
    document = {
        "schema": "angerona.release-root-policy/v1",
        "product": "Angerona",
        "version": 1,
        "threshold": 2,
        "keys": [
            {"signer_id": "release-a", "public_key": _public(seeds["SIGNER_A"])},
            {"signer_id": "release-b", "public_key": _public(seeds["SIGNER_B"])},
        ],
    }
    raw = json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode()
    path.write_bytes(raw)
    return path, hashlib.sha256(raw).hexdigest()


def _build(tmp_path, *, seeds=None):
    package = tmp_path / "package"
    package.mkdir()
    artifact = package / "Angerona.exe"
    blackbox = package / "AngeronaBlackBox.exe"
    sbom = package / "Angerona-SBOM.json"
    manifest = package / "release-payload-manifest.json"
    catalog = package / "release-payload.cat"
    provenance = package / "release-build-provenance.json"
    statement_path = package / "release-statement.json"
    authorization = package / "release-authorization.json"
    trust = package / "release-trust.json"
    root_policy = package / "release-root-policy.json"
    artifact.write_bytes(b"frozen-application")
    blackbox.write_bytes(b"frozen-black-box")
    sbom.write_text('{"bomFormat":"CycloneDX"}', encoding="utf-8")
    build_payload_manifest(payload_root=package, output=manifest)
    catalog.write_bytes(b"authenticode-signed-catalog")
    statement = prepare_release_statement(
        artifact=artifact,
        sbom=sbom,
        payload_manifest=manifest,
        payload_catalog=catalog,
        provenance_output=provenance,
        statement_output=statement_path,
        version="2.3.4",
        platform="windows-x64",
        source_revision="a" * 40,
        invocation_id="github-run-123",
        issued_at=1_000_000,
    )
    seeds = seeds or {"SIGNER_A": _seed(), "SIGNER_B": _seed()}
    root_policy, root_policy_sha256 = _root_policy(root_policy, seeds)
    responses = []
    for identity, variable in (
        ("release-a", "SIGNER_A"),
        ("release-b", "SIGNER_B"),
    ):
        response_path = package / f"{identity}.json"
        sign_release_statement(
            statement_path=statement_path,
            signature_output=response_path,
            signer=(identity, variable),
            expected_public_key_variable=f"{variable}_PUBLIC",
            # Production jobs expose only their own environment secret.
            environment={
                variable: seeds.get(variable, ""),
                f"{variable}_PUBLIC": _public(seeds.get(variable, _seed())),
            },
        )
        responses.append(response_path)
    finalize_release_authorization(
        statement_path=statement_path,
        signature_paths=responses,
        authorization_output=authorization,
        trust_output=trust,
        root_policy_path=root_policy,
        root_policy_sha256=root_policy_sha256,
    )
    return {
        "statement": statement,
        "package": package,
        "artifact": artifact,
        "sbom": sbom,
        "manifest": manifest,
        "catalog": catalog,
        "provenance": provenance,
        "statement_path": statement_path,
        "authorization": authorization,
        "trust": trust,
        "root_policy": root_policy,
        "root_policy_sha256": root_policy_sha256,
        "responses": responses,
    }


def _trust(path):
    raw = json.loads(path.read_text())
    return {
        name: base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        for name, value in raw.items()
    }


def test_split_builder_emits_verifiable_complete_payload_authorization(tmp_path):
    built = _build(tmp_path)
    result = verify_release_authorization(
        built["authorization"].read_bytes(),
        _trust(built["trust"]),
        UpdateAuthorityPolicy(),
        now=1_000_100,
        expected_platform="windows-x64",
        expected_artifact_sha256=file_sha256(built["artifact"]),
        expected_sbom_sha256=file_sha256(built["sbom"]),
        expected_payload_manifest_sha256=file_sha256(built["manifest"]),
        expected_payload_catalog_sha256=file_sha256(built["catalog"]),
        expected_provenance_sha256=file_sha256(built["provenance"]),
        installed_version="2.3.4",
    )
    assert result.valid
    assert result.statement == built["statement"]
    assert set(json.loads(built["authorization"].read_text())) == {
        "statement", "signatures",
    }
    assert not verify_payload_manifest(
        built["manifest"].read_bytes(), built["package"],
    )

    combined = "".join(
        path.read_text()
        for path in (
            built["authorization"],
            built["trust"],
            built["provenance"],
            *built["responses"],
        )
    )
    assert "SIGNER_A" not in combined and "SIGNER_B" not in combined
    assert all("public_key" not in json.loads(path.read_text()) for path in built["responses"])

    module = ReleaseTransparencyGuardModule(
        authorization_path=built["authorization"],
        artifact_path=built["artifact"],
        sbom_path=built["sbom"],
        payload_manifest_path=built["manifest"],
        payload_catalog_path=built["catalog"],
        payload_root=built["package"],
        provenance_path=built["provenance"],
        trust_store=_trust(built["trust"]),
        floor_path=tmp_path / "release-floor.json",
        floor_key=b"f" * 32,
        platform="windows-x64",
        clock=lambda: 1_000_100,
    )
    assert module.observe_once().valid
    assert (tmp_path / "release-floor.json").is_file()
    assert module.observe_once().valid


def test_signer_jobs_fail_closed_on_missing_or_aliased_seeds(tmp_path):
    package = tmp_path / "first"
    package.mkdir()
    artifact = package / "Angerona.exe"
    sbom = package / "Angerona-SBOM.json"
    manifest = package / "release-payload-manifest.json"
    catalog = package / "release-payload.cat"
    provenance = package / "provenance.json"
    statement_path = package / "statement.json"
    artifact.write_bytes(b"app")
    sbom.write_bytes(b"{}")
    build_payload_manifest(payload_root=package, output=manifest)
    catalog.write_bytes(b"catalog")
    prepare_release_statement(
        artifact=artifact,
        sbom=sbom,
        payload_manifest=manifest,
        payload_catalog=catalog,
        provenance_output=provenance,
        statement_output=statement_path,
        version="2.3.4",
        platform="windows-x64",
        source_revision="a" * 40,
        invocation_id="github-run-123",
        issued_at=1_000_000,
    )
    with pytest.raises(ValueError, match="missing"):
        sign_release_statement(
            statement_path=statement_path,
            signature_output=package / "missing.json",
            signer=("release-a", "SIGNER_A"),
            expected_public_key_variable="SIGNER_A_PUBLIC",
            environment={},
        )

    seed = _seed()
    other_seed = _seed()
    responses = []
    for identity, variable, candidate in (
        ("release-a", "A", seed),
        ("release-b", "B", other_seed),
    ):
        response = package / f"{identity}.json"
        sign_release_statement(
            statement_path=statement_path,
            signature_output=response,
            signer=(identity, variable),
            expected_public_key_variable=f"{variable}_PUBLIC",
            environment={variable: candidate, f"{variable}_PUBLIC": _public(candidate)},
        )
        responses.append(response)
    invalid_policy = package / "invalid-policy.json"
    invalid_policy, invalid_policy_sha256 = _root_policy(
        invalid_policy, {"SIGNER_A": seed, "SIGNER_B": seed},
    )
    with pytest.raises(ValueError, match="independent"):
        finalize_release_authorization(
            statement_path=statement_path,
            signature_paths=responses,
            authorization_output=package / "authorization.json",
            trust_output=package / "trust.json",
            root_policy_path=invalid_policy,
            root_policy_sha256=invalid_policy_sha256,
        )


def test_finalizer_rejects_response_for_a_different_statement(tmp_path):
    built = _build(tmp_path)
    response = json.loads(built["responses"][0].read_text())
    response["statement_sha256"] = "f" * 64
    built["responses"][0].write_text(json.dumps(response), encoding="utf-8")
    with pytest.raises(ValueError, match="different statement"):
        finalize_release_authorization(
            statement_path=built["statement_path"],
            signature_paths=built["responses"],
            authorization_output=built["authorization"],
            trust_output=built["trust"],
            root_policy_path=built["root_policy"],
            root_policy_sha256=built["root_policy_sha256"],
        )


def test_signer_and_finalizer_reject_replacement_keys(tmp_path):
    built = _build(tmp_path)
    replacement = _seed()
    with pytest.raises(ValueError, match="enrolled public root"):
        sign_release_statement(
            statement_path=built["statement_path"],
            signature_output=built["package"] / "replacement.json",
            signer=("release-a", "REPLACEMENT"),
            expected_public_key_variable="ENROLLED_A",
            environment={
                "REPLACEMENT": replacement,
                "ENROLLED_A": json.loads(
                    built["root_policy"].read_text()
                )["keys"][0]["public_key"],
            },
        )

    response = json.loads(built["responses"][0].read_text())
    key = Ed25519PrivateKey.from_private_bytes(
        base64.urlsafe_b64decode(replacement + "=" * (-len(replacement) % 4))
    )
    response["signature"] = base64.urlsafe_b64encode(
        key.sign(built["statement"].canonical())
    ).decode().rstrip("=")
    built["responses"][0].write_text(
        json.dumps(response, sort_keys=True, separators=(",", ":")), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="failed verification"):
        finalize_release_authorization(
            statement_path=built["statement_path"],
            signature_paths=built["responses"],
            authorization_output=built["authorization"],
            trust_output=built["trust"],
            root_policy_path=built["root_policy"],
            root_policy_sha256=built["root_policy_sha256"],
        )


def test_finalizer_rejects_unprotected_or_changed_root_policy(tmp_path):
    built = _build(tmp_path)
    with pytest.raises(ValueError, match="protected SHA-256"):
        finalize_release_authorization(
            statement_path=built["statement_path"],
            signature_paths=built["responses"],
            authorization_output=built["authorization"],
            trust_output=built["trust"],
            root_policy_path=built["root_policy"],
            root_policy_sha256="0" * 64,
        )


def test_payload_manifest_detects_post_build_tampering(tmp_path):
    built = _build(tmp_path)
    built["artifact"].write_bytes(b"tampered")
    errors = verify_payload_manifest(
        built["manifest"].read_bytes(), built["package"],
    )
    assert errors and "payload" in errors[0]


def test_version_sequence_is_monotonic_and_bounded():
    assert version_sequence("1.11.0") > version_sequence("1.10.99")
    assert version_sequence("1.11.0.1") > version_sequence("1.11.0")
    with pytest.raises(ValueError):
        version_sequence("1.70000.0")
