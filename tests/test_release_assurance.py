import base64
import json
import zipfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from angerona.core.release_assurance import (
    Preflight, StagedInstallPlan, build_manifest, generate_cyclonedx,
    slsa_provenance, verify_update_bundle, write_staged_plan,
)


def make_bundle(tmp_path, *, unsafe_name=None):
    root = tmp_path / "payload"
    root.mkdir()
    artifact = root / "app.bin"
    artifact.write_bytes(b"release")
    manifest = build_manifest(
        root, [artifact], product="Angerona", version="2.0.0", platform="windows-x64"
    )
    key = Ed25519PrivateKey.generate()
    sig = base64.urlsafe_b64encode(key.sign(manifest.canonical())).decode().rstrip("=")
    envelope = {
        "publisher_id": "release", "manifest": json.loads(manifest.canonical()),
        "signature": sig,
    }
    bundle = tmp_path / "update.zip"
    with zipfile.ZipFile(bundle, "w") as archive:
        archive.writestr("release-envelope.json", json.dumps(envelope))
        archive.writestr(unsafe_name or "app.bin", b"release")
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return bundle, public


def test_offline_signed_bundle_and_preflight(tmp_path):
    bundle, public = make_bundle(tmp_path)
    preflight = Preflight("windows-x64", "1.9.4", "1.0.0", "2.0.0", 1000, 100)
    result = verify_update_bundle(bundle, {"release": public}, preflight)
    assert result.valid
    assert result.manifest.version == "2.0.0"
    assert not verify_update_bundle(bundle, {}).valid


def test_path_traversal_and_payload_mismatch_fail_closed(tmp_path):
    bundle, public = make_bundle(tmp_path, unsafe_name="../app.bin")
    result = verify_update_bundle(bundle, {"release": public})
    assert not result.valid
    assert any("unsafe archive path" in error for error in result.errors)


def test_sbom_and_slsa_are_deterministic_and_digest_tied(tmp_path):
    sbom = generate_cyclonedx("Angerona", "2.0.0", [
        {"name": "zlib", "version": "1"}, {"name": "alpha", "version": "2"},
    ])
    assert [item["name"] for item in sbom["components"]] == ["alpha", "zlib"]
    root = tmp_path / "root"
    root.mkdir()
    item = root / "x"
    item.write_bytes(b"x")
    manifest = build_manifest(root, [item], product="Angerona",
                              version="2.0.0", platform="any")
    provenance = slsa_provenance(manifest, builder_id="local", invocation_id="i")
    assert provenance["subject"][0]["digest"]["sha256"] == manifest.artifacts[0].sha256


def test_atomic_plan_is_non_installing_and_has_rollback(tmp_path):
    plan = StagedInstallPlan(
        "p1", "a" * 64, "2.0.0", "stage",
        (("app.bin", "b" * 64),), (("app.bin", "c" * 64),),
    )
    path = tmp_path / "plan.json"
    write_staged_plan(path, plan)
    raw = json.loads(path.read_text())
    assert raw["install_authorized"] is False
    assert raw["rollback_files"]
