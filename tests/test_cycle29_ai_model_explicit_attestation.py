from __future__ import annotations

import hashlib
import json

import pytest

from angerona.modules import ai_model_integrity
from angerona.modules.ai_model_integrity import (
    AIModelIntegrityGuardModule,
    ModelIntegrityError,
    _hash_file,
    require_fresh_model_attestation,
)
from angerona.modules.ai_triage import AITriageModule


def _model_tree(root, *, name: str = "fixture", content: bytes = b"model-bytes"):
    blob_hex = hashlib.sha256(content).hexdigest()
    blob = root / "blobs" / f"sha256-{blob_hex}"
    blob.parent.mkdir(parents=True, exist_ok=True)
    blob.write_bytes(content)
    manifest = {
        "config": {
            "digest": f"sha256:{blob_hex}",
            "size": len(content),
        },
        "layers": [],
    }
    raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    manifest_path = (
        root
        / "manifests"
        / "registry.ollama.ai"
        / "library"
        / name
        / "latest"
    )
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_bytes(raw)
    return blob, manifest_path, "sha256:" + hashlib.sha256(raw).hexdigest()


def _module(monkeypatch, tmp_path):
    models = tmp_path / "models"
    models.mkdir()
    monkeypatch.setenv("ANGERONA_OLLAMA_MODELS", str(models))
    module = AIModelIntegrityGuardModule()
    module._baseline_path = tmp_path / "model-baseline.json"
    module._baseline_key_override = b"k" * 32
    return module, models


def test_missing_baseline_never_trusts_or_persists_observation(
    monkeypatch, tmp_path,
) -> None:
    module, models = _module(monkeypatch, tmp_path)
    _model_tree(models)

    with pytest.raises(ModelIntegrityError, match="approval-required"):
        module._verify_pass()

    assert module._baseline == {}
    assert not module._baseline_path.exists()
    assert module._baseline_status == "approval-required"


def test_explicit_authenticated_inventory_detects_missing_new_and_changed(
    monkeypatch, tmp_path,
) -> None:
    module, models = _module(monkeypatch, tmp_path)
    blob, _manifest, _digest = _model_tree(models)

    with pytest.raises(PermissionError):
        module.rebaseline()
    assert module.rebaseline(approved=True) == 2
    assert module._load_baseline() is True
    assert module._verify_pass() == (2, [])

    original = blob.read_bytes()
    blob.unlink()
    with pytest.raises(ModelIntegrityError, match="manifests and content-addressed"):
        module._verify_pass()

    blob.write_bytes(original)
    extra = models / "blobs" / "unapproved"
    extra.write_bytes(b"new-model")
    checked, mismatches = module._verify_pass()
    assert checked == 3
    assert any("(unapproved-new)" in item for item in mismatches)

    extra.unlink()
    blob.write_bytes(b"different-same-name")
    with pytest.raises(ModelIntegrityError, match="content address"):
        module._verify_pass()


def test_tampered_baseline_is_not_reenrolled_or_overwritten(monkeypatch, tmp_path) -> None:
    module, models = _module(monkeypatch, tmp_path)
    _model_tree(models)
    module.rebaseline(approved=True)
    document = json.loads(module._baseline_path.read_text(encoding="utf-8"))
    document["files"][next(iter(document["files"]))] = "0" * 64
    module._baseline_path.write_text(json.dumps(document), encoding="utf-8")
    attacked_bytes = module._baseline_path.read_bytes()

    assert module._load_baseline() is False
    assert module._baseline_status == "invalid"
    with pytest.raises(ModelIntegrityError, match="refusing to overwrite"):
        module.rebaseline(approved=True)
    assert module._baseline_path.read_bytes() == attacked_bytes


def test_hasher_raises_typed_failure_instead_of_persistable_sentinel(tmp_path) -> None:
    missing = tmp_path / "missing-model"
    with pytest.raises(ModelIntegrityError):
        _hash_file(missing)


def test_exact_model_receipt_binds_approved_tag_and_blocks_changed_blob(
    monkeypatch, tmp_path,
) -> None:
    data = tmp_path / "data"
    data.mkdir()
    (data / "bus.key").write_text((b"z" * 32).hex(), encoding="ascii")
    models = tmp_path / "models"
    models.mkdir()
    blob, _manifest, expected = _model_tree(models)
    monkeypatch.setattr(ai_model_integrity, "_repo_root", lambda: data)
    monkeypatch.setenv("ANGERONA_OLLAMA_MODELS", str(models))
    ai_model_integrity._ATTESTATION_CACHE.clear()

    guard = AIModelIntegrityGuardModule()
    guard.rebaseline(approved=True)
    receipt = require_fresh_model_attestation("fixture:latest")
    assert receipt.manifest_digest == expected
    assert receipt.model_ref == "fixture:latest"

    blob.write_bytes(b"tampered")
    ai_model_integrity._ATTESTATION_CACHE.clear()
    with pytest.raises(ModelIntegrityError):
        require_fresh_model_attestation("fixture:latest")


def test_triage_never_contacts_model_when_attestation_fails(monkeypatch) -> None:
    module = AITriageModule()
    module._attest_model = lambda: False
    monkeypatch.setattr(
        "angerona.modules.ai_triage.safe_urlopen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("unattested model request escaped")
        ),
    )

    assert module._ask("security event") is None
