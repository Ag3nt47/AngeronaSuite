from __future__ import annotations

import hashlib
import json

import pytest

from angerona.modules import ai_model_integrity as integrity
from angerona.modules.ai_triage import AITriageModule


@pytest.fixture
def approved_model(tmp_path, monkeypatch):
    models = tmp_path / "models"
    blob_bytes = b"inert approved test model"
    digest = hashlib.sha256(blob_bytes).hexdigest()
    blob = models / "blobs" / ("sha256-" + digest)
    blob.parent.mkdir(parents=True)
    blob.write_bytes(blob_bytes)
    manifest = models / "manifests" / "registry.ollama.ai" / "library" / "fixture" / "latest"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(json.dumps({
        "config": {"digest": "sha256:" + digest, "size": len(blob_bytes)}, "layers": [],
    }), encoding="utf-8")
    monkeypatch.setenv("ANGERONA_OLLAMA_MODELS", str(models))
    monkeypatch.delenv("ANGERONA_CHILL_ACTIVE", raising=False)
    guard = integrity.AIModelIntegrityGuardModule()
    guard._baseline_path = tmp_path / "baseline.json"
    guard._baseline_key_override = b"k" * 32
    guard.rebaseline(approved=True)
    monkeypatch.setattr(integrity, "AIModelIntegrityGuardModule", lambda: guard)
    integrity._ATTESTATION_CACHE.clear()
    yield guard, blob
    integrity._ATTESTATION_CACHE.clear()


def _triage(monkeypatch):
    module = AITriageModule()
    module._model = "fixture"
    monkeypatch.setattr(module, "_ping_ollama", lambda: True)
    monkeypatch.setattr(module, "emit", lambda *_args, **_kwargs: None)
    return module


def test_unapproved_tag_fails_before_any_inventory_scan(approved_model, monkeypatch):
    guard, _blob = approved_model
    monkeypatch.setattr(guard, "_verify_pass", lambda: pytest.fail("unapproved tag scanned blobs"))
    with pytest.raises(integrity.ModelIntegrityError, match="tag is not present"):
        integrity.require_fresh_model_attestation("unknown")
    assert integrity._ATTESTATION_CACHE == {}


def test_metadata_readiness_does_not_hash_bytes_or_issue_receipt(approved_model, monkeypatch):
    monkeypatch.setattr(integrity, "_hash_file", lambda *_a, **_k: pytest.fail("idle full scan"))
    monkeypatch.setattr(integrity, "_hash_verified_blob", lambda *_a, **_k: pytest.fail("idle blob scan"))
    assert integrity.check_model_readiness("fixture") is None
    assert integrity._ATTESTATION_CACHE == {}


def test_idle_health_does_not_refresh_expired_attestation(approved_model, monkeypatch):
    guard, _blob = approved_model
    expired = integrity.ModelAttestationReceipt(
        "fixture", "sha256:" + "0" * 64, guard._baseline_sha256, 1, 24, 0.0, 1.0,
    )
    integrity._ATTESTATION_CACHE["fixture"] = expired
    module = _triage(monkeypatch)
    monkeypatch.setattr(module, "_attest_model", lambda: pytest.fail("idle health refreshed attestation"))
    monkeypatch.setattr(guard, "_verify_pass", lambda: pytest.fail("idle health scanned inventory"))
    module._check_health()
    assert module.health == 100
    assert "fresh byte attestation required before inference" in module.health_note
    assert integrity._ATTESTATION_CACHE["fixture"] is expired
    assert module._attestation_receipt is None


def test_ready_metadata_never_erases_known_byte_attestation_failure(approved_model, monkeypatch):
    module = _triage(monkeypatch)
    module._attestation_error = "configured blob failed content digest verification"
    module._check_health()
    assert module.health == 20
    assert "blob failed content digest" in module.health_note


def test_inference_and_explicit_selftest_still_require_fresh_bytes(approved_model, monkeypatch):
    guard, blob = approved_model
    module = _triage(monkeypatch)
    module._check_health()
    assert module.health == 100
    blob.write_bytes(b"tampered test model")
    monkeypatch.setattr(
        "angerona.modules.ai_triage.safe_urlopen",
        lambda *_a, **_k: pytest.fail("inference contacted unverified model"),
    )
    assert module._ask("explain this inert event") is None
    ok, detail = module.self_test()
    assert not ok and "attestation" in detail
    assert integrity._ATTESTATION_CACHE == {}


def test_baseline_tampering_is_not_hidden_by_readiness_or_cached_receipt(approved_model, monkeypatch):
    guard, _blob = approved_model
    integrity.require_fresh_model_attestation("fixture")
    guard._baseline_path.write_text("{}", encoding="utf-8")
    with pytest.raises(integrity.ModelIntegrityError, match="invalid"):
        integrity.check_model_readiness("fixture")
    with pytest.raises(integrity.ModelIntegrityError, match="invalid"):
        integrity.require_fresh_model_attestation("fixture")
    module = _triage(monkeypatch)
    module._check_health()
    assert module.health == 20 and "invalid" in module.health_note


def test_receipt_security_lifetime_cannot_be_extended(approved_model):
    with pytest.raises(ValueError, match="security bound"):
        integrity.require_fresh_model_attestation("fixture", maximum_age_seconds=61)
