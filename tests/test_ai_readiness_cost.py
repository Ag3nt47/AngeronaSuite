from __future__ import annotations

import hashlib
import io
import json
from dataclasses import replace

import pytest

from angerona.modules import ai_model_integrity as integrity
from angerona.modules.ai_triage import AITRIAGE_ATTESTATION_DEFERRED, AITriageModule


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
    monkeypatch.delenv("ANGERONA_CHILL_AI_BLOCKED", raising=False)
    guard = integrity.AIModelIntegrityGuardModule()
    guard._baseline_path = tmp_path / "baseline.json"
    guard._baseline_key_override = b"k" * 32
    guard.rebaseline(approved=True)
    monkeypatch.setattr(integrity, "AIModelIntegrityGuardModule", lambda **_kwargs: guard)
    integrity._ATTESTATION_CACHE.clear()
    yield guard, blob
    integrity._ATTESTATION_CACHE.clear()


def _triage(monkeypatch):
    module = AITriageModule()
    module._host = "http://127.0.0.1:14184"
    module._model = "fixture"
    monkeypatch.setattr("angerona.modules.ai_triage.attest_ollama_service", lambda *_args: None)
    monkeypatch.setattr(module, "_ping_ollama", lambda: True)
    monkeypatch.setattr(module, "emit", lambda *_args, **_kwargs: None)
    return module


def _record_inventory_requests(monkeypatch, guard):
    class Response(io.BytesIO):
        headers = {}

    requests = []
    digest = guard._baseline["manifests/registry.ollama.ai/library/fixture/latest"]

    def read_inventory(request, **kwargs):
        requests.append((request.get_method(), request.full_url))
        if requests[-1] != ("GET", "http://127.0.0.1:14184/api/tags"):
            pytest.fail("an inference or unexpected request reached Ollama transport")
        assert kwargs["timeout"] == 3.0
        return Response(json.dumps({"models": [{"name": "fixture:latest", "digest": digest}]}).encode())

    monkeypatch.setattr("angerona.modules.ai_triage.safe_urlopen", read_inventory)
    return requests


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


def test_tampered_model_blocks_inference_but_allows_selftest_inventory(approved_model, monkeypatch):
    guard, blob = approved_model
    module = _triage(monkeypatch)
    module._check_health()
    assert module.health == 100
    blob.write_bytes(b"tampered test model")
    requests = _record_inventory_requests(monkeypatch, guard)
    assert module._ask("explain this inert event") is None
    assert requests == []
    assert module._attestation_receipt is None
    monkeypatch.setattr(guard, "_verify_pass", lambda **_kwargs: pytest.fail("self-test rehashed model bytes"))
    ok, detail = module.self_test()
    assert not ok and "last disk byte attestation failed" in detail
    assert requests == [("GET", "http://127.0.0.1:14184/api/tags")]
    assert integrity._ATTESTATION_CACHE == {}


@pytest.mark.parametrize("receipt_state", ["missing", "stale", "fresh"])
def test_explicit_selftest_only_observes_existing_receipts(approved_model, monkeypatch, receipt_state):
    guard, _blob = approved_model
    module = _triage(monkeypatch)
    if receipt_state != "missing":
        receipt = integrity.require_fresh_model_attestation("fixture")
        if receipt_state == "stale":
            integrity._ATTESTATION_CACHE["fixture"] = replace(
                receipt,
                issued_monotonic=receipt.issued_monotonic - 120.0,
                expires_monotonic=receipt.expires_monotonic - 120.0,
            )
    before = integrity._ATTESTATION_CACHE.copy()
    requests = _record_inventory_requests(monkeypatch, guard)
    monkeypatch.setattr(guard, "_verify_pass", lambda **_kwargs: pytest.fail("self-test rehashed model bytes"))
    monkeypatch.setattr(module, "_ensure_ollama", lambda: pytest.fail("self-test started Ollama"))
    ok, detail = module.self_test()
    assert ok is (receipt_state == "fresh")
    if receipt_state == "fresh":
        assert "current disk attestation" in detail
    else:
        assert detail == AITRIAGE_ATTESTATION_DEFERRED
    assert requests == [("GET", "http://127.0.0.1:14184/api/tags")]
    assert integrity._ATTESTATION_CACHE == before
    assert module._attestation_receipt is None


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
