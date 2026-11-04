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
    module._host = "http://127.0.0.1:14184"
    monkeypatch.setattr("angerona.modules.ai_triage.attest_ollama_service", lambda *_args: None)
    module._attest_model = lambda **_kwargs: False
    monkeypatch.setattr(
        "angerona.modules.ai_triage.safe_urlopen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("unattested model request escaped")
        ),
    )

    assert module._ask("security event") is None


def _run_one_real_model_guard_pass(monkeypatch, module):
    from angerona.core.eventbus import BusAuthority, EventBus, Severity

    bus = EventBus()
    bus.arm(BusAuthority(b"private-test-event-key-material!!"))
    module.bind(bus)
    monkeypatch.setattr(module, "_wait_for_next_scan", lambda stop: stop.set())
    module.run()
    critical = [event for event in bus.recent(10) if event.severity == Severity.CRITICAL]
    assert len(critical) == 1
    event = critical[0]
    assert event.hmac_sig and bus.verify(event)
    return event


def _assert_inventory_gap_supplies_no_response_authority(monkeypatch, tmp_path, event):
    from angerona.modules.adversary_combat import AdversaryCombat

    monkeypatch.setenv("ANGERONA_ADVERSARY_COMBAT_ENABLED", "1")
    combat = AdversaryCombat(tmp_path / "private-response", rollback_anchor={})
    combat.status = "running"
    assert combat.policy().enabled
    combat._submit(event)
    assert combat._last_response_decision == "missing_contract"
    assert combat._response_counts == {"missing_contract": 1}
    assert combat._queue.empty() and combat._queue.unfinished_tasks == 0
    assert not combat.receipt_path.exists()
    assert not combat.quarantine_root.exists()


@pytest.mark.parametrize("gap", ["empty", "read-denied"])
def test_approved_inventory_collection_gap_stays_critical_but_not_active(
    monkeypatch, tmp_path, gap,
):
    from angerona.core.eventbus import Severity
    from angerona.core.threat import active_threat_events, event_disposition, is_active_threat

    module, models = _module(monkeypatch, tmp_path)
    blob, manifest, _digest = _model_tree(models)
    assert module.rebaseline(approved=True) == 2
    assert module._verify_pass() == (2, [])
    approved_bytes = module._baseline_path.read_bytes()
    if gap == "empty":
        blob.unlink()
        manifest.unlink()
        expected = "model inventory is empty"
    else:
        real_open = ai_model_integrity.os.open

        def deny_only_inert_blob(path, *args, **kwargs):
            if ai_model_integrity.Path(path) == blob:
                raise PermissionError("inert fixture read denied")
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr(ai_model_integrity.os, "open", deny_only_inert_blob)
        expected = "model inventory object could not be hashed"
    # The real authenticated baseline and disk readers still refuse inference.
    monkeypatch.setattr(ai_model_integrity, "AIModelIntegrityGuardModule", lambda: module)
    monkeypatch.setattr(ai_model_integrity, "_ATTESTATION_CACHE", {})
    with pytest.raises(ai_model_integrity.ModelInventoryUnavailable, match=expected):
        require_fresh_model_attestation("fixture:latest")
    assert ai_model_integrity._ATTESTATION_CACHE == {}
    event = _run_one_real_model_guard_pass(monkeypatch, module)
    assert event.severity == Severity.CRITICAL
    assert event.details == {
        "baseline_status": "approved", "error": expected,
        "disposition": "exposure", "active_attack": False, "response_authorized": False,
    }
    assert "inference is blocked" in event.message
    assert module.health == 0 and module.last_error == expected
    assert event_disposition(event) == "exposure"
    assert not is_active_threat(event)
    assert active_threat_events([event]) == []
    assert module._baseline_path.read_bytes() == approved_bytes
    _assert_inventory_gap_supplies_no_response_authority(monkeypatch, tmp_path, event)


@pytest.mark.parametrize(
    "change",
    ["content-address", "unapproved-file", "nofollow-loop", "not-a-directory",
     "is-directory", "too-many-links"],
)
def test_real_model_integrity_changes_keep_the_existing_active_critical_alert(
    monkeypatch, tmp_path, change,
):
    from angerona.core.eventbus import Severity
    from angerona.core.threat import event_disposition, is_active_threat

    module, models = _module(monkeypatch, tmp_path)
    blob, _manifest, _digest = _model_tree(models)
    assert module.rebaseline(approved=True) == 2
    assert module._verify_pass() == (2, [])
    approved_bytes = module._baseline_path.read_bytes()
    if change == "content-address":
        blob.write_bytes(b"genuinely changed private fixture bytes")
        expected = "content address"
    elif change == "unapproved-file":
        (models / "blobs" / "unapproved").write_bytes(b"unapproved private fixture")
        expected = "unapproved-new"
    else:
        import errno

        unsafe_errno = {
            "nofollow-loop": errno.ELOOP, "not-a-directory": errno.ENOTDIR,
            "is-directory": errno.EISDIR, "too-many-links": errno.EMLINK,
        }[change]
        real_open = ai_model_integrity.os.open

        def refuse_unsafe_inert_blob(path, *args, **kwargs):
            if ai_model_integrity.Path(path) == blob:
                raise OSError(unsafe_errno, "inert unsafe-object refusal")
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr(ai_model_integrity.os, "open", refuse_unsafe_inert_blob)
        expected = "model inventory object could not be hashed"
    monkeypatch.setattr(ai_model_integrity, "AIModelIntegrityGuardModule", lambda: module)
    monkeypatch.setattr(ai_model_integrity, "_ATTESTATION_CACHE", {})
    with pytest.raises(ModelIntegrityError, match=expected) as refused:
        require_fresh_model_attestation("fixture:latest")
    assert not isinstance(refused.value, ai_model_integrity.ModelInventoryUnavailable)
    if change not in {"content-address", "unapproved-file"}:
        assert refused.value.__cause__.errno == unsafe_errno
    assert ai_model_integrity._ATTESTATION_CACHE == {}
    event = _run_one_real_model_guard_pass(monkeypatch, module)
    assert event.severity == Severity.CRITICAL and module.health == 0
    assert event_disposition(event) == "active" and is_active_threat(event)
    assert "disposition" not in event.details
    assert "active_attack" not in event.details and "response_authorized" not in event.details
    assert "inference is blocked" in event.message
    assert module._baseline_path.read_bytes() == approved_bytes
