from __future__ import annotations

import json
import multiprocessing
import time
from base64 import b64encode
from datetime import datetime, timezone

from angerona.core.detection_packages import seal_package
from angerona.core.detection_registry import DetectionPackageRegistry

NOW = datetime(2030, 1, 1, tzinfo=timezone.utc)


def _document(version="1.0.0", marker="Get-Process"):
    return {
        "schema_version": 1, "id": "org.angerona.registry-demo", "version": version,
        "owner": "Angerona Community", "description": "Registry lifecycle fixture.",
        "telemetry": ["process.creation"], "attack": ["T1059.001"],
        "severity": "low", "confidence": 75,
        "logic": {"type": "sigma-subset", "detection": {
            "selection": {"cmdline|contains": marker}, "condition": "selection"}},
        "fixtures": [
            {"name": "hit", "event": {"cmdline": f"powershell {marker}"}, "expected_match": True},
            {"name": "miss", "event": {"cmdline": "notepad"}, "expected_match": False},
        ],
        "performance": {"max_eval_ms": 50, "max_events_per_second": 1000},
        "rollback": {"previous_digest": None, "instructions": "Reactivate the retained predecessor."},
        "expires_at": "2035-01-01T00:00:00Z",
    }


def _write(path, document):
    sealed = seal_package(document)
    path.write_text(json.dumps(sealed), encoding="utf-8")
    return sealed["digest"]


def _hold_registry_lock(root, ready):
    registry = DetectionPackageRegistry(root, lock_timeout=2)
    with registry._locked():
        ready.set()
        time.sleep(0.5)


def test_atomic_activation_and_rollback(tmp_path):
    registry = DetectionPackageRegistry(
        tmp_path / "registry", require_signed=False,
    )
    first_path, second_path = tmp_path / "one.json", tmp_path / "two.json"
    first = _write(first_path, _document())
    second = _write(second_path, _document("1.1.0", "Get-Service"))
    assert registry.stage(first_path, now=NOW).state == "staged"
    assert registry.activate("org.angerona.registry-demo", first, now=NOW).ok
    assert registry.stage(second_path, now=NOW).ok
    report = registry.activate("org.angerona.registry-demo", second, now=NOW)
    assert report.previous_digest == first
    assert registry.active("org.angerona.registry-demo", now=NOW).document["version"] == "1.1.0"
    assert registry.rollback("org.angerona.registry-demo", now=NOW).ok
    assert registry.active("org.angerona.registry-demo", now=NOW).document["version"] == "1.0.0"
    states = {d: r["state"] for d, r in registry.inventory()["org.angerona.registry-demo"].items()}
    assert states[first] == "active"
    assert states[second] == "retired"


def test_invalid_digest_is_quarantined_with_structured_report(tmp_path):
    registry = DetectionPackageRegistry(tmp_path / "registry")
    path = tmp_path / "bad.json"
    sealed = seal_package(_document())
    sealed["confidence"] = 99
    path.write_text(json.dumps(sealed), encoding="utf-8")
    report = registry.stage(path, now=NOW)
    assert not report.ok
    assert report.state == "quarantined"
    assert "digest" in report.errors[0]
    assert list((tmp_path / "registry" / "quarantine").glob("*.json"))


def test_expiry_gate_rechecked_during_activation(tmp_path):
    registry = DetectionPackageRegistry(
        tmp_path / "registry", require_signed=False,
    )
    path = tmp_path / "short.json"
    doc = _document()
    doc["expires_at"] = "2030-06-01T00:00:00Z"
    digest = _write(path, doc)
    assert registry.stage(path, now=NOW).ok
    later = datetime(2031, 1, 1, tzinfo=timezone.utc)
    report = registry.activate("org.angerona.registry-demo", digest, now=later)
    assert not report.ok and report.state == "quarantined"
    assert "expired" in report.errors[0]


def test_cross_process_lock_times_out_fail_closed(tmp_path):
    root = tmp_path / "registry"
    registry = DetectionPackageRegistry(root, lock_timeout=0.1)
    ready = multiprocessing.Event()
    process = multiprocessing.Process(target=_hold_registry_lock, args=(root, ready))
    process.start()
    try:
        assert ready.wait(3)
        path = tmp_path / "candidate.json"
        _write(path, _document())
        report = registry.stage(path, now=NOW)
        assert not report.ok
        assert "lock acquisition timed out" in report.errors[0]
    finally:
        process.join(3)
        if process.is_alive():
            process.terminate()


def test_signed_only_policy_requires_trusted_ed25519_signature(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    trust = tmp_path / "trusted-keys.json"
    trust.write_text(json.dumps({
        "keys": {"angerona-release": {"public_key": b64encode(public).decode("ascii")}}
    }), encoding="utf-8")
    package_path = tmp_path / "signed.json"
    digest = _write(package_path, _document())
    signature_path = tmp_path / "signed.sig.json"
    signature_path.write_text(json.dumps({
        "key_id": "angerona-release",
        "signature": b64encode(private.sign(package_path.read_bytes())).decode("ascii"),
    }), encoding="utf-8")

    registry = DetectionPackageRegistry(
        tmp_path / "registry", trusted_keys=trust, require_signed=True
    )
    report = registry.stage(package_path, signature=signature_path, now=NOW)
    assert report.ok
    assert registry.inventory()["org.angerona.registry-demo"][digest]["trusted"] is True
    assert registry.activate("org.angerona.registry-demo", digest, now=NOW).ok
    assert registry.active("org.angerona.registry-demo", now=NOW) is not None

    # Trust revocation is enforced on the normal read path, not only the
    # activation transition.
    trust.write_text('{"keys":{}}', encoding="utf-8")
    assert registry.active("org.angerona.registry-demo", now=NOW) is None
    assert (
        registry.inventory()["org.angerona.registry-demo"][digest]["state"]
        == "quarantined"
    )


def test_unsigned_package_stages_untrusted_but_signed_only_activation_fails(tmp_path):
    trust = tmp_path / "trusted-keys.json"
    trust.write_text('{"keys":{}}', encoding="utf-8")
    package_path = tmp_path / "unsigned.json"
    digest = _write(package_path, _document())
    registry = DetectionPackageRegistry(
        tmp_path / "registry", trusted_keys=trust, require_signed=True
    )
    assert registry.stage(package_path, now=NOW).ok
    record = registry.inventory()["org.angerona.registry-demo"][digest]
    assert record["state"] == "staged" and record["trusted"] is False
    report = registry.activate("org.angerona.registry-demo", digest, now=NOW)
    assert not report.ok
    assert "trusted publisher signature" in report.errors[0]


def test_unsigned_activation_requires_explicit_recorded_development_override(tmp_path):
    package_path = tmp_path / "unsigned.json"
    digest = _write(package_path, _document())
    default_registry = DetectionPackageRegistry(tmp_path / "default")
    assert default_registry.stage(package_path, now=NOW).ok
    assert not default_registry.activate(
        "org.angerona.registry-demo", digest, now=NOW,
    ).ok

    dev_registry = DetectionPackageRegistry(
        tmp_path / "development", require_signed=False,
    )
    assert dev_registry.stage(package_path, now=NOW).ok
    assert dev_registry.activate(
        "org.angerona.registry-demo", digest, now=NOW,
    ).ok
    manifest = json.loads(dev_registry.manifest_path.read_text(encoding="utf-8"))
    assert manifest["activation_policy"] == "development_unsigned_override"
