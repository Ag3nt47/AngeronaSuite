from __future__ import annotations

import pytest

from angerona.core.eventbus import EventBus, Severity
from angerona.modules.driver_provenance_guard import (
    SCHEMA,
    DriverCollection,
    DriverEvidenceRejected,
    DriverProvenanceEvidence,
    DriverProvenanceGuard,
    WindowsDriverEvidenceProvider,
    assess_driver_provenance,
    parse_driver_evidence,
)


def _evidence(**overrides):
    values = {
        "schema": SCHEMA,
        "driver_token": "a" * 64,
        "image_sha256": "b" * 64,
        "image_size": 4096,
        "load_state": "running",
        "signer_status": "trusted",
        "signer_thumbprint": "c" * 40,
        "catalog_status": "trusted",
        "blocklist_status": "not-listed",
        "blocklist_source": "local-hash-policy",
        "hvci_enabled": True,
        "secure_boot": True,
        "observed_at": 1_800_000_000.0,
    }
    values.update(overrides)
    return DriverProvenanceEvidence(**values)


def test_complete_driver_evidence_requires_every_joined_control():
    result = assess_driver_provenance(_evidence())
    assert result.state == "provenance-verified"
    assert result.evidence_complete
    assert result.response_authorized is False


def test_loaded_blocklisted_driver_is_critical_but_never_auto_disabled():
    evidence = _evidence(
        blocklist_status="listed",
        blocklist_source="microsoft-policy",
    )
    result = assess_driver_provenance(evidence)
    details = result.event_details(evidence.driver_token)
    assert result.state == "critical-loaded-blocklisted-driver"
    assert result.severity == "critical"
    assert details["driver_control_performed"] is False
    assert details["response_authorized"] is False


def test_untrusted_signature_catalog_or_host_boot_control_is_high_risk():
    result = assess_driver_provenance(
        _evidence(
            signer_status="untrusted",
            catalog_status="untrusted",
            hvci_enabled=False,
            secure_boot=False,
        )
    )
    assert result.state == "driver-provenance-risk"
    assert result.severity == "high"
    assert "loaded-driver-signature-untrusted" in result.risks
    assert "hvci-not-running" in result.risks


def test_missing_hash_blocklist_and_boot_evidence_is_unknown_not_safe():
    result = assess_driver_provenance(
        _evidence(
            image_sha256=None,
            image_size=None,
            signer_status="unknown",
            signer_thumbprint=None,
            catalog_status="unknown",
            blocklist_status="unknown",
            blocklist_source="unavailable",
            hvci_enabled=None,
            secure_boot=None,
        )
    )
    assert result.state == "incomplete-driver-evidence"
    assert not result.evidence_complete
    assert "blocklist_status" in result.unknown


def test_strict_driver_parser_rejects_extra_keys_bad_hash_and_bad_status():
    document = {
        "schema": SCHEMA,
        "driver_token": "a" * 64,
        "image_sha256": "b" * 64,
        "image_size": 4096,
        "load_state": "running",
        "signer_status": "trusted",
        "signer_thumbprint": "c" * 40,
        "catalog_status": "trusted",
        "blocklist_status": "not-listed",
        "blocklist_source": "local-hash-policy",
        "hvci_enabled": True,
        "secure_boot": True,
        "observed_at": 1_800_000_000.0,
    }
    assert parse_driver_evidence(document).image_sha256 == "b" * 64
    with pytest.raises(DriverEvidenceRejected):
        parse_driver_evidence({**document, "path": "C:\\secret.sys"})
    with pytest.raises(DriverEvidenceRejected):
        parse_driver_evidence({**document, "image_sha256": "not-a-hash"})
    with pytest.raises(DriverEvidenceRejected):
        parse_driver_evidence({**document, "blocklist_status": "safe"})


class Provider:
    def __init__(self, collection):
        self.collection = collection

    def collect(self):
        return self.collection


def test_module_emits_only_tokenized_observe_only_driver_evidence():
    evidence = _evidence(
        blocklist_status="listed", blocklist_source="microsoft-policy"
    )
    guard = DriverProvenanceGuard(Provider(DriverCollection((evidence,), True, "ok")))
    bus = EventBus()
    guard.bind(bus)
    result = guard.observe_once()
    assert result[0].severity == "critical"
    event = next(item for item in bus.recent(10) if item.severity == Severity.CRITICAL)
    assert event.severity == Severity.CRITICAL
    assert event.details["driver_token"] == "a" * 64
    assert event.details["driver_control_performed"] is False
    assert event.details["response_authorized"] is False
    assert "path" not in event.details


def test_incomplete_collection_is_high_visibility_and_never_green():
    guard = DriverProvenanceGuard(
        Provider(DriverCollection((), False, "inventory-unavailable"))
    )
    bus = EventBus()
    guard.bind(bus)
    assert guard.observe_once() == ()
    assert guard.health == 20
    event = bus.recent(1)[0]
    assert event.severity == Severity.HIGH
    assert event.details["response_authorized"] is False


def test_unchanged_driver_posture_does_not_reemit_when_only_receipt_time_changes():
    class ChangingReceiptProvider:
        def __init__(self):
            self.observed = 1_800_000_000.0

        def collect(self):
            self.observed += 10
            return DriverCollection((_evidence(observed_at=self.observed),), True, "ok")

    guard = DriverProvenanceGuard(ChangingReceiptProvider())
    bus = EventBus()
    guard.bind(bus)
    guard.observe_once()
    first_count = len(bus.recent(20))
    guard.observe_once()
    assert len(bus.recent(20)) == first_count


def test_driver_provenance_self_test_is_offline_and_passes():
    assert DriverProvenanceGuard().self_test()[0] is True


def test_more_than_256_running_drivers_is_explicitly_incomplete(monkeypatch):
    class Posture:
        @staticmethod
        def snapshot():
            return {"secure_boot": True, "hvci": True}

    rows = [
        {
            "name": f"driver-{index:03d}",
            "file_name": f"driver-{index:03d}.sys",
            "hash": "a" * 64,
            "size": 4096,
            "signature_status": "Valid",
            "signature_type": "Catalog",
            "signer_thumbprint": "b" * 40,
        }
        for index in range(256)
    ]
    # A 257th high-sorting service is absent from the bounded row set. The
    # separately reported total must prevent a clean coverage result.
    document = {
        "schema": "angerona.driver-inventory.v1",
        "total_count": 257,
        "truncated": True,
        "rows": rows,
    }
    provider = WindowsDriverEvidenceProvider(Posture())
    monkeypatch.setattr(provider, "_query", lambda: document)

    collection = provider.collect()

    assert len(collection.evidence) == 256
    assert collection.total_count == 257
    assert collection.truncated is True
    assert collection.complete is False
    assert collection.reason == "driver-inventory-truncated"
