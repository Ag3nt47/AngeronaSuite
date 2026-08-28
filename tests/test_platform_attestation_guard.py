from __future__ import annotations

from angerona.core.eventbus import EventBus
from angerona.core.measured_boot import QUOTE_SCHEMA, SCHEMA
from angerona.modules.platform_attestation_guard import PlatformAttestationGuard


NONCE = "n" * 43


def _platform_document(nonce=NONCE, *, dma=True, dma_policy=True):
    return {
        "schema": SCHEMA,
        "observed_at": 1_800_000_000.0,
        "os_posture": {
            "secure_boot": True,
            "vbs_running": True,
            "hvci_running": True,
            "code_integrity_enabled": True,
            "test_signing": False,
            "boot_debug": False,
            "dma_protection_available": dma,
            "external_dma_policy_restrictive": dma_policy,
        },
        "tpm": {
            "present": True,
            "version": "2.0",
            "quote": {
                "schema": QUOTE_SCHEMA,
                "nonce": nonce,
                "pcr_digest": "1" * 64,
                "attestation_blob": "fixture_attestation",
                "signature": "fixture_signature",
                "key_id": "fixture-ak",
            },
        },
    }


class Provider:
    def __init__(self, document):
        self.document = document

    def collect(self, challenge_nonce):
        return self.document


class Verifier:
    def verify(self, quote, *, expected_nonce, evidence_digest):
        return quote.nonce == expected_nonce and len(evidence_digest) == 64


def test_platform_guard_emits_sanitized_observe_only_hardware_result():
    bus = EventBus()
    guard = PlatformAttestationGuard(
        Provider(_platform_document()),
        quote_verifier=Verifier(),
        nonce_factory=lambda: NONCE,
    )
    guard.bind(bus)
    result = guard.observe_once()
    assert result.hardware_attested
    event = bus.recent(1)[0]
    assert event.details["hardware_attested"] is True
    assert event.details["response_authorized"] is False
    assert "fixture_attestation" not in repr(event.details)
    assert "fixture_signature" not in repr(event.details)


def test_platform_guard_degrades_unknown_dma_instead_of_reporting_green():
    guard = PlatformAttestationGuard(
        Provider(_platform_document(dma=None, dma_policy=None)),
        nonce_factory=lambda: NONCE,
    )
    result = guard.observe_once()
    assert result.state == "incomplete-evidence"
    assert guard.health < 50


def test_new_nonce_and_observation_time_do_not_reemit_unchanged_platform_posture():
    class ChangingProvider:
        def __init__(self):
            self.observed = 1_800_000_000.0

        def collect(self, challenge_nonce):
            self.observed += 10
            document = _platform_document(challenge_nonce)
            document["observed_at"] = self.observed
            return document

    nonces = iter(("x" * 43, "y" * 43))
    guard = PlatformAttestationGuard(
        ChangingProvider(),
        quote_verifier=Verifier(),
        nonce_factory=lambda: next(nonces),
    )
    bus = EventBus()
    guard.bind(bus)
    guard.observe_once()
    guard.observe_once()
    assert len(bus.recent(10)) == 1


def test_platform_guard_self_test_is_offline_and_passes():
    assert PlatformAttestationGuard().self_test()[0] is True
