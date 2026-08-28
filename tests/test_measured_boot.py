from __future__ import annotations

import json

import pytest

from angerona.core.measured_boot import (
    QUOTE_SCHEMA,
    SCHEMA,
    MeasuredBootEvidenceRejected,
    assess_measured_boot,
    parse_measured_boot_evidence,
)


NONCE = "n" * 43


def _document(*, quote=None, **posture_overrides):
    posture = {
        "secure_boot": True,
        "vbs_running": True,
        "hvci_running": True,
        "code_integrity_enabled": True,
        "test_signing": False,
        "boot_debug": False,
        "dma_protection_available": True,
        "external_dma_policy_restrictive": True,
    }
    posture.update(posture_overrides)
    return {
        "schema": SCHEMA,
        "observed_at": 1_800_000_000.0,
        "os_posture": posture,
        "tpm": {"present": True, "version": "2.0", "quote": quote},
    }


def _quote(nonce=NONCE):
    return {
        "schema": QUOTE_SCHEMA,
        "nonce": nonce,
        "pcr_digest": "1" * 64,
        "attestation_blob": "opaque_attestation",
        "signature": "opaque_signature",
        "key_id": "enrolled-ak-1",
    }


class AcceptingVerifier:
    def verify(self, quote, *, expected_nonce, evidence_digest):
        return (
            quote.nonce == expected_nonce
            and quote.key_id == "enrolled-ak-1"
            and len(evidence_digest) == 64
        )


def test_os_posture_without_quote_is_never_hardware_attestation():
    evidence = parse_measured_boot_evidence(_document())
    result = assess_measured_boot(evidence, expected_nonce=NONCE)
    assert result.state == "os-posture-only"
    assert result.posture_consistent
    assert not result.hardware_attested


def test_nonce_bound_quote_requires_an_injected_verifier():
    evidence = parse_measured_boot_evidence(_document(quote=_quote()))
    no_verifier = assess_measured_boot(evidence, expected_nonce=NONCE)
    verified = assess_measured_boot(
        evidence, expected_nonce=NONCE, quote_verifier=AcceptingVerifier()
    )
    assert no_verifier.quote_state == "unverified"
    assert not no_verifier.hardware_attested
    assert verified.state == "hardware-attested"
    assert verified.hardware_attested


def test_quote_nonce_mismatch_or_verifier_failure_is_untrusted():
    evidence = parse_measured_boot_evidence(_document(quote=_quote("x" * 43)))
    mismatch = assess_measured_boot(
        evidence, expected_nonce=NONCE, quote_verifier=AcceptingVerifier()
    )

    class ExplodingVerifier:
        def verify(self, quote, *, expected_nonce, evidence_digest):
            raise RuntimeError("simulated verifier outage")

    failure = assess_measured_boot(
        parse_measured_boot_evidence(_document(quote=_quote())),
        expected_nonce=NONCE,
        quote_verifier=ExplodingVerifier(),
    )
    assert mismatch.state == "untrusted-platform-evidence"
    assert failure.quote_state == "verification-failed"
    assert not failure.hardware_attested


def test_insecure_dma_and_boot_posture_is_explicitly_risky():
    evidence = parse_measured_boot_evidence(
        _document(
            secure_boot=False,
            hvci_running=False,
            dma_protection_available=False,
            external_dma_policy_restrictive=False,
        )
    )
    result = assess_measured_boot(evidence, expected_nonce=NONCE)
    assert result.state == "insecure-posture"
    assert "kernel-dma-protection-unavailable" in result.risks
    assert "external-dma-policy-permissive" in result.risks
    assert "secure-boot-disabled" in result.risks


def test_unknown_dma_evidence_remains_unknown_not_healthy():
    evidence = parse_measured_boot_evidence(
        _document(
            dma_protection_available=None,
            external_dma_policy_restrictive=None,
        )
    )
    result = assess_measured_boot(evidence, expected_nonce=NONCE)
    assert result.state == "incomplete-evidence"
    assert "dma_protection_available" in result.unknown
    assert "external_dma_policy_restrictive" in result.unknown


def test_strict_parser_rejects_unknown_and_duplicate_keys():
    document = _document()
    document["unexpected"] = True
    with pytest.raises(MeasuredBootEvidenceRejected):
        parse_measured_boot_evidence(document)
    duplicate = json.dumps(_document()).replace(
        '"schema": "angerona.measured-boot-evidence.v1"',
        '"schema": "angerona.measured-boot-evidence.v1", "schema": "other"',
        1,
    )
    with pytest.raises(MeasuredBootEvidenceRejected):
        parse_measured_boot_evidence(duplicate)


def test_public_assessment_omits_quote_material_and_has_no_response_authority():
    evidence = parse_measured_boot_evidence(_document(quote=_quote()))
    result = assess_measured_boot(
        evidence, expected_nonce=NONCE, quote_verifier=AcceptingVerifier()
    )
    details = result.event_details()
    assert "opaque_attestation" not in repr(details)
    assert "opaque_signature" not in repr(details)
    assert details["raw_quote_omitted"] is True
    assert details["response_authorized"] is False
