"""Measured-boot evidence parsing and conservative appraisal.

This module never claims to produce a TPM quote.  It accepts a bounded,
nonce-bound quote from an explicitly supplied collector and calls an injected
verifier.  OS-reported Secure Boot/VBS/HVCI posture remains useful evidence but
is labelled ``os-posture-only`` unless the quote is cryptographically verified
against an enrolled attestation key and acceptable PCR policy.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import asdict, dataclass
from typing import Mapping, Protocol


SCHEMA = "angerona.measured-boot-evidence.v1"
QUOTE_SCHEMA = "angerona.tpm-quote-evidence.v1"
MAX_EVIDENCE_BYTES = 64 * 1024
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_EVIDENCE_KEYS = frozenset({"schema", "observed_at", "os_posture", "tpm"})
_POSTURE_KEYS = frozenset(
    {
        "secure_boot",
        "vbs_running",
        "hvci_running",
        "code_integrity_enabled",
        "test_signing",
        "boot_debug",
        "dma_protection_available",
        "external_dma_policy_restrictive",
    }
)
_TPM_KEYS = frozenset({"present", "version", "quote"})
_QUOTE_KEYS = frozenset(
    {"schema", "nonce", "pcr_digest", "attestation_blob", "signature", "key_id"}
)


class MeasuredBootEvidenceRejected(ValueError):
    """Measured-boot input was oversized, ambiguous, or outside its schema."""


class _DuplicateJsonKey(ValueError):
    pass


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _strict_document(value: bytes | str | Mapping[str, object]) -> dict:
    if isinstance(value, Mapping):
        try:
            raw = _canonical(dict(value))
        except (TypeError, ValueError) as exc:
            raise MeasuredBootEvidenceRejected("measured-boot mapping is not JSON-safe") from exc
    elif isinstance(value, str):
        raw = value.encode("utf-8", "strict")
    elif isinstance(value, bytes):
        raw = value
    else:
        raise MeasuredBootEvidenceRejected("measured-boot input type is invalid")
    if not raw or len(raw) > MAX_EVIDENCE_BYTES:
        raise MeasuredBootEvidenceRejected("measured-boot input size is invalid")
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise MeasuredBootEvidenceRejected("measured-boot input is not strict UTF-8") from exc

    def unique_object(pairs):
        result = {}
        for key, item in pairs:
            if not isinstance(key, str) or key in result:
                raise _DuplicateJsonKey("duplicate or non-text JSON key")
            result[key] = item
        return result

    def reject_constant(_value):
        raise ValueError("non-finite JSON number")

    try:
        document = json.loads(
            text,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (json.JSONDecodeError, _DuplicateJsonKey, ValueError) as exc:
        raise MeasuredBootEvidenceRejected("measured-boot JSON is invalid or ambiguous") from exc
    if not isinstance(document, dict) or set(document) != _EVIDENCE_KEYS:
        raise MeasuredBootEvidenceRejected("measured-boot document schema is invalid")
    return document


def _optional_bool(value: object, field: str) -> bool | None:
    if value is None or type(value) is bool:
        return value
    raise MeasuredBootEvidenceRejected(f"{field} must be boolean or null")


def _bounded_ascii(value: object, field: str, *, minimum: int = 1, maximum: int = 8192) -> str:
    if (
        not isinstance(value, str)
        or not minimum <= len(value) <= maximum
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
    ):
        raise MeasuredBootEvidenceRejected(f"{field} encoding is invalid")
    return value


@dataclass(frozen=True)
class OsBootPosture:
    secure_boot: bool | None
    vbs_running: bool | None
    hvci_running: bool | None
    code_integrity_enabled: bool | None
    test_signing: bool | None
    boot_debug: bool | None
    dma_protection_available: bool | None
    external_dma_policy_restrictive: bool | None


@dataclass(frozen=True)
class TpmQuoteEvidence:
    schema: str
    nonce: str
    pcr_digest: str
    attestation_blob: str
    signature: str
    key_id: str

    def public_claim(self) -> dict:
        """Return identifiers/digests only; never echo opaque attestation bytes."""

        return {
            "schema": self.schema,
            "nonce_sha256": hashlib.sha256(self.nonce.encode("ascii")).hexdigest(),
            "pcr_digest": self.pcr_digest,
            "key_id": self.key_id,
            "attestation_blob_omitted": True,
            "signature_omitted": True,
        }


@dataclass(frozen=True)
class TpmEvidence:
    present: bool | None
    version: str | None
    quote: TpmQuoteEvidence | None


@dataclass(frozen=True)
class MeasuredBootEvidence:
    schema: str
    observed_at: float
    os_posture: OsBootPosture
    tpm: TpmEvidence

    def digest(self) -> str:
        return hashlib.sha256(_canonical(asdict(self))).hexdigest()


class TpmQuoteVerifier(Protocol):
    """Verifier must check signature, nonce, AK enrollment, PCRs, and policy."""

    def verify(
        self,
        quote: TpmQuoteEvidence,
        *,
        expected_nonce: str,
        evidence_digest: str,
    ) -> bool: ...


@dataclass(frozen=True)
class MeasuredBootAssessment:
    state: str
    posture_consistent: bool
    hardware_attested: bool
    response_authorized: bool
    quote_state: str
    evidence_digest: str
    risks: tuple[str, ...]
    unknown: tuple[str, ...]

    def event_details(self) -> dict:
        return {
            "schema": "angerona.measured-boot-assessment.v1",
            "state": self.state,
            "posture_consistent": self.posture_consistent,
            "hardware_attested": self.hardware_attested,
            "quote_state": self.quote_state,
            "evidence_sha256": self.evidence_digest,
            "risk_codes": list(self.risks),
            "unknown_fields": list(self.unknown),
            "raw_quote_omitted": True,
            "response_authorized": False,
            "response_authority": "observe-only",
        }


def parse_measured_boot_evidence(
    value: bytes | str | Mapping[str, object],
) -> MeasuredBootEvidence:
    document = _strict_document(value)
    if document.get("schema") != SCHEMA:
        raise MeasuredBootEvidenceRejected("measured-boot schema version is invalid")
    observed_at = document.get("observed_at")
    if (
        not isinstance(observed_at, (int, float))
        or isinstance(observed_at, bool)
        or not math.isfinite(float(observed_at))
        or not 0.0 <= float(observed_at) <= 32_503_680_000.0
    ):
        raise MeasuredBootEvidenceRejected("measured-boot observation time is invalid")
    posture = document.get("os_posture")
    if not isinstance(posture, dict) or set(posture) != _POSTURE_KEYS:
        raise MeasuredBootEvidenceRejected("OS boot-posture schema is invalid")
    os_posture = OsBootPosture(
        secure_boot=_optional_bool(posture["secure_boot"], "secure_boot"),
        vbs_running=_optional_bool(posture["vbs_running"], "vbs_running"),
        hvci_running=_optional_bool(posture["hvci_running"], "hvci_running"),
        code_integrity_enabled=_optional_bool(
            posture["code_integrity_enabled"], "code_integrity_enabled"
        ),
        test_signing=_optional_bool(posture["test_signing"], "test_signing"),
        boot_debug=_optional_bool(posture["boot_debug"], "boot_debug"),
        dma_protection_available=_optional_bool(
            posture["dma_protection_available"], "dma_protection_available"
        ),
        external_dma_policy_restrictive=_optional_bool(
            posture["external_dma_policy_restrictive"],
            "external_dma_policy_restrictive",
        ),
    )
    tpm = document.get("tpm")
    if not isinstance(tpm, dict) or set(tpm) != _TPM_KEYS:
        raise MeasuredBootEvidenceRejected("TPM evidence schema is invalid")
    present = _optional_bool(tpm["present"], "tpm.present")
    version_value = tpm["version"]
    if version_value is not None:
        version_value = _bounded_ascii(version_value, "tpm.version", maximum=32)
    quote_value = tpm["quote"]
    quote: TpmQuoteEvidence | None = None
    if quote_value is not None:
        if not isinstance(quote_value, dict) or set(quote_value) != _QUOTE_KEYS:
            raise MeasuredBootEvidenceRejected("TPM quote schema is invalid")
        if quote_value.get("schema") != QUOTE_SCHEMA:
            raise MeasuredBootEvidenceRejected("TPM quote schema version is invalid")
        nonce = _bounded_ascii(quote_value.get("nonce"), "TPM quote nonce", minimum=32, maximum=128)
        if not _NONCE.fullmatch(nonce):
            raise MeasuredBootEvidenceRejected("TPM quote nonce alphabet is invalid")
        digest = quote_value.get("pcr_digest")
        if not isinstance(digest, str) or not _HEX_64.fullmatch(digest):
            raise MeasuredBootEvidenceRejected("TPM PCR digest is invalid")
        quote = TpmQuoteEvidence(
            schema=QUOTE_SCHEMA,
            nonce=nonce,
            pcr_digest=digest,
            attestation_blob=_bounded_ascii(
                quote_value.get("attestation_blob"), "TPM attestation blob"
            ),
            signature=_bounded_ascii(quote_value.get("signature"), "TPM quote signature"),
            key_id=_bounded_ascii(quote_value.get("key_id"), "TPM attestation key id", maximum=128),
        )
    return MeasuredBootEvidence(
        schema=SCHEMA,
        observed_at=float(observed_at),
        os_posture=os_posture,
        tpm=TpmEvidence(present=present, version=version_value, quote=quote),
    )


def assess_measured_boot(
    evidence: MeasuredBootEvidence,
    *,
    expected_nonce: str,
    quote_verifier: TpmQuoteVerifier | None = None,
) -> MeasuredBootAssessment:
    if not isinstance(evidence, MeasuredBootEvidence):
        raise TypeError("measured-boot evidence contract is invalid")
    if not isinstance(expected_nonce, str) or not _NONCE.fullmatch(expected_nonce):
        raise ValueError("measured-boot challenge nonce is invalid")
    risks: list[str] = []
    unknown: list[str] = []
    posture = evidence.os_posture
    for field, risk in (
        ("secure_boot", "secure-boot-disabled"),
        ("vbs_running", "vbs-not-running"),
        ("hvci_running", "hvci-not-running"),
        ("code_integrity_enabled", "code-integrity-disabled"),
    ):
        value = getattr(posture, field)
        if value is False:
            risks.append(risk)
        elif value is None:
            unknown.append(field)
    for field, risk in (
        ("test_signing", "test-signing-enabled"),
        ("boot_debug", "boot-debug-enabled"),
    ):
        value = getattr(posture, field)
        if value is True:
            risks.append(risk)
        elif value is None:
            unknown.append(field)
    dma_available = posture.dma_protection_available
    if dma_available is False:
        risks.append("kernel-dma-protection-unavailable")
    elif dma_available is None:
        unknown.append("dma_protection_available")
    dma_policy = posture.external_dma_policy_restrictive
    if dma_policy is False:
        risks.append("external-dma-policy-permissive")
    elif dma_policy is None:
        unknown.append("external_dma_policy_restrictive")
    if evidence.tpm.present is None:
        unknown.append("tpm.present")
    elif evidence.tpm.present is False and evidence.tpm.quote is not None:
        risks.append("tpm-quote-present-while-tpm-reported-absent")

    quote_state = "absent"
    hardware_attested = False
    quote = evidence.tpm.quote
    if quote is not None:
        if not hmac_compare(quote.nonce, expected_nonce):
            quote_state = "nonce-mismatch"
            risks.append("tpm-quote-nonce-mismatch")
        elif quote_verifier is None:
            quote_state = "unverified"
            unknown.append("tpm.quote.verifier")
        else:
            try:
                verified = quote_verifier.verify(
                    quote,
                    expected_nonce=expected_nonce,
                    evidence_digest=evidence.digest(),
                )
            except Exception:
                verified = False
            if verified is True and evidence.tpm.present is True:
                quote_state = "verified"
                hardware_attested = True
            else:
                quote_state = "verification-failed"
                risks.append("tpm-quote-verification-failed")

    posture_consistent = not risks and not unknown
    if risks:
        state = "untrusted-platform-evidence" if "tpm" in " ".join(risks) else "insecure-posture"
    elif hardware_attested and posture_consistent:
        state = "hardware-attested"
    elif unknown:
        state = "incomplete-evidence"
    else:
        state = "os-posture-only"
    return MeasuredBootAssessment(
        state=state,
        posture_consistent=posture_consistent,
        hardware_attested=hardware_attested,
        response_authorized=False,
        quote_state=quote_state,
        evidence_digest=evidence.digest(),
        risks=tuple(sorted(set(risks))),
        unknown=tuple(sorted(set(unknown))),
    )


def hmac_compare(left: str, right: str) -> bool:
    """Constant-time text comparison without importing a quote implementation."""

    import hmac

    return hmac.compare_digest(left.encode("ascii"), right.encode("ascii"))


def self_test() -> tuple[bool, str]:
    nonce = "n" * 43
    evidence = parse_measured_boot_evidence(
        {
            "schema": SCHEMA,
            "observed_at": 1_800_000_000.0,
            "os_posture": {
                "secure_boot": True,
                "vbs_running": True,
                "hvci_running": True,
                "code_integrity_enabled": True,
                "test_signing": False,
                "boot_debug": False,
                "dma_protection_available": True,
                "external_dma_policy_restrictive": True,
            },
            "tpm": {"present": True, "version": "2.0", "quote": None},
        }
    )
    result = assess_measured_boot(evidence, expected_nonce=nonce)
    if result.hardware_attested or result.state != "os-posture-only":
        return False, "OS posture was incorrectly promoted to hardware attestation"
    return True, "strict posture parser preserves the TPM hardware-attestation boundary"


__all__ = [
    "MAX_EVIDENCE_BYTES",
    "MeasuredBootAssessment",
    "MeasuredBootEvidence",
    "MeasuredBootEvidenceRejected",
    "OsBootPosture",
    "QUOTE_SCHEMA",
    "SCHEMA",
    "TpmEvidence",
    "TpmQuoteEvidence",
    "TpmQuoteVerifier",
    "assess_measured_boot",
    "parse_measured_boot_evidence",
    "self_test",
]
