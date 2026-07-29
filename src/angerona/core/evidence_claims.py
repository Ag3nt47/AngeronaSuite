"""Deterministic claim gate over already-committed evidence references."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Sequence

MAX_REFERENCES = 5000
MAX_CLAIMS = 500
MAX_CITATIONS = 64
MAX_CLAIM_TEXT = 8000
_ID = re.compile(r"^[A-Za-z0-9_.:@/-]{1,160}$")


class ClaimStatus(str, Enum):
    VERIFIED = "verified"
    INFERRED = "inferred"
    UNVERIFIED = "unverified"


@dataclass(frozen=True)
class CommittedEvidenceRef:
    evidence_id: str
    sha256: str
    committed: bool
    provenance: str

    def __post_init__(self) -> None:
        if not _ID.fullmatch(self.evidence_id):
            raise ValueError("invalid evidence ID")
        if not re.fullmatch(r"[0-9a-f]{64}", self.sha256):
            raise ValueError("invalid evidence digest")
        if not self.provenance or len(self.provenance) > 1000:
            raise ValueError("bounded provenance is required")


@dataclass(frozen=True)
class EvidenceClaim:
    claim_id: str
    text: str
    evidence_ids: tuple[str, ...]
    confidence: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence_ids", tuple(self.evidence_ids))
        if not _ID.fullmatch(self.claim_id):
            raise ValueError("invalid claim ID")
        if not self.text or len(self.text) > MAX_CLAIM_TEXT:
            raise ValueError("claim text is empty or exceeds bound")
        if len(self.evidence_ids) > MAX_CITATIONS:
            raise ValueError("too many claim citations")
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError("duplicate claim citation")
        if any(not _ID.fullmatch(item) for item in self.evidence_ids):
            raise ValueError("invalid citation ID")
        if type(self.confidence) is not int or not 0 <= self.confidence <= 100:
            raise ValueError("confidence must be an integer from 0 to 100")


@dataclass(frozen=True)
class ResolvedClaim:
    claim_id: str
    text: str
    requested_confidence: int
    effective_confidence: int
    status: ClaimStatus
    committed_evidence_ids: tuple[str, ...]
    unresolved_evidence_ids: tuple[str, ...]
    reason: str
    resolution_hash: str


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def resolve_claims(
    claims: Sequence[EvidenceClaim],
    references: Sequence[CommittedEvidenceRef],
) -> tuple[ResolvedClaim, ...]:
    """Resolve claims without database, shell, model, or network access."""
    if len(claims) > MAX_CLAIMS or len(references) > MAX_REFERENCES:
        raise ValueError("claim gate input bound exceeded")
    ref_index: dict[str, CommittedEvidenceRef] = {}
    for reference in references:
        if reference.evidence_id in ref_index:
            raise ValueError("duplicate evidence reference")
        ref_index[reference.evidence_id] = reference
    output: list[ResolvedClaim] = []
    for claim in sorted(claims, key=lambda item: item.claim_id):
        committed = tuple(sorted(
            evidence_id for evidence_id in claim.evidence_ids
            if evidence_id in ref_index and ref_index[evidence_id].committed
        ))
        unresolved = tuple(sorted(set(claim.evidence_ids) - set(committed)))
        if claim.evidence_ids and not unresolved:
            status = ClaimStatus.VERIFIED
            confidence = claim.confidence
            reason = "all cited evidence references are committed"
        elif committed:
            status = ClaimStatus.INFERRED
            confidence = min(claim.confidence, 60)
            reason = "claim has partial committed support; unresolved citations remain"
        else:
            status = ClaimStatus.UNVERIFIED
            confidence = min(claim.confidence, 20)
            reason = "claim has no committed evidence reference"
        core = {
            "claim_id": claim.claim_id, "text": claim.text,
            "requested_confidence": claim.confidence,
            "effective_confidence": confidence, "status": status.value,
            "committed_evidence_ids": committed,
            "unresolved_evidence_ids": unresolved, "reason": reason,
        }
        output.append(ResolvedClaim(
            claim_id=claim.claim_id, text=claim.text,
            requested_confidence=claim.confidence,
            effective_confidence=confidence, status=status,
            committed_evidence_ids=committed,
            unresolved_evidence_ids=unresolved, reason=reason,
            resolution_hash=hashlib.sha256(_canonical(core)).hexdigest(),
        ))
    return tuple(output)
