import pytest

from angerona.core.evidence_claims import (
    ClaimStatus, CommittedEvidenceRef, EvidenceClaim, resolve_claims,
)


def reference(identifier, committed=True):
    return CommittedEvidenceRef(identifier, "a" * 64, committed, "signed ledger")


def test_all_citations_must_resolve_to_committed_references_for_verified():
    claim = EvidenceClaim("claim-1", "Process executed", ("ev-1",), 90)
    result = resolve_claims((claim,), (reference("ev-1"),))[0]
    assert result.status is ClaimStatus.VERIFIED
    assert result.effective_confidence == 90
    assert result.unresolved_evidence_ids == ()


def test_partial_support_downgrades_to_inferred_and_bounds_confidence():
    claim = EvidenceClaim(
        "claim-1", "Process contacted a suspicious host", ("ev-1", "missing"), 95
    )
    result = resolve_claims((claim,), (reference("ev-1"),))[0]
    assert result.status is ClaimStatus.INFERRED
    assert result.effective_confidence == 60
    assert result.unresolved_evidence_ids == ("missing",)


def test_absent_uncommitted_or_uncited_claim_is_unverified():
    claims = (
        EvidenceClaim("a", "No citation", (), 80),
        EvidenceClaim("b", "Pending evidence", ("ev-1",), 80),
    )
    results = resolve_claims(claims, (reference("ev-1", committed=False),))
    assert all(item.status is ClaimStatus.UNVERIFIED for item in results)
    assert all(item.effective_confidence == 20 for item in results)


def test_resolution_is_deterministic_and_sorted():
    claims = (
        EvidenceClaim("z", "later", ("ev-z",), 70),
        EvidenceClaim("a", "first", ("ev-a",), 70),
    )
    references = (reference("ev-z"), reference("ev-a"))
    one = resolve_claims(claims, references)
    two = resolve_claims(tuple(reversed(claims)), tuple(reversed(references)))
    assert one == two
    assert [item.claim_id for item in one] == ["a", "z"]
    assert all(len(item.resolution_hash) == 64 for item in one)


def test_duplicate_reference_and_bounded_claims_fail_closed():
    with pytest.raises(ValueError, match="duplicate evidence"):
        resolve_claims(
            (EvidenceClaim("c", "claim", ("ev",), 1),),
            (reference("ev"), reference("ev")),
        )
    with pytest.raises(ValueError, match="too many"):
        EvidenceClaim("c", "claim", tuple(f"ev-{i}" for i in range(65)), 1)
