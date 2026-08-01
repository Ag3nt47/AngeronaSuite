from dataclasses import replace
from pathlib import Path

import pytest

from angerona.core.capability_guide import (
    GUIDES,
    CapabilityMaturity,
    CatalogValidationError,
    DestinationActionability,
    DestinationAvailability,
    DestinationKind,
    actionable_guides,
    get_guide,
    search_guides,
    validate_catalog,
)


def test_guides_are_complete_unique_and_searchable():
    assert len({guide.key for guide in GUIDES}) == len(GUIDES)
    for guide in GUIDES:
        assert guide.name and guide.definition and guide.steps
        assert guide.verify and guide.privacy
        if guide.destination_kind is not DestinationKind.NONE:
            assert guide.destination
        assert isinstance(guide.maturity, CapabilityMaturity)
        assert isinstance(guide.destination_kind, DestinationKind)
        assert isinstance(guide.destination_availability, DestinationAvailability)
        assert isinstance(guide.destination_actionability, DestinationActionability)
        assert guide.evidence and guide.limitations
    assert search_guides("microphone")[0].key == "local-ai"
    assert search_guides("custody privacy")[0].key == "forensics"
    assert search_guides("password spray")[0].key == "identity-defense"
    assert search_guides("periodic beaconing")[0].key == "network-behavior"
    assert search_guides("expired exceptions")[0].key == "exposure-management"
    assert search_guides("entrypoint collisions")[0].key == "signed-plugins"
    assert search_guides("dead-letter")[0].key == "interop"
    assert search_guides("over-budget results")[0].key == "fleet-hunts"
    assert search_guides("separation duty")[0].key == "enterprise-rbac"
    assert search_guides("no such capability") == ()


def test_claimed_evidence_references_existing_regression_files():
    repository = Path(__file__).resolve().parents[1]
    for guide in GUIDES:
        for reference in guide.evidence:
            assert (repository / reference).is_file(), (guide.key, reference)


def test_empty_search_returns_the_full_stable_catalog():
    assert search_guides("") == GUIDES


def test_exact_intent_search_is_deterministic_and_specific():
    assert search_guides("audit export")[0].key == "audit-export"
    assert search_guides("fleet")[0].key == "fleet-preview"
    assert search_guides("fleet hunt")[0].key == "fleet-hunts"
    assert search_guides("response session")[0].key == "safe-live-response"
    assert get_guide("fleet").key == "fleet-preview"
    assert get_guide("signed-audit").key == "audit-export"


def test_destination_actionability_is_typed_and_honest():
    assert all(guide.is_actionable for guide in actionable_guides())
    assert get_guide("fleet").destination_actionability is (
        DestinationActionability.CONTEXTUAL
    )
    assert get_guide("red-team").destination_actionability is (
        DestinationActionability.DIRECT
    )
    assert get_guide("response-broker").maturity is CapabilityMaturity.LIBRARY_ONLY
    assert get_guide("response-broker").destination_kind is DestinationKind.NONE
    assert not get_guide("response-broker").is_actionable
    assert get_guide("release-evidence").maturity is CapabilityMaturity.CLI_ONLY
    assert get_guide("enterprise-rbac").maturity is (
        CapabilityMaturity.INTERNAL_CONTROL
    )


def test_catalog_validation_rejects_incomplete_or_ambiguous_claims():
    with pytest.raises(CatalogValidationError, match="evidence"):
        validate_catalog((replace(GUIDES[0], evidence=()),))
    with pytest.raises(CatalogValidationError, match="invalid maturity"):
        validate_catalog((replace(GUIDES[0], maturity="verified-local"),))
    ambiguous = replace(GUIDES[0], aliases=(*GUIDES[0].aliases, "fleet"))
    with pytest.raises(CatalogValidationError, match="ambiguous search intent"):
        validate_catalog((ambiguous, *GUIDES[1:]))
