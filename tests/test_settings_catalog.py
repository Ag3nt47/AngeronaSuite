import pytest

from angerona.core.settings_catalog import (
    AREAS, SettingsArea, resolve_area, validate_catalog,
)


def test_settings_catalog_has_one_owner_and_routes_common_terms():
    validate_catalog()
    assert len({area.key for area in AREAS}) == len(AREAS)
    assert resolve_area("microphone input").title == "ARIA"
    assert resolve_area("Proton VPN false positive").title == "Trusted Processes"
    assert resolve_area("AuthentiCode process baseline learning").title == (
        "Trusted Processes"
    )
    assert resolve_area("startup performance").title == "System"
    assert resolve_area("performance tuning").title == "System"
    assert resolve_area("Signal phone").title == "Mobile Integration"
    assert resolve_area("fleet RBAC").title == "Enterprise"
    assert resolve_area("restore privacy defaults").title == "ARIA"
    assert resolve_area("privacy").title == "ARIA"
    assert resolve_area("voice model").title == "ARIA"
    assert resolve_area("choose a microphone").title == "ARIA"
    assert resolve_area("configure a cloud API key").title == "API Keys"
    assert resolve_area("rotate API keys").title == "API Keys"
    assert resolve_area("unknown phrase") is None


def test_settings_catalog_uses_phrase_aware_deterministic_scoring():
    # The specific phrase wins over incidental single-word matches in other areas.
    assert resolve_area("voice model").title == "ARIA"
    assert resolve_area("cloud API key").title == "API Keys"

    # Matching uses complete words rather than arbitrary substrings.
    assert resolve_area("capital planning") is None

    # A true cross-area tie remains unresolved instead of depending on AREAS order.
    assert resolve_area("cloud theme") is None


def test_settings_catalog_rejects_overlapping_ownership():
    duplicate = (
        SettingsArea("one", "One", "First", ("shared",), "local"),
        SettingsArea("two", "Two", "Second", ("shared",), "local"),
    )
    with pytest.raises(ValueError, match="overlapping"):
        validate_catalog(duplicate)
