import pytest

from angerona.core.settings_catalog import (
    AREAS, SettingsArea, resolve_area, validate_catalog,
)


def test_settings_catalog_has_one_owner_and_routes_common_terms():
    validate_catalog()
    assert len({area.key for area in AREAS}) == len(AREAS)
    assert resolve_area("microphone input").title == "ARIA"
    assert resolve_area("Proton VPN false positive").title == "Trusted Processes"
    assert resolve_area("startup performance").title == "System"
    assert resolve_area("Signal phone").title == "Mobile Integration"
    assert resolve_area("fleet RBAC").title == "Enterprise"
    assert resolve_area("unknown phrase") is None


def test_settings_catalog_rejects_overlapping_ownership():
    duplicate = (
        SettingsArea("one", "One", "First", ("shared",), "local"),
        SettingsArea("two", "Two", "Second", ("shared",), "local"),
    )
    with pytest.raises(ValueError, match="overlapping"):
        validate_catalog(duplicate)
