from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from tools.build_msix_package import (
    RESCAP,
    four_part_version,
    render_manifest,
    validate_contract,
    validate_manifest,
)


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "installer" / "msix" / "AppxManifest.xml.in"
CONTRACT = ROOT / "installer" / "windows-install-contract.json"


def test_strict_full_trust_manifest_is_rendered_with_exact_external_identity(tmp_path):
    output = tmp_path / "AppxManifest.xml"
    render_manifest(
        template=TEMPLATE,
        output=output,
        package_name="Angerona.SecuritySuite",
        publisher_dn="CN=Angerona Release, O=Angerona Project, C=US",
        version="1.11.0",
    )
    raw = output.read_bytes()
    validate_manifest(
        raw,
        package_name="Angerona.SecuritySuite",
        publisher_dn="CN=Angerona Release, O=Angerona Project, C=US",
        version="1.11.0.0",
    )
    root = ET.fromstring(raw)
    capability = root.find(f".//{{{RESCAP}}}Capability")
    assert capability is not None and capability.attrib == {"Name": "runFullTrust"}
    assert b"Windows.FullTrustApplication" in raw
    assert b'Executable="AngeronaStartup.exe"' in raw
    assert b"ForceUpdateFromAnyVersion" not in raw
    with pytest.raises(ValueError, match="full-trust application"):
        validate_manifest(
            raw.replace(b'Executable="AngeronaStartup.exe"', b'Executable="Angerona.exe"'),
            package_name="Angerona.SecuritySuite",
            publisher_dn="CN=Angerona Release, O=Angerona Project, C=US",
            version="1.11.0.0",
        )


def test_manifest_rejects_identity_injection_or_non_four_part_version(tmp_path):
    with pytest.raises(ValueError, match="Name"):
        render_manifest(
            template=TEMPLATE,
            output=tmp_path / "bad.xml",
            package_name='Bad\" Name',
            publisher_dn="CN=Angerona",
            version="1.11.0",
        )
    with pytest.raises(ValueError, match="unsigned 16-bit"):
        four_part_version("1.11.70000")


def test_install_contract_declares_only_msix_as_public_first_install():
    validate_contract(CONTRACT)
    text = CONTRACT.read_text(encoding="utf-8")
    assert '"schema":"angerona.windows-install-contract/v2"' in text
    assert '"artifact":"signed-msix"' in text
    assert (
        '"public_windows_install_artifacts":'
        '["signed-msix","threshold-authorized-zip"]'
    ) in text
    assert '"protected_portable_upgrade":{"artifact":"threshold-authorized-zip"' in text
    assert '"requires_installed_protected_authority":true' in text
    assert '"rollback_floor_enforced":true' in text
    assert '"public_trust_bootstrap":false' in text
    assert '"public_release_asset":false' in text
    assert '"requires_prior_approved_installation":true' in text
    assert '"pre_elevation_custody_check":true' in text
    assert '"delegates_elevation_and_mutation_to_installed_authority":true' in text
    assert '"role":"approved-installation-migration-only"' in text
    assert '"enterprise_clean_install":{"included":false' in text
    assert '"requires_external_allow_policy":true' in text
    assert '"same_public_asset":false' in text
    assert '"separate_governed_artifact":true' in text
