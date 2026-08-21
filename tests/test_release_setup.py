from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def test_inno_setup_is_admin_scoped_and_bundles_only_release_outputs() -> None:
    text = (ROOT / "installer" / "Angerona.iss").read_text(encoding="utf-8")

    assert "PrivilegesRequired=admin" in text
    assert "ArchitecturesAllowed=x64compatible" in text
    assert "DefaultDirName={autopf}\\Angerona" in text
    assert 'Source: "..\\dist\\Angerona\\Angerona.exe"' in text
    assert 'Source: "..\\dist\\Angerona\\AngeronaBlackBox.exe"' in text
    assert "runtime-data" not in text
    assert "PrivilegesRequired=lowest" not in text


def test_release_workflow_publishes_and_attests_setup_executable() -> None:
    path = ROOT / ".github" / "workflows" / "release.yml"
    text = path.read_text(encoding="utf-8")
    parsed = yaml.safe_load(text)

    assert isinstance(parsed, dict)
    setup = "Angerona-${{ github.ref_name }}-win64-setup.exe"
    assert "Get-Command ISCC.exe" in text
    assert text.count(setup) >= 6
    assert f"{setup}.sha256" in text
    assert "Attest release archive" in text
    assert "Attest software bill of materials" in text


def test_readme_leads_with_setup_and_keeps_verified_zip_fallback() -> None:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    section = text.split("## 🚀 One-click Windows install", 1)[1].split("\n## ", 1)[0]

    assert "win64-setup.exe" in section
    assert "No Python or terminal is required" in section
    assert "Install-Angerona-Release.bat" in section
