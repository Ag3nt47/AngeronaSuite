from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from tools.release_artifact_tag import resolve_artifact_tag


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
    setup = "Angerona-${{ steps.artifact_name.outputs.tag }}-win64-setup.exe"
    assert "innosetup-6.7.1.exe" in text
    assert "Get-FileHash -Algorithm SHA256 $innoInstaller" in text
    assert "Join-Path $innoDir 'ISCC.exe'" in text
    assert "Get-Command ISCC.exe" not in text
    assert text.count(setup) >= 2
    assert f"{setup}.sha256" in text
    assert 'ANGERONA_ARTIFACT_TAG: ${{ steps.artifact_name.outputs.tag }}' in text
    assert '$setup = "Angerona-$env:ANGERONA_ARTIFACT_TAG-win64-setup.exe"' in text
    assert "Attest release archive" in text
    assert "Attest software bill of materials" in text
    assert text.count("id: artifact_name") == 2
    assert "tools/release_artifact_tag.py" in text


def test_release_workflow_builds_only_wheel_locked_posix_architectures() -> None:
    text = (ROOT / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )

    assert "build-posix:" in text
    assert "ubuntu-24.04" in text
    assert "macos-15" in text
    assert "linux-x86_64" in text
    assert "macos-arm64" in text
    assert "macos-15-intel" not in text
    assert "macos-x86_64" not in text
    assert "tests/test_linux_platform_contract.py" not in text  # full suite is the gate
    assert "Angerona-${{ steps.artifact_name.outputs.tag }}-${{ matrix.artifact }}.*" in text


def test_manual_release_branch_names_are_safe_deterministic_components() -> None:
    first = resolve_artifact_tag("feature/operator/ui", "workflow_dispatch")
    second = resolve_artifact_tag("feature/operator/ui", "workflow_dispatch")
    collision = resolve_artifact_tag("feature-operator-ui", "workflow_dispatch")

    assert first == second
    assert first != collision
    assert "/" not in first and "\\" not in first
    assert len(first) <= 80
    assert resolve_artifact_tag("main", "workflow_dispatch") == "main"
    # Tag-triggered releases preserve the published tag exactly.
    assert resolve_artifact_tag("v1.10.0", "push") == "v1.10.0"
    with pytest.raises(ValueError, match="unsupported release event"):
        resolve_artifact_tag("feature/operator/ui", "pull_request")

    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )
    build_jobs = workflow.split("  publish-release:", 1)[0]
    assert "Angerona-${{ github.ref_name }}" not in build_jobs


def test_posix_installer_is_local_user_scoped_and_has_safe_uninstall() -> None:
    installer = (ROOT / "install-angerona.sh").read_text(encoding="utf-8")
    release_installer = (ROOT / "Install-Angerona-Release.sh").read_text(
        encoding="utf-8"
    )
    uninstall = (ROOT / "uninstall-angerona.sh").read_text(encoding="utf-8")
    unit = (ROOT / "installer" / "linux" / "angerona-headless.service").read_text(
        encoding="utf-8"
    )

    assert 'if [ "$(id -u)" -eq 0 ]' in installer
    assert "Python 3.12 is required for the reviewed source installation" in installer
    assert "--require-hashes --no-deps" in installer
    assert "tools/verify_wheelhouse.py" in installer
    assert "--no-build-isolation --no-deps" in installer
    assert "systemctl --user enable --now" in installer
    assert 'if [ "$(id -u)" -eq 0 ]' in release_installer
    assert "XDG_DATA_HOME" in release_installer
    assert "Angerona.app" in release_installer
    assert "install -m 0755" in release_installer
    assert "angerona-setup" in installer
    assert "angerona-setup" in release_installer
    assert "--args --setup" in release_installer
    assert '"$HOME/.local/bin/angerona-setup"' in uninstall
    assert "NoNewPrivileges=yes" in unit
    assert "ProtectSystem=strict" in unit
    assert "MemoryDenyWriteExecute=yes" in unit
    assert "--purge-data" in uninstall
    assert "Refusing unexpected data path" in uninstall


def test_readme_leads_with_setup_and_keeps_verified_zip_fallback() -> None:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    section = text.split("## 🚀 One-click Windows install", 1)[1].split("\n## ", 1)[0]

    assert "win64-setup.exe" in section
    assert "No Python or terminal is required" in section
    assert "Install-Angerona-Release.bat" in section
