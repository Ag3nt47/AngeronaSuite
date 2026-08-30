from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess

import pytest
import yaml

from tools.release_artifact_tag import resolve_artifact_tag


ROOT = Path(__file__).resolve().parents[1]


def _parse_powershell(source: str) -> subprocess.CompletedProcess[str]:
    powershell = shutil.which("powershell.exe")
    assert powershell is not None
    parser = r"""
$source = [Console]::In.ReadToEnd()
$tokens = $null
$errors = $null
[void][Management.Automation.Language.Parser]::ParseInput(
    $source, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) {
    [Console]::Error.WriteLine(($errors | Out-String))
    exit 1
}
"""
    return subprocess.run(
        [
            powershell,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "RemoteSigned",
            "-Command",
            parser,
        ],
        input=source,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows ACL semantics are required")
@pytest.mark.parametrize(
    "case",
    [
        "safe_directory",
        "safe_file",
        "low_privilege",
        "custom_group",
        "file_specific",
        "bad_owner",
    ],
)
def test_release_custody_acl_policy_rejects_non_authority_writers(case: str) -> None:
    powershell = shutil.which("powershell.exe")
    assert powershell is not None
    harness = r"""
$ErrorActionPreference = 'Stop'
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $env:ANGERONA_CUSTODY_SCRIPT, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw ($parseErrors | Out-String) }
foreach ($function in $ast.FindAll({
        param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]
    }, $true)) {
    Invoke-Expression $function.Extent.Text
}
$approvedCustodySids = @('S-1-5-18', 'S-1-5-32-544')
$directory = $env:ANGERONA_CUSTODY_CASE -notin @('safe_file', 'file_specific')
$acl = New-ProtectedAcl $directory
switch ($env:ANGERONA_CUSTODY_CASE) {
    'low_privilege' {
        $sid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid, [Security.AccessControl.FileSystemRights]::Modify,
            [Security.AccessControl.AccessControlType]::Allow)
        [void]$acl.AddAccessRule($rule)
    }
    'custom_group' {
        $sid = [Security.Principal.SecurityIdentifier]::new(
            'S-1-5-21-111111111-222222222-333333333-4444')
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid, [Security.AccessControl.FileSystemRights]::WriteData,
            [Security.AccessControl.AccessControlType]::Allow)
        [void]$acl.AddAccessRule($rule)
    }
    'file_specific' {
        $sid = [Security.Principal.SecurityIdentifier]::new('S-1-5-11')
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid, [Security.AccessControl.FileSystemRights]::WriteAttributes,
            [Security.AccessControl.AccessControlType]::Allow)
        [void]$acl.AddAccessRule($rule)
    }
    'bad_owner' {
        $acl.SetOwner(
            [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'))
    }
}
$mustFail = $env:ANGERONA_CUSTODY_CASE -notin @('safe_directory', 'safe_file')
$rejected = $false
try {
    Assert-ProtectedAcl $acl $env:ANGERONA_CUSTODY_CASE
} catch {
    $rejected = $true
}
if ($rejected -ne $mustFail) {
    throw "ACL result mismatch: rejected=$rejected expected=$mustFail"
}
"""
    env = os.environ.copy()
    env["ANGERONA_CUSTODY_SCRIPT"] = str(ROOT / "Install-Angerona-Release.ps1")
    env["ANGERONA_CUSTODY_CASE"] = case
    result = subprocess.run(
        [
            powershell,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "RemoteSigned",
            "-Command",
            harness,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )
    assert result.returncode == 0, result.stderr or result.stdout


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell parser is required")
def test_release_powershell_and_every_workflow_pwsh_block_parse() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
    )
    blocks = [
        step["run"]
        for job in workflow["jobs"].values()
        for step in job.get("steps", [])
        if step.get("shell") == "pwsh" and isinstance(step.get("run"), str)
    ]
    sources = [
        (ROOT / "Install-Angerona-Release.ps1").read_text(encoding="utf-8"),
        (ROOT / "Verify-Angerona-Release.ps1").read_text(encoding="utf-8"),
        *blocks,
    ]
    assert len(blocks) >= 10
    for index, source in enumerate(sources):
        result = _parse_powershell(source)
        assert result.returncode == 0, (
            f"PowerShell source {index} failed parser validation: "
            f"{result.stderr or result.stdout}"
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows path semantics are required")
def test_protected_path_rejects_metadata_change_during_acl_inspection(tmp_path) -> None:
    candidate = tmp_path / "authority.json"
    candidate.write_text("before", encoding="utf-8")
    powershell = shutil.which("powershell.exe")
    assert powershell is not None
    harness = r"""
$ErrorActionPreference = 'Stop'
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $env:ANGERONA_CUSTODY_SCRIPT, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw ($parseErrors | Out-String) }
foreach ($function in $ast.FindAll({
        param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]
    }, $true)) {
    Invoke-Expression $function.Extent.Text
}
function Assert-ProtectedAcl { param($Acl, $Label) }
function Get-Acl {
    param([string]$LiteralPath, $ErrorAction)
    [IO.File]::AppendAllText($LiteralPath, '-changed')
    return New-Object Security.AccessControl.FileSecurity
}
$rejected = $false
try { Assert-ProtectedPath $env:ANGERONA_CUSTODY_TARGET $false } catch {
    $rejected = $_.Exception.Message -like '*changed during custody inspection*'
}
if (-not $rejected) { throw 'path metadata race was not rejected' }
"""
    env = os.environ.copy()
    env["ANGERONA_CUSTODY_SCRIPT"] = str(ROOT / "Install-Angerona-Release.ps1")
    env["ANGERONA_CUSTODY_TARGET"] = str(candidate)
    result = subprocess.run(
        [
            powershell,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "RemoteSigned",
            "-Command",
            harness,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )
    assert result.returncode == 0, result.stderr or result.stdout


def test_inno_setup_is_a_fail_closed_prior_installation_migration_wrapper() -> None:
    text = (ROOT / "installer" / "Angerona.iss").read_text(encoding="utf-8")

    assert "PrivilegesRequired=lowest" in text
    assert "ArchitecturesAllowed=x64compatible" in text
    assert "DefaultDirName={commonpf64}\\Angerona" in text
    assert "CreateAppDir=no" in text
    assert "CreateUninstallRegKey=no" in text
    assert "Uninstallable=no" in text
    assert 'Source: "..\\Angerona-{#ArtifactTag}-win64.zip"; Flags: dontcopy' in text
    assert "DestDir: \"{app}\"" not in text
    assert "SignTool=AngeronaSign" in text
    assert "VerifySetupPublisher" in text
    assert "VerifyPriorApprovedInstallation" in text
    assert "PrepareToInstall" in text
    assert "Install-Angerona-Release.ps1" in text
    assert "-CustodyPreflightOnly" in text
    assert "ShellExec(" in text and "'runas'" in text
    assert "No Angerona application file was installed by Setup" in text
    assert "PublisherCertificateSha256" in text
    assert "PrivilegesRequired=admin" not in text
    assert "ApprovedInstallationMigrationOnly" in text
    assert "MigrationOrEnterprisePolicyOnly" not in text
    assert "RegWrite" not in text
    assert "win64-migration-setup" in text
    assert text.index("VerifyPriorApprovedInstallation") < text.index(
        "ShellExec("
    )


def test_release_workflow_never_publishes_or_attests_classic_setup() -> None:
    path = ROOT / ".github" / "workflows" / "release.yml"
    text = path.read_text(encoding="utf-8")
    parsed = yaml.safe_load(text)

    assert isinstance(parsed, dict)
    jobs = parsed["jobs"]
    prepare = yaml.safe_dump(jobs["prepare-windows"], sort_keys=True)
    packager = yaml.safe_dump(jobs["package-windows"], sort_keys=True)
    finalizer = yaml.safe_dump(
        jobs["finalize-release-authority"], sort_keys=True
    )
    publisher = yaml.safe_dump(jobs["publish-release"], sort_keys=True)

    assert 'ANGERONA_ARTIFACT_TAG: ${{ steps.artifact_name.outputs.tag }}' in text
    assert "Attest release archive" in text
    assert "Attest software bill of materials" in text
    assert "Verify-Angerona-Release.ps1" in text
    assert (ROOT / "Verify-Angerona-Release.ps1").is_file()
    verifier_text = (ROOT / "Verify-Angerona-Release.ps1").read_text(encoding="utf-8")
    assert "@('.msix', '.exe', '.zip')" in verifier_text
    assert "tools/build_release_authorization.py" in text
    assert "sign-release-a:" not in text
    assert "sign-release-b:" not in text
    assert "ANGERONA_RELEASE_SIGNER_A" not in text
    assert "ANGERONA_RELEASE_SIGNER_B" not in text
    assert "ANGERONA_RELEASE_ROOT_POLICY_B64" not in text
    assert "ANGERONA_RELEASE_ROOT_POLICY_SHA256" not in text
    assert "permissions: {}" in finalizer
    assert "actions/checkout" not in finalizer
    assert "actions/download-artifact" not in finalizer
    assert "secrets." not in finalizer
    assert "exit 1" in finalizer
    assert jobs["finalize-release-authority"]["needs"] == "package-windows"
    assert "prepared-release-signing-request" in text
    assert "prepared-windows-publisher-request" in packager
    assert "finalized-windows-release-assets" in publisher
    assert "prepared-windows-publisher-request" not in publisher
    assert jobs["package-windows"]["needs"] == "prepare-windows"
    assert "finalize-release-authority" in jobs["publish-release"]["needs"]
    for forbidden in (
        "environment: windows-code-signing",
        "ANGERONA_WINDOWS_SIGNING_PFX_B64",
        "ANGERONA_WINDOWS_SIGNING_PASSWORD",
        "ANGERONA_WINDOWS_SIGNING_CERT_SHA256",
        "Import-PfxCertificate",
        "signtool.exe",
        "secrets.",
        "innosetup-6.7.1.exe",
        "win64-migration-setup",
    ):
        assert forbidden not in text
    assert "makeappx.exe" in text
    assert "10.0.26100.0" in text
    assert "ANGERONA_MSIX_PACKAGE_NAME" in text
    assert "ANGERONA_MSIX_PUBLISHER_DN" in text
    assert "Windows installation contract" in text
    assert "-win64-unsigned.msix" in packager
    assert "-win64-unsigned.zip" in packager
    assert "windows-publisher-request.sha256" in packager
    assert "win64-migration-setup" not in publisher
    assert "Angerona-${{ github.ref_name }}-*" not in publisher
    assert "pattern: angerona-*" not in publisher
    assert "merge-multiple: true" not in publisher
    for artifact_name in (
        "finalized-windows-release-assets",
        "angerona-linux-x86_64",
        "angerona-macos-arm64",
    ):
        assert artifact_name in publisher
    assert "win64-migration-setup" not in text.split(
        "      - name: Attest release archive", 1
    )[1]
    assert "--name AngeronaReleaseVerifier" in text
    assert "release-payload-manifest.json" in text
    assert "release-payload.cat" in text
    assert "release-build-provenance.json" in text
    assert "release-payload-unsigned.cat" in prepare
    assert "release-authorization.json" not in finalizer
    assert "release-trust.json" not in finalizer
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
    assert "extension: tar.gz" in text
    assert "extension: zip" in text
    assert (
        "Angerona-${{ steps.artifact_name.outputs.tag }}-"
        "${{ matrix.artifact }}.${{ matrix.extension }}"
    ) in text
    assert "${{ matrix.artifact }}.*" not in text


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


def test_readme_has_a_visible_windows_install_section() -> None:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    section = text.split("## 🚀 One-click Windows install", 1)[1].split("\n## ", 1)[0]

    assert "Angerona-<version>" in section
    assert "No Python or terminal is required" in section


def test_portable_release_installer_is_protected_upgrade_only() -> None:
    text = (ROOT / "Install-Angerona-Release.ps1").read_text(encoding="utf-8")

    for name in (
        "Angerona-SBOM.json",
        "release-build-provenance.json",
        "release-authorization.json",
        "release-trust.json",
        "release-payload-manifest.json",
        "release-payload.cat",
    ):
        assert name in text
    assert "The portable package is upgrade-only" in text
    assert "$trustedInstaller" in text
    assert "$runningInstaller" in text
    assert "Test-FileCatalog" in text
    assert "Assert-PublisherSignature" in text
    assert "ReleaseArchive" in text
    assert "Publisher trust-root rotation is not authorized" in text
    assert "Get-FileHash -LiteralPath $installedTrust -Algorithm SHA256" in text
    assert "$trustedAuthorizationVerifier" in text
    assert "Assert-ProtectedAcl" in text
    assert ".GetOwner(" in text
    assert ".GetAccessRules(" in text
    assert "$true, $true, [Security.Principal.SecurityIdentifier]" in text
    assert "S-1-5-18" in text and "S-1-5-32-544" in text
    assert "S-1-1-0', 'S-1-5-11', 'S-1-5-32-545" not in text
    assert "$installedCustodyNames" in text
    for name in (
        "Install-Angerona-Release.ps1",
        "Install-Angerona-Release.bat",
        "Verify-Angerona-Release.ps1",
        "AngeronaReleaseVerifier.exe",
        "Angerona.exe",
        "AngeronaBlackBox.exe",
        "Angerona-SBOM.json",
        "publisher-certificate.sha256",
        "release-payload-manifest.json",
        "release-payload.cat",
        "release-build-provenance.json",
        "release-authorization.json",
        "release-trust.json",
        "release-files.sha256",
        "release-floor.json",
    ):
        assert name in text
    assert "Assert-ProtectedPath $floor $false" in text
    assert "Assert-PublisherSignature $trustedAuthorizationVerifier" in text
    assert "--candidate-root $payloadRoot" in text
    assert "--floor-output $nextFloor" in text
    assert "release-floor.json" in text
    assert text.index("--floor-output $nextFloor") < text.index("$installPaths =")
    assert text.index("$publisherCertificate = Assert-InstalledCustody") < text.index(
        "Administrator privileges are required."
    )
    assert "if ($CustodyPreflightOnly)" in text
    assert text.count("Assert-InstalledCustody") >= 3
    assert text.rindex("$publisherCertificate = Assert-InstalledCustody") < text.index(
        "$stage = Join-Path $target"
    )


def test_batch_launcher_preflights_custody_before_requesting_elevation() -> None:
    text = (ROOT / "Install-Angerona-Release.bat").read_text(encoding="utf-8")

    preflight = text.index("-CustodyPreflightOnly")
    elevation = text.index("-Verb RunAs")
    assert preflight < elevation
    assert "-Wait -PassThru" in text
    assert "Classic Setup is restricted to a protected legacy migration" in text
    assert "Enterprise clean install requires a separate governed deployment artifact" in text
