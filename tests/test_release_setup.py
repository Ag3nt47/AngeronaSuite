from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest
import yaml

from tools.release_artifact_tag import resolve_artifact_tag
from angerona.core.privilege import trusted_powershell_path


ROOT = Path(__file__).resolve().parents[1]


def _parse_powershell_sources(sources: list[str]) -> list[dict]:
    """Parse each source independently in one child; never execute source text."""
    if type(sources) is not list or not sources or any(type(item) is not str for item in sources):
        raise ValueError("PowerShell parser requires a nonempty list of source strings")
    powershell = str(trusted_powershell_path())
    parser = r"""
$ErrorActionPreference = 'Stop'
$decodedSources = ConvertFrom-Json -InputObject ([Console]::In.ReadToEnd())
$sources = @($decodedSources)
$results = @()
$failed = $false
for ($index = 0; $index -lt $sources.Count; $index++) {
    $tokens = $null
    $errors = $null
    [void][Management.Automation.Language.Parser]::ParseInput(
        $sources[$index], [ref]$tokens, [ref]$errors)
    $messages = @($errors | ForEach-Object { $_.Message })
    $results += [pscustomobject]@{index = $index; errors = $messages}
    if ($messages.Count -ne 0) { $failed = $true }
}
[Console]::Out.Write((ConvertTo-Json -InputObject $results -Compress -Depth 5))
if ($failed) { exit 1 }
"""
    result = subprocess.run(
        [
            powershell,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "RemoteSigned",
            "-Command",
            parser,
        ],
        input=json.dumps(sources, ensure_ascii=True),
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode in (0, 1), result.stderr or result.stdout
    rows = json.loads(result.stdout.lstrip("\ufeff"))
    assert type(rows) is list and len(rows) == len(sources), "Incomplete parser result set"
    for index, row in enumerate(rows):
        assert (type(row) is dict and set(row) == {"index", "errors"}
                and type(row["index"]) is int and row["index"] == index
                and type(row["errors"]) is list
                and all(type(error) is str for error in row["errors"])), "Invalid indexed parser result"
    assert result.returncode == int(any(row["errors"] for row in rows)), "Parser result/exit mismatch"
    return rows


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
    for row in _parse_powershell_sources(sources):
        assert not row["errors"], (
            f"PowerShell source {row['index']} failed parser validation: "
            f"{row['errors']}"
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell is required")
@pytest.mark.parametrize("case", ["absent", "present", "directory", "unsigned", "unprotected"])
@pytest.mark.parametrize("helper_name", ["AngeronaStartup.exe", "AngeronaSafeStart.exe"])
def test_existing_startup_helper_requires_custody_and_signature(tmp_path, case, helper_name) -> None:
    target = tmp_path / "installed"
    target.mkdir()
    (target / "publisher-certificate.sha256").write_text("a" * 64, encoding="ascii")
    helper = target / helper_name
    if case == "directory":
        helper.mkdir()
    elif case != "absent":
        helper.write_bytes(b"test-only-placeholder")
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
$target = $env:ANGERONA_CUSTODY_TARGET
$installedCustodyNames = @()
$trustedAuthorizationVerifier = Join-Path $target 'AngeronaReleaseVerifier.exe'
$script:helperProtected = $false
$script:helperSigned = $false
function Assert-ProtectedPath {
    param([string]$Path, [bool]$Directory)
    if ($Path.EndsWith($env:ANGERONA_CUSTODY_HELPER)) {
        $script:helperProtected = $true
        if ($env:ANGERONA_CUSTODY_CASE -eq 'unprotected') { throw 'unprotected helper' }
    }
}
function Assert-PublisherSignature {
    param([string]$Path, [string]$Certificate)
    if ($Path.EndsWith($env:ANGERONA_CUSTODY_HELPER)) {
        $script:helperSigned = $true
        if ($env:ANGERONA_CUSTODY_CASE -eq 'unsigned') { throw 'unsigned helper' }
    }
}
$rejected = $false
try { $null = Assert-InstalledCustody } catch { $rejected = $true }
$mustFail = $env:ANGERONA_CUSTODY_CASE -in @('directory', 'unsigned', 'unprotected')
if ($rejected -ne $mustFail) { throw 'unexpected helper custody decision' }
if ($env:ANGERONA_CUSTODY_CASE -eq 'present' -and
        (-not $helperProtected -or -not $helperSigned)) {
    throw 'present helper did not receive both custody and signature validation'
}
if ($env:ANGERONA_CUSTODY_CASE -eq 'absent' -and
        ($helperProtected -or $helperSigned)) {
    throw 'prior release without a helper was not accepted'
}
"""
    env = os.environ.copy()
    env["ANGERONA_CUSTODY_SCRIPT"] = str(ROOT / "Install-Angerona-Release.ps1")
    env["ANGERONA_CUSTODY_TARGET"] = str(target)
    env["ANGERONA_CUSTODY_CASE"] = case
    env["ANGERONA_CUSTODY_HELPER"] = helper_name
    result = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", harness],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )
    assert result.returncode == 0, result.stderr or result.stdout


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
    assert "--name AngeronaStartup" in text
    assert "src/angerona/startup.py" in text
    assert "Frozen startup helper was not created" in text
    assert '--icon (Join-Path $PWD "assets/icons/blackbox.ico")' in text
    assert text.count('--icon (Join-Path $PWD "assets/icons/angerona.ico")') == 2
    assert '--icon "assets/icons/' not in text
    assert '--add-data "assets;assets"' not in text
    assert '--add-data "modules;modules"' not in text
    assert '--add-data "$(Join-Path $PWD \'assets\');assets"' in text
    assert '--add-data "$PWD/modules:modules"' in text
    assert "release-payload-manifest.json" in text
    assert "release-payload.cat" in text
    assert "release-build-provenance.json" in text
    assert "release-payload-unsigned.cat" in prepare
    assert "release-authorization.json" not in finalizer
    assert "release-trust.json" not in finalizer
    assert text.count("id: artifact_name") == 2
    assert "tools/release_artifact_tag.py" in text


def test_local_startup_build_uses_checkout_absolute_icon() -> None:
    text = (ROOT / "build.bat").read_text(encoding="utf-8")
    assert '--icon "%~dp0assets\\icons\\angerona.ico"' in text
    assert "--name AngeronaStartup" in text
    assert "--distpath dist\\Angerona" in text
    assert "pip install pyinstaller" not in text
    assert "build_packaged_safe_start.ps1" in text
    assert text.index("AngeronaStartup.exe exit /b 1") < text.index("build_packaged_safe_start.ps1")
    assert 'AngeronaSafeStart.exe" --verify-bootstrap' in text
    assert "Build complete - start dist\\Angerona\\AngeronaSafeStart.exe" in text


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
    section = text.split("## Choose your installation", 1)[1].split("\n## ", 1)[0]

    assert "Angerona-<version>-win64.msix" in section
    assert "SHA-256" in section and "publisher" in section
    assert "no Python or terminal" in section


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
    assert "Assert-PublisherSignature $installedStartup $certificate" in text
    assert "$shortcut.TargetPath = $installedStartupPath" in text
    assert "Start-Process -FilePath $installedStartupPath" in text
    assert "Assert-PublisherSignature $installedSafeStart $certificate" in text
    assert "$authenticatedStartupPaths = @{} + $seen" in text
    assert text.index("--floor-output $nextFloor") < text.index("$authenticatedStartupPaths =")
    assert text.index("Assert-AuthenticatedStartupBinding $installedStartupPath") < text.index("$shortcut.TargetPath")
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


def test_powershell_batch_contract_launches_one_parse_only_child(monkeypatch):
    sources = [f"$value = 'source-{index}'" for index in range(13)]
    sources[4] = "Write-Output 'unexecuted $value ; & { arbitrary text }'"
    sources[8] = "$unicode = '\u2603'"
    calls = []
    monkeypatch.setitem(globals(), "trusted_powershell_path", lambda: Path("inert-powershell.exe"))

    def run(command, **kwargs):
        calls.append((command, kwargs))
        assert json.loads(kwargs["input"]) == sources
        assert kwargs["timeout"] == 30 and kwargs["text"] is True
        parser = command[-1]
        assert "::ParseInput(" in parser
        assert "Invoke-Expression" not in parser and "ScriptBlock" not in parser
        assert sources[4] not in parser  # Source is stdin JSON data, never command interpolation.
        return subprocess.CompletedProcess(command, 0, json.dumps([
            {"index": index, "errors": []} for index in range(13)
        ]), "")

    monkeypatch.setattr(subprocess, "run", run)
    assert _parse_powershell_sources(sources) == [{"index": index, "errors": []} for index in range(13)]
    assert len(calls) == 1


@pytest.mark.parametrize("bad_index", [0, 6, 12])
def test_powershell_batch_contract_preserves_all_source_error_indexes(monkeypatch, bad_index):
    sources = [f"$value = {index}" for index in range(13)]
    rows = [{"index": index, "errors": ["inert parser error"] if index == bad_index else []}
            for index in range(13)]
    monkeypatch.setitem(globals(), "trusted_powershell_path", lambda: Path("inert-powershell.exe"))
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(
        args[0], 1, json.dumps(rows), "",
    ))
    result = _parse_powershell_sources(sources)
    assert len(result) == 13 and result[bad_index]["errors"] == ["inert parser error"]


@pytest.mark.parametrize("rows,returncode", [
    ([], 0),
    ([{"index": 0, "errors": []}], 0),
    ([{"index": 0, "errors": []}, {"index": 0, "errors": []}], 0),
    ([{"index": 0, "errors": []}, {"index": True, "errors": []}], 0),
    ([{"index": 0, "errors": []}, {"index": 1, "errors": "bad"}], 0),
    ([{"index": 0, "errors": []}, {"index": 1, "errors": [1]}], 1),
    ([{"index": 0, "errors": []}, {"index": 1, "errors": ["error"]}], 0),
    ([{"index": 0, "errors": []}, {"index": 1, "errors": []}], 1),
])
def test_powershell_batch_contract_rejects_incomplete_or_ambiguous_results(monkeypatch, rows, returncode):
    monkeypatch.setitem(globals(), "trusted_powershell_path", lambda: Path("inert-powershell.exe"))
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(
        args[0], returncode, json.dumps(rows), "",
    ))
    with pytest.raises(AssertionError):
        _parse_powershell_sources(["$a = 1", "$b = 2"])


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell parser is required")
def test_powershell_batch_native_sources_remain_unexecuted(tmp_path):
    marker = tmp_path / "must-not-be-created.txt"
    path_literal = str(marker).replace("'", "''")
    sources = [
        f"[IO.File]::WriteAllText('{path_literal}', 'executed')",
        "if (",
        "throw 'must remain inert parser data'",
    ]
    rows = _parse_powershell_sources(sources)
    assert rows[0]["errors"] == [] and rows[1]["errors"]
    assert rows[2]["errors"] == [] and not marker.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell parser is required")
@pytest.mark.parametrize("source,must_fail", [
    ("$valid = 7", False),
    ("if (", True),
])
def test_powershell_batch_native_single_source_retains_whole_text(source, must_fail):
    rows = _parse_powershell_sources([source])
    assert len(rows) == 1 and rows[0]["index"] == 0
    assert bool(rows[0]["errors"]) is must_fail
