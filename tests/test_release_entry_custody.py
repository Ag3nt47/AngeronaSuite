"""Private inert release fixtures; never run installer top-level, UAC or downloads."""
from __future__ import annotations
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import subprocess
import pytest
from angerona.core.privilege import trusted_powershell_path

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ("Install-Angerona-Release.bat", "Install-Angerona-Release.ps1", "Verify-Angerona-Release.ps1")
pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell and file sharing semantics")
LOADER = r"""
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$ErrorActionPreference = 'Stop'
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
$tokens = $null; $issues = $null
$ast = [Management.Automation.Language.Parser]::ParseInput($request.source, [ref]$tokens, [ref]$issues)
if ($issues.Count) { throw ($issues | Out-String) }
foreach ($name in $request.names) {
    $found = @($ast.FindAll({ param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true))
    if ($found.Count -ne 1) { throw ('Expected one named production function: '+$name) }
    . ([scriptblock]::Create($found[0].Extent.Text))
}
$data = $request.data
& ([scriptblock]::Create($request.fixture))
"""


def _source(name: str) -> str:
    raw = (ROOT / name).read_text(encoding="utf-8")
    return raw.split(":__ANGERONA_RELEASE_BOOTSTRAP__\n", 1)[1] if name.endswith(".bat") else raw


def _functions(name: str, names: list[str], script_source: str, *, child_environment=None, **data):
    result = subprocess.run(
        [str(trusted_powershell_path()), "-NoProfile", "-NonInteractive", "-Command", LOADER],
        input=json.dumps(dict(source=_source(name), names=names, fixture=script_source, data=data)),
        capture_output=True, text=True, encoding="utf-8", timeout=30, check=False,
        env=child_environment,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    assert result.returncode == 0, result.stderr or result.stdout
    return result.stdout.lstrip("\ufeff").strip()


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("case", ["safe", "writer", "owner", "null-dacl", "ancestor-create", "leaf-create"])
def test_release_authority_acl_requires_protected_owner_and_effective_custody(source, case):
    _functions(source, ["Assert-ReleaseAuthorityAcl"], r"""
$acl = [Security.AccessControl.DirectorySecurity]::new()
$system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$users = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
$acl.SetOwner($system)
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($system, 'FullControl', 'Allow'))
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($users, 'ReadAndExecute', 'Allow'))
if ($data.case -eq 'writer') {
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($users, 'WriteAttributes', 'Allow'))
}
if ($data.case -eq 'owner') { $acl.SetOwner($users) }
if ($data.case -eq 'null-dacl') { $acl.SetSecurityDescriptorSddlForm('O:SYG:SYD:NO_ACCESS_CONTROL') }
if ($data.case -in @('ancestor-create','leaf-create')) {
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($users, 'AppendData', 'Allow'))
}
$rejected = $false
try { Assert-ReleaseAuthorityAcl $acl 'in-memory ACL fixture' ($data.case -eq 'ancestor-create') } catch { $rejected = $true }
$expected = $data.case -in @('writer','owner','null-dacl','leaf-create')
if ($rejected -ne $expected) { throw ('Unexpected custody decision for '+$data.case) }
""", case=case)


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("case", ["safe", "parent-writer", "leaf-writer", "reparse", "hardlink", "metadata-race"])
def test_release_authority_checks_every_ancestor_before_helper_execution(source, case):
    _functions(source, ["Assert-ReleaseAuthorityAcl", "Assert-ReleaseAuthorityPath"], r"""
$script:leaf = 'Q:\OS Fixture\Program Files\Tool\tool.exe'
$script:unsafeParent = 'Q:\OS Fixture'
$script:reads = @{}
$script:seen = [Collections.Generic.List[string]]::new()
function Get-Item {
    param([string]$LiteralPath, [switch]$Force, $ErrorAction)
    $script:seen.Add($LiteralPath)
    if (!$script:reads.ContainsKey($LiteralPath)) { $script:reads[$LiteralPath] = 0 }
    $script:reads[$LiteralPath]++
    $isLeaf = $LiteralPath -eq $script:leaf
    $attributes = if ($isLeaf) { [IO.FileAttributes]::Normal } else { [IO.FileAttributes]::Directory }
    if ($data.case -eq 'reparse' -and $LiteralPath -eq $script:unsafeParent) {
        $attributes = $attributes -bor [IO.FileAttributes]::ReparsePoint
    }
    $link = if ($data.case -eq 'hardlink' -and $isLeaf) { 'HardLink' } else { $null }
    $length = if ($data.case -eq 'metadata-race' -and $isLeaf -and $script:reads[$LiteralPath] -gt 1) { 18 } else { 17 }
    [pscustomobject]@{ FullName=$LiteralPath; PSIsContainer=(!$isLeaf); Attributes=$attributes
        LinkType=$link; Length=$length; LastWriteTimeUtc=[DateTime]::new(2026,1,1) }
}
function Get-Acl {
    param([string]$LiteralPath, $ErrorAction)
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $owner = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $acl.SetOwner($owner)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($owner, 'FullControl', 'Allow'))
    if (($data.case -eq 'parent-writer' -and $LiteralPath -eq $script:unsafeParent) -or
            ($data.case -eq 'leaf-writer' -and $LiteralPath -eq $script:leaf)) {
        $users = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($users, 'Modify', 'Allow'))
    }
    return $acl
}
$rejected = $false
try { Assert-ReleaseAuthorityPath $script:leaf } catch { $rejected = $true }
if ($rejected -ne ($data.case -ne 'safe')) { throw 'Unexpected helper path custody decision.' }
if ($data.case -eq 'safe' -and !$script:seen.Contains('Q:\')) { throw 'The root ancestor was not inspected.' }
""", case=case)


@pytest.mark.parametrize("source", SOURCES)
def test_release_child_environment_discards_poisoned_paths_loader_and_gh_configuration(source, tmp_path):
    # KnownFolder's default query returns empty for an absent redirected user
    # directory. Populate only this private fixture profile; retain the product's
    # refusal of genuinely unavailable folders and its native KnownFolder query.
    profile = tmp_path / "profile"
    local = profile / "AppData" / "Local"
    roaming = profile / "AppData" / "Roaming"
    local.mkdir(parents=True)
    roaming.mkdir(parents=True)
    child = dict(os.environ, USERPROFILE=str(profile), LOCALAPPDATA=str(local), APPDATA=str(roaming))
    _functions(source, ["Initialize-ReleaseChildEnvironment"], r"""
$env:ProgramFiles = 'Q:\untrusted fixture'; $env:SystemRoot = 'Q:\untrusted fixture'
$env:PSModulePath = 'Q:\untrusted fixture'; $env:GH_HOST = 'untrusted.invalid'
$env:GH_CONFIG_DIR = 'Q:\untrusted fixture'; $env:GH_TOKEN = 'inert-test-token'
$env:COR_PROFILER_PATH = 'Q:\untrusted.dll'; $env:APPDOMAIN_MANAGER_ASM = 'Inert.Fixture'
Initialize-ReleaseChildEnvironment
$expectedProgramFiles = [Environment]::GetFolderPath('ProgramFiles')
$expectedWindows = [IO.Directory]::GetParent([Environment]::SystemDirectory).FullName
if ($env:ProgramFiles -ne $expectedProgramFiles -or $env:SystemRoot -ne $expectedWindows) {
    throw 'Caller environment still selects release authority directories.'
}
foreach ($name in @('GH_HOST','GH_CONFIG_DIR','GH_TOKEN','COR_PROFILER_PATH','APPDOMAIN_MANAGER_ASM')) {
    if ($null -ne [Environment]::GetEnvironmentVariable($name, 'Process')) {
        throw ('Inherited code or endpoint control was retained: '+$name)
    }
}
if ($env:PSModulePath -ne (Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\Modules')) {
    throw 'Caller environment still selects PowerShell modules.'
}
""", child_environment=child)


def test_release_github_cli_ignores_inherited_programfiles_and_checks_custody():
    _functions("Verify-Angerona-Release.ps1", ["Get-ReleaseGitHubCli"], r"""
$env:ProgramFiles = 'Q:\untrusted fixture'
[Environment]::SetEnvironmentVariable('ProgramFiles(x86)', 'Q:\other fixture', 'Process')
$script:checked = $null
function Test-Path { param($LiteralPath, $PathType) return $true }
function Assert-ReleaseAuthorityPath { param($Path) $script:checked = $Path }
$actual = Get-ReleaseGitHubCli
$expected = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'GitHub CLI\gh.exe'
if ($actual -ne $expected -or $script:checked -ne $actual -or $actual.StartsWith('Q:\')) {
    throw 'An inherited Program Files path selected the helper or bypassed custody.'
}
function Assert-ReleaseAuthorityPath { param($Path) throw 'inert denied custody' }
$rejected = $false
try { $null = Get-ReleaseGitHubCli } catch { $rejected = $true }
if (!$rejected) { throw 'An unprotected helper was admitted.' }
""")


def _windows_argv(command: str) -> list[str]:
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    shell.CommandLineToArgvW.argtypes = (wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int))
    shell.CommandLineToArgvW.restype = ctypes.POINTER(wintypes.LPWSTR)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.LocalFree.argtypes = (wintypes.HLOCAL,)
    kernel.LocalFree.restype = wintypes.HLOCAL
    count = ctypes.c_int()
    result = shell.CommandLineToArgvW(command, ctypes.byref(count))
    assert result
    try:
        return [result[index] for index in range(count.value)]
    finally:
        assert not kernel.LocalFree(result)


def test_release_elevation_arguments_round_trip_with_os_parser():
    arguments = ["", r"Q:\Program Files\Angerona\Install-Angerona-Release.ps1",
                 r"R:\Download folder\original.zip", 'literal "quoted" value',
                 "trailing\\", "double\\\\", "& $() % inert", "Unicode \u2603"]
    encoded = _functions("Install-Angerona-Release.bat", ["ConvertTo-ReleaseProcessArgument"], r"""
$values = @($data.arguments | ForEach-Object { ConvertTo-ReleaseProcessArgument $_ })
[Console]::Write((ConvertTo-Json -InputObject $values -Compress))
""", arguments=arguments)
    quoted = json.loads(encoded)
    assert _windows_argv('fixture.exe ' + " ".join(quoted)) == ["fixture.exe", *arguments]


def test_protected_install_lease_serializes_different_callers_and_reuses_same_object(tmp_path):
    fixture = tmp_path / "private-installed-fixture"
    fixture.mkdir()
    _functions("Install-Angerona-Release.ps1", ["Open-ProtectedReleaseInstallLease"], r"""
$fixture = [IO.Path]::GetFullPath($data.fixture)
function Assert-ProtectedPath {
    param([string]$Path, [bool]$Directory)
    $full = [IO.Path]::GetFullPath($Path)
    if ($full -ne $fixture -and $full -ne (Join-Path $fixture '.release-install.lock')) {
        throw 'Fixture attempted a path outside its private tree.'
    }
}
function New-ProtectedAcl {
    param([bool]$Directory)
    # Only this new fixture file is created; no real protected ACL is changed.
    $acl = [Security.AccessControl.FileSecurity]::new()
    $owner = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl.SetOwner($owner); $acl.SetAccessRuleProtection($true,$false)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($owner, 'FullControl', 'Allow'))
    return $acl
}
$first = Open-ProtectedReleaseInstallLease $fixture
try {
    $firstIdentity = [IO.File]::GetCreationTimeUtc((Join-Path $fixture '.release-install.lock'))
    $rejected = $false
    try { $other = Open-ProtectedReleaseInstallLease $fixture; $other.Dispose() } catch { $rejected = $true }
    if (!$rejected) { throw 'A concurrent installation crossed the retained lease.' }
} finally { $first.Dispose() }
$next = Open-ProtectedReleaseInstallLease $fixture
try {
    if ([IO.File]::GetCreationTimeUtc((Join-Path $fixture '.release-install.lock')) -ne $firstIdentity) {
        throw 'The installation lease file was replaced instead of retained.'
    }
} finally { $next.Dispose() }
""", fixture=str(fixture))
    assert list(fixture.iterdir()) == [fixture / ".release-install.lock"]
    assert (fixture / ".release-install.lock").stat().st_size == 0


def test_release_floor_validation_replacement_and_startup_share_one_lease_scope():
    _functions("Install-Angerona-Release.ps1", [], r"""
$main = @($ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.TryStatementAst] })
if ($main.Count -ne 1) { throw 'Expected one top-level transaction/recovery boundary.' }
$body = $main[0].Body.Extent.Text
$open = $body.IndexOf('$installLease = Open-ProtectedReleaseInstallLease $target')
$recheck = $body.IndexOf('$publisherCertificate = Assert-InstalledCustody')
$floor = $body.IndexOf('--floor-output $nextFloor')
$replace = $body.IndexOf('Invoke-ReleasePayloadReplacement -TargetRoot $target')
$start = $body.IndexOf('Start-Process -FilePath $installedStartupPath')
if ($open -lt 0 -or $recheck -le $open -or $floor -le $recheck -or
        $replace -le $floor -or $start -le $replace -or $body.Contains('$installLease.Dispose()')) {
    throw 'The current floor or replacement/startup escaped the target-wide lease.'
}
if (!$main[0].Finally.Extent.Text.Contains('$installLease.Dispose()')) {
    throw 'The retained installation lease has no final retirement.'
}
""")


def test_release_environment_scrub_does_not_autoload_a_caller_module():
    _functions("Install-Angerona-Release.ps1", [], r"""
$node = @($ast.FindAll({ param($item)
    $item -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $item.Name -eq 'Initialize-ReleaseChildEnvironment'
}, $true))[0]
$commands = @($node.Body.FindAll({ param($item)
    $item -is [Management.Automation.Language.CommandAst]
}, $true))
if ($commands.Count -ne 0) { throw 'Environment initialization can autoload a module before scrub.' }
""")


def test_release_lease_retires_even_if_preservation_notice_fails():
    _functions("Install-Angerona-Release.ps1", [], r"""
$main = @($ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.TryStatementAst] })[0]
$recoveryState = [pscustomobject]@{DestinationMutationAttempted=$true; Phase='inert'}
$stage = 'inert-private-fixture'
$script:released = $false
$installLease = [pscustomobject]@{}
$installLease | Add-Member -MemberType ScriptMethod -Name Dispose -Value { $script:released = $true }
function Write-ReleaseRecoveryNotice { param($Message) throw 'inert warning failure' }
$failed = $false
try { & ([scriptblock]::Create('try { throw "inert transaction failure" } finally '+$main.Finally.Extent.Text)) } catch { $failed = $true }
if (!$failed -or !$script:released) { throw 'The protected lease survived a failed cleanup/notice path.' }
""")


def test_release_bootstrap_removes_appdir_shadow_before_first_expansion():
    # Structural bootstrap invariant only: no installer, cmd.exe, UAC or
    # PowerShell child is executed by this regression. An inherited __APPDIR__
    # masks cmd.exe's dynamic variable unless its last prior assignment clears it.
    prefix = (ROOT / "Install-Angerona-Release.bat").read_text(encoding="utf-8").split(
        ":__ANGERONA_RELEASE_BOOTSTRAP__", 1,
    )[0].splitlines()
    first_read = next(index for index, line in enumerate(prefix) if "%__appdir__%" in line.casefold())
    assignments = [
        (index, line.strip().casefold()) for index, line in enumerate(prefix[:first_read])
        if line.strip().casefold().startswith('set "__appdir__=')
    ]
    assert assignments and assignments[-1][1] == 'set "__appdir__="'
    assert prefix[first_read].strip().casefold() == 'set "angerona_release_system=%__appdir__%"'
    assert assignments[-1][0] > next(
        index for index, line in enumerate(prefix) if line.strip().casefold().startswith("setlocal ")
    )


@pytest.mark.parametrize("container", [False, True])
@pytest.mark.parametrize("rights", ["ReadAndExecute", "AppendData", "DeleteSubdirectoriesAndFiles", "ChangePermissions"])
def test_verification_container_allows_additive_slots_but_rejects_replacement(container, rights):
    _functions("Verify-Angerona-Release.ps1", ["Assert-ReleaseAuthorityAcl", "Assert-ReleaseStageDirectory"], r"""
function Get-Item {
    param($LiteralPath,[switch]$Force,$ErrorAction)
    [pscustomobject]@{FullName=$LiteralPath;PSIsContainer=$true;Attributes=[IO.FileAttributes]::Directory;LastWriteTimeUtc=[DateTime]::new(2026,1,1)}
}
function Get-Acl {
    param($LiteralPath,$ErrorAction)
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $users = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
    $acl.SetOwner($system)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($system,'FullControl','Allow'))
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($users,[Security.AccessControl.FileSystemRights]$data.rights,'Allow'))
    return $acl
}
$rejected = $false
try { Assert-ReleaseStageDirectory 'Q:\Known Folder' -Container:$data.container } catch { $rejected = $true }
$expected = $data.rights -ne 'ReadAndExecute' -and !($data.container -and $data.rights -eq 'AppendData')
if ($rejected -ne $expected) { throw 'Unexpected container/replacement custody decision.' }
""", container=container, rights=rights)


def test_verification_never_repairs_unsafe_existing_staging_directory():
    _functions("Verify-Angerona-Release.ps1", ["New-ReleaseStageDirectory"], r"""
function Test-Path { param($LiteralPath) return $true }
function Assert-ReleaseStageDirectory { param($Path) throw 'inert unsafe existing parent' }
function New-ProtectedAcl { param($Directory) throw 'existing parent must never be hardened' }
$failed = $false
try { New-ReleaseStageDirectory 'Q:\unsafe existing parent' } catch {
    $failed = $_.Exception.Message -eq 'inert unsafe existing parent'
}
if (!$failed) { throw 'An unsafe existing staging parent was not preserved.' }
""")


def test_retained_verification_artifact_blocks_writes_and_rename_until_retirement(tmp_path):
    source = tmp_path / "original.bin"
    target = tmp_path / "staged.exe"
    source.write_bytes(b"inert artifact, not executable")
    _functions("Verify-Angerona-Release.ps1", ["Copy-RetainedReleaseStageFile"], r"""
$fixture = [IO.Path]::GetFullPath($data.fixture)
function Assert-ReleaseStageDirectory { param($Path) if ($Path -ne $fixture) { throw 'escaped fixture' } }
function Assert-ReleaseAuthorityAcl { param($Acl,$Label,$Ancestor) }
function New-ProtectedAcl {
    param($Directory)
    $acl = [Security.AccessControl.FileSecurity]::new()
    $owner = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl.SetOwner($owner); $acl.SetAccessRuleProtection($true,$false)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($owner,'FullControl','Allow'))
    return $acl
}
$held = Copy-RetainedReleaseStageFile $data.source $data.target 1024
try {
    $writeRejected = $false; $renameRejected = $false
    try { $writer = [IO.File]::Open($data.target,'Open','Write','ReadWrite');$writer.Dispose() } catch { $writeRejected = $true }
    try { [IO.File]::Move($data.target,($data.target+'.moved')) } catch { $renameRejected = $true }
    if (!$writeRejected -or !$renameRejected) { throw 'A verified artifact could be replaced while retained.' }
    if ([IO.File]::ReadAllBytes($data.target).Length -ne $held.Length) { throw 'Concurrent verifier read was blocked.' }
} finally { $held.Dispose() }
[IO.File]::Move($data.target,($data.target+'.moved'))
""", fixture=str(tmp_path), source=str(source), target=str(target))
    assert (tmp_path / "staged.exe.moved").read_bytes() == source.read_bytes()


def test_installed_evidence_rejects_null_dacl_before_owner_or_rules_can_look_safe():
    _functions("Install-Angerona-Release.ps1", ["Assert-ProtectedAcl"], r"""
$approvedCustodySids = @('S-1-5-18','S-1-5-32-544')
$acl = [Security.AccessControl.FileSecurity]::new()
$acl.SetSecurityDescriptorSddlForm('O:SYG:SYD:NO_ACCESS_CONTROL')
$rejected = $false
try { Assert-ProtectedAcl $acl 'in-memory installed floor' } catch {
    $rejected = $_.Exception.Message -like '*NULL DACL*'
}
if (!$rejected) { throw 'A null DACL was accepted as safe installed custody.' }
""")


@pytest.mark.parametrize("fault", ["safe", "weak-parent", "redirected-parent", "weak-leaf", "traversal"])
def test_release_nested_destination_admits_every_existing_component_without_hardening(fault):
    _functions("Install-Angerona-Release.ps1", ["Assert-SafeRelativePath", "Assert-SafeReleaseDestination"], r"""
$script:checked = [Collections.Generic.List[string]]::new()
function Test-Path { param($LiteralPath) return $true }
function Assert-ProtectedPath {
    param($Path,$Directory)
    $script:checked.Add($Path)
    if (($data.fault -in @('weak-parent','redirected-parent') -and $Path -eq 'Q:\Installed\nested') -or
            ($data.fault -eq 'weak-leaf' -and $Path.EndsWith('payload.bin'))) {
        throw 'inert denied native custody'
    }
}
function Set-Acl { throw 'An existing destination was silently hardened.' }
$relative = if ($data.fault -eq 'traversal') { '../escape.bin' } else { 'nested/deeper/payload.bin' }
$rejected = $false
try { Assert-SafeReleaseDestination 'Q:\Installed' $relative } catch { $rejected = $true }
if ($rejected -ne ($data.fault -ne 'safe')) { throw 'Unexpected nested destination admission.' }
if ($data.fault -eq 'safe' -and (!$script:checked.Contains('Q:\Installed') -or
        !$script:checked.Contains('Q:\Installed\nested') -or
        !$script:checked.Contains('Q:\Installed\nested\deeper') -or
        !$script:checked.Contains('Q:\Installed\nested\deeper\payload.bin'))) {
    throw 'An existing destination component escaped custody.'
}
""", fault=fault)


def test_verifier_retains_both_files_through_validation_and_optional_launch():
    _functions("Verify-Angerona-Release.ps1", [], r"""
$main = @($ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.TryStatementAst] })[0]
$body = $main.Body.Extent.Text
$copy = $body.IndexOf('$artifactLease = Copy-RetainedReleaseStageFile')
$checksum = $body.IndexOf('$checksumLease = Copy-RetainedReleaseStageFile')
$hash = $body.IndexOf('Get-FileHash -LiteralPath $stagedArtifact')
$signature = $body.IndexOf('Get-AuthenticodeSignature -LiteralPath $stagedArtifact')
$launch = $body.IndexOf('Start-Process -FilePath $stagedArtifact')
if ($copy -lt 0 -or $checksum -le $copy -or $hash -le $checksum -or
        $signature -le $hash -or $launch -le $signature -or $body.Contains('$artifactLease.Dispose()')) {
    throw 'Release validation or launch escaped retained file custody.'
}
$cleanup = $main.Finally.Extent.Text
if ($cleanup.IndexOf('$lease.Dispose()') -lt 0 -or
        $cleanup.IndexOf('Remove-Item') -le $cleanup.IndexOf('$lease.Dispose()')) {
    throw 'Cleanup ran before verified handle retirement.'
}
""")


@pytest.mark.parametrize("name,expected,version,rejected", [
    ("Angerona-v1.15.0-win64.zip", "", "1.15.0", False),
    ("Angerona-1.15.0-win64.msix", "1.15.0", "1.15.0", False),
    ("renamed Setup.exe", "1.15.0", "1.15.0", False),
    ("Angerona-v1.14.1-win64.zip", "1.15.0", "", True),
    ("Angerona-v01.15.0-win64.zip", "", "", True),
    ("Angerona-v1.15.0-win64.zip.extra", "", "", True),
    ("unversioned.zip", "", "", True),
    ("renamed.zip", "1.15.0;untrusted", "", True),
])
def test_release_attestation_requires_an_exact_expected_tag(name, expected, version, rejected):
    _functions("Verify-Angerona-Release.ps1", ["Resolve-ReleaseVerificationVersion"], r"""
$held = $false; $version = $null
try { $version = Resolve-ReleaseVerificationVersion $data.artifact_name $data.expected } catch { $held = $true }
if ($held -ne $data.rejected) { throw 'Unexpected release version admission.' }
if (!$held -and $version -cne $data.version) { throw 'Incorrect expected tag version.' }
""", artifact_name=name, expected=expected, version=version, rejected=rejected)


@pytest.mark.parametrize("exit_code", [0, 1])
def test_release_attestation_checks_official_workflow_ref_host_and_runner(exit_code):
    _functions("Verify-Angerona-Release.ps1",
               ["Resolve-ReleaseVerificationVersion", "Assert-ReleaseBuildAttestation"], r"""
$script:calls = [Collections.Generic.List[object]]::new()
function Invoke-FixtureGh {
    $script:calls.Add(@($args))
    $global:LASTEXITCODE = [int]$data.exit_code
}
$held = $false
try { Assert-ReleaseBuildAttestation 'Invoke-FixtureGh' 'Q:\inert\selected.zip' '1.15.0' } catch { $held = $true }
if ($held -ne ($data.exit_code -ne 0)) { throw 'Failed attestation was not held.' }
$expected = @('attestation','verify','Q:\inert\selected.zip','--repo','Ag3nt47/AngeronaSuite',
    '--hostname','github.com','--signer-workflow','Ag3nt47/AngeronaSuite/.github/workflows/release.yml',
    '--source-ref','refs/tags/v1.15.0','--deny-self-hosted-runners')
if ($script:calls.Count -ne 1 -or $script:calls[0].Count -ne $expected.Count) { throw 'Unexpected verifier call shape.' }
for ($i=0; $i -lt $expected.Count; $i++) {
    if ($script:calls[0][$i] -cne $expected[$i]) { throw 'Release provenance policy argument changed.' }
}
""", exit_code=exit_code)
