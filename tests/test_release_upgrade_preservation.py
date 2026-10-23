"""Confined Windows filesystem fixtures; no complete installer entry point.

Each native fixture requires fixed PowerShell custody, exact process-handle
admission and retirement, closed-handle evidence, and a bounded durable private
receipt. Failure retains the original exception and any unproved native owner.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time

import pytest


ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows installer fixtures")
_PENDING_OWNED_CHILDREN: list[subprocess.Popen] = []
_FAILURE_STREAM_BYTES = 2048


HARNESS = r"""
$ErrorActionPreference = 'Stop'
$script:fixtureClock = [Diagnostics.Stopwatch]::StartNew()
# Fixed advisory markers only; no approval, mutation or timing authority.
function Write-FixtureStage([string]$Stage) {
    [Console]::Error.WriteLine('ANGERONA_FIXTURE_STAGE=' + $Stage)
    [Console]::Error.Flush()
    # A present clock proves the existing stage Flush returned, not process exit.
    $elapsed = ($script:fixtureClock.ElapsedMilliseconds).ToString([Globalization.CultureInfo]::InvariantCulture)
    $utc = ([DateTime]::UtcNow.ToFileTimeUtc()).ToString([Globalization.CultureInfo]::InvariantCulture)
    [Console]::Error.WriteLine('ANGERONA_FIXTURE_CLOCK=' + $Stage + '|' + $elapsed + '|' + $utc)
    [Console]::Error.Flush()
}
Write-FixtureStage 'harness-entry'
$script:initialGuardTrace = $true
$script:initialGuardTraceCount = 0
function Write-InitialGuardStage([string]$Stage) {
    if (-not $script:initialGuardTrace) { return }
    # A finite startup-only trace; never emit fixture paths or skip a guard.
    if ($script:initialGuardTraceCount -lt 64) {
        $script:initialGuardTraceCount += 1
        Write-FixtureStage ('initial-guard-' + $Stage)
    } elseif ($script:initialGuardTraceCount -eq 64) {
        $script:initialGuardTraceCount += 1
        Write-FixtureStage 'initial-guard-trace-limit'
    }
}
function Assert-LocalCanonicalFixturePath([string]$Path) {
    Write-InitialGuardStage 'normalize'
    $full = [IO.Path]::GetFullPath($Path)
    if ($Path -notmatch '^[A-Za-z]:\\' -or $Path.Contains('/') -or
            -not $Path.TrimEnd('\').Equals($full.TrimEnd('\'),
                [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Fixture paths must be normalized absolute local-drive paths.'
    }
    Write-InitialGuardStage 'components'
    foreach ($component in $full.Substring(3).Split('\')) {
        if ($component -eq '') { continue }
        if ($component -in @('.', '..') -or $component -match '[~:*?<>|"\x00-\x1f]' -or
                $component.EndsWith('.') -or $component.EndsWith(' ') -or
                $component -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)') {
            throw 'Fixture alias, device or ambiguous component refused.'
        }
    }
    Write-InitialGuardStage 'drive-info'
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($full))
    Write-InitialGuardStage 'drive-type'
    if ($drive.DriveType -notin @([IO.DriveType]::Fixed,
            [IO.DriveType]::Removable, [IO.DriveType]::Ram)) {
        throw 'Network, unknown and unsupported fixture volumes are forbidden.'
    }
    $current = $full
    # Include the fixture itself, its parents, and the drive root. Access
    # denial is an error; only a genuinely absent path component is skipped.
    while ($null -ne $current -and $current -ne '') {
        $exists = $true
        Write-InitialGuardStage 'attributes'
        try { $attributes = [IO.File]::GetAttributes($current) }
        catch [IO.FileNotFoundException] { $exists = $false }
        catch [IO.DirectoryNotFoundException] { $exists = $false }
        if ($exists) {
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Fixture reparse point refused: $current"
            }
            Write-InitialGuardStage 'get-item'
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            Write-InitialGuardStage 'link-type'
            if (($item.PSObject.Properties.Name -contains 'LinkType') -and
                    -not [string]::IsNullOrEmpty([string]$item.LinkType)) {
                throw "Fixture linked object refused: $current"
            }
            Write-InitialGuardStage 'convert-path'
            $resolved = Convert-Path -LiteralPath $current -ErrorAction Stop
            Write-InitialGuardStage 'canonical-compare'
            if (-not $resolved.TrimEnd('\').Equals($current.TrimEnd('\'),
                    [StringComparison]::OrdinalIgnoreCase)) {
                throw "Fixture resolved-path alias refused: $current"
            }
        }
        Write-InitialGuardStage 'parent-name'
        $current = [IO.Path]::GetDirectoryName($current)
    }
    Write-InitialGuardStage 'complete'
}
$fixture = $env:ANGERONA_TEST_FIXTURE
Write-FixtureStage 'initial-path-guard'
Assert-LocalCanonicalFixturePath $fixture
Write-FixtureStage 'initial-root-guard-done'
$fixture = [IO.Path]::GetFullPath($fixture)
$fixturePrefix = $fixture.TrimEnd('\') + '\'
function Assert-FixturePath([string]$Path) {
    Assert-LocalCanonicalFixturePath $Path
    $full = [IO.Path]::GetFullPath($Path)
    if (-not $full.Equals($fixture, [StringComparison]::OrdinalIgnoreCase) -and
            -not $full.StartsWith($fixturePrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Fixture operation escaped its owned root: $full"
    }
}
Write-FixtureStage 'initial-fence-guard'
Assert-FixturePath $fixture
Write-FixtureStage 'initial-fence-guard-done'
Write-FixtureStage 'initial-version-check'
if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) {
    throw 'This fixture explicitly targets Windows PowerShell 5.1.'
}
Write-FixtureStage 'initial-release-join'
$release = Join-Path $fixture 'parent-release.marker'
Write-FixtureStage 'initial-release-guard'
Assert-FixturePath $release
Write-FixtureStage 'initial-release-guard-done'
$script:initialGuardTrace = $false
$releaseWait = [Diagnostics.Stopwatch]::StartNew()
Write-FixtureStage 'parent-admission-wait'
while (-not [IO.File]::Exists($release)) {
    if ($releaseWait.Elapsed.TotalSeconds -gt 10) { throw 'Parent did not admit this exact child.' }
    [Threading.Thread]::Sleep(10)
}
Write-FixtureStage 'parent-admission-observed'
if ($env:ANGERONA_TEST_CASE -like 'confinement-*') {
    $originalFixture = $fixture
    $originalPrefix = $fixturePrefix
    $rejections = [Collections.Generic.List[string]]::new()
    if ($env:ANGERONA_TEST_CASE -eq 'confinement-paths') {
        $probes = @(
            '\\server.invalid\share\fixture', '\\?\C:\fixture',
            (Join-Path $fixture 'alias~1'),
            (Join-Path $fixture 'missing\..\escape'),
            (Join-Path ([IO.Path]::GetDirectoryName($fixture)) 'outside'))
        $probeNumber = 0
        foreach ($probe in $probes) {
            Write-FixtureStage ('confinement-probe-' + $probeNumber + '-start')
            $refused = $false
            try { Assert-FixturePath $probe } catch { $refused = $true }
            if (-not $refused) { throw "Negative path probe was admitted: $probe" }
            $rejections.Add($probe)
            Write-FixtureStage ('confinement-probe-' + $probeNumber + '-done')
            $probeNumber++
        }
    } else {
        $probeTarget = Join-Path $fixture 'probe-target'
        $probeChild = Join-Path $probeTarget 'child'
        $probeLink = Join-Path $fixture 'probe-link'
        foreach ($path in @($probeTarget, $probeChild, $probeLink)) { Assert-FixturePath $path }
        [void](Microsoft.PowerShell.Management\New-Item -ItemType Directory -Path $probeTarget)
        [void](Microsoft.PowerShell.Management\New-Item -ItemType Directory -Path $probeChild)
        $sentinel = Join-Path $probeTarget 'sentinel.bin'
        Assert-FixturePath $sentinel
        [IO.File]::WriteAllText($sentinel, 'unrelated-probe-target')
        # Intentional adversarial fixture construction, only after checking
        # both endpoints within the original owned fence. No recursive remove.
        [void](Microsoft.PowerShell.Management\New-Item -ItemType Junction `
            -Path $probeLink -Target $probeTarget)
        $probeRoot = if ($env:ANGERONA_TEST_CASE -eq 'confinement-reparse-root') {
            $probeLink
        } else { Join-Path $probeLink 'child' }
        try {
            $fixture = $probeRoot
            $fixturePrefix = $fixture.TrimEnd('\') + '\'
            foreach ($probe in @($probeRoot, (Join-Path $probeRoot 'leaf'))) {
                $refused = $false
                try { Assert-LocalCanonicalFixturePath $probe } catch { $refused = $true }
                if (-not $refused) { throw "Root/ancestor reparse probe was admitted: $probe" }
                $rejections.Add('local:' + $probe)
                $refused = $false
                try { Assert-FixturePath $probe } catch { $refused = $true }
                if (-not $refused) { throw "Fixture root/ancestor probe was admitted: $probe" }
                $rejections.Add('fixture:' + $probe)
            }
        } finally {
            $fixture = $originalFixture
            $fixturePrefix = $originalPrefix
        }
    }
    Write-FixtureStage 'confinement-result-write'
    $probeResult = Join-Path $fixture 'confinement-result.json'
    Assert-FixturePath $probeResult
    [IO.File]::WriteAllText($probeResult, ([pscustomobject]@{
        case = $env:ANGERONA_TEST_CASE
        rejections = @($rejections.ToArray())
        product_functions_loaded = $false
        recursive_removal_executed = $false
    } | ConvertTo-Json -Depth 4 -Compress))
    Write-FixtureStage 'confinement-done'
    [Environment]::Exit(0)
}
$target = Join-Path $fixture 'target'
$stage = Join-Path $target '.installing-fixture'
$payloadRoot = Join-Path $stage 'payload'
foreach ($path in @($target, $stage, $payloadRoot)) { Assert-FixturePath $path }
$recoveryState = [pscustomobject]@{
    Phase = 'pre-mutation-staging'
    DestinationMutationAttempted = $false
    Entries = [Collections.Generic.List[object]]::new()
}
$upgradeFailure = $null
$script:injections = [Collections.Generic.List[string]]::new()
$script:removals = [Collections.Generic.List[string]]::new()
$script:moves = [Collections.Generic.List[string]]::new()
$case = $env:ANGERONA_TEST_CASE
$installPaths = @('a.bin', 'b.bin', 'release-floor.json')
if ($case -eq 'duplicate-path') { $installPaths = @('a.bin', 'A.bin') }
if ($case -eq 'new-parent-create') { $installPaths = @('nested/new.bin') }
if ($case -eq 'new-destination-copy') { $installPaths = @('new.bin') }

function Stop-FixtureAtInterruption([string]$Phase) {
    $marker = Join-Path $fixture 'interruption-marker.txt'
    Assert-FixturePath $marker
    [IO.File]::WriteAllText($marker, $Phase)
    # Deliberate fresh-process abrupt exit. No finally/reconciliation runs.
    # This marker is fixture evidence, not a durable recovery journal.
    [Environment]::Exit(99)
}

# Parse the actual source. Load only these exact named function definitions,
# never the top-level trust prelude, elevation path, shortcut or app launcher.
$tokens = $null; $issues = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $env:ANGERONA_TEST_INSTALLER, [ref]$tokens, [ref]$issues)
if ($issues.Count) { throw ($issues | Out-String) }
$names = @('Assert-SafeRelativePath', 'Assert-NotReparse', 'New-ProtectedAcl',
    'Write-ReleaseRecoveryNotice', 'Invoke-ReleasePayloadReplacement')
foreach ($name in $names) {
    $found = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq $name
    }, $true))
    if ($found.Count -ne 1) { throw "Expected exactly one real function: $name" }
    Invoke-Expression $found[0].Extent.Text
}
$outer = @($ast.EndBlock.Statements | Where-Object {
    $_ -is [Management.Automation.Language.TryStatementAst]
})
if ($outer.Count -ne 1 -or $outer[0].CatchClauses.Count -ne 1 -or
        $null -eq $outer[0].Finally) {
    throw 'The exact production error/cleanup boundary could not be selected.'
}

# Override only filesystem operation boundaries for controlled fixture faults.
# Set-Acl is a no-op boundary on ordinary paths so fixtures need no elevation.
# Its injected failure tests recovery, not real ACL enforcement. Existing ACL
# policy/custody tests remain separate and unchanged.
function New-Item {
    param([string]$ItemType, [string]$Path, [switch]$Force)
    Assert-FixturePath $Path
    $created = Microsoft.PowerShell.Management\New-Item -ItemType $ItemType -Path $Path -Force:$Force
    if ($case -eq 'new-parent-create' -and $Path -eq (Join-Path $target 'nested')) {
        $script:injections.Add($case)
        throw "injected-$case"
    }
    $created
}
function Move-Item {
    param([string]$LiteralPath, [string]$Destination)
    Assert-FixturePath $LiteralPath; Assert-FixturePath $Destination
    if ($recoveryState.Entries.Count -lt 1) { throw 'Move occurred before current-entry accounting.' }
    if (-not $recoveryState.DestinationMutationAttempted) { throw 'Move occurred before retention was armed.' }
    $script:moves.Add($Destination)
    if (-not $Destination.StartsWith((Join-Path $stage 'previous') + '\',
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'An automatic rollback move was attempted without object custody.'
    }
    Microsoft.PowerShell.Management\Move-Item -LiteralPath $LiteralPath -Destination $Destination
    if ($case -eq 'crash-after-move-a' -and [IO.Path]::GetFileName($Destination) -eq 'a.bin') {
        Stop-FixtureAtInterruption $case
    }
    if ($case -eq 'move-after-a' -and [IO.Path]::GetFileName($Destination) -eq 'a.bin') {
        $script:injections.Add('move-after-a')
        throw 'injected-move-after-a'
    }
}
function Copy-Item {
    param([string]$LiteralPath, [string]$Destination)
    Assert-FixturePath $LiteralPath; Assert-FixturePath $Destination
    if ($recoveryState.Entries.Count -lt 1) { throw 'Copy occurred before current-entry accounting.' }
    if (-not $recoveryState.DestinationMutationAttempted) { throw 'Copy occurred before retention was armed.' }
    $name = [IO.Path]::GetFileName($Destination)
    if (($case -eq 'copy-before-a' -and $name -eq 'a.bin') -or
            ($case -eq 'copy-before-b' -and $name -eq 'b.bin') -or
            ($case -eq 'warning-emission' -and $name -eq 'b.bin')) {
        if ($case -eq 'warning-emission') {
            $script:injections.Add('primary-copy-before-b')
            throw 'injected-primary-copy-before-b'
        }
        $script:injections.Add($case)
        throw "injected-$case"
    }
    if ($case -eq 'copy-partial-a' -and $name -eq 'a.bin') {
        [IO.File]::WriteAllBytes($Destination, [Text.Encoding]::ASCII.GetBytes('partial-a'))
        $script:injections.Add($case)
        throw "injected-$case"
    }
    if ($case -eq 'new-destination-copy' -and $name -eq 'new.bin') {
        [IO.File]::WriteAllBytes($Destination, [Text.Encoding]::ASCII.GetBytes('partial-new'))
        $script:injections.Add($case)
        throw "injected-$case"
    }
    Microsoft.PowerShell.Management\Copy-Item -LiteralPath $LiteralPath -Destination $Destination
    if ($case -eq 'crash-after-copy-b' -and $name -eq 'b.bin') {
        Stop-FixtureAtInterruption $case
    }
    if ($case -in @('foreign-distinct-b', 'foreign-same-b') -and $name -eq 'b.bin') {
        # Move a pre-existing, separately identified foreign generation into
        # the destination. Its matching bytes in foreign-same-b grant no right
        # to delete it. The Python parent records its native file ID beforehand.
        $foreign = Join-Path $fixture 'foreign.bin'
        $removedCandidate = Join-Path $fixture 'removed-candidate-b.bin'
        Assert-FixturePath $foreign; Assert-FixturePath $removedCandidate
        [IO.File]::Move($Destination, $removedCandidate)
        [IO.File]::Move($foreign, $Destination)
        $script:injections.Add($case)
        throw "injected-$case"
    }
}
function Set-Acl {
    param([string]$LiteralPath, $AclObject)
    Assert-FixturePath $LiteralPath
    if (($case -eq 'acl-a' -and $LiteralPath -eq (Join-Path $target 'a.bin')) -or
            ($case -eq 'acl-floor' -and $LiteralPath -eq (Join-Path $target 'release-floor.json')) -or
            ($case -eq 'target-acl' -and $LiteralPath -eq $target)) {
        $script:injections.Add($case)
        throw "injected-$case"
    }
}
function Write-Warning {
    [CmdletBinding()]
    param([string]$Message)
    if ($case -eq 'warning-emission') {
        $script:injections.Add('warning-emission-failure')
        throw 'injected-warning-emission-failure'
    }
    Microsoft.PowerShell.Utility\Write-Warning -Message $Message -WarningAction Continue
}
function Remove-Item {
    param([string]$LiteralPath, [switch]$Recurse, [switch]$Force)
    Assert-FixturePath $LiteralPath
    $script:removals.Add($LiteralPath)
    if ($recoveryState.DestinationMutationAttempted) {
        throw 'Destructive cleanup was attempted after destination mutation.'
    }
    if ($LiteralPath -ne $stage) { throw 'Cleanup attempted an unexpected fixture path.' }
    if ($case -eq 'pre-mutation-cleanup-failure') {
        $script:injections.Add('secondary-cleanup-failure')
        throw 'injected-secondary-cleanup-failure'
    }
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $LiteralPath -Recurse:$Recurse -Force:$Force
}

# Execute the real replacement function plus the EXACT production catch and
# finally AST extents. Candidate authorization is deliberately not simulated.
# The prepared fixture bytes are inert, never executable.
$driver = @'
try {
    if ($case -in @('pre-mutation', 'pre-mutation-cleanup-failure')) {
        $script:injections.Add('primary-pre-mutation')
        throw 'injected-primary-pre-mutation'
    }
    Invoke-ReleasePayloadReplacement -TargetRoot $target -PayloadRoot $payloadRoot `
        -StageRoot $stage -InstallPaths $installPaths -RecoveryState $recoveryState
    Set-Acl -LiteralPath $target -AclObject (New-ProtectedAcl $true)
}
'@ + $outer[0].CatchClauses[0].Extent.Text + ' finally ' + $outer[0].Finally.Extent.Text
$caught = $null
try { Invoke-Expression $driver } catch { $caught = $_.Exception.Message }
$result = [pscustomobject]@{
    phase = $recoveryState.Phase
    mutation_attempted = $recoveryState.DestinationMutationAttempted
    entries = @($recoveryState.Entries.ToArray())
    error = $caught
    injections = @($script:injections.ToArray())
    removals = @($script:removals.ToArray())
    moves = @($script:moves.ToArray())
    startup_executed = $false
    startup_verified = $false
}
[Console]::Out.WriteLine('ANGERONA_FIXTURE_RESULT=' + ($result | ConvertTo-Json -Depth 8 -Compress))
"""


def _assert_local_canonical_path(path: Path, *, fence: Path | None = None) -> Path:
    """Refuse ancestors/aliases before even creating the fixture or script.

    This is a confined-test preflight, not an atomic filesystem capability
    against a privileged concurrent actor. PowerShell rechecks all existing
    ancestors immediately before each controlled mutation/removal boundary.
    """
    import ctypes
    from ctypes import wintypes

    text = os.fspath(path)
    if not re.match(r"^[A-Za-z]:\\", text) or text.startswith("\\") or "/" in text:
        raise ValueError("Fixture requires an absolute local-drive path")
    normalized = os.path.normpath(text)
    if os.path.normcase(text.rstrip("\\")) != os.path.normcase(normalized.rstrip("\\")):
        raise ValueError("Fixture path is not normalized")
    for part in normalized[3:].split("\\"):
        if not part:
            continue
        if (part in {".", ".."} or re.search(r'[~:*?<>|"\x00-\x1f]', part)
                or part.endswith((".", " "))
                or re.match(r"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)", part, re.I)):
            raise ValueError("Fixture alias, device or ambiguous component refused")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
    kernel32.GetDriveTypeW.restype = wintypes.UINT
    if kernel32.GetDriveTypeW(Path(normalized).anchor) not in {2, 3, 6}:
        raise ValueError("Network or unsupported fixture drive refused")
    current = Path(normalized)
    while True:
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            pass
        else:
            if (stat.S_ISLNK(info.st_mode)
                    or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT):
                raise ValueError("Fixture reparse ancestor refused")
            if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise ValueError("Fixture requires ordinary filesystem objects")
            if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
                raise ValueError("Fixture hard-linked file refused")
            resolved = current.resolve(strict=True)
            if os.path.normcase(str(resolved)) != os.path.normcase(str(current)):
                raise ValueError("Fixture canonical-path alias refused")
        parent = current.parent
        if parent == current:
            break
        current = parent
    if fence is not None:
        expected = os.path.normcase(str(fence))
        if os.path.normcase(os.path.commonpath([str(fence), normalized])) != expected:
            raise ValueError("Fixture path escapes its owned fence")
    return Path(normalized)


def _native_api():
    import ctypes
    from ctypes import wintypes

    api = ctypes.WinDLL("kernel32", use_last_error=True)
    signatures = {
        "GetSystemDirectoryW": ([wintypes.LPWSTR, wintypes.UINT], wintypes.UINT),
        "GetProcessId": ([wintypes.HANDLE], wintypes.DWORD),
        "GetProcessTimes": ([wintypes.HANDLE, ctypes.POINTER(wintypes.FILETIME),
                             ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME),
                             ctypes.POINTER(wintypes.FILETIME)], wintypes.BOOL),
        "QueryFullProcessImageNameW": ([wintypes.HANDLE, wintypes.DWORD,
                                        wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL),
        "WaitForSingleObject": ([wintypes.HANDLE, wintypes.DWORD], wintypes.DWORD),
        "GetExitCodeProcess": ([wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL),
    }
    for name, (arguments, result_type) in signatures.items():
        function = getattr(api, name)
        function.argtypes = arguments
        function.restype = result_type
    return ctypes, wintypes, api


def _trusted_ps5() -> tuple[Path, str]:
    ctypes, _, api = _native_api()
    buffer = ctypes.create_unicode_buffer(32768)
    count = api.GetSystemDirectoryW(buffer, len(buffer))
    if not 0 < count < len(buffer):
        raise ctypes.WinError(ctypes.get_last_error())
    # Windows servicing may hard-link a genuine system executable to WinSxS.
    # Keep that runtime custody separate from fixture-data nlink==1 policy:
    # validate its directory ancestry strictly, then the fixed leaf's ordinary
    # type, non-reparse identity, canonical path and pinned bytes independently.
    directory = _assert_local_canonical_path(Path(buffer.value) / "WindowsPowerShell" / "v1.0")
    executable = directory / "powershell.exe"
    metadata = executable.lstat()
    if (not stat.S_ISREG(metadata.st_mode)
            or getattr(metadata, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
            or os.path.normcase(str(executable.resolve(strict=True))) != os.path.normcase(str(executable))):
        raise ValueError("Fixed Windows PowerShell executable custody is invalid")
    if not executable.is_file() or not (executable.parent / "Modules").is_dir():
        raise ValueError("Fixed trusted Windows PowerShell 5.1 installation is missing")
    _assert_local_canonical_path(executable.parent / "Modules")
    return executable, hashlib.sha256(executable.read_bytes()).hexdigest()


def _owned_child_identity(process: subprocess.Popen, executable: Path, proof: dict | None = None) -> dict:
    ctypes, wintypes, api = _native_api()
    proof = {} if proof is None else proof
    proof["pid"] = process.pid
    handle = wintypes.HANDLE(int(process._handle))
    proof["handle_pid"] = api.GetProcessId(handle)
    if proof["handle_pid"] != process.pid:
        raise AssertionError("Owned PowerShell handle/PID mismatch")
    times = [wintypes.FILETIME() for _ in range(4)]
    if not api.GetProcessTimes(handle, *(ctypes.byref(value) for value in times)):
        raise ctypes.WinError(ctypes.get_last_error())
    birth = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
    proof["birth_filetime"] = birth
    size = wintypes.DWORD(32768)
    image = ctypes.create_unicode_buffer(size.value)
    if not api.QueryFullProcessImageNameW(handle, 0, image, ctypes.byref(size)):
        raise ctypes.WinError(ctypes.get_last_error())
    proof["image"] = image.value
    if os.path.normcase(image.value) != os.path.normcase(str(executable)):
        raise AssertionError("Owned child image differs from fixed PowerShell executable")
    proof["admission_wait_status"] = api.WaitForSingleObject(handle, 0)
    if birth <= 0 or proof["admission_wait_status"] != 258:
        raise AssertionError("Owned child was not proven live before fixture admission")
    return proof



def _bounded_native_error(error: BaseException) -> str:
    try:
        detail = str(error)[:1024]
    except BaseException:
        detail = "UNPROVED"
    return f"{type(error).__name__}: {detail}"


def _write_native_retirement(fixture: Path, proof: dict) -> None:
    raw = json.dumps(proof, sort_keys=True, ensure_ascii=True).encode("utf-8")
    if len(raw) > 64 * 1024:
        raise AssertionError("Private native retirement receipt exceeded its bound")
    _assert_local_canonical_path(fixture)
    evidence = fixture / "native-retirement.json"
    _assert_local_canonical_path(evidence, fence=fixture)
    with evidence.open("xb") as receipt:
        written = receipt.write(raw)
        if written != len(raw):
            raise OSError("Private native retirement receipt was incomplete")
        receipt.flush()
        os.fsync(receipt.fileno())
    _assert_local_canonical_path(evidence, fence=fixture)


def _advisory_utc_filetime() -> int | None:
    """Optional diagnostic wall clock; never interrupt an owned cleanup."""
    try:
        nanoseconds = time.time_ns()
        if type(nanoseconds) is not int or nanoseconds < 0:
            return None
        filetime = nanoseconds // 100 + 116444736000000000
        return filetime if filetime <= 9_999_999_999_999_999_999 else None
    except BaseException:
        return None


def _retained_fixture_clocks(text: str) -> dict:
    """Parse bounded stream-tail evidence; never infer complete history."""
    rows, malformed = [], 0
    for line in text.splitlines():
        if not line.startswith("ANGERONA_FIXTURE_CLOCK="):
            continue
        match = re.fullmatch(
            r"ANGERONA_FIXTURE_CLOCK=([a-z0-9-]{1,80})\|([0-9]{1,8})\|([0-9]{1,19})", line,
        )
        if match is None:
            malformed += 1
            continue
        rows.append({"stage": match[1], "elapsed_ms": int(match[2]),
                     "utc_filetime_100ns": int(match[3])})
    return {
        "history": "retained stream tail only; earlier samples and gaps unproved",
        "parsed_retained_samples": len(rows), "malformed_retained_samples": malformed,
        "first_retained": rows[0] if rows else None,
        "last_retained": rows[-1] if rows else None,
        "retained_elapsed_nondecreasing": all(a["elapsed_ms"] <= b["elapsed_ms"]
            for a, b in zip(rows, rows[1:])) if len(rows) > 1 else None,
        "retained_wall_nondecreasing": all(a["utc_filetime_100ns"] <= b["utc_filetime_100ns"]
            for a, b in zip(rows, rows[1:])) if len(rows) > 1 else None,
        "authority": "advisory only; no clock stability or process-exit proof",
    }


def _capture_failure_stream(stream, *, limit: int = _FAILURE_STREAM_BYTES) -> dict:
    """Read only a bounded tail of our own regular temporary file."""
    if stream is None:
        return {"state": "not_created", "retained_bytes": 0, "truncated": False}
    try:
        stream.seek(0, os.SEEK_END)
        total = stream.tell()
        if type(total) is not int or total < 0:
            raise ValueError("Diagnostic stream length is invalid")
        stream.seek(max(0, total - limit))
        raw = stream.read(limit + 1)
        if not isinstance(raw, bytes):
            raise TypeError("Diagnostic stream did not return bytes")
        grew = len(raw) > limit
        raw = raw[:limit]
        text = raw.decode("utf-8", "replace")
        stages = re.findall(r"(?m)^ANGERONA_FIXTURE_STAGE=([a-z0-9-]{1,80})[ \t\r]*$", text)
        return {
            "state": "captured", "observed_total_bytes": total, "retained_bytes": len(raw),
            "limit_bytes": limit, "truncated": total > len(raw) or grew,
            "grew_during_read": grew, "sha256": hashlib.sha256(raw).hexdigest(),
            "encoding": "utf-8-replace", "text": text,
            "last_advisory_stage": stages[-1] if stages else None,
            "retained_clocks": _retained_fixture_clocks(text),
        }
    except BaseException as error:
        return {"state": "unavailable", "retained_bytes": 0, "limit_bytes": limit,
                "read_error": _bounded_native_error(error), "truncated": "UNPROVED"}


def _surface_failure_evidence(primary: BaseException, proof: dict, fixture: Path) -> None:
    """Expose bounded fixture-only evidence even when CI drops pytest temp files."""
    try:
        capture = proof.get("failure_capture", {})
        summary = {
            "kind": "angerona.owned-ps5-failure.v1", "failure_phase": proof["failure_phase"],
            "primary_error": _bounded_native_error(primary)[:256], "elapsed_seconds": proof["elapsed_seconds"],
            "native_execution_wait_seconds": proof["native_execution_wait_seconds"],
            "parent_clock": proof.get("parent_clock", {}),
            "retirement_proven": proof["retirement_proven"], "wait_status": proof["wait_status"],
            "native_exit_after_cleanup": proof["native_exit"],
            "owned_termination_requested": proof["owned_termination_requested"],
            "closed_handles": proof["closed_handles"],
            "receipt": str(fixture / "native-retirement.json")[-512:],
            "receipt_error": _bounded_native_error(primary.angerona_receipt_error)[:256]
                             if hasattr(primary, "angerona_receipt_error") else None,
            "capture": {},
            "advisory_only": True, "original_timeout_cause": "UNKNOWN",
        }
        for name in ("stdout", "stderr"):
            row = capture.get(name, {})
            summary["capture"][name] = {key: row.get(key) for key in (
                "state", "observed_total_bytes", "retained_bytes", "limit_bytes",
                "truncated", "last_advisory_stage", "retained_clocks")}
            summary["capture"][name]["text_tail"] = row.get("text", "")[-256:]
            summary["capture"][name]["read_error"] = row.get("read_error", "")[:256]
        note = "ANGERONA_OWNED_PS5_FAILURE=" + json.dumps(summary, sort_keys=True, ensure_ascii=True)
        add_note = getattr(primary, "add_note", None)
        if callable(add_note):
            add_note(note)
        else:  # Python 3.10 has no BaseException.add_note.
            print(note, file=sys.stderr, flush=True)
    except BaseException as error:
        primary.angerona_diagnostic_note_error = error


def _run_owned_ps5(command: list[str], environment: dict[str, str], tmp_path: Path,
                   fixture: Path, executable_sha256: str) -> subprocess.CompletedProcess[str]:
    """Capture the first failure before independent native/stream cleanup.

    The actual Popen owner remains retained whenever native retirement or its
    process-handle closure is unproved. Every created stream receives its own
    close attempt before the bounded durable receipt and any explicit rethrow.
    """
    started = time.monotonic()
    started_utc = _advisory_utc_filetime()
    execution_wait_started = None
    execution_wait_utc = None
    executable = Path(command[0])
    _assert_local_canonical_path(tmp_path)
    release = fixture / "parent-release.marker"
    _assert_local_canonical_path(release, fence=fixture)
    output = errors = process = None
    primary: BaseException | None = None
    phase = "stdout_stream_creation"
    failure_phase = "none"
    proof: dict = {
        "schema": "angerona.private-native-retirement.v1",
        "pid": "UNPROVED", "handle_pid": "UNPROVED",
        "birth_filetime": "UNPROVED", "image": "UNPROVED",
        "admission_wait_status": "UNPROVED", "admission_state": "not_attempted",
        "admission_completed": False, "wait_status": "UNPROVED",
        "retired_handle_pid": "UNPROVED", "retired_birth_filetime": "UNPROVED",
        "native_exit": "UNPROVED", "popen_exit": "UNPROVED",
        "executable_sha256": "UNPROVED", "handle_closed": "UNPROVED",
        "stdio_closed": "UNPROVED", "spawn_attempted": False,
        "owned_termination_requested": False,
        "streams_created": {"stdout": False, "stderr": False},
        "stream_closed": {"stdout": "UNPROVED", "stderr": "UNPROVED"},
    }
    retirement_errors: list[str] = []
    stream_close_errors: list[str] = []
    retired, closed = False, False
    stdout, stderr = "", ""
    try:
        output = tempfile.TemporaryFile(dir=tmp_path)
        proof["streams_created"]["stdout"] = True
        phase = "stderr_stream_creation"
        errors = tempfile.TemporaryFile(dir=tmp_path)
        proof["streams_created"]["stderr"] = True
        phase = "native_spawn"
        proof["spawn_attempted"] = True
        process = subprocess.Popen(
            command, cwd=tmp_path, env=environment, stdout=output, stderr=errors,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        proof["pid"] = process.pid
        phase = "admission_identity"
        _owned_child_identity(process, executable, proof)
        phase = "admission_executable_bytes"
        current_sha = hashlib.sha256(executable.read_bytes()).hexdigest()
        proof["executable_sha256"] = current_sha
        if current_sha != executable_sha256:
            raise AssertionError("PowerShell executable changed before fixture admission")
        phase = "admission_marker"
        _assert_local_canonical_path(release, fence=fixture)
        proof["admission_state"] = "UNPROVED"
        with release.open("x", encoding="ascii") as marker:
            proof["admission_state"] = "marker_created"
            marker.write("admitted-owned-process")
        proof.update(admission_state="admitted", admission_completed=True)
        phase = "native_execution_wait"
        execution_wait_started = time.monotonic()
        execution_wait_utc = _advisory_utc_filetime()
        process.wait(timeout=45)
    except BaseException as error:
        primary, failure_phase = error, phase
    wait_finished_utc = _advisory_utc_filetime() if execution_wait_started is not None else None
    execution_wait_seconds = (max(0.0, time.monotonic() - execution_wait_started)
                              if execution_wait_started is not None else None)
    if process is not None:
        try:
            if process.poll() is None:
                proof["owned_termination_requested"] = True
                process.kill()  # Only this retained Popen/native handle.
                process.wait(timeout=10)
            proof["popen_exit"] = process.returncode
            ctypes, wintypes, api = _native_api()
            handle = wintypes.HANDLE(int(process._handle))
            status = api.WaitForSingleObject(handle, 0)
            proof["wait_status"] = status
            exit_code = wintypes.DWORD()
            if status != 0 or not api.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                raise AssertionError("Owned PowerShell retirement was not proven")
            proof["native_exit"] = exit_code.value
            proof["retired_handle_pid"] = api.GetProcessId(handle)
            if proof["retired_handle_pid"] != process.pid:
                raise AssertionError("Owned handle identity changed at retirement")
            times = [wintypes.FILETIME() for _ in range(4)]
            if not api.GetProcessTimes(handle, *(ctypes.byref(value) for value in times)):
                raise ctypes.WinError(ctypes.get_last_error())
            retired_birth = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
            proof["retired_birth_filetime"] = retired_birth
            if isinstance(proof["birth_filetime"], int) and retired_birth != proof["birth_filetime"]:
                raise AssertionError("Owned generation changed at retirement")
            if exit_code.value != process.returncode:
                raise AssertionError("Native PowerShell exit disagrees with Popen")
            current_sha = hashlib.sha256(executable.read_bytes()).hexdigest()
            proof["executable_sha256"] = current_sha
            if current_sha != executable_sha256:
                raise AssertionError("PowerShell executable changed during fixture execution")
            retired = True
        except BaseException as secondary:
            retirement_errors.append("retirement: " + _bounded_native_error(secondary))
        if retired:
            try:
                process._handle.Close()
                proof["handle_closed"] = True
                closed = True
            except BaseException as secondary:
                retirement_errors.append("process_handle_close: " + _bounded_native_error(secondary))
        if not retired or not closed:
            if not any(owner is process for owner in _PENDING_OWNED_CHILDREN):
                _PENDING_OWNED_CHILDREN.append(process)
    if primary is None and retirement_errors:
        primary = AssertionError({"retirement_errors": retirement_errors, "owned_child": proof})
        failure_phase = "native_retirement_or_handle_close"
    if primary is None:
        try:
            output.seek(0)
            errors.seek(0)
            stdout = output.read().decode("utf-8", "replace")
            stderr = errors.read().decode("utf-8", "replace")
        except BaseException as error:
            primary, failure_phase = error, "captured_stream_read"
    if primary is not None:
        proof["failure_capture"] = {
            "diagnostic_only": True, "captured_after_retirement_attempt": True,
            "writer_retirement_proven": retired,
            "stdout": _capture_failure_stream(output),
            "stderr": _capture_failure_stream(errors),
        }
    # Each owner is closed independently. No context-manager unwinding can
    # replace a captured creation/spawn/admission/wait/read failure.
    for name, stream in (("stdout", output), ("stderr", errors)):
        if stream is None:
            continue
        try:
            stream.close()
            proof["stream_closed"][name] = True
        except BaseException as secondary:
            stream_close_errors.append(name + ": " + _bounded_native_error(secondary))
            if primary is None:
                primary, failure_phase = secondary, name + "_stream_close"
    if all(proof["streams_created"].values()) and all(
        value is True for value in proof["stream_closed"].values()
    ):
        proof["stdio_closed"] = True
    proof.update(
        spawned=True if process is not None else ("UNPROVED" if proof["spawn_attempted"] else False),
        popen_owner_created=process is not None, retirement_proven=retired,
        owner_retained=process is not None and any(owner is process for owner in _PENDING_OWNED_CHILDREN),
        failure_phase=failure_phase, retirement_errors=list(retirement_errors),
        stream_close_errors=list(stream_close_errors),
        primary_error=_bounded_native_error(primary) if primary is not None else "none",
        elapsed_seconds=max(0.0, time.monotonic() - started),
        native_execution_wait_seconds=execution_wait_seconds,
        parent_clock={
            "utc_unit": "Windows FILETIME 100ns since 1601 UTC; advisory wall clock",
            "run_start": started_utc, "wait_start": execution_wait_utc,
            "wait_finished_before_cleanup": wait_finished_utc,
            "wall_samples_available": all(value is not None for value in
                (started_utc, execution_wait_utc, wait_finished_utc)),
            "wall_minus_monotonic_seconds":
                (wait_finished_utc - execution_wait_utc) / 10_000_000 - execution_wait_seconds
                if execution_wait_utc is not None and wait_finished_utc is not None else None,
            "stability": "UNPROVED; samples do not establish absence of clock jumps",
        },
        closed_handles={"process": proof["handle_closed"], "stdio": proof["stdio_closed"]},
    )
    try:
        _write_native_retirement(fixture, proof)
    except BaseException as receipt_error:
        if primary is None:
            primary = receipt_error
        else:
            primary.angerona_receipt_error = receipt_error
    if primary is not None:
        primary.angerona_retirement_errors = retirement_errors
        primary.angerona_stream_close_errors = stream_close_errors
        primary.angerona_owned_child = proof
        primary.angerona_failure_capture = proof.get("failure_capture", {})
        _surface_failure_evidence(primary, proof, fixture)
        raise primary
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)



@pytest.fixture
def inert_owned_ps5(tmp_path: Path, monkeypatch):
    """Runner control: no process launch or installer; child observations are inert."""
    import ctypes
    from ctypes import wintypes
    from types import SimpleNamespace

    fixture = tmp_path / "inert-runner-fixture"
    fixture.mkdir()
    executable = tmp_path / "inert-powershell.exe"
    executable.write_bytes(b"inert executable custody control")
    state = SimpleNamespace(close_error=None, calls=[])

    class Handle:
        closed = False

        def __int__(self):
            return 0xC0DE

        def Close(self):
            state.calls.append("Close")
            if state.close_error is not None:
                raise state.close_error
            self.closed = True

    class Process:
        pid = 424242
        returncode = None
        _handle = Handle()

        def poll(self):
            return self.returncode

        def kill(self):
            state.calls.append("kill")

        def wait(self, timeout):
            state.calls.append(("wait", timeout))
            self.returncode = 0
            return 0

    process = Process()

    class API:
        @staticmethod
        def GetProcessId(_handle):
            return process.pid

        @staticmethod
        def GetProcessTimes(_handle, created, _exited, _kernel, _user):
            created._obj.dwLowDateTime = 123456
            created._obj.dwHighDateTime = 0
            return True

        @staticmethod
        def QueryFullProcessImageNameW(_handle, _flags, image, size):
            image.value = str(executable)
            size._obj.value = len(image.value)
            return True

        @staticmethod
        def WaitForSingleObject(_handle, _timeout):
            return 258 if process.returncode is None else 0

        @staticmethod
        def GetExitCodeProcess(_handle, value):
            value._obj.value = process.returncode
            return True

    def popen(*_args, **_kwargs):
        state.calls.append("Popen")
        return process

    before = tuple(_PENDING_OWNED_CHILDREN)
    monkeypatch.setattr(subprocess, "Popen", popen)
    monkeypatch.setattr(__import__(__name__, fromlist=["_native_api"]), "_native_api",
                        lambda: (ctypes, wintypes, API()))
    yield SimpleNamespace(
        fixture=fixture, executable=executable, process=process, state=state,
        command=[str(executable)], digest=hashlib.sha256(executable.read_bytes()).hexdigest(),
    )
    # Only this pure-Python fake owner is retired by fixture bookkeeping.
    # Real or foreign pending owners are never discarded by this control.
    _PENDING_OWNED_CHILDREN[:] = [owner for owner in _PENDING_OWNED_CHILDREN if owner is not process]
    assert len(_PENDING_OWNED_CHILDREN) == len(before)
    assert all(actual is expected for actual, expected in zip(_PENDING_OWNED_CHILDREN, before))


def test_failed_admission_persists_retirement_before_preserving_primary(
    tmp_path: Path, monkeypatch, inert_owned_ps5,
) -> None:
    control = inert_owned_ps5
    primary = RuntimeError("inert admission refused")
    original_identity = _owned_child_identity

    def refuse(process, executable, proof=None):
        observed = original_identity(process, executable)
        if proof is not None:
            proof.update(observed)
        raise primary

    monkeypatch.setattr(__import__(__name__, fromlist=["_owned_child_identity"]),
                        "_owned_child_identity", refuse)
    with pytest.raises(RuntimeError) as caught:
        _run_owned_ps5(control.command, {}, tmp_path, control.fixture, control.digest)
    assert caught.value is primary
    proof = json.loads((control.fixture / "native-retirement.json").read_text())
    assert proof["pid"] == control.process.pid and proof["birth_filetime"] == 123456
    assert proof["image"] == str(control.executable)
    assert proof["admission_completed"] is False and proof["admission_state"] == "not_attempted"
    assert proof["wait_status"] == 0 and proof["native_exit"] == 0
    assert proof["retirement_proven"] is True and proof["handle_closed"] is True
    assert proof["closed_handles"] == {"process": True, "stdio": True}
    assert proof["failure_phase"] == "admission_identity"
    assert not (control.fixture / "parent-release.marker").exists()
    assert control.process._handle.closed and ("wait", 10) in control.state.calls
    assert not any(owner is control.process for owner in _PENDING_OWNED_CHILDREN)


@pytest.mark.parametrize("admission_failure", [True, False])
def test_receipt_failure_cannot_report_success_or_replace_primary_and_keeps_unclosed_owner(
    tmp_path: Path, monkeypatch, inert_owned_ps5, admission_failure: bool,
) -> None:
    control = inert_owned_ps5
    primary = RuntimeError("inert admission refused")
    persistence_error = OSError("inert receipt persistence refused")
    original_identity = _owned_child_identity

    def identity(process, executable, proof=None):
        result = original_identity(process, executable)
        if proof is not None:
            proof.update(result)
        if admission_failure:
            raise primary
        return result

    def fail_receipt(_fixture, _proof):
        raise persistence_error

    module = __import__(__name__, fromlist=["_native_api"])
    monkeypatch.setattr(module, "_owned_child_identity", identity)
    monkeypatch.setattr(module, "_write_native_retirement", fail_receipt, raising=False)
    if admission_failure:
        control.state.close_error = OSError("inert process handle close refused")
    with pytest.raises(RuntimeError if admission_failure else OSError) as caught:
        _run_owned_ps5(control.command, {}, tmp_path, control.fixture, control.digest)
    if admission_failure:
        assert caught.value is primary
        assert primary.angerona_receipt_error is persistence_error
        assert primary.angerona_retirement_errors
        assert primary.angerona_owned_child["handle_closed"] == "UNPROVED"
        assert primary.angerona_owned_child["retirement_proven"] is True
        assert any(owner is control.process for owner in _PENDING_OWNED_CHILDREN)
        assert not control.process._handle.closed
    else:
        assert caught.value is persistence_error
        assert persistence_error.angerona_owned_child["admission_completed"] is True
        assert persistence_error.angerona_owned_child["handle_closed"] is True
        assert control.process._handle.closed and ("wait", 45) in control.state.calls
        assert not any(owner is control.process for owner in _PENDING_OWNED_CHILDREN)
    assert not (control.fixture / "native-retirement.json").exists()



@pytest.mark.parametrize("failure", ["second-stream", "spawn", "read"])
def test_creation_spawn_and_read_primary_survives_independent_stream_close_failure(
    tmp_path: Path, monkeypatch, inert_owned_ps5, failure: str,
) -> None:
    control = inert_owned_ps5
    primary = RuntimeError("inert " + failure + " failure")
    close_error = OSError("inert stdout close failure")
    created, close_calls = [], []
    original_popen = subprocess.Popen

    class Stream:
        def __init__(self, name):
            self.name = name

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            self.close()

        def seek(self, offset):
            assert offset == 0

        def read(self):
            if failure == "read" and self.name == "stdout":
                raise primary
            return b""

        def close(self):
            close_calls.append(self.name)
            if self.name == "stdout":
                raise close_error

    def temporary_file(*, dir):
        assert dir == tmp_path
        if created and failure == "second-stream":
            raise primary
        stream = Stream("stdout" if not created else "stderr")
        created.append(stream)
        return stream

    def popen(*args, **kwargs):
        if failure == "spawn":
            raise primary
        return original_popen(*args, **kwargs)

    monkeypatch.setattr(tempfile, "TemporaryFile", temporary_file)
    monkeypatch.setattr(subprocess, "Popen", popen)
    with pytest.raises(RuntimeError) as caught:
        _run_owned_ps5(control.command, {}, tmp_path, control.fixture, control.digest)
    assert caught.value is primary
    proof = json.loads((control.fixture / "native-retirement.json").read_text())
    assert proof["failure_phase"] == {
        "second-stream": "stderr_stream_creation",
        "spawn": "native_spawn", "read": "captured_stream_read",
    }[failure]
    assert sorted(close_calls) == sorted(stream.name for stream in created)
    assert close_calls.count("stdout") == 1
    assert proof["stream_closed"]["stdout"] == "UNPROVED"
    assert proof["stdio_closed"] == "UNPROVED"
    assert proof["stream_close_errors"] == primary.angerona_stream_close_errors
    assert len(proof["stream_close_errors"]) == 1
    assert proof["stream_close_errors"][0].startswith("stdout: OSError:")
    if failure == "second-stream":
        assert proof["streams_created"] == {"stdout": True, "stderr": False}
        assert proof["spawn_attempted"] is False and proof["spawned"] is False
    else:
        assert close_calls.count("stderr") == 1
        assert proof["streams_created"] == {"stdout": True, "stderr": True}
        assert proof["stream_closed"]["stderr"] is True
        assert proof["spawn_attempted"] is True
    if failure == "read":
        assert proof["popen_owner_created"] is True and proof["spawned"] is True
        assert proof["pid"] == control.process.pid and proof["birth_filetime"] == 123456
        assert proof["wait_status"] == 0 and proof["native_exit"] == 0
        assert proof["retirement_proven"] is True and proof["handle_closed"] is True
        assert control.process._handle.closed and ("wait", 45) in control.state.calls
    else:
        assert proof["popen_owner_created"] is False
        assert proof["pid"] == "UNPROVED" and proof["native_exit"] == "UNPROVED"
        assert proof["retirement_proven"] is False and proof["handle_closed"] == "UNPROVED"
        assert control.state.calls == []
        if failure == "spawn":
            assert proof["spawned"] == "UNPROVED"
    assert not any(owner is control.process for owner in _PENDING_OWNED_CHILDREN)



def _fixture(tmp_path: Path, case: str) -> tuple[Path, dict[str, bytes], dict[str, int], int]:
    tmp_path = _assert_local_canonical_path(tmp_path)
    if not tmp_path.is_dir():
        raise ValueError("Fixture parent does not exist")
    fixture = tmp_path / "fixture"
    target = fixture / "target"
    payload = target / ".installing-fixture" / "payload"
    _assert_local_canonical_path(payload, fence=tmp_path)
    payload.mkdir(parents=True)
    _assert_local_canonical_path(payload, fence=fixture)
    old = {"a.bin": b"old-a", "b.bin": b"old-b", "release-floor.json": b'{"floor":1}'}
    new = {"a.bin": b"new-a", "b.bin": b"new-b", "release-floor.json": b'{"floor":2}'}
    ids: dict[str, int] = {}
    for name, value in old.items():
        _assert_local_canonical_path(target / name, fence=fixture)
        (target / name).write_bytes(value)
        ids[name] = (target / name).stat().st_ino
        if ids[name] <= 0:
            raise ValueError("Fixture original lacks a usable native file identity")
        _assert_local_canonical_path(payload / name, fence=fixture)
        (payload / name).write_bytes(new[name])
    _assert_local_canonical_path(payload / "new.bin", fence=fixture)
    (payload / "new.bin").write_bytes(b"new-only")
    _assert_local_canonical_path(payload / "nested", fence=fixture)
    (payload / "nested").mkdir()
    _assert_local_canonical_path(payload / "nested" / "new.bin", fence=fixture)
    (payload / "nested" / "new.bin").write_bytes(b"new-nested")
    _assert_local_canonical_path(fixture / "sibling", fence=fixture)
    (fixture / "sibling").mkdir()
    _assert_local_canonical_path(fixture / "sibling" / "sentinel.bin", fence=fixture)
    (fixture / "sibling" / "sentinel.bin").write_bytes(b"unrelated-sentinel")
    foreign = fixture / "foreign.bin"
    _assert_local_canonical_path(foreign, fence=fixture)
    foreign.write_bytes(new["b.bin"] if case == "foreign-same-b" else b"foreign-b")
    if foreign.stat().st_ino <= 0:
        raise ValueError("Fixture foreign generation lacks a usable native file identity")
    return fixture, old, ids, foreign.stat().st_ino


def _run_process(
    tmp_path: Path, case: str,
) -> tuple[subprocess.CompletedProcess[str], Path, dict[str, bytes], dict[str, int], int]:
    fixture, old, ids, foreign_id = _fixture(tmp_path, case)
    powershell, executable_sha256 = _trusted_ps5()
    environment = dict(
        os.environ,
        TEMP=str(tmp_path),
        TMP=str(tmp_path),
        ANGERONA_TEST_FIXTURE=str(fixture),
        ANGERONA_TEST_INSTALLER=str(ROOT / "Install-Angerona-Release.ps1"),
        ANGERONA_TEST_CASE=case,
    )
    # A PS7 parent can supply an incompatible PSModulePath to PS5. Restrict
    # the child to its fixed built-in module directory and explicit PATH.
    for name in tuple(environment):
        if name.casefold() in {"psmodulepath", "psmoduleanalysiscachepath", "path"}:
            del environment[name]
    environment["PSModulePath"] = str(powershell.parent / "Modules")
    environment["PATH"] = os.pathsep.join([str(powershell.parent), str(powershell.parents[2])])
    module_cache = _assert_local_canonical_path(tmp_path / "ps-module-analysis.cache", fence=tmp_path)
    environment["PSModuleAnalysisCachePath"] = str(module_cache)
    script = tmp_path / "harness.ps1"
    _assert_local_canonical_path(script, fence=tmp_path)
    script.write_text(HARNESS, encoding="utf-8")
    result = _run_owned_ps5(
        [str(powershell), "-NoLogo", "-NoProfile", "-NonInteractive",
         "-ExecutionPolicy", "RemoteSigned", "-File", str(script)],
        environment, tmp_path, fixture, executable_sha256,
    )
    return result, fixture, old, ids, foreign_id


def _run(tmp_path: Path, case: str) -> tuple[dict, Path, dict[str, bytes], dict[str, int], int]:
    result, fixture, old, ids, foreign_id = _run_process(tmp_path, case)
    assert result.returncode == 0, result.stdout + result.stderr
    rows = [line.removeprefix("ANGERONA_FIXTURE_RESULT=") for line in result.stdout.splitlines()
            if line.startswith("ANGERONA_FIXTURE_RESULT=")]
    assert len(rows) == 1, result.stdout + result.stderr
    row = json.loads(rows[0])
    assert (fixture / "sibling" / "sentinel.bin").read_bytes() == b"unrelated-sentinel"
    assert row["startup_executed"] is False and row["startup_verified"] is False
    return row, fixture, old, ids, foreign_id


CONFINEMENT_CASES = (
    "confinement-paths", "confinement-reparse-root", "confinement-reparse-parent",
)


def _run_confinement_probe(tmp_path: Path, case: str) -> dict:
    result, fixture, _, _, _ = _run_process(tmp_path, case)
    assert result.returncode == 0, result.stdout + result.stderr
    row = json.loads((fixture / "confinement-result.json").read_text())
    assert row["case"] == case
    assert row["product_functions_loaded"] is False
    assert row["recursive_removal_executed"] is False
    if case == "confinement-paths":
        assert len(row["rejections"]) == 5
        for probe in (
            Path(r"\\server.invalid\share\fixture"), Path(r"\\?\C:\fixture"),
            fixture / "alias~1", fixture / "missing" / ".." / "escape",
            fixture.parent / "outside",
        ):
            with pytest.raises(ValueError):
                _assert_local_canonical_path(probe, fence=fixture)
    else:
        assert len(row["rejections"]) == 4
        link = fixture / "probe-link"
        link_info = link.lstat()
        assert link_info.st_ino > 0
        assert getattr(link_info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
        probe_root = link if case.endswith("-root") else link / "child"
        for probe in (probe_root, probe_root / "leaf"):
            with pytest.raises(ValueError):
                _assert_local_canonical_path(probe, fence=fixture)
        assert (fixture / "probe-target" / "sentinel.bin").read_text() == "unrelated-probe-target"
        # Remove only the exact owned junction itself, nonrecursively, after
        # both guards proved refusal. Unknown/replaced identities stay intact.
        current = link.lstat()
        assert current.st_ino == link_info.st_ino
        assert current.st_file_attributes == link_info.st_file_attributes
        link.rmdir()
        assert (fixture / "probe-target" / "sentinel.bin").read_text() == "unrelated-probe-target"
    return row


@pytest.fixture(scope="module", autouse=True)
def confinement_preflight(tmp_path_factory) -> dict[str, dict]:
    # Mandatory refusal-only probes precede ANY candidate replacement or
    # recursive-staging-cleanup fixture, even when pytest selects one case.
    return {
        case: _run_confinement_probe(tmp_path_factory.mktemp(case), case)
        for case in CONFINEMENT_CASES
    }


@pytest.mark.parametrize("case", CONFINEMENT_CASES)
def test_confinement_refusals_precede_replacement_or_recursive_cleanup(
    confinement_preflight, case: str,
) -> None:
    assert confinement_preflight[case]["recursive_removal_executed"] is False


@pytest.mark.parametrize("case", [
    "copy-before-a", "copy-partial-a", "acl-a", "copy-before-b", "move-after-a",
    "foreign-distinct-b", "foreign-same-b", "acl-floor", "target-acl",
])
def test_failed_replacement_retains_every_moved_original_and_foreign_generation(
    tmp_path: Path, case: str,
) -> None:
    row, fixture, old, ids, foreign_id = _run(tmp_path, case)
    target = fixture / "target"
    stage = target / ".installing-fixture"
    assert row["error"] == f"injected-{case}"
    assert row["injections"] == [case]
    assert row["mutation_attempted"] is True
    assert row["phase"] == "recovery-required-no-automatic-rollback"
    assert row["removals"] == []
    assert stage.is_dir()
    for name, value in old.items():
        backup = stage / "previous" / name
        surviving_original = backup if backup.exists() else target / name
        assert surviving_original.read_bytes() == value
        assert surviving_original.stat().st_ino == ids[name]
    expected_entries = 3 if case in {"acl-floor", "target-acl"} else (
        2 if case in {"copy-before-b", "foreign-distinct-b", "foreign-same-b"} else 1
    )
    assert len(row["entries"]) == expected_entries
    assert all(entry["Recovery"] == "not-authorized-no-file-object-custody"
               for entry in row["entries"])
    if case.startswith("foreign-"):
        expected = b"new-b" if case == "foreign-same-b" else b"foreign-b"
        assert (target / "b.bin").read_bytes() == expected
        assert (target / "b.bin").stat().st_ino == foreign_id
    if case == "copy-partial-a":
        assert (target / "a.bin").read_bytes() == b"partial-a"
    if case == "acl-floor":
        assert (target / "release-floor.json").read_bytes() == b'{"floor":2}'
        assert (stage / "previous" / "release-floor.json").read_bytes() == b'{"floor":1}'


def test_successful_file_copy_keeps_previous_payload_without_claiming_startup_health(tmp_path: Path) -> None:
    row, fixture, old, ids, _ = _run(tmp_path, "success")
    stage = fixture / "target" / ".installing-fixture"
    assert row["error"] is None
    assert row["injections"] == []
    assert row["phase"] == "files-copied-startup-unverified"
    assert row["removals"] == []
    assert row["mutation_attempted"] is True
    for name, value in old.items():
        assert (stage / "previous" / name).read_bytes() == value
        assert (stage / "previous" / name).stat().st_ino == ids[name]


@pytest.mark.parametrize("case", ["pre-mutation", "pre-mutation-cleanup-failure"])
def test_pre_mutation_cleanup_is_confined_and_does_not_mask_primary_error(tmp_path: Path, case: str) -> None:
    row, fixture, old, ids, _ = _run(tmp_path, case)
    target = fixture / "target"
    stage = target / ".installing-fixture"
    assert row["error"] == "injected-primary-pre-mutation"
    assert row["phase"] == "pre-mutation-staging"
    assert row["mutation_attempted"] is False
    assert row["entries"] == []
    assert len(row["removals"]) == 1
    assert Path(row["removals"][0]) == stage
    assert stage.exists() is (case == "pre-mutation-cleanup-failure")
    expected = ["primary-pre-mutation"]
    if case == "pre-mutation-cleanup-failure":
        expected.append("secondary-cleanup-failure")
    assert row["injections"] == expected
    for name, value in old.items():
        assert (target / name).read_bytes() == value
        assert (target / name).stat().st_ino == ids[name]


@pytest.mark.parametrize("case", ["new-parent-create", "new-destination-copy"])
def test_failure_creating_new_destination_retains_stage_and_existing_files(tmp_path: Path, case: str) -> None:
    row, fixture, old, ids, _ = _run(tmp_path, case)
    target = fixture / "target"
    stage = target / ".installing-fixture"
    assert row["error"] == f"injected-{case}"
    assert row["injections"] == [case]
    assert row["mutation_attempted"] is True
    assert row["phase"] == "recovery-required-no-automatic-rollback"
    assert len(row["entries"]) == 1 and row["entries"][0]["HadPrevious"] is False
    assert row["moves"] == [] and row["removals"] == []
    assert stage.is_dir()
    for name, value in old.items():
        assert (target / name).read_bytes() == value
        assert (target / name).stat().st_ino == ids[name]
    if case == "new-parent-create":
        assert (target / "nested").is_dir()
        assert not (target / "nested" / "new.bin").exists()
    else:
        assert (target / "new.bin").read_bytes() == b"partial-new"


def test_duplicate_path_is_rejected_before_destination_mutation(tmp_path: Path) -> None:
    row, fixture, old, ids, _ = _run(tmp_path, "duplicate-path")
    target = fixture / "target"
    assert row["error"] == "The verified installation path list contains a duplicate."
    assert row["mutation_attempted"] is False
    assert row["entries"] == [] and row["moves"] == []
    assert not (target / ".installing-fixture").exists()
    for name, value in old.items():
        assert (target / name).read_bytes() == value
        assert (target / name).stat().st_ino == ids[name]


def test_warning_failure_cannot_replace_original_copy_failure(tmp_path: Path) -> None:
    row, fixture, old, ids, _ = _run(tmp_path, "warning-emission")
    assert row["error"] == "injected-primary-copy-before-b"
    assert row["injections"][0] == "primary-copy-before-b"
    assert row["injections"].count("warning-emission-failure") == 2
    assert row["removals"] == []
    assert row["phase"] == "recovery-required-no-automatic-rollback"
    target = fixture / "target"
    stage = target / ".installing-fixture"
    for name, value in old.items():
        original = stage / "previous" / name
        if not original.exists():
            original = target / name
        assert original.read_bytes() == value
        assert original.stat().st_ino == ids[name]


@pytest.mark.parametrize("case", ["crash-after-move-a", "crash-after-copy-b"])
def test_fresh_child_abrupt_interruption_preserves_originals_without_claiming_recovery(
    tmp_path: Path, case: str,
) -> None:
    result, fixture, old, ids, _ = _run_process(tmp_path, case)
    assert result.returncode == 99, result.stdout + result.stderr
    assert "ANGERONA_FIXTURE_RESULT=" not in result.stdout
    assert (fixture / "interruption-marker.txt").read_text() == case
    proof = json.loads((fixture / "native-retirement.json").read_text())
    assert proof["wait_status"] == 0 and proof["native_exit"] == 99
    assert proof["handle_closed"] is True
    target = fixture / "target"
    stage = target / ".installing-fixture"
    assert stage.is_dir()
    assert (stage / "previous" / "a.bin").read_bytes() == old["a.bin"]
    for name, value in old.items():
        backup = stage / "previous" / name
        original = backup if backup.exists() else target / name
        assert original.read_bytes() == value
        assert original.stat().st_ino == ids[name]
    if case == "crash-after-move-a":
        assert not (target / "a.bin").exists()
        assert (target / "b.bin").read_bytes() == old["b.bin"]
    else:
        assert (target / "a.bin").read_bytes() == b"new-a"
        assert (target / "b.bin").read_bytes() == b"new-b"
    assert (fixture / "sibling" / "sentinel.bin").read_bytes() == b"unrelated-sentinel"
    # No second process reconciles or resumes protection. Surviving originals
    # plus exact child retirement establish preservation only, not recovery.
