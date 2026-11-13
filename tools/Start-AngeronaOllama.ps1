<#
.SYNOPSIS
  Compatibility entrypoint for Angerona's governed local AI controls.
.DESCRIPTION
  Angerona now owns optional AI startup, listener attestation and process
  retirement inside the application. This wrapper does not prepare a separate
  daemon, change saved environment settings, install software or download models.
  Open the Upgrade Console in Angerona to review governed model packs.
  With -LaunchAngerona, normal source startup is delegated immediately; optional
  AI availability does not decide whether that startup is attempted. The source
  supervisor retains its normal verification and recovery holds. An interrupted
  source activation still requires start-angerona.bat for its original-capsule
  recovery route. This editable source wrapper is not an independent trust anchor.
.PARAMETER WaitSeconds
  Accepted for compatibility; there is no separate AI wait in this wrapper.
.PARAMETER SkipUpdate
  Accepted for compatibility; this wrapper does not update software.
.PARAMETER FixHostBinding
  Accepted for compatibility; this wrapper leaves stored settings unchanged.
.PARAMETER LaunchAngerona
  Delegate to the fixed normal source startup supervisor.
#>
[CmdletBinding()]
param(
    [ValidateRange(30, 1800)][int]$WaitSeconds = 420,
    [switch]$SkipUpdate,
    [switch]$FixHostBinding,
    [switch]$LaunchAngerona
)
$ErrorActionPreference = 'Stop'

Write-Host 'Optional AI is managed inside Angerona. Use its Upgrade Console for governed model packs.'
if ($PSBoundParameters.ContainsKey('WaitSeconds') -or $SkipUpdate -or $FixHostBinding) {
    Write-Warning 'Legacy preparation options are accepted but do not change software, saved settings or other processes.'
}
if (-not $LaunchAngerona) {
    Write-Host 'Use -LaunchAngerona or start-angerona.bat to open the dashboard. No AI readiness or protection is asserted here.'
    exit 0
}

$repo = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
if ($repo -notmatch '^[A-Za-z]:\\' -or $repo.StartsWith('\\')) {
    throw 'Normal source startup requires a fixed local repository path.'
}
# Reject redirected DOS devices before asking the filesystem provider for any item.
# A unique private native type avoids accepting a caller-preloaded helper type.
$driveGuardName = 'AngeronaOllamaDriveGuard_' + [Guid]::NewGuid().ToString('N')
$driveGuardSource = @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
public static class __GUARD_NAME__ {
    [DllImport("kernel32.dll", EntryPoint="QueryDosDeviceW", CharSet=CharSet.Unicode,
        ExactSpelling=true, SetLastError=true)]
    private static extern uint QueryDosDevice(string deviceName,
        [Out, MarshalAs(UnmanagedType.LPArray, ArraySubType=UnmanagedType.U2, SizeParamIndex=2)]
        char[] targetPath, uint capacity);
    public static bool IsDirectFixed(string root) {
        try {
            if (root == null || root.Length != 3 || root[1] != ':' || root[2] != '\\' ||
                !((root[0] >= 'A' && root[0] <= 'Z') || (root[0] >= 'a' && root[0] <= 'z')))
                return false;
            char[] target = new char[2048];
            uint written = QueryDosDevice(root.Substring(0, 2), target, (uint)target.Length);
            if (written == 0 || written > (uint)target.Length) return false;
            string[] mappings = new string(target, 0, (int)written).Split(
                new char[] {'\0'}, StringSplitOptions.RemoveEmptyEntries);
            if (mappings.Length != 1 || !Regex.IsMatch(mappings[0],
                @"\A\\Device\\HarddiskVolume[0-9]+\z", RegexOptions.CultureInvariant,
                TimeSpan.FromMilliseconds(100))) return false;
            return new DriveInfo(root).DriveType == DriveType.Fixed;
        } catch { return false; }
    }
}
'@
$driveGuard = Add-Type -TypeDefinition ($driveGuardSource.Replace('__GUARD_NAME__', $driveGuardName)) -PassThru
$driveRoot = [IO.Path]::GetPathRoot($repo)
if (-not $driveGuard::IsDirectFixed($driveRoot)) {
    throw 'Normal source startup requires a direct fixed local volume; mapped, SUBST and ambiguous drives are refused.'
}

$startup = Join-Path $repo 'tools\Invoke-AngeronaSourceStartup.ps1'
$ancestors = [Collections.Generic.List[string]]::new()
$cursor = [IO.Path]::GetDirectoryName($startup)
while ($cursor) {
    $ancestors.Add($cursor)
    $cursor = [IO.Path]::GetDirectoryName($cursor)
}
# Inspect only children of already checked ancestors, starting at the drive root.
# These snapshots do not replace the normal supervisor's own source custody.
for ($index = $ancestors.Count - 1; $index -ge 0; $index--) {
    $ancestor = Get-Item -LiteralPath ($ancestors[$index]) -Force -ErrorAction Stop
    if (-not $ancestor.PSIsContainer -or ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'A source startup ancestor is redirected or is not a directory.'
    }
}
$startupItem = Get-Item -LiteralPath $startup -Force -ErrorAction Stop
if ($startupItem.PSIsContainer -or ($startupItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $startupItem.LinkType -eq 'HardLink') {
    throw 'The fixed source startup file is redirected; use the normal reviewed launcher.'
}
Write-Host 'Delegating to normal Angerona source startup. AI admission remains owned by the application.'
$global:LASTEXITCODE = 0
& $startup -RepositoryRoot $repo
exit $LASTEXITCODE
