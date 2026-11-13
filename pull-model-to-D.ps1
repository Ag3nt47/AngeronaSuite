<#
.SYNOPSIS
  Compatibility entrypoint for governed Angerona model downloads.
.DESCRIPTION
  Model downloads belong to Angerona's Upgrade Console, where the selected pack,
  digest, resources and result are reviewed. This wrapper performs no download,
  settings migration or independent daemon preparation. A supplied immutable
  model reference is validated only; it is not installed or forwarded as code.
  With -LaunchAngerona, normal source startup is delegated. That supervisor keeps
  its normal verification and recovery holds. Use start-angerona.bat for the full
  source bootstrap and interrupted-activation original-capsule recovery route.
.PARAMETER Model
  Optional immutable name@sha256:<64 lowercase hexadecimal digits> reference.
.PARAMETER Models
  Deprecated compatibility parameter. No directory is created or saved.
.PARAMETER LaunchAngerona
  Open normal source startup so governed model controls can be reviewed there.
#>
[CmdletBinding()]
param(
    [string]$Model = '',
    [string]$Models = '',
    [switch]$LaunchAngerona
)
$ErrorActionPreference = 'Stop'

# Validate supplied input before filesystem discovery or startup delegation.
$immutableModel = '\A[a-z0-9][a-z0-9._-]{0,63}@sha256:[0-9a-f]{64}\z'
if ($PSBoundParameters.ContainsKey('Model') -and ($Model.Length -gt 136 -or $Model -cnotmatch $immutableModel)) {
    throw 'Model must be an immutable name@sha256 reference. Mutable tags and URLs are refused; nothing was downloaded or changed.'
}

Write-Host 'This legacy helper does not download models. Open Angerona and review a governed pack in the Upgrade Console.'
if ($PSBoundParameters.ContainsKey('Models')) {
    Write-Warning 'The legacy Models option is not applied. Review storage in the governed model controls; the supplied setting remains unchanged.'
}
if ($PSBoundParameters.ContainsKey('Model')) {
    Write-Host 'The immutable reference syntax is valid. No model was installed, selected or approved by this wrapper.'
}
if (-not $LaunchAngerona) {
    Write-Host 'Use -LaunchAngerona or start-angerona.bat to open the dashboard. Optional AI availability does not block that attempt.'
    exit 0
}

$repo = [IO.Path]::GetFullPath($PSScriptRoot)
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
Write-Host 'Delegating to normal Angerona source startup. Review model downloads in its Upgrade Console.'
$global:LASTEXITCODE = 0
& $startup -RepositoryRoot $repo
exit $LASTEXITCODE
