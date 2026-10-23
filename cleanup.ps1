<#
.SYNOPSIS
Remove explicitly named, rebuildable Angerona build output.

.DESCRIPTION
By default, removes only build and src/angerona.egg-info beneath this script's
physical checkout. Add -IncludeDist to include dist. Use -WhatIf to review.

Leaves virtual environments, source Python caches and all paths outside those
explicit build targets alone. Known runtime/evidence names inside a selected
target cause refusal. An ignored file is not necessarily disposable. No runtime-
purge option exists.

All existing targets are checked before any removal. Links/reparse points,
unexpected file targets, known evidence names/types and unbounded trees cause a
terminating error. Access and removal errors are never suppressed.

Run while build/install processes are idle. A recheck immediately before each
removal reduces filesystem races, but PowerShell cannot make recursive removal
atomic against concurrent directory replacement. Unknown evidence placed inside
an explicitly selected build directory cannot be identified reliably by name.

Compatible syntax: Windows PowerShell 5.1 and PowerShell 7.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [switch]$IncludeDist
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$workspace = [System.IO.Path]::GetFullPath($PSScriptRoot)
$pathComparison = [System.StringComparison]::Ordinal
if ([System.IO.Path]::DirectorySeparatorChar -eq '\') {
    $pathComparison = [System.StringComparison]::OrdinalIgnoreCase
}
$workspacePrefix = $workspace.TrimEnd([char[]]@('\', '/')) +
    [System.IO.Path]::DirectorySeparatorChar
$entryLimit = 20000
$depthLimit = 64

function Assert-NoReparseAncestors {
    param([Parameter(Mandatory = $true)][string]$Path)

    $cursor = [System.IO.Path]::GetFullPath($Path)
    $ancestors = New-Object 'System.Collections.Generic.Stack[string]'
    while ($true) {
        $ancestors.Push($cursor)
        $parent = [System.IO.Directory]::GetParent($cursor)
        if ($null -eq $parent) { break }
        $cursor = $parent.FullName
    }
    # Inspect the volume root first, before accessing any child through it.
    foreach ($ancestor in $ancestors) {
        $item = Get-Item -LiteralPath $ancestor -Force -ErrorAction Stop
        if ($item.PSProvider.Name -ne 'FileSystem' -or
            ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refusing nonphysical or linked path: $ancestor"
        }
    }
}

function Assert-WithinWorkspace {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not [System.IO.Path]::IsPathRooted($Path)) {
        throw "Refusing relative cleanup path: $Path"
    }
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    if (-not $fullPath.StartsWith($workspacePrefix, $pathComparison)) {
        throw "Refusing cleanup outside the physical checkout: $fullPath"
    }
}

function Assert-RebuildableTree {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][ref]$Entries
    )

    Assert-WithinWorkspace -Path $Path
    Assert-NoReparseAncestors -Path $Path
    $target = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $target.PSIsContainer) {
        throw "Refusing cleanup target that is not a directory: $Path"
    }

    $protectedDirectories = @(
        '.tmp', 'runtime-data', 'logs', 'shared_logs', 'diagnostics', 'remediations',
        'backup', 'backups', 'quarantine', 'forensics', 'flight-recorder', 'baselines',
        'secrets', 'heartbeats', 'ipc', 'venv', '.venv', 'env'
    )
    $protectedFiles = @(
        'settings.json', 'user_config.json', 'custom_user_patch.ps1', 'standdown.cmd'
    )
    $protectedSuffix = '(?i)(\.(db|sqlite|sqlite3)(-(wal|shm|journal))?|' +
        '\.(log|key|pem|pfx|p12|token|journal|bak|backup|dmp|dump|pcap|pcapng|' +
        'evtx|etl|har|evidence|receipt|hmac|sig|hb|ring))$'
    $pending = New-Object 'System.Collections.Generic.Stack[object]'
    $pending.Push(@{ Path = $Path; Depth = 0 })
    while ($pending.Count -gt 0) {
        $current = $pending.Pop()
        Assert-NoReparseAncestors -Path $current.Path
        # No -Recurse: inspect each entry before deciding to enter a directory.
        Get-ChildItem -LiteralPath $current.Path -Force -ErrorAction Stop | ForEach-Object {
            $child = $_
            $Entries.Value += 1
            if ($Entries.Value -gt $entryLimit) {
                throw "Cleanup preflight exceeded $entryLimit entries; nothing is safe to assume."
            }
            Assert-WithinWorkspace -Path $child.FullName
            if (($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Refusing linked cleanup entry: $($child.FullName)"
            }
            if ($child.PSIsContainer) {
                if ($protectedDirectories -contains $child.Name) {
                    throw "Refusing possible runtime/evidence directory: $($child.FullName)"
                }
                $depth = $current.Depth + 1
                if ($depth -gt $depthLimit) {
                    throw "Cleanup preflight exceeded depth $depthLimit."
                }
                $pending.Push(@{ Path = $child.FullName; Depth = $depth })
            } elseif ($child.Name -match $protectedSuffix -or
                $child.Name -eq '.env' -or $child.Name -like '.env.*' -or
                $protectedFiles -contains $child.Name) {
                throw "Refusing possible runtime/evidence file: $($child.FullName)"
            }
        }
    }
}

if (-not [System.IO.Path]::IsPathRooted($workspace) -or
    $null -eq [System.IO.Directory]::GetParent($workspace)) {
    throw 'Refusing an empty, relative or filesystem-root checkout.'
}
Assert-NoReparseAncestors -Path $workspace
foreach ($marker in @('pyproject.toml', 'src/angerona/__init__.py')) {
    $markerPath = Join-Path -Path $workspace -ChildPath $marker
    Assert-NoReparseAncestors -Path $markerPath
    if ((Get-Item -LiteralPath $markerPath -Force -ErrorAction Stop).PSIsContainer) {
        throw "Checkout marker must be a file: $markerPath"
    }
}

$relativeTargets = @('build', 'src/angerona.egg-info')
if ($IncludeDist) { $relativeTargets += 'dist' }
$targets = New-Object 'System.Collections.Generic.List[string]'
$entries = 0
foreach ($relativeTarget in $relativeTargets) {
    $targetPath = [System.IO.Path]::GetFullPath((Join-Path $workspace $relativeTarget))
    Assert-WithinWorkspace -Path $targetPath
    # A missing final target is harmless; reject a linked existing parent anyway.
    $parentPath = [System.IO.Directory]::GetParent($targetPath).FullName
    Assert-NoReparseAncestors -Path $parentPath
    # Enumerate the exact known leaf name so even a dangling link is examined.
    $existingTarget = @(Get-ChildItem -LiteralPath $parentPath -Force -ErrorAction Stop `
        -Filter ([System.IO.Path]::GetFileName($targetPath)))
    if ($existingTarget.Count -gt 0) {
        Assert-RebuildableTree -Path $targetPath -Entries ([ref]$entries)
        $targets.Add($targetPath)
    }
}

foreach ($targetPath in $targets) {
    if ($PSCmdlet.ShouldProcess($targetPath, 'Remove explicitly selected rebuildable build output')) {
        $recheckEntries = 0
        Assert-RebuildableTree -Path $targetPath -Entries ([ref]$recheckEntries)
        Remove-Item -LiteralPath $targetPath -Recurse -Force -ErrorAction Stop
    }
}
Write-Verbose 'Build cleanup finished; runtime state and evidence are outside the cleanup allowlist.'
