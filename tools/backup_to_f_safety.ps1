[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Validate", "Scrub")]
    [string]$Mode,

    [Parameter(Mandatory = $true)]
    [string]$Source,

    [Parameter(Mandatory = $true)]
    [string]$Destination,

    [Parameter(Mandatory = $true)]
    [string]$LauncherPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Stop-UnsafeBackup {
    throw [System.InvalidOperationException]::new("Backup safety validation failed.")
}

function Get-NormalizedPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    # Windows PowerShell 5.1 targets .NET Framework, which does not expose
    # Path.IsPathFullyQualified. This launcher intentionally accepts only an
    # absolute local drive path (never relative, UNC, or device syntax).
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path -notmatch '^[A-Za-z]:[\\/]') {
        Stop-UnsafeBackup
    }
    try {
        $full = [System.IO.Path]::GetFullPath($Path)
    }
    catch {
        Stop-UnsafeBackup
    }
    $root = [System.IO.Path]::GetPathRoot($full)
    if ([string]::Equals($full, $root, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $root
    }
    return $full.TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    )
}

function Test-PathEqual {
    param(
        [Parameter(Mandatory = $true)][string]$Left,
        [Parameter(Mandatory = $true)][string]$Right
    )
    return [string]::Equals($Left, $Right, [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-StrictChildPath {
    param(
        [Parameter(Mandatory = $true)][string]$Child,
        [Parameter(Mandatory = $true)][string]$Parent
    )
    $prefix = $Parent.TrimEnd("\") + "\"
    return $Child.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-ParentPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $parent = [System.IO.Directory]::GetParent($Path)
    if ($null -eq $parent) {
        return ""
    }
    return $parent.FullName
}

function Assert-NoReparseAncestor {
    param([Parameter(Mandatory = $true)][string]$Path)

    $cursor = $Path
    while (-not (Test-Path -LiteralPath $cursor)) {
        $parent = Get-ParentPath $cursor
        if ([string]::IsNullOrWhiteSpace($parent) -or (Test-PathEqual $parent $cursor)) {
            Stop-UnsafeBackup
        }
        $cursor = $parent
    }

    while (-not [string]::IsNullOrWhiteSpace($cursor)) {
        $item = Get-Item -Force -LiteralPath $cursor
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            Stop-UnsafeBackup
        }
        $parent = Get-ParentPath $cursor
        if ([string]::IsNullOrWhiteSpace($parent) -or (Test-PathEqual $parent $cursor)) {
            break
        }
        $cursor = $parent
    }
}

function Assert-SafeBackupBoundary {
    if ($Destination -notmatch '^[A-Za-z]:[\\/]') {
        Stop-UnsafeBackup
    }
    $rawDestinationTail = $Destination.Substring(3).Replace("/", "\")
    $reservedNames = '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$'
    foreach ($component in $rawDestinationTail.Split("\")) {
        if ([string]::IsNullOrWhiteSpace($component) -or
            $component -in @(".", "..") -or
            $component.EndsWith(" ") -or
            $component.EndsWith(".") -or
            $component -match $reservedNames -or
            $component.IndexOfAny([char[]]'<>:"/|?*') -ge 0) {
            Stop-UnsafeBackup
        }
    }

    $sourcePath = Get-NormalizedPath $Source
    $destinationPath = Get-NormalizedPath $Destination
    $launcher = Get-NormalizedPath $LauncherPath
    $repositoryRoot = Get-NormalizedPath (Get-ParentPath $launcher)
    $safeRoot = Get-NormalizedPath "F:\Angerona-Backups"

    if (-not (Test-PathEqual $sourcePath $repositoryRoot)) {
        Stop-UnsafeBackup
    }
    if (-not (Test-Path -LiteralPath $sourcePath -PathType Container) -or
        -not (Test-Path -LiteralPath $launcher -PathType Leaf)) {
        Stop-UnsafeBackup
    }
    foreach ($marker in @("pyproject.toml", "src\angerona", "backup_to_F.bat")) {
        if (-not (Test-Path -LiteralPath (Join-Path $sourcePath $marker))) {
            Stop-UnsafeBackup
        }
    }

    if (-not (Test-StrictChildPath $destinationPath $safeRoot) -or
        (Test-PathEqual $destinationPath $safeRoot) -or
        (Test-PathEqual $destinationPath ([System.IO.Path]::GetPathRoot($destinationPath)))) {
        Stop-UnsafeBackup
    }
    $relativeDestination = $destinationPath.Substring($safeRoot.Length + 1)
    foreach ($component in $relativeDestination.Split("\")) {
        if ([string]::IsNullOrWhiteSpace($component) -or
            $component -in @(".", "..") -or
            $component.EndsWith(" ") -or
            $component.EndsWith(".") -or
            $component -match $reservedNames -or
            $component.IndexOfAny([char[]]'<>:"/|?*') -ge 0) {
            Stop-UnsafeBackup
        }
    }
    if (-not (Test-PathEqual ([System.IO.Path]::GetPathRoot($destinationPath)) "F:\") -or
        -not (Test-Path -LiteralPath "F:\" -PathType Container)) {
        Stop-UnsafeBackup
    }
    if ($destinationPath.Substring(2).Contains(":") -or
        $destinationPath.IndexOfAny([char[]]"*?") -ge 0) {
        Stop-UnsafeBackup
    }
    if ((Test-PathEqual $sourcePath $destinationPath) -or
        (Test-StrictChildPath $destinationPath $sourcePath) -or
        (Test-StrictChildPath $sourcePath $destinationPath)) {
        Stop-UnsafeBackup
    }
    if ((Test-Path -LiteralPath $destinationPath) -and
        -not (Test-Path -LiteralPath $destinationPath -PathType Container)) {
        Stop-UnsafeBackup
    }

    Assert-NoReparseAncestor $sourcePath
    Assert-NoReparseAncestor $destinationPath

    return [pscustomobject]@{
        Source = $sourcePath
        Destination = $destinationPath
    }
}

function Remove-PrivateBackupState {
    param(
        [Parameter(Mandatory = $true)][string]$DestinationPath
    )

    # Candidates come only from these exact names/extensions or anchored
    # generated-directory formats. The traversal never enters .git metadata,
    # never follows a reparse point, and collects the full deletion plan before
    # changing anything. Remove-Item always receives -LiteralPath.
    $privateDirectoryNames = @(
        "__pycache__", ".venv", "venv", "env", ".tmp", "node_modules",
        "runtime-data", "diagnostics", "shared_logs", "logs", "quarantine",
        "flight-recorder", "baselines", "remediations", "heartbeats", "ipc",
        "models", "secrets", "drill-sandbox", "staged_patches", "shadow_cache",
        "forensics", "build", "dist", ".dev-tools", ".pytest_cache", ".mypy_cache",
        ".ruff_cache", ".hypothesis", "htmlcov", ".tox", "pip-wheel-metadata",
        ".eggs"
    )
    $privateFileNames = @(
        ".env", "settings.json", "user_config.json", "bus.key", ".coverage",
        "credentials.json", "credentials.yaml", "credentials.yml", "secrets.json",
        "secrets.yaml", "secrets.yml", "tokens.json", "api_keys.json", "auth.json",
        "id_rsa", "id_ed25519", ".npmrc", ".pypirc", ".netrc",
        "custom_user_patch.ps1", "standdown.cmd", "Thumbs.db", "Desktop.ini"
    )
    $privateFileExtensions = @(
        ".pyc", ".key", ".pem", ".pfx", ".p12", ".token", ".secret",
        ".secrets", ".db", ".sqlite", ".sqlite3", ".log", ".gguf", ".hb",
        ".ring", ".bak", ".tmp", ".lnk", ".test", ".spec"
    )
    $generatedDirectoryNames = @(
        '^venv\.incompatible\.\d{8}-\d{6}$',
        '^LibreOffice_[A-Za-z0-9._-]+_Machine_(?:X64|ARM64)_msi_[A-Za-z-]+$'
    )
    $pending = New-Object 'System.Collections.Generic.Stack[string]'
    $candidates = New-Object 'System.Collections.Generic.List[string]'
    $pending.Push($DestinationPath)

    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        foreach ($item in Get-ChildItem -Force -LiteralPath $directory) {
            $candidate = Get-NormalizedPath $item.FullName
            if (-not (Test-StrictChildPath $candidate $DestinationPath) -or
                (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
                Stop-UnsafeBackup
            }

            if ($item.PSIsContainer) {
                if ([string]::Equals(
                        $item.Name, ".git", [System.StringComparison]::OrdinalIgnoreCase
                    )) {
                    continue
                }
                $relativePath = $candidate.Substring($DestinationPath.Length + 1)
                $generated = $false
                if (Test-PathEqual (Get-ParentPath $candidate) $DestinationPath) {
                    foreach ($pattern in $generatedDirectoryNames) {
                        if ($item.Name -cmatch $pattern) {
                            $generated = $true
                            break
                        }
                    }
                }
                if (($privateDirectoryNames -contains $item.Name) -or
                    [string]::Equals(
                        $relativePath,
                        "analysis\manual_build",
                        [System.StringComparison]::OrdinalIgnoreCase
                    ) -or $generated) {
                    $candidates.Add($candidate)
                }
                else {
                    $pending.Push($candidate)
                }
                continue
            }

            $extension = [System.IO.Path]::GetExtension($item.Name)
            $privateName = ($privateFileNames -contains $item.Name) -or
                $item.Name.StartsWith(".env.", [System.StringComparison]::OrdinalIgnoreCase) -or
                $item.Name.EndsWith(".settings.json", [System.StringComparison]::OrdinalIgnoreCase) -or
                $item.Name.StartsWith(
                    "ANGERONA_WATCHDOG_TOKEN",
                    [System.StringComparison]::OrdinalIgnoreCase
                ) -or
                ($item.Name -match '^client_secret.*\.(json|ya?ml|txt)$') -or
                ($item.Name -match '^selfcheck_report.*\.txt$') -or
                ($item.Name -match '^_.*vault.*$')
            if ($privateName -or ($privateFileExtensions -contains $extension)) {
                $candidates.Add($candidate)
            }
        }
    }

    foreach ($candidate in ($candidates | Sort-Object Length -Descending -Unique)) {
        if (-not (Test-StrictChildPath $candidate $DestinationPath) -or
            -not (Test-Path -LiteralPath $candidate)) {
            Stop-UnsafeBackup
        }
        $item = Get-Item -Force -LiteralPath $candidate
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            Stop-UnsafeBackup
        }
        if ($item.PSIsContainer) {
            Remove-Item -Force -Recurse -LiteralPath $candidate
        }
        else {
            Remove-Item -Force -LiteralPath $candidate
        }
    }
}

try {
    $boundary = Assert-SafeBackupBoundary
    if ($Mode -eq "Scrub") {
        if (-not (Test-Path -LiteralPath $boundary.Destination -PathType Container)) {
            Stop-UnsafeBackup
        }
        Remove-PrivateBackupState -DestinationPath $boundary.Destination
        [void](Assert-SafeBackupBoundary)
    }
    exit 0
}
catch {
    # Deliberately do not print paths, exception records, or file contents.
    [Console]::Error.WriteLine("Backup safety validation failed.")
    exit 16
}
