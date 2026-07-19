[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$source = [IO.Path]::GetFullPath((Split-Path -Parent $MyInvocation.MyCommand.Path))
$programFiles = [Environment]::GetFolderPath('ProgramFiles')
$target = [IO.Path]::GetFullPath((Join-Path $programFiles 'Angerona'))
$manifestPath = Join-Path $source 'release-files.sha256'
$required = @('Angerona.exe', 'AngeronaBlackBox.exe')

function Assert-NotReparse([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing reparse point: $Path"
    }
}

function New-ProtectedAcl([bool]$Directory) {
    $acl = if ($Directory) {
        New-Object Security.AccessControl.DirectorySecurity
    } else {
        New-Object Security.AccessControl.FileSecurity
    }
    $admins = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $users = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')
    $acl.SetOwner($admins)
    $acl.SetAccessRuleProtection($true, $false)
    if ($Directory) {
        $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
        foreach ($sid in @($admins, $system)) {
            $rule = [Security.AccessControl.FileSystemAccessRule]::new(
                $sid, [Security.AccessControl.FileSystemRights]::FullControl,
                $inherit, [Security.AccessControl.PropagationFlags]::None,
                [Security.AccessControl.AccessControlType]::Allow)
            [void]$acl.AddAccessRule($rule)
        }
        $read = [Security.AccessControl.FileSystemAccessRule]::new(
            $users, [Security.AccessControl.FileSystemRights]::ReadAndExecute,
            $inherit, [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow)
    } else {
        foreach ($sid in @($admins, $system)) {
            $rule = [Security.AccessControl.FileSystemAccessRule]::new(
                $sid, [Security.AccessControl.FileSystemRights]::FullControl,
                [Security.AccessControl.AccessControlType]::Allow)
            [void]$acl.AddAccessRule($rule)
        }
        $read = [Security.AccessControl.FileSystemAccessRule]::new(
            $users, [Security.AccessControl.FileSystemRights]::ReadAndExecute,
            [Security.AccessControl.AccessControlType]::Allow)
    }
    [void]$acl.AddAccessRule($read)
    return $acl
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Administrator privileges are required.'
}
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw 'release-files.sha256 is missing; refusing an incomplete release.'
}
Assert-NotReparse $source

$expected = @{}
foreach ($line in Get-Content -LiteralPath $manifestPath) {
    if ($line -notmatch '^([0-9a-fA-F]{64})  (Angerona(?:BlackBox)?\.exe)$') {
        throw "Invalid release manifest entry: $line"
    }
    if ($expected.ContainsKey($Matches[2])) { throw 'Duplicate release manifest entry.' }
    $expected[$Matches[2]] = $Matches[1].ToLowerInvariant()
}
if ($expected.Count -ne $required.Count) { throw 'Release manifest is incomplete.' }

foreach ($name in $required) {
    $path = Join-Path $source $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "$name is missing." }
    Assert-NotReparse $path
    $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected[$name]) { throw "$name failed release integrity verification." }
}

if (Test-Path -LiteralPath $target) {
    Assert-NotReparse $target
} else {
    [void](New-Item -ItemType Directory -Path $target)
}
Set-Acl -LiteralPath $target -AclObject (New-ProtectedAcl $true)

$stage = Join-Path $target ('.installing-' + [guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $stage)
Set-Acl -LiteralPath $stage -AclObject (New-ProtectedAcl $true)
try {
    foreach ($name in $required) {
        $staged = Join-Path $stage $name
        Copy-Item -LiteralPath (Join-Path $source $name) -Destination $staged
        Set-Acl -LiteralPath $staged -AclObject (New-ProtectedAcl $false)
        $actual = (Get-FileHash -LiteralPath $staged -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $expected[$name]) { throw "$name changed during installation." }
    }
    $installed = @()
    try {
        foreach ($name in $required) {
            $destination = Join-Path $target $name
            $backup = Join-Path $stage ($name + '.previous')
            $hadPrevious = Test-Path -LiteralPath $destination -PathType Leaf
            if ($hadPrevious) {
                Move-Item -LiteralPath $destination -Destination $backup
            }
            try {
                Move-Item -LiteralPath (Join-Path $stage $name) -Destination $destination
            } catch {
                if ($hadPrevious -and (Test-Path -LiteralPath $backup)) {
                    Move-Item -LiteralPath $backup -Destination $destination
                }
                throw
            }
            $installed += [pscustomobject]@{
                Destination = $destination
                Backup = $backup
                HadPrevious = $hadPrevious
            }
        }
    } catch {
        for ($index = $installed.Count - 1; $index -ge 0; $index--) {
            $entry = $installed[$index]
            if (Test-Path -LiteralPath $entry.Destination) {
                Remove-Item -LiteralPath $entry.Destination -Force
            }
            if ($entry.HadPrevious -and (Test-Path -LiteralPath $entry.Backup)) {
                Move-Item -LiteralPath $entry.Backup -Destination $entry.Destination
            }
        }
        throw
    }
    foreach ($name in @('README.md', 'LICENSE', 'SECURITY.md')) {
        $item = Join-Path $source $name
        if (Test-Path -LiteralPath $item -PathType Leaf) {
            Copy-Item -LiteralPath $item -Destination (Join-Path $target $name) -Force
        }
    }
    foreach ($name in @('docs', 'playbooks')) {
        $item = Join-Path $source $name
        if (Test-Path -LiteralPath $item -PathType Container) {
            Copy-Item -LiteralPath $item -Destination $target -Recurse -Force
        }
    }
    Set-Content -LiteralPath (Join-Path $target '.release-integrity') -Encoding ASCII `
        -Value (($required | ForEach-Object { $expected[$_] + '  ' + $_ }) -join "`n")
    Set-Acl -LiteralPath $target -AclObject (New-ProtectedAcl $true)
} finally {
    $stageFull = [IO.Path]::GetFullPath($stage)
    $targetPrefix = $target.TrimEnd('\') + '\'
    if ($stageFull.StartsWith($targetPrefix, [StringComparison]::OrdinalIgnoreCase) -and
            (Test-Path -LiteralPath $stageFull)) {
        Remove-Item -LiteralPath $stageFull -Recurse -Force
    }
}

$shortcutPath = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Angerona.lnk'
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = Join-Path $target 'Angerona.exe'
$shortcut.WorkingDirectory = $target
$shortcut.IconLocation = (Join-Path $target 'Angerona.exe') + ',0'
$shortcut.Save()

Write-Host "Angerona installed to $target" -ForegroundColor Green
Write-Host 'Runtime data defaults to protected D:\AngeronaData (ProgramData fallback when D: is unavailable).' -ForegroundColor Cyan
Start-Process -FilePath (Join-Path $target 'Angerona.exe')
