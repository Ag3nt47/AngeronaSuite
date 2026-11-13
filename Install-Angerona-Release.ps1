[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$ReleaseArchive = '',

    [switch]$CustodyPreflightOnly
)

$ErrorActionPreference = 'Stop'
$programFiles = [Environment]::GetFolderPath('ProgramFiles')
$target = [IO.Path]::GetFullPath([IO.Path]::Combine($programFiles,'Angerona'))
$trustedInstaller = [IO.Path]::Combine($target,'Install-Angerona-Release.ps1')
$trustedVerifier = [IO.Path]::Combine($target,'Verify-Angerona-Release.ps1')
$trustedAuthorizationVerifier = [IO.Path]::Combine($target,'AngeronaReleaseVerifier.exe')
$requiredEvidence = @(
    'Angerona.exe',
    'AngeronaStartup.exe',
    'AngeronaBlackBox.exe',
    'AngeronaReleaseVerifier.exe',
    'Angerona-SBOM.json',
    'publisher-certificate.sha256',
    'release-payload-manifest.json',
    'release-payload.cat',
    'release-build-provenance.json',
    'release-authorization.json',
    'release-trust.json'
)
$approvedCustodySids = @(
    'S-1-5-18',      # NT AUTHORITY\SYSTEM
    'S-1-5-32-544'   # BUILTIN\Administrators
)
$installedCustodyNames = @(
    'Install-Angerona-Release.ps1',
    'Install-Angerona-Release.bat',
    'Verify-Angerona-Release.ps1',
    'AngeronaReleaseVerifier.exe',
    'Angerona.exe',
    'AngeronaBlackBox.exe',
    'Angerona-SBOM.json',
    'publisher-certificate.sha256',
    'release-payload-manifest.json',
    'release-payload.cat',
    'release-build-provenance.json',
    'release-authorization.json',
    'release-trust.json',
    'release-files.sha256'
)


# This script is an editable trust anchor, not a hardware/security-service root.
# Custody rejects unrelated writers and environment-selected helpers. A local
# administrator or a writer of this bootstrap can replace the bootstrap itself.
function Assert-ReleaseAuthorityAcl($Acl, [string]$Label, [bool]$Ancestor) {
    $approved = @('S-1-5-18', 'S-1-5-32-544',
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $owner = $Acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin $approved) { throw "Release authority has an untrusted owner: $Label" }
    $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
        $Acl.GetSecurityDescriptorBinaryForm(), 0)
    if ($null -eq $descriptor.DiscretionaryAcl) {
        throw "Release authority has an unrestricted DACL: $Label"
    }
    $mask = [Security.AccessControl.FileSystemRights]::WriteData -bor
        [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
        [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    # A drive's create-subdirectory permission cannot replace an existing,
    # independently protected child. Leaf authority may permit no such writer.
    if (!$Ancestor) { $mask = $mask -bor [Security.AccessControl.FileSystemRights]::AppendData }
    foreach ($rule in $Acl.GetAccessRules($true, $true,
            [Security.Principal.SecurityIdentifier])) {
        if (($rule.PropagationFlags -band
                [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
                ([long]$rule.FileSystemRights -band [long]$mask) -ne 0 -and
                $rule.IdentityReference.Value -notin $approved) {
            throw "Release authority permits an unrelated writer: $Label"
        }
    }
}

function Assert-ReleaseAuthorityPath([string]$Path, [switch]$AllowSystemHardlinks) {
    $full = [IO.Path]::GetFullPath($Path)
    if ($full -notmatch '^[A-Za-z]:\\' -or $full.StartsWith('\\')) {
        throw 'Release authority requires a fixed local absolute path.'
    }
    $cursor = $full; $leaf = $true; $count = 0
    while ($cursor) {
        if (++$count -gt 64) { throw 'Release authority ancestry exceeds its bound.' }
        $before = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        if ((!$leaf -and !$before.PSIsContainer) -or ($leaf -and $before.PSIsContainer) -or
                ![string]::Equals($before.FullName, $cursor, [StringComparison]::OrdinalIgnoreCase) -or
                ($before.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Release authority is redirected or has an invalid type: $cursor"
        }
        if ($before.PSObject.Properties.Name -contains 'LinkType' -and
                ![string]::IsNullOrEmpty([string]$before.LinkType) -and
                !($leaf -and $AllowSystemHardlinks -and $before.LinkType -eq 'HardLink')) {
            throw "Release authority is linked: $cursor"
        }
        $length = if ($before.PSIsContainer) { -1L } else { [long]$before.Length }
        $write = $before.LastWriteTimeUtc.Ticks; $attributes = $before.Attributes
        $acl = Get-Acl -LiteralPath $cursor -ErrorAction Stop
        Assert-ReleaseAuthorityAcl $acl $cursor (!$leaf)
        $after = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        $afterLength = if ($after.PSIsContainer) { -1L } else { [long]$after.Length }
        if (![string]::Equals($after.FullName, $cursor, [StringComparison]::OrdinalIgnoreCase) -or
                $after.Attributes -ne $attributes -or $after.LastWriteTimeUtc.Ticks -ne $write -or
                $afterLength -ne $length -or [bool]$after.PSIsContainer -ne [bool]$before.PSIsContainer) {
            throw 'Release authority changed during custody inspection.'
        }
        $cursor = [IO.Path]::GetDirectoryName($cursor); $leaf = $false
    }
}

function Get-ReleaseSystemPowerShell {
    $hostPath = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    Assert-ReleaseAuthorityPath $hostPath -AllowSystemHardlinks
    return $hostPath
}

function Initialize-ReleaseChildEnvironment {
    if (![Environment]::Is64BitOperatingSystem -or ![Environment]::Is64BitProcess) {
        throw 'Angerona win64 upgrades require the native 64-bit Windows host.'
    }
    $system = [Environment]::SystemDirectory
    $windows = [IO.Directory]::GetParent($system).FullName
    $safe = @{
        SystemRoot=$windows; WINDIR=$windows
        SystemDrive=[IO.Path]::GetPathRoot($windows).TrimEnd('\')
        ComSpec=[IO.Path]::Combine($system,'cmd.exe'); PATHEXT='.COM;.EXE;.BAT;.CMD'
        PATH=($system+';'+$windows+';'+[IO.Path]::Combine($system,'Wbem')+';'+[IO.Path]::Combine($system,'WindowsPowerShell\v1.0'))
        PSModulePath=[IO.Path]::Combine($system,'WindowsPowerShell\v1.0\Modules')
    }
    foreach ($pair in @(@('ProgramFiles','ProgramFiles'), @('ProgramFiles(x86)','ProgramFilesX86'),
            @('ProgramData','CommonApplicationData'), @('USERPROFILE','UserProfile'),
            @('LOCALAPPDATA','LocalApplicationData'), @('APPDATA','ApplicationData'))) {
        $value = [Environment]::GetFolderPath([Environment+SpecialFolder]$pair[1])
        if ([string]::IsNullOrWhiteSpace($value) -or $value -notmatch '^[A-Za-z]:\\') {
            throw ('Windows could not establish a trusted '+$pair[0]+' directory.')
        }
        $safe[$pair[0]] = $value
    }
    $safe.ProgramW6432 = $safe.ProgramFiles
    $safe.TEMP = [IO.Path]::Combine($safe.LOCALAPPDATA,'Temp'); $safe.TMP = $safe.TEMP
    # Exact allowlist: inherited module/profiler/proxy/gh configuration and
    # credentials cannot select code or a verification endpoint in child tools.
    foreach ($name in @([Environment]::GetEnvironmentVariables().Keys)) {
        [Environment]::SetEnvironmentVariable([string]$name, $null, 'Process')
    }
    foreach ($name in $safe.Keys) {
        [Environment]::SetEnvironmentVariable([string]$name, [string]$safe[$name], 'Process')
    }
}

function ConvertTo-ReleaseProcessArgument([string]$Value) {
    if ($Value.Contains([string][char]0) -or $Value.Contains([string][char]10) -or
            $Value.Contains([string][char]13)) { throw 'Release argument contains a control character.' }
    # Windows CommandLineToArgvW quoting, including embedded quotes and trailing
    # backslashes. Start-Process joins its array argument; pass ONE quoted string.
    $encoded = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
    $encoded = [regex]::Replace($encoded, '(\\+)$', '$1$1')
    return '"'+$encoded+'"'
}

function Open-ProtectedReleaseInstallLease([string]$TargetRoot) {
    Assert-ProtectedPath $TargetRoot $true
    $path = Join-Path $TargetRoot '.release-install.lock'
    if (Test-Path -LiteralPath $path) { Assert-ProtectedPath $path $false }
    # One fixed protected path across users, GUI/manual entry and staging roots.
    # FileShare.Read denies another writable opener, including the same process.
    # Do not delete/recreate the file: its retained object is the lease authority.
    $lease = $null
    try {
        $lease = [IO.FileStream]::new($path, [IO.FileMode]::OpenOrCreate,
            ([Security.AccessControl.FileSystemRights]::Read -bor
                [Security.AccessControl.FileSystemRights]::Write),
            [IO.FileShare]::Read, 4096, [IO.FileOptions]::None, (New-ProtectedAcl $false))
        Assert-ProtectedPath $path $false
        return $lease
    } catch {
        if ($null -ne $lease) { $lease.Dispose() }
        throw ('Protected installation is busy or its lease custody is unavailable; ' +
            'no candidate or release floor was changed. '+$_.Exception.Message)
    }
}

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

function Assert-ProtectedAcl(
    [Security.AccessControl.FileSystemSecurity]$Acl,
    [string]$Label
) {
    $writeMask = (
        [Security.AccessControl.FileSystemRights]::WriteData -bor
        [Security.AccessControl.FileSystemRights]::AppendData -bor
        [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
        [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    )
    try {
        $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
            $Acl.GetSecurityDescriptorBinaryForm(), 0)
        if ($null -eq $descriptor.DiscretionaryAcl) {
            throw 'installed authority has an unrestricted NULL DACL'
        }
        $owner = $Acl.GetOwner(
            [Security.Principal.SecurityIdentifier])
        [void]$owner.Translate([Security.Principal.NTAccount])
        if ($owner.Value -notin $approvedCustodySids) {
            throw "owner $($owner.Value) is not SYSTEM or Administrators"
        }
        # Inspect both explicit and inherited rules. Safe read-only inheritance
        # from Program Files is retained, while inherited write is fail-closed.
        $rules = $Acl.GetAccessRules(
            $true, $true, [Security.Principal.SecurityIdentifier])
        foreach ($rule in $rules) {
            $sid = [Security.Principal.SecurityIdentifier]$rule.IdentityReference
            [void]$sid.Translate([Security.Principal.NTAccount])
            if ($rule.AccessControlType -ne
                    [Security.AccessControl.AccessControlType]::Allow -and
                    $rule.AccessControlType -ne
                    [Security.AccessControl.AccessControlType]::Deny) {
                throw "unsupported access-control entry for $($sid.Value)"
            }
            if ($rule.AccessControlType -eq
                    [Security.AccessControl.AccessControlType]::Allow -and
                    (($rule.FileSystemRights -band $writeMask) -ne 0) -and
                    $sid.Value -notin $approvedCustodySids) {
                throw "write-capable Allow ACE belongs to $($sid.Value)"
            }
        }
    } catch {
        throw "Protected custody ACL is invalid for ${Label}: $($_.Exception.Message)"
    }
}

function Assert-ProtectedPath([string]$Path, [bool]$Directory) {
    try {
        $expected = [IO.Path]::GetFullPath($Path)
        $before = Get-Item -LiteralPath $expected -Force -ErrorAction Stop
        if ([bool]$before.PSIsContainer -ne $Directory) {
            throw 'path type is not the expected regular file or directory'
        }
        if (-not $before.FullName.Equals(
                $expected, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'resolved path does not exactly match the protected path'
        }
        if (($before.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                ($before.PSObject.Properties.Name -contains 'LinkType' -and
                 -not [string]::IsNullOrEmpty([string]$before.LinkType))) {
            throw 'reparse points and linked authority paths are forbidden'
        }
        $beforeLength = if ($Directory) { -1L } else { [int64]$before.Length }
        $beforeWrite = $before.LastWriteTimeUtc.Ticks
        $acl = Get-Acl -LiteralPath $expected -ErrorAction Stop
        Assert-ProtectedAcl $acl $expected
        $after = Get-Item -LiteralPath $expected -Force -ErrorAction Stop
        $afterLength = if ($Directory) { -1L } else { [int64]$after.Length }
        if (-not $after.FullName.Equals(
                $expected, [StringComparison]::OrdinalIgnoreCase) -or
                $after.Attributes -ne $before.Attributes -or
                $afterLength -ne $beforeLength -or
                $after.LastWriteTimeUtc.Ticks -ne $beforeWrite) {
            throw 'path identity or metadata changed during custody inspection'
        }
    } catch {
        throw "Protected custody validation failed for ${Path}: $($_.Exception.Message)"
    }
}

function Get-CertificateSha256(
    [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
) {
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return (($sha256.ComputeHash($Certificate.RawData) |
            ForEach-Object { $_.ToString('x2') }) -join '')
    } finally {
        $sha256.Dispose()
    }
}

function Assert-PublisherSignature(
    [string]$Path,
    [string]$ExpectedCertificate
) {
    Assert-NotReparse $Path
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
            $null -eq $signature.SignerCertificate) {
        throw "Publisher signature is invalid: $Path"
    }
    $actual = Get-CertificateSha256 $signature.SignerCertificate
    if ($actual -ine $ExpectedCertificate) {
        throw "Publisher certificate identity is invalid: $Path"
    }
}

function Assert-SafeRelativePath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.Length -gt 240 -or
            $Path.Contains('\') -or $Path.Contains(':') -or
            [IO.Path]::IsPathRooted($Path)) {
        throw "Invalid release payload path: $Path"
    }
    foreach ($part in $Path.Split('/')) {
        if ([string]::IsNullOrWhiteSpace($part) -or $part -in @('.', '..')) {
            throw "Invalid release payload path: $Path"
        }
    }
}


function Assert-SafeReleaseDestination([string]$TargetRoot, [string]$RelativePath) {
    Assert-SafeRelativePath $RelativePath
    $root = [IO.Path]::GetFullPath($TargetRoot).TrimEnd('\')
    $destination = [IO.Path]::GetFullPath([IO.Path]::Combine($root,$RelativePath.Replace('/','\')))
    if (!$destination.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)) {
        throw 'Release destination escaped its protected installation.'
    }
    Assert-ProtectedPath $root $true
    $parts = $RelativePath.Split('/')
    if ($parts.Count -gt 64) { throw 'Release destination ancestry exceeds its bound.' }
    $cursor = $root
    for ($index=0; $index -lt $parts.Count-1; $index++) {
        $cursor = [IO.Path]::Combine($cursor,$parts[$index])
        if (!(Test-Path -LiteralPath $cursor)) { break }
        # An existing nested directory may select dependencies or redirect a
        # later copy. Reject unsafe custody; never Set-Acl repair it in place.
        Assert-ProtectedPath $cursor $true
    }
    if (Test-Path -LiteralPath $destination) { Assert-ProtectedPath $destination $false }
}

function Write-ReleaseRecoveryNotice([string]$Message) {
    # Recovery reporting must never replace the original installation error.
    try { Write-Warning -Message $Message -WarningAction Continue } catch {}
}

function Invoke-ReleasePayloadReplacement(
    [string]$TargetRoot,
    [string]$PayloadRoot,
    [string]$StageRoot,
    [string[]]$InstallPaths,
    $RecoveryState
) {
    # This helper is called only after the installed authority verifies the
    # candidate. It grants no release or rollback authority of its own.
    $seenPaths = @{}
    foreach ($relative in $InstallPaths) {
        Assert-SafeReleaseDestination $TargetRoot $relative
        $folded = $relative.ToLowerInvariant()
        if ($seenPaths.ContainsKey($folded)) {
            throw 'The verified installation path list contains a duplicate.'
        }
        $seenPaths[$folded] = $true
    }
    $backupRoot = Join-Path $StageRoot 'previous'
    [void](New-Item -ItemType Directory -Path $backupRoot)
    Set-Acl -LiteralPath $backupRoot -AclObject (New-ProtectedAcl $true)
    $RecoveryState.Phase = 'verified-payload-replacement'
    foreach ($relative in $InstallPaths) {
        $sourcePath = Join-Path $PayloadRoot ($relative.Replace('/', '\'))
        $destination = Join-Path $TargetRoot ($relative.Replace('/', '\'))
        $destinationParent = Split-Path -Parent $destination
        $backup = Join-Path $backupRoot ($relative.Replace('/', '\'))
        $backupParent = Split-Path -Parent $backup
        if (-not (Test-Path -LiteralPath $backupParent)) {
            [void](New-Item -ItemType Directory -Path $backupParent -Force)
        }
        $hadPrevious = Test-Path -LiteralPath $destination -PathType Leaf
        # Account for the current entry BEFORE any destination-side operation.
        # These labels are diagnostics, not retained file-object custody and
        # must never authorize removal or replacement of a recovery target.
        $entry = [pscustomobject]@{
            RelativePath = $relative
            HadPrevious = [bool]$hadPrevious
            PreviousMove = 'not-attempted'
            Copy = 'not-attempted'
            Acl = 'not-attempted'
            Recovery = 'not-authorized-no-file-object-custody'
        }
        [void]$RecoveryState.Entries.Add($entry)
        if (-not (Test-Path -LiteralPath $destinationParent)) {
            $RecoveryState.DestinationMutationAttempted = $true
            [void](New-Item -ItemType Directory -Path $destinationParent -Force)
        }
        Assert-SafeReleaseDestination $TargetRoot $relative
        if ($hadPrevious) {
            Assert-NotReparse $destination
            $RecoveryState.DestinationMutationAttempted = $true
            $entry.PreviousMove = 'attempted-outcome-unproven'
            Move-Item -LiteralPath $destination -Destination $backup
            $entry.PreviousMove = 'returned-success-not-object-attestation'
        } else {
            $entry.PreviousMove = 'not-required'
        }
        $RecoveryState.DestinationMutationAttempted = $true
        $entry.Copy = 'attempted-outcome-unproven'
        Copy-Item -LiteralPath $sourcePath -Destination $destination
        $entry.Copy = 'returned-success-not-object-attestation'
        $entry.Acl = 'attempted-outcome-unproven'
        Set-Acl -LiteralPath $destination -AclObject (New-ProtectedAcl $false)
        $entry.Acl = 'returned-success-not-runtime-verification'
    }
    # Paths or matching contents cannot prove ownership of a file generation.
    # No automatic destructive rollback is implemented here. In particular,
    # the previous release floor is evidence, never permission to downgrade.
    $RecoveryState.Phase = 'files-copied-startup-unverified'
}

function Select-AuthenticatedReleaseStartup {
    param([string]$TargetRoot, [hashtable]$ManifestPaths, [string]$Certificate)
    $name = if ($ManifestPaths.ContainsKey('angeronasafestart.exe')) {
        'AngeronaSafeStart.exe'
    } elseif ($ManifestPaths.ContainsKey('angeronastartup.exe')) {
        'AngeronaStartup.exe'
    } else {
        throw 'The authenticated release has no approved startup entry.'
    }
    $path = Join-Path $TargetRoot $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw 'The authenticated startup entry is missing or has an invalid type.'
    }
    Assert-ProtectedPath $path $false
    Assert-PublisherSignature $path $Certificate
    return $path
}

function Assert-AuthenticatedStartupBinding {
    param([string]$StartupPath)
    if ([IO.Path]::GetFileName($StartupPath) -ceq 'AngeronaSafeStart.exe') {
        & $StartupPath --verify-bootstrap
        if ($LASTEXITCODE -ne 0) {
            throw 'The authenticated native startup entry does not match its final startup helper bytes.'
        }
    }
}

function Assert-InstalledCustody {
    if (-not (Test-Path -LiteralPath $target -PathType Container)) {
        throw ('The portable package is upgrade-only. First installation requires the ' +
            'signed Angerona MSIX with an OS-enforced package identity.')
    }
    Assert-ProtectedPath $target $true
    foreach ($name in $installedCustodyNames) {
        $path = Join-Path $target $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "The protected installed authority or evidence is incomplete: $name"
        }
        Assert-ProtectedPath $path $false
    }
    # Prior releases did not include the startup helper. When present it is
    # executable authority and must have the same protected custody.
    $installedStartup = Join-Path $target 'AngeronaStartup.exe'
    if (Test-Path -LiteralPath $installedStartup) {
        if (-not (Test-Path -LiteralPath $installedStartup -PathType Leaf)) {
            throw 'The protected installed startup helper has an invalid path type.'
        }
        Assert-ProtectedPath $installedStartup $false
    }
    $installedSafeStart = Join-Path $target 'AngeronaSafeStart.exe'
    if (Test-Path -LiteralPath $installedSafeStart) {
        if (-not (Test-Path -LiteralPath $installedSafeStart -PathType Leaf)) {
            throw 'The protected installed native startup entry has an invalid path type.'
        }
        Assert-ProtectedPath $installedSafeStart $false
    }
    $floor = Join-Path $target 'release-floor.json'
    if (Test-Path -LiteralPath $floor) {
        if (-not (Test-Path -LiteralPath $floor -PathType Leaf)) {
            throw 'The protected release floor has an invalid path type.'
        }
        Assert-ProtectedPath $floor $false
    }

    $publisherPath = Join-Path $target 'publisher-certificate.sha256'
    $certificate = (
        Get-Content -LiteralPath $publisherPath -Raw).Trim().ToLowerInvariant()
    if ($certificate -notmatch '^[0-9a-f]{64}$') {
        throw 'The protected publisher-certificate identity is invalid.'
    }
    Assert-PublisherSignature $trustedAuthorizationVerifier $certificate
    Assert-PublisherSignature (Join-Path $target 'Angerona.exe') $certificate
    if (Test-Path -LiteralPath $installedStartup -PathType Leaf) {
        Assert-PublisherSignature $installedStartup $certificate
    }
    if (Test-Path -LiteralPath $installedSafeStart -PathType Leaf) {
        Assert-PublisherSignature $installedSafeStart $certificate
    }
    Assert-PublisherSignature (Join-Path $target 'release-payload.cat') $certificate
    return $certificate
}

Initialize-ReleaseChildEnvironment
$releaseHost = Get-ReleaseSystemPowerShell
$actualReleaseHost = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
if (![string]::Equals($actualReleaseHost, $releaseHost, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Protected upgrade requires the trusted native Windows PowerShell host.'
}
Assert-ReleaseAuthorityPath $trustedInstaller
Assert-ReleaseAuthorityPath $trustedVerifier
Assert-ReleaseAuthorityPath $trustedAuthorizationVerifier

$publisherCertificate = Assert-InstalledCustody
$runningInstaller = [IO.Path]::GetFullPath($MyInvocation.MyCommand.Path)
if (-not $runningInstaller.Equals(
        [IO.Path]::GetFullPath($trustedInstaller),
        [StringComparison]::OrdinalIgnoreCase)) {
    throw ('Portable upgrades must be launched through the protected installed ' +
        'Install-Angerona-Release.ps1, never a script from the candidate bundle.')
}
$installedTrust = Join-Path $target 'release-trust.json'

if ($CustodyPreflightOnly) {
    Write-Host 'PASS: protected installed upgrade custody verified.' `
        -ForegroundColor Green
    exit 0
}

if ([string]::IsNullOrWhiteSpace($ReleaseArchive)) {
    throw 'The protected upgrade requires an original Angerona release ZIP.'
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Administrator privileges are required.'
}

$recoveryState = [pscustomobject]@{
    Phase = 'pre-mutation-staging'
    DestinationMutationAttempted = $false
    Entries = [Collections.Generic.List[object]]::new()
}
$upgradeFailure = $null
$installedStartupPath = $null
$stage = $null
$installLease = $null
try {
    $installLease = Open-ProtectedReleaseInstallLease $target
    # The unelevated migration wrapper performs this same check before requesting
    # elevation. Repeat it in the elevated process immediately before any staging
    # directory or destination is created, so privilege handoff cannot carry stale
    # custody evidence into mutation.
    $publisherCertificate = Assert-InstalledCustody

    $archive = [IO.Path]::GetFullPath($ReleaseArchive)
    if ([IO.Path]::GetExtension($archive) -ine '.zip') {
        throw 'The portable upgrade input must be the original Angerona release ZIP.'
    }
    if (-not (Test-Path -LiteralPath $archive -PathType Leaf)) {
        throw 'The portable release ZIP is missing.'
    }
    Assert-NotReparse $archive
    $archiveChecksum = $archive + '.sha256'
    if (-not (Test-Path -LiteralPath $archiveChecksum -PathType Leaf)) {
        throw 'The portable release ZIP checksum is missing.'
    }
    Assert-NotReparse $archiveChecksum

    $stage = Join-Path $target ('.installing-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -ItemType Directory -Path $stage)
    Set-Acl -LiteralPath $stage -AclObject (New-ProtectedAcl $true)
    $stagedArchive = Join-Path $stage ([IO.Path]::GetFileName($archive))
    Copy-Item -LiteralPath $archive -Destination $stagedArchive
    Copy-Item -LiteralPath $archiveChecksum -Destination ($stagedArchive + '.sha256')
    Set-Acl -LiteralPath $stagedArchive -AclObject (New-ProtectedAcl $false)
    Set-Acl -LiteralPath ($stagedArchive + '.sha256') `
        -AclObject (New-ProtectedAcl $false)

    # The already protected verifier authenticates the exact protected copy.
    $powerShell = Join-Path ([Environment]::SystemDirectory) `
        'WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $powerShell -PathType Leaf)) {
        throw 'Trusted Windows PowerShell is unavailable.'
    }
    & $powerShell -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned `
        -File $trustedVerifier -Artifact $stagedArchive
    if ($LASTEXITCODE -ne 0) {
        throw 'Protected portable archive verification failed.'
    }

    $payloadRoot = Join-Path $stage 'payload'
    [void](New-Item -ItemType Directory -Path $payloadRoot)
    Set-Acl -LiteralPath $payloadRoot -AclObject (New-ProtectedAcl $true)
    Expand-Archive -LiteralPath $stagedArchive -DestinationPath $payloadRoot
    Get-ChildItem -LiteralPath $payloadRoot -Recurse -Force |
        ForEach-Object {
            if (($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "The portable payload contains a reparse point: $($_.FullName)"
            }
        }

    $releaseFilesPath = Join-Path $payloadRoot 'release-files.sha256'
    if (-not (Test-Path -LiteralPath $releaseFilesPath -PathType Leaf)) {
        throw 'release-files.sha256 is missing; refusing an incomplete release.'
    }
    $expected = @{}
    foreach ($line in Get-Content -LiteralPath $releaseFilesPath) {
        if ($line -notmatch '^([0-9a-fA-F]{64})  ([A-Za-z0-9.-]+)$') {
            throw "Invalid release evidence manifest entry: $line"
        }
        $name = $Matches[2]
        if ($name -notin $requiredEvidence -or $expected.ContainsKey($name)) {
            throw 'The release evidence manifest has an unexpected or duplicate entry.'
        }
        $expected[$name] = $Matches[1].ToLowerInvariant()
    }
    if ($expected.Count -ne $requiredEvidence.Count) {
        throw 'The release evidence manifest is incomplete.'
    }
    foreach ($name in $requiredEvidence) {
        $path = Join-Path $payloadRoot $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "$name is missing."
        }
        Assert-NotReparse $path
        $actual = (
            Get-FileHash -LiteralPath $path -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        if ($actual -ne $expected[$name]) {
            throw "$name failed release evidence verification."
        }
    }

    $incomingTrustHash = $expected['release-trust.json']
    $installedTrustHash = (
        Get-FileHash -LiteralPath $installedTrust -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    if ($installedTrustHash -ne $incomingTrustHash) {
        throw 'Publisher trust-root rotation is not authorized by the ordinary installer.'
    }
    $incomingPublisher = (
        Get-Content -LiteralPath (
            Join-Path $payloadRoot 'publisher-certificate.sha256') -Raw
    ).Trim().ToLowerInvariant()
    if ($incomingPublisher -ne $publisherCertificate) {
        throw 'Publisher certificate rotation is not authorized by the ordinary installer.'
    }

    foreach ($name in @(
            'Angerona.exe', 'AngeronaStartup.exe', 'AngeronaBlackBox.exe',
            'AngeronaReleaseVerifier.exe', 'release-payload.cat')) {
        Assert-PublisherSignature (
            Join-Path $payloadRoot $name) $publisherCertificate
    }

    $payloadManifestPath = Join-Path $payloadRoot 'release-payload-manifest.json'
    if ((Get-Item -LiteralPath $payloadManifestPath).Length -gt 2MB) {
        throw 'The release payload manifest exceeds its byte budget.'
    }
    $payloadManifest = Get-Content -LiteralPath $payloadManifestPath -Raw |
        ConvertFrom-Json
    $manifestFields = @($payloadManifest.PSObject.Properties.Name)
    if ($manifestFields.Count -ne 2 -or
            'schema' -notin $manifestFields -or 'files' -notin $manifestFields -or
            $payloadManifest.schema -ne 'angerona.release-payload/v1') {
        throw 'The release payload manifest schema is invalid.'
    }
    $entries = @($payloadManifest.files)
    if ($entries.Count -lt 1 -or $entries.Count -gt 4096) {
        throw 'The release payload manifest file list is not bounded.'
    }
    $seen = @{}
    $previous = ''
    foreach ($entry in $entries) {
        $fields = @($entry.PSObject.Properties.Name)
        if ($fields.Count -ne 3 -or 'path' -notin $fields -or
                'sha256' -notin $fields -or 'size' -notin $fields) {
            throw 'A release payload manifest entry has an invalid schema.'
        }
        Assert-SafeRelativePath $entry.path
        if ($entry.sha256 -notmatch '^[0-9a-f]{64}$' -or
                $entry.size -isnot [ValueType] -or [int64]$entry.size -lt 0) {
            throw 'A release payload manifest entry has invalid evidence.'
        }
        $folded = $entry.path.ToLowerInvariant()
        if ($seen.ContainsKey($folded) -or
                ($previous -ne '' -and
                 [string]::CompareOrdinal($entry.path, $previous) -le 0)) {
            throw 'Release payload manifest paths are duplicate or unsorted.'
        }
        $seen[$folded] = $true
        $previous = $entry.path
        $path = Join-Path $payloadRoot ($entry.path.Replace('/', '\'))
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Release payload file is missing: $($entry.path)"
        }
        Assert-NotReparse $path
        $item = Get-Item -LiteralPath $path
        if ($item.Length -ne [int64]$entry.size -or
                (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ine
                    $entry.sha256) {
            throw "Release payload file failed manifest verification: $($entry.path)"
        }
    }
    foreach ($name in @(
            'Angerona.exe', 'AngeronaStartup.exe', 'AngeronaBlackBox.exe',
            'AngeronaReleaseVerifier.exe', 'Angerona-SBOM.json',
            'publisher-certificate.sha256', 'Install-Angerona-Release.ps1',
            'Install-Angerona-Release.bat', 'Verify-Angerona-Release.ps1')) {
        if (-not $seen.ContainsKey($name.ToLowerInvariant())) {
            throw "The signed release payload omits required file $name."
        }
    }
    if ($seen.ContainsKey('angeronasafestart.exe')) {
        Assert-PublisherSignature (
            Join-Path $payloadRoot 'AngeronaSafeStart.exe') $publisherCertificate
    }

    # Reconstruct exactly the set signed by the Windows catalog, excluding all
    # later authorization metadata, and validate it before any target mutation.
    $catalogPayload = Join-Path $stage 'catalog-payload'
    [void](New-Item -ItemType Directory -Path $catalogPayload)
    Set-Acl -LiteralPath $catalogPayload -AclObject (New-ProtectedAcl $true)
    foreach ($entry in $entries) {
        $sourcePath = Join-Path $payloadRoot ($entry.path.Replace('/', '\'))
        $destination = Join-Path $catalogPayload ($entry.path.Replace('/', '\'))
        $parent = Split-Path -Parent $destination
        if (-not (Test-Path -LiteralPath $parent)) {
            [void](New-Item -ItemType Directory -Path $parent -Force)
        }
        Copy-Item -LiteralPath $sourcePath -Destination $destination
    }
    Copy-Item -LiteralPath $payloadManifestPath -Destination (
        Join-Path $catalogPayload 'release-payload-manifest.json')
    $catalogResult = Test-FileCatalog -Path $catalogPayload -CatalogFilePath (
        Join-Path $payloadRoot 'release-payload.cat') -Detailed
    if ($catalogResult.Status -ne [Management.Automation.CatalogValidationStatus]::Valid) {
        throw "The signed payload catalog is invalid: $($catalogResult.Status)"
    }

    # Only the already installed, ACL-protected native verifier may authenticate
    # the threshold authorization and advance the monotonic release floor. This
    # runs entirely in staging before any destination file is moved or replaced.
    $nextFloor = Join-Path $payloadRoot 'release-floor.json'
    & $trustedAuthorizationVerifier `
        --candidate-root $payloadRoot `
        --installed-root $target `
        --floor-output $nextFloor
    if ($LASTEXITCODE -ne 0 -or
            -not (Test-Path -LiteralPath $nextFloor -PathType Leaf)) {
        throw 'Threshold release authorization or anti-rollback verification failed.'
    }
    Assert-NotReparse $nextFloor
    Set-Acl -LiteralPath $nextFloor -AclObject (New-ProtectedAcl $false)

    # Only authenticated manifest membership selects a launch entry. An absent
    # declared modern wrapper never authorizes falling through to an old helper.
    $authenticatedStartupPaths = @{} + $seen
    # Execute only from the catalog reconstruction. The raw archive directory
    # can contain unlisted CLR configuration or assemblies beside a valid EXE.
    $stagedStartupPath = Select-AuthenticatedReleaseStartup -TargetRoot $catalogPayload `
        -ManifestPaths $authenticatedStartupPaths -Certificate $publisherCertificate
    Assert-AuthenticatedStartupBinding $stagedStartupPath

    $installPaths = @($entries | ForEach-Object { $_.path }) + @(
        'release-payload-manifest.json',
        'release-payload.cat',
        'release-build-provenance.json',
        'release-authorization.json',
        'release-trust.json',
        'release-files.sha256',
        'release-floor.json'
    )
    Invoke-ReleasePayloadReplacement -TargetRoot $target -PayloadRoot $payloadRoot `
        -StageRoot $stage -InstallPaths $installPaths -RecoveryState $recoveryState
    Set-Acl -LiteralPath $target -AclObject (New-ProtectedAcl $true)
    $installedStartupPath = Select-AuthenticatedReleaseStartup -TargetRoot $target `
        -ManifestPaths $authenticatedStartupPaths -Certificate $publisherCertificate
    Assert-AuthenticatedStartupBinding $installedStartupPath

    $shortcutPath = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Angerona.lnk'
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $installedStartupPath
    $shortcut.WorkingDirectory = $target
    $shortcut.IconLocation = (Join-Path $target 'Angerona.exe') + ',0'
    $shortcut.Save()

    Write-Host "Authorized Angerona upgrade files copied to $target; startup verification pending." `
        -ForegroundColor Yellow
    Start-Process -FilePath $installedStartupPath
} catch {
    $upgradeFailure = $_
    if ($recoveryState.DestinationMutationAttempted) {
        $recoveryState.Phase = 'recovery-required-no-automatic-rollback'
        Write-ReleaseRecoveryNotice (
            "Upgrade failed after destination mutation was attempted. " +
            "No automatic rollback is authorized; review $stage. " +
            "Accounted entries: $($recoveryState.Entries.Count). " +
            'Do not replace the protected release floor from a backup.')
    }
    throw
} finally {
    try {
        if ($recoveryState.DestinationMutationAttempted) {
            # Preserve the complete protected stage on failure, unknown outcomes,
            # AND apparent copy success. Start-Process is not a health receipt.
            # Never delete a candidate, backup, or replaced generation by path/hash.
            Write-ReleaseRecoveryNotice (
                "Recovery material retained at $stage; state: $($recoveryState.Phase). " +
                'Startup health and recovery reconciliation remain unverified.')
        } elseif ($null -ne $stage) {
            # No destination-side operation was attempted. Keep the existing
            # protected pre-mutation staging cleanup; failed cleanup must not mask
            # the primary verification/installation exception.
            try {
                $stageFull = [IO.Path]::GetFullPath($stage)
                $targetPrefix = $target.TrimEnd('\') + '\'
                if ($stageFull.StartsWith(
                        $targetPrefix, [StringComparison]::OrdinalIgnoreCase) -and
                        (Test-Path -LiteralPath $stageFull)) {
                    Assert-NotReparse $stageFull
                    Remove-Item -LiteralPath $stageFull -Recurse -Force
                }
            } catch {
                if ($null -eq $upgradeFailure) { throw }
                Write-ReleaseRecoveryNotice (
                    "Pre-mutation staging cleanup was not proven; retained path: $stage")
            }
        }
    } finally {
        if ($null -ne $installLease) { $installLease.Dispose(); $installLease = $null }
    }
}
