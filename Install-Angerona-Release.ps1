[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$ReleaseArchive = '',

    [switch]$CustodyPreflightOnly
)

$ErrorActionPreference = 'Stop'
$programFiles = [Environment]::GetFolderPath('ProgramFiles')
$target = [IO.Path]::GetFullPath((Join-Path $programFiles 'Angerona'))
$trustedInstaller = Join-Path $target 'Install-Angerona-Release.ps1'
$trustedVerifier = Join-Path $target 'Verify-Angerona-Release.ps1'
$trustedAuthorizationVerifier = Join-Path $target 'AngeronaReleaseVerifier.exe'
$requiredEvidence = @(
    'Angerona.exe',
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
    Assert-PublisherSignature (Join-Path $target 'release-payload.cat') $certificate
    return $certificate
}

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
try {
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
            'Angerona.exe', 'AngeronaBlackBox.exe',
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
            'Angerona.exe', 'AngeronaBlackBox.exe',
            'AngeronaReleaseVerifier.exe', 'Angerona-SBOM.json',
            'publisher-certificate.sha256', 'Install-Angerona-Release.ps1',
            'Install-Angerona-Release.bat', 'Verify-Angerona-Release.ps1')) {
        if (-not $seen.ContainsKey($name.ToLowerInvariant())) {
            throw "The signed release payload omits required file $name."
        }
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

    $installPaths = @($entries | ForEach-Object { $_.path }) + @(
        'release-payload-manifest.json',
        'release-payload.cat',
        'release-build-provenance.json',
        'release-authorization.json',
        'release-trust.json',
        'release-files.sha256',
        'release-floor.json'
    )
    $backupRoot = Join-Path $stage 'previous'
    [void](New-Item -ItemType Directory -Path $backupRoot)
    $installed = @()
    try {
        foreach ($relative in $installPaths) {
            Assert-SafeRelativePath $relative
            $sourcePath = Join-Path $payloadRoot ($relative.Replace('/', '\'))
            $destination = Join-Path $target ($relative.Replace('/', '\'))
            $destinationParent = Split-Path -Parent $destination
            if (-not (Test-Path -LiteralPath $destinationParent)) {
                [void](New-Item -ItemType Directory -Path $destinationParent -Force)
            }
            Assert-NotReparse $destinationParent
            $backup = Join-Path $backupRoot ($relative.Replace('/', '\'))
            $backupParent = Split-Path -Parent $backup
            if (-not (Test-Path -LiteralPath $backupParent)) {
                [void](New-Item -ItemType Directory -Path $backupParent -Force)
            }
            $hadPrevious = Test-Path -LiteralPath $destination -PathType Leaf
            if ($hadPrevious) {
                Assert-NotReparse $destination
                Move-Item -LiteralPath $destination -Destination $backup
            }
            try {
                Copy-Item -LiteralPath $sourcePath -Destination $destination
                Set-Acl -LiteralPath $destination -AclObject (New-ProtectedAcl $false)
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
    Set-Acl -LiteralPath $target -AclObject (New-ProtectedAcl $true)
} finally {
    $stageFull = [IO.Path]::GetFullPath($stage)
    $targetPrefix = $target.TrimEnd('\') + '\'
    if ($stageFull.StartsWith(
            $targetPrefix, [StringComparison]::OrdinalIgnoreCase) -and
            (Test-Path -LiteralPath $stageFull)) {
        Assert-NotReparse $stageFull
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

Write-Host "Verified Angerona upgrade installed to $target" -ForegroundColor Green
Start-Process -FilePath (Join-Path $target 'Angerona.exe')
