[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Artifact,

    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedPublisherCertificateSha256 = '',

    [switch]$Launch
)

$ErrorActionPreference = 'Stop'
$repository = 'Ag3nt47/AngeronaSuite'
$embeddedPublisherCertificateSha256 = '__ANGERONA_PUBLISHER_CERT_SHA256__'

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
    } else {
        foreach ($sid in @($admins, $system)) {
            $rule = [Security.AccessControl.FileSystemAccessRule]::new(
                $sid, [Security.AccessControl.FileSystemRights]::FullControl,
                [Security.AccessControl.AccessControlType]::Allow)
            [void]$acl.AddAccessRule($rule)
        }
    }
    return $acl
}

function Get-CertificateSha256([Security.Cryptography.X509Certificates.X509Certificate2]$Certificate) {
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha256.ComputeHash($Certificate.RawData)
        return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
    } finally {
        $sha256.Dispose()
    }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Administrator privileges are required for protected release staging.'
}

$candidate = [IO.Path]::GetFullPath($Artifact)
$candidateItem = Get-Item -LiteralPath $candidate -Force
if ($candidateItem.PSIsContainer -or
        ($candidateItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'The selected release artifact must be a regular non-reparse file.'
}
$extension = [IO.Path]::GetExtension($candidate).ToLowerInvariant()
if ($extension -notin @('.msix', '.exe', '.zip')) {
    throw 'Only an Angerona MSIX, migration Setup, or portable ZIP may be verified.'
}
$checksumPath = $candidate + '.sha256'
if (-not (Test-Path -LiteralPath $checksumPath -PathType Leaf)) {
    throw 'The adjacent SHA-256 file is missing.'
}
Assert-NotReparse $checksumPath

$programData = [IO.Path]::GetFullPath(
    [Environment]::GetFolderPath('CommonApplicationData'))
$stageRoot = [IO.Path]::GetFullPath(
    (Join-Path $programData 'Angerona\ReleaseVerification'))
if (-not $stageRoot.StartsWith(
        $programData.TrimEnd('\') + '\',
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'The protected verification root escaped ProgramData.'
}
if (-not (Test-Path -LiteralPath $stageRoot)) {
    [void](New-Item -ItemType Directory -Path $stageRoot -Force)
}
Assert-NotReparse $stageRoot
Set-Acl -LiteralPath $stageRoot -AclObject (New-ProtectedAcl $true)

$stage = [IO.Path]::GetFullPath(
    (Join-Path $stageRoot ([guid]::NewGuid().ToString('N'))))
[void](New-Item -ItemType Directory -Path $stage)
Set-Acl -LiteralPath $stage -AclObject (New-ProtectedAcl $true)
try {
    $stagedArtifact = Join-Path $stage ([IO.Path]::GetFileName($candidate))
    $stagedChecksum = $stagedArtifact + '.sha256'
    Copy-Item -LiteralPath $candidate -Destination $stagedArtifact
    Copy-Item -LiteralPath $checksumPath -Destination $stagedChecksum
    Set-Acl -LiteralPath $stagedArtifact -AclObject (New-ProtectedAcl $false)
    Set-Acl -LiteralPath $stagedChecksum -AclObject (New-ProtectedAcl $false)
    Assert-NotReparse $stagedArtifact
    Assert-NotReparse $stagedChecksum

    $line = (Get-Content -LiteralPath $stagedChecksum -Raw).Trim()
    if ($line -notmatch '^([0-9a-fA-F]{64})  ([^\\/]+)$') {
        throw 'The adjacent SHA-256 file has an invalid schema.'
    }
    if ($Matches[2] -cne [IO.Path]::GetFileName($stagedArtifact)) {
        throw 'The checksum does not name the selected artifact.'
    }
    $actual = (
        Get-FileHash -LiteralPath $stagedArtifact -Algorithm SHA256
    ).Hash
    if ($actual -ine $Matches[1]) {
        throw 'The staged release artifact failed SHA-256 verification.'
    }

    $ghCandidates = @(
        (Join-Path $env:ProgramFiles 'GitHub CLI\gh.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'GitHub CLI\gh.exe')
    )
    $ghPath = $ghCandidates |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
        Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($ghPath)) {
        throw 'GitHub CLI is required to verify the Sigstore-backed build attestation.'
    }
    $ghPath = [IO.Path]::GetFullPath($ghPath)
    Assert-NotReparse $ghPath
    & $ghPath attestation verify $stagedArtifact --repo $repository
    if ($LASTEXITCODE -ne 0) {
        throw 'GitHub build-provenance attestation verification failed.'
    }

    if ($extension -in @('.msix', '.exe')) {
        $expectedCertificate = $ExpectedPublisherCertificateSha256
        if ([string]::IsNullOrWhiteSpace($expectedCertificate)) {
            $expectedCertificate = $embeddedPublisherCertificateSha256
        }
        if ($expectedCertificate -notmatch '^[0-9a-fA-F]{64}$') {
            throw 'An exact trusted Angerona publisher-certificate SHA-256 is required.'
        }
        $signature = Get-AuthenticodeSignature -LiteralPath $stagedArtifact
        if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
                $null -eq $signature.SignerCertificate) {
            throw 'The staged Windows artifact has no valid publisher signature.'
        }
        $actualCertificate = Get-CertificateSha256 $signature.SignerCertificate
        if ($actualCertificate -ine $expectedCertificate) {
            throw 'The staged publisher certificate does not match the pinned identity.'
        }
    }

    Write-Host 'PASS: protected staged SHA-256 and GitHub attestation verified.' `
        -ForegroundColor Green
    if ($extension -in @('.msix', '.exe')) {
        Write-Host 'PASS: exact Authenticode publisher certificate verified.' `
            -ForegroundColor Green
    }
    if ($Launch) {
        if ($extension -ne '.exe') {
            throw '-Launch is supported only for the signed Windows Setup executable.'
        }
        $process = Start-Process -FilePath $stagedArtifact -Wait -PassThru
        if ($process.ExitCode -ne 0) {
            throw "Verified Setup exited with code $($process.ExitCode)."
        }
    }
} finally {
    $stageFull = [IO.Path]::GetFullPath($stage)
    $rootPrefix = $stageRoot.TrimEnd('\') + '\'
    if ($stageFull.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase) -and
            (Test-Path -LiteralPath $stageFull)) {
        Assert-NotReparse $stageFull
        Remove-Item -LiteralPath $stageFull -Recurse -Force
    }
}
