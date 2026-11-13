[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Artifact,

    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedPublisherCertificateSha256 = '',

    [ValidatePattern('^(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})$')]
    [string]$ExpectedVersion,

    [switch]$Launch
)

$ErrorActionPreference = 'Stop'
$repository = 'Ag3nt47/AngeronaSuite'
$embeddedPublisherCertificateSha256 = '__ANGERONA_PUBLISHER_CERT_SHA256__'


function Resolve-ReleaseVerificationVersion([string]$Name, [string]$Expected) {
    $versionPattern = '(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})'
    if ($Expected -and $Expected -cnotmatch ('^'+$versionPattern+'$')) {
        throw 'Expected release version must be an exact major.minor.patch value.'
    }
    $namedVersion = ''
    if ($Name -cmatch ('^Angerona-v?('+$versionPattern+')-win64\.(?:msix|zip)$')) {
        $namedVersion = $Matches[1]
    }
    if ($Expected) {
        if ($namedVersion -and $namedVersion -cne $Expected) {
            throw 'The artifact name disagrees with the expected release version.'
        }
        return $Expected
    }
    if (!$namedVersion) {
        throw 'An exact -ExpectedVersion is required for a renamed artifact or migration Setup.'
    }
    return $namedVersion
}

function Assert-ReleaseBuildAttestation([string]$GhPath, [string]$ArtifactPath, [string]$Version) {
    $checkedVersion = Resolve-ReleaseVerificationVersion '' $Version
    & $GhPath attestation verify $ArtifactPath --repo 'Ag3nt47/AngeronaSuite' `
        --hostname 'github.com' `
        --signer-workflow 'Ag3nt47/AngeronaSuite/.github/workflows/release.yml' `
        --source-ref ('refs/tags/v'+$checkedVersion) --deny-self-hosted-runners
    if ($LASTEXITCODE -ne 0) {
        throw 'GitHub build-provenance attestation failed the exact release workflow and version policy.'
    }
}



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


function Get-ReleaseGitHubCli {
    $candidates = @(
        (Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'GitHub CLI\gh.exe'),
        (Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'GitHub CLI\gh.exe')
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            $candidate = [IO.Path]::GetFullPath($candidate)
            Assert-ReleaseAuthorityPath $candidate
            return $candidate
        }
    }
    throw 'A protected GitHub CLI is required to verify the Sigstore-backed build attestation.'
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


function Assert-ReleaseStageDirectory([string]$Path, [switch]$Container) {
    $full = [IO.Path]::GetFullPath($Path)
    if ($full -notmatch '^[A-Za-z]:\\') { throw 'Verification staging requires a fixed local path.' }
    $before = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if (!$before.PSIsContainer -or ($before.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            ![string]::Equals($before.FullName,$full,[StringComparison]::OrdinalIgnoreCase)) {
        throw 'Verification staging contains a redirected or non-directory ancestor.'
    }
    $write = $before.LastWriteTimeUtc.Ticks
    $attributes = $before.Attributes
    $acl = Get-Acl -LiteralPath $full -ErrorAction Stop
    if (!$Container) { Assert-ReleaseAuthorityAcl $acl $full $false }
    else {
        # KnownFolder containers may allow unrelated child creation. They may
        # never allow an unrelated owner, replacement, DACL or ownership change.
        $approved = @('S-1-5-18','S-1-5-32-544',
            'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
        $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(),0)
        if ($owner -notin $approved -or $null -eq $descriptor.DiscretionaryAcl) {
            throw 'Verification container owner or DACL is unsafe.'
        }
        foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            if (($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
            if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
                    ([long]$rule.FileSystemRights -band 0x500d0040L) -ne 0 -and
                    $rule.IdentityReference.Value -notin $approved) {
                throw 'Verification container permits unrelated replacement.'
            }
        }
    }
    $after = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if (!$after.PSIsContainer -or $after.Attributes -ne $attributes -or
            $after.LastWriteTimeUtc.Ticks -ne $write -or
            ![string]::Equals($after.FullName,$full,[StringComparison]::OrdinalIgnoreCase)) {
        throw 'Verification staging ancestor changed during custody inspection.'
    }
}

function New-ReleaseStageDirectory([string]$Path, [switch]$Exclusive) {
    if (Test-Path -LiteralPath $Path) {
        if ($Exclusive) { throw 'Verification stage already exists; it was preserved.' }
        Assert-ReleaseStageDirectory $Path
        return
    }
    # DirectorySecurity is supplied to native directory creation. Existing
    # directories are never Set-Acl repaired; a raced creation must pass custody.
    [void][IO.Directory]::CreateDirectory($Path, (New-ProtectedAcl $true))
    Assert-ReleaseStageDirectory $Path
}

function Initialize-ReleaseVerificationRoot([switch]$ExistingOnly) {
    $base = [IO.Path]::GetFullPath([Environment]::GetFolderPath('CommonApplicationData'))
    $chain = [Collections.Generic.List[string]]::new()
    $cursor = $base
    while ($cursor) {
        if ($chain.Count -ge 64) { throw 'Verification container ancestry exceeds its bound.' }
        $chain.Add($cursor); $cursor = [IO.Path]::GetDirectoryName($cursor)
    }
    for ($index=$chain.Count-1; $index -ge 0; $index--) {
        Assert-ReleaseStageDirectory $chain[$index] -Container
    }
    $parent = [IO.Path]::Combine($base,'Angerona')
    if ($ExistingOnly) { Assert-ReleaseStageDirectory $parent }
    else { New-ReleaseStageDirectory $parent }
    $root = [IO.Path]::Combine($parent,'ReleaseVerification')
    if ($ExistingOnly) { Assert-ReleaseStageDirectory $root }
    else { New-ReleaseStageDirectory $root }
    return $root
}

function Copy-RetainedReleaseStageFile([string]$Source, [string]$Target, [long]$Maximum) {
    Assert-ReleaseStageDirectory ([IO.Path]::GetDirectoryName($Target))
    $inputStream = $null; $outputStream = $null; $retained = $null
    try {
        $inputStream = [IO.File]::Open($Source,'Open','Read','Read')
        if ($inputStream.Length -lt 1 -or $inputStream.Length -gt $Maximum) {
            throw 'The release input exceeds its permitted byte budget.'
        }
        $expectedLength = $inputStream.Length
        # The file has its final protected DACL BEFORE the first untrusted byte.
        $outputStream = [IO.FileStream]::new($Target,[IO.FileMode]::CreateNew,
            [Security.AccessControl.FileSystemRights]::Write,[IO.FileShare]::Read,
            65536,[IO.FileOptions]::None,(New-ProtectedAcl $false))
        $inputStream.CopyTo($outputStream,65536)
        $outputStream.Flush($true)
        if ($outputStream.Length -ne $expectedLength) { throw 'The protected release copy was incomplete.' }
        $outputStream.Dispose(); $outputStream = $null
        # The protected parent and no-replacement ancestry make reopening safe.
        # Keep read access while denying every writer/deleter through launch.
        $retained = [IO.File]::Open($Target,'Open','Read','Read')
        $item = Get-Item -LiteralPath $Target -Force -ErrorAction Stop
        if ($item.PSIsContainer -or $item.Length -ne $expectedLength -or
                ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                ($item.PSObject.Properties.Name -contains 'LinkType' -and
                 ![string]::IsNullOrEmpty([string]$item.LinkType))) {
            throw 'The protected release copy has unexpected custody.'
        }
        Assert-ReleaseAuthorityAcl (Get-Acl -LiteralPath $Target -ErrorAction Stop) $Target $false
        $result = $retained; $retained = $null
        return $result
    } finally {
        if ($null -ne $retained) { $retained.Dispose() }
        if ($null -ne $outputStream) { $outputStream.Dispose() }
        if ($null -ne $inputStream) { $inputStream.Dispose() }
    }
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

Initialize-ReleaseChildEnvironment
$releaseHost = Get-ReleaseSystemPowerShell
$actualReleaseHost = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
if (![string]::Equals($actualReleaseHost, $releaseHost, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Release verification requires the trusted native Windows PowerShell host.'
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

$stageRoot = Initialize-ReleaseVerificationRoot
$stage = [IO.Path]::Combine($stageRoot,[guid]::NewGuid().ToString('N'))
New-ReleaseStageDirectory $stage -Exclusive
$artifactLease = $null; $checksumLease = $null
try {
    $stagedArtifact = [IO.Path]::Combine($stage,[IO.Path]::GetFileName($candidate))
    $stagedChecksum = $stagedArtifact + '.sha256'
    $artifactLease = Copy-RetainedReleaseStageFile $candidate $stagedArtifact 1073741824
    $checksumLease = Copy-RetainedReleaseStageFile $checksumPath $stagedChecksum 1024

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

    $ghPath = Get-ReleaseGitHubCli
    $releaseVersion = Resolve-ReleaseVerificationVersion ([IO.Path]::GetFileName($stagedArtifact)) $ExpectedVersion
    Assert-ReleaseBuildAttestation $ghPath $stagedArtifact $releaseVersion

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
    $closeErrors = [Collections.Generic.List[object]]::new()
    foreach ($lease in @($checksumLease,$artifactLease)) {
        if ($null -ne $lease) { try { $lease.Dispose() } catch { $closeErrors.Add($_) } }
    }
    if ($closeErrors.Count -ne 0) {
        throw 'Verification file custody could not be retired; the protected stage was preserved.'
    }
    $stageFull = [IO.Path]::GetFullPath($stage)
    $rootPrefix = $stageRoot.TrimEnd('\') + '\'
    if ($stageFull.StartsWith($rootPrefix,[StringComparison]::OrdinalIgnoreCase) -and
            [IO.Path]::GetFileName($stageFull) -cmatch '^[0-9a-f]{32}$' -and
            (Test-Path -LiteralPath $stageFull)) {
        # Re-admit every fixed parent before cleanup; changed custody preserves
        # evidence. Never harden a foreign parent and then delete through it.
        if ((Initialize-ReleaseVerificationRoot -ExistingOnly) -ne $stageRoot) { throw 'Verification namespace changed.' }
        Assert-ReleaseStageDirectory $stageFull
        Remove-Item -LiteralPath $stageFull -Recurse -Force
    }
}
