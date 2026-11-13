[CmdletBinding()]
param(
    [string]$GoExecutable = '',
    [string]$OutputPath = '',
    [switch]$SkipTests,
    [string]$CertificateThumbprint = '',
    [string]$ExpectedPublisher = ''
)

$ErrorActionPreference = 'Stop'
$sourceRoot = Split-Path -Parent $PSScriptRoot
$moduleRoot = Join-Path $sourceRoot 'frz/watchdog3'
if ([string]::IsNullOrWhiteSpace($GoExecutable)) {
    # Select the ApplicationInfo before assigning its scalar path to [string].
    # Multiple PATH matches must never be joined into one nonexistent filename.
    $goCommand = @(Get-Command go.exe -CommandType Application -ErrorAction Stop)[0]
    $GoExecutable = $goCommand.Source
}
$GoExecutable = [IO.Path]::GetFullPath($GoExecutable)
if (-not (Test-Path -LiteralPath $GoExecutable -PathType Leaf)) { throw 'Go compiler is unavailable.' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Join-Path $sourceRoot 'build/watchdog3/watchdog3.exe' }
$OutputPath = [IO.Path]::GetFullPath($OutputPath)
if ($OutputPath.StartsWith('\\') -or [IO.Path]::GetFileName($OutputPath) -cne 'watchdog3.exe') {
    throw 'Output must be a local watchdog3.exe artifact.'
}
$outputDirectory = Split-Path -Parent $OutputPath
New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
if (Test-Path -LiteralPath $OutputPath) {
    if (((Get-Item -LiteralPath $OutputPath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Refusing a reparse-backed build output.'
    }
}
$temporaryOutput = Join-Path $outputDirectory ('watchdog3-build-' + [Guid]::NewGuid().ToString('N') + '.exe')
$savedEnvironment = @{}
foreach ($name in @('CGO_ENABLED','GOOS','GOARCH','GOENV','GOTOOLCHAIN')) {
    $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
Push-Location $moduleRoot
try {
    $env:CGO_ENABLED='0'; $env:GOOS='windows'; $env:GOARCH='amd64'
    $env:GOENV='off'; $env:GOTOOLCHAIN='local'
    $goVersion = (& $GoExecutable version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $goVersion -notmatch '^go version go1\.(\d+)(?:\.\d+)? windows/amd64$' -or [int]$Matches[1] -lt 25) {
        throw 'A local Windows amd64 Go 1.25 or newer compiler is required.'
    }
    if (-not $SkipTests) {
        & $GoExecutable test -mod=readonly -timeout 180s ./...
        if ($LASTEXITCODE -ne 0) { throw 'Native watchdog tests failed; no artifact promoted.' }
        & $GoExecutable vet -mod=readonly ./...
        if ($LASTEXITCODE -ne 0) { throw 'Native watchdog vet failed; no artifact promoted.' }
    }
    & $GoExecutable build -mod=readonly -trimpath -buildvcs=false '-ldflags=-s -w' -o $temporaryOutput .
    if ($LASTEXITCODE -ne 0) { throw 'Native watchdog compilation failed.' }
    $signed = $false
    if (-not [string]::IsNullOrWhiteSpace($CertificateThumbprint)) {
        if ($CertificateThumbprint -notmatch '^[0-9A-Fa-f]{40}$' -or [string]::IsNullOrWhiteSpace($ExpectedPublisher)) {
            throw 'Signing requires an exact existing certificate thumbprint and expected publisher.'
        }
        $certificate = Get-Item -LiteralPath ('Cert:/CurrentUser/My/' + $CertificateThumbprint) -ErrorAction Stop
        if (-not $certificate.HasPrivateKey -or $certificate.Subject -cne $ExpectedPublisher) {
            throw 'Existing publisher signing authority does not match.'
        }
        $signature = Set-AuthenticodeSignature -LiteralPath $temporaryOutput -Certificate $certificate -HashAlgorithm SHA256
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -cne $ExpectedPublisher) {
            throw 'Signed watchdog verification failed.'
        }
        $signed = $true
    } elseif (-not [string]::IsNullOrWhiteSpace($ExpectedPublisher)) {
        throw 'A publisher name alone cannot authorize an unsigned build.'
    }
    & $temporaryOutput --version
    if ($LASTEXITCODE -ne 0) { throw 'Standalone native executable did not run.' }
    $sourceFiles = @(Get-ChildItem -LiteralPath $moduleRoot -File -Filter '*.go' | Where-Object { $_.Name -notlike '*_test.go' })
    $sourceFiles += Get-Item -LiteralPath (Join-Path $moduleRoot 'go.mod'),(Join-Path $moduleRoot 'go.sum')
    $inputs = @($sourceFiles | Sort-Object Name | ForEach-Object {
        [ordered]@{name=$_.Name;sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
    })
    $digest = (Get-FileHash -LiteralPath $temporaryOutput -Algorithm SHA256).Hash.ToLowerInvariant()
    $metadata = [ordered]@{
        schema=1;artifact='watchdog3.exe';language='Go';python_runtime_required=$false
        compiler=$goVersion;cgo_enabled=$false;sha256=$digest;signed=$signed
        publisher=$(if ($signed) { $ExpectedPublisher } else { '' })
        flags=@('-mod=readonly','-trimpath','-buildvcs=false','-ldflags=-s -w')
        source_inputs=$inputs
    }
    Move-Item -LiteralPath $temporaryOutput -Destination $OutputPath -Force
    Copy-Item -LiteralPath (Join-Path $moduleRoot 'THIRD_PARTY_NOTICES.md') -Destination ($OutputPath + '.NOTICE.txt')
    $metadata | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath ($OutputPath + '.build.json') -Encoding utf8
    [Console]::WriteLine(($metadata | ConvertTo-Json -Depth 6 -Compress))
} finally {
    Pop-Location
    foreach ($name in $savedEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process')
    }
}
