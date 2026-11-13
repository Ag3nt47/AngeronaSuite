[CmdletBinding()]
param([switch]$AsJson)

# Diagnostic only. This script does not run a candidate, request elevation,
# enroll a certificate, read a key, or install/change/start a service.

function New-AngeronaServiceReadinessReport {
    param([Parameter(Mandatory = $true)]$Snapshot)

    $gaps = [Collections.Generic.List[string]]::new()
    if (@($Snapshot.Packages).Count -eq 0) {
        $gaps.Add('NO_MATCHING_PACKAGE_OBSERVED')
    }
    foreach ($name in @('AngeronaProtection', 'AngeronaWatchdog3')) {
        if (@($Snapshot.Services | Where-Object { $_.Name -ceq $name }).Count -ne 1) {
            $gaps.Add(('SERVICE_NOT_OBSERVED:' + $name))
        }
    }
    if (-not $Snapshot.ConfigurationPresent) {
        $gaps.Add('WATCHDOG_CONFIGURATION_NOT_OBSERVED')
    }
    if ($Snapshot.CandidateSignature -cne 'Valid') {
        $gaps.Add('DEVELOPMENT_WATCHDOG_NOT_VALIDLY_SIGNED')
    }
    if (@($Snapshot.Errors).Count -gt 0) {
        $gaps.Add('OBSERVATION_INCOMPLETE')
    }
    [pscustomobject][ordered]@{
        Schema = 'angerona.windows-service-readiness/v1'
        ReadOnly = $true
        ActivationVerified = $false
        Observation = $(if ($gaps.Count) { 'prerequisites_missing_or_unverified' } else { 'external_acceptance_still_required' })
        Gaps = @($gaps.ToArray())
        LocalObservations = $Snapshot
        RequiredAcceptance = @(
            'Independently approved publisher, final signed executable pins and package identity',
            'Governed installer for the dedicated restricted virtual-account engine service',
            'Protected separate watchdog configuration, key/runtime and independent SCM registration',
            'Native validation and retained-process service/start/STOP/upgrade/uninstall acceptance in a disposable VM'
        )
        Limitations = @(
            'A present package, valid signature or running SCM state does not prove the approved publisher, installed custody or working sensors.',
            'Local certificate absence does not exclude cloud/HSM signing. No private key is accessed or exported.',
            'MSIX desktop6:Service cannot specify the engine virtual account; its built-in account choices do not satisfy the current engine contract.',
            'An administrator token alone is insufficient. This report is neither install authority nor a service-health attestation.'
        )
    }
}

function Get-AngeronaServiceReadiness {
    $errorsSeen = [Collections.Generic.List[string]]::new()
    $programData = [Environment]::GetFolderPath('CommonApplicationData')
    $root = Split-Path -Parent $PSScriptRoot
    $candidate = Join-Path $root 'build\watchdog3\watchdog3.exe'
    $config = Join-Path $programData 'Angerona\watchdog3\config.json'
    $services = @()
    try {
        $services = @(Get-CimInstance Win32_Service -Filter "Name='AngeronaProtection' OR Name='AngeronaWatchdog3'" -ErrorAction Stop |
            Select-Object Name, State, StartName, StartMode, PathName, ProcessId)
    } catch { $errorsSeen.Add('SERVICE_QUERY_UNAVAILABLE') }
    $packages = @()
    try {
        $packages = @(Get-AppxPackage -Name '*Angerona*' -ErrorAction Stop |
            Select-Object Name, PackageFamilyName, Publisher, SignatureKind, Status)
    } catch { $errorsSeen.Add('PACKAGE_QUERY_UNAVAILABLE') }
    $signature = 'Missing'
    try {
        if (Test-Path -LiteralPath $candidate -PathType Leaf -ErrorAction Stop) {
            $signature = [string](Get-AuthenticodeSignature -LiteralPath $candidate -ErrorAction Stop).Status
        }
    } catch { $signature = 'Unavailable'; $errorsSeen.Add('CANDIDATE_SIGNATURE_UNAVAILABLE') }
    $certificateCount = 0
    foreach ($store in @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')) {
        try {
            $certificateCount += @(Get-ChildItem -LiteralPath $store -CodeSigningCert -ErrorAction Stop).Count
        } catch { $errorsSeen.Add('LOCAL_CERTIFICATE_INVENTORY_PARTIAL') }
    }
    $configurationPresent = $false
    try {
        $configurationPresent = Test-Path -LiteralPath $config -PathType Leaf -ErrorAction Stop
    } catch { $errorsSeen.Add('CONFIGURATION_METADATA_UNAVAILABLE') }
    $administrator = $false
    $identity = $null
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        $administrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { $errorsSeen.Add('CURRENT_TOKEN_OBSERVATION_UNAVAILABLE') } finally {
        if ($null -ne $identity) {
            try { $identity.Dispose() } catch { $errorsSeen.Add('CURRENT_TOKEN_RETIREMENT_UNVERIFIED') }
        }
    }
    New-AngeronaServiceReadinessReport ([pscustomobject][ordered]@{
        Administrator = $administrator
        Services = $services
        Packages = $packages
        CandidateSignature = $signature
        ConfigurationPresent = $configurationPresent
        LocalCodeSigningCertificateCount = $certificateCount
        Errors = @($errorsSeen.ToArray())
    })
}

if ($MyInvocation.InvocationName -ne '.') {
    $report = Get-AngeronaServiceReadiness
    if ($AsJson) { $report | ConvertTo-Json -Depth 8 } else { $report }
}
