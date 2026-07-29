param(
    [Parameter(Mandatory = $true)]
    [string]$DataRoot
)

$ErrorActionPreference = "Stop"
$admins = New-Object Security.Principal.SecurityIdentifier("S-1-5-32-544")
$system = New-Object Security.Principal.SecurityIdentifier("S-1-5-18")

function New-ProtectedDirectory([string]$Path) {
    $security = New-Object Security.AccessControl.DirectorySecurity
    $security.SetAccessRuleProtection($true, $false)
    $security.SetOwner($admins)
    foreach ($sid in @($admins, $system)) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit",
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$security.AddAccessRule($rule)
    }
    # This overload applies the protected descriptor as the directory is
    # created; there is no inherited-permission exposure window.
    [void][IO.Directory]::CreateDirectory($Path, $security)
}

function Test-Protected([string]$Path) {
    $acl = Get-Acl -LiteralPath $Path
    $owner = (New-Object Security.Principal.NTAccount($acl.Owner)).Translate(
        [Security.Principal.SecurityIdentifier]
    ).Value
    $bad = @($acl.Access | Where-Object {
        $_.AccessControlType -ne "Allow" -or
        $_.IdentityReference.Translate(
            [Security.Principal.SecurityIdentifier]
        ).Value -notin @("S-1-5-18", "S-1-5-32-544")
    })
    return (
        $owner -in @("S-1-5-18", "S-1-5-32-544") -and
        $bad.Count -eq 0 -and
        $acl.AreAccessRulesProtected
    )
}

$existed = Test-Path -LiteralPath $DataRoot
if (-not $existed) {
    New-ProtectedDirectory $DataRoot
} elseif ((Get-Item -LiteralPath $DataRoot -Force).Attributes -band
          [IO.FileAttributes]::ReparsePoint) {
    throw "Refusing reparse-point runtime data root"
} elseif (-not (Test-Protected $DataRoot)) {
    # Close the directory boundary first, then quarantine all potentially
    # attacker-known authorities without ever accepting their bytes.
    & "$env:SystemRoot\System32\icacls.exe" $DataRoot /inheritance:r `
        /setowner "*S-1-5-32-544" /grant:r `
        "*S-1-5-18:(OI)(CI)(F)" "*S-1-5-32-544:(OI)(CI)(F)" /T /C | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Protected $DataRoot)) {
        throw "Unable to establish protected runtime data custody"
    }
    foreach ($name in @("bus.key", "shutdown.key")) {
        $key = Join-Path $DataRoot $name
        if (Test-Path -LiteralPath $key) {
            $rejected = "$key.rejected-$([Guid]::NewGuid().ToString('N'))"
            Move-Item -LiteralPath $key -Destination $rejected
        }
    }
}

if (-not (Test-Protected $DataRoot)) {
    throw "Protected runtime data custody verification failed"
}
