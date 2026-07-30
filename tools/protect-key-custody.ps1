param(
    [Parameter(Mandatory = $true)]
    [string]$DataRoot
)

$ErrorActionPreference = "Stop"
$admins = New-Object Security.Principal.SecurityIdentifier("S-1-5-32-544")
$system = New-Object Security.Principal.SecurityIdentifier("S-1-5-18")

function New-ProtectedDirectorySecurity {
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
    return $security
}

function New-ProtectedDirectory([string]$Path) {
    $security = New-ProtectedDirectorySecurity
    # This overload applies the protected descriptor as the directory is
    # created; there is no inherited-permission exposure window.
    [void][IO.Directory]::CreateDirectory($Path, $security)
}

function Get-OwnerSid([Security.AccessControl.FileSystemSecurity]$Acl) {
    return (New-Object Security.Principal.NTAccount($Acl.Owner)).Translate(
        [Security.Principal.SecurityIdentifier]
    ).Value
}

function Test-SafeAcl([string]$Path, [bool]$RequireProtected) {
    $acl = Get-Acl -LiteralPath $Path
    $owner = Get-OwnerSid $acl
    $bad = @($acl.Access | Where-Object {
        $_.AccessControlType -ne "Allow" -or
        $_.IdentityReference.Translate(
            [Security.Principal.SecurityIdentifier]
        ).Value -notin @("S-1-5-18", "S-1-5-32-544")
    })
    return (
        $owner -in @("S-1-5-18", "S-1-5-32-544") -and
        $bad.Count -eq 0 -and
        (-not $RequireProtected -or $acl.AreAccessRulesProtected)
    )
}

function Test-Protected([string]$Path) {
    return Test-SafeAcl $Path $true
}

function Assert-RootNotReparsePoint([string]$Path) {
    $root = Get-Item -LiteralPath $Path -Force
    if ($root.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Refusing reparse-point runtime data root"
    }
}

function Assert-NoReparsePoints([string]$Path) {
    Assert-RootNotReparsePoint $Path
    $item = Get-ChildItem -LiteralPath $Path -Force -Recurse `
        -Attributes ReparsePoint | Select-Object -First 1
    if ($null -ne $item) {
        throw "Refusing reparse point inside runtime data: $($item.FullName)"
    }
}

function Invoke-Icacls([string[]]$Arguments, [string]$Operation) {
    & "$env:SystemRoot\System32\icacls.exe" @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to $Operation (icacls exit code $LASTEXITCODE)"
    }
}

$custodyMarker = Join-Path $DataRoot ".custody-v1"
Write-Host "[*] Checking protected runtime data custody..."
$existed = Test-Path -LiteralPath $DataRoot
if (-not $existed) {
    New-ProtectedDirectory $DataRoot
    [IO.File]::WriteAllText($custodyMarker, "protected-v1")
} elseif (-not (Test-Protected $DataRoot) -or
          -not (Test-Path -LiteralPath $custodyMarker -PathType Leaf)) {
    Write-Host "[*] One-time runtime data migration is required."
    # Validate the root itself before changing it, then close its DACL before
    # traversing descendants. Old scanner/test directories can legitimately
    # have tighter ACLs than the interactive account; walking them first made
    # startup fail with AccessDenied before custody could repair the tree.
    Assert-RootNotReparsePoint $DataRoot

    # Close the root boundary atomically before walking attacker-influenced
    # descendants. Ownership and DACL changes are separate icacls command
    # forms on Windows; combining /setowner with /inheritance or /grant makes
    # icacls reject the request as an invalid parameter.
    Set-Acl -LiteralPath $DataRoot -AclObject (New-ProtectedDirectorySecurity)
    Write-Host "    Taking protected ownership (this can take a moment)..."
    Invoke-Icacls @($DataRoot, "/setowner", "*S-1-5-32-544", "/T", "/L", "/Q") `
        "set protected runtime data ownership"

    # Replace every descendant DACL with inheritance from the now-protected
    # root. This removes stale explicit grants rather than merely adding the
    # Administrators and SYSTEM grants alongside them.
    $children = Join-Path $DataRoot "*"
    if (Get-ChildItem -LiteralPath $DataRoot -Force | Select-Object -First 1) {
        Write-Host "    Resetting inherited permissions..."
        Invoke-Icacls @($children, "/reset", "/T", "/L", "/Q") `
            "reset protected runtime data permissions"
    }
    Set-Acl -LiteralPath $DataRoot -AclObject (New-ProtectedDirectorySecurity)

    # /L changes the reparse object itself and never follows its target. Once
    # the tree is readable under the protected root, reject any reparse object
    # before reading, moving, or trusting descendant content.
    Write-Host "    Verifying the protected tree..."
    Assert-NoReparsePoints $DataRoot
    if (-not (Test-Protected $DataRoot)) {
        throw "Protected runtime data root verification failed"
    }

    # Quarantine potentially attacker-known authorities only after the
    # directory tree is under protected custody; their bytes are never read.
    foreach ($name in @("bus.key", "shutdown.key")) {
        $key = Join-Path $DataRoot $name
        if (Test-Path -LiteralPath $key) {
            $rejected = "$key.rejected-$([Guid]::NewGuid().ToString('N'))"
            Move-Item -LiteralPath $key -Destination $rejected
        }
    }
    [IO.File]::WriteAllText($custodyMarker, "protected-v1")
}

if (-not (Test-Protected $DataRoot) -or
    -not (Test-Path -LiteralPath $custodyMarker -PathType Leaf)) {
    throw "Protected runtime data custody verification failed"
}
Write-Host "[+] Protected runtime data custody verified."
