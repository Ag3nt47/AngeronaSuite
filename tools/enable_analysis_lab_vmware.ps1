# Explicit administrator preparation of installed VMware; no VM is started or modified.
#Requires -Version 5.1
#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
# Never trust an inherited expected-directory value for standalone use.
$env:ANGERONA_VMWARE_EXPECTED_DIRECTORY = ''
foreach ($view in @([Microsoft.Win32.RegistryView]::Registry32, [Microsoft.Win32.RegistryView]::Registry64)) {
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
    try {
        $key = $base.OpenSubKey('SOFTWARE\VMware, Inc.\VMware Workstation')
        if ($null -ne $key) {
            try { $candidate = [string]$key.GetValue('InstallPath', '') }
            finally { $key.Dispose() }
            if ($candidate) { $env:ANGERONA_VMWARE_EXPECTED_DIRECTORY = $candidate; break }
        }
    } finally { $base.Dispose() }
}

$ErrorActionPreference = 'Stop'
$directoryGuards = New-Object 'System.Collections.Generic.List[Microsoft.Win32.SafeHandles.SafeFileHandle]'
try {
    $expectedDirectory = [string]$env:ANGERONA_VMWARE_EXPECTED_DIRECTORY
    if ($expectedDirectory -notmatch '^[A-Za-z]:\\' -or $expectedDirectory.Contains('"')) {
        throw 'The trusted Workstation installation directory is unavailable. Repair VMware first.'
    }
    $expectedDirectory = [IO.Path]::GetFullPath($expectedDirectory)
    $serviceRecord = Get-CimInstance -ClassName Win32_Service -Filter "Name='VMAuthdService'"
    if ($null -eq $serviceRecord) { throw 'VMware Authorization Service is not installed.' }
    $registeredImage = [string]$serviceRecord.PathName
    $serviceImage = $registeredImage
    if ($serviceImage.StartsWith('"') -and $serviceImage.EndsWith('"')) {
        $serviceImage = $serviceImage.Substring(1, $serviceImage.Length - 2)
    } elseif ($serviceImage -match '\s') { throw 'Ambiguous service executable path.' }
    if ($serviceImage -notmatch '^[A-Za-z]:\\(?:[^"\\\r\n]+\\)*vmware-authd\.exe$') {
        throw 'Unexpected service executable.'
    }
    $serviceParent = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($serviceImage))
    if (-not [String]::Equals($serviceParent.TrimEnd('\'), $expectedDirectory.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'VMware service is outside its trusted Workstation installation. Repair VMware first.'
    }
    # The GUI already holds this trusted installation through UAC. The same
    # guard here also protects standalone administrator invocation: pin every
    # ancestor before inspecting or starting the registered service image.
    Add-Type -Namespace Angerona -Name SetupDirectoryCustody -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet=System.Runtime.InteropServices.CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
public static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFileW(string name, uint access, uint share, System.IntPtr security, uint disposition, uint flags, System.IntPtr template);
'@
    $parents = New-Object 'System.Collections.Generic.List[string]'
    $cursor = $expectedDirectory.TrimEnd('\')
    $anchor = [IO.Path]::GetPathRoot($expectedDirectory).TrimEnd('\')
    while ($cursor -and $cursor -ne $anchor) {
        $parents.Insert(0, $cursor)
        $cursor = [IO.Path]::GetDirectoryName($cursor)
        if ($cursor) { $cursor = $cursor.TrimEnd('\') }
    }
    foreach ($parentPath in $parents) {
        $parentItem = Get-Item -LiteralPath $parentPath -Force
        if (-not $parentItem.PSIsContainer -or ($parentItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'VMware installation contains a redirected directory. Repair VMware first.'
        }
        $guard = [Angerona.SetupDirectoryCustody]::CreateFileW($parentPath, 0x80, 3, [IntPtr]::Zero, 3, 0x02200000, [IntPtr]::Zero)
        if ($guard.IsInvalid) { $guard.Dispose(); throw 'Cannot retain VMware directory custody.' }
        $directoryGuards.Add($guard)
        $parentItem = Get-Item -LiteralPath $parentPath -Force
        if (-not $parentItem.PSIsContainer -or ($parentItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'VMware installation directory changed during verification.'
        }
    }
    $serviceItem = Get-Item -LiteralPath $serviceImage -Force
    if ($serviceItem.PSIsContainer -or ($serviceItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Service executable is not a regular file.'
    }
    $serviceFile = [IO.File]::Open($serviceItem.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $serviceItem.FullName
        if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate) {
            throw 'Invalid VMware service signature.'
        }
        $publisherName = $signature.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
        if ($publisherName -notin @('Broadcom Inc', 'Broadcom Inc.', 'VMware, Inc.', 'VMware, Inc')) {
            throw 'Unexpected service publisher.'
        }
        if ((Get-CimInstance -ClassName Win32_Service -Filter "Name='VMAuthdService'").PathName -cne $registeredImage) {
            throw 'Service registration changed during verification.'
        }
        Set-Service -Name 'VMAuthdService' -StartupType Manual
        if ((Get-CimInstance -ClassName Win32_Service -Filter "Name='VMAuthdService'").PathName -cne $registeredImage) {
            throw 'Service registration changed before startup.'
        }
        Start-Service -Name 'VMAuthdService'
        $readyService = Get-Service -Name 'VMAuthdService'
        $readyService.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(20))
    } finally { $serviceFile.Dispose() }
    exit 0
} catch { exit 1 }
finally { foreach ($guard in $directoryGuards) { $guard.Dispose() } }
