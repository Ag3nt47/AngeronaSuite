"""Explicit Windows VMware setup; no download, install, or elevation on import.

Broadcom's account/compliance download flow stays in the user's browser. Only
an explicitly selected, vendor-signed Workstation installer may be launched.
The selected file and its directory chain remain held through installer exit.
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

from angerona.core.executable_trust import _identity, _open_sealed
from angerona.core.source_sandbox import _hold_plain_directories, _validate_regular_file

DOWNLOAD_URL = "https://support.broadcom.com/"
DOWNLOAD_HELP_URL = "https://knowledge.broadcom.com/external/article/368734"
PURPOSE = (
    "VMware is optional. Analysis Lab uses it to inspect a copy of your source "
    "in an isolated virtual machine with fixed Python security and secret checks. "
    "It is not required for monitoring, autonomous defense, or Ollama. "
    "It needs an extra download, disk space, RAM, and hardware virtualization. "
    "The Lab runs only when you start it. Analysis Lab currently supports Windows."
)
VALIDATION_NOTE = (
    "Installing VMware does not make Analysis Lab ready. Its runtime and isolation "
    "checks must also pass. This release's native VMware check is currently blocked "
    "by configuration-file custody; setup does not remove that protection."
)
_MAX_INSTALLER_BYTES = 2 * 1024 * 1024 * 1024
_INSTALLER_NAME = re.compile(r"VMware-workstation-(?:full-)?[A-Za-z0-9][A-Za-z0-9._-]*\.exe", re.I)
_PUBLISHERS = frozenset({"Broadcom Inc", "Broadcom Inc.", "VMware, Inc.", "VMware, Inc"})

_INSPECT_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$s = Get-AuthenticodeSignature -LiteralPath $env:ANGERONA_VMWARE_INSTALLER
$publisher = if ($s.SignerCertificate) {
    $s.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
} else { '' }
$v = [Diagnostics.FileVersionInfo]::GetVersionInfo($env:ANGERONA_VMWARE_INSTALLER)
[pscustomobject]@{status=[string]$s.Status; publisher=[string]$publisher; product=[string]$v.ProductName} |
    ConvertTo-Json -Compress
"""

# No user path/text is interpolated into either PowerShell program. The selected
# installer travels only as environment data; the service program is immutable.
_INSTALL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
try {
    $p = Start-Process -FilePath $env:ANGERONA_VMWARE_INSTALLER -Verb RunAs -PassThru -Wait -WindowStyle Normal -WorkingDirectory ([Environment]::SystemDirectory)
    exit $p.ExitCode
} catch { exit 1 }
"""

# Reviewed tools/enable_analysis_lab_vmware.ps1 mechanics, embedded so an elevated
# launch never reads a mutable repository/temp script. Only this service changes.
_CONFIGURE_SCRIPT = r"""
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
"""


def _require_windows() -> None:
    if sys.platform != "win32":
        raise ValueError("Analysis Lab setup currently supports Windows. VMware is optional; skip this step on macOS or Linux.")


def _encoded(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


def _powershell(script: str, *, installer: Path | None = None,
                expected_directory: Path | None = None, timeout=None):
    from angerona.core.privilege import (
        sanitized_child_environment, trusted_powershell_path, trusted_windows_directories,
    )

    powershell = trusted_powershell_path()
    _windows, system = trusted_windows_directories()
    environment = sanitized_child_environment(source={})
    if installer is not None:
        environment["ANGERONA_VMWARE_INSTALLER"] = str(installer)
    if expected_directory is not None:
        environment["ANGERONA_VMWARE_EXPECTED_DIRECTORY"] = str(expected_directory)
    with _hold_plain_directories(powershell.parent), _open_sealed(powershell):
        return subprocess.run(
            [str(powershell), "-NoProfile", "-NonInteractive", "-EncodedCommand", _encoded(script)],
            cwd=str(system), env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False,
            timeout=timeout, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )


def _installer_identity(path: Path) -> tuple[str, str, str]:
    result = _powershell(_INSPECT_SCRIPT, installer=path, timeout=30)
    if result.returncode or len(result.stdout) > 4096:
        raise ValueError("The VMware installer signature could not be verified.")
    try:
        value = json.loads(result.stdout.decode("utf-8-sig"))
        return value["status"], value["publisher"], value["product"]
    except (UnicodeError, ValueError, KeyError, TypeError) as exc:
        raise ValueError("The VMware installer identity is unavailable.") from exc


@contextlib.contextmanager
def verified_installer(selected):
    """Pin one selected local installer; a digest records bytes, not new trust."""
    _require_windows()
    path = Path(selected)
    raw = str(path)
    if (not path.is_absolute() or raw.startswith(("\\\\", "//"))
            or "\x00" in raw or not _INSTALLER_NAME.fullmatch(path.name)):
        raise ValueError("Select the original local VMware Workstation Windows .exe installer.")
    with _hold_plain_directories(path.parent):
        _validate_regular_file(path)
        with _open_sealed(path) as stream:
            held = os.fstat(stream.fileno())
            expected = _identity(held)

            def verify():
                _validate_regular_file(path)
                if (_identity(os.fstat(stream.fileno())) != expected
                        or _identity(path.stat()) != expected):
                    raise ValueError("The selected VMware installer changed during verification.")

            if (not stat.S_ISREG(held.st_mode) or held.st_nlink != 1
                    or not 0 < held.st_size <= _MAX_INSTALLER_BYTES):
                raise ValueError("The VMware installer must be one bounded, regular file.")
            verify()
            status, publisher, product = _installer_identity(path)
            if status != "Valid" or publisher not in _PUBLISHERS:
                raise ValueError("The installer needs a valid VMware or Broadcom digital signature.")
            if product not in {"VMware Workstation", "VMware Workstation Pro"}:
                raise ValueError("The signed file is not a VMware Workstation installer.")
            digest = hashlib.sha256()
            remaining = held.st_size
            while remaining:
                chunk = stream.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise ValueError("The VMware installer read was incomplete.")
                digest.update(chunk)
                remaining -= len(chunk)
            if stream.read(1):
                raise ValueError("The VMware installer changed size.")
            verify()
            yield path, digest.hexdigest(), verify


def install_selected(selected, progress=lambda _message: None) -> str:
    progress("Verifying the selected VMware Workstation installer…")
    with verified_installer(selected) as (path, _digest, verify):
        progress("Verified VMware installer. Complete its UAC and license prompts; cancel there to stop installation.")
        verify()
        # Wait without a timeout: releasing custody while the native installer
        # is still running would defeat the verified-file handoff.
        result = _powershell(_INSTALL_SCRIPT, installer=path)
        if result.returncode not in {0, 3010, 1641}:
            raise ValueError("VMware installation was cancelled or failed. No Lab readiness is assumed.")
    if result.returncode in {3010, 1641}:
        return "The VMware installer requested a Windows restart. Restart before configuring or checking Analysis Lab."
    return "The VMware installer exited successfully. Configure its service, then prepare and check Analysis Lab."


def configure_service(progress=lambda _message: None) -> str:
    _require_windows()
    from angerona.core import analysis_vmware

    # Validate the existing installation before requesting elevation. This also
    # proves this is setup of installed VMware, not an implicit installation.
    with analysis_vmware.trusted_installation() as directory:
        progress("Approve UAC to set VMware Authorization Service to Manual and start it. No VM will be started.")
        encoded = _encoded(_CONFIGURE_SCRIPT)
        script = (
            "$ErrorActionPreference='Stop';try {"
            "$p=Start-Process -FilePath ([Environment]::SystemDirectory + '\\WindowsPowerShell\\v1.0\\powershell.exe') "
            "-Verb RunAs -PassThru -Wait -WindowStyle Hidden "
            "-WorkingDirectory ([Environment]::SystemDirectory) "
            "-ArgumentList @('-NoProfile','-NonInteractive','-EncodedCommand','" + encoded + "');"
            "exit $p.ExitCode } catch { exit 1 }"
        )
        result = _powershell(script, expected_directory=directory)
        if result.returncode:
            raise ValueError("VMware configuration was cancelled or failed. Check its installation and service registration.")
        analysis_vmware.service_ready()
    return "VMware Authorization Service is running with Manual startup. Open Analysis Lab to prepare its runtime and check readiness."
