"""Explicit, content-pinned setup of the optional Windows Analysis Lab emulator.

Nothing downloads or requests elevation on import. The fixed privileged helper
only copies reviewed bytes and runs the vendor installer UI when requested; it
never runs QEMU, Python, repository code, or an analysis guest as administrator.
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import os
import platform
import re
import shutil
import stat
import subprocess
import uuid
import zipfile
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from angerona.core import analysis_qemu_runtime
from angerona.core.analysis_qemu_catalog import FILES, INSTALLER
from angerona.core.executable_trust import _open_sealed
from angerona.core.analysis_qemu_runtime import require_user_session as _require_unprivileged
from angerona.core.source_sandbox import (
    _absolute, _ensure_directory, _hold_plain_directories, _validate_regular_file,
)

PURPOSE = (
    'Analysis Lab is optional. It checks a copy of your source with fixed Python '
    'security and secret scanners inside a diskless, offline virtual machine. '
    'It runs only when you start a check and is not needed for monitoring, '
    'automatic defense, or Ollama. Setup downloads the reviewed QEMU 11.1.0 '
    'Windows installer (about 197 MiB) if needed, shows its installation and '
    'license prompts, and configures a protected 122 MiB Lab runtime. The guest '
    'uses one virtual CPU and 768 MiB RAM while running. Choose the installer’s '
    'default Program Files\\qemu location. You can skip setup and use Angerona normally.'
)
TRUST_NOTE = (
    'The distributor uses an expired signing certificate. Angerona verifies this '
    'specific reviewed download against pinned SHA-256 and SHA-512 checksums; '
    'it does not describe that certificate as currently valid.'
)

# Embedded, reviewed bootstrap: no privileged script is read from a mutable
# checkout or temporary file. The common ACL/copy mechanics are intentionally
# self-contained; PSModulePath is fixed before any module autoload can occur.
_BOOTSTRAP = r"""
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:PSModulePath = [Environment]::SystemDirectory + '\WindowsPowerShell\v1.0\Modules'
$env:PATH = [Environment]::SystemDirectory
$admin = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$users = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
$programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$trustedOwners = @($admin.Value, $system.Value, 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
function Directory-Security {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner($admin)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($principal in @($admin, $system)) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $principal, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $users, 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    return $acl
}
function File-Security {
    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetOwner($admin)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($principal in @($admin, $system)) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($principal, 'FullControl', 'Allow'))
    }
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($users, 'ReadAndExecute', 'Allow'))
    return $acl
}
function New-ProtectedFile([string]$path) {
    return [IO.FileStream]::new($path, [IO.FileMode]::CreateNew,
        [Security.AccessControl.FileSystemRights]::Write, [IO.FileShare]::None,
        4096, [IO.FileOptions]::None, (File-Security))
}
function Assert-PlainChain([string]$path) {
    $cursor = [IO.Path]::GetFullPath($path)
    while ($cursor) {
        $item = Get-Item -LiteralPath $cursor -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Refusing redirected privileged runtime path.'
        }
        $parent = [IO.Directory]::GetParent($cursor)
        $cursor = if ($null -eq $parent) { $null } else { $parent.FullName }
    }
}
function New-ProtectedDirectory([string]$path) {
    Assert-PlainChain ([IO.Path]::GetDirectoryName($path))
    if (Test-Path -LiteralPath $path) { throw 'Protected destination already exists.' }
    $null = [IO.Directory]::CreateDirectory($path, (Directory-Security))
    $actual = Get-Acl -LiteralPath $path
    if ($actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $admin.Value -or
        -not $actual.AreAccessRulesProtected) { throw 'Protected ACL was not established.' }
    Assert-PlainChain $path
}
function Copy-VerifiedFile([string]$source, [string]$digest, [string]$destination, [long]$bytes) {
    Assert-PlainChain $source
    $inputStream = [IO.File]::Open($source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ($inputStream.Length -ne $bytes) { throw 'Reviewed payload size changed.' }
        $hasher = [Security.Cryptography.SHA256]::Create()
        try { $actual = [BitConverter]::ToString($hasher.ComputeHash($inputStream)).Replace('-', '').ToLowerInvariant() }
        finally { $hasher.Dispose() }
        if ($actual -cne $digest) { throw 'Reviewed payload checksum changed.' }
        $inputStream.Position = 0
        $outputStream = New-ProtectedFile $destination
        try { $inputStream.CopyTo($outputStream); $outputStream.Flush($true) }
        finally { $outputStream.Dispose() }
    } finally { $inputStream.Dispose() }
}
# Use the already loaded signed Windows .NET Framework interop boundary. No
# compiler, temporary source, downloaded assembly, or external helper executes.
$nativeType = [object].Assembly.GetType('Microsoft.Win32.Win32Native', $true)
$nativeMethods = @($nativeType.GetMethods([Reflection.BindingFlags]'Static,NonPublic') | Where-Object {
    $_.Name -ceq 'CreateFile' -and $_.GetParameters().Count -eq 7 -and
    $_.ReturnType -eq [Microsoft.Win32.SafeHandles.SafeFileHandle]
})
if ($nativeMethods.Count -ne 1) { throw 'Trusted Windows directory interop is unavailable.' }
$directoryGuards = [Collections.Generic.List[Microsoft.Win32.SafeHandles.SafeFileHandle]]::new()
$parents = [Collections.Generic.List[string]]::new()
$cursor = [IO.Path]::GetFullPath($programFiles)
while ($cursor) {
    $parents.Insert(0, $cursor)
    $parent = [IO.Directory]::GetParent($cursor)
    $cursor = if ($null -eq $parent) { $null } else { $parent.FullName }
}
foreach ($path in $parents) {
    Assert-PlainChain $path
    $guard = $nativeMethods[0].Invoke($null, [object[]]@(
        $path, [int]0x80, [IO.FileShare]3, $null, [IO.FileMode]3, [int]0x02200000, [IntPtr]::Zero))
    if ($guard.IsInvalid) { $guard.Dispose(); throw 'Cannot retain protected directory custody.' }
    $directoryGuards.Add($guard)
    Assert-PlainChain $path
}
# Process-owned guards remain open across copying, native installer UI and
# cleanup, even if the unelevated caller exits. Windows closes them on exit.
$programAcl = Get-Acl -LiteralPath $programFiles
if ($programAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trustedOwners) {
    throw 'Program Files has an unexpected owner.'
}
$writeRights = 0x000D0156 -bor 268435456 -bor 1073741824
foreach ($rule in $programAcl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    if ($rule.AccessControlType -eq 'Allow' -and
        ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0 -and
        ($rule.FileSystemRights -band $writeRights) -ne 0 -and $rule.IdentityReference.Value -notin $trustedOwners) {
        throw 'Program Files permits unexpected write authority.'
    }
}
"""

_COPY_BUNDLE = r"""
$destination = Join-Path $programFiles __DESTINATION__
$created = $false
try {
    New-ProtectedDirectory $destination
    $created = $true
    $archivePath = Join-Path $destination 'verified-payload.zip'
    Copy-VerifiedFile __SOURCE__ __DIGEST__ $archivePath __ARCHIVE_BYTES__
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($archivePath)
    try {
        if ($archive.Entries.Count -ne __FILES__) { throw 'Reviewed file count changed.' }
        $total = [long]0
        foreach ($entry in $archive.Entries) {
            $name = $entry.FullName
            if ($name -notmatch '^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)?$' -or
                @($name.Split('/') | Where-Object { $_ -eq '.' -or $_ -eq '..' -or $_.EndsWith('.') }).Count) {
                throw 'Unsafe payload member name.'
            }
            $total += $entry.Length
            if ($total -gt __EXPANDED_BYTES__) { throw 'Payload expanded size exceeds bound.' }
            $target = [IO.Path]::GetFullPath((Join-Path $destination $name.Replace('/', '\')))
            if (-not $target.StartsWith($destination + '\', [StringComparison]::OrdinalIgnoreCase)) {
                throw 'Payload escaped its destination.'
            }
            $parent = [IO.Path]::GetDirectoryName($target)
            if ($parent -ne $destination -and -not (Test-Path -LiteralPath $parent)) { New-ProtectedDirectory $parent }
            Assert-PlainChain $parent
            $reader = $entry.Open()
            try {
                $writer = New-ProtectedFile $target
                try {
                    $buffer = [byte[]]::new(65536)
                    $written = [long]0
                    while (($count = $reader.Read($buffer, 0, $buffer.Length)) -gt 0) {
                        $written += $count
                        if ($written -gt $entry.Length) { throw 'Payload stream exceeded its size.' }
                        $writer.Write($buffer, 0, $count)
                    }
                    if ($written -ne $entry.Length) { throw 'Incomplete payload stream.' }
                    $writer.Flush($true)
                } finally { $writer.Dispose() }
            } finally { $reader.Dispose() }
        }
        if ($total -ne __EXPANDED_BYTES__) { throw 'Reviewed expanded size changed.' }
    } finally { $archive.Dispose() }
    Remove-Item -LiteralPath $archivePath
    exit 0
} catch {
    # Only this invocation's exact newly created protected directory is removed.
    $expected = [IO.Path]::GetFullPath((Join-Path $programFiles __DESTINATION__))
    if ($created -and [IO.Path]::GetFullPath($destination) -ceq $expected) {
        Assert-PlainChain $destination
        $acl = Get-Acl -LiteralPath $destination
        if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq $admin.Value -and $acl.AreAccessRulesProtected) {
            Remove-Item -LiteralPath $destination -Recurse -Force
        }
    }
    exit 1
}
"""

_INSTALL_VENDOR = r"""
$stage = Join-Path $programFiles __STAGE__
$created = $false
$installer = Join-Path $stage 'qemu-installer.exe'
$code = 1
try {
    New-ProtectedDirectory $stage
    $created = $true
    Copy-VerifiedFile __SOURCE__ __DIGEST__ $installer __INSTALLER_BYTES__
    # The installer executes from a protected DLL namespace, never Downloads.
    $process = Start-Process -FilePath $installer -PassThru -Wait -WindowStyle Normal -WorkingDirectory ([Environment]::SystemDirectory)
    $code = $process.ExitCode
} catch { $code = 1 }
finally {
    if ($created -and [IO.Path]::GetFullPath($stage) -ceq [IO.Path]::GetFullPath((Join-Path $programFiles __STAGE__))) {
        Assert-PlainChain $stage
        if (Test-Path -LiteralPath $installer) { Remove-Item -LiteralPath $installer }
        # Nonrecursive: unexpected installer-created files are never removed.
        if (@(Get-ChildItem -LiteralPath $stage -Force).Count -eq 0) { [IO.Directory]::Delete($stage) }
    }
}
exit $code
"""

_ELEVATE = r"""
$ErrorActionPreference = 'Stop'
$env:PSModulePath = [Environment]::SystemDirectory + '\WindowsPowerShell\v1.0\Modules'
try {
    $shell = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    $process = Start-Process -FilePath $shell -Verb RunAs -PassThru -Wait -WindowStyle Hidden -WorkingDirectory ([Environment]::SystemDirectory) -ArgumentList @('-NoProfile', '-NonInteractive', '-EncodedCommand', $env:ANGERONA_QEMU_BOOTSTRAP)
    exit $process.ExitCode
} catch { exit 1 }
"""


def _literal(value) -> str:
    text = str(value)
    if any(ord(char) < 32 for char in text):
        raise ValueError('Invalid setup path or catalog value.')
    return "'" + text.replace("'", "''") + "'"


def _script(template, values):
    return _BOOTSTRAP + re.sub(r'__[A-Z_]+__', lambda match: str(values[match[0]]), template)


def _elevated(script):
    from angerona.core.privilege import (
        sanitized_child_environment, trusted_powershell_path, trusted_windows_directories,
    )
    powershell = trusted_powershell_path()
    _windows, system = trusted_windows_directories()
    environment = sanitized_child_environment(source={})
    environment['PATH'] = str(system)
    encoded = base64.b64encode(script.encode('utf-16-le')).decode('ascii')
    if len(encoded) > 29000:
        raise ValueError('The reviewed setup command exceeds the Windows command limit.')
    environment['ANGERONA_QEMU_BOOTSTRAP'] = encoded
    wrapper = base64.b64encode(_ELEVATE.encode('utf-16-le')).decode('ascii')
    with _hold_plain_directories(powershell.parent), _open_sealed(powershell):
        # Do not time out and release verified-file custody while the native
        # installer/UAC is still running. The user cancels in those native UIs.
        result = subprocess.run(
            [str(powershell), '-NoProfile', '-NonInteractive', '-EncodedCommand', wrapper],
            cwd=str(system), env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
        )
    return result.returncode


def _verify(stream, expected, operation):
    held = os.fstat(stream.fileno())
    if not stat.S_ISREG(held.st_mode) or held.st_nlink != 1 or held.st_size != expected['size']:
        raise ValueError('A reviewed setup file has changed identity or size.')
    hashes = {name: hashlib.new(name) for name in ('sha256', 'sha512') if name in expected}
    stream.seek(0)
    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
        operation.check()
        for digest in hashes.values():
            digest.update(chunk)
    if any(digest.hexdigest() != expected[name] for name, digest in hashes.items()):
        raise ValueError('A setup file does not match the reviewed catalog checksum.')
    stream.seek(0)


def _remove_owned(path, identity):
    try:
        path.lstat()  # Missing owned temporary files are normal after rename.
        _validate_regular_file(path)
        held = path.stat(follow_symlinks=False)
        if held.st_nlink == 1 and (held.st_dev, held.st_ino) == identity:
            path.unlink()
    except FileNotFoundError:
        pass


def _download(directory, operation, progress):
    import requests
    cached = directory / (INSTALLER['sha256'] + '.exe')
    if cached.exists():
        _validate_regular_file(cached)
        with _open_sealed(cached) as stream:
            _verify(stream, INSTALLER, operation)
        return cached
    operation.phase(900)
    temporary = directory / ('qemu-' + uuid.uuid4().hex + '.part')
    identity = None
    try:
        with temporary.open('xb') as output, requests.Session() as session:
            info = os.fstat(output.fileno())
            identity = info.st_dev, info.st_ino
            session.trust_env = False
            url = INSTALLER['url']
            for _attempt in range(4):
                parsed = urlsplit(url)
                if (parsed.scheme != 'https' or parsed.netloc != 'qemu.weilnetz.de'
                        or parsed.fragment or parsed.username or parsed.password):
                    raise ValueError('Unapproved QEMU installer download endpoint.')
                operation.check()
                with session.get(url, timeout=(10, 10), stream=True, allow_redirects=False,
                                 headers={'Accept-Encoding': 'identity'}) as response:
                    if response.status_code in (301, 302, 303, 307, 308):
                        url = urljoin(url, response.headers.get('Location', ''))
                        continue
                    if response.status_code != 200:
                        raise ValueError(f'QEMU installer download failed (HTTP {response.status_code}).')
                    length = response.headers.get('Content-Length')
                    if length is not None and (not length.isdecimal() or int(length) != INSTALLER['size']):
                        raise ValueError('QEMU installer download size differs from the reviewed catalog.')
                    count = 0
                    percentage = -1
                    for chunk in response.iter_content(64 * 1024):
                        operation.check()
                        count += len(chunk)
                        if count > INSTALLER['size']:
                            raise ValueError('QEMU installer exceeds its reviewed byte limit.')
                        output.write(chunk)
                        current = count * 100 // INSTALLER['size']
                        if current != percentage:
                            percentage = current
                            progress(f'Downloading reviewed QEMU installer: {current}%')
                    if count != INSTALLER['size']:
                        raise ValueError('The QEMU installer download was incomplete.')
                    output.flush()
                    os.fsync(output.fileno())
                    break
            else:
                raise ValueError('The QEMU installer redirected too many times.')
        with _open_sealed(temporary) as stream:
            _verify(stream, INSTALLER, operation)
        # Never overwrite another file, including a cache created concurrently.
        temporary.rename(cached)
        return cached
    finally:
        if identity is not None:
            _remove_owned(temporary, identity)


@contextlib.contextmanager
def _bundle(source, directory, operation):
    """Copy only held, exact catalog files; unrelated vendor files stay unused."""
    destination = directory / ('qemu-runtime-' + uuid.uuid4().hex + '.zip')
    identity = None
    try:
        with contextlib.ExitStack() as stack:
            stack.enter_context(_hold_plain_directories(source / 'share', directory))
            sources = {}
            for name, expected in FILES.items():
                if not re.fullmatch(r'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?', name) or '..' in Path(name).parts:
                    raise ValueError('Invalid reviewed runtime member path.')
                path = source / name
                path.lstat()  # Preserve FileNotFoundError for an incomplete vendor install.
                _validate_regular_file(path)
                stream = stack.enter_context(_open_sealed(path))
                _verify(stream, expected, operation)
                sources[name] = stream
            with destination.open('xb') as output:
                held = os.fstat(output.fileno())
                identity = held.st_dev, held.st_ino
                with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_STORED) as archive:
                    for name, stream in sources.items():
                        operation.check()
                        with archive.open(name, 'w') as member:
                            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                                operation.check()
                                member.write(chunk)
                output.flush()
                os.fsync(output.fileno())
        with _open_sealed(destination) as stream:
            held = os.fstat(stream.fileno())
            if not stat.S_ISREG(held.st_mode) or held.st_nlink != 1:
                raise ValueError('The prepared runtime archive is not an unaliased regular file.')
            size = held.st_size
            if size > sum(item['size'] for item in FILES.values()) + 1024**2:
                raise ValueError('The prepared runtime archive exceeded its bound.')
            _verify_bundle(stream, operation)
            stream.seek(0)
            digest = hashlib.sha256()
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                operation.check()
                digest.update(chunk)
            yield destination, size, digest.hexdigest()
    finally:
        if identity is not None:
            _remove_owned(destination, identity)


def _verify_bundle(stream, operation):
    """Bind the sealed ZIP to catalog bytes, including a pre-seal replacement."""
    with zipfile.ZipFile(stream) as archive:
        members = archive.infolist()
        if len(members) != len(FILES) or {entry.filename for entry in members} != set(FILES):
            raise ValueError('The sealed runtime archive file set changed.')
        for entry in members:
            expected = FILES[entry.filename]
            if entry.file_size != expected['size'] or entry.flag_bits & 1:
                raise ValueError('The sealed runtime archive member size changed.')
            count = 0
            digest = hashlib.sha256()
            with archive.open(entry) as reader:
                for chunk in iter(lambda: reader.read(1024 * 1024), b''):
                    operation.check()
                    count += len(chunk)
                    if count > expected['size']:
                        raise ValueError('The sealed runtime archive member exceeded its bound.')
                    digest.update(chunk)
            if count != expected['size'] or digest.hexdigest() != expected['sha256']:
                raise ValueError('The sealed runtime archive member checksum changed.')


def _configure_bundle(bundle, operation, progress):
    path, size, digest = bundle
    operation.check()
    progress('Approve UAC to configure the protected Lab runtime. No virtual machine runs as administrator.')
    script = _script(_COPY_BUNDLE, {
        '__DESTINATION__': _literal(analysis_qemu_runtime.RUNTIME_DIRECTORY),
        '__SOURCE__': _literal(path), '__DIGEST__': _literal(digest),
        '__ARCHIVE_BYTES__': size, '__FILES__': len(FILES),
        '__EXPANDED_BYTES__': sum(item['size'] for item in FILES.values()),
    })
    if _elevated(script):
        raise ValueError('Protected Lab configuration was cancelled or failed. No readiness was assumed.')
    operation.check()


def _install_vendor(path, operation, progress):
    with _hold_plain_directories(path.parent), _open_sealed(path) as stream:
        _verify(stream, INSTALLER, operation)
        operation.check()
        progress('Approve UAC, then complete the reviewed QEMU installer and license prompts. '
                 'Keep the default Program Files\\qemu destination; cancel in the installer to stop.')
        script = _script(_INSTALL_VENDOR, {
            '__STAGE__': _literal('AngeronaAnalysisInstaller-11.1.0-' + uuid.uuid4().hex),
            '__SOURCE__': _literal(path), '__DIGEST__': _literal(INSTALLER['sha256']),
            '__INSTALLER_BYTES__': INSTALLER['size'],
        })
        code = _elevated(script)
        if code not in (0, 3010, 1641):
            raise ValueError('QEMU installation was cancelled or failed. No Lab runtime was configured.')
        operation.check()
        if code in (3010, 1641):
            raise ValueError('QEMU requested a Windows restart. Restart, then run Lab setup again.')


def install_and_configure(root, operation, progress=lambda _message: None) -> str:
    from angerona.core.privilege import _windows_known_folder
    from angerona.core.tool_analysis_jobs import transaction
    _require_unprivileged()
    if os.name != 'nt' or platform.machine().lower() not in {'amd64', 'x86_64'}:
        raise ValueError('The optional Analysis Lab emulator requires 64-bit Windows on an Intel or AMD processor.')
    root = _absolute(Path(root))
    program_files = _windows_known_folder(0x26)
    target = program_files / analysis_qemu_runtime.RUNTIME_DIRECTORY
    with transaction(root):
        operation.check()
        if target.exists():
            with analysis_qemu_runtime.trusted_installation():
                return 'The protected Lab emulator is already verified. Prepare the guest runtime, then check readiness.'
        downloads = root / 'downloads'
        _ensure_directory(downloads)
        if shutil.disk_usage(downloads).free < 512 * 1024**2:
            raise ValueError('Lab setup needs at least 512 MiB of free download and staging space.')
        if shutil.disk_usage(program_files).free < 2 * 1024**3:
            raise ValueError('Lab setup needs at least 2 GiB free on the Windows application drive for QEMU and its runtime.')
        with _hold_plain_directories(downloads, program_files), contextlib.ExitStack() as prepared_stack:
            source = program_files / 'qemu'
            operation.phase(180)
            progress('Checking for the exact reviewed QEMU installation…')
            # Detect an existing matching vendor installation before requesting
            # a download/UAC; only catalog members are copied from that tree.
            prepared = None
            if source.is_dir() and (source / 'share').is_dir():
                try:
                    prepared = prepared_stack.enter_context(_bundle(source, downloads, operation))
                except (FileNotFoundError, NotADirectoryError):
                    pass
                except ValueError as exc:
                    if 'catalog checksum' not in str(exc) and 'changed identity or size' not in str(exc):
                        raise
            if prepared is not None:
                # Copy-phase errors must not be mistaken for an absent vendor
                # install and retrigger an unrelated installation.
                operation.phase(24 * 60 * 60)
                _configure_bundle(prepared, operation, progress)
            if prepared is None:
                path = _download(downloads, operation, progress)
                # Native dialogs may remain open until the user decides. The
                # cancellation flag is rechecked afterwards, but their wall
                # time must not silently turn a successful install into expiry.
                operation.phase(24 * 60 * 60)
                _install_vendor(path, operation, progress)
                operation.phase(180)
                progress('Verifying installed QEMU files and preparing the protected Lab copy…')
                if not source.is_dir() or not (source / 'share').is_dir():
                    raise ValueError('Reviewed QEMU files were not found in Program Files\\qemu. '
                                     'Use the installer’s default location, then repeat Lab setup.')
                try:
                    with _bundle(source, downloads, operation) as bundle:
                        operation.phase(24 * 60 * 60)
                        _configure_bundle(bundle, operation, progress)
                except FileNotFoundError as exc:
                    raise ValueError('Reviewed QEMU files were not found in Program Files\\qemu. '
                                     'Use the installer’s default location, then repeat Lab setup.') from exc
            operation.check()
            with analysis_qemu_runtime.trusted_installation():
                pass
    return 'Protected Lab emulator configured. Prepare the guest runtime, then check both analyzers before use.'
