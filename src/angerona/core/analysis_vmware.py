"""Fixed, diskless VMware appliance supervisor for the offline analyzer catalog."""
from __future__ import annotations

import contextlib
import ctypes
import os
import re
import stat
import subprocess
import time
from pathlib import Path

from angerona.core.executable_trust import _authenticode_identity, _open_sealed
from angerona.core.github_tool_catalog import _require_unprivileged
from angerona.core.source_sandbox import _hold_plain_directories, _validate_regular_file

MAX_OUTPUT = 2 * 1024 * 1024
SUPERVISOR_PROFILE = 'sealed-vmx-custody-v1'


def installation() -> Path:
    if os.name != 'nt':
        raise ValueError('Analysis Lab currently requires VMware Workstation on Windows.')
    import winreg
    for view in (winreg.KEY_WOW64_32KEY, winreg.KEY_WOW64_64KEY):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r'SOFTWARE\VMware, Inc.\VMware Workstation',
                                0, winreg.KEY_READ | view) as key:
                directory = Path(winreg.QueryValueEx(key, 'InstallPath')[0])
            for path in (directory / 'vmrun.exe', directory / 'x64/vmware-vmx.exe'):
                _validate_regular_file(path)
            return directory
        except (OSError, ValueError):
            continue
    raise ValueError('Install VMware Workstation to use Analysis Lab; it was not found in Windows registration.')


def service_ready() -> None:
    import win32service
    manager = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
    try:
        service = win32service.OpenService(manager, 'VMAuthdService', win32service.SERVICE_QUERY_STATUS)
        try:
            if win32service.QueryServiceStatus(service)[1] != win32service.SERVICE_RUNNING:
                raise ValueError('Start VMware Authorization Service in Windows Services as administrator, then Check readiness.')
        finally:
            win32service.CloseServiceHandle(service)
    finally:
        win32service.CloseServiceHandle(manager)


@contextlib.contextmanager
def trusted_installation():
    _require_unprivileged()
    directory = installation()
    with contextlib.ExitStack() as stack:
        stack.enter_context(_hold_plain_directories(directory, directory / 'x64'))
        for path in (directory / 'vmrun.exe', directory / 'x64/vmware-vmx.exe'):
            _validate_regular_file(path)
            stack.enter_context(_open_sealed(path))
            status, publisher, _thumbprint = _authenticode_identity(path)
            if status.lower() != 'valid' or not re.search(
                r'(?:^|, )O=(?:Broadcom Inc\.?|"VMware, Inc\.")(?=, |$)', publisher,
            ):
                raise ValueError('The installed VMware executable has no valid VMware/Broadcom signature.')
        yield directory


def configuration(job_id: str) -> str:
    if not re.fullmatch('[0-9a-f]{32}', job_id):
        raise ValueError('Invalid analysis job identity.')
    values = {
        '.encoding': 'UTF-8', 'config.version': '8', 'virtualHW.version': '20',
        'displayName': 'Angerona offline analysis ' + job_id[:8], 'guestOS': 'otherlinux-64',
        'memsize': '768', 'numvcpus': '1', 'firmware': 'bios',
        'ide0:0.present': 'TRUE', 'ide0:0.deviceType': 'cdrom-image',
        'ide0:0.fileName': 'boot.iso', 'ide0:0.startConnected': 'TRUE',
        'ethernet0.present': 'FALSE', 'usb.present': 'FALSE', 'ehci.present': 'FALSE',
        'usb_xhci.present': 'FALSE', 'sound.present': 'FALSE', 'vmci0.present': 'FALSE',
        'floppy0.present': 'FALSE', 'mks.enable3d': 'FALSE',
        'isolation.tools.copy.disable': 'TRUE', 'isolation.tools.paste.disable': 'TRUE',
        'isolation.tools.hgfs.disable': 'TRUE', 'isolation.tools.dnd.disable': 'TRUE',
        'sharedFolder.maxNum': '0', 'serial0.present': 'TRUE', 'serial0.fileType': 'pipe',
        'serial0.pipe.endPoint': 'client', 'serial0.tryNoRxLoss': 'FALSE',
        'serial0.yieldOnMsrRead': 'TRUE', 'serial0.fileName': pipe_name(job_id),
        'mainMem.useNamedFile': 'FALSE', 'logging': 'FALSE', 'msg.autoAnswer': 'TRUE',
        'snapshot.disabled': 'TRUE', 'tools.syncTime': 'FALSE',
    }
    return '\n'.join(f'{key} = "{value}"' for key, value in values.items()) + '\n'


def pipe_name(job_id):
    return '\\\\.\\pipe\\angerona-analysis-' + job_id


@contextlib.contextmanager
def sealed_configuration(job_dir: Path, job_id: str):
    """Retain exact generated VMX custody through start, GO and teardown.

    Windows FILE_SHARE_READ denies concurrent writers/deletion. Do not relax
    this seal if a VMware version requires rewriting its configuration: that
    version needs a separately reviewed handoff before it can run this Lab.
    """
    expected = configuration(job_id).encode('utf-8')
    job_dir = Path(job_dir)
    if not job_dir.is_absolute() or job_dir.name != job_id:
        raise ValueError('Analysis configuration is outside its exact generated job.')
    vmx = job_dir / 'analysis.vmx'
    with _hold_plain_directories(job_dir):
        _validate_regular_file(vmx)
        with _open_sealed(vmx) as handle:
            original = os.fstat(handle.fileno())

            def verify():
                _validate_regular_file(vmx)
                named = vmx.stat(follow_symlinks=False)
                held = os.fstat(handle.fileno())
                identity = (original.st_dev, original.st_ino)
                if (not stat.S_ISREG(held.st_mode)
                        or held.st_nlink != 1 or named.st_nlink != 1
                        or (held.st_dev, held.st_ino) != identity
                        or (named.st_dev, named.st_ino) != identity):
                    raise ValueError('Analysis configuration identity or local alias changed.')
                handle.seek(0)
                if handle.read(len(expected) + 1) != expected:
                    raise ValueError('Analysis configuration differs from the fixed reviewed profile.')

            verify()
            yield verify
            verify()


def _control(directory, verb, vmx, *, timeout=20):
    from angerona.core.privilege import sanitized_child_environment
    args = [str(directory / 'vmrun.exe'), '-T', 'ws', verb, str(vmx)]
    args.append('nogui' if verb == 'start' else 'hard')
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout, cwd=str(directory),
                            env=sanitized_child_environment(), creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode and verb == 'start':
        output = (result.stdout + result.stderr).lower()
        if b'file access error' in output or b'sharing violation' in output:
            raise ValueError(
                'VMware could not open the protected analysis configuration. '
                'This installation has not passed the Lab isolation check. '
                'Configuration protection remains enabled; no analysis was accepted.'
            )
        raise ValueError('VMware could not start the analysis appliance. Check its Authorization Service and virtualization settings.')


def _client_job(pipe, expected_vmx, directory):
    """Bind the named-pipe client to this exact VM, then enforce OS quotas."""
    from ctypes import wintypes
    import psutil
    import win32api
    import win32job
    import win32process
    client = wintypes.ULONG()
    query = ctypes.WinDLL('kernel32', use_last_error=True).GetNamedPipeClientProcessId
    query.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG)]
    query.restype = wintypes.BOOL
    if not query(int(pipe), ctypes.byref(client)):
        raise ValueError('VMware output pipe has no verifiable client process.')
    handle = win32api.OpenProcess(0x0100 | 0x0001 | 0x0400, False, client.value)
    job = None
    try:
        job = win32job.CreateJobObject(None, '')
        process = psutil.Process(client.value)
        created = win32process.GetProcessTimes(handle)['CreationTime'].timestamp()
        if (abs(process.create_time() - created) > .001
                or Path(process.exe()) != directory / 'x64/vmware-vmx.exe'
                or not any(os.path.normcase(arg) == os.path.normcase(str(expected_vmx))
                           for arg in process.cmdline()) or process.children()
                or win32process.GetExitCodeProcess(handle) != 259):
            raise ValueError('VMware output did not originate from the isolated job process.')
        limits = win32job.QueryInformationJobObject(job, win32job.JobObjectExtendedLimitInformation)
        limits['BasicLimitInformation']['LimitFlags'] = (
            win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | win32job.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | win32job.JOB_OBJECT_LIMIT_PROCESS_MEMORY)
        limits['BasicLimitInformation']['ActiveProcessLimit'] = 1
        limits['ProcessMemoryLimit'] = 2 * 1024**3
        win32job.SetInformationJobObject(job, win32job.JobObjectExtendedLimitInformation, limits)
        win32job.AssignProcessToJobObject(job, handle)
        return job
    except Exception as exc:
        if job is not None:
            job.Close()
        if isinstance(exc, ValueError):
            raise
        raise ValueError('Windows could not enforce the analysis VM process limits.') from None
    finally:
        handle.Close()


def supervise(job_dir: Path, job_id: str, operation) -> bytes:
    import pywintypes
    import win32api
    import win32file
    import win32pipe
    import win32security
    service_ready()
    # Only this user and SYSTEM may attach; refuse remote clients and name reuse.
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), 8)
    try:
        sid = win32security.ConvertSidToStringSid(win32security.GetTokenInformation(token, 1)[0])
    finally:
        token.Close()
    security = pywintypes.SECURITY_ATTRIBUTES()
    security.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        f'D:P(A;;GA;;;SY)(A;;GA;;;{sid})', 1)
    pipe = win32pipe.CreateNamedPipe(pipe_name(job_id), win32pipe.PIPE_ACCESS_DUPLEX | 0x80000,
                                    win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_NOWAIT | 0x8,
                                    1, 4096, 4096, 0, security)
    vmx = job_dir / 'analysis.vmx'
    result = bytearray()
    job = None
    started = False
    try:
        try:
            win32pipe.ConnectNamedPipe(pipe, None)
        except pywintypes.error as exc:
            if exc.winerror != 536:
                raise
        with trusted_installation() as directory, sealed_configuration(job_dir, job_id) as verify_configuration:
            operation.check()
            try:
                verify_configuration()
                started = True  # Also clean up when the control request times out.
                _control(directory, 'start', vmx, timeout=45)
                while True:
                    operation.check()
                    try:
                        _, chunk = win32file.ReadFile(pipe, 8192)
                    except pywintypes.error as exc:
                        if exc.winerror == 109:
                            break
                        if exc.winerror not in (232, 233, 536):
                            raise
                        chunk = b''
                    if chunk:
                        result.extend(chunk)
                        if len(result) > MAX_OUTPUT:
                            raise ValueError('Analysis exceeded its 2 MiB output limit.')
                        if job is None and ('ANGERONA_READY:' + job_id).encode() in result:
                            job = _client_job(pipe, vmx, directory)
                            operation.check()
                            verify_configuration()
                            win32file.WriteFile(pipe, b'G')
                        if b'ANGERONA_ANALYZER_FAILED' in result:
                            raise ValueError('The offline analyzer failed; no raw source or secret output was retained.')
                        if b'ANGERONA_REPORT:' in result and result.endswith(b'\n'):
                            if job is None:
                                raise ValueError('Analyzer output arrived before host supervision.')
                            verify_configuration()
                            return bytes(result)
                    time.sleep(.05)
                raise ValueError('VMware stopped without a complete analysis report.')
            finally:
                # Closing a successfully assigned Job Object kills VMX even if
                # vmrun or the GUI has failed. Before the GO handshake only the
                # trusted boot entry point runs; it also has a 45-second timer.
                try:
                    if started:
                        _control(directory, 'stop', vmx)
                finally:
                    if job is not None:
                        job.Close()
                        job = None
    finally:
        if job is not None:
            job.Close()
        pipe.Close()
