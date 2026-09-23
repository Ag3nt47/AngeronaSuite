"""Bounded, diskless QEMU supervision with an immutable launch profile.

The caller MUST retain verified executable/DLL/firmware directory custody and
read-only kernel/initrd seals for the entire call. This module does not acquire
or trust a runtime. It starts only that runtime, at medium integrity, with no
configuration files, host disks, network, monitor, or host directory sharing.
"""
from __future__ import annotations

import ctypes
import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

SUPERVISOR_PROFILE = 'qemu-11.1-fixed-argv-medium-job-single-byte-no-vapic-v3'
MAX_OUTPUT = 2 * 1024**2
BOOT_SECONDS = 90
TOTAL_SECONDS = 300
MEMORY_LIMIT = 2 * 1024**3
CPU_RATE = 2500  # Windows hard cap: 25% of total host CPU capacity.


def fixed_arguments(runtime: Path, kernel: Path, initrd: Path, job_id: str) -> list[str]:
    """Return the complete reviewed command; no caller-supplied options exist."""
    if not isinstance(job_id, str) or not re.fullmatch('[0-9a-f]{32}', job_id):
        raise ValueError('Invalid analysis job identity.')
    runtime, kernel, initrd = Path(runtime), Path(kernel), Path(initrd)
    for path in (runtime, kernel, initrd):
        if (not path.is_absolute() or '..' in path.parts
                or str(path).startswith(('\\\\', '//'))
                or any(ord(char) < 32 for char in str(path))):
            raise ValueError('Analysis requires absolute, local, protected runtime paths.')
    return [
        str(runtime / 'qemu-system-x86_64.exe'),
        '-no-user-config', '-nodefaults', '-display', 'none', '-monitor', 'none',
        '-nic', 'none', '-parallel', 'none', '-serial', 'stdio', '-no-reboot',
        '-machine', 'pc-i440fx-11.1,usb=off,vmport=off',
        '-global', 'apic.vapic=off',
        '-accel', 'tcg,thread=single', '-cpu', 'max',
        '-smp', '1,sockets=1,cores=1,threads=1,maxcpus=1', '-m', '768M',
        '-L', str(runtime / 'share'), '-bios', str(runtime / 'share/bios-256k.bin'),
        '-kernel', str(kernel), '-initrd', str(initrd),
        '-append', 'console=ttyS0 quiet panic=1 rdinit=/init',
        '-name', 'angerona-analysis-' + job_id,
    ]


@dataclass(frozen=True)
class _Identity:
    sid: str
    session: int
    integrity: int
    elevated: bool
    primary: bool
    ui_access: bool


def _medium(identity):
    return (identity.integrity == 0x2000 and not identity.elevated
            and identity.primary and not identity.ui_access and identity.session > 0)


class _Native:
    """Win32 handle ownership boundary; imported lazily on Windows only."""

    def __init__(self):
        import win32api
        import win32event
        import win32file
        import win32job
        import win32pipe
        import win32process
        import win32security
        self.api, self.event, self.file = win32api, win32event, win32file
        self.job, self.pipe = win32job, win32pipe
        self.process, self.security = win32process, win32security

    def identity(self, process=None):
        security = self.security
        token = security.OpenProcessToken(
            self.api.GetCurrentProcess() if process is None else process, security.TOKEN_QUERY,
        )
        try:
            def info(name):
                return security.GetTokenInformation(token, getattr(security, name))
            label = info('TokenIntegrityLevel')[0]
            return _Identity(
                security.ConvertSidToStringSid(info('TokenUser')[0]),
                int(info('TokenSessionId')),
                int(label.GetSubAuthority(label.GetSubAuthorityCount() - 1)),
                bool(info('TokenElevation')), info('TokenType') == 1, bool(info('TokenUIAccess')),
            )
        finally:
            token.Close()

    def system_directory(self):
        from ctypes import wintypes
        get = ctypes.WinDLL('kernel32', use_last_error=True).GetSystemDirectoryW
        get.argtypes = [wintypes.LPWSTR, wintypes.UINT]
        get.restype = wintypes.UINT
        buffer = ctypes.create_unicode_buffer(32768)
        size = get(buffer, len(buffer))
        if not 0 < size < len(buffer):
            raise OSError('Windows system directory could not be verified.')
        return Path(buffer.value)

    def pipes(self):
        import pywintypes
        security = pywintypes.SECURITY_ATTRIBUTES()
        security.bInheritHandle = True
        owned = []
        try:
            child_input, parent_input = self.pipe.CreatePipe(security, 4096)
            owned.extend((child_input, parent_input))
            parent_output, child_output = self.pipe.CreatePipe(security, 4096)
            owned.extend((parent_output, child_output))
            for handle in (parent_input, parent_output):
                self.api.SetHandleInformation(handle, 1, 0)
            return child_input, child_output, parent_input, parent_output
        except BaseException:
            for handle in owned:
                self.close(handle)
            raise

    def create(self, argv, directory, environment, child_input, child_output):
        from ctypes import wintypes

        class StartupInfo(ctypes.Structure):
            _fields_ = [
                ('cb', wintypes.DWORD), ('lpReserved', wintypes.LPWSTR),
                ('lpDesktop', wintypes.LPWSTR), ('lpTitle', wintypes.LPWSTR),
                ('dwX', wintypes.DWORD), ('dwY', wintypes.DWORD),
                ('dwXSize', wintypes.DWORD), ('dwYSize', wintypes.DWORD),
                ('dwXCountChars', wintypes.DWORD), ('dwYCountChars', wintypes.DWORD),
                ('dwFillAttribute', wintypes.DWORD), ('dwFlags', wintypes.DWORD),
                ('wShowWindow', wintypes.WORD), ('cbReserved2', wintypes.WORD),
                ('lpReserved2', ctypes.POINTER(ctypes.c_byte)),
                ('hStdInput', wintypes.HANDLE), ('hStdOutput', wintypes.HANDLE),
                ('hStdError', wintypes.HANDLE),
            ]

        class StartupInfoEx(ctypes.Structure):
            _fields_ = [('StartupInfo', StartupInfo), ('lpAttributeList', wintypes.LPVOID)]

        class ProcessInfo(ctypes.Structure):
            _fields_ = [('hProcess', wintypes.HANDLE), ('hThread', wintypes.HANDLE),
                        ('dwProcessId', wintypes.DWORD), ('dwThreadId', wintypes.DWORD)]

        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        initialize = kernel.InitializeProcThreadAttributeList
        initialize.argtypes = [wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
                               ctypes.POINTER(ctypes.c_size_t)]
        initialize.restype = wintypes.BOOL
        update = kernel.UpdateProcThreadAttribute
        update.argtypes = [wintypes.LPVOID, wintypes.DWORD, ctypes.c_size_t,
                           wintypes.LPVOID, ctypes.c_size_t, wintypes.LPVOID, wintypes.LPVOID]
        update.restype = wintypes.BOOL
        delete = kernel.DeleteProcThreadAttributeList
        delete.argtypes = [wintypes.LPVOID]
        delete.restype = None
        create = kernel.CreateProcessW
        create.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.LPVOID,
                           wintypes.LPVOID, wintypes.BOOL, wintypes.DWORD,
                           wintypes.LPVOID, wintypes.LPCWSTR,
                           ctypes.POINTER(StartupInfoEx), ctypes.POINTER(ProcessInfo)]
        create.restype = wintypes.BOOL

        size = ctypes.c_size_t()
        initialize(None, 1, 0, ctypes.byref(size))
        if not 0 < size.value <= 65536:
            raise OSError('Windows process handle list could not be allocated.')
        attributes = ctypes.create_string_buffer(size.value)
        if not initialize(attributes, 1, 0, ctypes.byref(size)):
            raise OSError('Windows process handle list could not be initialized.')
        try:
            handles = (wintypes.HANDLE * 2)(int(child_input), int(child_output))
            if not update(attributes, 0, 0x20002, handles, ctypes.sizeof(handles), None, None):
                raise OSError('Windows could not restrict inherited analysis handles.')
            startup = StartupInfoEx()
            startup.StartupInfo.cb = ctypes.sizeof(startup)
            startup.StartupInfo.dwFlags = 0x101  # USESTDHANDLES | USESHOWWINDOW.
            startup.StartupInfo.wShowWindow = 0
            startup.StartupInfo.hStdInput = int(child_input)
            startup.StartupInfo.hStdOutput = int(child_output)
            startup.StartupInfo.hStdError = int(child_output)
            startup.lpAttributeList = ctypes.cast(attributes, wintypes.LPVOID)
            command = subprocess.list2cmdline(argv)
            if len(command) >= 32767:
                raise ValueError('Analysis runtime paths are too long.')
            command_buffer = ctypes.create_unicode_buffer(command)
            block = '\0'.join(f'{key}={environment[key]}'
                              for key in sorted(environment, key=str.casefold)) + '\0\0'
            environment_buffer = ctypes.create_unicode_buffer(block)
            process = ProcessInfo()
            # SUSPENDED | UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT | NO_WINDOW.
            flags = 0x00000004 | 0x00000400 | 0x00080000 | 0x08000000 | 0x00004000
            if not create(argv[0], command_buffer, None, None, True, flags,
                          environment_buffer, str(directory), ctypes.byref(startup),
                          ctypes.byref(process)):
                raise OSError('Windows could not create the suspended analysis process.')
            return int(process.hProcess), int(process.hThread), int(process.dwProcessId)
        finally:
            delete(attributes)

    def make_job(self):
        from ctypes import wintypes
        job = self.job.CreateJobObject(None, '')
        try:
            limits = self.job.QueryInformationJobObject(
                job, self.job.JobObjectExtendedLimitInformation,
            )
            limits['BasicLimitInformation']['LimitFlags'] = (
                self.job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                | self.job.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
                | self.job.JOB_OBJECT_LIMIT_PROCESS_MEMORY
            )
            limits['BasicLimitInformation']['ActiveProcessLimit'] = 1
            limits['ProcessMemoryLimit'] = MEMORY_LIMIT
            self.job.SetInformationJobObject(job, self.job.JobObjectExtendedLimitInformation, limits)

            class CpuLimits(ctypes.Structure):
                _fields_ = [('ControlFlags', wintypes.DWORD), ('CpuRate', wintypes.DWORD)]
            cpu = CpuLimits(0x1 | 0x4, CPU_RATE)  # ENABLE | HARD_CAP.
            set_info = ctypes.WinDLL('kernel32', use_last_error=True).SetInformationJobObject
            set_info.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
            set_info.restype = wintypes.BOOL
            if not set_info(int(job), 15, ctypes.byref(cpu), ctypes.sizeof(cpu)):
                raise OSError('Windows could not enforce the analysis CPU limit.')
            return job
        except BaseException:
            job.Close()
            raise

    def assign(self, job, process):
        self.job.AssignProcessToJobObject(job, process)

    def image_and_pid(self, process):
        from ctypes import wintypes
        query = ctypes.WinDLL('kernel32', use_last_error=True).QueryFullProcessImageNameW
        query.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                          ctypes.POINTER(wintypes.DWORD)]
        query.restype = wintypes.BOOL
        buffer = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(buffer))
        if not query(process, 0, buffer, ctypes.byref(size)):
            raise OSError('The suspended analysis image could not be verified.')
        return Path(buffer.value), self.process.GetProcessId(process)

    def resume(self, thread):
        return self.process.ResumeThread(thread)

    def read(self, handle):
        try:
            _data, available, _left = self.pipe.PeekNamedPipe(handle, 0)
            if available:
                return self.file.ReadFile(handle, min(8192, available))[1]
            return b''
        except self.api.error as exc:
            if exc.winerror in (109, 232):  # Broken pipe or closed peer.
                return b''
            raise

    def write(self, handle, data):
        # A single byte avoids QEMU's Windows stdio backend dropping subsequent
        # bytes while the emulated UART cannot accept them. The exclusive pipe,
        # attested child and exact READY UUID already bind this authorization.
        if data != b'G' or self.file.WriteFile(handle, data)[1] != 1:
            raise OSError('Analysis start handshake could not be delivered.')

    def exited(self, process):
        return self.event.WaitForSingleObject(process, 0) == 0

    def reap(self, process, job):
        # Handle ownership, not names/PIDs or a machine-wide process search,
        # determines the only process this supervisor is allowed to terminate.
        deadline = time.monotonic() + 5
        if job is not None:
            try:
                self.job.TerminateJobObject(job, 1)
            except Exception:
                # Assignment or job termination may have failed. The exact
                # creation handle still provides a safe, mandatory fallback.
                pass
        # Job termination is asynchronous. AccessDenied from TerminateProcess
        # can mean that termination is already pending, not that the process
        # survived. Accept success only after the creation handle is signalled.
        if self.event.WaitForSingleObject(process, 100) == 0:
            return
        failure = None
        if not self.exited(process):
            try:
                self.api.TerminateProcess(process, 1)
            except Exception as exc:
                failure = exc
        remaining = max(0, int((deadline - time.monotonic()) * 1000))
        if self.event.WaitForSingleObject(process, remaining) != 0:
            raise OSError('The owned analysis process did not stop; no result was accepted.') from failure

    def close(self, handle):
        if hasattr(handle, 'Close'):
            handle.Close()
        else:
            self.api.CloseHandle(handle)


def _supervise(native, arguments, job_id, operation):
    child_input = child_output = parent_input = parent_output = None
    process = thread = job = None
    try:
        operation.check()
        parent = native.identity()
        if not _medium(parent):
            raise ValueError('Run Analysis Lab from a normal, non-administrator user session.')
        directory = native.system_directory()
        # Do not inherit PATH, HOME, APPDATA, QEMU_*, GLib or Python settings.
        environment = {'SystemRoot': str(directory.parent), 'WINDIR': str(directory.parent),
                       'PATH': str(directory), 'GNUTLS_SYSTEM_PRIORITY_FILE': 'NUL',
                       'OPENSSL_CONF': 'NUL',
                       'OPENSSL_MODULES': str(Path(arguments[0]).parent / 'COPYING'),
                       'OPENSSL_ENGINES': str(Path(arguments[0]).parent / 'COPYING')}
        job = native.make_job()
        child_input, child_output, parent_input, parent_output = native.pipes()
        operation.check()
        process, thread, pid = native.create(
            arguments, directory, environment, child_input, child_output,
        )
        native.close(child_input)
        child_input = None
        native.close(child_output)
        child_output = None
        native.assign(job, process)
        child = native.identity(process)
        image, actual_pid = native.image_and_pid(process)
        if (not _medium(child) or child.sid != parent.sid or child.session != parent.session
                or actual_pid != pid or image != Path(arguments[0]) or native.exited(process)):
            raise ValueError('The suspended analysis process did not match its trusted identity.')
        operation.check()
        if native.resume(thread) != 1:
            raise ValueError('The analysis process was not exclusively suspended before supervision.')
        native.close(thread)
        thread = None
        started = time.monotonic()
        output = bytearray()
        scan = 0
        go_offset = None
        ready = ('ANGERONA_READY:' + job_id).encode()
        while True:
            operation.check()
            elapsed = time.monotonic() - started
            if elapsed >= TOTAL_SECONDS or (go_offset is None and elapsed >= BOOT_SECONDS):
                raise ValueError('The isolated analysis appliance exceeded its startup or execution deadline.')
            chunk = native.read(parent_output)
            if chunk:
                if len(output) + len(chunk) > MAX_OUTPUT:
                    raise ValueError('Analysis exceeded its 2 MiB output limit.')
                output.extend(chunk)
                while True:
                    end = output.find(b'\n', scan)
                    if end < 0:
                        break
                    line_start = scan
                    line = bytes(output[scan:end]).rstrip(b'\r')
                    scan = end + 1
                    if b'ANGERONA_ANALYZER_FAILED' in line:
                        raise ValueError('The offline analyzer failed; no raw source or secret output was retained.')
                    if line == ready:
                        if go_offset is not None:
                            raise ValueError('The analysis appliance repeated its start handshake.')
                        operation.check()
                        go_offset = len(output)
                        native.write(parent_input, b'G')
                    elif line.startswith(b'ANGERONA_READY:'):
                        raise ValueError('The analysis appliance reported a different job identity.')
                    elif line.startswith(b'ANGERONA_REPORT:'):
                        if go_offset is None or line_start < go_offset:
                            raise ValueError('Analyzer output arrived before the host start handshake.')
                        operation.check()
                        return bytes(output)
            elif native.exited(process):
                raise ValueError('The isolated analysis appliance stopped without a complete report.')
            time.sleep(.05)
    finally:
        try:
            if process is not None:
                native.reap(process, job)
        finally:
            errors = []
            for handle in (thread, process, job, child_input, child_output, parent_input, parent_output):
                if handle is not None:
                    try:
                        native.close(handle)
                    except Exception as exc:
                        errors.append(exc)
            if errors:
                raise OSError('Windows analysis handles could not all be closed.') from errors[0]


def supervise(runtime: Path, kernel: Path, initrd: Path, job_id: str, operation) -> bytes:
    """Run one isolated job while the caller holds the complete verified runtime."""
    if os.name != 'nt':
        raise ValueError('This isolated Analysis Lab runtime currently requires Windows.')
    return _supervise(_Native(), fixed_arguments(runtime, kernel, initrd, job_id), job_id, operation)
