"""Kernel validation and lifetime of the critical startup scratch capability."""
from __future__ import annotations

import ctypes
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

import pytest

from angerona import startup
from angerona.core import startup_recovery as recovery


pytestmark = pytest.mark.skipif(os.name != "nt", reason="Native Windows startup scratch lease")


class Guard:
    def __init__(self, root: Path, *, role="preflight", writable=False, shared_write=False, content=b""):
        self.root = root / "installation"
        self.storage = root / "state"
        self.root.mkdir(parents=True)
        directory = self.storage / "tmp" / f"startup-temp.critical-{role}"
        directory.parent.mkdir(parents=True)
        assert recovery.private_directory(directory, create=True)
        self.path = directory / "startup-critical.lease"
        self.kernel = kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel.GetCurrentProcess.restype = w.HANDLE
        kernel.CloseHandle.argtypes = (w.HANDLE,)
        kernel.CloseHandle.restype = w.BOOL
        kernel.LocalFree.argtypes = (w.LPVOID,)
        kernel.LocalFree.restype = w.LPVOID
        kernel.CreateFileW.argtypes = (w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID, w.DWORD, w.DWORD, w.HANDLE)
        kernel.CreateFileW.restype = w.HANDLE
        advapi.OpenProcessToken.argtypes = (w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE))
        advapi.GetTokenInformation.argtypes = (w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD))
        advapi.ConvertSidToStringSidW.argtypes = (w.LPVOID, ctypes.POINTER(w.LPWSTR))
        advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = (w.LPCWSTR, w.DWORD, ctypes.POINTER(w.LPVOID), ctypes.POINTER(w.DWORD))
        token = w.HANDLE()
        assert advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token))
        sid = w.LPWSTR()
        try:
            needed = w.DWORD()
            advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
            info = ctypes.create_string_buffer(needed.value)
            assert advapi.GetTokenInformation(token, 1, info, len(info), ctypes.byref(needed))
            assert advapi.ConvertSidToStringSidW(ctypes.c_void_p.from_buffer(info).value, ctypes.byref(sid))
            identity = sid.value
        finally:
            if sid:
                kernel.LocalFree(sid)
            assert kernel.CloseHandle(token)
        descriptor = w.LPVOID()
        size = w.DWORD()
        assert advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            f"O:{identity}D:P(A;;FA;;;{identity})(A;;FA;;;SY)(A;;FA;;;BA)", 1,
            ctypes.byref(descriptor), ctypes.byref(size))

        class Attributes(ctypes.Structure):
            _fields_ = [("length", w.DWORD), ("descriptor", w.LPVOID), ("inherit", w.BOOL)]

        attributes = Attributes(ctypes.sizeof(Attributes), descriptor, False)
        try:
            created = kernel.CreateFileW(str(self.path), 0x12019F, 3, ctypes.byref(attributes), 1, 0x00200080, None)
            assert created != ctypes.c_void_p(-1).value
        finally:
            kernel.LocalFree(descriptor)
        assert kernel.CloseHandle(created)
        if content:
            self.path.write_bytes(content)
        self.handle = kernel.CreateFileW(str(self.path), 0x12019F if writable else 0x120089,
                                         3 if shared_write else 1, None, 3, 0x00200000, None)
        assert self.handle != ctypes.c_void_p(-1).value
        self.plan = startup.LaunchPlan(self.root, self.storage, (sys.executable,), False)

    def writer_allowed(self):
        handle = self.kernel.CreateFileW(str(self.path), 2, 3, None, 3, 0x00200000, None)
        if handle == ctypes.c_void_p(-1).value:
            assert ctypes.get_last_error() == 32
            return False
        assert self.kernel.CloseHandle(handle)
        return True

    def close(self):
        if self.handle is not None:
            handle, self.handle = self.handle, None
            assert self.kernel.CloseHandle(handle)


def test_valid_guard_allows_real_private_io_below_advisory_reserve_and_no_new_guids(tmp_path, monkeypatch):
    guard = Guard(tmp_path)
    lease = None
    try:
        lease = startup._CriticalScratchLease(guard.plan, str(guard.handle))
        monkeypatch.setattr(startup.shutil, "disk_usage", lambda _path: type("Usage", (), {"free": 0})())
        startup.prepare_storage(guard.storage, scratch_lease=lease)
        for _ in range(40):
            assert recovery.select_temporary(guard.storage, guard.root, validate=startup._plain_path,
                                             fixed=lambda _anchor: True, inherited={},
                                             critical_directory=lease.directory) == guard.path.parent
        assert list(guard.path.parent.parent.iterdir()) == [guard.path.parent]
        with pytest.raises(startup.StartupError, match="128 MB"):
            startup.prepare_storage(guard.storage)
        monkeypatch.setattr(startup, "write_read_proof", lambda _path: (_ for _ in ()).throw(OSError("required I/O unavailable")))
        with pytest.raises(OSError, match="required I/O"):
            startup.prepare_storage(guard.storage, scratch_lease=lease)
    finally:
        if lease:
            lease.close()
        guard.close()


@pytest.mark.parametrize("options", [dict(writable=True), dict(shared_write=True), dict(role="control"), dict(content=b"changed")])
def test_guard_validation_rejects_untrusted_rights_sharing_purpose_and_content(tmp_path, options):
    guard = Guard(tmp_path, **options)
    try:
        with pytest.raises(startup.StartupError):
            startup._CriticalScratchLease(guard.plan, str(guard.handle))
    finally:
        guard.close()


DUMMY = r"""
import ctypes,json,os,sys,time
from ctypes import wintypes as w
k=ctypes.WinDLL('kernel32',use_last_error=True)
k.GetCurrentProcess.restype=w.HANDLE
k.GetProcessTimes.argtypes=(w.HANDLE,*([ctypes.POINTER(w.FILETIME)]*4))
values=[w.FILETIME() for _ in range(4)]
assert k.GetProcessTimes(k.GetCurrentProcess(),*(ctypes.byref(v) for v in values))
birth=(values[0].dwHighDateTime<<32)|values[0].dwLowDateTime
with open(sys.argv[1]+'.publishing','w',encoding='utf-8') as out:json.dump({'pid':os.getpid(),'birth':str(birth)},out)
os.replace(sys.argv[1]+'.publishing',sys.argv[1])
time.sleep(30)
"""


def retain_dummy(kernel, identity_path):
    deadline = time.monotonic() + 10
    while not identity_path.exists() and time.monotonic() < deadline:
        time.sleep(.02)
    record = json.loads(identity_path.read_text(encoding="utf-8"))
    kernel.OpenProcess.argtypes = (w.DWORD, w.BOOL, w.DWORD)
    kernel.OpenProcess.restype = w.HANDLE
    kernel.GetProcessTimes.argtypes = (w.HANDLE, *([ctypes.POINTER(w.FILETIME)] * 4))
    kernel.WaitForSingleObject.argtypes = (w.HANDLE, w.DWORD)
    kernel.WaitForSingleObject.restype = w.DWORD
    kernel.TerminateProcess.argtypes = (w.HANDLE, w.UINT)
    handle = kernel.OpenProcess(0x101001, False, record["pid"])
    assert handle
    values = [w.FILETIME() for _ in range(4)]
    assert kernel.GetProcessTimes(handle, *(ctypes.byref(v) for v in values))
    assert str((values[0].dwHighDateTime << 32) | values[0].dwLowDateTime) == record["birth"]
    assert kernel.WaitForSingleObject(handle, 0) == 258
    return handle


def test_native_probe_retains_guard_after_helper_copy_closes_until_job_retires(tmp_path, monkeypatch):
    guard = Guard(tmp_path)
    lease = startup._CriticalScratchLease(guard.plan, str(guard.handle))
    monkeypatch.setattr(startup._STARTUP_CONTEXT, "critical_scratch_lease", lease, raising=False)
    monkeypatch.setattr(startup._STARTUP_CONTEXT, "probe_lease", None, raising=False)
    output = tmp_path / "probe.log"
    identity = tmp_path / "probe.json"
    probe = None
    try:
        with output.open("wb") as stream:
            probe = startup._WindowsProbe([sys.executable, "-c", DUMMY, str(identity)], cwd=tmp_path,
                                           env=dict(os.environ), stdout=stream)
        held = retain_dummy(guard.kernel, identity)
        try:
            guard.close(); lease.close()
            assert not guard.writer_allowed()
            probe.close()
            assert guard.kernel.WaitForSingleObject(held, 5000) == 0
            assert guard.writer_allowed()
        finally:
            guard.kernel.CloseHandle(held)
    finally:
        if probe:
            probe.close()
        lease.close(); guard.close()


def test_core_handoff_keeps_guard_when_monitor_cancels_without_killing_core(tmp_path, monkeypatch):
    guard = Guard(tmp_path)
    identity = tmp_path / "core-fixture.json"
    plan = startup.LaunchPlan(guard.root, guard.storage, (sys.executable, "-c", DUMMY, str(identity)), False)
    monkeypatch.setattr(startup, "platform_plan", lambda: plan)
    monkeypatch.setattr(startup, "_assert_no_pending_repair", lambda _plan: None)
    monkeypatch.setattr(startup, "probe_source", lambda *_args: None)
    monkeypatch.setenv("ANGERONA_STARTUP_SCRATCH_LEASE_HANDLE", str(guard.handle))
    from angerona.resilience import shutdown_token as shutdown_control
    monkeypatch.setattr(shutdown_control, "clear_standdown_for_storage", lambda _storage: None)
    monkeypatch.setattr(shutdown_control, "standdown_active_for_storage", lambda _storage: False)
    processes = []
    original = subprocess.Popen

    def capture(*args, **kwargs):
        assert kwargs["close_fds"] is True
        assert len(kwargs["startupinfo"].lpAttributeList["handle_list"]) == 1
        process = original(*args, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(startup.subprocess, "Popen", capture)
    monkeypatch.setattr(startup, "wait_dashboard", lambda *_args: (_ for _ in ()).throw(startup.StartupCancelled("fixture monitor closed")))
    held = None
    try:
        with pytest.raises(startup.StartupCancelled, match="fixture monitor"):
            startup.run_startup(lambda _message: None, threading.Event())
        held = retain_dummy(guard.kernel, identity)
        guard.close()
        assert not guard.writer_allowed()
        assert guard.kernel.WaitForSingleObject(held, 0) == 258
    finally:
        if held:
            assert guard.kernel.TerminateProcess(held, 0)
            assert guard.kernel.WaitForSingleObject(held, 5000) == 0
            guard.kernel.CloseHandle(held)
        for process in processes:
            process.wait(timeout=40)
        guard.close()
    assert guard.writer_allowed()
