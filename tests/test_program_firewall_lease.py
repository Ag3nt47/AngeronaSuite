"""Identity custody uses inert adapters or owned children, never a firewall."""
from __future__ import annotations

from dataclasses import replace
import os
import shutil
import subprocess

import pytest

from angerona.core import program_firewall_lease as custody
from angerona.core.program_firewall_lease import (
    FileObjectIdentity, ProgramFirewallLease, ProgramFirewallLeaseError,
)
from angerona.core.windows_process_lease import ProcessObjectIdentity


class FakeNative:
    def __init__(self):
        self.process = ProcessObjectIdentity(4242, 116444736500000000, r"c:\fixture\target.exe")
        self.exited = False
        self.fixed = True
        self.calls = []
        self.next_handle = 100
        self.handles = {}
        self.handle_paths = {}
        self.closed = []
        self.open_error = None
        self.close_error = None
        self.case_flags = {"c:\\": 0, r"c:\fixture": 0}
        self.case_error = None
        self.identities = {
            "c:\\": FileObjectIdentity(1, "1" * 32, 0x10, 1, 0, 1, "c:\\"),
            r"c:\fixture": FileObjectIdentity(1, "2" * 32, 0x10, 1, 0, 1, r"c:\fixture"),
            r"c:\fixture\target.exe": FileObjectIdentity(1, "3" * 32, 0x80, 1, 123, 1, r"c:\fixture\target.exe"),
        }

    def fixed_drive(self, root):
        self.calls.append(("drive", root))
        return self.fixed

    def open_process(self, pid, rights, inherit):
        self.calls.append(("process", pid, rights, inherit))
        self.handles[99] = "process"
        return 99

    def process_identity(self, handle):
        assert handle == 99 and handle not in self.closed
        return self.process

    def process_exited(self, handle):
        assert handle == 99 and handle not in self.closed
        return self.exited

    def open_file(self, path, directory):
        self.calls.append(("file", path, directory))
        if self.open_error == path:
            raise OSError("inert sharing refusal")
        self.next_handle += 1
        self.handles[self.next_handle] = self.identities[path]
        self.handle_paths[self.next_handle] = path
        return self.next_handle

    def file_identity(self, handle):
        assert handle not in self.closed
        return self.handles[handle]

    def directory_case_flags(self, handle):
        assert handle not in self.closed
        path = self.handle_paths[handle]
        self.calls.append(("case", handle, path))
        if self.case_error == path:
            raise OSError("inert case-query unsupported or denied")
        return self.case_flags[path]

    def close(self, handle):
        assert handle not in self.closed
        self.closed.append(handle)
        if self.close_error == handle:
            raise OSError("inert uncertain close")


def acquire(native=None, **kwargs):
    return ProgramFirewallLease(4242, 50.0, r"c:\fixture\target.exe", _native=native or FakeNative(), **kwargs)


def test_query_only_noninheritable_process_and_all_files_survive_until_close():
    native = FakeNative()
    with acquire(native) as lease:
        proof = lease.proof()
        assert native.calls[0] == ("drive", "c:\\")
        assert native.calls[1] == ("process", 4242, 0x101000, False)
        assert proof["program_file_id"] == "3" * 32
        assert proof["native_birth_ticks"] == "116444736500000000"
        assert proof["program_ancestor_count"] == 2
        assert "not mapped image or socket" in proof["program_custody_scope"]
        retained = [handle for _name, handle, _identity, _directory in lease._files]
        assert not set(retained + [99]) & set(native.closed)
        lease.validate()
        lease.check_deadline()
    assert len(native.closed) == len(set(native.closed)) == len(native.handles)
    lease.close()  # No raw handle is closed twice.
    with pytest.raises(ProgramFirewallLeaseError, match="closed"):
        lease.validate()


@pytest.mark.parametrize("directory,flags", [(False, 0x00200000), (True, 0x02200000)])
def test_native_file_open_requests_participating_read_access_without_write_delete_sharing(directory, flags):
    from ctypes import wintypes
    from types import SimpleNamespace

    native = object.__new__(custody._Native)
    calls = []
    native.w = wintypes
    native.api = SimpleNamespace(CreateFileW=lambda *arguments: calls.append(arguments) or 101)
    assert native.open_file(r"c:\fixture", directory) == 101
    assert calls == [(r"c:\fixture", 0x81, 1, None, 3, flags, None)]


def test_native_process_image_query_keeps_case_instead_of_reusing_termination_normalization():
    import ctypes
    from types import SimpleNamespace

    image = r"C:\Fixture\A.exe"

    def query(handle, flags, buffer, size):
        assert handle == 99 and flags == 0
        buffer.value = image
        ctypes.cast(size, ctypes.POINTER(ctypes.c_uint32)).contents.value = len(image)
        return True

    native = object.__new__(custody._Native)
    native.c = ctypes
    native.w = SimpleNamespace(DWORD=ctypes.c_uint32)
    native.process = SimpleNamespace(object_identity=lambda handle: (4242, 116444736500000000))
    native.api = SimpleNamespace(QueryFullProcessImageNameW=query)
    assert native.process_identity(99).image == image
    assert custody._path(image) == image


def test_native_case_query_is_handle_bound_and_uses_exact_four_byte_info_class():
    import ctypes
    from types import SimpleNamespace

    calls = []

    def query(handle, info_class, pointer, length):
        calls.append((handle, info_class, length))
        ctypes.cast(pointer, ctypes.POINTER(ctypes.c_uint32)).contents.value = 1
        return True

    native = object.__new__(custody._Native)
    native.c = ctypes
    native.api = SimpleNamespace(GetFileInformationByHandleEx=query)
    assert native.directory_case_flags(123) == 1
    assert calls == [(123, 23, 4)]


def test_case_sensitive_upper_lower_siblings_are_not_folded_or_opened_as_each_other():
    native = FakeNative()
    upper, lower = r"c:\fixture\A.exe", r"c:\fixture\a.exe"
    native.process = replace(native.process, image=upper)
    native.identities[upper] = replace(native.identities.pop(r"c:\fixture\target.exe"), name=upper)
    native.identities[lower] = replace(native.identities[upper], name=lower, file_id="4" * 32)
    native.case_flags[r"c:\fixture"] = 1
    with pytest.raises(ProgramFirewallLeaseError, match="case-sensitive"):
        ProgramFirewallLease(4242, 50.0, upper, _native=native)
    assert not [call for call in native.calls if call[0] == "file" and call[1] in {upper, lower}]
    assert len(native.closed) == len(set(native.closed)) == len(native.handles)


def test_expected_native_and_final_case_differences_use_only_native_opens_after_custody():
    native = FakeNative()
    caller = r"C:\FIXTURE\TARGET.exe"
    for path, identity in native.identities.items():
        native.identities[path] = replace(identity, name=path.upper())
    with ProgramFirewallLease(4242, 50.0, caller, _native=native) as lease:
        assert lease.path == native.process.image == r"c:\fixture\target.exe"
        assert lease.proof()["program_file_id"] == "3" * 32
        opened = [call[1] for call in native.calls if call[0] == "file"]
        assert opened and all(path in native.identities for path in opened)
        assert caller not in opened and caller.lower() == lease.path
        # A new final-name spelling is harmless only with unchanged object IDs
        # and insensitive ancestor metadata. Named opens still use raw casing.
        path = r"c:\fixture\target.exe"
        native.identities[path] = replace(native.identities[path], name=r"C:\Fixture\Target.EXE")
        lease.validate()
        native.identities[path] = replace(native.identities[path], file_id="4" * 32)
        with pytest.raises(ProgramFirewallLeaseError, match="differs"):
            lease.validate()


def test_insensitive_ancestry_still_opens_only_raw_case_exact_image_spelling():
    native = FakeNative()
    upper = r"c:\fixture\A.exe"
    native.process = replace(native.process, image=upper)
    native.identities[upper] = replace(native.identities.pop(r"c:\fixture\target.exe"), name=upper)
    with ProgramFirewallLease(4242, 50.0, upper, _native=native) as lease:
        assert lease.path == lease.proof()["native_image"] == upper
        assert not [call for call in native.calls if call[0] == "file" and call[1] == upper.lower()]


@pytest.mark.parametrize("path", ["c:\\", r"c:\fixture"])
@pytest.mark.parametrize("flags", [1, 2, -1, None, False])
def test_sensitive_unknown_or_untyped_ancestry_is_refused_even_when_file_identity_is_unchanged(path, flags):
    native = FakeNative()
    native.case_flags[path] = flags
    with pytest.raises(ProgramFirewallLeaseError, match="case-sensitive"):
        acquire(native)
    assert len(native.closed) == len(set(native.closed)) == len(native.handles)


def test_unsupported_case_query_never_means_case_insensitive():
    native = FakeNative()
    native.case_error = r"c:\fixture"
    with pytest.raises(OSError, match="case-query"):
        acquire(native)
    assert len(native.closed) == len(set(native.closed)) == len(native.handles)


@pytest.mark.parametrize("path", ["c:\\", r"c:\fixture"])
def test_held_ancestor_case_flags_are_requeried_and_refuse_metadata_change(path):
    native = FakeNative()
    with acquire(native) as lease:
        retained = [handle for _name, handle, _identity, _directory in lease._files]
        native.case_flags[path] = 1
        with pytest.raises(ProgramFirewallLeaseError, match="case-sensitive"):
            lease.proof()
        assert not set(retained + [99]) & set(native.closed)


@pytest.mark.parametrize("image", [
    "relative.exe", r"\\server\share\target.exe", r"\\?\C:\fixture\target.exe",
    r"C:\fixture\..\target.exe", r"C:\fixture\target.exe:stream", "C:\\fixture\\target.exe ",
    "C:\\fixture\\target.exe.", r"C:\fixture\con.exe", "C:\\fixture\\target.exe\x00",
    "C:\\" + "folder\\" * 33 + "target.exe",
])
def test_unsupported_aliases_are_rejected_before_native_open(image):
    native = FakeNative()
    with pytest.raises(ProgramFirewallLeaseError):
        ProgramFirewallLease(4242, 50.0, image, _native=native)
    assert native.calls == []


@pytest.mark.parametrize("field,value", [
    ("pid", True), ("pid", 0), ("pid", 2**32),
    ("create_time", True), ("create_time", float("nan")), ("create_time", 10**400),
    ("lifetime", 0), ("lifetime", 61), ("lifetime", float("inf")),
])
def test_invalid_contract_or_deadline_never_opens(field, value):
    native = FakeNative()
    arguments = dict(pid=4242, create_time=50.0, image=r"C:\fixture\target.exe", _native=native)
    arguments[field] = value
    with pytest.raises(ProgramFirewallLeaseError):
        ProgramFirewallLease(**arguments)
    assert native.calls == []


def test_remote_drive_gate_precedes_process_and_path_queries():
    native = FakeNative()
    native.fixed = False
    with pytest.raises(ProgramFirewallLeaseError, match="fixed local"):
        acquire(native)
    assert native.calls == [("drive", "c:\\")]


@pytest.mark.parametrize("change", ["birth", "path", "exit", "ancestor", "same_name", "leaf_write", "links", "reparse"])
def test_changed_current_process_or_held_named_object_is_refused(change):
    native = FakeNative()
    with acquire(native) as lease:
        if change == "birth":
            native.process = replace(native.process, birth_ticks=native.process.birth_ticks + 1)
        elif change == "path":
            native.process = replace(native.process, image=r"c:\fixture\other.exe")
        elif change == "exit":
            native.exited = True
        else:
            path = r"c:\fixture" if change == "ancestor" else r"c:\fixture\target.exe"
            original = native.identities[path]
            field = {"ancestor": "file_id", "same_name": "file_id", "leaf_write": "write_ticks",
                     "links": "links", "reparse": "attributes"}[change]
            value = {"file_id": "4" * 32, "write_ticks": 2, "links": 2, "attributes": 0x480}[field]
            native.identities[path] = replace(original, **{field: value})
        with pytest.raises(ProgramFirewallLeaseError):
            lease.validate()
    assert native.closed[-1] == 99
    assert sum(call[0] == "process" for call in native.calls) == 1  # No PID reselection.


@pytest.mark.parametrize("path,change", [
    (r"c:\fixture", {"attributes": 0x410}),
    (r"c:\fixture\target.exe", {"links": 2}),
    (r"c:\fixture\target.exe", {"name": r"c:\fixture\different.exe"}),
    (r"c:\fixture\target.exe", {"file_id": "0" * 32}),
])
def test_initial_reparse_hardlink_or_name_ambiguity_closes_partial_custody(path, change):
    native = FakeNative()
    native.identities[path] = replace(native.identities[path], **change)
    with pytest.raises(ProgramFirewallLeaseError):
        acquire(native)
    assert len(native.closed) == len(set(native.closed)) == len(native.handles)


def test_sharing_refusal_does_not_fall_back_or_leak_previously_opened_handles():
    native = FakeNative()
    native.open_error = r"c:\fixture\target.exe"
    with pytest.raises(OSError, match="sharing"):
        acquire(native)
    assert len(native.closed) == len(set(native.closed)) == len(native.handles)
    assert sum(call[0] == "process" for call in native.calls) == 1


@pytest.mark.parametrize("now", [60.0, -1.0, float("nan")])
def test_expiry_or_clock_regression_refuses_validation_but_keeps_handles_for_rollback(now):
    native, clock = FakeNative(), [0.0]
    with acquire(native, _monotonic=lambda: clock[0]) as lease:
        retained = [handle for _name, handle, _identity, _directory in lease._files]
        clock[0] = now
        with pytest.raises(ProgramFirewallLeaseError):
            lease.validate()
        assert not set(retained + [99]) & set(native.closed)
    assert native.closed[-1] == 99


def test_close_failure_attempts_every_owned_handle_once_and_remains_explicit():
    native = FakeNative()
    lease = acquire(native)
    native.close_error = lease._files[-1][1]
    with pytest.raises(ProgramFirewallLeaseError, match="did not close"):
        lease.close()
    before = native.closed.copy()
    lease.close()
    assert native.closed == before
    assert len(native.closed) == len(set(native.closed)) == len(native.handles)


@pytest.mark.skipif(os.name != "nt", reason="native Windows handle/sharing contract")
@pytest.mark.parametrize("caller_spelling", ["original", "different_case"])
def test_native_owned_child_and_scratch_path_sharing_are_retained(tmp_path, caller_spelling):
    # Copy the OS command interpreter; the only command is its built-in stdin
    # read. No payload, firewall or third-party process is inspected.
    import ctypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetSystemDirectoryW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
    kernel.GetSystemDirectoryW.restype = ctypes.c_uint
    directory = ctypes.create_unicode_buffer(32768)
    length = kernel.GetSystemDirectoryW(directory, len(directory))
    assert 0 < length < len(directory)
    from pathlib import Path

    executable = tmp_path / "owned" / "cmd.exe"
    executable.parent.mkdir()
    shutil.copyfile(Path(directory[:length]) / "cmd.exe", executable)
    child = subprocess.Popen([str(executable), "/d", "/q", "/c", "set /p angerona_owned_probe="],
                             stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             creationflags=0x08000000)
    lease = None
    try:
        native = custody._Native()
        handle = native.open_process(child.pid, custody._PROCESS_RIGHTS, False)
        try:
            identity = native.process_identity(handle)
        finally:
            native.close(handle)
        assert child.poll() is None, "Owned inert command exited before custody acquisition"
        # Exercise the real caller boundary, not a path copied back from the
        # lease's own native identity query.
        expected = str(executable)
        if caller_spelling == "different_case":
            expected = expected.swapcase()
        lease = ProgramFirewallLease(child.pid, identity.create_time, expected)
        assert lease.path == identity.image
        lease.validate()
        with pytest.raises(OSError):
            executable.rename(executable.with_name("replacement.exe"))
        with pytest.raises(OSError):
            executable.write_bytes(b"inert denied write")
        with pytest.raises(OSError):
            executable.parent.rename(executable.parent.with_name("replacement-parent"))
        lease.close()
        lease = None
    finally:
        try:
            if lease is not None:
                lease.close()
        finally:
            try:
                if child.stdin is not None:
                    child.stdin.close()
            finally:
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    # Exact retained Popen handle only; never rediscover a PID.
                    child.kill()
                    child.wait(timeout=5)
                    raise
    assert child.returncode is not None


@pytest.mark.skipif(os.name != "nt", reason="native Windows file sharing contract")
def test_native_read_handles_deny_scratch_replacement_and_allow_it_after_release(tmp_path):
    folder = tmp_path / "owned-sharing"
    folder.mkdir()
    target = folder / "inert.bin"
    target.write_bytes(b"owned inert data")
    native = custody._Native()
    assert native.fixed_drive(str(tmp_path.anchor))
    handles = []
    try:
        handles.append(native.open_file(str(folder), True))
        handles.append(native.open_file(str(target), False))
        identity = native.file_identity(handles[-1])
        assert identity.links == 1 and identity.size == len(b"owned inert data")
        assert len(identity.file_id) == 32
        with pytest.raises(OSError):
            target.write_bytes(b"denied")
        with pytest.raises(OSError):
            target.rename(folder / "replacement.bin")
        with pytest.raises(OSError):
            folder.rename(tmp_path / "replacement-directory")
    finally:
        while handles:
            native.close(handles.pop())
    target.write_bytes(b"allowed after release")
    moved = target.rename(folder / "replacement.bin")
    assert moved.read_bytes() == b"allowed after release"


@pytest.mark.skipif(os.name != "nt", reason="native Windows per-directory case semantics")
def test_native_owned_case_sensitive_siblings_keep_distinct_ids_and_ancestry_is_refused(tmp_path):
    # No host-wide/ancestor setting changes. The optional flag change is on
    # this newly created empty owned directory only, with no elevation prompt.
    folder = tmp_path / "owned-case-semantics"
    folder.mkdir()
    native = custody._Native()
    c, w = native.c, native.w
    setter = native.api.SetFileInformationByHandle
    setter.argtypes = [w.HANDLE, c.c_int, w.LPVOID, w.DWORD]
    setter.restype = w.BOOL

    def writer(*, availability=False):
        handle = native.api.CreateFileW(str(folder), 0x180, 7, None, 3, 0x02200000, None)
        if handle == w.HANDLE(-1).value:
            error = c.get_last_error()
            if availability and error in {1, 5, 50, 87, 120, 1314}:
                pytest.skip(f"Owned scratch case attribute access unavailable (Windows {error})")
            pytest.fail(f"Unexpected owned scratch case handle failure (Windows {error})")
        return int(handle)

    def restore(handle):
        flags = c.c_uint32(0)
        assert setter(handle, 23, c.byref(flags), c.sizeof(flags)), "Owned scratch case flag restore failed"
        assert native.directory_case_flags(handle) == 0

    handle, changed = writer(availability=True), False
    try:
        try:
            original = native.directory_case_flags(handle)
        except ProgramFirewallLeaseError:
            error = c.get_last_error()
            if error in {1, 5, 50, 87, 120, 1314}:
                pytest.skip(f"Owned scratch case query unavailable (Windows {error})")
            raise
        assert original in {0, 1}
        if original == 0:
            flags = c.c_uint32(1)
            if not setter(handle, 23, c.byref(flags), c.sizeof(flags)):
                error = c.get_last_error()
                if error in {1, 5, 50, 87, 120, 1314}:
                    pytest.skip(f"Owned scratch case setting unavailable (Windows {error})")
                pytest.fail(f"Unexpected owned scratch case setting failure (Windows {error})")
            changed = True
        assert native.directory_case_flags(handle) == 1
    except BaseException:
        # Once changed, even a setup/query failure requires a proved restore;
        # no later access failure may downgrade this fixture to an availability
        # skip. The directory is still empty and this writer is still owned.
        if changed:
            restore(handle)
        raise
    finally:
        native.close(handle)

    upper, lower = folder / "A.exe", folder / "a.exe"
    handles = []
    try:
        upper.write_bytes(b"owned upper inert data")
        lower.write_bytes(b"owned lower inert data")
        handles.append(native.open_file(str(folder), True))
        handles.append(native.open_file(str(upper), False))
        handles.append(native.open_file(str(lower), False))
        first, second = native.file_identity(handles[1]), native.file_identity(handles[2])
        assert first.file_id != second.file_id and first.name != second.name
        assert first.name.endswith("\\A.exe") and second.name.endswith("\\a.exe")
        assert native.directory_case_flags(handles[0]) == 1
        # Exercise the exact lease refusal using real retained-directory data;
        # no process discovery or mutation is needed for this scratch case.
        lease = object.__new__(ProgramFirewallLease)
        lease._native, lease._closed = native, False
        lease._clock, lease._last_now, lease._deadline = lambda: 0.0, 0.0, 60.0
        with pytest.raises(ProgramFirewallLeaseError, match="case-sensitive"):
            lease._check_directory(handles[0])
    finally:
        try:
            while handles:
                native.close(handles.pop())
        finally:
            upper.unlink(missing_ok=True)
            lower.unlink(missing_ok=True)
            if changed:
                handle = writer()
                try:
                    restore(handle)
                finally:
                    native.close(handle)
