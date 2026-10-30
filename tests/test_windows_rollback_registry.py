"""Inert native-registry boundary and servicing-provider coverage regressions."""
from __future__ import annotations

import ctypes
from contextlib import contextmanager
from ctypes import wintypes
from dataclasses import dataclass
import io
from pathlib import PureWindowsPath
import stat
import sys
from types import ModuleType, SimpleNamespace

import pytest

from angerona.core import windows_rollback_audit as audit
from angerona.core import privilege


WINDOWS = r"C:\Windows"
CANONICAL = WINDOWS + r"\WinSxS\pending.xml"
CUSTOM = r"C:\staging\pending.xml"
COMMAND = WINDOWS + r"\System32\poqexec.exe /display_progress " + CUSTOM
MULTI = (COMMAND + "\0\0").encode("utf-16-le")


@dataclass(frozen=True)
class NativeReply:
    status: int = 0
    kind: int = 7
    size: int | None = None
    raw: bytes = MULTI


def install_registry_boundary(monkeypatch, replies=(), *, open_error=None):
    """Model RegQueryValueExW's typed output pointers, never a real HKEY."""
    trace = SimpleNamespace(opened=[], closed=0, queries=[], loads=[])
    registry = ModuleType("winreg")
    registry.HKEY_LOCAL_MACHINE = 0x80000002
    registry.KEY_READ = 0x20019
    registry.KEY_WOW64_64KEY = 0x100
    registry.REG_MULTI_SZ = 7

    class Key:
        def __int__(self):
            return 1234

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            trace.closed += 1

    def open_key(*arguments):
        trace.opened.append(arguments)
        if open_error is not None:
            raise open_error
        return Key()

    class Query:
        def __call__(self, key, name, reserved, kind, data, size):
            assert key == 1234 and name == "PoqexecCmdline" and reserved is None
            size_pointer = ctypes.cast(size, ctypes.POINTER(wintypes.DWORD))
            kind_pointer = ctypes.cast(kind, ctypes.POINTER(wintypes.DWORD))
            capacity = size_pointer[0]
            index = len(trace.queries)
            assert index < len(replies), "unexpected additional native registry query"
            reply = replies[index]
            trace.queries.append((data is None, capacity))
            if data is not None:
                # A caller-selected fixed allocation must remain independent
                # of either registry-reported length, including racing growth.
                assert ctypes.sizeof(data) == capacity == 16384
                ctypes.memmove(data, reply.raw, min(len(reply.raw), capacity))
            kind_pointer[0] = reply.kind
            size_pointer[0] = len(reply.raw) if reply.size is None else reply.size
            return reply.status

    query = Query()

    def library(name, **kwargs):
        trace.loads.append((name, kwargs))
        assert name == "advapi32" and kwargs == {"use_last_error": True}
        return SimpleNamespace(RegQueryValueExW=query)

    registry.OpenKey = open_key
    monkeypatch.setitem(sys.modules, "winreg", registry)
    monkeypatch.setattr(ctypes, "WinDLL", library, raising=False)
    return trace


@contextmanager
def registry_boundary(monkeypatch, *args, **kwargs):
    # Do not retain global ctypes/winreg models into unrelated Qt cleanup.
    with monkeypatch.context() as scoped:
        yield install_registry_boundary(scoped, *args, **kwargs)


def test_native_registry_reads_exactly_two_bounded_queries_and_closes_key(monkeypatch):
    with registry_boundary(monkeypatch, [NativeReply(), NativeReply()]) as trace:
        assert audit.read_pending_reference(WINDOWS) == (CUSTOM, "custom-local-reference")
    assert trace.queries == [(True, 0), (False, 16384)]
    assert trace.closed == 1
    assert trace.opened == [(0x80000002,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\SideBySide\Configuration", 0, 0x20119)]


@pytest.mark.parametrize("source", ["key", "value"])
def test_native_absence_alone_selects_canonical_default(monkeypatch, source):
    with registry_boundary(monkeypatch, [NativeReply(status=2)],
             open_error=FileNotFoundError("modeled missing key") if source == "key" else None) as trace:
        assert audit.read_pending_reference(WINDOWS) == (CANONICAL, "canonical-default")
    assert len(trace.queries) == (0 if source == "key" else 1)
    assert trace.closed == (0 if source == "key" else 1)


def test_native_key_access_denied_does_not_fall_back(monkeypatch):
    with registry_boundary(monkeypatch, open_error=PermissionError("modeled key denied")) as trace:
        with pytest.raises(PermissionError):
            audit.read_pending_reference(WINDOWS)
    assert trace.queries == [] and trace.loads == [] and trace.closed == 0


@pytest.mark.parametrize("reply", [
    NativeReply(status=5), NativeReply(status=234), NativeReply(kind=1),
    NativeReply(size=0), NativeReply(size=3), NativeReply(size=16385),
], ids=["denied", "more-data", "wrong-type", "empty-size", "short-size", "oversize"])
def test_first_query_errors_and_unbounded_values_hold_before_allocation(monkeypatch, reply):
    with registry_boundary(monkeypatch, [reply]) as trace, monkeypatch.context() as scoped:
        scoped.setattr(ctypes, "create_string_buffer",
                       lambda *_a: pytest.fail("unadmitted registry value allocated a native buffer"))
        with pytest.raises(ValueError):
            audit.read_pending_reference(WINDOWS)
    assert trace.queries == [(True, 0)] and trace.closed == 1


@pytest.mark.parametrize("reply", [
    NativeReply(status=2), NativeReply(status=5), NativeReply(status=234, size=32768),
    NativeReply(kind=1), NativeReply(size=16385), NativeReply(size=3),
    NativeReply(raw=b"\0" * 5), NativeReply(raw=MULTI[:-2]),
    NativeReply(raw=b"\x00\xd8\0\0\0\0"),
    NativeReply(raw=(COMMAND + "\0" + COMMAND + "\0\0").encode("utf-16-le")),
], ids=["disappeared", "denied", "racing-growth", "type-race", "bad-native-size", "short-size",
        "odd-utf16", "missing-double-terminator", "invalid-utf16", "multiple-items"])
def test_second_query_races_and_malformed_multisz_are_coverage_holds(monkeypatch, reply):
    with registry_boundary(monkeypatch, [NativeReply(), reply]) as trace:
        with pytest.raises(ValueError):
            audit.read_pending_reference(WINDOWS)
    assert trace.queries == [(True, 0), (False, 16384)] and trace.closed == 1


def install_provider_paths(monkeypatch, *, reference=(CANONICAL, "canonical-default"),
                           reference_error=None, pending_error=None, old_error=None, old_reparse=False):
    """Every path, open and stat belongs to this inert model, never the host."""
    trace = SimpleNamespace(reference_reads=0, regular=[], opens=[], versions=[], stats=[])
    old_path = r"C:\Windows.old"

    class Path(PureWindowsPath):
        def lstat(self):
            trace.stats.append(str(self))
            assert str(self) == old_path
            if old_error is not None:
                raise old_error
            return SimpleNamespace(st_mode=stat.S_IFDIR,
                st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT if old_reparse else 0)

        def open(self, mode):
            trace.opens.append((str(self), mode))
            assert mode == "rb" and str(self) == reference[0]
            return io.BytesIO(b"<PendingTransaction><POQ/></PendingTransaction>")

    def read_reference(_windows):
        trace.reference_reads += 1
        if reference_error is not None:
            raise reference_error
        return reference

    def regular(path):
        trace.regular.append(path)
        assert path == reference[0]
        if pending_error is not None:
            raise pending_error
        return SimpleNamespace()

    def version(path):
        trace.versions.append(path)
        return (10, 0, 26100, 1)

    monkeypatch.setattr(audit, "Path", Path)
    monkeypatch.setattr(audit, "read_pending_reference", read_reference)
    monkeypatch.setattr(audit, "_regular_local", regular)
    monkeypatch.setattr(audit, "read_disk_version", version)
    monkeypatch.setattr(privilege, "trusted_windows_directories",
                        lambda: (Path(WINDOWS), Path(WINDOWS) / "System32"))
    return trace


def test_provider_unknown_registry_reference_never_reads_canonical_fallback(monkeypatch):
    trace = install_provider_paths(monkeypatch, reference_error=ValueError("modeled unsupported registry"),
                                    old_error=FileNotFoundError("modeled absent Windows.old"))
    result = audit.WindowsRollbackAuditProvider().collect()
    assert result.queue_reference == "unavailable-or-unsupported"
    assert result.pending_state == "unavailable-or-unsupported" and result.unsupported > 0
    assert trace.reference_reads == 1 and trace.regular == trace.opens == trace.versions == []
    assert not result.leads and result.event_details()["response_authorized"] is False


@pytest.mark.parametrize("reference,state", [
    ((CUSTOM, "custom-local-reference"), "unavailable-or-unsupported"),
    ((CANONICAL, "canonical-reference"), "unavailable-or-unsupported"),
    ((CANONICAL, "canonical-default"), "absent"),
], ids=["custom-reference", "explicit-canonical-reference", "absent-default"])
def test_provider_missing_selected_queue_preserves_reference_uncertainty(monkeypatch, reference, state):
    trace = install_provider_paths(monkeypatch, reference=reference,
        pending_error=FileNotFoundError("modeled missing selected queue"),
        old_error=FileNotFoundError("modeled absent Windows.old"))
    result = audit.WindowsRollbackAuditProvider().collect()
    assert result.queue_reference == reference[1] and result.pending_state == state
    assert trace.regular == [reference[0]] and trace.opens == trace.versions == []
    assert not result.leads


def test_provider_redirected_pending_sample_is_unavailable_without_reading(monkeypatch):
    trace = install_provider_paths(monkeypatch, reference=(CUSTOM, "custom-local-reference"),
        pending_error=ValueError("modeled reparse sample unavailable"),
        old_error=FileNotFoundError("modeled absent Windows.old"))
    result = audit.WindowsRollbackAuditProvider().collect()
    assert result.pending_state == "unavailable-or-unsupported"
    assert result.queue_reference == "custom-local-reference"
    assert trace.regular == [CUSTOM] and trace.opens == trace.versions == []


@pytest.mark.parametrize("old_error,reparse", [
    (None, True), (PermissionError("modeled Windows.old denied"), False),
], ids=["redirected-old-root", "unreadable-old-root"])
def test_provider_windows_old_uncertainty_is_an_explicit_gap(monkeypatch, old_error, reparse):
    trace = install_provider_paths(monkeypatch, pending_error=FileNotFoundError("modeled no pending queue"),
                                    old_error=old_error, old_reparse=reparse)
    result = audit.WindowsRollbackAuditProvider().collect()
    assert result.pending_state == "absent" and result.unavailable == 1
    assert trace.stats == [r"C:\Windows.old"] and trace.versions == []
    assert not result.leads and result.event_details()["full_queue_coverage"] is False
