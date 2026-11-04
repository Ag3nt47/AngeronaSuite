"""Inert Windows registry adapter tests. No host registry is opened."""
from __future__ import annotations

import ctypes
import json

from angerona.core import spyware_native_windows as reader


class _Key:
    def __init__(self, registry, identity):
        self.registry, self.identity = registry, identity
        self.handle = len(registry.handles) + 1
        registry.handles[self.handle] = self
        self.closed = False

    def __int__(self):
        assert not self.closed
        return self.handle

    def __enter__(self):
        return self

    def __exit__(self, *_):
        assert not self.closed
        self.closed = True


class _Winreg:
    HKEY_LOCAL_MACHINE = object()
    KEY_QUERY_VALUE = 0x0001
    KEY_ENUMERATE_SUB_KEYS = 0x0008
    KEY_WOW64_32KEY = 0x0200
    KEY_WOW64_64KEY = 0x0100
    REG_SZ = 1
    REG_DWORD = 4

    def __init__(self):
        self.keys = {}
        self.denied = set()
        self.changing = set()
        self.calls = []
        self.handles = {}
        self.info_counts = {}

    def root(self, view, path, **values):
        self.keys[(view, path)] = values

    def put(self, view, root, image, **values):
        self.keys.setdefault((view, root), {})
        self.keys[(view, root + "\\" + image)] = values

    def OpenKey(self, parent, name, reserved, access):
        assert reserved == 0
        view = access & (self.KEY_WOW64_32KEY | self.KEY_WOW64_64KEY)
        assert view in (self.KEY_WOW64_32KEY, self.KEY_WOW64_64KEY)
        assert access & ~(view | self.KEY_QUERY_VALUE | self.KEY_ENUMERATE_SUB_KEYS) == 0
        assert access & self.KEY_QUERY_VALUE
        if parent is self.HKEY_LOCAL_MACHINE:
            assert name == reader._IFEO or name == reader._SILENT_EXIT or name.startswith(reader._IFEO + "\\")
            path = name
        else:
            assert not parent.closed and parent.identity[0] == view
            assert "\\" not in name
            path = parent.identity[1] + "\\" + name
        identity = view, path
        self.calls.append(("open", identity))
        if identity in self.denied:
            raise PermissionError("fixture-private-path")
        named = next((key for key in self.keys if key[0] == view and key[1].lower() == path.lower()), None)
        if named is None:
            raise FileNotFoundError("fixture-private-path")
        return _Key(self, named)

    def _children(self, key):
        assert not key.closed
        view, path = key.identity
        prefix = path + "\\"
        return [name[len(prefix):] for actual_view, name in self.keys
                if actual_view == view and name.startswith(prefix) and "\\" not in name[len(prefix):]]

    def QueryInfoKey(self, key):
        self.info_counts[key.identity] = self.info_counts.get(key.identity, 0) + 1
        return (len(self._children(key)), len(self.keys[key.identity]),
                self.info_counts[key.identity] if key.identity in self.changing else 1)

    def EnumKey(self, key, index):
        self.calls.append(("enumerate", key.identity, index))
        return self._children(key)[index]

    def query(self, handle, name, reserved, kind_pointer, buffer, size_pointer):
        key = self.handles[handle]
        assert not key.closed and reserved is None
        assert name in {"UseFilter", "Debugger", "GlobalFlag", "ReportingMode", "MonitorProcess"}
        self.calls.append(("value", key.identity, name))
        value = self.keys[key.identity].get(name)
        if value is None:
            return 2
        kind, payload = value
        kind_cell = ctypes.cast(kind_pointer, ctypes.POINTER(ctypes.c_uint32)).contents
        size_cell = ctypes.cast(size_pointer, ctypes.POINTER(ctypes.c_uint32)).contents
        assert size_cell.value == reader._MAX_VALUE_BYTES
        kind_cell.value = kind
        size_cell.value = len(payload)
        if len(payload) > reader._MAX_VALUE_BYTES:
            return 234
        ctypes.memmove(buffer, payload, len(payload))
        return 0


def _text(value):
    return _Winreg.REG_SZ, (value + "\0").encode("utf-16-le")


def _number(value):
    return _Winreg.REG_DWORD, value.to_bytes(4, "little")


def _collect(winreg, cancelled=lambda: False, clock=lambda: 0):
    result = reader._collect(reader._Registry(winreg, winreg.query), cancelled, clock)
    assert all(key.closed for key in winreg.handles.values())
    return result


def test_both_exact_logical_views_group_debugger_advisories_without_raw_commands():
    reg = _Winreg()
    for view, label in ((reg.KEY_WOW64_32KEY, "32"), (reg.KEY_WOW64_64KEY, "64")):
        reg.put(view, reader._IFEO, "MixedCase.exe", Debugger=_text("fixture-command-secret-" + label))
        reg.put(view, reader._IFEO, "normal.exe", GlobalFlag=_number(0))
    result = _collect(reg)
    assert result["state"] == "completed" and result["checked"] == 4
    (finding,) = result["findings"]
    assert finding["evidence_type"] == "ifeo-debugger"
    assert finding["image_name"] == "mixedcase.exe" and finding["registry_views"] == ["32", "64"]
    assert finding["classification"] == "advisory"
    assert finding["execution_observed"] is False and finding["response_authorized"] is False
    assert "fixture-command-secret" not in json.dumps(result)


def test_silent_launch_requires_all_three_fields_from_the_same_view():
    reg = _Winreg()
    x86 = reg.KEY_WOW64_32KEY
    x64 = reg.KEY_WOW64_64KEY
    reg.put(x86, reader._IFEO, "joined.exe", GlobalFlag=_text("0x00000200"))
    reg.put(x86, reader._SILENT_EXIT, "JOINED.EXE", ReportingMode=_number(3), MonitorProcess=_text("fixture-local"))
    reg.put(x64, reader._IFEO, "cross.exe", GlobalFlag=_number(0x200))
    reg.put(x86, reader._SILENT_EXIT, "cross.exe", ReportingMode=_number(1), MonitorProcess=_text("fixture-cross"))
    reg.put(x64, reader._IFEO, "dump.exe", GlobalFlag=_number(0x200))
    reg.put(x64, reader._SILENT_EXIT, "dump.exe", ReportingMode=_number(2), MonitorProcess=_text("fixture-dump"))
    reg.put(x64, reader._IFEO, "disabled.exe", GlobalFlag=_number(0))
    reg.put(x64, reader._SILENT_EXIT, "disabled.exe", ReportingMode=_number(1), MonitorProcess=_text("fixture-disabled"))

    result = _collect(reg)
    (finding,) = result["findings"]
    assert finding["evidence_type"] == "silent-process-exit-monitor"
    assert finding["image_name"] == "joined.exe" and finding["registry_views"] == ["32"]
    assert result["sources"]["silent-process-exit-monitor-32"]["configuration_counts"] == {
        "configured": 1, "image-flag-not-enabled": 1,
    }
    assert result["sources"]["silent-process-exit-monitor-64"]["configuration_counts"] == {
        "reporting-without-launch": 1, "image-flag-not-enabled": 1,
    }
    assert "fixture-" not in json.dumps(result)


def test_partial_coverage_for_filter_global_fallback_denial_and_invalid_typed_values():
    reg = _Winreg()
    x86 = reg.KEY_WOW64_32KEY
    x64 = reg.KEY_WOW64_64KEY
    reg.put(x86, reader._IFEO, "filtered.exe", UseFilter=_number(1), Debugger=_text("fixture-filtered"))
    reg.put(x86, reader._IFEO, "badtype.exe", Debugger=_number(8))
    reg.put(x86, reader._IFEO, "big.exe", Debugger=_text("x" * 3000))
    reg.put(x86, reader._IFEO, "embedded.exe", Debugger=_text("one\0two"))
    reg.put(x86, reader._IFEO, "fallback.exe", GlobalFlag=_number(0x200))
    reg.root(x86, reader._SILENT_EXIT, MonitorProcess=_text("fixture-global"))
    reg.put(x86, reader._SILENT_EXIT, "fallback.exe", ReportingMode=_number(1))
    reg.put(x86, reader._SILENT_EXIT, "filtered.exe", ReportingMode=_number(1), MonitorProcess=_text("fixture-filtered"))
    reg.denied.add((x64, reader._IFEO))
    result = _collect(reg)
    assert result["state"] == "partial" and not result["findings"]
    assert result["sources"]["ifeo-debugger-32"]["gaps"] == {
        "path-filter-not-evaluated": 1, "unexpected-value-type": 1, "value-size-limit": 1, "invalid-value": 1,
    }
    assert result["sources"]["silent-process-exit-monitor-32"]["gaps"] == {
        "global-monitor-not-evaluated": 1, "path-filter-not-evaluated": 1,
    }
    assert result["sources"]["ifeo-debugger-64"]["state"] == "unavailable"
    assert result["sources"]["ifeo-debugger-64"]["gaps"] == {"access-denied": 1}
    assert "fixture-" not in json.dumps(result)


def test_unstable_leaf_prevents_advisory_from_a_changing_join():
    reg = _Winreg()
    view = reg.KEY_WOW64_64KEY
    reg.put(view, reader._IFEO, "unstable.exe", GlobalFlag=_number(0x200))
    reg.put(view, reader._SILENT_EXIT, "unstable.exe", ReportingMode=_number(1), MonitorProcess=_text("fixture"))
    reg.changing.add((view, reader._IFEO + "\\unstable.exe"))
    result = _collect(reg)
    assert not result["findings"]
    assert result["sources"]["silent-process-exit-monitor-64"]["gaps"] == {"key-changed": 1}


def test_entry_cap_and_cancellation_preserve_observed_rows_and_gap_counts(monkeypatch):
    monkeypatch.setattr(reader, "_MAX_IMAGES_PER_SOURCE", 2)
    reg = _Winreg()
    for name in ("first.exe", "second.exe", "omitted.exe"):
        reg.put(reg.KEY_WOW64_32KEY, reader._IFEO, name, Debugger=_text("fixture"))
    limited = _collect(reg)
    assert [row["image_name"] for row in limited["findings"]] == ["first.exe", "second.exe"]
    assert limited["sources"]["ifeo-debugger-32"]["gaps"] == {"image-entry-limit": 1}
    reg.calls.clear()
    cancelled = _collect(reg, cancelled=lambda: any(call[0] == "enumerate" for call in reg.calls))
    assert [row["image_name"] for row in cancelled["findings"]] == ["first.exe"]
    assert cancelled["sources"]["ifeo-debugger-32"]["gaps"] == {"image-entry-limit": 1, "cancelled": 1}
    assert sum(call[0] == "enumerate" for call in reg.calls) == 1

    reg.calls.clear()
    timed_out = _collect(reg, clock=lambda: 4 if any(call[0] == "enumerate" for call in reg.calls) else 0)
    assert [row["image_name"] for row in timed_out["findings"]] == ["first.exe"]
    assert timed_out["sources"]["ifeo-debugger-32"]["gaps"] == {"image-entry-limit": 1, "time-limit": 1}
    assert sum(call[0] == "enumerate" for call in reg.calls) == 1


def test_public_reader_without_windows_does_not_open_registry(monkeypatch):
    monkeypatch.setattr(reader.sys, "platform", "linux")
    result = reader.scan_windows_launch_configuration(cancelled=lambda: False)
    assert result == {"state": "unavailable", "checked": 0, "skipped": 1, "sources": {},
                      "reason": "windows-only", "findings": []}
