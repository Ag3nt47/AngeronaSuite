"""Inert PID-table admission contracts; no host enumeration or watcher starts."""
from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from angerona.telemetry import sensors


def _row(pid):
    return {"pid": pid, "name": "fixture.exe", "exe": "C:/fixture.exe",
            "username": "fixture", "cmdline": ["fixture.exe"], "create_time": 100.0}


@pytest.fixture(autouse=True)
def _fresh_cache(monkeypatch):
    monkeypatch.setattr(sensors, "_proc_cache", (0.0, None))
    monkeypatch.setattr(sensors, "_WINDOWS_PROCESS_MAP", True)


def test_pid_table_uses_two_independent_metadata_objects_around_one_parent_map(monkeypatch):
    calls, objects = [], []
    rich = ("pid", "name", "exe", "username", "cmdline", "create_time")
    identity = ("pid", "create_time", "exe")

    def pids():
        calls.append(("pids",))
        return [732, 731]

    class Process:
        def __init__(self, pid):
            self.pid = pid
            objects.append(self)
            calls.append(("open", pid))

        def as_dict(self, *, attrs, ad_value):
            assert ad_value is None
            calls.append(("read", self.pid, tuple(attrs)))
            return {field: _row(self.pid).get(field) for field in attrs}

    def parents():
        calls.append(("map",))
        return {731: 4, 732: 5}

    monkeypatch.setitem(sys.modules, "psutil", SimpleNamespace(
        pids=pids, Process=Process, _ppid_map=parents,
        process_iter=lambda: pytest.fail("cached Process enumeration must not be used"),
    ))
    receipt = sensors.process_snapshot(max_age=0)
    assert calls == [
        ("pids",), ("open", 732), ("read", 732, rich),
        ("open", 731), ("read", 731, rich), ("map",),
        ("open", 732), ("read", 732, identity),
        ("open", 731), ("read", 731, identity),
    ]
    assert len(objects) == 4 and len({id(item) for item in objects}) == 4
    assert receipt.complete and receipt.enumeration_complete
    assert receipt.enumerated == 2 and receipt.skipped == 0
    assert receipt.unreadable == 0 and receipt.identity_incomplete == 0
    assert [item["pid"] for item in receipt.processes] == [732, 731]
    assert [item["ppid"] for item in receipt.processes] == [5, 4]
    assert all(item["username"] == "fixture" and item["cmdline"] == ("fixture.exe",)
               for item in receipt.processes)


@pytest.mark.parametrize("phase", ["open", "metadata"])
@pytest.mark.parametrize("error_type", [ProcessLookupError, PermissionError], ids=["exited", "denied"])
def test_raw_pid_that_disappears_or_is_denied_remains_explicit_loss(monkeypatch, phase, error_type):
    reads, opened, maps = [], [], []

    class Process:
        def __init__(self, pid):
            opened.append(pid)
            self.pid = pid
            if pid == 732 and phase == "open":
                raise error_type("inert PID unavailable")

        def as_dict(self, *, attrs, ad_value):
            assert ad_value is None
            reads.append((self.pid, tuple(attrs)))
            if self.pid == 732:
                raise error_type("inert metadata unavailable")
            return {field: _row(self.pid).get(field) for field in attrs}

    def parents():
        maps.append(True)
        return {731: 4, 732: 5}

    monkeypatch.setitem(sys.modules, "psutil", SimpleNamespace(
        pids=lambda: [731, 732], Process=Process, _ppid_map=parents,
        process_iter=lambda: pytest.fail("vanished PIDs must not trigger cached enumeration"),
    ))
    receipt = sensors.process_snapshot(max_age=0)
    assert [item["pid"] for item in receipt.processes] == [731]
    assert receipt.processes[0]["ppid"] == 4
    assert receipt.enumerated == 2 and receipt.skipped == 1
    assert not receipt.complete and not receipt.enumeration_complete and receipt.error
    assert receipt.unreadable == 0 and receipt.identity_incomplete == 0
    assert opened == [731, 732, 731] and maps == [True]
    assert len([item for item in reads if item[0] == 731]) == 2
    assert len([item for item in reads if item[0] == 732]) == int(phase == "metadata")


@pytest.mark.parametrize("missing", [False, True], ids=["denied", "unavailable"])
def test_pid_table_failure_is_an_explicit_gap_without_cached_fallback(monkeypatch, missing):
    calls = []

    def denied():
        calls.append(True)
        raise PermissionError("inert PID table denied")

    adapter = SimpleNamespace(
        Process=lambda _pid: pytest.fail("failed PID enumeration opened a process"),
        process_iter=lambda: pytest.fail("failed PID enumeration used cached fallback"),
        _ppid_map=lambda: pytest.fail("empty failed enumeration queried parents"),
    )
    if not missing:
        adapter.pids = denied
    monkeypatch.setitem(sys.modules, "psutil", adapter)
    receipt = sensors.process_snapshot(max_age=0)
    assert receipt.processes == () and receipt.enumerated == 0 and receipt.skipped == 0
    assert not receipt.complete and not receipt.enumeration_complete
    assert receipt.error.startswith("process enumeration failed:")
    assert calls == ([] if missing else [True])
