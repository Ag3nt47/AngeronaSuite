"""Inert inventory contracts: no watchers, OS PID reuse or live enumeration."""
from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from angerona.telemetry import sensors


def row(pid=731, **changes):
    return {"pid": pid, "name": "fixture.exe", "exe": "C:/fixture.exe", "username": "fixture",
            "cmdline": ["fixture.exe"], "create_time": 100.0, "ppid": 4, **changes}


@pytest.fixture(autouse=True)
def fresh_cache(monkeypatch):
    monkeypatch.setattr(sensors, "_proc_cache", (0.0, None))
    monkeypatch.setattr(sensors, "_WINDOWS_PROCESS_MAP", True)


def install(monkeypatch, rows, *, after=None, parents=None, map_hook=None, iterator=None):
    calls = dict(iteration=0, maps=0, reads=[])
    by_pid = {item["pid"]: item for item in rows}
    after = by_pid if after is None else after

    class Process:
        def __init__(self, pid):
            self.pid = pid

        def as_dict(self, *, attrs, ad_value):
            assert ad_value is None
            calls["reads"].append((self.pid, tuple(attrs)))
            source = after if len(attrs) == 3 else by_pid
            result = source[self.pid]
            if isinstance(result, Exception):
                raise result
            return {key: result.get(key) for key in attrs}

    def process_iter():
        calls["iteration"] += 1
        if iterator is not None:
            return iterator()
        # These simulate stale process_iter objects; touching their metadata
        # would regress the separate fresh-object admission contract.
        class Cached:
            def __init__(self, pid):
                self.pid = pid

            @property
            def info(self):
                pytest.fail("cached process metadata must never be consumed")

            def is_running(self):
                pytest.fail("cached identity comparison must never be consumed")
        return iter(Cached(item["pid"]) for item in rows)

    def parent_map():
        calls["maps"] += 1
        if map_hook:
            map_hook()
        return {item["pid"]: item["ppid"] for item in rows} if parents is None else parents

    adapter = SimpleNamespace(Process=Process, process_iter=process_iter, _ppid_map=parent_map)
    monkeypatch.setitem(sys.modules, "psutil", adapter)
    return calls, adapter


def test_one_parent_map_for_many_rows_and_shared_cache(monkeypatch):
    calls, _adapter = install(monkeypatch, [row(pid) for pid in range(1, 101)])
    first = sensors.process_snapshot(max_age=60)
    assert first.complete and len(first.processes) == 100
    assert calls["iteration"] == 1 and calls["maps"] == 1
    assert len(calls["reads"]) == 200
    assert all("ppid" not in attrs for _pid, attrs in calls["reads"])
    assert sensors.process_snapshot(max_age=60) is first
    assert calls["maps"] == 1
    assert sensors.process_snapshot(max_age=0) is not first
    assert calls["maps"] == 2 and calls["iteration"] == 2


@pytest.mark.parametrize("replacement", [dict(create_time=200.0), dict(exe="C:/new.exe"), dict(pid=999)])
def test_map_is_bracketed_by_fresh_unchanged_child_identity(monkeypatch, replacement):
    changed = {**row(), **replacement}
    calls, _adapter = install(monkeypatch, [row()], after={731: changed})
    receipt = sensors.process_snapshot(max_age=0)
    assert calls["maps"] == 1
    assert receipt.processes == () and receipt.skipped == 1
    assert not receipt.complete and not receipt.enumeration_complete and receipt.error


@pytest.mark.parametrize("birth", [None, 0, -1, float("nan"), float("inf"), True, "100", 10 ** 1000])
def test_unavailable_or_invalid_birth_keeps_unknown_row_without_parent_claim(monkeypatch, birth):
    install(monkeypatch, [row(create_time=birth)])
    receipt = sensors.process_snapshot(max_age=0)
    assert receipt.enumeration_complete and not receipt.complete and not receipt.error
    assert receipt.identity_incomplete == 1 and receipt.skipped == 0
    assert receipt.processes[0]["create_time"] is None
    assert receipt.processes[0]["ppid"] is None


@pytest.mark.parametrize("field", ["create_time", "exe"])
@pytest.mark.parametrize("side", ["before", "after"])
def test_denied_identity_read_cannot_leave_apparently_confirmed_metadata(monkeypatch, field, side):
    before, after = row(), row()
    (before if side == "before" else after)[field] = None
    install(monkeypatch, [before], after={731: after})
    receipt = sensors.process_snapshot(max_age=0)
    assert receipt.enumeration_complete and not receipt.complete and not receipt.error
    assert receipt.processes[0][field] is None
    assert receipt.processes[0]["ppid"] is None and receipt.identity_incomplete == 1


@pytest.mark.parametrize("parents", [[], {True: 4}, {731: True}, {-1: 4}, {731: -1},
                                     {2 ** 32: 4}, {731: 2 ** 32}])
def test_invalid_native_map_is_visible_loss_without_per_row_fallback(monkeypatch, parents):
    calls, _adapter = install(monkeypatch, [row()], parents=parents)
    receipt = sensors.process_snapshot(max_age=0)
    assert calls["maps"] == 1
    assert len(receipt.processes) == 1 and receipt.processes[0]["ppid"] is None
    assert not receipt.complete and not receipt.enumeration_complete
    assert "parent map unavailable" in receipt.error


@pytest.mark.parametrize("reader", [None, lambda: (_ for _ in ()).throw(PermissionError("inert denied"))])
def test_missing_or_failed_private_adapter_is_an_explicit_gap(monkeypatch, reader):
    _calls, adapter = install(monkeypatch, [row()])
    adapter._ppid_map = reader
    receipt = sensors.process_snapshot(max_age=0)
    assert not receipt.complete and not receipt.enumeration_complete
    assert receipt.processes[0]["ppid"] is None and receipt.error


def test_bounded_map_validation_and_bounded_row_enumeration(monkeypatch):
    monkeypatch.setattr(sensors, "_MAX_PARENT_MAP_ROWS", 2)
    install(monkeypatch, [row()], parents={731: 4, 732: 4, 733: 4})
    oversized = sensors.process_snapshot(max_age=0)
    assert not oversized.enumeration_complete and oversized.error
    monkeypatch.setattr(sensors, "_MAX_PROCESS_ROWS", 2)
    calls, _adapter = install(monkeypatch, [row(731), row(732), row(733)])
    truncated = sensors.process_snapshot(max_age=0)
    assert truncated.enumerated == 3 and truncated.skipped == 1
    assert len(truncated.processes) == 2 and not truncated.enumeration_complete
    assert "bounded row limit" in truncated.error and calls["maps"] == 1


def test_missing_pid_in_map_is_unknown_instead_of_invented_parent(monkeypatch):
    install(monkeypatch, [row()], parents={999: 4})
    receipt = sensors.process_snapshot(max_age=0)
    assert receipt.enumeration_complete and not receipt.complete
    assert receipt.identity_incomplete == 1 and receipt.processes[0]["ppid"] is None


def test_partial_enumeration_preserves_rows_and_explicit_loss(monkeypatch):
    def iterator():
        yield SimpleNamespace(pid=731)
        raise PermissionError("fixture remaining table denied")
    calls, _adapter = install(monkeypatch, [row()], iterator=iterator)
    receipt = sensors.process_snapshot(max_age=0)
    assert len(receipt.processes) == 1 and calls["maps"] == 1
    assert receipt.enumerated == 1 and "denied" in receipt.error
    assert not receipt.complete and not receipt.enumeration_complete


def test_empty_table_needs_no_parent_adapter_and_import_loss_is_not_empty_health(monkeypatch):
    calls, adapter = install(monkeypatch, [])
    del adapter._ppid_map
    receipt = sensors.process_snapshot(max_age=0)
    assert receipt.complete and not receipt.processes and calls["maps"] == 0
    monkeypatch.setitem(sys.modules, "psutil", None)
    unavailable = sensors.process_snapshot(max_age=0)
    assert not unavailable.complete and not unavailable.enumeration_complete and unavailable.error


def test_posix_path_keeps_per_row_parent_and_never_uses_windows_map(monkeypatch):
    monkeypatch.setattr(sensors, "_WINDOWS_PROCESS_MAP", False)
    calls, adapter = install(monkeypatch, [row()])
    adapter._ppid_map = lambda: pytest.fail("Windows map used on another platform")
    receipt = sensors.process_snapshot(max_age=0)
    assert receipt.complete and receipt.processes[0]["ppid"] == 4
    assert "ppid" in calls["reads"][0][1] and "ppid" not in calls["reads"][1][1]


@pytest.mark.skipif(sys.platform != "win32", reason="Windows denied-fast-birth identity cache")
@pytest.mark.parametrize("new_birth", [100.0, 200.0], ids=["same-birth-image-change", "replacement-birth"])
def test_fresh_objects_defeat_actual_psutil_denied_fast_birth_cache(monkeypatch, new_birth):
    import psutil
    # This uses the installed public Process implementation with an entirely
    # synthetic backend. No native PID is opened, replaced or enumerated.
    state = dict(birth=100.0, image="C:/old.exe", parent=4)

    class Backend:
        def __init__(self, pid):
            self.pid, self._name = pid, None

        def create_time(self, fast_only=False, monotonic=False):
            if fast_only:
                raise psutil.AccessDenied(self.pid)
            return state["birth"]

        def oneshot_enter(self):
            pass

        def oneshot_exit(self):
            pass

        def name(self):
            return state["image"].split("/")[-1]

        def exe(self):
            return state["image"]

        def username(self):
            return "fixture"

        def cmdline(self):
            return [state["image"]]

        def ppid(self):
            return state["parent"]

    monkeypatch.setattr(psutil._psplatform, "Process", Backend)
    cached = psutil.Process(731)
    cached.as_dict(attrs=["create_time", "exe", "ppid"])
    assert cached._ident == (731, None)
    state.update(birth=new_birth, image="C:/new.exe", parent=5)
    assert cached.is_running()  # The old cached PID-only comparison is weak.
    monkeypatch.setattr(psutil, "process_iter", lambda: iter([cached]))
    monkeypatch.setattr(psutil, "_ppid_map", lambda: {731: 5}, raising=False)
    receipt = sensors.process_snapshot(max_age=0)
    assert receipt.complete and receipt.processes[0]["create_time"] == new_birth
    assert receipt.processes[0]["exe"] == "C:/new.exe" and receipt.processes[0]["ppid"] == 5
    assert cached.create_time() == 100.0 and cached.exe() == "C:/old.exe"


def test_portable_same_birth_cached_exe_is_bypassed_by_fresh_objects(monkeypatch):
    import psutil

    # Ordinary successful birth reads work on every supported platform. All
    # backend metadata is synthetic; the account seam avoids host-user lookup.
    monkeypatch.setattr(sensors, "_WINDOWS_PROCESS_MAP", False)
    state = {"image": "/fixture/old.exe"}

    class Backend:
        def __init__(self, pid):
            self.pid, self._name = pid, None

        def create_time(self, fast_only=False, monotonic=False):
            return 100.0

        def oneshot_enter(self):
            pass

        def oneshot_exit(self):
            pass

        def name(self):
            return state["image"].split("/")[-1]

        def exe(self):
            return state["image"]

        def cmdline(self):
            return [state["image"]]

        def ppid(self):
            return 4

    monkeypatch.setattr(psutil._psplatform, "Process", Backend)
    monkeypatch.setattr(psutil.Process, "username", lambda _self: "fixture")
    monkeypatch.setattr(psutil, "_ppid_map", lambda: pytest.fail("Windows adapter used"), raising=False)
    cached = psutil.Process(731)
    assert cached.create_time() == 100.0 and cached.exe() == "/fixture/old.exe"
    state["image"] = "/fixture/new.exe"
    assert cached.is_running() and cached.exe() == "/fixture/old.exe"
    monkeypatch.setattr(psutil, "process_iter", lambda: iter([cached]))
    receipt = sensors.process_snapshot(max_age=0)
    assert receipt.complete and receipt.processes[0]["create_time"] == 100.0
    assert receipt.processes[0]["exe"] == "/fixture/new.exe"
    assert receipt.processes[0]["cmdline"] == ("/fixture/new.exe",)
    assert receipt.processes[0]["ppid"] == 4
    assert cached.exe() == "/fixture/old.exe"


@pytest.mark.parametrize("pid", [True, -1, "731", None])
def test_invalid_iterator_pid_is_loss_without_opening_a_process(monkeypatch, pid):
    calls, _adapter = install(monkeypatch, [row()], iterator=lambda: iter([SimpleNamespace(pid=pid)]))
    receipt = sensors.process_snapshot(max_age=0)
    assert not calls["reads"] and calls["maps"] == 0
    assert receipt.skipped == 1 and not receipt.enumeration_complete and receipt.error


def test_process_exit_during_postmap_verification_cannot_leave_a_row(monkeypatch):
    install(monkeypatch, [row()], after={731: ProcessLookupError("inert process exited")})
    receipt = sensors.process_snapshot(max_age=0)
    assert not receipt.processes and receipt.skipped == 1
    assert not receipt.complete and not receipt.enumeration_complete and receipt.error
