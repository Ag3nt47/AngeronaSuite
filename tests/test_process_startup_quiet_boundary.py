"""PW26 startup quiet-boundary tests using only supplied immutable process rows."""
from __future__ import annotations

from dataclasses import replace
import sys
from types import SimpleNamespace

import pytest

from angerona.modules import process_monitor as pm
from angerona.telemetry.sensors import ProcessSnapshot


def row(pid, birth, *, exe="C:/fixture.exe"):
    return {"pid": pid, "ppid": 4, "name": "fixture.exe", "exe": exe,
            "cmdline": ["fixture.exe"], "create_time": birth}


def partial(birth=111.0, *, exe="C:/fixture.exe", **changes):
    rows = (row(0, None, exe=""), row(4, None, exe="System"), row(100, birth, exe=exe))
    value = ProcessSnapshot(rows, 1000.0, False, 3, 0, identity_incomplete=2)
    return replace(value, **changes)


def run_polls(monkeypatch, snapshots, *, initial=(0, 4, 100)):
    events, evaluated, boundaries, seen, pids_calls = [], [], [], [], []

    def pids():
        pids_calls.append(True)
        return list(initial)

    def forbidden(*_args, **_kwargs):
        pytest.fail("fake poll queried native process metadata")

    monkeypatch.setitem(sys.modules, "psutil", SimpleNamespace(
        pids=pids, Process=forbidden, process_iter=forbidden))
    monkeypatch.setattr(pm, "time", SimpleNamespace(
        time=lambda: 1000.0, monotonic=lambda: 100.0, monotonic_ns=lambda: 100_000_000_000))
    module = pm.ProcessMonitorModule()
    assert pids_calls == []  # Construction adds no PID/native inventory.
    monkeypatch.setattr(module, "emit", lambda message, severity, **details:
                        events.append((message, severity, details)))
    monkeypatch.setattr(module, "_evaluate", lambda process, _names: evaluated.append(dict(process)))
    pending = iter(snapshots)
    count = 0

    def collect(**_kwargs):
        nonlocal count
        boundaries.append(None if module._initial_pid_baseline is None
                          else set(module._initial_pid_baseline))
        seen.append(set(module._seen))
        count += 1
        return next(pending)

    def sleep(*_args, **_kwargs):
        if count == len(snapshots):
            module.stop()

    monkeypatch.setattr(pm, "process_snapshot", collect)
    monkeypatch.setattr(module, "sleep", sleep)
    module.run()
    assert count == len(snapshots) and pids_calls == [True]
    creations = [details for _message, _severity, details in events
                 if details.get("event_type") == "process_creation"]
    return SimpleNamespace(module=module, events=events, evaluated=evaluated,
                           boundaries=boundaries, seen=seen, creations=creations)


def test_pid0_and_pid4_gaps_cannot_keep_reused_startup_pid_quiet(monkeypatch):
    no_user = replace(partial(), processes=partial().processes[:2], enumerated=2)
    h = run_polls(monkeypatch, [partial(), partial(222.0), partial(222.0),
                              no_user, partial(222.0), partial(333.0)])
    assert h.boundaries == [{4, 100}, None, None, None, None, None]
    assert [details["process_create_time"] for details in h.creations] == [222.0, 333.0]
    assert [process["create_time"] for process in h.evaluated] == [222.0, 333.0]
    identities = {pm._process_identity(row(100, value))[0] for value in (111.0, 222.0, 333.0)}
    assert identities <= h.module._seen  # Partial absence never proves exit.
    assert h.module._last_coverage["complete"] is False
    assert h.module._last_coverage["observed_identity_gaps"] == 2 and h.module.health < 100


@pytest.mark.parametrize("bad", [
    [], partial(collected_at=1.0), partial(collected_at=1060.0),
    partial(collected_at=float("nan")), partial(enumerated=True), partial(enumerated=0),
], ids=["untyped", "stale", "future", "nan-stamp", "boolean-count", "inconsistent-count"])
def test_stale_or_malformed_poll_keeps_startup_boundary_until_current_valid_enrichment(monkeypatch, bad):
    h = run_polls(monkeypatch, [bad, partial(), partial(222.0), partial(222.0)])
    assert h.boundaries[:2] == [{4, 100}, {4, 100}]
    assert h.boundaries[2:] == [None, None]
    assert [details["process_create_time"] for details in h.creations] == [222.0]
    assert [process["create_time"] for process in h.evaluated] == [222.0]
    assert h.module._last_coverage["complete"] is False and h.module.health < 100


@pytest.mark.parametrize("changes", [
    {}, {"unreadable": 1}, {"enumeration_complete": False, "error": "inert partial enumeration"},
])
def test_retiring_quiet_boundary_does_not_claim_complete_collection(monkeypatch, changes):
    h = run_polls(monkeypatch, [partial(**changes)])
    assert h.module._initial_pid_baseline is None and h.creations == [] and h.evaluated == []
    assert h.module._last_coverage["fresh"] is True and h.module._last_coverage["counts_valid"] is True
    assert h.module._last_coverage["complete"] is False and h.module.health < 100
    assert "incomplete" in h.module.health_note


@pytest.mark.parametrize("later", [partial(222.0), partial(111.0, exe="C:/different.exe")],
                         ids=["new-birth", "new-executable"])
def test_exact_identity_change_reports_once_and_unchanged_partial_rows_do_not_repeat(monkeypatch, later):
    h = run_polls(monkeypatch, [partial(), later, later, later])
    assert len(h.creations) == len(h.evaluated) == 1
    assert h.creations[0]["process_create_time"] == later.processes[2]["create_time"]
    assert h.creations[0]["exe"] == later.processes[2]["exe"]
    assert h.module._last_coverage["complete"] is False
