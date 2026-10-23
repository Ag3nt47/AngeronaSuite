"""Actual ProcessMonitor loop consumes typed collection loss, with inert OS rows."""
from dataclasses import replace
import threading
import time
from types import SimpleNamespace

import pytest

from angerona.core import attack_coverage
from angerona.core.eventbus import BusAuthority, EventBus, Severity
from angerona.core.verified_readiness import VerifiedReadiness
from angerona.modules import process_monitor
from angerona.telemetry import sensors


def row(pid=701, *, name="fixture.exe", parent=1, exe=r"C:\Windows\fixture.exe", birth=123.0):
    return dict(pid=pid, name=name, ppid=parent, exe=exe, create_time=birth, cmdline=[name])


def receipt(rows=(), **changes):
    return replace(sensors.ProcessSnapshot(tuple(rows), time.time(), True, len(rows), 0), **changes)


def run_polls(monkeypatch, snapshots, *, initial=(), capability=None):
    module = process_monitor.ProcessMonitorModule()
    bus = EventBus()
    module.bind(bus)
    module.bind_redteam_receipt_capability(capability)
    monkeypatch.setattr("psutil.pids", lambda: list(initial))
    pending = iter(snapshots)
    count = 0

    def collect(**_kwargs):
        nonlocal count
        count += 1
        return next(pending)

    def sleep(*_args, **_kwargs):
        if count == len(snapshots):
            module.stop()

    monkeypatch.setattr(process_monitor, "process_snapshot", collect)
    monkeypatch.setattr(module, "sleep", sleep)
    module.run()
    return module, bus


@pytest.mark.parametrize("changes", [
    dict(complete=False, enumeration_complete=False, error="inert denied"),
    dict(complete=False), dict(error="collector error"), dict(enumeration_complete=False),
    dict(collected_at=1.0), dict(collected_at=float("nan")), dict(collected_at=time.time() + 60),
    dict(enumerated=True),
])
def test_empty_denied_unknown_stale_and_invalid_receipts_are_not_healthy(monkeypatch, changes):
    module, _bus = run_polls(monkeypatch, [receipt(**changes)])
    assert module.health < 90
    assert module._last_coverage["complete"] is False
    assert "incomplete" in module.health_note


def test_genuinely_complete_empty_receipt_can_be_healthy(monkeypatch):
    module, _bus = run_polls(monkeypatch, [receipt()])
    assert module.health == 100 and module._last_coverage["complete"] is True


def test_untyped_list_never_grants_healthy_collection(monkeypatch):
    module, _bus = run_polls(monkeypatch, [[]])
    assert module.health == 55
    assert module._last_coverage["complete"] is False


@pytest.mark.parametrize("change", [dict(skipped=1, enumerated=3), dict(unreadable=1), dict(identity_incomplete=1)])
def test_partial_rows_keep_true_office_child_alert_with_visible_coverage_gap(monkeypatch, change):
    rows = (row(700, name="winword.exe"), row(name="powershell.exe", parent=700))
    module, bus = run_polls(monkeypatch, [receipt(rows, complete=False, **change)])
    assert module.health < 90 and not module._last_coverage["complete"]
    assert any(event.severity is Severity.CRITICAL and event.details["pid"] == 701 for event in bus.recent(20))


def test_denied_poll_preserves_generation_and_validation_dedup(monkeypatch):
    observed = row()
    calls = []

    class Capability:
        def issue_process_observation(self, _module, *, process):
            calls.append(process["pid"])
            return {"inert_receipt": True}

    module, bus = run_polls(monkeypatch, [receipt([observed]),
        receipt(complete=False, enumeration_complete=False, error="inert denied"), receipt([observed])], capability=Capability())
    creations = [event for event in bus.recent(20) if event.details.get("event_type") == "process_creation"]
    assert len(creations) == 1 and calls == [701]
    assert module.health == 100 and len(module._redteam_receipted) == 1


def test_partial_identity_retention_is_bounded_but_keeps_current_rows(monkeypatch):
    monkeypatch.setattr(process_monitor, "_MAX_PARTIAL_IDENTITIES", 3)
    module, _bus = run_polls(monkeypatch, [receipt([row(700 + index)], complete=False) for index in range(10)])
    assert len(module._seen) == 3
    assert any(identity[0] == 709 for identity in module._seen)


@pytest.mark.parametrize("partial", [False, True])
def test_actual_native_denied_or_partial_receipt_cannot_grant_readiness(monkeypatch, partial):
    import psutil
    entered, release = threading.Event(), threading.Event()
    module = process_monitor.ProcessMonitorModule()
    bus = EventBus()
    bus.arm(BusAuthority(b"r" * 32))
    module.bind(bus)
    manager = type("InertManager", (), {})()
    manager.bus, manager.modules = bus, {module.name: module}
    manager.module_trust = {module.name: {"origin": "builtin"}}
    manager._shutdown = manager._ugcap_paused = False
    module._angerona_origin = "builtin"
    readiness = VerifiedReadiness(manager)
    readiness.register(module)
    monkeypatch.setattr(psutil, "pids", lambda: [])
    monkeypatch.setattr(sensors, "_proc_cache", (0.0, None))
    calls = []

    def enumerate_processes():
        calls.append(True)
        if partial:
            yield SimpleNamespace(pid=701)
        raise PermissionError("inert remaining process table denied")

    monkeypatch.setattr(psutil, "process_iter", enumerate_processes)

    class Process:
        def __init__(self, pid):
            self.pid = pid

        def as_dict(self, *, attrs, ad_value):
            supplied = row(self.pid)
            return {field: supplied.get(field) for field in attrs}

    monkeypatch.setattr(psutil, "Process", Process)
    monkeypatch.setattr(psutil, "_ppid_map", lambda: {701: 1}, raising=False)
    sleeps = 0

    def sleep(*_args, **_kwargs):
        nonlocal sleeps
        sleeps += 1
        if sleeps > 1:
            entered.set()
            assert release.wait(3)

    monkeypatch.setattr(module, "sleep", sleep)
    module.start()
    try:
        assert entered.wait(2)
        assert calls == [True]  # No duplicate enumeration added by receipt handling.
        assert module.health < 90 and module._last_coverage["enumeration_complete"] is False
        rows = readiness.snapshot(attack_coverage.COVERAGE)["techniques"]
        assert not any(source["collecting"] for row_view in rows for source in row_view["sources"]
                       if source["source"] == module.name)
    finally:
        module.stop()
        release.set()
        module._thread.join(3)
    assert not module._thread.is_alive()
