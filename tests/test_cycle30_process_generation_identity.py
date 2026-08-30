from __future__ import annotations

from types import SimpleNamespace

from angerona.core.eventbus import EventBus, Severity
from angerona.modules import lsass_guard, process_monitor


def test_process_monitor_evaluates_same_pid_with_new_birth(monkeypatch) -> None:
    snapshots = [
        [{
            "pid": 700,
            "ppid": 1,
            "name": "benign.exe",
            "exe": r"C:\Windows\benign.exe",
            "cmdline": ["benign.exe"],
            "create_time": 10.0,
        }],
        [{
            "pid": 700,
            "ppid": 1,
            "name": "payload.exe",
            "exe": r"C:\Users\me\Downloads\payload.exe",
            "cmdline": ["payload.exe"],
            "create_time": 20.0,
        }],
    ]
    calls = 0

    def list_processes(*_args, **_kwargs):
        nonlocal calls
        result = snapshots[min(calls, 1)]
        calls += 1
        return result

    monkeypatch.setattr(process_monitor, "list_processes", list_processes)
    module = process_monitor.ProcessMonitorModule()
    bus = EventBus()
    module.bind(bus)
    monkeypatch.setattr(
        module,
        "sleep",
        lambda _seconds, **_kwargs: module.stop() if calls >= 2 else None,
    )

    module.run()

    detections = [event for event in bus.recent(20) if event.severity == Severity.MEDIUM]
    assert any(event.details.get("process_create_time") == 20.0 for event in detections)
    assert any(identity[1] == "20.000000" for identity in module._seen)


def test_process_monitor_missing_birth_is_visible_in_health(monkeypatch) -> None:
    snapshots = [[], [{
        "pid": 701,
        "ppid": 1,
        "name": "unknown.exe",
        "exe": r"C:\unknown.exe",
        "cmdline": [],
        "create_time": None,
    }]]
    calls = 0

    def list_processes(*_args, **_kwargs):
        nonlocal calls
        result = snapshots[min(calls, 1)]
        calls += 1
        return result

    monkeypatch.setattr(process_monitor, "list_processes", list_processes)
    module = process_monitor.ProcessMonitorModule()
    monkeypatch.setattr(
        module,
        "sleep",
        lambda _seconds, **_kwargs: module.stop() if calls >= 2 else None,
    )

    module.run()

    assert module.health == 70
    assert "identity incomplete" in module.health_note


def test_lsass_guard_alerts_same_pid_for_two_birth_generations(monkeypatch) -> None:
    processes = [
        SimpleNamespace(info={
            "pid": 800,
            "name": "tool.exe",
            "exe": r"C:\tool.exe",
            "cmdline": ["tool.exe", "procdump", "-ma", "lsass.exe"],
            "create_time": birth,
        })
        for birth in (10.0, 20.0)
    ]
    calls = 0

    def process_iter(_attrs):
        nonlocal calls
        result = [processes[min(calls, 1)]]
        calls += 1
        return result

    monkeypatch.setattr(
        lsass_guard,
        "psutil",
        SimpleNamespace(process_iter=process_iter),
    )
    module = lsass_guard.LsassGuardModule()
    bus = EventBus()
    module.bind(bus)
    sleeps = 0

    def stop_after_two(_seconds: float) -> None:
        nonlocal sleeps
        sleeps += 1
        if sleeps >= 2:
            module.stop()

    monkeypatch.setattr(module, "sleep", stop_after_two)
    module.run()

    detections = [event for event in bus.recent(20) if event.severity == Severity.CRITICAL]
    assert sorted(event.details["process_create_time"] for event in detections) == [
        10.0,
        20.0,
    ]
    assert module._detections == 2
