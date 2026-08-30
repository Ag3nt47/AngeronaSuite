from __future__ import annotations

from types import SimpleNamespace

from angerona.core.eventbus import EventBus, Severity
from angerona.modules import shadowcopy_guard


class _Parent:
    def __init__(self, _pid: int) -> None:
        pass

    @staticmethod
    def ppid() -> int:
        return 900


def test_pid_reuse_with_new_birth_identity_is_detected_again(monkeypatch) -> None:
    snapshots = [
        SimpleNamespace(info={
            "pid": 444,
            "name": "cmd.exe",
            "exe": r"C:\Windows\System32\cmd.exe",
            "cmdline": ["cmd.exe", "/c", "vssadmin delete shadows /all"],
            "create_time": birth,
        })
        for birth in (100.0, 200.0)
    ]
    calls = 0

    def process_iter(_attrs):
        nonlocal calls
        item = snapshots[min(calls, 1)]
        calls += 1
        return [item]

    monkeypatch.setattr(
        shadowcopy_guard,
        "psutil",
        SimpleNamespace(process_iter=process_iter, Process=_Parent),
    )
    module = shadowcopy_guard.ShadowCopyGuardModule()
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
        100.0,
        200.0,
    ]
    assert module._detections == 2


def test_unreadable_process_command_lines_degrade_coverage(monkeypatch) -> None:
    process = SimpleNamespace(info={
        "pid": 555,
        "name": None,
        "exe": None,
        "cmdline": None,
        "create_time": None,
    })
    monkeypatch.setattr(
        shadowcopy_guard,
        "psutil",
        SimpleNamespace(process_iter=lambda _attrs: [process], Process=_Parent),
    )
    module = shadowcopy_guard.ShadowCopyGuardModule()
    monkeypatch.setattr(module, "sleep", lambda _seconds: module.stop())

    module.run()

    assert module.health == 70
    assert "0/1 command lines readable" in module.health_note
    assert module._last_coverage == {
        "enumerated": 1,
        "readable": 0,
        "unreadable": 1,
        "identity_incomplete": 1,
    }
