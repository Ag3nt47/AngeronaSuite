from __future__ import annotations

from angerona.core.eventbus import Event, EventBus, Severity
from angerona.modules import purple_guard


def test_eventbus_revision_changes_only_after_publish() -> None:
    bus = EventBus()

    assert bus.revision() == 0
    bus.recent(20)
    assert bus.revision() == 0

    bus.publish(Event("sensor", "one", Severity.INFO, ts=1.0))
    assert bus.revision() == 1
    bus.publish(Event("sensor", "two", Severity.HIGH, ts=2.0))
    assert bus.revision() == 2


def test_purple_guard_cycle_reads_policy_once(tmp_path, monkeypatch) -> None:
    calls = 0

    def _policy(_root=None):
        nonlocal calls
        calls += 1
        return {"techniques": {}}

    monkeypatch.setattr(purple_guard, "_read_policy", _policy)
    module = purple_guard.PurpleGuard(tmp_path)

    assert module.work_cycle() == (0, 0, 0)
    assert calls == 1


def test_purple_guard_skips_unchanged_process_snapshot_without_losing_new_event(
    tmp_path,
) -> None:
    policy = {purple_guard._PROCESS_TECHNIQUE: {"state": "CANDIDATE_READY"}}
    bus = EventBus()
    module = purple_guard.PurpleGuard(tmp_path)
    module.bind(bus)
    emitted: list[dict] = []
    module.emit = lambda _message, severity=Severity.INFO, **details: emitted.append(
        details
    )

    bus.publish(
        Event(
            "Telemetry Scanner",
            "process_creation: cmd.exe",
            Severity.INFO,
            ts=1.0,
            details={
                "event_type": "process_creation",
                "pid": 10,
                "cmdline": "cmd /c rem ANGERONA_REDTEAM_deadbeef",
            },
        )
    )
    assert module.scan_process_once(policy) == 1
    assert module.scan_process_once(policy) == 0
    assert len(emitted) == 1

    bus.publish(
        Event(
            "Telemetry Scanner",
            "process_creation: powershell.exe",
            Severity.INFO,
            ts=2.0,
            details={
                "event_type": "process_creation",
                "pid": 11,
                "cmdline": "powershell -c echo ANGERONA_REDTEAM_cafebabe",
            },
        )
    )
    assert module.scan_process_once(policy) == 1
    assert len(emitted) == 2


def test_purple_guard_policy_change_rechecks_unchanged_bus(tmp_path) -> None:
    bus = EventBus()
    module = purple_guard.PurpleGuard(tmp_path)
    module.bind(bus)
    emitted: list[dict] = []
    module.emit = lambda _message, severity=Severity.INFO, **details: emitted.append(
        details
    )
    bus.publish(
        Event(
            "Telemetry Scanner",
            "process_creation: cmd.exe",
            Severity.INFO,
            ts=3.0,
            details={
                "event_type": "process_creation",
                "pid": 12,
                "cmdline": "cmd /c rem ANGERONA_REDTEAM_0123abcd",
            },
        )
    )

    assert module.scan_process_once({}) == 0
    enabled = {purple_guard._PROCESS_TECHNIQUE: {"state": "CANDIDATE_READY"}}
    assert module.scan_process_once(enabled) == 1
    assert len(emitted) == 1
