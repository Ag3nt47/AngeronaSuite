from __future__ import annotations

import json
from types import SimpleNamespace

from angerona.core.eventbus import EventBus
from angerona.modules import persistence_sweep as persistence_module
from angerona.modules.persistence_sweep import PersistenceSweepModule


def test_persistence_records_detect_added_modified_and_removed() -> None:
    added, modified, removed = PersistenceSweepModule._diff(
        {
            "unchanged": '{"value":"same"}',
            "changed": '{"value":"old"}',
            "deleted": '{"value":"gone"}',
        },
        {
            "unchanged": '{"value":"same"}',
            "changed": '{"value":"new"}',
            "created": '{"value":"added"}',
        },
    )
    assert added == {"created"}
    assert modified == {"changed"}
    assert removed == {"deleted"}


def test_sweep_reports_drift_without_promoting_it(monkeypatch) -> None:
    module = PersistenceSweepModule()
    bus = EventBus(ring_size=50)
    module.bind(bus)
    baseline = {
        "HKCU\\Run": {
            "stable": '{"value":"same"}',
            "changed": '{"value":"old"}',
            "gone": '{"value":"deleted"}',
        }
    }
    current = {
        "HKCU\\Run": {
            "stable": '{"value":"same"}',
            "changed": '{"value":"powershell -enc SQBFAFgA"}',
            "new": '{"value":"C:\\\\Users\\\\Public\\\\payload.exe"}',
        }
    }
    sweeps = iter((baseline, current))
    monkeypatch.setattr(module, "_sweep", lambda include_slow: next(sweeps))
    sleeps = 0

    def bounded_sleep(_seconds: float) -> None:
        nonlocal sleeps
        sleeps += 1
        if sleeps > 1:
            module.stop()

    monkeypatch.setattr(module, "sleep", bounded_sleep)
    module.run()

    assert module._baseline == baseline
    changes = {
        event.details.get("change"): event
        for event in bus.recent(20)
        if event.module == module.name and event.details.get("change")
    }
    assert set(changes) == {"added", "modified", "removed"}
    assert changes["modified"].details["previous_value"] == '{"value":"old"}'
    assert changes["removed"].details["entry"] == "gone"
    assert all(event.details.get("response_authorized") is False for event in changes.values())


def test_change_deduplication_is_bounded(monkeypatch) -> None:
    monkeypatch.setattr(persistence_module, "_MAX_REPORTED_CHANGES", 3)
    module = PersistenceSweepModule()
    assert module._remember_change("one")
    assert module._remember_change("two")
    assert module._remember_change("three")
    assert not module._remember_change("three")
    assert module._remember_change("four")
    assert len(module._reported_changes) == 3
    assert "one" not in module._reported_changes


def test_persistence_self_test_covers_record_diffs() -> None:
    passed, detail = PersistenceSweepModule().self_test()
    assert passed, detail


def test_winlogon_exact_defaults_apply_only_to_shell_and_userinit() -> None:
    module = PersistenceSweepModule()
    ordinary = module._classify(
        "HKLM\\Winlogon", "AutoRestartShell", "1", "T1547.004"
    )
    hijack = module._classify(
        "HKLM\\Winlogon", "Shell", "explorer.exe,evil.exe", "T1547.004"
    )
    typed_clean = module._classify(
        "HKLM\\Winlogon",
        "Shell",
        json.dumps({"value": "explorer.exe", "type": 1}),
        "T1547.004",
    )

    assert ordinary[0].name == "MEDIUM"
    assert hijack[0].name == "CRITICAL"
    assert typed_clean[0].name == "MEDIUM"


def test_successful_empty_scheduled_task_collection_is_authoritative(monkeypatch) -> None:
    module = PersistenceSweepModule()
    monkeypatch.setattr(module, "_run", lambda _cmd: "[]")

    snapshot = module._sweep(include_slow=True)

    assert snapshot["ScheduledTask"] == {}
    assert module.coverage_snapshot()["ScheduledTask"]["status"] == "complete"


def test_nonzero_collector_exit_is_unknown_not_empty(monkeypatch) -> None:
    module = PersistenceSweepModule()
    monkeypatch.setattr(
        persistence_module.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=5, stdout="", stderr="access denied"
        ),
    )

    assert module._run(["collector"]) is None
    module._pending = {}
    module._coverage = {}
    module._collect_scheduled()

    assert "ScheduledTask" not in module._pending
    assert module.coverage_snapshot()["ScheduledTask"]["status"] == "unknown"


def test_scheduled_task_action_only_change_is_detected(monkeypatch) -> None:
    module = PersistenceSweepModule()
    documents = iter((
        json.dumps([{"id": "\\Task", "actions": [{"Execute": "good.exe"}]}]),
        json.dumps([{"id": "\\Task", "actions": [{"Execute": "evil.exe"}]}]),
    ))
    monkeypatch.setattr(module, "_run", lambda _cmd: next(documents))
    snapshots = []
    for _ in range(2):
        module._pending = {}
        module._coverage = {}
        module._values = {}
        module._collect_scheduled()
        snapshots.append({
            name: module._values[f"ScheduledTask\x00{name}"]
            for name in module._pending["ScheduledTask"]
        })
    before, after = snapshots

    assert PersistenceSweepModule._diff(before, after)[1] == {"\\Task"}


def test_wmi_consumer_content_change_is_detected(monkeypatch) -> None:
    module = PersistenceSweepModule()
    documents = iter((
        json.dumps({
            "filters": [],
            "consumers": [{"Name": "Watcher", "ScriptText": "old"}],
            "bindings": [{"Filter": "F", "Consumer": "C"}],
        }),
        json.dumps({
            "filters": [],
            "consumers": [{"Name": "Watcher", "ScriptText": "new"}],
            "bindings": [{"Filter": "F", "Consumer": "C"}],
        }),
    ))
    monkeypatch.setattr(module, "_run", lambda _cmd: next(documents))
    snapshots = []
    for _ in range(2):
        module._pending = {}
        module._coverage = {}
        module._values = {}
        module._collect_wmi()
        snapshots.append({
            name: module._values[f"WMISubscription\x00{name}"]
            for name in module._pending["WMISubscription"]
        })
    before, after = snapshots

    assert PersistenceSweepModule._diff(before, after)[1] == {"Consumer:Watcher"}


def test_suspicious_preexisting_entry_is_not_silently_trusted(monkeypatch) -> None:
    module = PersistenceSweepModule()
    bus = EventBus(ring_size=50)
    module.bind(bus)
    monkeypatch.setattr(
        module,
        "_sweep",
        lambda include_slow: {
            "HKCU\\Run": {"encoded": "powershell -enc SQBFAFgA"}
        },
    )
    monkeypatch.setattr(module, "sleep", lambda _seconds: module.stop())

    module.run()

    enrollment = [
        event for event in bus.recent(20)
        if event.details.get("change") == "baseline_enrollment"
    ]
    assert len(enrollment) == 1
    assert enrollment[0].details["baseline_trust"] == "unreviewed"
    assert module.health < 100


def test_failed_surface_is_not_diffed_as_empty(monkeypatch) -> None:
    module = PersistenceSweepModule()
    bus = EventBus(ring_size=50)
    module.bind(bus)
    calls = 0

    def sweep(include_slow: bool):
        del include_slow
        nonlocal calls
        calls += 1
        if calls == 1:
            module._coverage = {
                "ScheduledTask": {"status": "complete", "error": ""}
            }
            return {"ScheduledTask": {"\\Task": '{"action":"good.exe"}'}}
        module._coverage = {
            "ScheduledTask": {"status": "unknown", "error": "access denied"}
        }
        return {}

    monkeypatch.setattr(module, "_sweep", sweep)
    sleeps = 0

    def bounded_sleep(_seconds: float) -> None:
        nonlocal sleeps
        sleeps += 1
        if sleeps > 1:
            module.stop()

    monkeypatch.setattr(module, "sleep", bounded_sleep)
    module.run()

    assert not any(
        event.details.get("change") == "removed" for event in bus.recent(50)
    )
    assert module.health == 50
