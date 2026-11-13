"""Selected task definitions retain evidence while transient states stop repeating."""
from __future__ import annotations

import copy
import itertools
import json

import pytest

from angerona.core.eventbus import EventBus
from angerona.modules import persistence_sweep as persistence
from angerona.modules.persistence_sweep import PersistenceSweepModule


ENTRY = r"\SyntheticEncodedTask"


def _task(state="Ready"):
    return {
        "id": ENTRY, "state": state, "author": "Synthetic fixture",
        "description": 'Read-only fixture with quoted braces: "[{}]" and \\ paths',
        "actions": [{"Execute": "powershell.exe", "Arguments": "-EncodedCommand SQBFAFgA",
                     "WorkingDirectory": r"C:\Admin", "ClassId": None, "Data": None}],
        "triggers": [{"Enabled": True, "StartBoundary": None, "EndBoundary": None,
                      "ExecutionTimeLimit": None, "UserId": "SyntheticUser", "Delay": "PT1M",
                      "RandomDelay": None}],
        "principal": {"UserId": "SyntheticUser", "LogonType": 3, "RunLevel": 0,
                      "GroupId": None, "DisplayName": None},
        "settings": {"Enabled": True, "Hidden": False, "AllowDemandStart": True,
                     "ExecutionTimeLimit": "PT1H", "MultipleInstances": 0, "RestartCount": 0,
                     "RestartInterval": None, "RunOnlyIfIdle": False,
                     "RunOnlyIfNetworkAvailable": False, "StartWhenAvailable": True,
                     "WakeToRun": False},
    }


def _dump(row):
    return json.dumps(row, sort_keys=True, separators=(",", ":"))


def _diff(before, after, *, surface="ScheduledTask"):
    return PersistenceSweepModule._diff({ENTRY: before}, {ENTRY: after}, surface=surface)


def _set(row, path, value):
    target = row
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value


@pytest.mark.parametrize("before,after", tuple(itertools.permutations(("Ready", "Running", "Queued"), 2)))
def test_only_transient_top_level_task_state_is_not_definition_drift(before, after):
    previous = _dump(_task(before))
    current = json.dumps(_task(after), indent=2)
    assert previous != current
    assert _diff(previous, current) == (set(), set(), set())
    assert json.loads(previous)["state"] == before
    assert json.loads(current)["state"] == after


_DEFINITION_CHANGES = [
    (("author",), "Changed author"), (("description",), "Changed description"),
    *[(("actions", 0, key), "changed") for key in (
        "Execute", "Arguments", "WorkingDirectory", "ClassId", "Data")],
    (("triggers", 0, "Enabled"), False),
    *[(("triggers", 0, key), "changed") for key in (
        "StartBoundary", "EndBoundary", "ExecutionTimeLimit", "UserId", "Delay", "RandomDelay")],
    *[(("principal", key), "changed") for key in ("UserId", "GroupId", "DisplayName")],
    (("principal", "LogonType"), 4), (("principal", "RunLevel"), 1),
    *[(("settings", key), not _task()["settings"][key]) for key in (
        "Enabled", "Hidden", "AllowDemandStart", "RunOnlyIfIdle", "RunOnlyIfNetworkAvailable",
        "StartWhenAvailable", "WakeToRun")],
    (("settings", "ExecutionTimeLimit"), "PT2H"), (("settings", "MultipleInstances"), 1),
    (("settings", "RestartCount"), 2), (("settings", "RestartInterval"), "PT1M"),
]


@pytest.mark.parametrize("path,value", _DEFINITION_CHANGES)
def test_every_collected_definition_field_still_produces_drift(path, value):
    after = _task("Running")
    _set(after, path, value)
    assert _diff(_dump(_task()), _dump(after))[1] == {ENTRY}


@pytest.mark.parametrize("state", ["Disabled", "Unknown", "ready", "", None, 1, True, [], {}])
def test_disabled_unknown_and_mistyped_states_are_not_suppressed(state):
    assert _diff(_dump(_task()), _dump(_task(state)))[1] == {ENTRY}
    assert _diff(_dump(_task(state)), _dump(_task("Running")))[1] == {ENTRY}


@pytest.mark.parametrize("path,value", [
    (("settings", "Enabled"), 1), (("settings", "RestartCount"), 0.0),
    (("settings", "MultipleInstances"), False), (("principal", "RunLevel"), False),
    (("principal", "LogonType"), "3"), (("triggers", 0, "Enabled"), 1),
])
def test_definition_type_changes_cannot_equal_python_numeric_aliases(path, value):
    after = _task("Running")
    _set(after, path, value)
    assert _diff(_dump(_task()), _dump(after))[1] == {ENTRY}


@pytest.mark.parametrize("missing", list(_task()))
def test_missing_selected_top_level_fields_cannot_prove_equivalence(missing):
    previous, current = _task(), _task("Running")
    current.pop(missing)
    assert _diff(_dump(previous), _dump(current))[1] == {ENTRY}


@pytest.mark.parametrize("path", [
    ("actions", 0, "Arguments"), ("triggers", 0, "StartBoundary"),
    ("principal", "LogonType"), ("settings", "RestartInterval"),
])
def test_missing_selected_nested_fields_cannot_prove_equivalence(path):
    previous, current = _task(), _task("Running")
    for row in (previous, current):
        target = row
        for key in path[:-1]:
            target = target[key]
        target.pop(path[-1])
    assert _diff(_dump(previous), _dump(current))[1] == {ENTRY}


@pytest.mark.parametrize("path,value", [
    (("actions",), "System.Object[]"), (("actions", 0), "MSFT_TaskExecAction"),
    (("triggers",), {}), (("triggers", 0), "MSFT_TaskLogonTrigger"),
    (("principal",), "MSFT_TaskPrincipal"), (("settings",), "MSFT_TaskSettings3"),
])
def test_depth_truncated_or_unknown_container_shapes_retain_drift(path, value):
    previous, current = _task(), _task("Running")
    _set(previous, path, value)
    _set(current, path, value)
    assert _diff(_dump(previous), _dump(current))[1] == {ENTRY}


def test_unknown_extra_fields_and_mismatched_identity_retain_drift():
    for change in ({"truncated": True}, {"future_field": None}, {"id": r"\OtherTask"}):
        previous, current = _task(), _task("Running")
        previous.update(change)
        current.update(change)
        assert _diff(_dump(previous), _dump(current))[1] == {ENTRY}


@pytest.mark.parametrize("invalid", [
    lambda text: text[:-1],
    lambda text: '{"state":"Running",' + text[1:],
    lambda text: text.replace('"Arguments":', '"Arguments":"duplicate", "Arguments":', 1),
    lambda text: text.replace('"RestartCount":0', '"RestartCount":NaN'),
    lambda text: text.replace('"RestartCount":0', '"RestartCount":Infinity'),
    lambda text: text.replace('"RestartCount":0', '"RestartCount":1e999'),
    lambda text: text + " trailing-data",
    lambda text: "[" * 9 + text + "]" * 9,
])
def test_malformed_duplicate_nonfinite_and_deep_json_never_equates(invalid):
    assert _diff(_dump(_task()), invalid(_dump(_task("Running"))))[1] == {ENTRY}


def test_record_byte_caps_and_display_truncation_cannot_prove_equivalence():
    before, after = _task(), _task("Running")
    before["actions"][0]["Arguments"] = after["actions"][0]["Arguments"] = "x" * 70_000
    assert _diff(_dump(before), _dump(after))[1] == {ENTRY}
    assert persistence._task_definition(_dump(before)[:8192], ENTRY) is None
    before["description"] = after["description"] = "\U0001f600" * 20_000
    before["actions"][0]["Arguments"] = after["actions"][0]["Arguments"] = "ordinary"
    raw_before = json.dumps(before, ensure_ascii=False)
    raw_after = json.dumps(after, ensure_ascii=False)
    assert len(raw_before) < 65536 < len(raw_before.encode("utf-8"))
    assert _diff(raw_before, raw_after)[1] == {ENTRY}


def test_quoted_braces_are_not_miscounted_as_json_nesting():
    before, after = _task(), _task("Running")
    before["description"] = after["description"] = '[{ \\ " }]' * 50
    assert _diff(_dump(before), _dump(after)) == (set(), set(), set())


@pytest.mark.parametrize("surface", ["", "Service", "WMISubscription", r"HKCU\Run"])
def test_other_surfaces_keep_raw_comparison(surface):
    assert _diff(_dump(_task()), _dump(_task("Running")), surface=surface)[1] == {ENTRY}


def test_same_state_format_changes_and_new_deleted_entries_keep_existing_semantics():
    row = _task()
    assert _diff(_dump(row), json.dumps(row, indent=2))[1] == {ENTRY}
    added, modified, removed = PersistenceSweepModule._diff(
        {ENTRY: _dump(row), "gone": "raw"},
        {ENTRY: _dump(_task("Running")), "new": "raw"}, surface="ScheduledTask",
    )
    assert (added, modified, removed) == ({"new"}, set(), {"gone"})


@pytest.mark.parametrize("output", [
    '[{"id":"a","id":"b"}]',
    '[{"id":"a","actions":[{"Execute":"a","Execute":"b"}]}]',
    '[{"id":"a"},{"id":"a"}]',
    '[{"id":"a","x":NaN}]', '[{"id":"a","x":1e999}]',
    '[' * 9 + ']' * 9, '[{"id":"a"}',
])
def test_ambiguous_scheduled_inventory_is_unknown_while_other_surfaces_continue(monkeypatch, output):
    module = PersistenceSweepModule()
    monkeypatch.setattr(module, "_run", lambda _cmd: output)
    monkeypatch.setattr(module, "_collect_registry", lambda: module._surface_complete(r"HKCU\Run", {"stable"}))
    monkeypatch.setattr(module, "_collect_startup", lambda: None)
    monkeypatch.setattr(module, "_collect_services", lambda: module._surface_complete("Service", {"stable"}))
    monkeypatch.setattr(module, "_collect_wmi", lambda: module._surface_complete("WMISubscription", set()))
    snapshot = module._sweep(include_slow=True)
    assert "ScheduledTask" not in snapshot
    assert set(snapshot) == {r"HKCU\Run", "Service", "WMISubscription"}
    assert module.coverage_snapshot()["ScheduledTask"]["status"] == "unknown"
    assert module.coverage_snapshot()["Service"]["status"] == "complete"


def test_collection_preserves_both_raw_states_and_every_selected_field(monkeypatch):
    module = PersistenceSweepModule()
    documents = iter((json.dumps([_task()]), json.dumps([_task("Running")])))
    monkeypatch.setattr(module, "_run", lambda _cmd: next(documents))
    snapshots = []
    for _ in range(2):
        module._pending, module._coverage, module._values = {}, {}, {}
        module._collect_scheduled()
        assert module.coverage_snapshot()["ScheduledTask"]["status"] == "complete"
        snapshots.append(module._values[f"ScheduledTask\x00{ENTRY}"])
    assert json.loads(snapshots[0]) == _task()
    assert json.loads(snapshots[1]) == _task("Running")
    assert snapshots[0] != snapshots[1]
    assert _diff(*snapshots) == (set(), set(), set())


def test_real_loop_preserves_baseline_and_risky_enrollment_without_state_only_repeats(monkeypatch):
    module = PersistenceSweepModule()
    bus = EventBus(ring_size=100)
    module.bind(bus)
    before = _dump(_task())
    changed = _task("Running")
    changed["actions"][0]["Arguments"] = "-EncodedCommand RQBWAEkATAA="
    changed_raw = _dump(changed)
    baseline = {"ScheduledTask": {ENTRY: before}}
    original = copy.deepcopy(baseline)
    sweeps = iter((baseline, {"ScheduledTask": {ENTRY: _dump(_task("Running"))}},
                   {"ScheduledTask": {ENTRY: _dump(_task("Queued"))}},
                   {"ScheduledTask": {ENTRY: changed_raw}}, baseline))
    monkeypatch.setattr(module, "_sweep", lambda include_slow: next(sweeps))
    module._values[f"ScheduledTask\x00{ENTRY}\x00mitre"] = "T1053.005"
    sleeps = 0

    def bounded_sleep(_seconds):
        nonlocal sleeps
        sleeps += 1
        if sleeps > 4:
            module.stop()

    monkeypatch.setattr(module, "sleep", bounded_sleep)
    module.run()
    # EventBus.recent returns newest first; assertions below follow emission order.
    events = [event for event in reversed(bus.recent(100)) if event.details.get("change")]
    assert len(events) == 2
    enrollment, modification = events
    assert enrollment.details["change"] == "baseline_enrollment"
    assert enrollment.severity.name == "CRITICAL"
    assert enrollment.details["disposition"] == "observation"
    assert enrollment.details["value"] == before
    assert modification.details["change"] == "modified"
    assert modification.severity.name == "CRITICAL"
    assert modification.details["previous_value"] == before
    assert modification.details["value"] == changed_raw
    assert all(event.details["response_authorized"] is False for event in events)
    assert module._baseline == original == baseline


@pytest.mark.parametrize("equates_all", [False, True])
def test_module_self_test_detects_both_state_noise_and_overbroad_equivalence(monkeypatch, equates_all):
    monkeypatch.setattr(persistence, "_only_transient_task_state_changed", lambda *_args: equates_all)
    passed, detail = PersistenceSweepModule().self_test()
    assert not passed
    assert "selected scheduled-task drift probes" in detail


def test_module_self_test_exercises_synthetic_drift_without_host_collection(monkeypatch):
    module = PersistenceSweepModule()

    def forbidden(*_args, **_kwargs):
        pytest.fail("Pure self-test must never invoke host collectors or subprocesses")

    for name in ("_sweep", "_collect_registry", "_collect_startup", "_collect_services",
                 "_collect_scheduled", "_collect_wmi", "_run"):
        monkeypatch.setattr(module, name, forbidden)
    monkeypatch.setattr(persistence.subprocess, "run", forbidden)
    passed, detail = module.self_test()
    assert passed, detail
    assert "state/action/Disabled drift probes verified" in detail
    assert "synthetic only; no host collection" in detail
    assert module._baseline == {} and module._values == {}
    assert not module._reported_changes
