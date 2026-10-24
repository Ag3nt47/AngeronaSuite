"""Supplied-row LSASS parity and pure-matcher work controls; no live sensors."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import MappingProxyType, ModuleType

import pytest

from angerona.core.eventbus import Severity
from angerona.modules import lsass_guard
from angerona.telemetry.sensors import ProcessSnapshot


_BEFORE = (
    "                    readable += 1\n"
    "                    reason = _looks_like_lsass_dump(cmd)\n"
    "                    if reason and identity not in self._alerted:\n"
)
_AFTER = (
    "                    readable += 1\n"
    "                    if identity in self._alerted:\n"
    "                        continue\n"
    "                    reason = _looks_like_lsass_dump(cmd)\n"
    "                    if reason:\n"
)


class _UnexpectedLiveAccess(BaseException):
    """Do not let the detector's normal Exception handling swallow a guard."""


class _NoLivePsutil:
    def __getattr__(self, name):
        raise _UnexpectedLiveAccess(f"inert LSASS fixture blocked psutil.{name}")


def _reference_module():
    # Reverse exactly the reviewed optimization in actual checked-out source.
    # All other matcher, response, coverage and identity code is shared. This
    # comparator is not a separately implemented, possibly divergent detector.
    path = Path(lsass_guard.__file__)
    source = path.read_text(encoding="utf-8")
    assert source.count(_AFTER) == 1, "reviewed dedup block is not unique"
    source = source.replace(_AFTER, _BEFORE, 1)
    namespace = ModuleType("angerona.modules._lsass_before_dedup_fixture")
    namespace.__file__ = str(path)
    exec(compile(source, str(path) + "[before-dedup]", "exec"), namespace.__dict__)
    return namespace


def _row(tmp_path, **changes):
    return {
        "pid": 731,
        "name": "procdump64.exe",
        "exe": str(tmp_path / "procdump64.exe"),
        "cmdline": ("procdump64.exe", "-ma", "lsass.exe"),
        "create_time": 100.0,
        **changes,
    }


def _snapshot(
    *rows, enumeration_complete=True, skipped=0, error="",
    complete=True, unreadable=0, identity_incomplete=0,
):
    return ProcessSnapshot(
        tuple(MappingProxyType(dict(row)) for row in rows),
        1_700_000_000.0,
        complete and enumeration_complete and not skipped,
        len(rows) + skipped, skipped,
        unreadable=unreadable, identity_incomplete=identity_incomplete, error=error,
        enumeration_complete=enumeration_complete,
    )


def _run(monkeypatch, provider, snapshots, *, trusted_rundll32=False):
    module = provider.LsassGuardModule()
    result = {"events": [], "cycles": [], "requests": [], "sleeps": [], "matcher_calls": []}
    original_matcher = provider._looks_like_lsass_dump

    def collect(**kwargs):
        assert kwargs == {"max_age": 1.5}
        index = len(result["requests"])
        assert index < len(snapshots), "unexpected extra process collection"
        result["requests"].append(dict(kwargs))
        return snapshots[index]

    def matcher(command):
        result["matcher_calls"].append(command)
        return original_matcher(command)

    def emit(message, severity=Severity.INFO, **details):
        result["events"].append((message, severity, deepcopy(details)))

    def health(value, note):
        # Preserve the loop's actual values without collecting BaseModule
        # source/stack presentation evidence, publishing or starting a worker.
        module.health = value
        module.health_note = note

    def sleep(seconds):
        result["sleeps"].append(seconds)
        result["cycles"].append({
            "coverage": dict(module._last_coverage),
            "alerted": frozenset(module._alerted),
            "detections": module._detections,
            "health": module.health,
            "health_note": module.health_note,
            "last_error": module.last_error,
        })
        if len(result["cycles"]) >= len(snapshots):
            module._stop.set()

    with monkeypatch.context() as scope:
        scope.setattr(provider, "psutil", _NoLivePsutil())
        scope.setattr(provider, "process_snapshot", collect)
        scope.setattr(provider, "_looks_like_lsass_dump", matcher)
        # These cases model tool-role evidence; they never query a real PID,
        # resolve/sign a System32 binary or execute a response action.
        scope.setattr(provider, "_rundll32_targets_lsass", lambda _args: trusted_rundll32)
        scope.setattr(provider, "_trusted_system_image", lambda _exe, _name: trusted_rundll32)
        scope.setattr(module, "emit", emit)
        scope.setattr(module, "set_health", health)
        scope.setattr(module, "sleep", sleep)
        module.run()
    assert len(result["requests"]) == len(snapshots)
    assert result["sleeps"] == [3.0] * len(snapshots)
    assert all(cycle["last_error"] == "" for cycle in result["cycles"])
    return result


def _pair(monkeypatch, snapshots, *, trusted_rundll32=False):
    reference = _reference_module()
    before = _run(monkeypatch, reference, snapshots, trusted_rundll32=trusted_rundll32)
    after = _run(monkeypatch, lsass_guard, snapshots, trusted_rundll32=trusted_rundll32)
    # Compare complete emitted message/order/severity/details, every cycle's
    # coverage/counters/health/dedup state, collector requests and sleep values.
    for key in ("events", "cycles", "requests", "sleeps"):
        assert after[key] == before[key], key
    return before, after


def _detections(result):
    return [event[2] for event in result["events"] if event[1] == Severity.CRITICAL]


def test_repeated_positive_skips_only_redundant_pure_matcher_calls(monkeypatch, tmp_path):
    snapshot = _snapshot(_row(tmp_path))
    before, after = _pair(monkeypatch, [snapshot] * 4)
    assert len(before["matcher_calls"]) == 4
    assert len(after["matcher_calls"]) == 1
    assert len(_detections(after)) == 1
    assert [cycle["coverage"]["readable"] for cycle in after["cycles"]] == [1] * 4
    assert [cycle["detections"] for cycle in after["cycles"]] == [1] * 4


@pytest.mark.parametrize("changed", ["birth", "executable"])
def test_new_exact_identity_at_same_pid_still_alerts(monkeypatch, tmp_path, changed):
    first = _row(tmp_path)
    second = _row(tmp_path, **(
        {"create_time": 101.0} if changed == "birth"
        else {"exe": str(tmp_path / "replacement" / "procdump64.exe")}
    ))
    before, after = _pair(monkeypatch, [
        _snapshot(first), _snapshot(second), _snapshot(second),
    ])
    assert len(before["matcher_calls"]) == 3
    assert len(after["matcher_calls"]) == 2
    events = _detections(after)
    assert len(events) == 2
    assert [event["pid"] for event in events] == [731, 731]
    assert [event["process_create_time"] for event in events] == [
        first["create_time"], second["create_time"],
    ]
    assert [event["exe"] for event in events] == [first["exe"], second["exe"]]


@pytest.mark.parametrize("birth", [None, 0, "unknown"])
def test_identity_gap_retains_advisory_authority_and_coverage(monkeypatch, tmp_path, birth):
    snapshot = _snapshot(_row(tmp_path, create_time=birth), complete=False, identity_incomplete=1)
    before, after = _pair(monkeypatch, [snapshot, snapshot])
    assert len(before["matcher_calls"]) == 2
    assert len(after["matcher_calls"]) == 1
    event, = _detections(after)
    assert event["response_authorized"] is False
    assert "response_contract" not in event
    assert all(cycle["health"] == 70 for cycle in after["cycles"])
    assert all(cycle["coverage"]["identity_incomplete"] == 1 for cycle in after["cycles"])
    assert all(cycle["coverage"]["readable"] == 1 for cycle in after["cycles"])


def test_partial_absence_preserves_dedup_complete_absence_evicts(monkeypatch, tmp_path):
    present = _snapshot(_row(tmp_path))
    before, after = _pair(monkeypatch, [
        present,
        _snapshot(enumeration_complete=False, skipped=1, error="fixture partial inventory"),
        present,
        _snapshot(),
        present,
    ])
    assert len(before["matcher_calls"]) == 3
    assert len(after["matcher_calls"]) == 2
    assert len(_detections(after)) == 2
    assert [len(cycle["alerted"]) for cycle in after["cycles"]] == [1, 1, 1, 0, 1]
    assert [cycle["health"] for cycle in after["cycles"]] == [100, 60, 100, 60, 100]
    assert after["cycles"][1]["coverage"]["enumeration_complete"] is False
    assert after["cycles"][1]["coverage"]["skipped"] == 1


@pytest.mark.parametrize("command", [None, ("procdump64.exe", 42)])
def test_already_alerted_unreadable_command_keeps_accounting(monkeypatch, tmp_path, command):
    present = _snapshot(_row(tmp_path))
    before, after = _pair(monkeypatch, [
        present, _snapshot(_row(tmp_path, cmdline=command), complete=False, unreadable=1), present,
    ])
    assert len(before["matcher_calls"]) == 2
    assert len(after["matcher_calls"]) == 1
    assert len(_detections(after)) == 1
    middle = after["cycles"][1]
    assert middle["coverage"]["enumerated"] == 1
    assert middle["coverage"]["readable"] == 0
    assert middle["coverage"]["unreadable"] == 1
    assert middle["health"] == 70
    assert len(middle["alerted"]) == 1


def test_negative_command_is_rechecked_without_new_birth(monkeypatch, tmp_path):
    first = _row(tmp_path, name="helper.exe", exe=str(tmp_path / "helper.exe"),
                 cmdline=("helper.exe", "--description", "safe"))
    changed = {**first, "cmdline": ("helper.exe", "--description", "mimikatz")}
    before, after = _pair(monkeypatch, [
        _snapshot(first), _snapshot(changed), _snapshot(first), _snapshot(changed),
    ])
    assert len(before["matcher_calls"]) == 4
    assert len(after["matcher_calls"]) == 2
    event, = _detections(after)
    assert event["active_attack"] is False
    assert event["response_authorized"] is False
    assert event["disposition"] == "observation"
    assert [cycle["detections"] for cycle in after["cycles"]] == [0, 1, 1, 1]


@pytest.mark.parametrize("expected_scope", ["observation", "process", "host"])
def test_first_alert_reason_and_typed_response_scope_stay_equal(
    monkeypatch, tmp_path, expected_scope,
):
    if expected_scope == "observation":
        row = _row(tmp_path, name="helper.exe", exe=str(tmp_path / "helper.exe"),
                   cmdline=("helper.exe", "--description", "mimikatz"))
    elif expected_scope == "host":
        row = _row(tmp_path, name="rundll32.exe", exe=str(tmp_path / "rundll32.exe"),
                   cmdline=("rundll32.exe", "comsvcs.dll,MiniDump", "640", "lsass.dmp", "full"))
    else:
        row = _row(tmp_path)
    snapshot = _snapshot(row)
    before, after = _pair(
        monkeypatch, [snapshot, snapshot], trusted_rundll32=expected_scope == "host",
    )
    assert len(before["matcher_calls"]) == 2
    assert len(after["matcher_calls"]) == 1
    event, = _detections(after)
    if expected_scope == "observation":
        assert event["response_authorized"] is False
        assert "response_contract" not in event
        assert event["detector_policy"] == "semantic-indicator-alert-only"
    else:
        assert event["response_authorized"] is True
        assert event["detector_policy"] == "exact-tool-lsass-dump"
        contract = event["response_contract"]
        assert contract["targets"]["pid"] == 731
        assert contract["targets"]["process_create_time"] == 100.0
        assert "suspend_process" in contract["actions"]
        assert "terminate_process" in contract["actions"]
        assert ("isolate_host" in contract["actions"]) is (expected_scope == "host")
        assert (contract["targets"].get("host") == "local") is (expected_scope == "host")


@pytest.mark.parametrize("pid", [None, 0, -1, "bad"])
def test_invalid_identity_keeps_gap_without_matcher(monkeypatch, tmp_path, pid):
    before, after = _pair(monkeypatch, [
        _snapshot(_row(tmp_path, pid=pid), complete=False, identity_incomplete=1),
    ])
    assert before["matcher_calls"] == after["matcher_calls"] == []
    assert _detections(after) == []
    cycle, = after["cycles"]
    assert cycle["coverage"]["enumerated"] == 1
    assert cycle["coverage"]["identity_incomplete"] == 1
    assert cycle["coverage"]["readable"] == 0
    assert cycle["health"] == 70
