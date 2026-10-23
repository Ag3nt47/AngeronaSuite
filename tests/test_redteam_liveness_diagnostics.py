from __future__ import annotations

import copy
import json
import threading
from types import SimpleNamespace

import pytest

from angerona.core import report_attest
from angerona.core.module_base import BaseModule
from angerona.modules import purple_guard
from angerona.modules.process_monitor import ProcessMonitorModule
from angerona.shark.red_team import RedTeamEngine
from angerona.shark.run_manifest import (
    attest_run_history, expected_red_team_plan, preflight_run, verify_run_history,
)


@pytest.fixture
def live_check(monkeypatch):
    # Inert unit state for predicate diagnostics only: no issued lease,
    # producer thread, native collector, marker or host mutation.
    purple = object.__new__(purple_guard.PurpleGuard)
    process = object.__new__(ProcessMonitorModule)
    bus = object()
    purple._bus = process._bus = bus
    manager = SimpleNamespace(bus=bus, modules={purple.name: purple, process.name: process})
    state = SimpleNamespace(
        lock=threading.RLock(), module=purple, process_module=process,
        manager=manager, bus=bus, readiness={"sensor_generation": 4, "process_sensor": {"generation": 7}},
        released=False, artifact_custody_failed=False, consumed=True,
        bound_run_id="inert-run", run_deadline_monotonic=200.0,
        process_epoch=purple_guard._LEASE_PROCESS_EPOCH,
    )
    purple_status = {"status": "running", "thread_alive": True, "health": 100, "lifecycle_generation": 4}
    process_status = {"status": "running", "thread_alive": True, "health": 100,
                      "lifecycle_generation": 7, "first_cycle_complete": True, "event_overflow_count": 0}
    snapshot_calls = []

    def snapshot(module):
        snapshot_calls.append(module)
        return dict(purple_status if module is purple else process_status)

    monkeypatch.setattr(purple_guard, "_lease_authority", lambda _lease: state)
    monkeypatch.setattr(BaseModule, "operational_snapshot", snapshot)
    monkeypatch.setattr(purple_guard, "time", SimpleNamespace(monotonic=lambda: 100.0))
    return SimpleNamespace(state=state, purple=purple_status, process=process_status,
                           purple_module=purple, process_module=process,
                           lease=object.__new__(purple_guard.RedTeamValidationLease), calls=snapshot_calls)


def _set_case(ctx, case):
    if case == "LEASE_RELEASED":
        ctx.state.released = True
    elif case == "ARTIFACT_CUSTODY_FAILED":
        ctx.state.artifact_custody_failed = True
    elif case == "LEASE_NOT_CONSUMED":
        ctx.state.consumed = False
    elif case == "RUN_MISMATCH":
        ctx.state.bound_run_id = "different-run"
    elif case == "RUN_EXPIRED":
        ctx.state.run_deadline_monotonic = 99.0
    elif case == "PROCESS_EPOCH_CHANGED":
        ctx.state.process_epoch = "different-epoch"
    elif case == "MANAGER_BUS_CHANGED":
        ctx.state.manager.bus = object()
    elif case == "REGISTRY_UNAVAILABLE":
        ctx.state.manager.modules = None
    elif case == "PURPLE_REGISTRY_CHANGED":
        ctx.state.manager.modules[ctx.purple_module.name] = object()
    elif case == "PROCESS_REGISTRY_CHANGED":
        ctx.state.manager.modules["Process Monitor"] = object()
    elif case == "PURPLE_BUS_CHANGED":
        ctx.purple_module._bus = object()
    elif case == "PROCESS_BUS_CHANGED":
        ctx.process_module._bus = object()
    elif case == "PURPLE_STATUS_UNPROVEN":
        ctx.purple["status"] = "restarting"
    elif case == "PURPLE_THREAD_UNPROVEN":
        ctx.purple["thread_alive"] = False
    elif case == "PURPLE_HEALTH_LOW":
        ctx.purple["health"] = 89
    elif case == "PURPLE_GENERATION_CHANGED":
        ctx.purple["lifecycle_generation"] = 5
    elif case == "PROCESS_STATUS_UNPROVEN":
        ctx.process["status"] = "stopped"
    elif case == "PROCESS_THREAD_UNPROVEN":
        ctx.process["thread_alive"] = False
    elif case == "PROCESS_FIRST_CYCLE_UNPROVEN":
        ctx.process["first_cycle_complete"] = False
    elif case == "PROCESS_HEALTH_LOW":
        ctx.process["health"] = 49
    elif case == "PROCESS_OVERFLOW":
        ctx.process["event_overflow_count"] = 1
    elif case == "PROCESS_GENERATION_CHANGED":
        ctx.process["lifecycle_generation"] = 8
    else:
        raise AssertionError(case)


CASES = (
    "LEASE_RELEASED",
    "ARTIFACT_CUSTODY_FAILED",
    "LEASE_NOT_CONSUMED",
    "RUN_MISMATCH",
    "RUN_EXPIRED",
    "PROCESS_EPOCH_CHANGED",
    "MANAGER_BUS_CHANGED",
    "REGISTRY_UNAVAILABLE",
    "PURPLE_REGISTRY_CHANGED",
    "PROCESS_REGISTRY_CHANGED",
    "PURPLE_BUS_CHANGED",
    "PROCESS_BUS_CHANGED",
    "PURPLE_STATUS_UNPROVEN",
    "PURPLE_THREAD_UNPROVEN",
    "PURPLE_HEALTH_LOW",
    "PURPLE_GENERATION_CHANGED",
    "PROCESS_STATUS_UNPROVEN",
    "PROCESS_THREAD_UNPROVEN",
    "PROCESS_FIRST_CYCLE_UNPROVEN",
    "PROCESS_HEALTH_LOW",
    "PROCESS_OVERFLOW",
    "PROCESS_GENERATION_CHANGED",
)


@pytest.mark.parametrize("case", CASES)
def test_each_original_liveness_refusal_has_exact_first_reason(live_check, case):
    _set_case(live_check, case)
    expected = purple_guard.ValidationLivenessReason[case]
    with pytest.raises(purple_guard.RedTeamProducerLivenessError) as caught:
        purple_guard.RedTeamValidationLease.assert_live_producers(live_check.lease, run_id="inert-run")
    assert isinstance(caught.value, purple_guard.RedTeamValidationError)
    assert caught.value.reason is expected
    assert caught.value.failure_evidence()["enrolled_producer"] == expected.enrolled_producer
    assert str(caught.value).startswith("validation producers are no longer live")
    assert live_check.calls == [live_check.purple_module, live_check.process_module]


def test_healthy_live_producers_do_not_hide_expired_lease(live_check):
    live_check.state.run_deadline_monotonic = 99.0
    with pytest.raises(purple_guard.RedTeamProducerLivenessError) as caught:
        purple_guard.RedTeamValidationLease.assert_live_producers(live_check.lease, run_id="inert-run")
    assert caught.value.reason is purple_guard.ValidationLivenessReason.RUN_EXPIRED
    assert caught.value.failure_evidence()["enrolled_producer"] is None
    assert all(row["status"] == "running" and row["thread_alive"] and row["health"] == 100
               for row in (live_check.purple, live_check.process))


def test_valid_liveness_still_passes(live_check):
    assert purple_guard.RedTeamValidationLease.assert_live_producers(live_check.lease, run_id="inert-run") is None


@pytest.mark.parametrize("first", ["LEASE_RELEASED", "RUN_EXPIRED", "REGISTRY_UNAVAILABLE"])
def test_first_failure_does_not_evaluate_unsafe_later_predicates(live_check, first):
    class UnsafeInteger:
        def __int__(self):
            raise AssertionError("a later predicate ran after an earlier refusal")

    _set_case(live_check, first)
    live_check.purple["health"] = UnsafeInteger()
    live_check.process["event_overflow_count"] = UnsafeInteger()
    with pytest.raises(purple_guard.RedTeamProducerLivenessError) as caught:
        purple_guard.RedTeamValidationLease.assert_live_producers(live_check.lease, run_id="inert-run")
    assert caught.value.reason is purple_guard.ValidationLivenessReason[first]


def test_existing_numeric_conversion_failure_is_not_relaxed(live_check):
    live_check.purple["health"] = "invalid"
    with pytest.raises(ValueError):
        purple_guard.RedTeamValidationLease.assert_live_producers(live_check.lease, run_id="inert-run")


def test_all_reason_evidence_is_complete_bounded_and_enum_only():
    for reason in purple_guard.ValidationLivenessReason:
        error = purple_guard.RedTeamProducerLivenessError(reason)
        detail = error.failure_detail()
        assert len(detail) <= 500
        assert detail.startswith("RedTeamValidationError: validation producers are no longer live; diagnostic=")
        evidence = json.loads(detail.split("; diagnostic=", 1)[1])
        assert evidence == {"schema": "angerona.redteam-liveness.v1", "reason": reason.code,
                            "enrolled_producer": reason.enrolled_producer}


def test_typed_failure_is_signed_incomplete_evidence_not_detection_credit(tmp_path, monkeypatch):
    key = bytes.fromhex("42" * 32)
    key_path = tmp_path / "bus.key"
    key_path.write_text(key.hex(), encoding="ascii")
    monkeypatch.setattr(report_attest, "_key_path", lambda: key_path)
    engine = RedTeamEngine(tmp_path)
    preflight = preflight_run(kind="red_team", cycles=1, jitter_range=(0, 0), noise_chance=0,
                             target_dir=engine.default_documents_dir, campaign=True, comprehensive=False)
    assert preflight.accepted
    engine.run_id = "inert-typed-liveness-history"
    engine._run_contract = preflight
    engine._expected_plan = expected_red_team_plan(preflight.as_dict())
    engine._complexity = 1
    engine._campaign = True
    engine._comprehensive = False
    engine._validation_lease = object()
    engine._evidence_lease = True
    engine._running.set()
    monkeypatch.setattr(purple_guard.RedTeamValidationLease, "assert_target_identity",
                        staticmethod(lambda _lease, *, run_id: None))

    def expired(_lease, *, run_id):
        raise purple_guard.RedTeamProducerLivenessError(purple_guard.ValidationLivenessReason.RUN_EXPIRED)

    monkeypatch.setattr(purple_guard.RedTeamValidationLease, "assert_live_producers", staticmethod(expired))
    # Authority fails before the first technique can create any marker/child.
    engine._run_playbook((0, 0), 0)
    assert not engine.is_running
    assert len(engine.steps) == 1 and engine.steps[0].ok is False
    assert not engine.steps[0].artifact_paths and not engine.steps[0].pids
    history = json.loads(engine.history_path.read_text(encoding="utf-8"))
    assert history["status"] == "incomplete"
    assert history["campaign"]["complete"] is False
    assert history["campaign"]["score_eligible"] is False
    assert verify_run_history(history, key=key).valid
    detail = history["steps"][0]["detail"]
    evidence = json.loads(detail.split("; diagnostic=", 1)[1])
    assert evidence["reason"] == "run-expired" and evidence["enrolled_producer"] is None
    # Even re-signing the document cannot conceal a changed step detail from
    # the independent per-step chain unless that chain is rebuilt too.
    altered = copy.deepcopy(history)
    altered["steps"][0]["detail"] = detail.replace("run-expired", "lease-released")
    altered = attest_run_history(altered, key=key)
    assert verify_run_history(altered, key=key).valid is False
