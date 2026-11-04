"""Inert regressions for passive native-response timing; no product/native imports."""
from __future__ import annotations

import json
import threading
from types import SimpleNamespace

import pytest

from gui_response_cost_diagnostic import ResponseCostDiagnostic


class Unprintable:
    def __repr__(self):
        raise AssertionError("The observer must not render private objects")


def row_for(snapshot, stage):
    return next(row for row in snapshot["stages"] if row["stage"] == stage)


def test_nested_timings_preserve_values_and_separate_inclusive_cost():
    ticks = iter((0, 10, 30, 50))
    diagnostic = ResponseCostDiagnostic(clock=lambda: next(ticks))
    diagnostic.set_phase("run1")
    diagnostic.set_response_thread(threading.current_thread)
    sentinel, calls = Unprintable(), []

    def child(value, *, token):
        calls.append((value is sentinel, token is sentinel))
        return sentinel

    observed_child = diagnostic.wrap(child, "issuer.scope", boolean_result=True)
    observed_parent = diagnostic.wrap(
        lambda value: observed_child(value, token=value), "combat.host_authority")
    assert observed_parent(sentinel) is sentinel
    assert calls == [(True, True)]
    snapshot = diagnostic.snapshot()
    parent, nested = row_for(snapshot, "combat.host_authority"), row_for(snapshot, "issuer.scope")
    assert (parent["inclusive_ns"], parent["exclusive_ns"], parent["max_inclusive_ns"]) == (50, 30, 50)
    assert (nested["inclusive_ns"], nested["exclusive_ns"]) == (20, 20)
    assert parent["role"] == nested["role"] == "response-worker"
    assert parent["phase"] == nested["phase"] == "run1"
    assert snapshot["calls_accepted"] == snapshot["calls_completed"] == 2
    assert snapshot["coverage_complete"] is True
    assert nested["true_returns"] == nested["false_returns"] == 0
    json.dumps(snapshot, allow_nan=False)


def test_original_exception_identity_is_preserved_without_message_or_argument_capture():
    class OriginalFailure(BaseException):
        pass

    failure = OriginalFailure("PRIVATE-EXCEPTION-DO-NOT-CAPTURE")
    diagnostic = ResponseCostDiagnostic(clock=iter((0, 7)).__next__)
    calls = []

    def original(secret):
        calls.append(secret)
        raise failure

    wrapped = diagnostic.wrap(original, "journal.append")
    sentinel = Unprintable()
    with pytest.raises(OriginalFailure) as caught:
        wrapped(sentinel)
    assert caught.value is failure
    assert len(calls) == 1 and calls[0] is sentinel
    snapshot = diagnostic.snapshot()
    row = row_for(snapshot, "journal.append")
    assert row["raised"] == row["completed"] == 1
    assert row["inclusive_ns"] == 7
    assert snapshot["coverage_complete"] is True
    encoded = json.dumps(snapshot)
    assert "PRIVATE-EXCEPTION" not in encoded
    assert "secret" not in encoded


def test_actual_deferred_flag_requires_original_code_frame_and_current_guard():
    diagnostic = ResponseCostDiagnostic()
    diagnostic.set_phase("run2")
    sentinel = Unprintable()

    def host(flag, *, call_guard=True):
        deferred_canary = flag
        return observed_guard() if call_guard else sentinel

    observed_guard = diagnostic.wrap(
        lambda: sentinel, "combat.current_event", host_code=host.__code__)

    def unrelated():
        deferred_canary = True
        return observed_guard()

    assert host(True) is sentinel
    assert host(False) is sentinel
    assert host("PRIVATE-NON-BOOLEAN") is sentinel
    assert host(True, call_guard=False) is sentinel
    assert unrelated() is sentinel
    snapshot = diagnostic.snapshot()
    flags = snapshot["actual_deferred_flags_at_current_guard"]
    assert len(flags) == 1
    assert flags[0]["phase"] == "run2" and flags[0]["role"] == "other-thread"
    assert flags[0]["actual_true"] == flags[0]["actual_false"] == 1
    assert flags[0]["flag_unavailable"] == 1
    assert flags[0]["outside_host"] + flags[0]["frame_depth_limit"] == 1
    assert row_for(snapshot, "combat.current_event")["entered"] == 4
    assert "PRIVATE-NON-BOOLEAN" not in json.dumps(snapshot)


def test_child_and_fixture_gate_filtering_never_skips_original():
    diagnostic = ResponseCostDiagnostic()
    calls = []

    def original(value, *, selected):
        calls.append((value, selected))
        return value

    wrapped = diagnostic.wrap(original, "issuer.scope", child_only=True,
                              gate=lambda args, kwargs: kwargs["selected"] is True)
    assert wrapped(1, selected=True) == 1  # no observed root
    root = diagnostic.wrap(lambda: (wrapped(2, selected=False), wrapped(3, selected=True)),
                           "combat.handle")
    assert root() == (2, 3)
    snapshot = diagnostic.snapshot()
    assert calls == [(1, True), (2, False), (3, True)]
    assert snapshot["intentional_filtered_calls_lower_bound"] == 2
    assert row_for(snapshot, "issuer.scope")["entered"] == 1
    assert snapshot["coverage_complete"] is True


def test_enter_and_exit_contention_are_nonblocking_visible_gaps():
    diagnostic = ResponseCostDiagnostic()
    calls = []
    wrapped = diagnostic.wrap(lambda: calls.append("entered") or True,
                              "issuer.scope", boolean_result=True)
    diagnostic._lock.acquire()
    try:
        assert wrapped() is True
    finally:
        diagnostic._lock.release()
    first = diagnostic.snapshot()
    assert first["drop_counts_lower_bounds"]["busy_enter"] == 1
    assert first["coverage_complete"] is False
    assert first["stages"] == []
    assert calls == ["entered"]

    def original():
        diagnostic._lock.acquire()
        return False

    wrapped_exit = diagnostic.wrap(original, "issuer.scope", boolean_result=True)
    try:
        assert wrapped_exit() is False
    finally:
        diagnostic._lock.release()
    second = diagnostic.snapshot()
    assert second["drop_counts_lower_bounds"]["busy_exit"] == 1
    assert second["calls_accepted"] == 1 and second["calls_completed"] == 0
    assert row_for(second, "issuer.scope")["inflight_observations"] == 1
    assert second["coverage_complete"] is False


def test_call_depth_and_row_limits_preserve_calls_and_bound_storage():
    diagnostic = ResponseCostDiagnostic()
    diagnostic.MAX_CALLS, diagnostic.MAX_ROWS, diagnostic.MAX_DEPTH = 1, 1, 1
    calls = []
    child = diagnostic.wrap(lambda: calls.append("child") or True, "issuer.scope")
    parent = diagnostic.wrap(lambda: child(), "combat.handle")
    assert parent() is True
    assert parent() is True
    snapshot = diagnostic.snapshot()
    assert calls == ["child", "child"]
    assert snapshot["calls_accepted"] == snapshot["calls_completed"] == 1
    assert len(snapshot["stages"]) == 1
    assert snapshot["drop_counts_lower_bounds"]["depth"] == 1
    assert snapshot["drop_counts_lower_bounds"]["budget"] == 2
    assert snapshot["coverage_complete"] is False


@pytest.mark.parametrize("failure_source", ["clock", "role", "gate"])
def test_observer_failures_do_not_replace_result_or_invent_complete_coverage(failure_source):
    diagnostic = ResponseCostDiagnostic()
    sentinel, calls = Unprintable(), []

    def broken(*_args, **_kwargs):
        raise RuntimeError("PRIVATE-OBSERVER-FAILURE")

    gate = None
    if failure_source == "clock":
        diagnostic._clock = broken
    elif failure_source == "role":
        diagnostic._role = broken
    else:
        gate = broken
    wrapped = diagnostic.wrap(lambda: calls.append(True) or sentinel,
                              "combat.handle", gate=gate)
    assert wrapped() is sentinel
    assert calls == [True]
    snapshot = diagnostic.snapshot()
    assert snapshot["coverage_complete"] is False
    assert snapshot["drop_counts_lower_bounds"]["observer"] == 1
    assert "PRIVATE-OBSERVER" not in json.dumps(snapshot)


def test_invalid_clock_and_fixed_label_rejection():
    diagnostic = ResponseCostDiagnostic(clock=lambda: True)
    calls = []
    assert diagnostic.wrap(lambda: calls.append(True) or True, "issuer.scope")() is True
    assert calls == [True]
    assert diagnostic.snapshot()["drop_counts_lower_bounds"]["clock"] == 1
    with pytest.raises(ValueError):
        diagnostic.wrap(lambda: None, "PRIVATE-UNTRUSTED-LABEL")
    with pytest.raises(ValueError):
        diagnostic.set_phase("PRIVATE-UNTRUSTED-PHASE")
    with pytest.raises(ValueError):
        diagnostic.wrap(lambda: None, "combat.handle", host_code=object())


def test_output_requires_exact_retirement_and_never_overwrites(tmp_path):
    diagnostic = ResponseCostDiagnostic()
    target = tmp_path / "cost.json"
    for producers, recorder in ((False, True), (True, False), (1, True), (True, 1)):
        with pytest.raises(ValueError):
            diagnostic.write_after_retirement(target, producers_retired=producers,
                                               recorder_retired=recorder)
        assert not target.exists()
    assert diagnostic.write_after_retirement(target, producers_retired=True,
                                              recorder_retired=True) is True
    raw = target.read_bytes()
    assert len(raw) <= diagnostic.MAX_JSON_BYTES
    result = json.loads(raw.decode("ascii"))
    assert result["fixture_retirement_gate"] == {"producers_retired": True, "recorder_retired": True}
    with pytest.raises(FileExistsError):
        diagnostic.write_after_retirement(target, producers_retired=True, recorder_retired=True)
    assert target.read_bytes() == raw


def test_snapshot_reports_live_observation_then_completes_without_retirement_claim():
    diagnostic = ResponseCostDiagnostic()
    during = []
    wrapped = diagnostic.wrap(lambda: during.append(diagnostic.snapshot()) or True,
                              "combat.handle")
    assert wrapped() is True
    assert during[0]["coverage_complete"] is False
    assert row_for(during[0], "combat.handle")["inflight_observations"] == 1
    after = diagnostic.snapshot()
    assert after["coverage_complete"] is True
    assert row_for(after, "combat.handle")["inflight_observations"] == 0
    assert "fixture_retirement_gate" not in after


def test_output_budget_and_snapshot_contention_do_not_write(tmp_path):
    diagnostic = ResponseCostDiagnostic()
    diagnostic._lock.acquire()
    try:
        busy = diagnostic.snapshot()
    finally:
        diagnostic._lock.release()
    assert busy["state"] == "snapshot-busy" and busy["coverage_complete"] is False
    diagnostic.MAX_JSON_BYTES = 8
    target = tmp_path / "over-budget.json"
    with pytest.raises(ValueError):
        diagnostic.write_after_retirement(target, producers_retired=True, recorder_retired=True)
    assert not target.exists()


def test_module_local_os_view_forwards_exact_calls_without_changing_shared_source():
    diagnostic = ResponseCostDiagnostic()
    secret, returned = Unprintable(), Unprintable()
    calls = []

    def fsync(descriptor):
        calls.append(("fsync", descriptor is secret))
        return returned

    def replace(source, destination, *, src_dir_fd=None, dst_dir_fd=None):
        calls.append(("replace", source is secret, destination is secret,
                      src_dir_fd is secret, dst_dir_fd is secret))
        return returned

    source = SimpleNamespace(fsync=fsync, replace=replace, read=secret,
                             path=secret, environ={"inert": secret}, name="inert")
    view = diagnostic.os_view(source,
        fsync_scopes=(("credential.write", "credential.fsync"),),
        replace_scopes=(("credential.replace", "credential.os_replace"),))
    assert source.fsync is fsync and source.replace is replace
    assert view.read is view.path is secret and view.environ is source.environ
    assert view.name == source.name
    assert view.fsync(secret) is returned  # Unselected call still runs unchanged.
    assert view.replace(secret, secret, src_dir_fd=secret, dst_dir_fd=secret) is returned
    observed_sync = diagnostic.wrap(lambda: view.fsync(secret), "credential.write")
    observed_replace = diagnostic.wrap(
        lambda: view.replace(secret, secret, src_dir_fd=secret, dst_dir_fd=secret),
        "credential.replace")
    assert observed_sync() is returned and observed_replace() is returned
    assert calls == [("fsync", True), ("replace", True, True, True, True)] * 2
    snapshot = diagnostic.snapshot()
    assert row_for(snapshot, "credential.fsync")["completed"] == 1
    assert row_for(snapshot, "credential.os_replace")["completed"] == 1
    assert snapshot["coverage_complete"] is True
    assert snapshot["intentional_filtered_calls_lower_bound"] == 2
    assert source.fsync is fsync and source.replace is replace


def test_scoped_native_exception_runs_once_and_preserves_exact_exception():
    class NativeFailure(BaseException):
        pass

    diagnostic = ResponseCostDiagnostic()
    failure = NativeFailure("PRIVATE-NATIVE-SUBSTAGE-FAILURE")
    calls = []

    def original(value):
        calls.append(value)
        raise failure

    observed = diagnostic.wrap_scoped(original, (("credential.write", "credential.fsync"),))
    root = diagnostic.wrap(lambda value: observed(value), "credential.write")
    secret = Unprintable()
    with pytest.raises(NativeFailure) as caught:
        root(secret)
    assert caught.value is failure and len(calls) == 1 and calls[0] is secret
    snapshot = diagnostic.snapshot()
    assert row_for(snapshot, "credential.fsync")["raised"] == 1
    assert row_for(snapshot, "credential.write")["raised"] == 1
    assert snapshot["coverage_complete"] is True
    assert "PRIVATE-NATIVE" not in json.dumps(snapshot)


def test_scoped_call_uses_nearest_parent_and_subtracts_only_observed_child_time():
    diagnostic = ResponseCostDiagnostic(clock=iter((0, 10, 20, 40, 60, 90)).__next__)
    calls = []
    observed = diagnostic.wrap_scoped(lambda: calls.append(True) or None, (
        ("journal.append_bytes", "journal.fsync"), ("witness.write", "witness.fsync")))
    witness = diagnostic.wrap(lambda: observed(), "witness.write")
    journal = diagnostic.wrap(lambda: witness(), "journal.append_bytes")
    assert journal() is None and calls == [True]
    snapshot = diagnostic.snapshot()
    assert {row["stage"] for row in snapshot["stages"]} == {
        "journal.append_bytes", "witness.write", "witness.fsync"}
    assert row_for(snapshot, "journal.append_bytes")["inclusive_ns"] == 90
    assert row_for(snapshot, "journal.append_bytes")["exclusive_ns"] == 40
    assert row_for(snapshot, "witness.write")["inclusive_ns"] == 50
    assert row_for(snapshot, "witness.write")["exclusive_ns"] == 30
    assert row_for(snapshot, "witness.fsync")["inclusive_ns"] == 20
    assert snapshot["calls_accepted"] == snapshot["calls_completed"] == 3
    assert snapshot["coverage_complete"] is True


@pytest.mark.parametrize("broken_stack,reason", [(Unprintable(), "observer"),
                                                 ([None, None], "depth")])
def test_scoped_selection_failure_remains_nonblocking_and_calls_original_once(broken_stack, reason):
    diagnostic = ResponseCostDiagnostic()
    diagnostic.MAX_DEPTH = 1
    diagnostic._local.stack = broken_stack
    calls, returned = [], Unprintable()
    observed = diagnostic.wrap_scoped(lambda: calls.append(True) or returned,
                                     (("credential.write", "credential.fsync"),))
    assert observed() is returned and calls == [True]
    snapshot = diagnostic.snapshot()
    assert snapshot["coverage_complete"] is False
    assert snapshot["drop_counts_lower_bounds"][reason] == 1
    assert snapshot["stages"] == []


def test_scoped_child_budget_rejection_does_not_skip_a_durability_call():
    diagnostic = ResponseCostDiagnostic()
    diagnostic.MAX_CALLS = 1
    calls = []
    observed = diagnostic.wrap_scoped(lambda: calls.append(True) or None,
                                     (("credential.write", "credential.fsync"),))
    root = diagnostic.wrap(lambda: observed(), "credential.write")
    assert root() is None and root() is None
    assert calls == [True, True]
    snapshot = diagnostic.snapshot()
    assert snapshot["calls_accepted"] == snapshot["calls_completed"] == 1
    assert snapshot["drop_counts_lower_bounds"]["budget"] == 2
    assert snapshot["coverage_complete"] is False


@pytest.mark.parametrize("scopes", [(), [], (("untrusted-label", "credential.fsync"),),
    (("credential.write", "untrusted-label"),), (["credential.write", "credential.fsync"],),
    (("credential.write", "credential.fsync"),) * 2,
    (("credential.write", "credential.fsync"),) * 9])
def test_scoped_labels_reject_unbounded_nonplain_unknown_or_duplicate_input(scopes):
    diagnostic = ResponseCostDiagnostic()
    calls = []
    with pytest.raises(ValueError):
        diagnostic.wrap_scoped(lambda: calls.append(True), scopes)
    assert calls == [] and diagnostic.snapshot()["calls_accepted"] == 0
