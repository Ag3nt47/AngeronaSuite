"""Inert observations preserve the original guard and reserve late-hold capacity."""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import threading

import pytest

from gui_response_hold_diagnostic import ResponseHoldDiagnostic


class _Held(RuntimeError):
    pass


@dataclass(frozen=True)
class _Event:
    ts: float = 100.0
    hmac_sig: str = "a" * 64
    details: dict = field(default_factory=lambda: {"run_id": "original-run", "step_id": "original-step"})


class _Stream:
    def __init__(self, mode=None):
        self.mode = mode
        self.parts = []
        self.calls = 0

    def write(self, raw):
        self.calls += 1
        if self.mode == "error":
            raise OSError("inert diagnostic stream failure")
        if self.mode == "partial":
            self.parts.append(raw[:len(raw) // 2])
            return len(raw) // 2
        self.parts.append(raw)
        return len(raw)


def _rows(stream):
    return [json.loads(raw) for raw in stream.parts]


def _guard(diagnostic, *, held=None, context=None, calls=None, result=None):
    def original(*args, **kwargs):
        if calls is not None:
            calls.append((args, kwargs))
        if held is not None:
            raise held
        return result
    return diagnostic.wrap_guard(original, hold_type=_Held, event_type=_Event,
                                 dispatch_context=lambda: context)


def test_success_calls_original_once_with_untouched_arguments_and_no_diagnostic_clock_or_io():
    stream, calls, clocks, contexts = _Stream(), [], [], []
    diagnostic = ResponseHoldDiagnostic(stream, wall_clock=lambda: clocks.append(True))
    event, extra, result = _Event(), object(), object()

    def original(*args, **kwargs):
        calls.append((args, kwargs))
        return result

    guarded = diagnostic.wrap_guard(original, hold_type=_Held, event_type=_Event,
                                    dispatch_context=lambda: contexts.append(True))
    before = json.dumps(event.__dict__, sort_keys=True)
    assert guarded(event, extra, admission=True, canary=extra) is result
    assert len(calls) == 1 and calls[0][0] == (event, extra)
    assert calls[0][1] == {"admission": True, "canary": extra}
    assert clocks == contexts == [] and stream.calls == 0
    assert json.dumps(event.__dict__, sort_keys=True) == before
    coverage = diagnostic.coverage()
    assert coverage["state"] == "none_observed" and coverage["hold_coverage_complete"] is False


def test_hold_records_actual_original_identity_and_one_post_hold_age_then_reraises_same_object():
    stream, calls, clocks = _Stream(), [], []
    diagnostic = ResponseHoldDiagnostic(stream, wall_clock=lambda: clocks.append(True) or 95.0)
    event = _Event(details={"run_id": "retained-run", "step_id": "retained-step", "private_path": "excluded"})
    context_event = _Event(ts=1.0, hmac_sig="b" * 64)
    held = _Held("Original response evidence expired.")
    before = json.dumps(event.__dict__, sort_keys=True)
    guarded = _guard(diagnostic, held=held, calls=calls, context=(context_event, None, None, None))
    with pytest.raises(_Held) as observed:
        guarded(event, admission=True)
    assert observed.value is held and len(calls) == len(clocks) == 1
    assert calls[0][0][0] is event
    row = _rows(stream)[0]
    assert row["event"] == {
        "hmac_sig": "a" * 64, "run_id": "retained-run", "step_id": "retained-step", "ts": 100.0,
        "identity_states": {"hmac_sig": "cached", "run_id": "cached", "step_id": "cached"},
    }
    assert row["reason"] == held.args[0] and row["exception_type"] == "_Held"
    assert row["age_observed_after_hold_seconds"] == -5.0  # No clamping or timestamp renewal.
    assert row["age_is_original_guard_sample"] is False
    assert row["phase_facts"]["admission"] is True
    assert row["phase_facts"]["retained_dispatch_context_present"] is True
    assert row["phase_facts"]["retained_context_event_is_argument"] is False
    assert "excluded" not in stream.parts[0].decode("ascii")
    assert json.dumps(event.__dict__, sort_keys=True) == before
    assert diagnostic.coverage()["hold_coverage_complete"] is True


def test_nested_action_scopes_restore_after_hold_without_guessing_a_callsite():
    stream = _Stream()
    diagnostic = ResponseHoldDiagnostic(stream, wall_clock=lambda: 101.0)
    event, held, action, pinned = _Event(), _Held("issuer proof held"), object(), object()
    guarded = _guard(diagnostic, held=held)
    with diagnostic.action_scope("_quarantine_file"):
        with pytest.raises(_Held):
            with diagnostic.action_scope("_act_on_process"):
                guarded(event, action=action, pinned=pinned)
        with pytest.raises(_Held):
            guarded(event)
    with pytest.raises(_Held):
        guarded(event)
    facts = [row["phase_facts"] for row in _rows(stream)]
    assert [row["outer_action_scope"] for row in facts] == ["_act_on_process", "_quarantine_file", None]
    assert facts[0]["action_argument_present"] and facts[0]["pinned_argument_present"]
    assert not facts[0]["retained_dispatch_context_present"]
    assert not facts[0]["admission"]  # Absence of retained context does not imply admission.


def test_matching_context_is_only_a_fact_and_does_not_replace_original_arguments():
    stream = _Stream()
    diagnostic = ResponseHoldDiagnostic(stream, wall_clock=lambda: 101.0)
    event, held, action = _Event(), _Held("held fixture"), object()
    with pytest.raises(_Held):
        _guard(diagnostic, held=held, context=(event, None, action, None))(event, action=action)
    facts = _rows(stream)[0]["phase_facts"]
    assert facts["retained_context_event_is_argument"] is True
    assert facts["action_argument_present"] is True


def test_nonhold_row_exhaustion_leaves_all_eight_late_hold_records_available():
    stream, lock = _Stream(), threading.Lock()
    diagnostic = ResponseHoldDiagnostic(stream, lock=lock, wall_clock=lambda: 101.0)
    with lock:
        for _index in range(56):
            assert diagnostic.write_nonhold_locked(b"{}\n")
        assert diagnostic.nonhold_full_locked()
        assert not diagnostic.write_nonhold_locked(b"{}\n")
    guarded = _guard(diagnostic, held=_Held("late proof held"))
    for _index in range(8):
        with pytest.raises(_Held):
            guarded(_Event())
    coverage = diagnostic.coverage()
    assert coverage["nonhold_rows_reserved"] == 56 and coverage["hold_rows_written"] == 8
    assert coverage["hold_coverage_complete"] is True
    assert len(stream.parts) == 64 and sum(map(len, stream.parts)) <= 64 * 1024
    with pytest.raises(_Held):
        guarded(_Event())
    exhausted = diagnostic.coverage()
    assert exhausted["hold_budget_drops"] == 1 and exhausted["hold_rows_written"] == 8
    assert exhausted["hold_coverage_complete"] is False


def test_nonhold_byte_exhaustion_preserves_hold_partition_without_expanding_total_budget():
    stream, lock = _Stream(), threading.Lock()
    diagnostic = ResponseHoldDiagnostic(stream, lock=lock, wall_clock=lambda: 101.0)
    with lock:
        assert diagnostic.write_nonhold_locked(b"x" * (48 * 1024))
        assert diagnostic.nonhold_full_locked()
        assert not diagnostic.write_nonhold_locked(b"x")
    for _index in range(8):
        with pytest.raises(_Held):
            _guard(diagnostic, held=_Held("late held fixture"))(_Event())
    coverage = diagnostic.coverage()
    assert coverage["nonhold_bytes_reserved"] == 48 * 1024
    assert coverage["hold_rows_written"] == 8 and coverage["hold_bytes_reserved"] <= 16 * 1024
    assert sum(map(len, stream.parts)) <= 64 * 1024


@pytest.mark.parametrize("mode", ["error", "partial"])
def test_failed_or_partial_writes_consume_capacity_and_never_claim_a_capture(mode):
    stream = _Stream(mode)
    diagnostic = ResponseHoldDiagnostic(stream, wall_clock=lambda: 101.0)
    held = _Held("original held fixture")
    for _index in range(10):
        with pytest.raises(_Held) as observed:
            _guard(diagnostic, held=held)(_Event())
        assert observed.value is held
    coverage = diagnostic.coverage()
    assert stream.calls == coverage["hold_rows_reserved"] == 8
    assert coverage["hold_rows_written"] == 0 and coverage["hold_budget_drops"] == 2
    assert coverage["hold_write_errors" if mode == "error" else "hold_partial_writes"] == 8
    assert coverage["hold_coverage_complete"] is False


@pytest.mark.parametrize("unavailable", ["stream", "lock", "clock", "context"])
def test_unavailable_capture_is_counted_without_changing_the_original_exception(unavailable):
    stream, lock, clocks = _Stream(), threading.Lock(), []

    def clock():
        clocks.append(True)
        if unavailable == "clock":
            raise RuntimeError("inert clock capture failed")
        return 101.0

    def context():
        if unavailable == "context":
            raise RuntimeError("inert cached context failed")
        return None

    diagnostic = ResponseHoldDiagnostic(None if unavailable == "stream" else stream,
                                        lock=lock, wall_clock=clock)
    if unavailable == "lock":
        lock.acquire()
    held = _Held("original held fixture")
    guarded = diagnostic.wrap_guard(lambda *_a, **_k: (_ for _ in ()).throw(held),
                                    hold_type=_Held, event_type=_Event, dispatch_context=context)
    try:
        with pytest.raises(_Held) as observed:
            guarded(_Event())
        assert observed.value is held
    finally:
        if unavailable == "lock":
            lock.release()
    coverage = diagnostic.coverage()
    assert coverage["holds_observed"] == 1 and coverage["hold_rows_written"] == 0
    assert coverage["hold_coverage_complete"] is False
    field = {"stream": "hold_unavailable_drops", "lock": "hold_busy_drops"}.get(unavailable, "hold_capture_errors")
    assert coverage[field] == 1
    assert stream.calls == 0
    assert len(clocks) == (0 if unavailable in {"stream", "lock"} else 1)


def test_identity_and_reason_bounds_are_explicit_without_stringifying_arbitrary_values():
    class Untrusted:
        def __str__(self):
            raise AssertionError("untrusted identity was stringified")

    stream = _Stream()
    diagnostic = ResponseHoldDiagnostic(stream, wall_clock=lambda: 101.0)
    event = _Event(hmac_sig="h" * 129, details={"run_id": Untrusted(), "step_id": "x" * 129})
    with pytest.raises(_Held):
        _guard(diagnostic, held=_Held("R" * 1000))(event)
    row = _rows(stream)[0]
    assert row["event"]["hmac_sig"] is row["event"]["run_id"] is row["event"]["step_id"] is None
    assert row["event"]["identity_states"] == {"hmac_sig": "oversized", "run_id": "unavailable", "step_id": "oversized"}
    assert row["reason"] == "R" * 128 and row["reason_truncated"] is True
    assert len(stream.parts[0]) <= 2 * 1024


def test_other_exceptions_are_propagated_without_diagnostic_work():
    stream, clocks = _Stream(), []
    diagnostic = ResponseHoldDiagnostic(stream, wall_clock=lambda: clocks.append(True))
    original = ValueError("original non-hold failure")

    def guard(*_args, **_kwargs):
        raise original

    wrapped = diagnostic.wrap_guard(guard, hold_type=_Held, event_type=_Event, dispatch_context=lambda: None)
    with pytest.raises(ValueError) as observed:
        wrapped(_Event())
    assert observed.value is original
    assert clocks == [] and stream.calls == diagnostic.coverage()["holds_observed"] == 0
