"""Inert startup caps, diagnostic input limits and optional-custody failures.

These cases launch no application, source scan, helper or attack probe. Native
owners/pipes are explicit fixtures; no synthetic result earns catch credit.
"""
from __future__ import annotations

import io
import json
import os
import threading
from types import SimpleNamespace

import pytest

from angerona.gui import red_team_bridge as bridge
from angerona.shark import red_team_ipc as ipc


def observation(**changes):
    row = dict(phase="source-seal", status="completed", error_type="", elapsed_ms=123)
    row.update(changes)
    return ipc.STARTUP_PREFIX + json.dumps(row).encode() + b"\n"


def test_advisory_parser_has_no_raw_text_key_frame_or_path_retention():
    buffer = ipc.ToolStartupObservations()
    private = b"DO_NOT_KEEP_KEY_OR_PATH"
    raw = b"untrusted " + private + b"\n" + observation(extra=private.decode())
    raw += observation(error_type=private.decode(), status="failed") + observation()
    for begin in range(0, len(raw), 7):
        assert buffer.feed(raw[begin:begin + 7], received_after_ms=200)
    result = buffer.snapshot()
    assert result["advisory_only"] and len(result["records"]) == 1
    assert result["records"][0]["received_after_ms"] == 200
    assert result["unrecognized_lines"] == 1 and result["malformed_lines"] == 2
    assert private.decode() not in json.dumps(result)
    result["records"][0]["phase"] = "forged"
    assert buffer.snapshot()["records"][0]["phase"] == "source-seal"


def test_raw_byte_line_and_retained_record_limits_are_separate_and_finite():
    byte_limit = ipc.ToolStartupObservations()
    assert not byte_limit.feed(b"x" * (ipc.MAX_STARTUP_BYTES + 17))
    result = byte_limit.snapshot()
    assert result["raw_bytes"] == ipc.MAX_STARTUP_BYTES and result["omitted_bytes"] == 17
    assert result["oversized_lines"] == 1 and result["exhausted"]
    assert len(byte_limit._line) <= ipc.MAX_STARTUP_LINE
    line_limit = ipc.ToolStartupObservations()
    assert not line_limit.feed(b"\n" * (ipc.MAX_STARTUP_LINES + 1))
    assert line_limit.snapshot()["lines"] == ipc.MAX_STARTUP_LINES
    rows = ipc.ToolStartupObservations()
    assert rows.feed(observation() * (ipc.MAX_STARTUP_RECORDS + 1))
    assert len(rows.snapshot()["records"]) == ipc.MAX_STARTUP_RECORDS
    assert rows.snapshot()["omitted_records"] == 1


@pytest.mark.parametrize("replacement", [
    {"phase": "arbitrary-command"}, {"status": "ready"}, {"elapsed_ms": True},
    {"elapsed_ms": -1}, {"elapsed_ms": 105001}, {"elapsed_ms": float("nan")},
    {"error_type": "secret"}, {"phase": ["source-seal"]},
])
def test_nonclosed_diagnostic_values_cannot_become_readiness_or_authority(replacement):
    buffer = ipc.ToolStartupObservations()
    assert buffer.feed(observation(**replacement))
    assert not buffer.snapshot()["records"]
    assert buffer.snapshot()["malformed_lines"] == 1


@pytest.mark.parametrize("failure", ["raise", "nan", "inf", "invalid-start"])
def test_optional_emitter_clock_failure_cannot_replace_actual_startup(monkeypatch, failure):
    writes = []
    safe_os = SimpleNamespace(**vars(os))
    safe_os.write = lambda fd, value: writes.append((fd, value)) or len(value)
    monkeypatch.setattr(ipc, "os", safe_os)
    def unavailable():
        raise RuntimeError("private optional clock error")
    value = unavailable if failure == "raise" else lambda: float(failure) if failure in {"nan", "inf"} else 1.
    monkeypatch.setattr(ipc, "time", SimpleNamespace(monotonic=value))
    ipc.emit_startup_observation("source-seal", "started", None if failure == "invalid-start" else 0.)
    assert not writes


def test_emitter_uses_stderr_only_and_maps_unknown_exception_names(monkeypatch):
    writes = []
    safe_os = SimpleNamespace(**vars(os))
    safe_os.write = lambda fd, value: writes.append((fd, value)) or len(value)
    monkeypatch.setattr(ipc, "os", safe_os)
    monkeypatch.setattr(ipc, "time", SimpleNamespace(monotonic=lambda: 1.))
    class PRIVATE_EXCEPTION_NAME(Exception):
        pass
    ipc.emit_startup_observation("source-seal", "failed", 0., PRIVATE_EXCEPTION_NAME("private message"))
    assert {fd for fd, _raw in writes} == {2}
    buffer = ipc.ToolStartupObservations()
    buffer.feed(b"".join(raw for _fd, raw in writes))
    assert buffer.snapshot()["records"][0]["error_type"] == "Exception"
    assert b"PRIVATE_EXCEPTION_NAME" not in writes[0][1] and b"private message" not in writes[0][1]


@pytest.mark.parametrize("deadline", [None, True, 0, -1, 1.5, float("nan"), 2**64, "123"])
def test_bootstrap_requires_an_exact_original_unsigned_monotonic_deadline(deadline):
    with pytest.raises(ipc.ToolProtocolError):
        ipc.bootstrap(b"x" * 32, "1" * 32, 1001, "123", 1002, "124", startup_deadline_ns=deadline)


def budget_clock(monkeypatch):
    now = [1_000_000_000_000]
    monkeypatch.setattr(bridge, "time", SimpleNamespace(monotonic_ns=lambda: now[0], monotonic=lambda: now[0] / 1e9))
    return now


def test_verification_gets_its_own_cap_and_does_not_spend_the_presentation_budget(monkeypatch):
    now = budget_clock(monkeypatch)
    owner = bridge.RedTeamToolOwner(lambda *_args: None)
    original = owner._bootstrap_deadline_ns
    now[0] += 30_000_000_000
    assert owner.startup_timeout_reason() is None  # The old whole15s cutoff would fail here.
    owner._start_presentation_budget()  # Clock-only unit fixture, no native admission/readiness.
    assert owner._bootstrap_deadline_ns == original and not owner._ready.is_set()
    now[0] += 14_999_999_999
    assert owner.startup_timeout_reason() is None
    now[0] += 1
    assert owner.startup_timeout_reason() == "UiReadinessTimeout"
    assert not owner._ui_ready.is_set()


def test_late_hello_or_unavailable_authoritative_clock_never_grants_readiness(monkeypatch):
    now = budget_clock(monkeypatch)
    owner = bridge.RedTeamToolOwner(lambda *_args: None)
    now[0] = owner._bootstrap_deadline_ns
    with pytest.raises(ipc.ToolProtocolError):
        owner._assert_startup_current()
    assert owner.lifecycle_snapshot()["startup_failure"]["exception_type"] == "BootstrapReadinessTimeout"
    assert not owner._ready.is_set() and owner._process is None
    now[0] = owner._startup_started_ns - 1
    assert owner.startup_timeout_reason() == "StartupClockUnavailable"


def test_absolute_whole_attempt_cap_cannot_be_extended_by_stage_or_child_claims(monkeypatch):
    now = budget_clock(monkeypatch)
    owner = bridge.RedTeamToolOwner(lambda *_args: None)
    now[0] = owner._bootstrap_deadline_ns - 1
    owner._start_presentation_budget()
    owner._startup_stderr.feed(observation(elapsed_ms=0))
    now[0] = owner._whole_deadline_ns
    assert owner.startup_timeout_reason() == "StartupAttemptTimeout"
    assert not owner._ui_ready.is_set()


def test_stderr_flood_has_a_bounded_owned_abort_and_no_protocol_output(monkeypatch):
    owner = bridge.RedTeamToolOwner(lambda *_args: None)
    owner._process = SimpleNamespace(stderr=io.BytesIO(b"x" * (ipc.MAX_STARTUP_BYTES + 1)))
    stopped = []
    monkeypatch.setattr(owner, "abort_lifetime", lambda: stopped.append(True))
    owner._read_startup_stderr()
    assert stopped == [True] and owner._error == "StartupDiagnosticOutputLimit"
    assert owner._startup_stderr.snapshot()["exhausted"]
    assert not owner._ready.is_set() and not owner._ui_ready.is_set()


def native_owner(calls, *, getter=None, prepare_error=None):
    def prepare(**_kwargs):
        calls.append("prepare")
        if prepare_error:
            raise RuntimeError("mandatory retained custody unavailable")
    result = SimpleNamespace(prepare_tree_retirement=prepare,
        terminate=lambda: calls.append("terminate"), wait_tree=lambda **_kwargs: calls.append("wait"),
        close=lambda: calls.append("close"))
    if getter is not None:
        result.tree_retirement_members_snapshot = getter
    return result


@pytest.mark.parametrize("failure", ["getter", "factory", "image"])
def test_optional_native_diagnostic_failure_never_prevents_valid_original_termination(monkeypatch, failure):
    import angerona.core.windows_process_lease as lease
    calls = []
    def getter():
        if failure == "getter":
            raise ValueError("optional getter failed")
        return {"cut_recorded": True, "members": ({"pid": 1002, "birth_ticks": "123"},)}
    class Native:
        def __init__(self):
            if failure == "factory":
                raise OSError("optional native factory failed")
        def open(self, *_args): return 99
        def object_identity(self, _pin): return 1002, 123
        def wait(self, *_args): return False
        def identity(self, _pin): raise OSError("optional image unavailable")
        def close(self, _pin): calls.append("diagnostic-close")
    monkeypatch.setattr(lease, "_Native", Native)
    owner = bridge.RedTeamToolOwner(lambda *_args: None)
    owner._native_owner = native_owner(calls, getter=getter)
    owner._terminate_owned_native(1.)
    assert calls[0] == "prepare" and calls[-1] == "terminate"
    assert owner._startup_native_capture_error


def test_failed_mandatory_native_prepare_still_holds_and_never_terminates():
    calls = []
    owner = bridge.RedTeamToolOwner(lambda *_args: None)
    owner._native_owner = native_owner(calls, prepare_error=True)
    with pytest.raises(RuntimeError):
        owner._terminate_owned_native(1.)
    assert calls == ["prepare"] and not owner._native_termination_dispatched


def test_optional_native_work_cannot_borrow_or_extend_original_stop_budget(monkeypatch):
    now = budget_clock(monkeypatch)
    calls = []
    def prepare(**_kwargs):
        calls.append("prepare")
        now[0] += 950_000_000
    def getter():
        calls.append("memory-only")
        return {"cut_recorded": True, "members": ({"pid": 1002, "birth_ticks": "123"},)}
    owner = bridge.RedTeamToolOwner(lambda *_args: None)
    owner._native_owner = native_owner(calls, getter=getter)
    owner._native_owner.prepare_tree_retirement = prepare
    owner._terminate_owned_native(1.)
    assert calls == ["prepare", "memory-only", "terminate"]
    assert owner._startup_native_capture_error == "NativeDiagnosticBudgetGap"


def test_optional_readonly_close_gap_never_retries_or_blocks_mandatory_cleanup(monkeypatch):
    import angerona.core.windows_process_lease as lease
    calls = []
    class Native:
        def object_identity(self, _pin): return 1002, 123
        def wait(self, *_args): return True
        def exit_code(self, _pin): return 1
        def close(self, _pin):
            calls.append("one-optional-close")
            raise OSError("unknown close result")
    monkeypatch.setattr(lease, "_Native", Native)
    shared_hold = threading.Event()
    owner = bridge.RedTeamToolOwner(lambda *_args: None, native_diagnostic_hold=shared_hold)
    owner._native_owner = native_owner(calls)
    row = {"pid": 1002, "birth_ticks": "123", "handle_closed": False}
    owner._startup_native_pins.append((Native(), 99, row))
    owner._startup_native_rows.append(row)
    assert owner.stop(1.)
    assert calls == ["prepare", "terminate", "wait", "one-optional-close", "close"]
    assert shared_hold.is_set() and not row["handle_closed"] and owner._retired.is_set()
    assert owner.lifecycle_snapshot()["startup_native_diagnostic_close_gap"]
    owner.stop(1.)
    assert calls.count("one-optional-close") == 1
    later = bridge.RedTeamToolOwner(lambda *_args: None, native_diagnostic_hold=shared_hold)
    later._native_owner = native_owner(calls, getter=lambda: pytest.fail("Latched optional collection must stay off"))
    later._terminate_owned_native(1.)
    assert later._startup_native_capture_error == "DiagnosticNativeCollectionHeld"


def test_optional_pin_cleanup_uses_its_retained_adapter_even_if_new_factory_fails(monkeypatch):
    import angerona.core.windows_process_lease as lease
    calls = []
    adapter = SimpleNamespace(object_identity=lambda _p: (1002, 123), wait=lambda *_a: True,
        exit_code=lambda _p: 1, close=lambda _p: calls.append("retained-adapter-close"))
    monkeypatch.setattr(lease, "_Native", lambda: pytest.fail("Cleanup must not acquire a new native adapter"))
    owner = bridge.RedTeamToolOwner(lambda *_args: None)
    owner._native_owner = native_owner(calls)
    row = {"pid": 1002, "birth_ticks": "123", "handle_closed": False}
    owner._startup_native_pins.append((adapter, 99, row))
    assert owner.stop(1.)
    assert row["handle_closed"] and calls[-1] == "close"
    assert calls.count("retained-adapter-close") == 1


def test_owned_stderr_reader_must_retire_before_once_only_pipe_closure():
    calls = []
    class Reader:
        ident = 1
        alive = True
        def join(self, timeout):
            assert 0 <= timeout <= 1.
            calls.append("join-stderr")
        def is_alive(self): return self.alive
    class Stream:
        def __init__(self, label): self.label = label
        def close(self): calls.append("pipe-" + self.label)
    owner = bridge.RedTeamToolOwner(lambda *_args: None)
    owner._native_owner = native_owner(calls)
    owner._process = SimpleNamespace(wait=lambda **_kwargs: 0,
        _handle=SimpleNamespace(Close=lambda: calls.append("popen-handle")),
        stdin=Stream("stdin"), stdout=Stream("stdout"), stderr=Stream("stderr"))
    owner._stderr_reader = Reader()
    assert not owner.stop(1.)
    assert not any(item.startswith("pipe-") for item in calls) and not owner._retired.is_set()
    owner._stderr_reader.alive = False
    assert owner.stop(1.)
    assert [item for item in calls if item.startswith("pipe-")] == ["pipe-stdin", "pipe-stdout", "pipe-stderr"]
    owner.stop(1.)
    assert calls.count("terminate") == calls.count("close") == calls.count("popen-handle") == 1


def test_retained_member_view_is_detached_unknown_is_not_empty_and_never_renews_a_proof(monkeypatch):
    from angerona.core import windows_child_job as jobs
    owner = jobs.OwnedWindowsChild.__new__(jobs.OwnedWindowsChild)
    monkeypatch.setattr(jobs, "time", SimpleNamespace(monotonic=lambda: pytest.fail("Snapshot queried a clock")))
    assert owner.tree_retirement_members_snapshot()["members"] is None
    opaque_handle = object()
    owner._tree_retirement = SimpleNamespace(ready=True, processes=[(opaque_handle, (1002, 123))],
        deadline=0.1, failure="")
    value = owner.tree_retirement_members_snapshot()
    assert value["advisory_only"] and value["recorded_wait_deadline"] == 0.1
    assert value["members"] == ({"pid": 1002, "birth_ticks": "123"},)
    assert opaque_handle not in value.values()
    value["members"][0]["pid"] = 999
    assert owner.tree_retirement_members_snapshot()["members"][0]["pid"] == 1002
    assert owner.tree_retirement_members_snapshot()["recorded_wait_deadline"] == 0.1
