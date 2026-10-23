"""Inert runner-failure controls, independent of module-autouse PS preflight.

Only the existing pure-Python owner fixture is re-exported. Importing its module
does not re-export confinement_preflight or launch PowerShell.
"""
from __future__ import annotations

import io
import json
import subprocess
import tempfile
from types import SimpleNamespace

import pytest

import test_release_upgrade_preservation as release


pytestmark = release.pytestmark  # Same Windows-only path/native-fixture contract.
inert_owned_ps5 = release.inert_owned_ps5


def _timeout_owner(control, monkeypatch):
    primary = subprocess.TimeoutExpired(control.command, 45)

    def wait(timeout):
        control.state.calls.append(("wait", timeout))
        if timeout == 45:
            raise primary
        assert timeout == 10
        control.process.returncode = 1  # Deliberately after parent cleanup.
        return 1

    monkeypatch.setattr(control.process, "wait", wait)
    return primary


def _inert_output(control, monkeypatch, stdout, stderr):
    owned_popen = subprocess.Popen

    def popen(*args, **kwargs):
        kwargs["stdout"].write(stdout)
        kwargs["stderr"].write(stderr)
        return owned_popen(*args, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", popen)


def _note(primary, capsys):
    return "\n".join(getattr(primary, "__notes__", ())) + capsys.readouterr().err


def test_timeout_retains_bounded_outputs_stage_and_exact_retirement_without_replacing_primary(
    tmp_path, monkeypatch, inert_owned_ps5, capsys,
):
    control = inert_owned_ps5
    primary = _timeout_owner(control, monkeypatch)
    stdout = b"x" * (release._FAILURE_STREAM_BYTES * 4) + b"stdout-tail"
    stderr = (b"y" * (release._FAILURE_STREAM_BYTES * 4)
              + b"\nANGERONA_FIXTURE_STAGE=confinement-probe-2-start\ncontrolled-ps5-error\n"
              + b"ANGERONA_FIXTURE_CLOCK=confinement-probe-2-start|12|134372000000000000\n")
    _inert_output(control, monkeypatch, stdout, stderr)
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        release._run_owned_ps5(control.command, {}, tmp_path, control.fixture, control.digest)
    assert caught.value is primary and primary.timeout == 45
    proof = json.loads((control.fixture / "native-retirement.json").read_text())
    assert proof["failure_phase"] == "native_execution_wait"
    assert proof["admission_completed"] is True
    assert proof["native_execution_wait_seconds"] >= 0
    assert proof["owned_termination_requested"] is True
    assert proof["retirement_proven"] and proof["wait_status"] == 0
    assert proof["native_exit"] == 1 and proof["popen_exit"] == 1
    assert proof["closed_handles"] == {"process": True, "stdio": True}
    assert control.process._handle.closed
    assert ("wait", 45) in control.state.calls and ("wait", 10) in control.state.calls
    assert control.state.calls.index("kill") < control.state.calls.index(("wait", 10))
    assert not any(owner is control.process for owner in release._PENDING_OWNED_CHILDREN)
    for name, raw in (("stdout", stdout), ("stderr", stderr)):
        captured = proof["failure_capture"][name]
        assert captured["state"] == "captured" and captured["truncated"] is True
        assert captured["observed_total_bytes"] == len(raw)
        assert captured["retained_bytes"] == release._FAILURE_STREAM_BYTES
        assert captured["text"].encode("utf-8") == raw[-release._FAILURE_STREAM_BYTES:]
    assert proof["failure_capture"]["stderr"]["last_advisory_stage"] == "confinement-probe-2-start"
    note = _note(primary, capsys)
    assert "controlled-ps5-error" in note and "original_timeout_cause" in note
    assert "parent_clock" in note and "stability" in note
    assert "utc_filetime_100ns" in note
    assert proof["failure_capture"]["stderr"]["retained_clocks"]["last_retained"]["elapsed_ms"] == 12
    assert proof["parent_clock"]["wall_samples_available"] is True
    assert proof["parent_clock"]["stability"].startswith("UNPROVED")
    assert (control.fixture / "native-retirement.json").stat().st_size <= 64 * 1024


@pytest.mark.parametrize("broken", ["stdout", "stderr"])
def test_timeout_capture_read_failure_preserves_primary_and_closes_both_stream_owners(
    tmp_path, monkeypatch, inert_owned_ps5, broken, capsys,
):
    control = inert_owned_ps5
    primary = _timeout_owner(control, monkeypatch)
    original_temporary_file = tempfile.TemporaryFile
    streams, close_calls = [], []

    class Stream:
        def __init__(self, name, actual):
            self.name, self.actual = name, actual

        def seek(self, *args):
            return self.actual.seek(*args)

        def tell(self):
            return self.actual.tell()

        def write(self, raw):
            return self.actual.write(raw)

        def read(self, size=-1):
            assert 0 <= size <= release._FAILURE_STREAM_BYTES + 1
            if self.name == broken:
                raise OSError("inert capture read refused")
            return self.actual.read(size)

        def close(self):
            close_calls.append(self.name)
            self.actual.close()

    def temporary_file(*, dir):
        stream = Stream("stdout" if not streams else "stderr",
                        original_temporary_file(dir=dir))
        streams.append(stream)
        return stream

    monkeypatch.setattr(tempfile, "TemporaryFile", temporary_file)
    _inert_output(control, monkeypatch, b"stdout-diagnostic", b"stderr-diagnostic")
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        release._run_owned_ps5(control.command, {}, tmp_path, control.fixture, control.digest)
    assert caught.value is primary
    proof = json.loads((control.fixture / "native-retirement.json").read_text())
    assert proof["failure_capture"][broken]["state"] == "unavailable"
    assert "inert capture read refused" in proof["failure_capture"][broken]["read_error"]
    other = "stderr" if broken == "stdout" else "stdout"
    assert proof["failure_capture"][other]["state"] == "captured"
    assert close_calls == ["stdout", "stderr"] and all(stream.actual.closed for stream in streams)
    assert proof["closed_handles"] == {"process": True, "stdio": True}
    assert proof["retirement_proven"] and control.process._handle.closed
    assert "inert capture read refused" in _note(primary, capsys)


def test_timeout_receipt_and_handle_close_faults_keep_primary_and_owned_pending_state(
    tmp_path, monkeypatch, inert_owned_ps5, capsys,
):
    control = inert_owned_ps5
    primary = _timeout_owner(control, monkeypatch)
    receipt_error = OSError("inert failure receipt unavailable")
    control.state.close_error = OSError("inert owned handle close unavailable")
    _inert_output(control, monkeypatch, b"stdout-retained", b"stderr-retained")

    def refuse_receipt(_fixture, _proof):
        raise receipt_error

    monkeypatch.setattr(release, "_write_native_retirement", refuse_receipt)
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        release._run_owned_ps5(control.command, {}, tmp_path, control.fixture, control.digest)
    assert caught.value is primary and primary.angerona_receipt_error is receipt_error
    proof = primary.angerona_owned_child
    assert proof["retirement_proven"] is True and proof["handle_closed"] == "UNPROVED"
    assert proof["stdio_closed"] is True
    assert proof["owner_retained"] is True and not control.process._handle.closed
    assert any(owner is control.process for owner in release._PENDING_OWNED_CHILDREN)
    assert proof["failure_capture"]["stdout"]["text"] == "stdout-retained"
    assert proof["failure_capture"]["stderr"]["text"] == "stderr-retained"
    assert "inert failure receipt unavailable" in _note(primary, capsys)
    assert not (control.fixture / "native-retirement.json").exists()

def test_clock_tail_preserves_gaps_and_regressions_and_rejects_nonfinite_fields():
    raw = (
        b"ANGERONA_FIXTURE_CLOCK=harness-entry|0|134372000000000000\n"
        + b"x" * release._FAILURE_STREAM_BYTES
        + b"\nANGERONA_FIXTURE_CLOCK=confinement-result-write|100|134372000000001000\n"
        + b"ANGERONA_FIXTURE_CLOCK=confinement-done|90|134372000000000900\n"
        + b"ANGERONA_FIXTURE_CLOCK=bad-nan|NaN|134372000000000900\n"
        + b"ANGERONA_FIXTURE_CLOCK=bad-inf|90|Infinity\n"
    )
    captured = release._capture_failure_stream(io.BytesIO(raw))
    clocks = captured["retained_clocks"]
    assert captured["truncated"] is True
    assert captured["retained_bytes"] == release._FAILURE_STREAM_BYTES
    assert clocks["parsed_retained_samples"] == 2
    assert clocks["malformed_retained_samples"] == 2
    assert clocks["first_retained"]["stage"] == "confinement-result-write"
    assert clocks["last_retained"] == {
        "stage": "confinement-done", "elapsed_ms": 90,
        "utc_filetime_100ns": 134372000000000900,
    }
    assert clocks["retained_elapsed_nondecreasing"] is False
    assert clocks["retained_wall_nondecreasing"] is False
    assert "gaps unproved" in clocks["history"]
    assert "no clock stability or process-exit proof" in clocks["authority"]
    json.dumps(captured, allow_nan=False)


@pytest.mark.parametrize("fault", ["raise", "nonfinite", "oversized"])
def test_unavailable_parent_wall_clock_cannot_replace_timeout_or_cleanup(
    tmp_path, monkeypatch, inert_owned_ps5, capsys, fault,
):
    control = inert_owned_ps5
    primary = _timeout_owner(control, monkeypatch)

    def clock_fault():
        if fault == "raise":
            raise OSError("controlled diagnostic wall-clock read failure")
        if fault == "oversized":
            return 10 ** 1000
        return float("nan")

    monkeypatch.setattr(release, "time", SimpleNamespace(
        monotonic=release.time.monotonic, time_ns=clock_fault,
    ))
    _inert_output(control, monkeypatch, b"stdout-clock-fault", b"stderr-clock-fault")
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        release._run_owned_ps5(control.command, {}, tmp_path, control.fixture, control.digest)
    assert caught.value is primary and primary.timeout == 45
    proof = json.loads((control.fixture / "native-retirement.json").read_text())
    parent = proof["parent_clock"]
    assert parent["run_start"] is None and parent["wait_start"] is None
    assert parent["wait_finished_before_cleanup"] is None
    assert parent["wall_samples_available"] is False
    assert parent["wall_minus_monotonic_seconds"] is None
    assert parent["stability"].startswith("UNPROVED")
    assert proof["retirement_proven"] and control.process._handle.closed
    assert proof["closed_handles"] == {"process": True, "stdio": True}
    assert proof["failure_capture"]["stderr"]["text"] == "stderr-clock-fault"
    assert "parent_clock" in _note(primary, capsys)
    json.dumps(proof, allow_nan=False)
