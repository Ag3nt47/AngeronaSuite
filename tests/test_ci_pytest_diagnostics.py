"""In-process CI diagnostics checks; pytest and native children are never launched."""
from __future__ import annotations

import json
from pathlib import Path
import shlex
import sys
from types import SimpleNamespace

import pytest
import yaml

from tools import ci_pytest


class _Output:
    def __init__(self, failure=None):
        self.failure = failure
        self.writes = []
        self.flushes = 0

    def write(self, value):
        if self.failure == "write":
            raise OSError("inert private write failure")
        self.writes.append(value)
        return len(value)

    def flush(self):
        self.flushes += 1
        if self.failure == "flush":
            raise ValueError("inert private flush failure")


def _console(monkeypatch, *, opt_in="1", output=None):
    if opt_in is None:
        monkeypatch.delenv("ANGERONA_PYTEST_CONSOLE_DIAGNOSTICS", raising=False)
    else:
        monkeypatch.setenv("ANGERONA_PYTEST_CONSOLE_DIAGNOSTICS", opt_in)
    output = _Output() if output is None else output
    proxy = SimpleNamespace(stdout=output, argv=["ci_pytest", "private argument with spaces"],
                            version=sys.version, path=list(sys.path))
    monkeypatch.setattr(ci_pytest, "sys", proxy)
    return output, proxy


def _rows(output):
    prefix = "CI_PYTEST_STAGE "
    assert all(line.startswith(prefix) for line in output.writes)
    return [json.loads(line[len(prefix):]) for line in output.writes]


def _harness(monkeypatch, *, output=None):
    output, proxy = _console(monkeypatch, output=output)
    state = SimpleNamespace(output=output, proxy=proxy, callbacks=[], journal=[], closed=False)

    def register(callback, *arguments):
        state.callbacks.append((callback, arguments))
        return callback

    def record(kind, **fields):
        state.journal.append({"kind": kind, **fields})

    def finish():
        record("python-atexit-end")
        state.closed = True

    def retire_callbacks():
        while state.callbacks:
            callback, arguments = state.callbacks.pop()
            callback(*arguments)

    monkeypatch.setattr(ci_pytest, "atexit", SimpleNamespace(register=register))
    monkeypatch.setattr(ci_pytest, "_journal", lambda: (record, finish))
    state.register, state.retire_callbacks = register, retire_callbacks
    return state


def test_windows_ci_streams_test_ids_and_opt_in_stages_without_changing_job_policy():
    workflow = yaml.safe_load((Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml").read_text())
    job = workflow["jobs"]["python"]
    assert job["timeout-minutes"] == "${{ (matrix.python-version == '3.10' || matrix.python-version == '3.11') && 75 || 60 }}"
    assert job["strategy"]["fail-fast"] is False
    assert job["strategy"]["matrix"]["python-version"] == ["3.10", "3.11", "3.12", "3.13"]
    steps = [step for step in job["steps"] if "tools.ci_pytest" in step.get("run", "")]
    assert len(steps) == 2
    for step in steps:
        assert step["env"]["ANGERONA_PYTEST_CONSOLE_DIAGNOSTICS"] == "1"
        command = next(line.strip() for line in step["run"].splitlines() if "-m tools.ci_pytest" in line)
        arguments = shlex.split(command)
        assert arguments[:7] == ["python", "-u", "-X", "faulthandler", "-m", "tools.ci_pytest", "-v"]
        assert "-q" not in arguments
    recovery, full = steps
    assert shlex.split(recovery["run"].splitlines()[-2])[-1] == "@recoveryTests"
    assert "-p tools.pytest_execution_trace --durations=25 --durations-min=1.0" in full["run"]
    assert "exit $pytestExit" in full["run"] and "exit $LASTEXITCODE" in recovery["run"]


@pytest.mark.parametrize("opt_in", [None, "", "0", "true", "yes"])
def test_console_diagnostics_require_exact_explicit_opt_in(monkeypatch, opt_in):
    output, _proxy = _console(monkeypatch, opt_in=opt_in)
    ci_pytest._console_diagnostics()("process-start", python="fixture", argument_count=1)
    assert output.writes == [] and output.flushes == 0


def test_console_markers_are_allowlisted_bounded_private_and_immediately_flushed(monkeypatch):
    output, _proxy = _console(monkeypatch)
    record = ci_pytest._console_diagnostics()
    private = "private-argument-message-path-fixture"
    record("process-start", python="v" * 4096 + private, argument_count=1,
           argv=[private], path=private, message=private, environment={"secret": private})
    record("pytest-exception", python="\u2603" * 128, exception_type="\u2603" * 128,
           exit_code_type="\u2603" * 128, exit_code=2 ** 4096)
    record("unknown-" + private, exception_type=private)
    rows = _rows(output)
    assert len(rows) == output.flushes == 2
    assert rows[0]["python"] == "v" * 128 and rows[0]["argument_count"] == 1
    assert all(set(row) <= {"kind", "monotonic", "python", "argument_count", "exit_code",
                            "exit_code_type", "exception_type"} for row in rows)
    assert all(len(line.encode("ascii")) <= 1024 and line.count("\n") == 1 for line in output.writes)
    assert private not in "".join(output.writes)
    assert "exit_code" not in rows[1]


def test_console_captures_output_encoder_and_clock_before_pytest_replaces_them(monkeypatch):
    output, proxy = _console(monkeypatch)
    monkeypatch.setattr(ci_pytest, "time", SimpleNamespace(monotonic=lambda: 12.5))
    record = ci_pytest._console_diagnostics()
    replacement = _Output()
    proxy.stdout = replacement
    monkeypatch.setattr(ci_pytest, "json", SimpleNamespace(dumps=lambda *_a, **_k: 1 / 0))
    monkeypatch.setattr(ci_pytest, "time", SimpleNamespace(monotonic=lambda: 1 / 0))
    record("process-start", argument_count=1)
    assert _rows(output) == [{"kind": "process-start", "monotonic": 12.5, "argument_count": 1}]
    assert output.flushes == 1 and replacement.writes == []


def test_repeated_allowed_markers_cannot_exceed_seven_console_attempts(monkeypatch):
    output, _proxy = _console(monkeypatch)
    record = ci_pytest._console_diagnostics()
    for _index in range(100):
        record("process-start", argument_count=1)
    assert len(_rows(output)) == output.flushes == 7


@pytest.mark.parametrize("failure", ["write", "flush"])
def test_failed_console_attempts_consume_the_same_budget_before_output_recovers(monkeypatch, failure):
    output, _proxy = _console(monkeypatch, output=_Output(failure))
    record = ci_pytest._console_diagnostics()
    for _index in range(3):
        record("process-start")
    writes_before, flushes_before = len(output.writes), output.flushes
    output.failure = None
    for _index in range(100):
        record("pytest-entrypoint-finished")
    assert len(output.writes) - writes_before == output.flushes - flushes_before == 4
    assert [row["kind"] for row in _rows(output)][-4:] == ["pytest-entrypoint-finished"] * 4


@pytest.mark.parametrize("code", [None, 0, 1, 2, 3, 4, 5, "private exit fixture"])
def test_live_stages_preserve_in_process_arguments_and_original_system_exit(monkeypatch, code):
    state = _harness(monkeypatch)
    arguments = state.proxy.argv
    original = SystemExit(code)

    def run_module(name, *, run_name, alter_sys):
        assert (name, run_name, alter_sys) == ("pytest", "__main__", True)
        assert state.proxy.argv is arguments and arguments == ["ci_pytest", "private argument with spaces"]
        assert [row["kind"] for row in _rows(state.output)] == ["process-start"]
        assert state.output.flushes == 1  # Visible before the entrypoint runs.
        raise original

    monkeypatch.setattr(ci_pytest, "runpy", SimpleNamespace(run_module=run_module))
    with pytest.raises(SystemExit) as raised:
        ci_pytest.main()
    assert raised.value is original and raised.value.code == code
    assert [row["kind"] for row in _rows(state.output)] == [
        "process-start", "pytest-system-exit", "pytest-entrypoint-finished",
    ]
    state.retire_callbacks()
    assert [row["kind"] for row in _rows(state.output)] == [row["kind"] for row in state.journal]
    assert state.output.flushes == 5 and state.closed
    assert "private exit fixture" not in "".join(state.output.writes)
    assert "private argument with spaces" not in "".join(state.output.writes)


@pytest.mark.parametrize("failure", ["write", "flush"])
@pytest.mark.parametrize("code", [0, 1])
def test_console_output_failures_cannot_change_pytest_exit_or_journal(monkeypatch, failure, code):
    state = _harness(monkeypatch, output=_Output(failure))
    original = SystemExit(code)

    def run_module(*_args, **_kwargs):
        raise original

    monkeypatch.setattr(ci_pytest, "runpy", SimpleNamespace(run_module=run_module))
    with pytest.raises(SystemExit) as raised:
        ci_pytest.main()
    assert raised.value is original
    state.retire_callbacks()
    assert [row["kind"] for row in state.journal] == [
        "process-start", "pytest-system-exit", "pytest-entrypoint-finished",
        "python-atexit-begin", "python-atexit-end",
    ]
    assert state.closed


def test_unavailable_stdout_cannot_disable_the_independent_exit_journal(monkeypatch):
    state = _harness(monkeypatch)
    state.proxy.stdout = None
    original = SystemExit(1)

    def run_module(*_args, **_kwargs):
        raise original

    monkeypatch.setattr(ci_pytest, "runpy", SimpleNamespace(run_module=run_module))
    with pytest.raises(SystemExit) as raised:
        ci_pytest.main()
    assert raised.value is original
    state.retire_callbacks()
    assert state.output.writes == [] and state.output.flushes == 0
    assert state.closed and state.journal[-1]["kind"] == "python-atexit-end"


@pytest.mark.parametrize("original", [RuntimeError("private exception fixture"), KeyboardInterrupt()])
def test_original_exception_and_cancellation_are_propagated(monkeypatch, original):
    state = _harness(monkeypatch)

    def run_module(*_args, **_kwargs):
        raise original

    monkeypatch.setattr(ci_pytest, "runpy", SimpleNamespace(run_module=run_module))
    with pytest.raises(type(original)) as raised:
        ci_pytest.main()
    assert raised.value is original
    state.retire_callbacks()
    assert _rows(state.output)[1]["exception_type"] == type(original).__name__
    assert "private exception fixture" not in "".join(state.output.writes)


def test_return_and_atexit_markers_bracket_only_callbacks_registered_during_pytest(monkeypatch):
    state = _harness(monkeypatch)
    observed = []

    def before_wrapper():
        assert state.closed
        observed.append(("older", _rows(state.output)[-1]["kind"]))

    def pytest_callback():
        assert not state.closed
        observed.append(("pytest", _rows(state.output)[-1]["kind"]))
        assert state.journal[-1]["kind"] == "python-atexit-begin"

    def run_module(*_args, **_kwargs):
        state.register(pytest_callback)

    state.register(before_wrapper)
    monkeypatch.setattr(ci_pytest, "runpy", SimpleNamespace(run_module=run_module))
    assert ci_pytest.main() is None
    assert _rows(state.output)[1]["kind"] == "pytest-returned"
    assert len(_rows(state.output)) == 3 and state.output.flushes == 3
    state.retire_callbacks()
    assert observed == [("pytest", "python-atexit-begin"), ("older", "python-atexit-end")]
    assert [row["kind"] for row in state.journal].count("python-atexit-end") == 1
    assert len(_rows(state.output)) == state.output.flushes == 5
