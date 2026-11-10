"""Injected CLI/process/job fixtures only: no messages, inboxes or native launch."""
from __future__ import annotations

import io
import subprocess
import threading
from types import SimpleNamespace

import pytest

from angerona.core import mobile_cli_custody as custody
from angerona.modules import mobile_bridge as mobile


@pytest.fixture
def fake_cli(monkeypatch):
    monkeypatch.setattr(custody, "_ACTIVE", {})
    monkeypatch.setattr(custody, "_CALLS", {})
    monkeypatch.setattr(custody, "_HOLDS", {})
    monkeypatch.setattr(custody, "_STOP", threading.Event())
    monkeypatch.setattr(custody, "_LAUNCH", threading.Lock())
    state = dict(events=[], failure="", output=b"inert-version\n", process=None, job=None, argv=None, kwargs=None)

    class Handle(int):
        def Close(self):
            state["events"].append("process-close")

    class Stream:
        def __init__(self):
            self.raw = io.BytesIO(state["output"])
        def read(self, size):
            if state["failure"] == "reader-io":
                raise OSError("inert read error")
            return self.raw.read(size)
        def close(self):
            state["events"].append("pipe-close")
            if state["failure"] == "pipe-close":
                raise OSError("inert close uncertainty")
            self.raw.close()

    class Process:
        def __init__(self, argv, **kwargs):
            state.update(process=self, argv=argv, kwargs=kwargs)
            state["events"].append("spawn-suspended")
            self.pid, self._handle = 4242, Handle(123)
            self.stdout, self.returncode, self.terminated = Stream(), None, False
        def wait(self, timeout=None):
            if state["failure"] == "process-wait":
                raise subprocess.TimeoutExpired("inert", timeout)
            if state["failure"] == "eof-without-exit" and not self.terminated:
                raise subprocess.TimeoutExpired("inert", timeout)
            self.returncode = 0
            return 0
        def kill(self):
            self.terminated = True
            state["events"].append("root-kill")

    class Job:
        def __init__(self):
            self._handle = Handle(987)
            state["job"] = self
            state["events"].append("job-create")
        def assign(self, handle):
            assert handle == 123
            state["events"].append("assign")
            if state["failure"] == "assign":
                raise OSError("inert assign refusal")
        def wait_empty(self, timeout):
            state["events"].append("empty")
        def close(self):
            state["events"].append("job-close")

    class Child:
        def __init__(self, handle, pid, job):
            assert handle == 123 and pid == 4242 and job is state["job"]
            self.proven = self.closed = False
        def prepare_tree_retirement(self, timeout):
            state["events"].append("prepare")
            if state["failure"] == "prepare":
                raise OSError("inert query failure")
        def terminate(self):
            state["process"].terminated = True
            state["events"].append("terminate-tree")
        def wait_tree(self, timeout):
            state["events"].append("signals")
            if state["failure"] == "signals":
                raise OSError("inert signal timeout")
            self.proven = True
        def tree_retirement_snapshot(self):
            return {"signals_proven": self.proven, "handles_closed": self.closed}
        def close(self):
            state["events"].append("native-close")
            if state["failure"] == "native-close":
                raise OSError("inert native close uncertainty")
            self.closed = True

    monkeypatch.setattr(custody.subprocess, "Popen", Process)
    monkeypatch.setattr(custody, "WindowsChildJob", Job)
    monkeypatch.setattr(custody, "OwnedWindowsChild", Child)
    from angerona.resilience import _selftest_environment as environment
    monkeypatch.setattr(environment, "_resume_windows_process", lambda _p: state["events"].append("resume"))
    return state


def invoke():
    return custody.run_signal_cli([r"C:\fixture\signal-cli.exe", "--version"], {},
                                  cwd=r"C:\fixture", timeout=1.0, max_output=1024)


def test_completion_requires_assignment_resume_exact_tree_signals_and_close(fake_cli):
    assert invoke() == ("complete", 0, b"inert-version\n")
    events = fake_cli["events"]
    assert events == ["job-create", "spawn-suspended", "assign", "resume", "prepare", "terminate-tree",
                      "signals", "pipe-close", "native-close"]
    if hasattr(subprocess, "CREATE_NO_WINDOW"):
        assert fake_cli["kwargs"]["creationflags"] & subprocess.CREATE_NO_WINDOW
    assert fake_cli["kwargs"]["creationflags"] & getattr(subprocess, "CREATE_SUSPENDED", 0x00000004)
    assert fake_cli["kwargs"]["close_fds"] is True
    assert custody.signal_cli_custody_snapshot()["active_invocations"] == 0
    assert custody.signal_cli_custody_snapshot()["held_resources"] == 0


@pytest.mark.parametrize("failure, external", [("prepare", True), ("process-wait", True),
                                              ("signals", True), ("pipe-close", False), ("native-close", False)])
def test_ambiguous_retirement_preserves_owner_and_fences_future_launch_without_retry(fake_cli, failure, external):
    fake_cli["failure"] = failure
    result = invoke()
    assert result[0] == "retirement-held" and result[1] == -1
    snapshot = custody.signal_cli_custody_snapshot()
    assert snapshot["capability_held"] is True and snapshot["active_invocations"] == 0
    assert snapshot["pending_external_trees"] == int(external)
    owner, kind, _external = next(iter(custody._HOLDS.values()))
    assert kind == "invocation" and owner.process is fake_cli["process"]
    assert owner.original_job_handle == 987 and owner.original_process_handle == 123
    before = list(fake_cli["events"])
    assert not owner.retire()
    assert invoke() == ("custody-held", -1, b"")
    assert fake_cli["events"] == before
    custody.request_signal_stop()
    assert custody.signal_cli_custody_snapshot()["launch_quiescent"] is True


def test_assignment_failure_never_resumes_and_retires_only_exact_suspended_process(fake_cli):
    fake_cli["failure"] = "assign"
    state, code, _output = invoke()
    assert state == "execution-error" and code == -1
    assert "resume" not in fake_cli["events"] and "root-kill" in fake_cli["events"]
    assert fake_cli["events"][-3:] == ["pipe-close", "job-close", "process-close"]
    assert not custody.signal_cli_custody_snapshot()["capability_held"]


def test_unknown_reader_exit_retains_thread_and_every_native_resource(fake_cli):
    owner = custody._Invocation(1.0, 1024)
    owner.start([r"C:\fixture\signal-cli.exe", "--version"], {}, r"C:\fixture")
    joined = []
    reader = SimpleNamespace(join=lambda timeout: joined.append(timeout), is_alive=lambda: True)
    owner.reader = reader
    assert owner.retire() is False
    assert owner.reader is reader and owner.process is fake_cli["process"]
    assert "pipe-close" not in fake_cli["events"] and "native-close" not in fake_cli["events"]
    assert custody.signal_cli_custody_snapshot()["pending_external_trees"] == 1
    before = list(fake_cli["events"])
    assert not owner.retire() and fake_cli["events"] == before and joined == [2.0]


def test_stop_during_resumption_cancels_read_and_retires_exact_tree(fake_cli, monkeypatch):
    from angerona.resilience import _selftest_environment as environment
    monkeypatch.setattr(environment, "_resume_windows_process", lambda _p: custody.request_signal_stop())
    assert invoke()[0] == "cancelled"
    snapshot = custody.signal_cli_custody_snapshot()
    assert snapshot["launch_quiescent"] is True and snapshot["pending_external_trees"] == 0
    assert snapshot["held_resources"] == 0 and "signals" in fake_cli["events"]


@pytest.mark.parametrize("failure, expected", [("eof-without-exit", "timeout"), ("reader-io", "io-error")])
def test_pipe_eof_or_io_failure_is_not_success_without_proven_root_exit(fake_cli, failure, expected):
    fake_cli["failure"] = failure
    assert invoke()[0] == expected
    assert "signals" in fake_cli["events"]
    assert custody.signal_cli_custody_snapshot()["held_resources"] == 0


def test_bounded_output_and_stopped_admission_never_spawn_again(fake_cli):
    fake_cli["output"] = b"x" * 2048
    state, _code, output = invoke()
    assert state == "overflow" and len(output) == 1024
    custody.request_signal_stop()
    before = list(fake_cli["events"])
    assert invoke() == ("custody-held", -1, b"")
    assert fake_cli["events"] == before
    assert custody.resume_signal_admission()


@pytest.mark.parametrize("result", [False, "raises"])
def test_failed_executable_close_retains_exact_pin_and_is_never_retried(fake_cli, monkeypatch, result):
    calls = []
    class Close:
        def __call__(self, handle):
            calls.append(handle)
            if result == "raises":
                raise OSError("inert native close uncertainty")
            return False
    close = Close()
    monkeypatch.setattr(mobile.ctypes, "WinDLL", lambda *_a, **_k: SimpleNamespace(CloseHandle=close))
    sealed = mobile._SealedCli(mobile._CliIdentity("fixture.exe", "a" * 64, "fixture", (1, 2, 3, 4)), 789)
    with pytest.raises(OSError):
        sealed.close()
    with pytest.raises(OSError, match="remains unverified"):
        sealed.close()
    assert calls == [789] and sealed.handle == 789
    snapshot = custody.signal_cli_custody_snapshot()
    assert snapshot["capability_held"] and snapshot["pending_external_trees"] == 0


def test_invocation_result_cannot_be_verified_before_its_pin_closes(fake_cli, monkeypatch):
    bridge = mobile.MobileResponseBridge()
    sealed = SimpleNamespace(identity=SimpleNamespace(sha256="a" * 64),
                             close=lambda: (_ for _ in ()).throw(OSError("inert pin close failure")))
    monkeypatch.setattr(bridge, "_acquire_cli", lambda _cfg: sealed)
    monkeypatch.setattr(bridge, "_launch_cli", lambda *_a: ("complete", 0, b"inert-version"))
    monkeypatch.setattr(bridge, "_seal_still_valid", lambda _seal: True)
    result = bridge._invoke_cli("self-test", ["--version"], timeout=1)
    assert result.verified is False and result.receipt.state == "close-held"
    assert not bridge._result_valid(result, "self-test")
    assert bridge._cli_failures["self-test"]


def test_shutdown_error_is_closed_sanitized_schema(fake_cli):
    error = custody.SignalCliRetirementIncomplete({"active_invocations": True, "pending_external_trees": 1,
                                                  "launch_quiescent": False, "secret": "must not escape"})
    assert error.outcome["active_invocations"] is None
    assert error.outcome["pending_external_trees"] == 1
    assert "secret" not in error.outcome and "must not escape" not in str(error)


def test_full_invocation_preflight_lease_is_visible_until_final_pin_close(fake_cli):
    lease = custody.begin_signal_call()
    assert custody.signal_cli_custody_snapshot()["active_invocations"] == 1
    custody.request_signal_stop()
    snapshot = custody.signal_cli_custody_snapshot()
    assert snapshot["active_invocations"] == 1 and snapshot["pending_external_trees"] == 0
    assert snapshot["launch_quiescent"] is False
    with pytest.raises(OSError, match="stopped"):
        custody.begin_signal_call()
    custody.end_signal_call(lease)
    assert custody.signal_cli_custody_snapshot()["launch_quiescent"] is True
    with pytest.raises(ValueError, match="original owner"):
        custody.end_signal_call(lease)


def test_executable_preflight_runs_inside_registered_full_call_and_cannot_launch_after_stop(fake_cli, monkeypatch):
    bridge = mobile.MobileResponseBridge()
    observed = []
    def acquire(_cfg):
        observed.append(custody.signal_cli_custody_snapshot()["active_invocations"])
        custody.request_signal_stop()
        raise PermissionError("inert preflight cancelled")
    monkeypatch.setattr(bridge, "_acquire_cli", acquire)
    result = bridge._invoke_cli("self-test", ["--version"], timeout=1)
    assert observed == [1] and result.verified is False
    assert custody.signal_cli_custody_snapshot()["launch_quiescent"] is True
    assert fake_cli["events"] == []


def test_authenticode_helper_has_owned_output_deadline_and_exact_environment_path(fake_cli, monkeypatch):
    from pathlib import Path
    from angerona.core import privilege
    executable = Path(r"C:\fixture\powershell.exe")
    monkeypatch.setattr(mobile.sys, "platform", "win32")
    monkeypatch.setattr(privilege, "trusted_powershell_path", lambda: executable)
    monkeypatch.setattr(privilege, "trusted_windows_directories", lambda: (Path(r"C:\Windows"), Path(r"C:\Windows\System32")))
    monkeypatch.setattr(Path, "is_file", lambda _self: True)
    captured = []
    def owned(argv, environment, **options):
        captured.append((argv, environment, options))
        return "complete", 0, b'{"status":"Valid","publisher":"CN=Inert Fixture"}'
    monkeypatch.setattr(mobile, "run_signal_cli", owned)
    target = Path(r"C:\fixture\quoted' & target.exe")
    assert mobile._authenticode_publisher(target) == ("Valid", "CN=Inert Fixture")
    argv, environment, options = captured[0]
    assert argv[0] == str(executable) and str(target) not in argv[-1]
    assert environment["ANGERONA_SIGNAL_CLI_PATH"] == str(target)
    assert options["timeout"] == 15 and options["max_output"] == 4096
