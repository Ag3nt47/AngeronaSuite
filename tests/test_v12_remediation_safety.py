from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from angerona.modules import remediation_actions as actions


class _AccessDenied(Exception):
    pass


class _NoSuchProcess(Exception):
    pass


class _Process:
    def __init__(
        self,
        pid: int = 4242,
        *,
        created: float = 100.0,
        name: str = "malware.exe",
        exe: str = r"C:\Temp\malware.exe",
        identity_error: Exception | None = None,
    ) -> None:
        self.pid = pid
        self.created = created
        self.process_name = name
        self.process_exe = exe
        self.identity_error = identity_error
        self.killed = False
        self.suspended = False

    def create_time(self) -> float:
        if self.identity_error:
            raise self.identity_error
        return self.created

    def name(self) -> str:
        if self.identity_error:
            raise self.identity_error
        return self.process_name

    def exe(self) -> str:
        if self.identity_error:
            raise self.identity_error
        return self.process_exe

    def kill(self) -> None:
        self.killed = True

    def suspend(self) -> None:
        self.suspended = True

    def resume(self) -> None:
        self.suspended = False

    def status(self) -> str:
        return "stopped" if self.suspended else "running"


def _weakness() -> dict:
    return {
        "pid": 4242,
        "process_create_time": 100.0,
        "process_name": "malware.exe",
        "exe": r"C:\Temp\malware.exe",
        "name": "active ransomware",
    }


def _psutil(process_factory):
    return SimpleNamespace(
        Process=process_factory,
        AccessDenied=_AccessDenied,
        NoSuchProcess=_NoSuchProcess,
    )


def test_process_actions_refuse_pid_reuse_before_mutation(monkeypatch, tmp_path: Path) -> None:
    reused = _Process(created=200.0, name="unrelated.exe", exe=r"C:\Good\unrelated.exe")
    monkeypatch.setattr(actions, "_psutil", _psutil(lambda pid: reused))

    kill = actions.KillProcessAction().apply(_weakness(), tmp_path)
    suspend = actions.SuspendProcessAction().apply(_weakness(), tmp_path)

    assert kill["ok"] is False
    assert suspend["ok"] is False
    assert reused.killed is False
    assert reused.suspended is False


def test_kill_verify_distinguishes_access_denied_from_target_exit(monkeypatch) -> None:
    denied = _Process(identity_error=_AccessDenied())
    monkeypatch.setattr(actions, "_psutil", _psutil(lambda pid: denied))
    record = {"ok": True, **_weakness(), "create_time": 100.0, "name": "malware.exe"}

    assert actions.KillProcessAction().verify({}, record) is False

    def missing(pid):
        raise _NoSuchProcess(pid)

    monkeypatch.setattr(actions, "_psutil", _psutil(missing))
    assert actions.KillProcessAction().verify({}, record) is True


def test_driver_action_rejects_untyped_service_name_without_mutation(monkeypatch, tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def run(command, **kwargs):
        del kwargs
        calls.append(command)
        raise AssertionError("an untyped driver name must never reach service control")

    monkeypatch.setattr(actions, "run_hidden", run)
    action = actions.DisableDriverServiceAction()
    record = action.apply({"driver": "bad.sys"}, tmp_path)

    assert record["ok"] is False
    assert record["changed"] is False
    assert "authenticated exact-target" in record["error"]
    assert action.matches({"driver": "bad.sys"}) is False
    assert calls == []


def test_network_isolation_partial_apply_fails_and_rolls_back(monkeypatch, tmp_path: Path) -> None:
    calls: list[list[str]] = []
    add_codes = iter([0, 5])

    def run(command, **kwargs):
        del kwargs
        calls.append(command)
        if "show" in command:
            return SimpleNamespace(returncode=1, stdout="No rules match", stderr="")
        if "add" in command:
            return SimpleNamespace(returncode=next(add_codes), stdout="", stderr="denied")
        return SimpleNamespace(returncode=0, stdout="deleted", stderr="")

    monkeypatch.setattr(actions, "run_hidden", run)
    action = actions.NetworkIsolationAction()
    record = action.apply({"remote_ip": "8.8.8.8"}, tmp_path)

    assert record["ok"] is False
    assert action.verify({}, record) is False
    rollback = action.rollback(record)
    assert rollback["ok"] is True
    deleted = [command for command in calls if "delete" in command]
    assert len(deleted) == 2


def test_base_verifier_and_acl_action_fail_closed() -> None:
    assert actions.RemediationAction().verify({}, {}) is False
    assert not any(isinstance(action, actions.LockdownAclAction) for action in actions.ACTIONS)
