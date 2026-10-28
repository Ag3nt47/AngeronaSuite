"""Authenticated automatic-start admission without a UI, core, or host action."""
from __future__ import annotations

import io
import threading
from types import SimpleNamespace

import pytest

from angerona import startup
from angerona.core import privilege
from angerona.resilience import shutdown_token as token


@pytest.fixture(autouse=True)
def isolated_startup(monkeypatch, tmp_path):
    for name in (
        "ANGERONA_SUPERVISED_RECOVERY", "ANGERONA_STARTUP_SUPERVISED",
        "ANGERONA_OLLAMA_MODELS", "OLLAMA_MODELS",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(startup, "canonical_storage", lambda: tmp_path / "errors")
    monkeypatch.setattr(privilege, "_minimal_environment", lambda _source: {})

    def forbidden(*_args, **_kwargs):
        pytest.fail("Automatic-start tests must not start a real process or UI")

    monkeypatch.setattr(startup.subprocess, "Popen", forbidden)
    monkeypatch.setattr(startup, "ReadyListener", forbidden)
    monkeypatch.setattr(startup, "_interface_lease", forbidden)
    monkeypatch.setattr(startup, "_configure_tk_environment", forbidden)
    monkeypatch.setattr(startup, "_startup_window", forbidden)


def plan_for(tmp_path, *, frozen=False):
    return startup.LaunchPlan(
        tmp_path, tmp_path / "storage",
        (str(tmp_path / ("Angerona.exe" if frozen else "python.exe")),), frozen,
    )


def signed_stop(storage):
    """Create only the case's own authority and authenticated command fixture."""
    (storage / "ipc").mkdir(parents=True, exist_ok=True)
    key = bytes(range(32))
    (storage / "shutdown.key").write_text(key.hex(), encoding="ascii")
    token.request_operator_stop(key=key, path=storage / "ipc" / "standdown.cmd")
    return storage / "ipc" / "standdown.cmd"


def inert_startup(monkeypatch, tmp_path):
    plan = plan_for(tmp_path)
    calls = []
    records = []
    launches = []
    monkeypatch.setattr(startup, "platform_plan", lambda: plan)
    monkeypatch.setattr(startup, "prepare_storage", lambda _root: None)
    monkeypatch.setattr(startup, "_assert_no_pending_repair", lambda _plan: None)
    monkeypatch.setattr(startup, "select_temporary", lambda *_args, **_kwargs: tmp_path / "scratch")
    monkeypatch.setattr(startup, "process_identity", lambda *_args: {})
    monkeypatch.setattr(startup, "_log_file", lambda *_args: io.BytesIO())
    monkeypatch.setattr(startup, "StartupDiagnostics", lambda _root: SimpleNamespace(
        record=lambda *args, **kwargs: records.append((args, kwargs)),
    ))
    monkeypatch.setattr(startup, "StartupLease", lambda _root: SimpleNamespace(
        close=lambda: calls.append("lease-close"),
    ))
    monkeypatch.setattr(startup, "probe_source", lambda *_args: calls.append("preflight"))
    monkeypatch.setattr(startup, "ReadyListener", lambda: SimpleNamespace(
        endpoint="12345:" + "a" * 64, close=lambda: calls.append("listener-close"),
    ))
    process = SimpleNamespace(pid=424242, poll=lambda: None)

    def launch(command, **kwargs):
        calls.append("launch")
        launches.append((command, kwargs))
        return process

    monkeypatch.setattr(startup.subprocess, "Popen", launch)
    monkeypatch.setattr(startup, "wait_dashboard", lambda *_args: process.pid)
    return SimpleNamespace(plan=plan, calls=calls, records=records, launches=launches)


@pytest.mark.parametrize("trigger", ["flag", "environment"])
@pytest.mark.parametrize("supervised,expected", [(False, 0), (True, 86)])
def test_authenticated_stop_exits_before_tk_preflight_or_processes(
    tmp_path, monkeypatch, capsys, trigger, supervised, expected,
):
    plan = plan_for(tmp_path)
    command = signed_stop(plan.storage)
    original = command.read_bytes()
    monkeypatch.setattr(startup, "platform_plan", lambda: plan)
    monkeypatch.setattr(startup, "run_startup", lambda *_args, **_kwargs: pytest.fail("preflight ran"))
    monkeypatch.setattr(startup, "_record_startup_failure", lambda *_args, **_kwargs: pytest.fail("STOP is not an error"))
    arguments = ["angerona.startup"]
    if trigger == "flag":
        arguments.append("--automatic-start")
    else:
        monkeypatch.setenv("ANGERONA_SUPERVISED_RECOVERY", "1")
    if supervised:
        monkeypatch.setenv("ANGERONA_STARTUP_SUPERVISED", "1")
    monkeypatch.setattr(startup.sys, "argv", arguments)

    assert startup.main() == expected
    assert "Authenticated STOP" in capsys.readouterr().out
    assert command.read_bytes() == original
    assert not (plan.storage / "logs").exists()


@pytest.mark.parametrize("value", [None, "", "0", "true", "1 ", " 1", "1"])
@pytest.mark.parametrize("frozen", [False, True])
def test_only_exact_inhibition_value_crosses_dashboard_environment(
    tmp_path, monkeypatch, value, frozen,
):
    if value is not None:
        monkeypatch.setenv("ANGERONA_SUPERVISED_RECOVERY", value)
    environment = startup.child_environment(plan_for(tmp_path, frozen=frozen))
    assert environment.get("ANGERONA_SUPERVISED_RECOVERY") == ("1" if value == "1" else None)
    assert environment["PYINSTALLER_RESET_ENVIRONMENT"] == "1"


def test_missing_stop_read_is_side_effect_free(tmp_path):
    storage = tmp_path / "absent-storage"
    assert token.standdown_active_for_storage(storage) is False
    assert not storage.exists()


def test_unsigned_stop_cannot_block_or_create_authority(tmp_path):
    storage = tmp_path / "storage"
    command = signed_stop(storage)
    original = command.read_bytes()
    command.write_bytes(original.replace(b"operator-stop", b"operator-st0p"))
    before = {path.name: path.read_bytes() for path in (command, storage / "shutdown.key")}
    assert token.standdown_active_for_storage(storage) is False
    assert {path.name: path.read_bytes() for path in (command, storage / "shutdown.key")} == before


def test_automatic_stop_authority_error_holds_without_ui_or_probes(tmp_path, monkeypatch):
    monkeypatch.setattr(startup, "platform_plan", lambda: plan_for(tmp_path))
    monkeypatch.setattr(startup.sys, "argv", ["angerona.startup", "--automatic-start"])
    monkeypatch.setattr(token, "standdown_active_for_storage", lambda _root: (_ for _ in ()).throw(RuntimeError("fixture authority unavailable")))
    failures = []
    monkeypatch.setattr(startup, "_record_startup_failure", lambda *args, **kwargs: failures.append((args, kwargs)))
    monkeypatch.setattr(startup, "run_startup", lambda *_args, **_kwargs: pytest.fail("preflight ran"))
    assert startup.main() == 85
    assert len(failures) == 1
    assert failures[0][0][1] == "automatic-stop-admission"


@pytest.mark.parametrize("automatic", [False, True])
def test_check_only_never_clears_stop_or_launches(tmp_path, monkeypatch, automatic):
    state = inert_startup(monkeypatch, tmp_path)
    command = signed_stop(state.plan.storage)
    original = command.read_bytes()
    monkeypatch.setattr(token, "clear_standdown_for_storage", lambda _root: pytest.fail("check-only cleared STOP"))
    if automatic:
        monkeypatch.setenv("ANGERONA_SUPERVISED_RECOVERY", "1")
    assert startup.run_startup(lambda _text: None, threading.Event(), check_only=True) == state.plan.storage
    assert state.calls == ["preflight", "lease-close"]
    assert state.launches == []
    assert command.read_bytes() == original


def test_explicit_resume_occurs_once_after_preflight_and_core_remains_inhibited(
    tmp_path, monkeypatch,
):
    state = inert_startup(monkeypatch, tmp_path)

    def clear(storage):
        assert storage == state.plan.storage
        state.calls.append("clear-stop")

    monkeypatch.setattr(token, "clear_standdown_for_storage", clear)
    assert startup.run_startup(lambda _text: None, threading.Event()) == state.plan.storage
    assert state.calls == ["preflight", "clear-stop", "launch", "listener-close", "lease-close"]
    assert len(state.launches) == 1
    assert state.launches[0][1]["env"]["ANGERONA_SUPERVISED_RECOVERY"] == "1"


def test_failed_preflight_preserves_stop_and_never_launches(tmp_path, monkeypatch):
    state = inert_startup(monkeypatch, tmp_path)
    command = signed_stop(state.plan.storage)
    original = command.read_bytes()
    monkeypatch.setattr(token, "clear_standdown_for_storage", lambda _root: pytest.fail("failed preflight cleared STOP"))
    monkeypatch.setattr(startup, "probe_source", lambda *_args: (_ for _ in ()).throw(startup.StartupError("fixture preflight failed")))
    with pytest.raises(startup.StartupError, match="fixture preflight failed"):
        startup.run_startup(lambda _text: None, threading.Event())
    assert state.calls == ["lease-close"]
    assert state.launches == []
    assert command.read_bytes() == original


def test_stop_arriving_during_automatic_preflight_prevents_core_launch(tmp_path, monkeypatch):
    state = inert_startup(monkeypatch, tmp_path)
    monkeypatch.setenv("ANGERONA_SUPERVISED_RECOVERY", "1")
    monkeypatch.setattr(token, "clear_standdown_for_storage", lambda _root: pytest.fail("automatic startup cleared STOP"))
    monkeypatch.setattr(startup, "probe_source", lambda *_args: signed_stop(state.plan.storage))
    with pytest.raises(startup.OperatorStopped, match="automatic startup remains stopped"):
        startup.run_startup(lambda _text: None, threading.Event())
    assert state.launches == []
    assert token.standdown_active_for_storage(state.plan.storage)
    assert state.calls == ["lease-close"]


def test_stop_during_readiness_is_operator_outcome_and_preserves_command(tmp_path, monkeypatch):
    state = inert_startup(monkeypatch, tmp_path)
    monkeypatch.setattr(token, "clear_standdown_for_storage", lambda _root: None)

    def stopped(*_args):
        signed_stop(state.plan.storage)
        raise startup.StartupError("dashboard exited before readiness")

    monkeypatch.setattr(startup, "wait_dashboard", stopped)
    with pytest.raises(startup.OperatorStopped, match="no retry will reopen"):
        startup.run_startup(lambda _text: None, threading.Event())
    assert len(state.launches) == 1
    assert state.calls == ["preflight", "launch", "listener-close", "lease-close"]
    assert token.standdown_active_for_storage(state.plan.storage)
    assert not any(args[:2] == ("dashboard", "readiness-verified") for args, _ in state.records)


@pytest.mark.parametrize("supervised,expected", [(False, 0), (True, 86)])
def test_nonwindow_operator_stop_is_quiet_and_never_an_error(tmp_path, monkeypatch, supervised, expected):
    monkeypatch.setattr(startup.sys, "argv", ["angerona.startup", "--no-startup-window"])
    if supervised:
        monkeypatch.setenv("ANGERONA_STARTUP_SUPERVISED", "1")
    monkeypatch.setattr(startup, "run_startup", lambda *_args, **_kwargs: (_ for _ in ()).throw(startup.OperatorStopped("fixture STOP")))
    monkeypatch.setattr(startup, "_record_startup_failure", lambda *_args, **_kwargs: pytest.fail("STOP classified as failure"))
    assert startup.main() == expected
