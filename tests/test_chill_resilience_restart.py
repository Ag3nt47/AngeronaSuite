"""Automatic restart commands retain Chill intent during sensor escalation."""
from __future__ import annotations

from types import SimpleNamespace
import threading

import pytest


@pytest.mark.parametrize("quiet,blocked,expected_chill", [
    (False, True, True),  # CHILL:ALERT retains the operator AI lock
    (True, False, True),  # legacy quiet-only startup intent
    (False, False, True),  # automatic recovery also defaults safely from Full
])
def test_recovery_command_preserves_chill_during_alert(monkeypatch, quiet, blocked, expected_chill):
    from angerona.resilience import manager as resilience

    class Supervisor:
        def __init__(self, **_kwargs):
            pass

        def add(self, *_args, **_kwargs):
            pass

        def start(self):
            pass

        def stop(self, **_kwargs):
            pass

    monkeypatch.setattr(resilience, "ProcessSupervisor", Supervisor)
    monkeypatch.setattr(resilience.hb, "HeartbeatWriter", lambda _name:
                        SimpleNamespace(beat=lambda: None, close=lambda: None))
    monkeypatch.setattr(resilience.ipc_ring, "RingReader", lambda _path:
                        SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(resilience.ipc_ring, "ring_path", lambda _name: "inert-unused-ring")
    monkeypatch.setattr(resilience, "_blackbox_script", lambda: None)
    monkeypatch.setenv("ANGERONA_CORE_CMD", "stale pre-Chill command")
    monkeypatch.setenv("ANGERONA_PY", resilience.sys.executable)
    monkeypatch.setenv("ANGERONA_SCANNER_UI", "0")
    if quiet:
        monkeypatch.setenv("ANGERONA_CHILL_ACTIVE", "1")
    if blocked:
        monkeypatch.setenv("ANGERONA_CHILL_AI_BLOCKED", "1")
    runtime = resilience.ResilienceManager(None, start_watchdog=False, with_ui=False)
    monkeypatch.setattr(runtime, "_spawn_thread", lambda *_args: None)
    try:
        runtime.start()
        command = resilience.os.environ["ANGERONA_CORE_CMD"]
        assert (" --chill" in command) is expected_chill
        assert command.endswith("-m angerona --chill" if expected_chill else "-m angerona")
        assert command != "stale pre-Chill command"
    finally:
        runtime.stop()


@pytest.mark.parametrize("stored_chill,missing_launcher", [(False, False), (True, False), (False, True)])
def test_existing_watchdog_forces_chill_for_stored_full_and_fallback_commands(
    monkeypatch, stored_chill, missing_launcher,
):
    from pathlib import Path
    from angerona.resilience import watchdog

    instances = []

    class Supervisor:
        def __init__(self, **_kwargs):
            self.components = {}
            instances.append(self)

        def add(self, name, argv, **_kwargs):
            self.components[name] = list(argv)

        def start(self):
            pass

        def stop(self, **_kwargs):
            pass

    launcher = (str(Path(watchdog.sys.executable).parent / "inert-missing" / "python.exe")
                if missing_launcher else watchdog.sys.executable)
    command = f'"{launcher}" -m angerona' + (" --chill" if stored_chill else "")
    monkeypatch.setenv("ANGERONA_CORE_CMD", command)
    monkeypatch.setenv("ANGERONA_PY", watchdog.sys.executable)
    monkeypatch.setattr(watchdog, "ProcessSupervisor", Supervisor)
    monkeypatch.setattr(watchdog.hb, "HeartbeatWriter", lambda _name:
                        SimpleNamespace(beat=lambda: None, close=lambda: None))
    monkeypatch.setattr(watchdog, "_blackbox_script", lambda: None)
    monkeypatch.setattr(watchdog, "_standdown_requested", lambda: True)
    monkeypatch.setattr(watchdog.diag, "write_status", lambda *_args: None)
    monkeypatch.setattr(watchdog.signal, "signal", lambda *_args: None)
    assert watchdog.main([]) == 0
    command = instances[0].components["core"]
    assert command[0] == watchdog.sys.executable
    assert command[1:3] == ["-m", "angerona"]
    assert command.count("--chill") == 1


@pytest.mark.parametrize("flag", ["--engine-serve", "--engine-service", "--engine-console"])
@pytest.mark.parametrize("forced", [False, True])
def test_combined_engine_cli_routes_runtime_chill_intent(monkeypatch, flag, forced):
    from angerona import __main__ as entry
    from angerona.core import privilege

    calls = []
    monkeypatch.setattr(entry.sys, "argv", ["angerona", flag] + (["--chill"] if forced else []))
    monkeypatch.setattr(entry.sys, "frozen", False, raising=False)
    monkeypatch.setattr(privilege, "is_admin", lambda: False)
    monkeypatch.setattr(entry, "_run_engine_mode", lambda mode, **kwargs:
                        calls.append((mode, kwargs)) or 23)
    assert entry.main() == 23
    assert calls == [(flag, {"force_chill": True} if forced else {})]


@pytest.mark.parametrize("forced", [False, True])
def test_headless_launch_override_precedes_every_worker_without_saving_preferences(monkeypatch, forced):
    from angerona.core import headless

    saved = []
    config = SimpleNamespace(eco_mode=False, db_path="unused", save=lambda: saved.append(True))
    monkeypatch.setattr(headless.Config, "load", lambda: config)
    observed = []

    class StopBeforeWorkers(Exception):
        pass

    def first_service(_path):
        from angerona.core.chill_mode import chill_ai_blocked
        observed.append(config.eco_mode)
        assert chill_ai_blocked(config) is forced
        raise StopBeforeWorkers

    monkeypatch.setattr(headless, "FlightRecorder", first_service)
    with pytest.raises(StopBeforeWorkers):
        headless.run_headless(force_chill=forced)
    assert observed == [forced]
    assert saved == []


@pytest.mark.parametrize("frozen", [False, True])
def test_detached_launch_argv_propagates_force_without_changing_default(monkeypatch, frozen):
    from angerona.core import persistent_engine

    monkeypatch.setattr(persistent_engine.sys, "frozen", frozen, raising=False)
    default = persistent_engine.engine_command()
    forced = persistent_engine.engine_command(force_chill=True)
    assert "--chill" not in default
    assert forced == default + ["--chill"]


def test_engine_serve_cli_passes_chill_to_headless_route(monkeypatch):
    from angerona.core import persistent_engine

    calls = []
    monkeypatch.setattr(persistent_engine, "serve", lambda **kwargs: calls.append(kwargs) or 17)
    assert persistent_engine.main(["serve", "--chill"]) == 17
    assert calls == [{}]


@pytest.mark.parametrize("flag,module_name,method_name", [
    ("--engine-serve", "angerona.core.persistent_engine", "serve"),
    ("--engine-service", "angerona.core.engine_windows_service", "run_dispatcher"),
])
def test_actual_engine_entry_dispatch_preserves_force(monkeypatch, flag, module_name, method_name):
    import importlib
    from angerona import __main__ as entry

    calls = []
    target = importlib.import_module(module_name)
    monkeypatch.setattr(target, method_name, lambda **kwargs: calls.append(kwargs) or 19)
    assert entry._run_engine_mode(flag, force_chill=True) == 19
    assert calls == [{}]  # service entries impose Chill intrinsically


@pytest.mark.parametrize("forced", [False, True])
def test_actual_headless_cli_dispatch_preserves_runtime_force(monkeypatch, forced):
    from angerona import __main__ as entry
    from angerona.core import data_paths, hardening, headless, privilege, singleton, win, crashlog

    calls = []
    closed = []
    monkeypatch.setattr(entry.sys, "argv", ["angerona", "--headless"] + (["--chill"] if forced else []))
    monkeypatch.setattr(entry.sys, "frozen", False, raising=False)
    monkeypatch.setattr(privilege, "is_admin", lambda: False)
    monkeypatch.setattr(data_paths, "configure_runtime_environment", lambda: None)
    monkeypatch.setattr(win, "install_no_window_default", lambda: None)
    monkeypatch.setattr(crashlog, "install", lambda: None)
    monkeypatch.setattr(hardening, "apply_process_mitigations", lambda: None)
    monkeypatch.setattr(singleton, "acquire_single_instance", lambda:
                        SimpleNamespace(close=lambda: closed.append(True)))
    monkeypatch.setattr(headless, "run_headless", lambda **kwargs: calls.append(kwargs) or 29)
    assert entry.main() == 29
    assert calls == [{"force_chill": True} if forced else {}]
    assert closed == [True]


def test_scm_dispatch_closure_carries_force_to_headless_worker(monkeypatch):
    import sys
    from angerona.core import engine_windows_service, data_paths, singleton, headless

    calls, closed = [], []

    class ServiceBase:
        def __init__(self, _args):
            pass

    hosted = []
    monkeypatch.setattr(engine_windows_service, "require_package_service", lambda: None)
    monkeypatch.setitem(sys.modules, "win32serviceutil", SimpleNamespace(ServiceFramework=ServiceBase))
    monkeypatch.setitem(sys.modules, "win32service", SimpleNamespace(SERVICE_STOP_PENDING=1))
    monkeypatch.setitem(sys.modules, "servicemanager", SimpleNamespace(
        Initialize=lambda: None, PrepareToHostSingle=hosted.append,
        StartServiceCtrlDispatcher=lambda: hosted[0]([]).SvcDoRun(),
    ))
    monkeypatch.setattr(data_paths, "configure_runtime_environment", lambda: None)
    monkeypatch.setattr(singleton, "acquire_single_instance", lambda:
                        SimpleNamespace(close=lambda: closed.append(True)))
    monkeypatch.setattr(headless, "run_headless", lambda **kwargs: calls.append(kwargs))
    assert engine_windows_service.run_dispatcher() == 0
    assert calls[0]["force_chill"] is True
    assert isinstance(calls[0]["stop_event"], threading.Event)
    assert closed == [True]


def test_unflagged_detached_service_always_passes_chill_to_headless(monkeypatch):
    from angerona.core import persistent_engine, engine_control, data_paths, singleton, headless, crashlog, hardening

    calls, closed = [], []
    monkeypatch.setattr(persistent_engine, "_require_user", lambda: None)
    monkeypatch.setattr(data_paths, "configure_runtime_environment", lambda: None)
    monkeypatch.setattr(singleton, "acquire_single_instance", lambda:
                        SimpleNamespace(close=lambda: closed.append("lease")))
    monkeypatch.setattr(engine_control, "EngineControl", lambda _stop:
                        SimpleNamespace(close=lambda: closed.append("control"), fail=lambda _reason: None,
                                        dispatch=lambda _request: {}))
    monkeypatch.setattr(persistent_engine, "EngineServer", lambda *_args:
                        SimpleNamespace(instance="fixture", start=lambda: None, close=lambda: closed.append("server")))
    monkeypatch.setattr(crashlog, "install", lambda: None)
    monkeypatch.setattr(hardening, "apply_process_mitigations", lambda: None)
    monkeypatch.setattr(headless, "run_headless", lambda **kwargs: calls.append(kwargs) or 31)
    assert persistent_engine.serve() == 31
    assert calls[0]["force_chill"] is True
    assert isinstance(calls[0]["stop_event"], threading.Event)
    assert closed == ["control", "server", "lease"]


def test_engine_console_connection_worker_preserves_requested_chill(monkeypatch):
    from angerona.gui import engine_console

    calls = []
    marker = object()
    monkeypatch.setattr(engine_console, "ensure_engine", lambda **kwargs:
                        calls.append(kwargs) or marker)
    worker = engine_console.ConsoleWorker(force_chill=True)
    worker._command("connect", None)
    assert worker.client is marker
    assert calls == [{"force_chill": True}]


def test_runtime_chill_admission_latches_before_queued_work_and_rejects_unlock():
    from angerona.core.engine_control import EngineControl
    from angerona.core.engine_transport import EngineError
    from angerona.core.chill_mode import chill_ai_blocked

    control = EngineControl(threading.Event())
    config = SimpleNamespace(eco_mode=False)
    control.config = config
    control.state = "ready"  # Intentionally leave the execution worker stopped.
    with pytest.raises(EngineError, match="schema"):
        control.dispatch({"operation": "enter_chill", "enabled": False})
    assert not chill_ai_blocked(config)
    receipt = control.dispatch({"operation": "enter_chill"})
    assert receipt["state"] == "queued"
    assert chill_ai_blocked(config)
    assert config.eco_mode is False  # The queued transition has not run yet.


def test_forced_console_attach_changes_existing_engine_runtime_without_preference_write(tmp_path, monkeypatch):
    from angerona.core import chill_runtime, persistent_engine
    from angerona.core.chill_mode import set_chill_ai_blocked, chill_ai_blocked
    from angerona.core.engine_control import EngineControl
    from angerona.core.engine_transport import EngineServer
    from angerona.core.eventbus import EventBus

    class Runtime:
        def __init__(self, _manager, _bus, config):
            self.config = config

        def prepare_runtime(self):
            set_chill_ai_blocked(self.config, True)

        def prepare_modules(self):
            return set()

        def start(self, _selected):
            pass

        def stop(self):
            pass

    monkeypatch.setattr(chill_runtime, "ChillRuntimeController", Runtime)
    config_file = tmp_path / "saved-preferences.json"
    config_file.write_text('{"eco_mode": false}', encoding="utf-8")
    config = SimpleNamespace(eco_mode=False, save=lambda: pytest.fail("Runtime override rewrote preferences"))
    control = EngineControl(threading.Event())
    control.attach(SimpleNamespace(modules={}), EventBus(), config, None)
    server = EngineServer(tmp_path / "engine", control.dispatch)
    server.start()
    control.ready()
    client = persistent_engine.EngineClient(server.directory)
    monkeypatch.setattr(persistent_engine, "_require_user", lambda: None)
    monkeypatch.setattr(persistent_engine, "EngineClient", lambda: client)
    monkeypatch.setattr(persistent_engine.subprocess, "Popen", lambda *_a, **_kw:
                        pytest.fail("Existing engine was duplicated"))
    try:
        assert persistent_engine.ensure_engine(force_chill=True, timeout=5) is client
        assert config.eco_mode is True and chill_ai_blocked(config)
        assert control.chill is not None
        assert config_file.read_text(encoding="utf-8") == '{"eco_mode": false}'
    finally:
        control.close()
        server.close()


def test_forced_new_engine_launch_carries_flag_before_authenticated_attach(monkeypatch, tmp_path):
    from angerona.core import persistent_engine
    from angerona.core.engine_transport import EngineError

    started, entered = [], []

    class Client:
        directory = tmp_path

        def status(self):
            if not started:
                raise EngineError("No existing engine")
            return {"state": "ready"}

        def enter_chill(self):
            entered.append(True)
            return {"id": "fixture"}

        def operation_status(self, _identity):
            return {"state": "completed"}

    client = Client()
    monkeypatch.setattr(persistent_engine, "_require_user", lambda: None)
    monkeypatch.setattr(persistent_engine, "EngineClient", lambda: client)
    monkeypatch.setattr(persistent_engine, "private_directory", lambda _path: None)
    monkeypatch.setattr(persistent_engine, "_child_environment", lambda: {})
    monkeypatch.setattr(persistent_engine.subprocess, "Popen", lambda command, **_kwargs:
                        started.append(command) or SimpleNamespace(poll=lambda: None))
    assert persistent_engine.ensure_engine(force_chill=True, timeout=5) is client
    assert len(started) == 1 and started[0][-1] == "--chill"
    assert entered == [True]


def test_earlier_full_cannot_clear_new_chill_but_later_manual_full_can(monkeypatch):
    from angerona.core.engine_control import EngineControl
    from angerona.core.chill_mode import chill_ai_blocked

    control = EngineControl(threading.Event())
    control.config = SimpleNamespace(eco_mode=False, save=lambda: None)
    control.state = "ready"
    # Both requests are authenticated and queued, but the earlier Full action
    # has not executed when the newer Chill intent is accepted.
    earlier = {"operation": "settings_patch", "settings": {"eco_mode": False}}
    control.dispatch(earlier)
    control.dispatch({"operation": "enter_chill"})
    assert chill_ai_blocked(control.config)
    control._execute(earlier)
    assert chill_ai_blocked(control.config)
    assert control._pending_chill_entries == 1
    original = control._set_chill
    monkeypatch.setattr(control, "_set_chill", lambda enabled: None)
    control._execute({"operation": "enter_chill"})
    assert control._pending_chill_entries == 0
    monkeypatch.setattr(control, "_set_chill", original)
    control._execute(earlier)  # a fresh manual Full after the Chill transition
    assert not chill_ai_blocked(control.config)


def test_failed_existing_engine_chill_request_never_spawns_another_engine(monkeypatch):
    from angerona.core import persistent_engine
    from angerona.core.engine_transport import EngineError

    client = SimpleNamespace(status=lambda: {"state": "ready"},
                             enter_chill=lambda: {"id": "fixture"},
                             operation_status=lambda _identity: {"state": "failed"})
    monkeypatch.setattr(persistent_engine, "_require_user", lambda: None)
    monkeypatch.setattr(persistent_engine, "EngineClient", lambda: client)
    monkeypatch.setattr(persistent_engine.subprocess, "Popen", lambda *_a, **_kw:
                        pytest.fail("Failed runtime operation duplicated an existing engine"))
    with pytest.raises(EngineError, match="could not apply"):
        persistent_engine.ensure_engine(force_chill=True, timeout=5)


def test_unflagged_console_attach_preserves_existing_engine_mode(monkeypatch):
    from angerona.core import persistent_engine

    client = SimpleNamespace(status=lambda: {"state": "ready"},
                             enter_chill=lambda: pytest.fail("Unflagged attach changed existing mode"))
    monkeypatch.setattr(persistent_engine, "_require_user", lambda: None)
    monkeypatch.setattr(persistent_engine, "EngineClient", lambda: client)
    monkeypatch.setattr(persistent_engine.subprocess, "Popen", lambda *_a, **_kw:
                        pytest.fail("Existing engine was duplicated"))
    assert persistent_engine.ensure_engine() is client
