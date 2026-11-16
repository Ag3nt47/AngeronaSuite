"""Canonical helper intent crosses to singleton admission without resuming a new STOP."""
from __future__ import annotations

from contextlib import nullcontext
import dataclasses
import io
import json
import threading
from types import SimpleNamespace

import pytest

import angerona.__main__ as entry
from angerona import startup
from angerona.resilience import source_stop as stop
from test_source_stop_protocol import source as source, _context


@pytest.fixture(autouse=True)
def isolate_launch_references(monkeypatch):
    for name in (stop.SOURCE_SESSION_ENV, stop.SOURCE_LAUNCH_ENV):
        monkeypatch.setenv(name, "")
        monkeypatch.delenv(name)


@pytest.fixture
def bridge(source, monkeypatch):
    from angerona.core import data_paths, privilege
    from angerona.resilience import shutdown_token

    storage, root, identity, identity_state = source
    state = SimpleNamespace(source=source, cores=[], environments=[], events=[], on_probe=lambda: None)
    plan = startup.LaunchPlan(root, storage, (str(root / "python.exe"),), False)
    for name in (stop.SOURCE_SESSION_ENV, stop.SOURCE_LAUNCH_ENV, "ANGERONA_SUPERVISED_RECOVERY"):
        monkeypatch.setenv(name, "")
        monkeypatch.delenv(name)
    for name in ("ANGERONA_STARTUP_SCRATCH_LEASE_HANDLE", "ANGERONA_OLLAMA_MODELS", "OLLAMA_MODELS"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(startup, "platform_plan", lambda: plan)
    monkeypatch.setattr(startup, "_check_installed_startup_request", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(startup, "prepare_storage", lambda *_args, **_kwargs: state.events.append("storage"))
    monkeypatch.setattr(startup, "_assert_no_pending_repair", lambda _plan: None)
    monkeypatch.setattr(startup, "select_temporary", lambda *_args, **_kwargs: storage)
    monkeypatch.setattr(startup, "StartupDiagnostics", lambda _root: SimpleNamespace(record=lambda *_a, **_k: True))
    class Lease:
        def __init__(self, _root):
            state.events.append("lease")
        def close(self):
            state.events.append("lease-close")
    monkeypatch.setattr(startup, "StartupLease", Lease)
    monkeypatch.setattr(startup, "_activation_launch_descriptor", lambda _plan: None)
    monkeypatch.setattr(startup, "_export_activation_ready", lambda *_args: False)
    monkeypatch.setattr(privilege, "_minimal_environment", lambda _source: {})
    monkeypatch.setattr(data_paths, "data_dir", lambda: storage)
    monkeypatch.setattr(startup, "_log_file", lambda *_args: nullcontext(io.BytesIO()))
    monkeypatch.setattr(startup, "process_identity", lambda process=None: {"pid": getattr(process, "pid", identity.pid)})
    monkeypatch.setattr(startup, "ReadyListener", lambda: SimpleNamespace(endpoint="inert-ready-reference", close=lambda: None))
    monkeypatch.setattr(startup, "wait_dashboard", lambda _l, process, *_args: process.pid)
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Ordinary canonical source startup crossed into admin STOP authority")
    monkeypatch.setattr(shutdown_token, "standdown_active_for_storage", forbidden)
    monkeypatch.setattr(shutdown_token, "clear_standdown_for_storage", forbidden)
    def probe(_plan, environment, _cancel):
        state.events.append("probe")
        assert stop.SOURCE_LAUNCH_ENV not in environment, "Intent belongs only to the final Core child"
        state.on_probe()
    monkeypatch.setattr(startup, "probe_source", probe)
    def launch(_command, **options):
        state.events.append("child")
        state.environments.append(dict(options["env"]))
        core_identity = dataclasses.replace(identity, pid=identity.pid + 1, birth=identity.birth + 1)
        prior = identity_state["identity"]
        try:
            identity_state["identity"] = core_identity
            with monkeypatch.context() as child:
                for name in (stop.SOURCE_SESSION_ENV, stop.SOURCE_LAUNCH_ENV, "ANGERONA_SUPERVISED_RECOVERY"):
                    child.setenv(name, "")  # Record absence before main() writes its epoch directly.
                    child.delenv(name, raising=False)
                    if name in options["env"]:
                        child.setenv(name, options["env"][name])
                state.events.append("singleton-acquired")
                context = entry._source_stop_session_after_lock(object(), ordinary_source=True)
                assert context is not None and context.respawn_allowed()
                state.cores.append(context)
        finally:
            identity_state["identity"] = prior
        return SimpleNamespace(pid=core_identity.pid)
    monkeypatch.setattr(startup.subprocess, "Popen", launch)
    state.plan = plan
    return state


def test_real_canonical_helper_supervised_child_reaches_singleton_source_admission(bridge):
    assert startup.run_startup(lambda _report: None, threading.Event()) == bridge.plan.storage
    context, = bridge.cores
    environment, = bridge.environments
    assert environment["ANGERONA_SUPERVISED_RECOVERY"] == "1"
    assert stop.SOURCE_LAUNCH_ENV in environment and stop.SOURCE_SESSION_ENV not in environment
    assert context.epoch
    assert bridge.events.index("probe") < bridge.events.index("singleton-acquired")
    assert bridge.events[-1] == "lease-close"


@pytest.mark.parametrize("automatic", [False, True])
def test_new_stop_during_canonical_preflight_blocks_child_without_epoch_rotation(bridge, monkeypatch, automatic):
    old = _context(bridge.source)
    if automatic:
        monkeypatch.setenv("ANGERONA_SUPERVISED_RECOVERY", "1")
    bridge.on_probe = old.request_stop
    with pytest.raises(startup.OperatorStopped, match="changed during preflight"):
        startup.run_startup(lambda _report: None, threading.Event())
    assert old.is_stop_requested() and bridge.cores == [] and bridge.environments == []
    joined = stop.join_source_session(bridge.plan.storage)
    assert joined is not None and joined.epoch == old.epoch


def test_automatic_old_stop_is_held_before_dependency_probe(bridge, monkeypatch):
    old = _context(bridge.source)
    old.request_stop()
    monkeypatch.setenv("ANGERONA_SUPERVISED_RECOVERY", "1")
    with pytest.raises(startup.OperatorStopped, match="automatic startup remains stopped"):
        startup.run_startup(lambda _report: None, threading.Event())
    assert bridge.events == [] and bridge.cores == [] and old.is_stop_requested()


def test_explicit_helper_may_resume_unchanged_stop_present_before_preflight(bridge):
    old = _context(bridge.source)
    old.request_stop()
    assert startup.run_startup(lambda _report: None, threading.Event()) == bridge.plan.storage
    fresh, = bridge.cores
    assert fresh.epoch != old.epoch and old.is_stop_requested()


def test_automatic_helper_recovers_active_epoch_but_does_not_override_inherited_epoch(bridge, monkeypatch):
    old = _context(bridge.source)
    monkeypatch.setenv("ANGERONA_SUPERVISED_RECOVERY", "1")
    monkeypatch.setenv(stop.SOURCE_SESSION_ENV, old.epoch)
    assert startup.run_startup(lambda _report: None, threading.Event()) == bridge.plan.storage
    recovered, = bridge.cores
    environment, = bridge.environments
    assert recovered.epoch == old.epoch and not old.is_stop_requested()
    assert environment[stop.SOURCE_SESSION_ENV] == old.epoch
    assert stop.SOURCE_LAUNCH_ENV not in environment


def test_automatic_canonical_intent_recovers_active_source_without_inherited_epoch(bridge, monkeypatch):
    old = _context(bridge.source)
    monkeypatch.setenv("ANGERONA_SUPERVISED_RECOVERY", "1")
    assert startup.run_startup(lambda _report: None, threading.Event()) == bridge.plan.storage
    fresh, = bridge.cores
    assert fresh.epoch != old.epoch and old.is_stop_requested()
    intent = json.loads(bridge.environments[0][stop.SOURCE_LAUNCH_ENV])
    assert intent["automatic"] is True and intent["stop"] == ""


def test_first_ever_snapshot_can_precede_creation_of_storage_root(source):
    storage = source[0] / "not-created-yet"
    raw = stop.capture_source_launch_intent(storage)
    assert raw is not None and not storage.exists()
    storage.mkdir()
    context = stop.activate_source_launch_intent(storage, raw)
    assert context is not None and context.respawn_allowed()


def test_new_stop_after_helper_dispatch_is_rechecked_by_singleton_core(source, monkeypatch):
    old = _context(source)
    raw = stop.capture_source_launch_intent(source[0])
    old.request_stop()
    monkeypatch.setenv(stop.SOURCE_LAUNCH_ENV, raw)
    monkeypatch.setenv("ANGERONA_SUPERVISED_RECOVERY", "1")
    from angerona.core import data_paths
    monkeypatch.setattr(data_paths, "data_dir", lambda: source[0])
    with pytest.raises(entry._SourceStopStartupHeld):
        entry._source_stop_session_after_lock(object(), ordinary_source=True)
    assert old.is_stop_requested()


def test_stop_during_creation_reclamation_is_rechecked_before_superseding_epoch(source, monkeypatch):
    old = _context(source)
    raw = stop.capture_source_launch_intent(source[0])
    actual_reclaim = stop._reclaim_closed
    def stop_after_reclaim(*args, **kwargs):
        actual_reclaim(*args, **kwargs)
        old.request_stop()
    monkeypatch.setattr(stop, "_reclaim_closed", stop_after_reclaim)
    assert stop.activate_source_launch_intent(source[0], raw) is None
    assert old.is_stop_requested()
    assert stop.join_source_session(source[0]).epoch == old.epoch


def test_second_instance_cannot_consume_intent_or_rotate_epoch(source, monkeypatch):
    old = _context(source)
    raw = stop.capture_source_launch_intent(source[0])
    monkeypatch.setenv(stop.SOURCE_LAUNCH_ENV, raw)
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Second instance consumed source intent")
    monkeypatch.setattr(stop, "activate_source_launch_intent", forbidden)
    assert entry._source_stop_session_after_lock(None, ordinary_source=True) is None
    assert stop.join_source_session(source[0]).epoch == old.epoch


@pytest.mark.parametrize("change", ["extra", "boolean-schema", "nonbool-mode", "wrong-scope", "bad-hash", "duplicate"])
def test_bogus_or_open_schema_intents_never_create_authority(source, change):
    raw = stop.capture_source_launch_intent(source[0])
    value = json.loads(raw)
    if change == "extra":
        value["grant"] = "admin"
    elif change == "boolean-schema":
        value["schema"] = True
    elif change == "nonbool-mode":
        value["automatic"] = 0
    elif change == "wrong-scope":
        value["session"] += 1
    elif change == "bad-hash":
        value["latest"] = "invalid"
    if change == "duplicate":
        raw = raw[:-1] + ',"schema":1}'
    else:
        raw = json.dumps(value)
    assert stop.activate_source_launch_intent(source[0], raw) is None
    assert list(source[0].iterdir()) == []


def test_privileged_or_unknown_probe_has_no_source_snapshot_io(source, monkeypatch):
    monkeypatch.setattr(stop, "_effective_identity", lambda: None)
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Unadmitted launch touched source authority")
    monkeypatch.setattr(stop, "_launch_scope", forbidden)
    assert stop.capture_source_launch_intent(source[0]) is None
    assert not stop.source_launch_intent_current(source[0], "{}")
    assert stop.activate_source_launch_intent(source[0], "{}") is None


def test_packaged_plan_never_reads_source_launch_authority(source, monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Packaged helper consulted source authority")
    monkeypatch.setattr(stop, "source_runtime_admitted", forbidden)
    plan = startup.LaunchPlan(source[1], source[0], ("inert.exe",), True)
    assert startup._source_startup_bridge(plan) == {}


def test_watchdog_child_sanitizer_does_not_forward_canonical_intent(source, monkeypatch):
    from angerona.core import privilege
    monkeypatch.setattr(privilege, "_minimal_environment", lambda _source: {})
    raw = stop.capture_source_launch_intent(source[0])
    assert stop.SOURCE_LAUNCH_ENV not in privilege.sanitized_child_environment(
        source={stop.SOURCE_LAUNCH_ENV: raw})
