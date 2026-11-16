"""Source STOP crosses only its admitted family and preserves native custody.

The protocol fixtures touch only a private tmp_path. Native-model tests execute
the real Job retirement implementation against inert kernel objects; the
separate existing OS tests prove actual Windows signal/Job behavior.
"""
from __future__ import annotations

import os
import sys
import threading
from types import SimpleNamespace

import pytest

from angerona.resilience import manager, scanner, source_stop, supervisor, watchdog
from test_child_job_owned_identities import inert_child_factory as inert_child_factory
from test_ollama_owned_retirement import owned as owned


@pytest.fixture
def source(tmp_path, monkeypatch):
    storage, root = tmp_path / "SourceData", tmp_path / "source"
    storage.mkdir()
    root.mkdir()
    identity = source_stop._Identity("S-1-5-21-11-22-33-1001", 2, 101,
                                     134000000000000001, str(tmp_path / "python.exe"))
    monkeypatch.setattr(source_stop, "_effective_identity", lambda: identity)
    monkeypatch.setattr(source_stop, "_source_root", lambda: root)
    monkeypatch.setattr(supervisor.tok, "is_standdown_requested", lambda: False)
    context = source_stop.create_source_session(storage)
    assert context is not None
    return storage, context


def _component(instance, name="scanner"):
    component = supervisor.Component(name, [sys.executable, "-m", "inert.owned.fixture"])
    instance.components[name] = component
    return component


def _inert_spawn_admission(instance, monkeypatch):
    monkeypatch.setattr(instance, "_is_running", lambda _component: False)
    monkeypatch.setattr(instance, "_authenticated_record", lambda _component: (None, "missing"))
    monkeypatch.setattr(supervisor, "try_claim_spawn", lambda _name: True)
    monkeypatch.setattr(instance, "_release_when_up", lambda _component: None)
    monkeypatch.setattr(instance, "_pop_restart_requests", lambda: {"scanner"})


def test_source_stop_blocks_start_spawn_and_manual_restart(source, monkeypatch):
    _storage, context = source
    instance = supervisor.ProcessSupervisor(source_stop_context=context)
    component = _component(instance)
    _inert_spawn_admission(instance, monkeypatch)
    monkeypatch.setattr(supervisor, "spawn_detached", lambda *_a, **_k: pytest.fail("source STOP spawned"))
    monkeypatch.setattr(instance, "_terminate", lambda _c: pytest.fail("STOP became a manual restart"))
    context.request_stop()
    instance.start()
    assert instance._thread is None
    assert not instance._spawn(component)
    assert instance.tick() == {"scanner": "standdown"}


def test_stop_during_source_launch_guard_prevents_dispatch(source, monkeypatch):
    _storage, context = source
    instance = supervisor.ProcessSupervisor(
        source_stop_context=context, launch_guard=lambda _c: context.request_stop() and True)
    component = _component(instance)
    _inert_spawn_admission(instance, monkeypatch)
    monkeypatch.setattr(supervisor, "spawn_detached", lambda *_a, **_k: pytest.fail("late source dispatch"))
    assert instance._spawn(component) is False
    assert component.restarts == 0


def test_old_source_supervisor_cannot_follow_new_current_epoch(source, monkeypatch):
    storage, old = source
    instance = supervisor.ProcessSupervisor(source_stop_context=old)
    old.request_stop()
    new = source_stop.create_source_session(storage)
    assert new is not None and new.epoch != old.epoch
    assert not new.is_stop_requested()
    assert instance._respawn_blocked()
    assert not supervisor.ProcessSupervisor(source_stop_context=new)._respawn_blocked()
    # Explicit source families and installed/default callers consult separate
    # authority domains. Stale installed STOP cannot veto this fresh source.
    assert not supervisor.ProcessSupervisor()._respawn_blocked()
    monkeypatch.setattr(supervisor.tok, "is_standdown_requested", lambda: True)
    assert not supervisor.ProcessSupervisor(source_stop_context=new)._respawn_blocked()
    assert supervisor.ProcessSupervisor()._respawn_blocked()


def test_source_peers_and_core_never_consult_generic_stop(source, monkeypatch):
    _storage, context = source
    generic_calls = []

    def stale_installed_stop():
        generic_calls.append("generic")
        return True

    monkeypatch.setattr(supervisor.tok, "is_standdown_requested", stale_installed_stop)
    assert not supervisor.ProcessSupervisor(source_stop_context=context)._respawn_blocked()
    assert not watchdog._standdown_requested(context)
    host = scanner.ScannerHost.__new__(scanner.ScannerHost)
    host._source_stop_context = context
    assert not host._standdown_requested()
    owner = manager.ResilienceManager.__new__(manager.ResilienceManager)
    owner._source_stop_context = context
    waits = iter([False, True])
    owner._stop = SimpleNamespace(wait=lambda _seconds: next(waits))
    owner.heartbeat_interval = 0.1
    owner._sup = SimpleNamespace(heartbeat_allowed=lambda: True)
    beats = []
    owner._core_beat = SimpleNamespace(beat=lambda: beats.append("source"))
    owner.stop = lambda: pytest.fail("stale installed STOP reached the source manager")
    owner._heartbeat_loop()
    assert beats == ["source"] and generic_calls == []
    assert watchdog._standdown_requested() is True
    host._source_stop_context = None
    assert host._standdown_requested() is True
    assert supervisor.ProcessSupervisor()._respawn_blocked()
    assert generic_calls == ["generic"] * 3


@pytest.mark.parametrize("supersession", [True, False, None, 1, "true", "missing", "unavailable"])
def test_only_verified_supersession_gracefully_stands_down_old_family(monkeypatch, supersession):
    monkeypatch.setattr(watchdog.diag, "write_status", lambda *_a, **_k: None)
    context = SimpleNamespace(is_stop_requested=lambda: False)
    if supersession != "missing":
        def probe():
            if supersession == "unavailable":
                raise OSError("inert global fence observation unavailable")
            return supersession
        context.is_superseded = probe
    expected = supersession is True
    monkeypatch.setattr(supervisor.tok, "is_standdown_requested",
                        lambda: pytest.fail("source supersession consulted generic STOP"))
    assert watchdog._standdown_requested(context) is expected
    host = scanner.ScannerHost.__new__(scanner.ScannerHost)
    host._source_stop_context = context
    assert host._standdown_requested() is expected
    owner = manager.ResilienceManager.__new__(manager.ResilienceManager)
    owner._source_stop_context = context
    waits = iter([False, True])
    owner._stop = SimpleNamespace(wait=lambda _seconds: next(waits))
    owner.heartbeat_interval = 0.1
    owner._sup = SimpleNamespace(heartbeat_allowed=lambda: True)
    beats, requests = [], []
    owner._core_beat = SimpleNamespace(beat=lambda: beats.append("pulse"))
    owner.request_stop = lambda: requests.append("self-stop")
    owner._heartbeat_loop()
    assert requests == (["self-stop"] if expected else [])
    assert beats == ([] if expected else ["pulse"])


def test_corrupt_captured_session_holds_respawn_without_forging_stop(source):
    storage, context = source
    instance = supervisor.ProcessSupervisor(source_stop_context=context)
    context._command_path().with_name("session.json").write_bytes(b"corrupt")
    assert not context.is_stop_requested()
    assert instance._respawn_blocked()


def test_same_supervisor_instance_cannot_reopen_stop(monkeypatch):
    instance = supervisor.ProcessSupervisor()
    monkeypatch.setattr(supervisor.tok, "is_standdown_requested", lambda: False)
    instance.request_stop()
    instance.start()
    assert instance._thread is None and instance._respawn_blocked()


def test_pre_dispatch_source_refusal_is_not_unknown_native_ownership(source, monkeypatch):
    _storage, context = source
    instance = supervisor.ProcessSupervisor(source_stop_context=context)
    component = _component(instance)
    _inert_spawn_admission(instance, monkeypatch)

    def refused(*_args, **_kwargs):
        context.request_stop()
        raise supervisor._PeerLaunchHeld("local gate refused before native dispatch")

    monkeypatch.setattr(supervisor, "spawn_detached", refused)
    assert not instance._spawn(component)
    assert not component._admission_committed and not component._admission_uncertain
    assert instance.stop()


def test_epoch_is_forwarded_after_environment_sanitization_only(source, monkeypatch):
    _storage, context = source
    from angerona.core import privilege

    launches = []
    # The private sanitizer result is the complete starting environment. Any
    # untrusted source epoch in the supplied parent block must be discarded.
    monkeypatch.setattr(privilege, "sanitized_child_environment", lambda **_k: {"PRIVATE": "yes"})
    monkeypatch.setattr(supervisor, "_isolated_peer_argv", lambda argv: list(argv))
    if os.name == "nt":
        from angerona.core import windows_child_job

        monkeypatch.setattr(windows_child_job, "launch_windows_child",
                            lambda argv, env, **_k: launches.append((argv, env)) or object())
    else:
        monkeypatch.setattr(supervisor.subprocess, "Popen",
                            lambda argv, **kwargs: launches.append((argv, kwargs["env"])) or object())
    supplied = {source_stop.SOURCE_SESSION_ENV: "f" * 32, "SECRET": "never-forward"}
    supervisor.spawn_detached(["inert-fixture"], env=supplied)
    assert launches[-1][1] == {"PRIVATE": "yes"}
    supervisor.spawn_detached(["inert-fixture"], env=supplied, source_stop_context=context)
    assert launches[-1][1] == {"PRIVATE": "yes", source_stop.SOURCE_SESSION_ENV: context.epoch}
    context.request_stop()
    with pytest.raises(RuntimeError, match="requested STOP"):
        supervisor.spawn_detached(["inert-fixture"], source_stop_context=context)
    with pytest.raises(ValueError, match="validated"):
        supervisor.spawn_detached(["inert-fixture"], source_stop_context=SimpleNamespace(epoch=context.epoch))
    assert len(launches) == 2


def test_source_adoption_checks_only_epoch_after_invocation_identity(source, monkeypatch):
    _storage, context = source
    epoch = {"value": "f" * 32}
    process = SimpleNamespace(
        pid=1234, info={"cmdline": ["inert-runtime", "-m", "inert.module"]},
        cmdline=lambda: ["inert-runtime", "-m", "inert.module"],
        exe=lambda: "inert-runtime", create_time=lambda: 100.0,
        is_running=lambda: True, status=lambda: "running",
        environ=lambda: {source_stop.SOURCE_SESSION_ENV: epoch["value"], "SECRET": "unretained"})
    table = SimpleNamespace(process_iter=lambda _fields: [process])
    probe = supervisor.cached_cmdline_probe(
        expected_argv=["inert-runtime", "-m", "inert.module"],
        psutil_module=table, source_stop_context=context)
    assert probe() is False and probe.retained_identity() is None
    epoch["value"] = context.epoch
    assert probe() is True
    assert set(probe.retained_identity()) == {"pid", "birth", "image", "parent"}
    process.environ = lambda: pytest.fail("exact already-adopted generation reread whole environment")
    assert probe() is True


def test_heartbeat_from_other_source_epoch_cannot_become_target(source, monkeypatch):
    _storage, context = source
    import psutil

    argv = [sys.executable, "-m", "angerona.resilience.scanner"]
    component = supervisor.Component("scanner", argv, _source_stop_context=context)
    process = SimpleNamespace(pid=202, cmdline=lambda: argv, exe=lambda: sys.executable,
                              create_time=lambda: 990.0, is_running=lambda: True,
                              environ=lambda: {source_stop.SOURCE_SESSION_ENV: "f" * 32})
    monkeypatch.setattr(psutil, "Process", lambda _pid: process)
    with pytest.raises(ValueError, match="configured role"):
        supervisor._heartbeat_process_identity(component, {"pid": 202, "ts_ns": 1000 * 10**9})


@pytest.mark.parametrize("peer", [watchdog, scanner])
def test_source_peer_exits_before_status_or_gui_admission(source, monkeypatch, peer):
    storage, context = source
    context.request_stop()
    monkeypatch.setenv(source_stop.SOURCE_SESSION_ENV, context.epoch)
    monkeypatch.setattr(peer.hb, "_data_dir", lambda: storage)
    monkeypatch.setattr(peer.hb, "HeartbeatWriter", lambda *_a, **_k: pytest.fail("stopped peer initialized"))
    monkeypatch.setattr(scanner, "ScannerHost", lambda *_a, **_k: pytest.fail("stopped scanner initialized"))
    assert peer.main([]) == 0


@pytest.mark.parametrize("peer", [watchdog, scanner])
def test_invalid_explicit_reference_never_retargets_current_source(source, monkeypatch, peer):
    storage, context = source
    unknown = "0" * 32 if context.epoch != "0" * 32 else "1" * 32
    monkeypatch.setenv(source_stop.SOURCE_SESSION_ENV, unknown)
    monkeypatch.setattr(peer.hb, "_data_dir", lambda: storage)
    monkeypatch.setattr(peer.hb, "HeartbeatWriter", lambda *_a, **_k: pytest.fail("invalid peer initialized"))
    monkeypatch.setattr(scanner, "ScannerHost", lambda *_a, **_k: pytest.fail("invalid scanner initialized"))
    assert peer.main([]) == 2


def test_scanner_source_stop_preserves_generic_protected_stop(source, monkeypatch):
    _storage, context = source
    host = scanner.ScannerHost.__new__(scanner.ScannerHost)
    host._source_stop_context = context
    assert not host._standdown_requested()
    context.request_stop()
    assert host._standdown_requested()
    host._source_stop_context = None
    monkeypatch.setattr(scanner.tok, "is_standdown_requested", lambda: True)
    assert host._standdown_requested()


@pytest.mark.skipif(os.name != "nt", reason="Inert Windows Job API model")
def test_late_spawn_is_retired_and_unrelated_python_is_untouched(source, monkeypatch, owned):
    _storage, context = source
    instance = supervisor.ProcessSupervisor(source_stop_context=context)
    component = _component(instance)
    sample = owned.make(register=False)
    unrelated = owned.make((8001, 8002), register=False)
    _inert_spawn_admission(instance, monkeypatch)

    def late_spawn(*_a, **kwargs):
        assert kwargs["source_stop_context"] is context
        context.request_stop()
        return sample.owner

    monkeypatch.setattr(supervisor, "spawn_detached", late_spawn)
    assert instance._spawn(component) is False
    assert sample.model.termination_calls == [1]
    assert sample.owner._process is None
    assert unrelated.model.termination_calls == []
    assert unrelated.owner._process is unrelated.root and not unrelated.root.closed
    unrelated.owner.prepare_tree_retirement(timeout=3)
    unrelated.owner.terminate()
    unrelated.owner.wait(timeout=3)
    unrelated.owner.wait_tree(timeout=3)
    unrelated.owner.close()


@pytest.mark.skipif(os.name != "nt", reason="Inert Windows Job API model")
def test_peer_stop_receipt_requires_member_signals_and_handles(owned):
    instance = supervisor.ProcessSupervisor()
    component = _component(instance)
    sample = owned.make(register=False)
    component.proc = sample.owner
    custody = instance.capture_retirement_custody()
    assert not instance.shutdown_retired(custody)
    assert instance.stop() is True
    proof = sample.owner.tree_retirement_snapshot()
    assert proof["signals_proven"] is True and proof["handles_closed"] is True
    assert instance.shutdown_retired(custody)


@pytest.mark.skipif(os.name != "nt", reason="Inert Windows retained-query API model")
def test_capture_adopted_helper_before_stop_retains_exact_exit_handle(inert_child_factory, monkeypatch):
    import psutil
    from angerona.core.windows_process_lease import ProcessObjectIdentity

    native = inert_child_factory.native
    identity = ProcessObjectIdentity(1234, 134000000000000001, r"C:\inert\python.exe")
    native.identities[identity.pid] = identity
    native.object_identity = lambda handle: (native.identity(handle).pid, native.identity(handle).birth_ticks)
    native.exit_code = lambda _handle: 0
    process = SimpleNamespace(pid=identity.pid, cmdline=lambda: [identity.image, "-m", "inert.helper"],
                              exe=lambda: identity.image, create_time=lambda: identity.create_time,
                              is_running=lambda: identity.pid not in native.exited)
    monkeypatch.setattr(psutil, "Process", lambda _pid: process)
    instance = supervisor.ProcessSupervisor()
    component = supervisor.Component("scanner_ui", [identity.image, "-m", "inert.helper"], adopted=True,
        adopted_identity={"pid": identity.pid, "birth": identity.create_time, "image": identity.image, "parent": None})
    instance.components[component.name] = component
    custody = instance.capture_retirement_custody()
    assert component._peer_exit_owner is not None
    assert native.opened[0][1] == 0x101000  # QUERY_LIMITED_INFORMATION + SYNCHRONIZE only.
    native.exited.add(identity.pid)  # The real peer independently honored its source STOP.
    assert instance.capture_retirement_custody() is custody
    assert len(native.opened) == 1  # No recapture after the original process exits.
    assert instance.stop()
    assert instance.shutdown_retired(custody)
    assert len(native.opened) == len(native.closed) == 1


@pytest.mark.skipif(os.name != "nt", reason="Inert Windows Job API model")
def test_one_held_peer_does_not_block_other_peer_retirement(owned):
    instance = supervisor.ProcessSupervisor()
    stuck = _component(instance, "watchdog")
    good = _component(instance, "scanner")
    failed, retired = owned.make(register=False), owned.make((8001, 8002), register=False)
    stuck.proc, good.proc = failed.owner, retired.owner
    # Signal failure retains original native lifetime and cannot become True.
    owned.transport.stubborn.add(7002)
    custody = instance.capture_retirement_custody()
    assert instance.stop() is False
    assert not instance.shutdown_retired(custody)
    assert stuck.proc is failed.owner and failed.owner._process is failed.root
    assert good.proc is None and retired.owner._process is None
    assert retired.owner.tree_retirement_snapshot()["signals_proven"] is True
    # Retire the inert held model explicitly; never leave even a simulated
    # outstanding owner behind after verifying the unresolved outcome.
    owned.native.exited.add(7002)
    failed.owner.wait_tree(timeout=3)
    failed.owner.close()


@pytest.mark.skipif(os.name != "nt", reason="Inert Windows Job API model")
def test_observational_cut_failure_still_attempts_exact_owned_stop(owned, monkeypatch):
    instance = supervisor.ProcessSupervisor()
    component = _component(instance)
    sample = owned.make(register=False)
    unrelated = owned.make((8001, 8002), register=False)
    component.proc = sample.owner
    original_prepare = sample.owner.prepare_tree_retirement

    def capture_unavailable(**_kwargs):
        raise OSError("inert private query capture unavailable")

    monkeypatch.setattr(sample.owner, "prepare_tree_retirement", capture_unavailable)
    custody = instance.capture_retirement_custody()
    assert instance.stop() is False
    assert sample.model.termination_calls == [1]
    assert component.proc is sample.owner and sample.owner._process is sample.root
    assert not instance.shutdown_retired(custody)
    assert unrelated.model.termination_calls == []
    assert unrelated.owner._process is unrelated.root and not unrelated.root.closed
    # This branch intentionally could not capture a cut, so its attempts must
    # not be represented as complete proof. Close only the exact inert models.
    monkeypatch.setattr(sample.owner, "prepare_tree_retirement", original_prepare)
    sample.owner.wait(timeout=3)
    sample.owner.wait_tree(timeout=3)
    sample.owner.close()
    unrelated.owner.prepare_tree_retirement(timeout=3)
    unrelated.owner.terminate()
    unrelated.owner.wait(timeout=3)
    unrelated.owner.wait_tree(timeout=3)
    unrelated.owner.close()


def _manager(instance):
    owner = manager.ResilienceManager.__new__(manager.ResilienceManager)
    owner._sup = instance
    owner._stop = threading.Event()
    owner._shutdown_lock = threading.RLock()
    owner._closed = owner._shutdown_requested = False
    owner._retirement_errors = set()
    owner._threads = []
    owner._unsigned_watchdog = owner._source_update_controller = None
    owner._component_heartbeat_cache = None
    owner._core_beat = SimpleNamespace(close=lambda: None)
    owner._reader = None
    return owner


def test_manager_retirement_cannot_be_inferred_from_stopped_status(monkeypatch):
    instance = supervisor.ProcessSupervisor()
    owner = _manager(instance)
    custody = owner.capture_retirement_custody()
    owner.status = "stopped"
    assert not owner.shutdown_retired(custody)
    assert owner.stop(terminate_children=True)
    assert owner.shutdown_retired(custody)
    replacement = supervisor.ProcessSupervisor()
    owner._sup = replacement
    assert not owner.shutdown_retired(custody)


def test_manager_reuses_pre_token_custody_after_fence_and_on_repeated_stop(monkeypatch):
    instance = supervisor.ProcessSupervisor()
    owner = _manager(instance)
    captures = []
    original = instance.capture_retirement_custody

    def capture():
        captures.append("pre-stop")
        assert not owner._stop.is_set()
        return original()

    monkeypatch.setattr(instance, "capture_retirement_custody", capture)
    custody = owner.capture_retirement_custody()
    assert owner.capture_retirement_custody() is custody
    # The supervisor also retains its initial cut. Its stop must not call a
    # fresh capture implementation after Manager's local fence has closed.
    monkeypatch.setattr(instance, "capture_retirement_custody", original)
    owner.request_stop()
    assert owner.stop(terminate_children=True)
    assert owner.stop(terminate_children=True)
    assert captures == ["pre-stop"]
    assert owner.capture_retirement_custody() is custody
    assert owner.shutdown_retired(custody)


def test_optional_monitor_error_does_not_prevent_peer_fence_or_cleanup(monkeypatch):
    instance = supervisor.ProcessSupervisor()
    owner = _manager(instance)
    attempts = []

    def fail():
        attempts.append("monitor")
        raise RuntimeError("private inert observer failure")

    owner._unsigned_watchdog = SimpleNamespace(request_stop=fail, stop=fail)
    monkeypatch.setattr(instance, "stop", lambda **_kwargs: attempts.append("peers"))
    assert owner.stop(terminate_children=True) is False
    assert instance._stop.is_set() and instance._shutdown_requested
    assert "peers" in attempts


def test_component_registry_drift_invalidates_retirement_receipt(monkeypatch):
    instance = supervisor.ProcessSupervisor()
    _component(instance)
    monkeypatch.setattr(instance, "_retire_for_stop", lambda _c: True)
    custody = instance.capture_retirement_custody()
    assert instance.stop()
    instance.components["scanner"] = supervisor.Component("scanner", ["different-inert-fixture"])
    assert not instance.shutdown_retired(custody)


def test_query_close_failure_never_counts_as_retired(monkeypatch):
    instance = supervisor.ProcessSupervisor()
    component = _component(instance)
    component._peer_exit_owner = SimpleNamespace(exited=lambda: True, close=lambda: False)
    custody = instance.capture_retirement_custody()
    assert not instance.stop()
    assert not instance.shutdown_retired(custody)
    assert component._peer_exit_close_failed


def test_never_admitted_presentation_slot_has_no_owned_shutdown_work(monkeypatch):
    instance = supervisor.ProcessSupervisor(launch_guard=lambda _c: False)
    component = _component(instance, "blackbox")
    component.running_probe = lambda: pytest.fail("shutdown discovered foreign presentation processes")
    custody = instance.capture_retirement_custody()
    monkeypatch.setattr(instance, "_terminate", lambda _c: pytest.fail("unadmitted process termination"))
    assert instance.stop()
    assert instance.shutdown_retired(custody)


def test_observed_but_unverified_peer_cannot_become_empty_slot(monkeypatch):
    instance = supervisor.ProcessSupervisor()
    component = _component(instance)
    monkeypatch.setattr(supervisor.tok, "is_standdown_requested", lambda: False)
    monkeypatch.setattr(instance, "_is_running", lambda _c: False)
    monkeypatch.setattr(instance, "_authenticated_record", lambda _c: ({"pid": 321}, "unavailable"))
    monkeypatch.setattr(supervisor.hb, "pid_alive", lambda _pid: True)
    assert instance._spawn(component) is False
    assert component._admission_uncertain and not component._admission_committed
    monkeypatch.setattr(instance, "_terminate", lambda _c: pytest.fail("unverified peer termination"))
    assert instance.stop() is False


@pytest.mark.parametrize("mismatch", ["child", "parent"])
def test_old_query_witness_cannot_prove_replacement_generation_retired(monkeypatch, mismatch, tmp_path):
    instance = supervisor.ProcessSupervisor()
    component = _component(instance)
    image = str(tmp_path / "python.exe")
    component.adopted = component._admission_committed = True
    component.adopted_identity = {"pid": 101, "birth": 10.0, "image": image,
                                  "parent": (100, 9.0, image) if mismatch == "parent" else None}
    component._peer_exit_owner = SimpleNamespace(
        identity=SimpleNamespace(pid=102 if mismatch == "child" else 101, create_time=10.0, image=image),
        exited=lambda: True)
    if mismatch == "parent":
        instance._stop_parent_owners[component.name] = SimpleNamespace(
            identity=SimpleNamespace(pid=100, create_time=8.0, image=image), exited=lambda: True)
    monkeypatch.setattr(instance, "_terminate", lambda _c: pytest.fail("replacement was targeted"))
    assert instance._retire_for_stop(component) is False
