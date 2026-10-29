"""One-shot ensure preserves operator intent and uses the existing supervisors."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def helper(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("ensure_mutual_recovery_under_test", ROOT / "tools/ensure_mutual_recovery.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    from angerona.core import data_paths
    monkeypatch.setattr(data_paths, "data_dir", lambda create=False: tmp_path)
    return module


@pytest.mark.skipif(os.name != "nt", reason="Windows retained native identity")
def test_check_only_absent_runtime_creates_no_files_keys_or_processes(helper, tmp_path, monkeypatch):
    monkeypatch.setattr(helper, "_guarded_launch", lambda: pytest.fail("Read-only check launched a process"))
    before = tuple(tmp_path.iterdir())
    report = helper.ensure(check_only=True)
    assert report["outcome"] == "not-running"
    assert report["actions"] == [] and report["protection_verified"] is False
    assert tuple(tmp_path.iterdir()) == before


@pytest.mark.skipif(os.name != "nt", reason="Windows retained native identity")
@pytest.mark.parametrize("check_only", [True, False])
def test_any_operator_intent_presence_holds_and_cannot_be_cleared(helper, monkeypatch, check_only):
    monkeypatch.setattr(helper, "_stop_hold", lambda root: True)
    monkeypatch.setattr(helper, "_core_owner", lambda *_: pytest.fail("STOP must precede runtime discovery"))
    monkeypatch.setattr(helper, "_guarded_launch", lambda: pytest.fail("STOP must suppress guarded launch"))
    report = helper.ensure(check_only=check_only)
    assert report["outcome"] == "held" and report["actions"] == []


@pytest.mark.skipif(os.name != "nt", reason="Windows retained native identity")
def test_active_unsupervised_core_requires_controlled_restart(helper, monkeypatch):
    monkeypatch.setattr(helper, "_core_owner", lambda *_: object())
    monkeypatch.setattr(helper, "_shutdown_key", lambda _: (_ for _ in ()).throw(OSError("No existing authority")))
    monkeypatch.setattr(helper, "_guarded_launch", lambda: pytest.fail("Do not replace an active core"))
    report = helper.ensure()
    assert report["outcome"] == "controlled-restart-required"
    assert report["actions"] == [] and not report["supervision_verified"]


@pytest.mark.skipif(os.name != "nt", reason="Windows retained native identity")
def test_absent_core_requests_only_canonical_guarded_launch(helper, monkeypatch):
    monkeypatch.setattr(helper, "_guarded_launch", lambda: {"outcome": "launch-requested", "launcher_pid": 123})
    report = helper.ensure()
    assert report["outcome"] == "launch-requested"
    assert report["actions"] == ["canonical-guarded-source-launch"]
    assert not report["supervision_verified"] and not report["protection_verified"]


@pytest.mark.skipif(os.name != "nt", reason="Windows guarded source startup")
def test_late_stop_after_ensure_inspection_is_not_cleared_by_guarded_fallback(helper, tmp_path, monkeypatch):
    from angerona import startup
    from angerona.resilience import shutdown_token
    captured = {}
    def launch(argv, **kwargs):
        captured.update(argv=argv, **kwargs)
        return SimpleNamespace(pid=123)
    monkeypatch.setattr(helper.subprocess, "Popen", launch)
    assert helper._guarded_launch()["outcome"] == "launch-requested"
    assert captured["env"]["ANGERONA_SUPERVISED_RECOVERY"] == "1"
    # Simulate intent written after ensure's last absence check, before the
    # assistant consumes its inherited inhibition-only marker.
    monkeypatch.setenv("ANGERONA_SUPERVISED_RECOVERY", captured["env"]["ANGERONA_SUPERVISED_RECOVERY"])
    monkeypatch.setenv("ANGERONA_STARTUP_SUPERVISED", "1")
    monkeypatch.setattr(startup, "platform_plan", lambda: SimpleNamespace(storage=tmp_path))
    monkeypatch.setattr(shutdown_token, "standdown_active_for_storage", lambda _: True)
    monkeypatch.setattr(shutdown_token, "clear_standdown_for_storage", lambda _: pytest.fail("Ensure fallback cleared a new STOP"))
    monkeypatch.setattr(startup, "run_startup", lambda *_args, **_kwargs: pytest.fail("Late STOP launched startup work"))
    monkeypatch.setattr(sys, "argv", ["angerona.startup", "--no-startup-window"])
    assert startup.main() == 86


@pytest.mark.skipif(os.name != "nt", reason="Windows private settings custody")
@pytest.mark.parametrize("enabled,expected", [(True, True), (False, False)])
def test_blackbox_preference_is_read_without_enabling_it(helper, tmp_path, enabled, expected):
    from angerona.core.engine_transport import create_private_file, private_directory
    root = private_directory(tmp_path / "preferences")
    with os.fdopen(create_private_file(root / "settings.json"), "w", encoding="utf-8") as stream:
        json.dump({"blackbox_enabled": enabled}, stream)
    assert ("blackbox" in helper._required_peers(root)) is expected


@pytest.mark.skipif(os.name != "nt", reason="Windows one-shot ensure")
def test_peer_that_recovers_during_observation_is_not_force_restarted(helper, monkeypatch):
    from angerona.resilience import supervisor
    core = SimpleNamespace(validate=lambda: None)
    monkeypatch.setattr(helper, "_core_owner", lambda *_: core)
    monkeypatch.setattr(helper, "_shutdown_key", lambda _: bytes(range(32)))
    monkeypatch.setattr(helper, "_required_peers", lambda _: ("watchdog", "scanner"))
    monkeypatch.setattr(helper.time, "sleep", lambda _: None)
    calls = []
    def heartbeat(_root, role, _key, _stack, owner=None):
        calls.append(role)
        if role == "scanner" and calls.count("scanner") == 1:
            raise helper.Held("Peer has not published its first heartbeat yet")
        return core
    monkeypatch.setattr(helper, "_heartbeat", heartbeat)
    monkeypatch.setattr(supervisor, "request_restart", lambda *_: pytest.fail("A newly fresh peer was force restarted"))
    report = helper.ensure()
    assert report["supervision_verified"] and report["actions"] == []


@pytest.mark.skipif(os.name != "nt", reason="Native Windows batch parsing")
@pytest.mark.parametrize("arguments,expected", [([], []), (["--check-only"], ["--check-only"])])
def test_batch_wrapper_ignores_hostile_inherited_control_text(tmp_path, arguments, expected):
    installation = tmp_path / "isolated-wrapper"
    scripts = installation / "venv/Scripts"
    scripts.mkdir(parents=True)
    (installation / "tools").mkdir()
    # A copied trusted redirector and a minimal isolated venv run only this
    # inert stdlib recorder. The real ensure tool and real runtime never start.
    shutil.copyfile(ROOT / "venv/Scripts/python.exe", scripts / "python.exe")
    (installation / "venv/pyvenv.cfg").write_text(
        "home = " + str(Path(sys._base_executable).parent) + "\ninclude-system-site-packages = false\n", encoding="utf-8")
    recorder = installation / "tools/ensure_mutual_recovery.py"
    recorder.write_text("import json,os,sys\nfrom pathlib import Path\nPath(os.environ['ENSURE_FIXTURE_RESULT']).write_text(json.dumps({'args':sys.argv[1:],'bytecode_disabled':sys.dont_write_bytecode}))\n", encoding="utf-8")
    wrapper = installation / "Ensure-Angerona-Recovery.bat"
    shutil.copyfile(ROOT / wrapper.name, wrapper)
    output, forbidden = tmp_path / "arguments.json", tmp_path / "must-not-execute"
    environment = dict(os.environ, ENSURE_FIXTURE_RESULT=str(output),
        ANGERONA_ENSURE_CHECK='--check-only & echo injected > "' + str(forbidden) + '"',
        ERRORLEVEL='0 & echo inherited-errorlevel-injection > "' + str(forbidden) + '"')
    command = Path(os.environ["SystemRoot"]) / "System32/cmd.exe"
    result = subprocess.run([str(command), "/d", "/c", str(wrapper), *arguments],
                            env=environment, cwd=installation, capture_output=True, timeout=15, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(output.read_text()) == {"args": expected, "bytecode_disabled": True}
    assert not forbidden.exists()


@pytest.mark.skipif(os.name != "nt", reason="Native Windows private jobs, locks and process handles")
def test_native_existing_supervisor_consumes_signed_requests_and_real_children_publish_heartbeats(helper, tmp_path, monkeypatch):
    from angerona.core.engine_transport import private_directory
    from angerona.core.privilege import sanitized_child_environment
    from angerona.core.windows_child_job import launch_windows_child
    from angerona.resilience import heartbeat, shutdown_token, supervisor

    # All identities, keys, heartbeat writers and restart inboxes in this fixture
    # are private and synthetic. No real core/manager or host collector is run.
    root = private_directory(tmp_path / "isolated-runtime")
    for name in ("ipc", "heartbeats"):
        private_directory(root / name)
    fixture = tmp_path / "inert_supervision.py"
    fixture.write_text(r'''
import sys,time
from pathlib import Path
from angerona.core import singleton
from angerona.core.engine_transport import create_private_file
from angerona.resilience import heartbeat,shutdown_token,supervisor
role,root=sys.argv[1],Path(sys.argv[2])
heartbeat._data_dir=lambda:root
shutdown_token._data_dir=lambda:root
singleton.data_dir=lambda:root
key=bytes(range(32))
lease=None;peer=None
if role=='core':
    with __import__('os').fdopen(create_private_file(root/'shutdown.key'),'w',encoding='ascii') as stream:stream.write(key.hex())
    lease=singleton.acquire_single_instance()
    if lease is None:raise RuntimeError('Unexpected isolated incumbent')
    def event(level,message,details):
        with (root/'events.jsonl').open('a',encoding='utf-8') as stream:stream.write(__import__('json').dumps({'level':level,'message':message,'details':details})+'\n')
    peer=supervisor.ProcessSupervisor(poll_interval=.1,on_event=event)
    for target in ('watchdog','scanner','blackbox'):
        component=peer.add(target,[sys.executable,__file__,target,str(root)],stale_after_s=10,window='hidden')
        component.safe_mode=True;component.safe_mode_since=time.time()
    peer.start()
writer=heartbeat.HeartbeatWriter(role,token_raw=key,path=root/'heartbeats'/(role+'.hb'))
while True:
    writer.beat()
    time.sleep(.1)
''', encoding="utf-8")
    from angerona.core import data_paths
    monkeypatch.setattr(data_paths, "data_dir", lambda create=False: root)
    monkeypatch.setattr(heartbeat, "_data_dir", lambda: root)
    monkeypatch.setattr(shutdown_token, "_data_dir", lambda: root)
    monkeypatch.setattr(helper, "_expected_argv", lambda role: [sys.executable, str(fixture), role, str(root)])
    child = launch_windows_child([sys.executable, str(fixture), "core", str(root)],
                                 sanitized_child_environment(), cwd=str(ROOT), window="hidden", kill_on_close=True)
    retained = []
    redirectors = {}
    receipt = {"schema": 1, "synthetic": True, "protection_verified": False, "generations": []}
    try:
        deadline = time.monotonic() + 15
        while not (root / "heartbeats/core.hb").exists() and time.monotonic() < deadline:
            if child.poll() is not None:
                pytest.fail("Isolated native supervisor fixture exited before its first heartbeat")
            time.sleep(.05)
        record = heartbeat.HeartbeatReader("core", path=root / "heartbeats/core.hb", key_raw=bytes(range(32))).read()
        retained.append(helper.ReadOnlyGeneration(int(record["pid"]), "core"))
        before = helper.ensure(check_only=True)
        assert before["outcome"] == "needs-attention" and before["missing"] == ["watchdog", "scanner", "blackbox"]
        original = supervisor.request_restart
        def publish_and_start(*roles):
            paths = original(*roles)
            assert set(roles) == {"watchdog", "scanner", "blackbox"}
            assert all(path.is_relative_to(root / "ipc") for path in paths)
            return paths
        monkeypatch.setattr(supervisor, "request_restart", publish_and_start)
        report = helper.ensure(wait_seconds=15)
        assert report["outcome"] == "supervision-live", (report, (root / "events.jsonl").read_text() if (root / "events.jsonl").exists() else "no supervisor event")
        assert report["supervision_verified"] and not report["protection_verified"]
        assert report["actions"] == ["signed-restart:watchdog", "signed-restart:scanner", "signed-restart:blackbox"]
        for role in ("watchdog", "scanner", "blackbox"):
            record = heartbeat.HeartbeatReader(role, path=root / "heartbeats" / (role + ".hb"), key_raw=bytes(range(32))).read()
            retained.append(helper.ReadOnlyGeneration(int(record["pid"]), role))
        import psutil
        for role, generation in zip(("core", "watchdog", "scanner", "blackbox"), retained):
            invocation = supervisor._invocation_identity(psutil.Process(generation.identity.pid), tuple(helper._expected_argv(role)))
            if invocation["parent"]:
                pid, birth, image = invocation["parent"]
                handle = generation.native.open(pid, 0x101000, False)
                identity = generation.native.identity(handle)
                if abs(identity.create_time - birth) > .001:
                    generation.native.close(handle)
                    pytest.fail("Fixture redirector generation changed before teardown")
                redirectors[pid] = (generation.native, handle, identity, role)
    finally:
        child.terminate()
        child.wait(timeout=10)
        child.wait_tree(timeout=10)
        for generation in retained:
            assert generation.native.wait(generation.handle, 10000), "An exact isolated fixture generation did not retire"
            receipt["generations"].append({"pid": generation.identity.pid, "birth_filetime": str(generation.identity.birth_ticks), "native_handle_signaled": True})
            generation.close()
        for native, handle, identity, role in redirectors.values():
            assert native.wait(handle, 10000), "An exact isolated redirector generation did not retire"
            receipt["generations"].append({"role": role + "-redirector", "pid": identity.pid, "birth_filetime": str(identity.birth_ticks), "native_handle_signaled": True})
            native.close(handle)
        child.close()
        (tmp_path / "native-recovery-evidence.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
