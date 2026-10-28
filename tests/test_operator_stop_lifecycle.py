"""STOP custody and race regression tests; never touch a host Ollama service."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest

from angerona.app import AngeronaApp
from angerona.core import ollama_lifecycle as ai
from angerona.resilience import shutdown_token as token
from angerona.resilience import supervisor


def test_operator_stop_survives_age_and_requires_signed_domain(tmp_path, monkeypatch):
    key, path = bytes(range(32)), tmp_path / "standdown.cmd"
    now = time.time()
    monkeypatch.setattr(token.time, "time", lambda: now)
    command = token.request_operator_stop(key=key, path=path)
    monkeypatch.setattr(token.time, "time", lambda: now + 86400 * 60)
    assert token.is_standdown_requested(key=key, path=path)
    command["reason"] = "maintenance"
    path.write_text(json.dumps(command))
    assert not token.is_standdown_requested(key=key, path=path)
    token.request_standdown("maintenance", key=key, path=path)
    monkeypatch.setattr(token.time, "time", lambda: now + 86400 * 61)
    assert not token.is_standdown_requested(key=key, path=path)


@pytest.mark.parametrize("raw", [b"[]", b"null", b"x" * 4097])
def test_stop_parser_is_bounded_and_rejects_wrong_shapes(tmp_path, raw):
    path = tmp_path / "stop.cmd"
    path.write_bytes(raw)
    assert token.is_standdown_requested(key=b"k" * 32, path=path) is False


def test_startup_storage_stop_check_is_readonly_and_ignores_environment(tmp_path, monkeypatch):
    root = tmp_path / "trusted"
    assert not token.standdown_active_for_storage(root)
    assert not root.exists()
    (root / "ipc").mkdir(parents=True)
    key = b"a" * 32
    (root / "shutdown.key").write_text(key.hex())
    token.request_operator_stop(key=key, path=root / "ipc" / "standdown.cmd")
    monkeypatch.setenv("ANGERONA_DATA", str(tmp_path / "unrelated"))
    assert token.standdown_active_for_storage(root)
    (root / "shutdown.key").write_text("malformed")
    with pytest.raises(RuntimeError, match="authority is unavailable"):
        token.standdown_active_for_storage(root)


def test_explicit_storage_resume_deletes_only_authenticated_command(tmp_path, monkeypatch):
    root = tmp_path / "trusted"
    token.clear_standdown_for_storage(root)
    assert not root.exists()
    (root / "ipc").mkdir(parents=True)
    key = b"r" * 32
    authority = root / "shutdown.key"
    authority.write_text(key.hex())
    command = root / "ipc" / "standdown.cmd"
    token.request_operator_stop(key=key, path=command)
    monkeypatch.setenv("ANGERONA_DATA", str(tmp_path / "unrelated"))
    token.clear_standdown_for_storage(root)
    assert not command.exists() and authority.read_text() == key.hex()
    command.write_text('{"reason":"unsigned"}')
    with pytest.raises(RuntimeError, match="could not be cleared"):
        token.clear_standdown_for_storage(root)
    assert command.exists()


def test_external_stop_needs_proven_parent_context(tmp_path, monkeypatch):
    from angerona.core import privilege

    monkeypatch.setattr(privilege, "_validated_watchdog_context", lambda _env: {})
    assert token.signal_external_watchdog_stop() is False
    key = b"s" * 32
    monkeypatch.setattr(privilege, "_validated_watchdog_context", lambda _env: {
        "ANGERONA_WATCHDOG_TOKEN": key.hex(), "ANGERONA_WD_DATADIR": str(tmp_path),
    })
    assert token.signal_external_watchdog_stop()
    command = json.loads((tmp_path / "watchdog.stop").read_text())
    payload = f"angerona-watchdog-stop-v1\0{command['nonce']}\0{command['ts']}".encode()
    assert command["sig"] == hmac.new(key, payload, hashlib.sha256).hexdigest()
    assert not list(tmp_path.glob("*.tmp"))


@pytest.mark.parametrize("value", ["1", "0", "true", "1 "])
def test_privileged_bootstrap_preserves_only_exact_recovery_inhibition(monkeypatch, value):
    from angerona.core import privilege

    saved = dict(os.environ)
    monkeypatch.setattr(privilege, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(privilege, "_minimal_environment", lambda _source: {})
    monkeypatch.setattr(privilege, "_validated_watchdog_context", lambda _source: {})
    try:
        os.environ["ANGERONA_SUPERVISED_RECOVERY"] = value
        privilege.sanitize_privileged_bootstrap_environment()
        assert os.environ.get("ANGERONA_SUPERVISED_RECOVERY") == ("1" if value == "1" else None)
    finally:
        os.environ.clear()
        os.environ.update(saved)


def test_stop_dominates_authenticated_manual_restart(monkeypatch):
    sup = supervisor.ProcessSupervisor()
    sup.add("core", ["inert"])
    monkeypatch.setattr(supervisor.tok, "is_standdown_requested", lambda: True)
    monkeypatch.setattr(sup, "_pop_restart_requests", lambda: {"core"})
    monkeypatch.setattr(sup, "_spawn", lambda _c: pytest.fail("STOP admitted a spawn"))
    monkeypatch.setattr(sup, "_terminate", lambda _c: pytest.fail("STOP replayed restart"))
    assert sup.tick() == {"core": "standdown"}
    assert not sup._spawn_locked(sup.components["core"])


def test_manager_request_stop_still_closes_heartbeat_and_reader_once(monkeypatch):
    from angerona.resilience import manager

    calls = []
    monkeypatch.setattr(manager.hb, "HeartbeatWriter", lambda _name: SimpleNamespace(
        close=lambda: calls.append("heartbeat-close"),
    ))
    monkeypatch.setattr(manager, "ProcessSupervisor", lambda **_kwargs: SimpleNamespace(
        request_stop=lambda: calls.append("admission-close"),
        stop=lambda **kwargs: calls.append(("children-stop", kwargs["terminate_children"])),
    ))
    owner = manager.ResilienceManager(start_watchdog=False)
    owner._reader = SimpleNamespace(close=lambda: calls.append("reader-close"))
    owner.request_stop()
    owner.stop(terminate_children=True)
    owner.stop(terminate_children=True)
    assert calls.count("heartbeat-close") == calls.count("reader-close") == 1
    assert calls.count(("children-stop", True)) == 2
    assert owner.status == "stopped"


def test_stop_during_spawn_retires_exact_child_and_tags_recovery(monkeypatch):
    sup = supervisor.ProcessSupervisor()
    component = sup.add("core", ["inert"])
    captured = []
    monkeypatch.setattr(supervisor.tok, "is_standdown_requested", lambda: False)
    monkeypatch.setattr(sup, "_is_running", lambda _c: False)
    monkeypatch.setattr(sup, "_authenticated_record", lambda _c: (None, "missing"))
    monkeypatch.setattr(supervisor, "try_claim_spawn", lambda _name: True)
    monkeypatch.setattr(sup, "_release_when_up", lambda _c: None)

    def spawn(argv, *, env, window):
        assert env["ANGERONA_SUPERVISED_RECOVERY"] == "1"
        sup.request_stop()
        return SimpleNamespace(pid=123)

    monkeypatch.setattr(supervisor, "spawn_detached", spawn)
    monkeypatch.setattr(sup, "_terminate", lambda c: captured.append(c.proc) or True)
    assert not sup._spawn(component)
    assert captured == [component.proc]
    assert component.restarts == 0


def test_automatic_app_cannot_clear_stop_or_open_window(monkeypatch):
    app = AngeronaApp.__new__(AngeronaApp)
    monkeypatch.setenv("ANGERONA_SUPERVISED_RECOVERY", "1")
    monkeypatch.setattr(token, "is_standdown_requested", lambda: True)
    calls = []
    monkeypatch.setattr(token, "signal_external_watchdog_stop", lambda: calls.append("native-stop"))
    monkeypatch.setattr(token, "clear_standdown", lambda: pytest.fail("automatic clear"))
    assert app.start() is False
    assert calls == ["native-stop"]


def test_inflight_automatic_app_notices_later_stop(monkeypatch):
    app = AngeronaApp.__new__(AngeronaApp)
    calls = []
    app._operator_stop_timer = SimpleNamespace(stop=lambda: calls.append("timer-stop"))
    app.window = SimpleNamespace(_terminate=lambda: calls.append("owned-stop"))
    monkeypatch.setattr(token, "is_standdown_requested", lambda: True)
    assert app._startup_cancelled()
    app._honor_operator_stop()
    assert calls == ["timer-stop", "owned-stop"]


def test_explicit_resume_cannot_open_when_stop_removal_fails(monkeypatch):
    app = AngeronaApp.__new__(AngeronaApp)
    monkeypatch.delenv("ANGERONA_SUPERVISED_RECOVERY", raising=False)
    calls = []
    monkeypatch.setattr(token, "clear_standdown", lambda *, strict: calls.append(strict))
    monkeypatch.setattr(token, "is_standdown_requested", lambda: True)
    with pytest.raises(RuntimeError, match="could not clear"):
        app.start()
    assert calls == [True]


def test_adopted_shared_interpreter_with_wrong_module_cannot_be_terminated(monkeypatch):
    sup = supervisor.ProcessSupervisor()
    component = sup.add("watchdog", [sys.executable, "-m", "angerona.resilience.watchdog"])
    monkeypatch.setattr(sup, "_authenticated_record", lambda _c: ({"pid": 123}, "authenticated"))
    monkeypatch.setattr(supervisor.hb, "pid_alive", lambda _pid: True)
    process = SimpleNamespace(
        create_time=lambda: 42.0,
        exe=lambda: sys.executable,
        cmdline=lambda: [sys.executable, "-m", "optimus.tests"],
        terminate=lambda: pytest.fail("unrelated shared Python killed"),
    )
    monkeypatch.setitem(sys.modules, "psutil", SimpleNamespace(Process=lambda _pid: process))
    assert sup._terminate(component) is False


def test_prepare_stop_persists_before_cleanup_and_fences_ai(monkeypatch):
    app = AngeronaApp.__new__(AngeronaApp)
    calls = []
    app._resilience = SimpleNamespace(request_stop=lambda: calls.append("spawn-fence"))
    monkeypatch.setattr(token, "request_operator_stop", lambda: calls.append("persist"))
    monkeypatch.setattr(token, "signal_external_watchdog_stop", lambda: calls.append("native"))
    app.prepare_shutdown()
    assert app._shutdown_requested.is_set() and ai.ollama_blocked()
    assert calls == ["persist", "spawn-fence", "native"]


def test_failed_primary_stop_write_leaves_protection_admission_open(monkeypatch):
    app = AngeronaApp.__new__(AngeronaApp)
    calls = []
    app._resilience = SimpleNamespace(request_stop=lambda: calls.append("fence"))
    monkeypatch.setattr(token, "request_operator_stop", lambda: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError):
        app.prepare_shutdown()
    assert not calls and not ai._ai_shutdown.is_set()
    assert not getattr(app, "_shutdown_requested", threading.Event()).is_set()


def test_nonoperator_finally_cleanup_does_not_suppress_startup_recovery(monkeypatch):
    app = AngeronaApp.__new__(AngeronaApp)
    app._resilience = None
    calls = []
    app._shutdown_owned = lambda: calls.append("cleanup")
    monkeypatch.setattr(token, "request_operator_stop", lambda: pytest.fail("exception became STOP"))
    monkeypatch.setattr(token, "signal_external_watchdog_stop", lambda: pytest.fail("exception stopped parent"))
    app.shutdown()
    app.shutdown()
    assert app._shutdown_requested.is_set() and ai.ollama_blocked()
    assert calls == ["cleanup"]


@pytest.mark.parametrize("blocker", ["supervisor", "healer"])
def test_ai_and_direct_blackbox_retire_before_blocked_lifecycle_drain(monkeypatch, blocker):
    app = AngeronaApp.__new__(AngeronaApp)
    calls, blocked, release = [], threading.Event(), threading.Event()
    app.config = SimpleNamespace(ollama_host="http://127.0.0.1:1", ollama_model="fixture")
    app._blackbox_proc = SimpleNamespace(
        owns_descendants=True,
        terminate=lambda: calls.append("blackbox-stop"),
        wait=lambda **_k: None, wait_tree=lambda **_k: None, close=lambda: None,
    )

    def stop(kind):
        calls.append(kind)
        if kind == blocker:
            blocked.set()
            assert release.wait(timeout=3)

    app._resilience = SimpleNamespace(stop=lambda **_k: stop("supervisor"))
    app._runtime_healer = SimpleNamespace(stop=lambda: stop("healer"))
    monkeypatch.setattr(ai, "shutdown_ollama", lambda *_a, **_k: calls.append("ai-stop"))
    worker = threading.Thread(target=app._shutdown_critical_owned)
    worker.start()
    try:
        assert blocked.wait(timeout=2)
        assert calls[:2] == ["blackbox-stop", "ai-stop"]
    finally:
        release.set()
        worker.join(timeout=3)
        assert not worker.is_alive()


def _inert_stop_window(calls):
    from angerona.gui.main_window import MainWindow

    return SimpleNamespace(
        _termination_started=False,
        _shutdown_prepare=lambda: calls.append("persist"),
        _shutdown_callback=lambda: calls.append("owned-cleanup"),
        _close_flight_instructor=lambda: None,
        _close_spyware_guard_window=lambda: None,
        red_team_engine=SimpleNamespace(stop_and_clean=lambda: None),
        shark_engine=SimpleNamespace(stop_and_clean=lambda: None),
        _release_redteam_validation_lease=lambda: None,
        _holographic_orb=SimpleNamespace(shutdown=lambda: None),
        tray=SimpleNamespace(hide=lambda: None),
        _terminate=lambda: calls.append("terminate"),
        method=MainWindow._terminate,
    )


def test_dashboard_stop_runs_app_owned_callback_before_own_exit(monkeypatch):
    from PySide6 import QtWidgets

    calls = []
    window = _inert_stop_window(calls)
    monkeypatch.setattr(QtWidgets, "QApplication", SimpleNamespace(
        instance=lambda: SimpleNamespace(quit=lambda: calls.append("qt-quit")),
    ))
    monkeypatch.setattr(os, "_exit", lambda code: calls.append(("exit", code)))
    window.method(window)
    assert calls == ["persist", "owned-cleanup", "qt-quit", ("exit", 0)]


def test_dashboard_does_not_exit_if_authenticated_stop_cannot_be_saved(monkeypatch):
    from PySide6.QtWidgets import QMessageBox

    calls = []
    window = _inert_stop_window(calls)
    window._shutdown_prepare = lambda: (_ for _ in ()).throw(OSError("fixture"))
    monkeypatch.setattr(QMessageBox, "critical", lambda *_a: calls.append("stop-error"))
    monkeypatch.setattr(os, "_exit", lambda _code: pytest.fail("unrecorded exit"))
    window.method(window)
    assert calls == ["stop-error"] and not window._termination_started


def test_callback_free_dashboard_also_persists_before_ai_fence(monkeypatch):
    from PySide6.QtWidgets import QMessageBox

    calls = []
    window = _inert_stop_window(calls)
    window._shutdown_prepare = None
    monkeypatch.setattr(ai, "begin_ollama_shutdown", lambda: pytest.fail("unrecorded AI fence"))
    monkeypatch.setattr(token, "request_operator_stop", lambda: (_ for _ in ()).throw(OSError("full")))
    monkeypatch.setattr(QMessageBox, "critical", lambda *_a: calls.append("stop-error"))
    monkeypatch.setattr(os, "_exit", lambda _code: pytest.fail("unrecorded exit"))
    window.method(window)
    assert calls == ["stop-error"]


def test_red_stop_never_discovers_or_kills_unrelated_python(monkeypatch):
    import psutil
    from PySide6.QtWidgets import QMessageBox
    from angerona.gui.main_window import MainWindow

    calls = []
    monkeypatch.setattr(QMessageBox, "question", lambda *_a: QMessageBox.Yes)
    monkeypatch.setattr(psutil, "process_iter", lambda *_a: pytest.fail("broad process discovery"))
    MainWindow._full_shutdown(_inert_stop_window(calls))
    assert calls == ["terminate"]


def test_shutdown_unloads_only_resident_configured_models_on_fake_server(monkeypatch):
    # Exercise the real loopback HTTP boundary against an inert private server.
    from angerona.core import url_policy

    calls = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            assert self.path == "/api/ps"
            raw = json.dumps({"models": [{"name": "qwen3:8b"}, {"name": "unrelated:latest"}]}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self):
            assert self.path == "/api/generate"
            calls.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            raw = b'{"done":true}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        monkeypatch.setattr(ai, "attest_ollama_service", lambda *_a, **_k: None)
        monkeypatch.setattr(ai, "_owned_services", {})
        host = f"http://127.0.0.1:{server.server_port}"
        assert ai.shutdown_ollama(host, "qwen3:8b") == ["qwen3:8b"]
        assert calls == [{"model": "qwen3:8b", "prompt": "", "stream": False, "keep_alive": 0}]
        assert ai.ollama_blocked()
        with pytest.raises(url_policy.UrlPolicyError):
            url_policy.local_json_request(
                host, "/api/generate", policy=url_policy.OLLAMA_SERVICE_POLICY,
                payload={"model": "qwen3:8b", "prompt": "should not run"}, timeout=0.1,
            )
        assert len(calls) == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()


def test_ai_spawn_finishes_after_stop_and_is_retired(monkeypatch):
    host = "http://127.0.0.1:11434"
    entered, release = threading.Event(), threading.Event()
    retired = []

    class Child:
        def poll(self):
            return 0 if retired else None

        def terminate(self):
            retired.append(True)

        def wait(self, timeout=None):
            return 0

    def spawn(*_args, **_kwargs):
        entered.set()
        assert release.wait(timeout=2)
        return Child()

    monkeypatch.setattr(ai, "_startup_port_present", lambda _host: False)
    monkeypatch.setattr(ai, "_spawn_ollama_service", spawn)
    monkeypatch.setattr(ai, "chill_active", lambda: False)
    monkeypatch.setattr(ai, "chill_ai_blocked", lambda: False)
    monkeypatch.setattr(ai, "_owned_services", {})
    attempt = ai._StartupAttempt()
    worker = threading.Thread(target=ai._run_startup, args=(host, attempt), kwargs={"timeout": 2})
    worker.start()
    try:
        assert entered.wait(timeout=2)
        ai.begin_ollama_shutdown()
        release.set()
        worker.join(timeout=3)
        assert not worker.is_alive()
        assert retired and ai._owned_services == {}
        assert not attempt.status.daemon_ready
    finally:
        release.set()
        worker.join(timeout=3)


@pytest.mark.skipif(os.name != "nt", reason="Windows native Job custody")
def test_owned_job_retires_runner_after_server_already_exited(tmp_path):
    import win32con
    import win32process
    from angerona.core.ollama_owned_process import OwnedOllamaJob, OwnedOllamaProcess

    runner_pid_path = tmp_path / "runner.pid"
    runner_script = tmp_path / "runner.py"
    runner_script.write_text("import time; time.sleep(30)")
    server_script = tmp_path / "server.py"
    server_script.write_text(
        "import pathlib,subprocess,sys\n"
        f"p=subprocess.Popen([sys.executable,{str(runner_script)!r}])\n"
        f"pathlib.Path({str(runner_pid_path)!r}).write_text(str(p.pid))\n"
    )
    # The fixture starts suspended and is assigned before any Python code runs.
    # Use the actual base image so the unrelated fixture has no venv redirector
    # child outside our retained process handle.
    fixture_python = getattr(sys, "_base_executable", sys.executable)
    job = OwnedOllamaJob()
    process = thread = owned = runner_handle = None
    unrelated = subprocess.Popen([fixture_python, "-c", "import time; time.sleep(30)"],
                                 creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        process, thread, pid, _ = win32process.CreateProcess(
            fixture_python, subprocess.list2cmdline([fixture_python, str(server_script)]),
            None, None, False, win32con.CREATE_SUSPENDED | win32con.CREATE_NO_WINDOW,
            None, str(tmp_path), win32process.STARTUPINFO(),
        )
        job.assign(process)
        owned = OwnedOllamaProcess(process, pid, job)
        process = None
        win32process.ResumeThread(thread)
        owned.wait(timeout=8)
        assert runner_pid_path.exists()
        import win32api
        import win32event
        runner_handle = win32api.OpenProcess(0x00100000 | 0x1000, False, int(runner_pid_path.read_text()))
        assert win32event.WaitForSingleObject(runner_handle, 0) == win32event.WAIT_TIMEOUT
        # The server is dead, but its retained job still owns the runner.
        assert owned.poll() is not None
        owned.close()
        owned = None
        assert win32event.WaitForSingleObject(runner_handle, 5000) == win32event.WAIT_OBJECT_0
        assert unrelated.poll() is None
    finally:
        if owned is not None:
            owned.close()
        elif process is not None:
            job.close()
            process.Close()
        job.close()
        if thread is not None:
            thread.Close()
        if runner_handle is not None:
            runner_handle.Close()
        unrelated.terminate()
        unrelated.wait(timeout=5)
        assert unrelated.poll() is not None


@pytest.mark.skipif(os.name != "nt", reason="Windows source redirector custody")
def test_supervisor_stop_retires_venv_redirector_and_actual_child_tree(tmp_path):
    import win32api
    import win32event

    marker = tmp_path / "child.pid"
    script = tmp_path / "sidecar.py"
    script.write_text(
        "import pathlib,subprocess,sys,time\n"
        "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'])\n"
        f"pathlib.Path({str(marker)!r}).write_text(str(p.pid))\n"
        "time.sleep(30)\n"
    )
    sup = supervisor.ProcessSupervisor()
    component = sup.add("scanner", [sys.executable, str(script)])
    child = supervisor.spawn_detached(component.argv, window="hidden")
    component.proc = child
    runner = None
    try:
        deadline = time.monotonic() + 8
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert marker.exists()
        runner = win32api.OpenProcess(0x1000 | 0x00100000, False, int(marker.read_text()))
        assert win32event.WaitForSingleObject(runner, 0) == win32event.WAIT_TIMEOUT
        assert sup._terminate(component)
        assert component.proc is None and component._dead
        # Job accounting can reach zero just before the terminated process
        # object's final signal; prove the exact descendant handle retires.
        assert win32event.WaitForSingleObject(runner, 3000) == win32event.WAIT_OBJECT_0
    finally:
        if component.proc is not None:
            child.terminate()
            child.wait(timeout=3)
            child.wait_tree(timeout=3)
            child.close()
        if runner is not None:
            assert win32event.WaitForSingleObject(runner, 3000) == win32event.WAIT_OBJECT_0
            runner.Close()


@pytest.mark.skipif(os.name != "nt", reason="Windows resilience crash-survival policy")
def test_resilience_job_close_does_not_kill_peer_on_core_crash(tmp_path):
    import win32api
    import win32event

    script = tmp_path / "peer.py"
    script.write_text("import time;time.sleep(30)")
    base = getattr(sys, "_base_executable", sys.executable)
    child = supervisor.spawn_detached([base, str(script)], window="hidden")
    custody = win32api.OpenProcess(0x1000 | 0x00100000 | 1, False, child.pid)
    try:
        child.close()  # Kernel closes this job when a core crashes, too.
        assert win32event.WaitForSingleObject(custody, 100) == win32event.WAIT_TIMEOUT
    finally:
        win32api.TerminateProcess(custody, 1)
        assert win32event.WaitForSingleObject(custody, 3000) == win32event.WAIT_OBJECT_0
        custody.Close()


@pytest.mark.skipif(os.name != "nt", reason="Windows adopted venv lineage custody")
def test_recovered_core_can_stop_adopted_heartbeatless_venv_child(tmp_path):
    import win32api
    import win32event

    marker = tmp_path / "base.pid"
    script = tmp_path / "blackbox_fixture.py"
    script.write_text(
        "import os,pathlib,time\n"
        f"pathlib.Path({str(marker)!r}).write_text(str(os.getpid()))\n"
        "time.sleep(30)\n"
    )
    argv = [sys.executable, str(script)]
    original = supervisor.spawn_detached(argv, window="hidden")
    native = redirector = None
    try:
        deadline = time.monotonic() + 8
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert marker.exists()
        actual_pid = int(marker.read_text())
        native = win32api.OpenProcess(0x00100000, False, actual_pid)
        redirector = win32api.OpenProcess(0x00100000, False, original.pid)
        # Simulate losing the old core's job handle without killing peers.
        original.close()
        probe = supervisor.cached_cmdline_probe(expected_argv=argv)
        replacement = supervisor.ProcessSupervisor()
        component = replacement.add("blackbox", argv, running_probe=probe)
        assert replacement._spawn(component)
        assert component.proc is None and component.adopted
        assert component.adopted_identity["pid"] == actual_pid
        assert replacement._terminate(component)
        assert win32event.WaitForSingleObject(native, 3000) == win32event.WAIT_OBJECT_0
        assert win32event.WaitForSingleObject(redirector, 3000) == win32event.WAIT_OBJECT_0
    finally:
        # Independent retained handles close the fixture even on failed proof.
        if native is not None:
            if win32event.WaitForSingleObject(native, 0) == win32event.WAIT_TIMEOUT:
                import psutil
                process = psutil.Process(actual_pid)
                from angerona.core.windows_process_lease import WindowsProcessLease
                with WindowsProcessLease(actual_pid, process.create_time(), process.exe()) as lease:
                    lease.terminate()
                    lease.wait_terminated()
            native.Close()
        if redirector is not None:
            assert win32event.WaitForSingleObject(redirector, 3000) == win32event.WAIT_OBJECT_0
            redirector.Close()
