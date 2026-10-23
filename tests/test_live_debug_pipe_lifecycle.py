"""Native connect statuses and bounded shutdown must preserve I/O custody."""
from __future__ import annotations

import gc
import os
from pathlib import Path
import secrets
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
import weakref

import pytest

from angerona.core import live_debug as debug
from angerona.core.eventbus import Event, EventBus


pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows overlapped pipe lifecycle")


@pytest.mark.parametrize("code,raised", [(0, False), (535, False), (535, True),
                                         (997, False), (997, True), (5, True), (5, False)])
def test_connect_only_waits_and_retires_a_submitted_pending_operation(monkeypatch, code, raised):
    import win32file
    import win32pipe

    actions = []
    pipe = debug._Pipe(object())
    overlap = SimpleNamespace(hEvent=SimpleNamespace(Close=lambda: actions.append("event-close")))
    monkeypatch.setattr(pipe, "_overlap", lambda: overlap)

    def connect(*_args):
        actions.append("connect")
        if raised:
            error = OSError("controlled connect status")
            error.winerror = code
            raise error
        return code

    monkeypatch.setattr(win32pipe, "ConnectNamedPipe", connect)
    monkeypatch.setattr(pipe, "_wait", lambda *_args: actions.append("wait"))
    monkeypatch.setattr(win32file, "GetOverlappedResult", lambda *_args: actions.append("retire"))
    if code == 5:
        with pytest.raises(debug.LiveDebugError):
            pipe.connect_server(0.1)
    else:
        pipe.connect_server(0.1)
    expected = ["connect", "wait", "retire", "event-close"] if code == 997 else ["connect", "event-close"]
    assert actions == expected


def test_interrupted_pending_connect_drains_before_releasing_event(monkeypatch):
    import win32file
    import win32pipe

    actions = []
    pipe = debug._Pipe(object())
    overlap = SimpleNamespace(hEvent=SimpleNamespace(Close=lambda: actions.append("event-close")))
    monkeypatch.setattr(pipe, "_overlap", lambda: overlap)
    monkeypatch.setattr(win32pipe, "ConnectNamedPipe", lambda *_args: 997)

    def interrupted(*_args):
        raise KeyboardInterrupt

    def completion(_handle, _overlap, wait):
        if not wait:
            actions.append("check-pending")
            error = OSError("controlled pending operation")
            error.winerror = 996
            raise error
        actions.append("drain")
        return 0

    monkeypatch.setattr(pipe, "_wait", interrupted)
    monkeypatch.setattr(debug, "_cancel_pipe_io", lambda _handle: actions.append("cancel"))
    monkeypatch.setattr(win32file, "GetOverlappedResult", completion)
    with pytest.raises(KeyboardInterrupt):
        pipe.connect_server(0.1)
    assert actions == ["check-pending", "cancel", "drain", "event-close"]


def test_stop_deadline_retains_pending_buffer_and_reports_unclean_shutdown(tmp_path, monkeypatch):
    import win32file

    actions, references = [], {}
    entered, release = threading.Event(), threading.Event()
    pipe = debug._Pipe(SimpleNamespace(Close=lambda: actions.append("handle-close")))
    overlap = SimpleNamespace(hEvent=SimpleNamespace(Close=lambda: actions.append("event-close")))
    monkeypatch.setattr(pipe, "_overlap", lambda: overlap)
    monkeypatch.setattr(debug, "_cancel_pipe_io", lambda _handle: actions.append("cancel"))

    class Buffer(bytearray):
        pass

    def allocate(count):
        value = Buffer(count)
        references["buffer"] = weakref.ref(value)
        return value

    def held_wait(*_args):
        entered.set()
        assert release.wait(10)
        return 0

    monkeypatch.setattr(win32file, "AllocateReadBuffer", allocate)
    monkeypatch.setattr(win32file, "ReadFile", lambda *_args: (997, None))
    monkeypatch.setattr(pipe, "_wait", held_wait)
    monkeypatch.setattr(win32file, "GetOverlappedResult", lambda *_args: actions.append("retired"))
    service = debug.LiveDebugService(EventBus(), tmp_path)
    server = debug._NamedPipeServer(service)
    service._server = server
    server.pipes = [pipe]
    monkeypatch.setattr(server, "_serve_client_loop", lambda owned: owned.read(30))
    worker = threading.Thread(target=server._serve, args=(pipe,), daemon=False)
    server.threads = [worker]
    worker.start()
    try:
        assert entered.wait(2)
        start = time.monotonic()
        assert service.stop(timeout=0.03) is False
        assert time.monotonic() - start < 0.5
        assert worker.is_alive()
        assert references["buffer"]() is not None
        assert "event-close" not in actions and "handle-close" not in actions
        assert service.status()["shutdown_pending"] is True
        assert "native I/O remains worker-owned" in service.status()["error"]
    finally:
        release.set()
        worker.join(5)
    assert not worker.is_alive()
    assert actions.index("retired") < actions.index("event-close") < actions.index("handle-close")
    gc.collect()
    assert references["buffer"]() is None
    assert service.stop(timeout=1) is True
    assert service.status()["shutdown_pending"] is False


def test_partial_thread_start_failure_preserves_error_and_closes_owned_pipes(tmp_path, monkeypatch):
    original_start = threading.Thread.start

    def failed_start(thread):
        if thread.name == "LiveDebugPipe-1":
            raise RuntimeError("controlled second pipe worker startup failure")
        return original_start(thread)

    monkeypatch.setattr(threading.Thread, "start", failed_start)
    service = debug.LiveDebugService(EventBus(), tmp_path, enabled=True, export_logs=False)
    try:
        assert service.start() is False
        assert "controlled second pipe worker startup failure" in service.status()["error"]
        assert len(service._server.threads) == 2
        assert service._server.threads[1].ident is None
        assert all(not thread.is_alive() for thread in service._server.threads)
        assert all(pipe._handle_closed for pipe in service._server.pipes)
        assert not service.status()["shutdown_pending"]
    finally:
        service.stop()


def _native_case(case: str, directory: Path):
    """Runs in a bounded, owned child so a future hang fails instead of hanging CI."""
    import win32con
    import win32file
    import win32pipe
    from angerona.core.eventbus import BusAuthority

    if case in {"partial-interrupt", "partial-exit"}:
        exception_type = KeyboardInterrupt if case == "partial-interrupt" else SystemExit
        original_start = threading.Thread.start

        def interrupted_start(thread):
            if thread.name == "LiveDebugPipe-1":
                raise exception_type("controlled partial startup interruption")
            return original_start(thread)

        threading.Thread.start = interrupted_start
        service = debug.LiveDebugService(EventBus(), directory, enabled=True, export_logs=False)
        try:
            with pytest.raises(exception_type):
                service.start()
            assert "controlled partial startup interruption" in service.status()["error"]
            assert service._server.threads[1].ident is None
            assert all(not thread.is_alive() for thread in service._server.threads)
            assert all(pipe._handle_closed for pipe in service._server.pipes)
            assert not service.status()["shutdown_pending"]
        finally:
            service.stop()
        return

    if case == "repeated-service":
        bus = EventBus()
        bus.arm(BusAuthority(secrets.token_bytes(32)))
        service = debug.LiveDebugService(bus, directory, enabled=True, export_logs=False)
        assert service.start(), service.status()
        clients = []
        try:
            assert all(not thread.daemon for thread in service._server.threads)
            for _cycle in range(8):
                for _slot in range(debug.MAX_CLIENTS):
                    client = debug.LiveDebugClient(service.endpoint, os.getpid(), service.birth)
                    clients.append(client)
                    client.connect(timeout=2)
                    assert client.read(timeout=2)["kind"] == "hello"
                for client in clients:
                    client.close()
                clients.clear()
                # A write promptly observes each closed reader; otherwise the
                # next heartbeat intentionally waits two seconds per round.
                bus.publish(Event("native lifecycle fixture", "closed-reader write probe"))
                deadline = time.monotonic() + 3
                while service.status()["client_count"] and time.monotonic() < deadline:
                    time.sleep(0.01)
                assert service.status()["client_count"] == 0
        finally:
            for client in clients:
                client.close()
            start = time.monotonic()
            assert service.stop(timeout=1) is True, service.status()
            assert time.monotonic() - start < 2
        assert all(not thread.is_alive() for thread in service._server.threads)
        assert all(pipe._handle_closed for pipe in service._server.pipes)
        return

    endpoint = rf"\\.\pipe\Angerona.TestConnect.{os.getpid()}.{secrets.token_hex(8)}"
    handle = win32pipe.CreateNamedPipe(
        endpoint, 2 | win32file.FILE_FLAG_OVERLAPPED | 0x80000, 8, 1,
        4096, 0, 1000, debug._pipe_attributes(),
    )
    pipe = debug._Pipe(handle)
    client = None
    worker = None
    try:
        if case == "already-connected":
            client = win32file.CreateFile(endpoint, win32con.GENERIC_READ, 0, None,
                                          win32con.OPEN_EXISTING, 0, None)
            start = time.monotonic()
            pipe.connect_server(timeout=0.1)
            assert time.monotonic() - start < 0.5
            # The already-connected pipe still carries real bytes normally.
            pipe.write(b"test", timeout=1)
            assert win32file.ReadFile(client, 4)[1] == b"test"
        elif case == "pending-timeout":
            with pytest.raises(TimeoutError):
                pipe.connect_server(timeout=0.05)
        elif case == "pending-success":
            submitted = threading.Event()
            codes, errors = [], []
            original_connect = win32pipe.ConnectNamedPipe

            def recorded_connect(*args):
                code = original_connect(*args)
                codes.append(code)
                submitted.set()
                return code

            def serve():
                try:
                    pipe.connect_server(timeout=2)
                except Exception as exc:
                    errors.append(repr(exc))

            win32pipe.ConnectNamedPipe = recorded_connect
            worker = threading.Thread(target=serve, daemon=False)
            worker.start()
            assert submitted.wait(2)
            assert codes == [997]
            client = win32file.CreateFile(endpoint, win32con.GENERIC_READ, 0, None,
                                          win32con.OPEN_EXISTING, 0, None)
            worker.join(3)
            assert not worker.is_alive() and not errors
        elif case == "rejected":
            handle.Close()
            with pytest.raises(debug.LiveDebugError):
                pipe.connect_server(timeout=0.1)
        else:
            raise AssertionError("Unknown native case")
    finally:
        pipe.cancel()
        if worker is not None:
            worker.join(3)
        if client is not None:
            client.Close()
        assert pipe.close(timeout=1)


@pytest.mark.parametrize("case", ["already-connected", "pending-timeout", "pending-success", "rejected", "repeated-service",
                                  "partial-interrupt", "partial-exit"])
def test_native_connect_and_stop_lifecycle(tmp_path, case):
    from angerona.core.privilege import sanitized_child_environment

    repo = Path(__file__).resolve().parents[1]
    script = (
        "import faulthandler,pathlib,runpy,sys;faulthandler.dump_traceback_later(10);"
        f"sys.path.insert(0,{str(repo / 'src')!r});"
        f"case=runpy.run_path({str(Path(__file__).resolve())!r});"
        f"case['_native_case']({case!r},pathlib.Path({str(tmp_path)!r}));"
        "print('native lifecycle clean')"
    )
    environment = sanitized_child_environment(source={})
    environment.update({"ANGERONA_DATA": str(tmp_path), "ANGERONA_DIAG_DIR": str(tmp_path / "diagnostics"),
                        "TEMP": str(tmp_path), "TMP": str(tmp_path), "PYTHON_DOTENV_DISABLED": "1"})
    try:
        result = subprocess.run([sys.executable, "-c", script], cwd=str(repo), env=environment,
                                capture_output=True, text=True, timeout=15,
                                creationflags=subprocess.CREATE_NO_WINDOW)
    except subprocess.TimeoutExpired as exc:
        pytest.fail(f"Native {case} exceeded its child deadline: {exc.stdout!r} {exc.stderr!r}")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "native lifecycle clean" in result.stdout
