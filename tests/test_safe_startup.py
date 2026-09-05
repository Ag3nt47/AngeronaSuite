"""Isolated startup-helper checks; no dashboard, sensors or response service runs."""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import threading
from types import SimpleNamespace

import pytest

from angerona import startup
from angerona.core.startup_protocol import notify_dashboard_ready


def _plan(tmp_path: Path, *, frozen: bool = False) -> startup.LaunchPlan:
    return startup.LaunchPlan(
        tmp_path, tmp_path / "runtime",
        (str(tmp_path / ("Angerona.exe" if frozen else "python.exe")),), frozen,
    )


class Process:
    def __init__(self, code=None):
        self.pid = os.getpid()
        self.returncode = code
        self.actions = []

    def poll(self):
        return self.returncode

    def kill(self):
        self.actions.append("kill")
        self.returncode = -1

    def terminate(self):
        self.actions.append("terminate")

    def wait(self, timeout=None):
        self.actions.append(("wait", timeout))
        return self.returncode


def _send(listener: startup.ReadyListener, frame: bytes) -> None:
    port = int(listener.endpoint.split(":", 1)[0])
    with socket.create_connection(("127.0.0.1", port), timeout=1) as connection:
        connection.sendall(frame)


def test_ready_listener_accepts_actual_dashboard_protocol_and_closes_socket() -> None:
    listener = startup.ReadyListener()
    try:
        assert listener.socket.getsockname()[0] == "127.0.0.1"
        assert len(listener.token) == 64
        assert notify_dashboard_ready(listener.endpoint) is True
        assert listener.receive() == os.getpid()
    finally:
        listener.close()
    assert listener.socket.fileno() == -1


@pytest.mark.parametrize("kind", [
    "wrong_token", "boolean_pid", "string_pid", "negative_pid", "zero_pid",
    "missing_pid", "extra_field", "array", "invalid_json", "invalid_utf8", "oversize",
])
def test_ready_listener_ignores_bad_frames_then_accepts_valid_notice(kind) -> None:
    listener = startup.ReadyListener()
    try:
        payload = {"token": listener.token, "pid": os.getpid()}
        if kind == "wrong_token":
            payload["token"] = "0" * 64 if listener.token != "0" * 64 else "1" * 64
        elif kind == "boolean_pid":
            payload["pid"] = True
        elif kind == "string_pid":
            payload["pid"] = str(os.getpid())
        elif kind == "negative_pid":
            payload["pid"] = -1
        elif kind == "zero_pid":
            payload["pid"] = 0
        elif kind == "missing_pid":
            payload.pop("pid")
        elif kind == "extra_field":
            payload["command"] = "ignored"
        elif kind == "array":
            payload = [payload]
        frame = json.dumps(payload).encode("ascii") + b"\n"
        if kind == "invalid_json":
            frame = b"{\n"
        elif kind == "invalid_utf8":
            frame = b"\xff\n"
        elif kind == "oversize":
            frame = b" " * 300 + frame
        _send(listener, frame)
        assert listener.receive() is None
        assert notify_dashboard_ready(listener.endpoint) is True
        assert listener.receive() == os.getpid()
    finally:
        listener.close()


def test_wait_dashboard_rejects_different_source_pid_without_restarting(tmp_path, monkeypatch) -> None:
    import psutil

    process = Process()
    notices = iter([process.pid + 1, process.pid])
    listener = SimpleNamespace(receive=lambda: next(notices))

    def unavailable(pid):
        raise psutil.NoSuchProcess(pid)

    monkeypatch.setattr(psutil, "Process", unavailable)
    startup.wait_dashboard(listener, process, _plan(tmp_path), 0, threading.Event(), timeout=1)
    assert process.actions == []


@pytest.mark.parametrize("reason", ["timeout", "cancel", "exit"])
def test_dashboard_failure_or_cancel_never_terminates_or_restarts_child(
    tmp_path, monkeypatch, reason,
) -> None:
    process = Process(7 if reason == "exit" else None)
    listener = SimpleNamespace(receive=lambda: None)
    cancel = threading.Event()
    if reason == "cancel":
        cancel.set()
    clock = iter([0.0, 0.1, 1.0])
    monkeypatch.setattr(startup.time, "monotonic", lambda: next(clock))
    with pytest.raises(startup.StartupError, match={
        "timeout": "did not respond", "cancel": "left running", "exit": "code 7",
    }[reason]):
        startup.wait_dashboard(listener, process, _plan(tmp_path), 0, cancel, timeout=0.5)
    assert process.actions == []


def test_frozen_zero_exit_waits_for_elevated_dashboard(tmp_path, monkeypatch) -> None:
    process = Process(0)
    notices = iter([None, process.pid + 1])
    listener = SimpleNamespace(receive=lambda: next(notices))
    seen = []
    monkeypatch.setattr(
        startup, "_ready_process",
        lambda pid, *_args: seen.append(pid) or pid == process.pid + 1,
    )
    startup.wait_dashboard(listener, process, _plan(tmp_path, frozen=True), 0,
                           threading.Event(), timeout=1)
    assert seen == [process.pid + 1]
    assert process.actions == []


def test_frozen_nonzero_exit_is_reported_without_retry(tmp_path) -> None:
    process = Process(2)
    listener = SimpleNamespace(receive=lambda: None)
    with pytest.raises(startup.StartupError, match="code 2"):
        startup.wait_dashboard(listener, process, _plan(tmp_path, frozen=True), 0,
                               threading.Event(), timeout=1)
    assert process.actions == []


@pytest.mark.parametrize("identity", ["valid", "different_image", "stale", "dead", "denied"])
def test_frozen_ready_requires_fresh_live_expected_image(tmp_path, monkeypatch, identity) -> None:
    import psutil

    plan = _plan(tmp_path, frozen=True)

    def candidate(_pid):
        if identity == "denied":
            raise psutil.AccessDenied(_pid)
        return SimpleNamespace(
            exe=lambda: str(tmp_path / "other.exe") if identity == "different_image" else plan.command[0],
            create_time=lambda: 10 if identity == "stale" else 100,
            is_running=lambda: identity != "dead",
        )

    monkeypatch.setattr(psutil, "Process", candidate)
    assert startup._ready_process(123, Process(0), plan, 100) is (identity == "valid")


@pytest.mark.parametrize("identity", [
    "valid", "different_parent", "different_image", "stale", "dead", "denied",
    "parent_exited", "helper_denied",
])
def test_source_venv_child_requires_owned_live_parent_and_same_python_runtime(
    tmp_path, monkeypatch, identity,
) -> None:
    import psutil

    monkeypatch.setattr(startup.sys, "platform", "win32")
    plan = _plan(tmp_path)
    bootstrap = Process(0 if identity == "parent_exited" else None)
    bootstrap.pid = os.getpid() + 100
    dashboard_pid = bootstrap.pid + 1
    runtime = tmp_path / "Python312" / "python.exe"
    observed = []

    def process_metadata(pid):
        observed.append(pid)
        if pid == os.getpid():
            if identity == "helper_denied":
                raise psutil.AccessDenied(pid)
            return SimpleNamespace(exe=lambda: str(runtime))
        assert pid == dashboard_pid
        if identity == "denied":
            raise psutil.AccessDenied(pid)
        return SimpleNamespace(
            ppid=lambda: bootstrap.pid + 2 if identity == "different_parent" else bootstrap.pid,
            exe=lambda: str(tmp_path / "unrelated.exe") if identity == "different_image" else str(runtime),
            create_time=lambda: 10 if identity == "stale" else 100,
            is_running=lambda: identity != "dead",
        )

    monkeypatch.setattr(psutil, "Process", process_metadata)
    assert startup._ready_process(dashboard_pid, bootstrap, plan, 100) is (identity == "valid")
    assert bootstrap.actions == []
    if identity == "valid":
        assert dashboard_pid in observed and os.getpid() in observed


@pytest.mark.parametrize("code", [None, 0])
def test_source_direct_pid_still_requires_retained_process_alive(tmp_path, monkeypatch, code) -> None:
    import psutil

    process = Process(code)

    def must_not_inspect(_pid):
        pytest.fail("An exact retained Popen PID does not need process rediscovery")

    monkeypatch.setattr(psutil, "Process", must_not_inspect)
    assert startup._ready_process(process.pid, process, _plan(tmp_path), 100) is (code is None)


def test_storage_repair_creates_only_directories_and_removes_own_probe(tmp_path) -> None:
    root = tmp_path / "new" / "runtime"
    startup.prepare_storage(root)
    assert sorted(path.name for path in root.iterdir()) == ["logs", "tmp"]
    assert list((root / "tmp").iterdir()) == []
    evidence = root / "operator-evidence.json"
    evidence.write_bytes(b"preserve authenticated operator evidence")
    startup.prepare_storage(root)
    assert evidence.read_bytes() == b"preserve authenticated operator evidence"


def test_low_disk_failure_preserves_existing_state_and_creates_no_probe(tmp_path, monkeypatch) -> None:
    root = tmp_path / "runtime"
    root.mkdir()
    evidence = root / "config.json"
    evidence.write_bytes(b"existing settings")
    monkeypatch.setattr(startup.shutil, "disk_usage", lambda _path: SimpleNamespace(free=127 * 1024 * 1024))
    with pytest.raises(startup.StartupError, match="128 MB"):
        startup.prepare_storage(root)
    assert evidence.read_bytes() == b"existing settings"
    assert list((root / "tmp").iterdir()) == []


def test_storage_failed_flush_removes_only_its_own_probe(tmp_path, monkeypatch) -> None:
    root = tmp_path / "runtime"
    startup.prepare_storage(root)
    other = root / "tmp" / "operator-file"
    other.write_bytes(b"preserve")

    def fail_flush(_fd):
        raise OSError("simulated storage failure")

    monkeypatch.setattr(startup.os, "fsync", fail_flush)
    with pytest.raises(OSError, match="storage failure"):
        startup.prepare_storage(root)
    assert list((root / "tmp").iterdir()) == [other]
    assert other.read_bytes() == b"preserve"


def test_storage_rejects_redirected_ancestor_without_writing_destination(tmp_path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "redirect"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"Creating a directory symlink is unavailable: {error}")
    with pytest.raises(startup.StartupError, match="redirected"):
        startup.prepare_storage(link / "runtime")
    assert list(outside.iterdir()) == []


def test_storage_reparse_attribute_is_rejected_before_directory_creation(tmp_path, monkeypatch) -> None:
    root = tmp_path / "runtime"
    original = Path.lstat

    def reparse_lstat(path, *args, **kwargs):
        if path == root:
            return SimpleNamespace(st_mode=0o40755, st_file_attributes=0x400)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", reparse_lstat)
    with pytest.raises(startup.StartupError, match="redirected"):
        startup.prepare_storage(root)
    assert not root.exists()


def test_startup_lease_rejects_second_helper_and_releases_without_delete(tmp_path) -> None:
    startup.prepare_storage(tmp_path)
    first = startup.StartupLease(tmp_path)
    try:
        with pytest.raises(startup.StartupError, match="already working"):
            startup.StartupLease(tmp_path)
    finally:
        first.close()
    assert (tmp_path / "startup-helper.lock").exists()
    startup.StartupLease(tmp_path).close()


@pytest.mark.parametrize("frozen", [False, True])
def test_child_environment_drops_inherited_controls_and_uses_owned_storage(
    tmp_path, monkeypatch, frozen,
) -> None:
    plan = _plan(tmp_path, frozen=frozen)
    hostile = {
        "PYTHONPATH": "untrusted-modules", "QT_PLUGIN_PATH": "untrusted-qt",
        "TCL_LIBRARY": "untrusted-tcl", "ANGERONA_CORE_CMD": "unexpected-command",
        "ANGERONA_STARTUP_READY": "unexpected-marker", "ANGERONA_DATA": "unexpected-root",
        "ANGERONA_EXTERNAL_WATCHDOG": "1", "OPENAI_API_KEY": "test-secret-not-a-real-key",
        "HTTPS_PROXY": "http://unexpected.invalid", "ANGERONA_FLEET_SERVICE_KEY": "test-only",
    }
    for key, value in hostile.items():
        monkeypatch.setenv(key, value)
    environment = startup.child_environment(plan)
    for key, value in hostile.items():
        assert environment.get(key) != value
    assert environment["TEMP"] == str(plan.storage / "tmp")
    assert environment["TMP"] == environment["TEMP"]
    assert environment["PYTHONNOUSERSITE"] == "1"
    assert environment["PYINSTALLER_RESET_ENVIRONMENT"] == "1"
    if frozen:
        assert "ANGERONA_DATA" not in environment
        assert "ANGERONA_DIAG_DIR" not in environment
    else:
        assert environment["ANGERONA_DATA"] == str(plan.storage)
        assert environment["ANGERONA_DIAG_DIR"] == str(plan.storage / "diagnostics")
        assert environment["ANGERONA_STORAGE_AUTOMIGRATE"] == "0"


@pytest.mark.parametrize("reason", ["cancel", "timeout"])
def test_source_probe_cancellation_and_timeout_only_kill_disposable_probe(
    tmp_path, monkeypatch, reason,
) -> None:
    plan = _plan(tmp_path)
    startup.prepare_storage(plan.storage)
    process = Process()
    launched = []
    monkeypatch.setattr(startup.subprocess, "Popen", lambda *args, **kwargs: launched.append((args, kwargs)) or process)
    cancel = threading.Event()
    if reason == "cancel":
        cancel.set()
    else:
        cancel = SimpleNamespace(wait=lambda _timeout: False)
        clock = iter([0, 31])
        monkeypatch.setattr(startup.time, "monotonic", lambda: next(clock))
    with pytest.raises(startup.StartupError, match="cancelled or timed out"):
        startup.probe_source(plan, {}, cancel)
    assert process.actions == ["kill", ("wait", 5)]
    assert len(launched) == 1
    assert launched[0][0][0][:2] == [plan.command[0], "-c"]
    assert launched[0][1]["env"]["QT_QPA_PLATFORM"] == "offscreen"


def test_failed_dependency_probe_preserves_settings_and_evidence(tmp_path, monkeypatch) -> None:
    plan = _plan(tmp_path)
    startup.prepare_storage(plan.storage)
    evidence = plan.storage / "config.json"
    evidence.write_bytes(b"preserved")
    process = Process(1)
    monkeypatch.setattr(startup.subprocess, "Popen", lambda *_args, **_kwargs: process)
    with pytest.raises(startup.StartupError, match="settings and evidence were preserved"):
        startup.probe_source(plan, {}, threading.Event())
    assert evidence.read_bytes() == b"preserved"
    assert process.actions == []


def test_run_startup_launches_once_and_finishes_only_after_real_nonce_notice(
    tmp_path, monkeypatch,
) -> None:
    plan = _plan(tmp_path)
    process = Process()
    launched = []
    reports = []
    monkeypatch.setattr(startup, "platform_plan", lambda: plan)
    monkeypatch.setattr(startup, "probe_source", lambda *_args: None)

    def fake_dashboard(command, **kwargs):
        launched.append((command, kwargs))
        ready_argument = next(arg for arg in command if arg.startswith("--startup-ready="))
        assert notify_dashboard_ready(ready_argument.split("=", 1)[1]) is True
        return process

    monkeypatch.setattr(startup.subprocess, "Popen", fake_dashboard)
    assert startup.run_startup(reports.append, threading.Event(), setup=True) == plan.storage
    assert len(launched) == 1
    command, arguments = launched[0]
    assert command[0] == plan.command[0]
    assert "--chill" in command and "--setup" in command
    assert arguments["cwd"] == plan.root
    assert arguments["env"]["ANGERONA_DATA"] == str(plan.storage)
    assert reports[-1] == "Dashboard ready. Closing the startup assistant."
    assert process.actions == []
    startup.StartupLease(plan.storage).close()


def test_cancelled_startup_never_launches_dashboard_and_releases_lease(tmp_path, monkeypatch) -> None:
    plan = _plan(tmp_path)
    cancel = threading.Event()
    cancel.set()
    monkeypatch.setattr(startup, "platform_plan", lambda: plan)
    monkeypatch.setattr(startup, "probe_source", lambda *_args: None)

    def must_not_launch(*_args, **_kwargs):
        raise AssertionError("Cancelled startup must not launch a dashboard")

    monkeypatch.setattr(startup.subprocess, "Popen", must_not_launch)
    with pytest.raises(startup.StartupError, match="cancelled before launching"):
        startup.run_startup(lambda _report: None, cancel)
    startup.StartupLease(plan.storage).close()


def _fake_tk(monkeypatch, *, close_after_dispatch=None):
    """Run Tk's callback contract without opening a real desktop window."""
    widgets = []

    class Widget:
        def __init__(self, *_args, **kwargs):
            self.values = kwargs
            self.text = []
            self.stopped = False
            widgets.append(self)

        def pack(self, **_kwargs):
            pass

        def configure(self, **kwargs):
            self.values.update(kwargs)

        def start(self, _interval):
            pass

        def stop(self):
            self.stopped = True

        def insert(self, _position, value):
            self.text.append(value)

        def see(self, _position):
            pass

    class Window(Widget):
        def __init__(self):
            super().__init__()
            self.timers = []
            self.scheduled_delays = []
            self.titles = []
            self.destroyed = False
            self.closed_by_user = False
            self.now = 0
            self.next_order = 0
            self.protocols = {}

        def title(self, value):
            self.titles.append(value)

        def geometry(self, _value):
            pass

        def minsize(self, *_args):
            pass

        def protocol(self, name, callback):
            self.protocols[name] = callback

        def after(self, delay, callback):
            self.next_order += 1
            self.scheduled_delays.append(delay)
            self.timers.append((self.now + delay, self.next_order, callback))

        def destroy(self):
            self.destroyed = True

        def mainloop(self):
            for dispatched in range(20):
                if self.destroyed:
                    return
                assert self.timers, "The startup UI stopped scheduling work before completion"
                self.timers.sort(key=lambda item: (item[0], item[1]))
                self.now, _, callback = self.timers.pop(0)
                callback()
                if close_after_dispatch is not None:
                    close_after_dispatch(self, dispatched)
            raise AssertionError("The fake startup event loop did not finish")

    window = Window()

    class TkBase:
        def __new__(cls, *_args, **_kwargs):
            return window

    tk = SimpleNamespace(
        Tk=TkBase, Label=Widget, Text=Widget,
        ttk=SimpleNamespace(Progressbar=Widget, Button=Widget),
    )
    monkeypatch.setitem(startup.sys.modules, "tkinter", tk)
    return window, widgets


@pytest.mark.parametrize("failure", [False, True])
def test_helper_ui_closes_on_ready_and_keeps_errors_visible_until_user_closes(
    monkeypatch, failure,
) -> None:
    threads = []
    runs = []

    def user_closes_error_window(window, dispatched):
        if failure and dispatched == 6:
            assert not window.destroyed
            assert window.titles[-1].endswith("needs attention")
            window.closed_by_user = True
            window.protocols["WM_DELETE_WINDOW"]()

    window, widgets = _fake_tk(monkeypatch, close_after_dispatch=user_closes_error_window)

    def run(report, cancel, *, setup):
        runs.append((cancel, setup))
        report("Checking the isolated installation")
        if failure:
            raise startup.StartupError("Synthetic dependency failure: repair the runtime")
        report("Synthetic dashboard ready")

    def thread(**kwargs):
        threads.append(kwargs)
        return SimpleNamespace(start=kwargs["target"])

    monkeypatch.setattr(startup, "run_startup", run)
    monkeypatch.setattr(startup.threading, "Thread", thread)
    monkeypatch.setattr(startup.sys, "argv", ["AngeronaStartup.exe", "--setup", "--chill"])
    assert startup.main() == (1 if failure else 0)
    assert len(runs) == 1 and runs[0][1] is True
    assert runs[0][0].is_set()
    assert threads[0]["daemon"] is False
    assert window.destroyed
    assert window.closed_by_user is failure
    assert (250 in window.scheduled_delays) is (not failure)
    if failure:
        assert any(widget.stopped for widget in widgets)
        assert any("Synthetic dependency failure" in text for widget in widgets for text in widget.text)


def test_closing_helper_retains_worker_until_its_owned_probe_is_reaped(tmp_path, monkeypatch) -> None:
    plan = _plan(tmp_path)
    startup.prepare_storage(plan.storage)
    process = Process()
    probe_started = threading.Event()
    threads = []
    thread_factory = threading.Thread

    def process_created(*_args, **_kwargs):
        probe_started.set()
        return process

    def close_during_probe(window, dispatched):
        if dispatched == 0:
            assert probe_started.wait(timeout=2), "The disposable probe did not start"
            window.protocols["WM_DELETE_WINDOW"]()

    window, _ = _fake_tk(monkeypatch, close_after_dispatch=close_during_probe)

    def owned_thread(**kwargs):
        thread = thread_factory(**kwargs)
        threads.append(thread)
        return thread

    monkeypatch.setattr(startup, "run_startup", lambda _report, cancel, **_kwargs: startup.probe_source(plan, {}, cancel))
    monkeypatch.setattr(startup.subprocess, "Popen", process_created)
    monkeypatch.setattr(startup.threading, "Thread", owned_thread)
    monkeypatch.setattr(startup.sys, "argv", ["AngeronaStartup.exe"])
    try:
        assert startup.main() == 1
        assert window.destroyed
        assert len(threads) == 1
        assert threads[0].daemon is False
    finally:
        for thread in threads:
            thread.join(timeout=2)
    assert not threads[0].is_alive()
    assert process.actions == ["kill", ("wait", 5)]


def test_malformed_readiness_endpoint_rejected_after_uac_without_runtime_writes(monkeypatch) -> None:
    import angerona.__main__ as entry
    from angerona.core import data_paths, privilege, windows_package_identity

    arguments = ["Angerona.exe", "--chill", "--startup-ready=invalid"]
    calls = []
    monkeypatch.setattr(entry.sys, "argv", arguments)
    monkeypatch.setattr(entry.sys, "platform", "win32")
    monkeypatch.setattr(entry.sys, "frozen", True, raising=False)
    monkeypatch.setattr(
        windows_package_identity, "verify_current_msix_authority",
        lambda: calls.append("package") or windows_package_identity.PackageAuthority(True, "trusted"),
    )

    def elevate():
        assert entry.sys.argv is arguments
        assert entry.sys.argv[-1] == "--startup-ready=invalid"
        calls.append("uac")
        return privilege.ElevationResult(privilege.ElevationState.EFFECTIVE_ADMINISTRATOR, "test token")

    monkeypatch.setattr(privilege, "ensure_admin", elevate)
    monkeypatch.setattr(privilege, "is_admin", lambda: True)
    monkeypatch.setattr(
        data_paths, "configure_runtime_environment",
        lambda: pytest.fail("Malformed helper arguments reached runtime initialization"),
    )
    assert entry.main() == 2
    assert calls == ["package", "uac", "package"]
    assert arguments == ["Angerona.exe", "--chill", "--startup-ready=invalid"]


def test_tk_source_environment_removes_optional_search_overrides_case_insensitively(monkeypatch) -> None:
    environment = {
        "TCL_LIBRARY": "custom-tcl", "tcl_library": "custom-lowercase",
        "Tk_Library": "custom-tk", "tClLiBpAtH": "custom-search",
        "UNRELATED_SETTING": "preserve",
    }
    monkeypatch.setattr(startup.os, "environ", environment)
    monkeypatch.delattr(startup.sys, "frozen", raising=False)
    startup._configure_tk_environment()
    assert environment == {"UNRELATED_SETTING": "preserve"}


def test_tk_frozen_environment_uses_only_checked_bundled_runtime_directories(tmp_path, monkeypatch) -> None:
    for name in ("_tcl_data", "_tk_data"):
        (tmp_path / name).mkdir()
    environment = {
        "TCL_LIBRARY": "previous-tcl", "tk_library": "previous-tk",
        "TclLibPath": "previous-search", "UNRELATED_SETTING": "preserve",
    }
    monkeypatch.setattr(startup.os, "environ", environment)
    monkeypatch.setattr(startup.sys, "frozen", True, raising=False)
    monkeypatch.setattr(startup.sys, "_MEIPASS", str(tmp_path), raising=False)
    startup._configure_tk_environment()
    assert environment == {
        "TCL_LIBRARY": str(tmp_path / "_tcl_data"),
        "TK_LIBRARY": str(tmp_path / "_tk_data"),
        "UNRELATED_SETTING": "preserve",
    }


@pytest.mark.parametrize("redirected", ["_tcl_data", "_tk_data"])
def test_tk_frozen_environment_rejects_redirected_runtime_directories(
    tmp_path, monkeypatch, redirected,
) -> None:
    for name in ("_tcl_data", "_tk_data"):
        (tmp_path / name).mkdir()
    monkeypatch.setattr(startup.os, "environ", {"TCLLIBPATH": "previous-search"})
    monkeypatch.setattr(startup.sys, "frozen", True, raising=False)
    monkeypatch.setattr(startup.sys, "_MEIPASS", str(tmp_path), raising=False)
    original = Path.lstat

    def redirected_lstat(path, *args, **kwargs):
        if path == tmp_path / redirected:
            return SimpleNamespace(st_mode=0o40755, st_file_attributes=0x400)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", redirected_lstat)
    with pytest.raises(startup.StartupError, match="redirected"):
        startup._configure_tk_environment()
    assert "TCLLIBPATH" not in startup.os.environ


def test_startup_window_suppresses_optional_tk_profile_callback() -> None:
    calls = []

    class ProfileTk:
        def __init__(self):
            calls.append("initialized")
            self.readprofile("sample-base", "sample-class")

        def readprofile(self, *_args):
            pytest.fail("The startup window must not load an optional Tk profile")

    window = startup._startup_window(SimpleNamespace(Tk=ProfileTk))
    assert isinstance(window, ProfileTk)
    assert calls == ["initialized"]
