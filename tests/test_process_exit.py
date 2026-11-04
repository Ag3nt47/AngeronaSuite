"""Final self-exit bindings are inert here; no test can terminate a process."""
from __future__ import annotations

import builtins
import ctypes
from ctypes import wintypes
import inspect
from pathlib import Path
from types import MethodType, SimpleNamespace
import threading
import time

import pytest

from angerona.core import process_exit


class NativeSelfExit(BaseException):
    """Stand in for the native self-call which cannot return on success."""


class CRTSelfExit(BaseException):
    """Stand in for the last-resort CRT self-call."""


class Function:
    def __init__(self, name, outcome, calls):
        self.name, self.outcome, self.calls = name, outcome, calls
        self.argtypes = self.restype = None

    def __call__(self, *args):
        self.calls.append((self.name, args))
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


@pytest.fixture
def native(monkeypatch):
    calls = []
    pseudo = ctypes.c_void_p(-1).value
    current = Function("current", pseudo, calls)
    terminate = Function("terminate", NativeSelfExit(), calls)

    class Kernel:
        GetCurrentProcess = current
        TerminateProcess = terminate

        def __getattr__(self, name):
            pytest.fail(f"Unexpected native API: {name}")

    def load(name, **kwargs):
        calls.append(("load", name, kwargs))
        return Kernel()

    def crt(code):
        calls.append(("crt", code))
        raise CRTSelfExit

    # Replace every authority boundary before invoking the finalizer. The
    # module's os reference is isolated rather than changing global os.name.
    monkeypatch.setattr(ctypes, "WinDLL", load, raising=False)
    monkeypatch.setattr(process_exit, "os", SimpleNamespace(name="nt", _exit=crt))
    return SimpleNamespace(calls=calls, pseudo=pseudo, current=current,
                           terminate=terminate, crt=crt)


def test_windows_selects_only_the_fixed_current_process_with_zero_exit_code(native):
    with pytest.raises(NativeSelfExit):
        process_exit.exit_after_operator_shutdown()
    assert native.calls == [
        ("load", "kernel32", {"use_last_error": True}),
        ("current", ()),
        ("terminate", (native.pseudo, 0)),
    ]
    assert type(native.calls[-1][1][1]) is int
    assert native.current.argtypes == []
    assert native.current.restype is wintypes.HANDLE
    assert native.terminate.argtypes == [wintypes.HANDLE, wintypes.UINT]
    assert native.terminate.restype is wintypes.BOOL


@pytest.mark.parametrize("value", [None, False, True, 0, 1, -1, "current"])
def test_unexpected_or_noninteger_pseudo_handle_never_becomes_a_target(native, value):
    native.current.outcome = value
    with pytest.raises(CRTSelfExit):
        process_exit.exit_after_operator_shutdown()
    assert [call[0] for call in native.calls] == ["load", "current", "crt"]
    assert native.calls[-1] == ("crt", 0)


@pytest.mark.parametrize("returned", [False, True, None, 0, 1])
def test_every_unexpected_native_return_falls_back_instead_of_leaving_stop_alive(native, returned):
    native.terminate.outcome = returned
    with pytest.raises(CRTSelfExit):
        process_exit.exit_after_operator_shutdown()
    assert native.calls[-2:] == [("terminate", (native.pseudo, 0)), ("crt", 0)]
    assert sum(call[0] == "terminate" for call in native.calls) == 1


@pytest.mark.parametrize("failure", ["binding", "current", "terminate"])
def test_binding_and_native_call_errors_fall_back_without_terminal_path_io(native, monkeypatch, capsys, failure):
    error = OSError("private native failure must not be logged during final exit")
    if failure == "binding":
        def unavailable(*_args, **_kwargs):
            raise error

        monkeypatch.setattr(ctypes, "WinDLL", unavailable)
    elif failure == "current":
        native.current.outcome = error
    else:
        native.terminate.outcome = error
    with pytest.raises(CRTSelfExit):
        process_exit.exit_after_operator_shutdown()
    assert native.calls[-1] == ("crt", 0)
    output = capsys.readouterr()
    assert output.out == output.err == ""


@pytest.mark.parametrize("platform", ["posix", "java"])
def test_other_platforms_retain_the_existing_crt_exit_without_native_binding(native, monkeypatch, platform):
    monkeypatch.setattr(process_exit, "os", SimpleNamespace(name=platform, _exit=native.crt))
    with pytest.raises(CRTSelfExit):
        process_exit.exit_after_operator_shutdown()
    assert native.calls == [("crt", 0)]


def test_finalizer_accepts_no_pid_handle_or_exit_code(native):
    assert not inspect.signature(process_exit.exit_after_operator_shutdown).parameters
    assert not inspect.signature(process_exit._terminate_current_windows_process).parameters
    with pytest.raises(TypeError):
        process_exit.exit_after_operator_shutdown(123)
    with pytest.raises(TypeError):
        process_exit.exit_after_operator_shutdown(pid=123)
    assert native.calls == []


def test_cold_module_loading_does_not_import_or_bind_a_native_backend(monkeypatch):
    source = Path(process_exit.__file__).read_text(encoding="utf-8")
    ordinary_import = builtins.__import__

    def no_native_import(name, *args, **kwargs):
        if name == "ctypes" or name.startswith("ctypes."):
            pytest.fail("A cold finalizer module loaded native bindings")
        return ordinary_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_native_import)
    namespace = {"__name__": "inert_process_exit_import"}
    exec(compile(source, process_exit.__file__, "exec"), namespace)
    assert callable(namespace["exit_after_operator_shutdown"])


@pytest.mark.parametrize("cleanup_completes", [True, False])
def test_dashboard_keeps_durable_stop_and_bounded_cleanup_before_final_self_exit(
    monkeypatch, tmp_path, cleanup_completes,
):
    from PySide6 import QtWidgets
    from PySide6.QtCore import QCoreApplication, QEvent
    from angerona.gui import action_worker, breach_display, live_debug_panel, main_window
    from angerona.gui import shutdown_retirement

    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    calls, clock = [], [0.0]
    cleanup_entered, release_cleanup = threading.Event(), threading.Event()
    original_retirement = shutdown_retirement.ShutdownRetirement

    def bounded_retirement(owner, **kwargs):
        return original_retirement(owner, **kwargs, timeout=.1,
                                   diagnostic_timeout=.1, clock=lambda: clock[0])

    def cleanup():
        calls.append("owned-cleanup")
        cleanup_entered.set()
        assert release_cleanup.wait(5), "Test did not release its exact cleanup owner"
        calls.append("cleanup-complete")

    owner = QtWidgets.QWidget()
    owner._termination_started = False
    owner._shutdown_prepare = lambda: calls.append("durable-stop")
    owner._shutdown_critical = lambda: calls.append("critical-cleanup")
    owner._shutdown_callback = cleanup
    owner.config = SimpleNamespace(data_dir=tmp_path)
    owner.console = SimpleNamespace(_append=lambda _message: None)
    owner._simulation_session = None
    owner._close_flight_instructor = lambda: calls.append("close-flight")
    owner._close_spyware_guard_window = lambda: calls.append("close-spyware")
    owner._close_github_tools_window = lambda: calls.append("close-tools")
    owner.red_team_engine = SimpleNamespace(stop_and_clean=lambda: calls.append("clean-red-team"))
    owner.shark_engine = SimpleNamespace(stop_and_clean=lambda: calls.append("clean-shark"))
    owner._release_redteam_validation_lease = lambda: calls.append("release-validation")
    owner._holographic_orb = SimpleNamespace(shutdown=lambda: calls.append("close-orb"))
    owner.tray = SimpleNamespace(hide=lambda: calls.append("hide-tray"))
    for name in ("_shutdown_view_owners", "_hold_shutdown_views", "_retained_shutdown_workers",
                 "_retained_shutdown_custody", "_operator_stop_cleanup",
                 "_operator_stop_progress", "_operator_stop_finish"):
        setattr(owner, name, MethodType(getattr(main_window.MainWindow, name), owner))
    assert not action_worker.active_finite_actions()
    assert not breach_display.active_report_exports()
    assert not live_debug_panel.active_live_debug_streams()
    monkeypatch.setattr(action_worker, "_CLOSING", action_worker._CLOSING)
    monkeypatch.setattr(breach_display, "_REPORT_EXPORT_ADMISSION", breach_display._REPORT_EXPORT_ADMISSION)
    monkeypatch.setattr(live_debug_panel, "_STREAM_ADMISSION", live_debug_panel._STREAM_ADMISSION)
    monkeypatch.setattr(shutdown_retirement, "ShutdownRetirement", bounded_retirement)
    monkeypatch.setattr(QtWidgets.QApplication, "quit", lambda *_: calls.append("qt-quit"))
    monkeypatch.setattr(process_exit, "exit_after_operator_shutdown", lambda: calls.append("self-exit"))

    def wait_for(predicate):
        deadline = time.monotonic() + 5
        while not predicate() and time.monotonic() < deadline:
            app.processEvents()
            time.sleep(.005)
        assert predicate()

    try:
        main_window.MainWindow._terminate(owner)
        assert owner._termination_started and calls[0] == "durable-stop"
        wait_for(cleanup_entered.is_set)
        assert "self-exit" not in calls  # No UI-thread blocking or early finalizer.
        assert calls.index("critical-cleanup") < calls.index("owned-cleanup")
        if cleanup_completes:
            release_cleanup.set()
        else:
            clock[0] = 1.0  # Exercise the real owner deadline with an exact live worker.
        wait_for(lambda: owner._operator_stop_retirement._done)
        result = owner._operator_stop_result
        assert calls.count("self-exit") == 1
        assert result["forced"] is (not cleanup_completes)
        assert result["diagnostic_persisted"] is True
        if cleanup_completes:
            assert result["state"] == "retired" and not result["pending_workers"]
            assert calls[-4:] == ["close-orb", "hide-tray", "qt-quit", "self-exit"]
            assert "cleanup-complete" in calls
        else:
            assert result["state"] == "forced-incomplete"
            assert "owned-runtime-cleanup" in result["pending_workers"]
            assert all(name not in calls for name in ("close-orb", "hide-tray", "qt-quit"))
            assert "cleanup-complete" not in calls
    finally:
        release_cleanup.set()
        retirement = getattr(owner, "_operator_stop_retirement", None)
        if retirement is not None:
            workers = [row.worker for row in retirement._retained.values()]
            workers.append(retirement._diagnostic_thread)
            for worker in workers:
                if worker is not None and worker.ident is not None:
                    worker.join(3)
                    assert not worker.is_alive(), "Exact test-owned worker did not retire"
        owner.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
