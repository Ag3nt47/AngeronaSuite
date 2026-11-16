"""Source STOP App wiring: separate authority and exact retained companion proof."""
from __future__ import annotations

import copy
import socket
import subprocess
import threading
from types import MethodType, SimpleNamespace

import pytest

import angerona.app as app_module
from angerona.app import AngeronaApp
from angerona.core import ollama_lifecycle
from angerona.resilience import shutdown_token, source_stop


class SourceContext:
    epoch = "a" * 32

    def __init__(self, calls):
        self.calls = calls
        self.stopped = False
        self.admitted = True

    def admission_current(self):
        return self.admitted

    def respawn_allowed(self):
        return self.admitted and not self.stopped

    def is_stop_requested(self):
        return self.stopped

    def request_stop(self, *, reason):
        self.calls.append("source-stop")
        self.stopped = True
        return {"reason": reason}

    def mark_retired(self):
        self.calls.append("source-retired")
        return {"retired": True}


class ResilienceOwner:
    def __init__(self, calls):
        self.calls, self.custody = calls, object()
        self.closed = False
        self.held = False

    def capture_retirement_custody(self):
        self.calls.append("capture")
        return self.custody

    def request_stop(self):
        self.calls.append("cancel-peers")

    def stop(self, *, terminate_children):
        assert terminate_children is True
        self.calls.append("retire-peers")
        self.closed = True
        return not self.held

    def shutdown_retired(self, custody):
        assert custody is self.custody
        return self.closed and not self.held


class BlackBoxOwner:
    owns_descendants = True

    def __init__(self, calls):
        self.calls, self.close_error = calls, False
        self.receipt = dict(cut_ready=False, dispatched=False, signals_proven=False,
                            handles_closed=False, close_held=False, error_type="")

    def prepare_tree_retirement(self, *, timeout):
        self.calls.append("capture-blackbox")
        self.receipt["cut_ready"] = True

    def terminate(self):
        self.calls.append("stop-blackbox")
        self.receipt["dispatched"] = True

    def wait(self, *, timeout):
        self.calls.append("wait-blackbox-root")
        return 0

    def wait_tree(self, *, timeout):
        self.calls.append("wait-blackbox-tree")
        self.receipt["signals_proven"] = True

    def close(self):
        if self.close_error:
            self.receipt["close_held"] = True
            raise OSError("inert exact handle close failure")
        self.calls.append("close-blackbox")
        self.receipt["handles_closed"] = True

    def tree_retirement_snapshot(self):
        return dict(self.receipt)


@pytest.fixture
def app_owner(monkeypatch):
    calls = []

    def forbidden(*_args, **_kwargs):
        raise AssertionError("App source STOP tests grant no host/process/network authority")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(ollama_lifecycle, "shutdown_ollama",
                        lambda *_args, **_kwargs: calls.append("ai-cleanup"))
    monkeypatch.setattr(ollama_lifecycle, "owned_ollama_retirement_proven", lambda: True)
    from angerona.core import mobile_cli_custody
    monkeypatch.setattr(mobile_cli_custody, "signal_retirement_proven_memory", lambda: True)
    monkeypatch.setattr(source_stop, "source_runtime_admitted", lambda: False)
    for name in ("request_operator_stop", "clear_standdown", "signal_external_watchdog_stop"):
        monkeypatch.setattr(shutdown_token, name, forbidden)
    monkeypatch.setattr(shutdown_token, "is_standdown_requested", forbidden)
    owner = object.__new__(AngeronaApp)
    owner._source_stop_context = SourceContext(calls)
    owner._shutdown_requested = threading.Event()
    owner._resilience = ResilienceOwner(calls)
    owner._process_snapshot_lifecycle = None
    owner._blackbox_proc = None
    owner._runtime_healer = None
    owner.config = SimpleNamespace(ollama_host="http://localhost:11434", ollama_model="inert",
                                   autostart_enabled=False, blackbox_enabled=True, eco_mode=True)
    owner.manager = SimpleNamespace(modules={})
    owner._record_ai_retirement_outcome = lambda: calls.append("ai-diagnostic")
    owner._signal_retirement_outcome = lambda: dict(schema=1, active_invocations=0,
        pending_external_trees=0, held_resources=0, launch_quiescent=True)

    def cancel():
        calls.append("fence-work")
        owner._shutdown_requested.set()
        if owner._resilience is not None:
            owner._resilience.request_stop()

    owner._cancel_owned_work = cancel
    return owner, calls


def test_source_stop_captures_before_source_command_and_all_fences_without_admin_token(app_owner):
    owner, calls = app_owner
    owner.prepare_shutdown()
    assert calls == ["capture", "source-stop", "fence-work", "cancel-peers"]
    assert owner._operator_stop_recorded and owner._shutdown_requested.is_set()
    assert owner._shutdown_resilience_custody == ((owner._resilience, owner._resilience.custody),)


def test_failed_authorization_keeps_work_admission_open_and_preserves_owner(app_owner):
    owner, calls = app_owner
    original = owner._resilience
    def fail_command(*, reason):
        calls.append("source-command-failed")
        raise PermissionError("inert session command rejected")
    owner._source_stop_context.request_stop = fail_command
    with pytest.raises(PermissionError):
        owner.prepare_shutdown()
    assert "fence-work" not in calls and "cancel-peers" not in calls
    assert not owner._shutdown_requested.is_set()
    assert getattr(owner, "_operator_stop_recorded", False) is False
    assert owner._resilience is original


def test_query_capture_failure_does_not_veto_stop_for_other_owners(app_owner):
    owner, calls = app_owner
    original = owner._resilience
    def fail_capture():
        calls.append("capture-failed")
        raise OSError("inert query custody unavailable")
    original.capture_retirement_custody = fail_capture
    owner.prepare_shutdown()
    assert calls == ["capture-failed", "source-stop", "fence-work", "cancel-peers"]
    assert owner._shutdown_resilience_custody == ((original, None),)
    assert "capture-resilience:OSError" in owner._shutdown_custody_capture_errors
    owner._shutdown_critical_owned()
    assert "retire-peers" in calls
    assert owner.shutdown_companions_retired() is False


def test_blackbox_capture_failure_preserves_owner_and_does_not_block_other_shutdown(app_owner):
    owner, calls = app_owner
    box = owner._blackbox_proc = BlackBoxOwner(calls)
    def fail_cut(*, timeout):
        calls.append("capture-blackbox-failed")
        raise OSError("inert exact Job query failed")
    box.prepare_tree_retirement = fail_cut
    owner.prepare_shutdown()
    assert owner._shutdown_blackbox_custody == (box,)
    assert "source-stop" in calls and "fence-work" in calls
    owner._shutdown_critical_owned()
    assert "stop-blackbox" in calls and "retire-peers" in calls and "ai-cleanup" in calls
    assert owner.shutdown_companions_retired() is False


def test_missing_source_context_never_falls_back_to_installed_authority(app_owner, monkeypatch):
    owner, calls = app_owner
    owner._source_stop_context = None
    monkeypatch.setattr(source_stop, "source_runtime_admitted", lambda: True)
    with pytest.raises(RuntimeError, match="no admitted"):
        owner.prepare_shutdown()
    assert calls == ["capture"] and not owner._shutdown_requested.is_set()


def test_protected_stop_keeps_separate_control_authority(app_owner, monkeypatch):
    owner, calls = app_owner
    owner._source_stop_context = None
    monkeypatch.setattr(shutdown_token, "request_operator_stop", lambda: calls.append("protected-stop"))
    monkeypatch.setattr(shutdown_token, "signal_external_watchdog_stop", lambda: calls.append("external-stop"))
    owner.prepare_shutdown()
    assert calls == ["capture", "protected-stop", "fence-work", "cancel-peers", "external-stop"]


@pytest.fixture
def startup_ui(monkeypatch):
    class Signal:
        def __init__(self):
            self.callback = None
        def connect(self, callback):
            self.callback = callback

    class Timer:
        shots = []
        def __init__(self, owner):
            self.timeout = Signal()
            self.active = False
        def setInterval(self, interval):
            self.interval = interval
        def start(self):
            self.active = True
        def stop(self):
            self.active = False
        @classmethod
        def singleShot(cls, delay, callback):
            cls.shots.append((delay, callback))

    from PySide6 import QtCore
    monkeypatch.setattr(QtCore, "QTimer", Timer)
    monkeypatch.setenv("ANGERONA_RESILIENCE", "1")
    monkeypatch.delenv("ANGERONA_SUPERVISED_RECOVERY", raising=False)
    return Signal, Timer


def wire_startup(owner, calls, signal_type):
    owner.window = SimpleNamespace(show=lambda: calls.append("show"), _panel_reveal=None,
                                    _terminate=lambda: calls.append("terminate"))
    owner.qt = SimpleNamespace(aboutToQuit=signal_type())
    owner._schedule_dashboard_ready = lambda: calls.append("schedule-ready")
    owner._start_recorder_integrity = lambda: calls.append("integrity-start")


def test_source_start_publishes_exact_epoch_without_clearing_installed_stop(app_owner, startup_ui, monkeypatch):
    owner, calls = app_owner
    signal_type, timer_type = startup_ui
    wire_startup(owner, calls, signal_type)
    monkeypatch.delenv(source_stop.SOURCE_SESSION_ENV, raising=False)
    assert owner.start() is True
    import os
    assert os.environ[source_stop.SOURCE_SESSION_ENV] == owner._source_stop_context.epoch
    assert calls == ["show", "schedule-ready", "integrity-start"]
    assert owner._operator_stop_timer.active
    owner._source_stop_context.stopped = True
    owner._honor_operator_stop()
    assert calls[-1] == "terminate" and not owner._operator_stop_timer.active
    assert owner._startup_cancelled()


@pytest.mark.parametrize("held", ["stopped", "invalid"])
def test_source_recovery_never_clears_or_rotates_a_held_epoch(app_owner, startup_ui, held):
    owner, calls = app_owner
    wire_startup(owner, calls, startup_ui[0])
    if held == "stopped":
        owner._source_stop_context.stopped = True
        assert owner.start() is False
    else:
        owner._source_stop_context.admitted = False
        with pytest.raises(RuntimeError, match="unavailable"):
            owner.start()
    assert calls == []


def test_protected_start_still_clears_its_authenticated_token(app_owner, startup_ui, monkeypatch):
    owner, calls = app_owner
    owner._source_stop_context = None
    wire_startup(owner, calls, startup_ui[0])
    monkeypatch.setattr(shutdown_token, "clear_standdown", lambda *, strict: calls.append(("clear-protected", strict)))
    monkeypatch.setattr(shutdown_token, "is_standdown_requested", lambda: False)
    assert owner.start() is True
    assert calls[0] == ("clear-protected", True)
    assert not hasattr(owner, "_operator_stop_timer")


@pytest.mark.parametrize("with_source", [False, True])
def test_resilience_receives_source_context_only_when_admitted(app_owner, monkeypatch, with_source):
    owner, calls = app_owner
    if not with_source:
        owner._source_stop_context = None
    owner._startup_cancelled = lambda: False
    owner._startup_loading_token = None
    owner._source_update_controller = None
    monkeypatch.setattr(app_module, "current_platform", lambda: "windows")
    monkeypatch.setenv("ANGERONA_RESILIENCE", "1")
    from angerona.resilience import manager
    class StopAfterCapture(BaseException):
        pass
    captured = []
    def fake_start(*args, **kwargs):
        captured.append(kwargs)
        if with_source:
            import os
            assert os.environ[source_stop.SOURCE_SESSION_ENV] == owner._source_stop_context.epoch
        raise StopAfterCapture()
    monkeypatch.setattr(manager, "start_resilience", fake_start)
    owner.bus = object()
    with pytest.raises(StopAfterCapture):
        owner._load_modules()
    assert len(captured) == 1
    if with_source:
        assert captured[0]["source_stop_context"] is owner._source_stop_context
    else:
        assert "source_stop_context" not in captured[0]


def test_direct_blackbox_close_failure_is_retained_while_other_companions_still_stop(app_owner):
    owner, calls = app_owner
    box = owner._blackbox_proc = BlackBoxOwner(calls)
    box.close_error = True
    owner.prepare_shutdown()
    owner._shutdown_critical_owned()
    assert "stop-blackbox" in calls and "retire-peers" in calls and "ai-diagnostic" in calls
    assert owner._blackbox_proc is box
    assert "blackbox:OSError" in owner._critical_companion_errors
    assert owner.shutdown_companions_retired() is False
    assert box.receipt["signals_proven"] and not box.receipt["handles_closed"]


def test_resilience_false_retirement_is_not_converted_to_success(app_owner):
    owner, calls = app_owner
    owner._resilience.held = True
    owner.prepare_shutdown()
    owner._shutdown_critical_owned()
    assert "retire-peers" in calls
    assert "resilience:retirement-unproven" in owner._critical_companion_errors
    assert owner.shutdown_companions_retired() is False


def test_exact_blackbox_receipt_and_retained_manager_custody_enable_cached_completion(app_owner):
    owner, calls = app_owner
    owner._blackbox_proc = BlackBoxOwner(calls)
    box = owner._blackbox_proc
    owner.prepare_shutdown()
    owner._shutdown_critical_owned()
    assert owner._blackbox_proc is None
    assert owner._shutdown_blackbox_custody == (box,)
    assert owner.shutdown_companions_retired() is True
    def forbidden_capture():
        pytest.fail("GUI cached proof attempted a new native custody capture")
    owner._capture_shutdown_custody = forbidden_capture
    assert owner.shutdown_companions_retired() is True
    late = ResilienceOwner(calls)
    owner._resilience = late
    assert owner.shutdown_companions_retired() is False


def test_inventory_retired_signal_does_not_replace_actual_owner_thread_exit():
    ready, release = threading.Event(), threading.Event()
    retired = threading.Event()
    def owner_loop():
        retired.set()
        ready.set()
        assert release.wait(5)
    thread = threading.Thread(target=owner_loop)
    owner = SimpleNamespace(_retired=retired, _thread=thread)
    thread.start()
    try:
        assert ready.wait(1)
        assert AngeronaApp._inventory_retirement_proven(owner) is False
    finally:
        release.set()
        thread.join(3)
    assert not thread.is_alive()
    assert AngeronaApp._inventory_retirement_proven(owner) is True


def test_epoch_receipt_requires_full_gui_companion_and_engine_retirement(app_owner):
    owner, calls = app_owner
    owner.prepare_shutdown()
    owner._shutdown_critical_owned()
    owner._optional_owned_drained = True
    owner._engine_threads_retired = lambda: True
    valid = dict(state="retired", forced=False, pending_workers=[], pending_custody=[])
    for invalid in (
        dict(valid, state="forced-incomplete", forced=True),
        dict(valid, pending_workers=["inert-pending-thread"]),
        dict(valid, pending_custody=["inert-native-hold"]),
    ):
        with pytest.raises(RuntimeError, match="unproven"):
            owner.finalize_source_stop(invalid)
        assert "source-retired" not in calls
    owner.finalize_source_stop(copy.deepcopy(valid))
    assert calls[-1] == "source-retired" and owner._source_stop_epoch_retired


@pytest.mark.parametrize("broken", ["recorder-integrity", "community-tools", "breach-response",
                                   "owned-ai", "signal-cli", "resilience"])
def test_one_failed_fence_does_not_block_other_owners_or_accepted_stop(app_owner, monkeypatch, broken):
    owner, calls = app_owner
    owner._cancel_owned_work = MethodType(AngeronaApp._cancel_owned_work, owner)
    phases = ["recorder-integrity", "community-tools", "breach-response", "owned-ai", "signal-cli", "resilience"]
    def operation(phase):
        def run():
            calls.append("fence:" + phase)
            if phase == broken:
                raise RuntimeError("inert " + phase + " fence failed")
        return run
    owner.recorder_integrity_runtime = SimpleNamespace(request_stop=operation("recorder-integrity"))
    owner.manager._curated_tools_controller = SimpleNamespace(shutdown=operation("community-tools"))
    owner._breach_state_controller = SimpleNamespace(request_stop=operation("breach-response"))
    monkeypatch.setattr(ollama_lifecycle, "begin_ollama_shutdown", operation("owned-ai"))
    from angerona.core import mobile_cli_custody
    monkeypatch.setattr(mobile_cli_custody, "request_signal_stop", operation("signal-cli"))
    owner._resilience.request_stop = operation("resilience")
    owner.prepare_shutdown()
    assert calls[:2] == ["capture", "source-stop"]
    assert [call for call in calls if call.startswith("fence:")] == ["fence:" + phase for phase in phases]
    assert owner._operator_stop_recorded and owner._shutdown_requested.is_set()
    assert owner._shutdown_fences_incomplete is True
    assert owner._shutdown_fence_errors == (broken + ":RuntimeError",)
    # All native-owner receipts may complete while one admitted fence failed.
    # That must still remain an explicit incomplete STOP, never a green receipt.
    owner._shutdown_critical_owned()
    assert owner._resilience.closed and owner._critical_ai_done and owner._critical_signal_done
    assert owner.shutdown_companions_retired() is False
    assert broken + ":RuntimeError" in owner._critical_companion_errors


def test_missing_fence_method_is_recorded_and_does_not_abort_other_fences(app_owner, monkeypatch):
    owner, calls = app_owner
    owner._cancel_owned_work = MethodType(AngeronaApp._cancel_owned_work, owner)
    owner.recorder_integrity_runtime = object()
    monkeypatch.setattr(ollama_lifecycle, "begin_ollama_shutdown", lambda: calls.append("begin-ai"))
    from angerona.core import mobile_cli_custody
    monkeypatch.setattr(mobile_cli_custody, "request_signal_stop", lambda: calls.append("stop-signal"))
    owner.prepare_shutdown()
    assert "begin-ai" in calls and "stop-signal" in calls and "cancel-peers" in calls
    assert owner._shutdown_fence_errors == ("recorder-integrity:AttributeError",)
    assert owner._operator_stop_recorded and owner._shutdown_fences_incomplete


def test_protected_auxiliary_signal_failure_preserves_accepted_stop_and_continues(app_owner, monkeypatch):
    owner, calls = app_owner
    owner._source_stop_context = None
    monkeypatch.setattr(shutdown_token, "request_operator_stop", lambda: calls.append("protected-stop"))
    def signal_failure():
        calls.append("external-signal-failed")
        raise OSError("inert external signal failed")
    monkeypatch.setattr(shutdown_token, "signal_external_watchdog_stop", signal_failure)
    owner.prepare_shutdown()
    assert calls == ["capture", "protected-stop", "fence-work", "cancel-peers", "external-signal-failed"]
    assert owner._operator_stop_recorded and owner._shutdown_requested.is_set()
    assert owner._shutdown_fences_incomplete is True
    assert owner._shutdown_fence_errors == ("external-watchdog:OSError",)
