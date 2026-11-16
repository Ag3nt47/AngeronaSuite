"""Exact helper STOP dispatch under failed observation; no messages/native launch."""
from __future__ import annotations

import socket
import subprocess
import threading
from types import SimpleNamespace

import pytest

from angerona.core import mobile_cli_custody as custody
from angerona.gui.red_team_bridge import RedTeamBridge, RedTeamToolOwner
from test_signal_cli_retained_custody import fake_cli as fake_cli, invoke


@pytest.fixture(autouse=True)
def no_host_helpers(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Owned-helper fixtures grant no native, network or message authority")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)


def install_operator_child_dispatch(monkeypatch, fake_cli, *, failure=False):
    def operator_stop(_child):
        fake_cli["events"].append("operator-stop-job")
        if failure:
            raise OSError("inert constructor-retained Job lifetime changed")
        fake_cli["process"].terminated = True
    monkeypatch.setattr(custody.OwnedWindowsChild, "terminate_for_operator_stop", operator_stop,
                        raising=False)
    original_wait = custody.OwnedWindowsChild.wait_tree
    def wait_tree(child, timeout):
        if fake_cli["failure"] == "prepare":
            fake_cli["events"].append("unknown-cut-wait")
            raise OSError("inert original cut never became a retirement proof")
        return original_wait(child, timeout)
    monkeypatch.setattr(custody.OwnedWindowsChild, "wait_tree", wait_tree)


def test_signal_operator_stop_dispatches_exact_job_after_cut_failure_but_keeps_unknown_proof(fake_cli, monkeypatch):
    fake_cli["failure"] = "prepare"
    install_operator_child_dispatch(monkeypatch, fake_cli)
    from angerona.resilience import _selftest_environment as environment
    monkeypatch.setattr(environment, "_resume_windows_process", lambda _p: custody.request_operator_signal_stop())
    result = invoke()
    assert result[:2] == ("retirement-held", -1)
    assert fake_cli["events"].count("operator-stop-job") == 1
    assert "terminate-tree" not in fake_cli["events"]
    assert "native-close" not in fake_cli["events"] and "pipe-close" not in fake_cli["events"]
    owner, kind, external = next(iter(custody._HOLDS.values()))
    assert kind == "invocation" and external is True
    assert owner.child is not None and owner.process is fake_cli["process"]
    assert not owner.retirement_proven and not owner.retired
    assert custody.signal_cli_custody_snapshot()["pending_external_trees"] == 1


def test_signal_normal_cancellation_does_not_gain_operator_fallback(fake_cli, monkeypatch):
    fake_cli["failure"] = "prepare"
    install_operator_child_dispatch(monkeypatch, fake_cli)
    from angerona.resilience import _selftest_environment as environment
    monkeypatch.setattr(environment, "_resume_windows_process", lambda _p: custody.request_signal_stop())
    assert invoke()[0] == "retirement-held"
    assert "operator-stop-job" not in fake_cli["events"]
    assert "terminate-tree" not in fake_cli["events"]


def test_signal_changed_job_dispatch_failure_does_not_retry_regular_termination_or_close(fake_cli, monkeypatch):
    install_operator_child_dispatch(monkeypatch, fake_cli, failure=True)
    from angerona.resilience import _selftest_environment as environment
    monkeypatch.setattr(environment, "_resume_windows_process", lambda _p: custody.request_operator_signal_stop())
    assert invoke()[0] == "retirement-held"
    assert fake_cli["events"].count("operator-stop-job") == 1
    assert "terminate-tree" not in fake_cli["events"] and "native-close" not in fake_cli["events"]


def test_signal_operator_scope_cannot_cross_replaced_event_or_registry(fake_cli, monkeypatch):
    original = custody._Invocation(1.0, 128)
    custody._ACTIVE[id(original)] = original
    custody.request_operator_signal_stop()
    assert original._operator_stop_admitted()
    monkeypatch.setattr(custody, "_STOP", threading.Event())
    monkeypatch.setattr(custody, "_ACTIVE", {})
    replacement = custody._Invocation(1.0, 128)
    custody._ACTIVE[id(replacement)] = replacement
    custody.request_signal_stop()  # Ordinary cancellation of a fresh scope.
    assert not original._operator_stop_admitted()
    assert not replacement._operator_stop_admitted()
    custody._ACTIVE.clear()
    assert custody.resume_signal_admission()
    assert custody._OPERATOR_STOP_SCOPE is None


class NativeOwner:
    def __init__(self, *, cut_failure=True, dispatch_failure=False):
        self.events = []
        self.cut_failure = cut_failure
        self.dispatch_failure = dispatch_failure
    def prepare_tree_retirement(self, *, timeout):
        self.events.append("prepare")
        if self.cut_failure:
            raise OSError("inert cut query unavailable")
    def terminate(self):
        self.events.append("normal-terminate")
    def terminate_for_operator_stop(self):
        self.events.append("operator-stop-job")
        if self.dispatch_failure:
            raise OSError("inert constructor-retained owner changed")
    def wait_tree(self, *, timeout):
        self.events.append("wait-tree")
        if self.cut_failure:
            raise OSError("inert retirement signals remain unknown")
    def close(self):
        self.events.append("native-close")


def tool_owner(native, *, operator=False):
    owner = RedTeamToolOwner(lambda *_args: None, command=["inert-owned-tool"])
    owner._native_owner = native
    owner._capture_startup_native_cut = lambda _deadline: native.events.append("diagnostic-cut")
    if operator:
        owner._operator_stop.set()
    return owner


def test_red_team_operator_stop_dispatches_after_cut_failure_without_clean_receipt():
    native = NativeOwner()
    owner = tool_owner(native, operator=True)
    assert owner._stop_native_lifetime(1.0) is False
    assert native.events == ["prepare", "operator-stop-job", "wait-tree"]
    assert owner._native_termination_dispatched
    assert owner._native_owner is native and not owner._retired.is_set()
    assert owner._retirement_error == "OSError" and "native-close" not in native.events


def test_red_team_ordinary_close_still_holds_on_failed_cut():
    native = NativeOwner()
    owner = tool_owner(native)
    assert owner._stop_native_lifetime(1.0) is False
    assert native.events == ["prepare"]
    assert not owner._native_termination_dispatched and not owner._retired.is_set()


def test_red_team_optional_observation_lock_cannot_veto_accepted_operator_job_stop():
    native = NativeOwner()
    owner = tool_owner(native, operator=True)
    owner._startup_native_capture_lock.acquire()
    try:
        owner._terminate_owned_native(.001)
    finally:
        owner._startup_native_capture_lock.release()
    assert native.events == ["operator-stop-job"]
    assert owner._native_termination_dispatched
    assert owner._startup_native_capture_error == "NativeDiagnosticBusyAtOperatorStop"
    assert not owner._retired.is_set()


def test_red_team_changed_owner_does_not_retry_through_normal_termination():
    native = NativeOwner(dispatch_failure=True)
    owner = tool_owner(native, operator=True)
    assert owner._stop_native_lifetime(1.0) is False
    assert native.events == ["prepare", "operator-stop-job"]
    assert not owner._native_termination_dispatched and not owner._retired.is_set()
    assert "native-close" not in native.events


@pytest.mark.parametrize("accepted", [False, True])
def test_bridge_latches_operator_fallback_only_after_parent_accepted_stop(accepted):
    owner = tool_owner(NativeOwner())
    calls = []
    bridge = SimpleNamespace(owner=owner, parent_view=SimpleNamespace(_termination_started=accepted),
                             _timer=SimpleNamespace(start=lambda: calls.append("poll")), _closing=False)
    RedTeamBridge.request_shutdown(bridge)
    assert owner._operator_stop.is_set() is accepted
    assert bridge._closing and calls == ["poll"]
