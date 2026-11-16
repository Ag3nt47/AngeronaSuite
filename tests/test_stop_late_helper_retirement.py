"""Current helper ownership can release STOP after an earlier false sample."""
from __future__ import annotations

import socket
import subprocess
import threading
import time

import pytest

from angerona.app import AngeronaApp
from angerona.core import mobile_cli_custody as signal
from angerona.core import ollama_lifecycle as ai


@pytest.fixture
def proof(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Late-retirement proof grants no host, process or native authority")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(signal, "_LOCK", threading.RLock())
    monkeypatch.setattr(signal, "_STOP", threading.Event())
    monkeypatch.setattr(signal, "_ACTIVE", {})
    monkeypatch.setattr(signal, "_CALLS", {})
    monkeypatch.setattr(signal, "_HOLDS", {})
    signal._STOP.set()
    ai_state = [True]
    monkeypatch.setattr(ai, "owned_ollama_retirement_proven", lambda: ai_state[0])
    owner = object.__new__(AngeronaApp)
    owner._shutdown_requested = threading.Event()
    owner._shutdown_requested.set()
    owner._shutdown_custody_captured = True
    owner._critical_cleanup_observed = True
    owner._critical_signal_done = False  # Earlier three-second worker sample.
    owner._critical_ai_done = False
    owner._shutdown_fences_incomplete = False
    owner._critical_ai_error_type = "HistoricalConfiguredModelUnloadFailure"
    owner._capture_shutdown_custody = forbidden
    owner._shutdown_critical_owned = forbidden
    owner._signal_retirement_outcome = forbidden
    return owner, ai_state


def test_signal_retiring_after_initial_wait_releases_custody_without_critical_rerun(proof):
    owner, _ = proof
    invocation = object()
    signal._ACTIVE[id(invocation)] = invocation
    assert owner.shutdown_companions_retired() is False
    # The owned reader/worker finishes later (e.g. second four). No timer,
    # native query, authority request or second critical cleanup is necessary.
    signal._ACTIVE.clear()
    assert owner._critical_signal_done is False
    assert owner.shutdown_companions_retired() is True


def test_late_owned_ai_retirement_uses_current_memory_and_keeps_unload_diagnostic(proof):
    owner, ai_state = proof
    ai_state[0] = False
    assert owner.shutdown_companions_retired() is False
    ai_state[0] = True
    assert owner._critical_ai_done is False
    assert owner.shutdown_companions_retired() is True
    assert owner._critical_ai_error_type == "HistoricalConfiguredModelUnloadFailure"


def test_full_call_preflight_and_external_holds_still_block_late_completion(proof):
    owner, _ = proof
    lease = object()
    signal._CALLS[id(lease)] = lease
    assert owner.shutdown_companions_retired() is False
    signal._CALLS.clear()
    signal._HOLDS[id(lease)] = (lease, "invocation", True)
    assert owner.shutdown_companions_retired() is False
    signal._HOLDS[id(lease)] = (lease, "executable-pin", False)
    assert owner.shutdown_companions_retired() is True


@pytest.mark.parametrize("hold", [(object(), "invocation", "unknown"),
                                 (object(), "unknown-kind", False), (object(),)])
def test_malformed_signal_custody_is_held(proof, hold):
    signal._HOLDS[1] = hold
    assert signal.signal_retirement_proven_memory() is False
    assert proof[0].shutdown_companions_retired() is False


def test_admission_must_actually_be_stopped(proof):
    signal._STOP.clear()
    assert signal.signal_retirement_proven_memory() is False
    assert proof[0].shutdown_companions_retired() is False


def test_failed_fence_remains_held_even_when_both_helpers_later_retire(proof):
    owner, _ = proof
    owner._shutdown_fences_incomplete = True
    assert signal.signal_retirement_proven_memory() is True
    assert owner.shutdown_companions_retired() is False


def test_busy_registry_lock_returns_without_waiting_on_the_gui_caller(proof):
    owner, _ = proof
    entered, release = threading.Event(), threading.Event()
    def hold_registry():
        with signal._LOCK:
            entered.set()
            assert release.wait(3)
    thread = threading.Thread(target=hold_registry)
    thread.start()
    try:
        assert entered.wait(1)
        started = time.perf_counter()
        assert signal.signal_retirement_proven_memory() is False
        assert owner.shutdown_companions_retired() is False
        assert time.perf_counter() - started < .5
        assert thread.is_alive() and not release.is_set()
    finally:
        release.set()
        thread.join(3)
        assert not thread.is_alive()
