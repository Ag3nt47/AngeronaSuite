"""Floating-point deadline handoffs retain the original owned-AI budget."""
from __future__ import annotations

from collections import OrderedDict
import math
import threading
from types import SimpleNamespace

import pytest

from angerona.core import ollama_lifecycle as ollama
from angerona.telemetry import process_snapshot_worker as worker


@pytest.fixture
def owned_scope(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(ollama, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    monkeypatch.setattr(ollama, "_owned_services", {})
    monkeypatch.setattr(ollama, "_startup_attempts", OrderedDict())
    monkeypatch.setattr(ollama, "_ai_shutdown", threading.Event())
    monkeypatch.setattr(ollama, "_startup_lock", threading.RLock())
    monkeypatch.setattr(ollama, "_startup_launch_lock", threading.Lock())
    monkeypatch.setattr(ollama, "_owned_stop_lock", threading.Lock())
    monkeypatch.setattr(worker, "on_gui_thread", lambda: False)
    return clock


def test_binary_boundary_rounding_does_not_reject_valid_one_second_scope(owned_scope):
    origin = math.nextafter(511.01, -math.inf)
    owned_scope[0] = origin
    assert (origin + 1.0) - origin == 1.0000000000000568
    assert ollama.observe_owned_ollama_process_identities(timeout=1.0) == ()


@pytest.mark.parametrize(("origin", "budget"), [
    (math.nextafter(511.01, -math.inf), 1.0),
    (512.0, 0.1),
    (2.0**30, 0.2),
])
def test_every_nested_registry_timeout_stays_within_original_budget(
    owned_scope, monkeypatch, origin, budget,
):
    owned_scope[0] = origin
    assert (origin + budget) - origin > budget
    actual_capture = ollama.capture_owned_ollama_process_scope
    received = []

    def capture(*, timeout):
        received.append(timeout)
        assert 0 < timeout <= budget
        return actual_capture(timeout=timeout)

    monkeypatch.setattr(ollama, "capture_owned_ollama_process_scope", capture)
    assert ollama.observe_owned_ollama_process_identities(timeout=budget) == ()
    assert len(received) == 2


def test_elapsed_time_reduces_nested_budget_instead_of_renewing_it(owned_scope, monkeypatch):
    actual_capture = ollama.capture_owned_ollama_process_scope
    received = []

    def capture(*, timeout):
        received.append(timeout)
        value = actual_capture(timeout=timeout)
        owned_scope[0] += 0.25
        return value

    monkeypatch.setattr(ollama, "capture_owned_ollama_process_scope", capture)
    assert ollama.observe_owned_ollama_process_identities(timeout=1.0) == ()
    assert received == [1.0, 0.75]


def test_expiry_during_registry_read_holds_and_releases_stop_custody(owned_scope, monkeypatch):
    actual_capture = ollama.capture_owned_ollama_process_scope

    def capture(*, timeout):
        value = actual_capture(timeout=timeout)
        owned_scope[0] = 101.0
        return value

    monkeypatch.setattr(ollama, "capture_owned_ollama_process_scope", capture)
    with pytest.raises(worker.InventoryWorkerError, match="observation deadline"):
        ollama.observe_owned_ollama_process_identities(timeout=1.0)
    assert ollama._owned_stop_lock.acquire(blocking=False)
    ollama._owned_stop_lock.release()


@pytest.mark.parametrize("timeout", [True, False, None, "1", 0, -1, math.nan, math.inf,
                                      math.nextafter(1.0, math.inf)])
def test_invalid_public_timeout_is_rejected_before_clock_or_lock(owned_scope, monkeypatch, timeout):
    def forbidden():
        pytest.fail("Invalid public timeout reached the monotonic clock")

    monkeypatch.setattr(ollama, "time", SimpleNamespace(monotonic=forbidden))
    with pytest.raises(worker.InventoryWorkerError, match="finite background owner"):
        ollama.observe_owned_ollama_process_identities(timeout=timeout)


@pytest.mark.parametrize("now", [math.nan, math.inf, -math.inf, -1.0, True, "100"])
def test_invalid_start_clock_is_not_converted_to_a_fresh_budget(owned_scope, now):
    owned_scope[0] = now
    with pytest.raises(worker.InventoryWorkerError, match="clock unavailable"):
        ollama.observe_owned_ollama_process_identities(timeout=1.0)


@pytest.mark.parametrize("now", [math.nan, math.inf, -math.inf, 99.75, True, "100", 101.0, 101.25])
def test_invalid_regressed_or_expired_clock_holds_before_registry_read(
    owned_scope, monkeypatch, now,
):
    observations = iter((100.0, now))
    monkeypatch.setattr(ollama, "time", SimpleNamespace(monotonic=lambda: next(observations)))
    monkeypatch.setattr(ollama, "capture_owned_ollama_process_scope",
                        lambda **_kwargs: pytest.fail("Invalid clock admitted a registry read"))
    with pytest.raises(worker.InventoryWorkerError, match="observation deadline"):
        ollama.observe_owned_ollama_process_identities(timeout=1.0)
    assert ollama._owned_stop_lock.acquire(blocking=False)
    ollama._owned_stop_lock.release()
