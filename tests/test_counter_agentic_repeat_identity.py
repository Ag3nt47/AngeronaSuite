from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import pytest

from angerona.modules import counter_agentic


@pytest.fixture
def watch(monkeypatch):
    """Synthetic records only: no Config, host process or socket lookup."""
    rows, events, approval_calls = [], [], []
    clock, birth = [1000.0], [1234.5]

    class Process:
        def __init__(self, pid):
            self.pid = pid

        def create_time(self):
            return birth[0]

        def name(self):
            return "fixture.exe"

        def exe(self):
            return "C:/fixture/fixture.exe"

    monkeypatch.setattr(counter_agentic, "_configured_inference_port", lambda: (
        11434, "http://127.0.0.1:11434", "",
    ))
    monkeypatch.setattr(counter_agentic, "list_connections", lambda: rows)
    monkeypatch.setattr(counter_agentic, "psutil", SimpleNamespace(Process=Process))
    monkeypatch.setattr(counter_agentic, "policy_snapshot", lambda: ())
    monkeypatch.setattr(counter_agentic, "time", SimpleNamespace(time=lambda: clock[0]))

    def approval(*args, **kwargs):
        approval_calls.append((args, kwargs))
        return False

    monkeypatch.setattr(counter_agentic, "is_digest_pinned_allowed", approval)
    module = counter_agentic.CounterAgenticModule()
    module.emit = lambda *args, **kwargs: events.append((args, kwargs))
    return SimpleNamespace(module=module, rows=rows, events=events, clock=clock,
                           birth=birth, process_type=Process, approval_calls=approval_calls)


def _row(pid=4242, *, status="ESTABLISHED", local="127.0.0.1:11434", remote=""):
    return dict(pid=pid, status=status, laddr=local, raddr=remote)


@pytest.mark.parametrize("second", [PermissionError("second birth read unavailable"), 1235.0])
def test_second_birth_read_failure_cannot_approve_or_group(watch, monkeypatch, second):
    class Incomplete(watch.process_type):
        def __init__(self, pid):
            super().__init__(pid)
            self.reads = 0

        def create_time(self):
            self.reads += 1
            if self.reads == 1:
                return 1234.5
            if isinstance(second, Exception):
                raise second
            return second

    monkeypatch.setattr(counter_agentic.psutil, "Process", Incomplete)
    monkeypatch.setattr(counter_agentic, "is_digest_pinned_allowed", lambda *a, **k: (
        pytest.fail("incomplete process identity reached digest approval")
    ))
    watch.rows.append(_row())
    first = watch.module._watch_ollama_port()
    watch.rows[0]["raddr"] = "127.0.0.1:50001"
    second_receipt = watch.module._watch_ollama_port()

    assert not first.complete and not second_receipt.complete
    assert first.identity_failures == second_receipt.identity_failures == 1
    assert first.unexpected == second_receipt.unexpected == 1
    assert len(watch.events) == 2
    assert watch.module._port_generation_alerted == {}
    for _args, details in watch.events:
        assert details["process_identity_complete"] is False
        assert details["process_create_time"] is None and details["process_path"] == ""
        assert details["identity_error"]
        assert details["response_authorized"] is False


@pytest.mark.parametrize("birth", [float("nan"), float("inf"), 0.0, -1.0])
def test_invalid_birth_cannot_become_verified_identity(watch, birth):
    watch.birth[0] = birth
    watch.rows.append(_row())
    receipt = watch.module._watch_ollama_port()
    assert not receipt.complete and receipt.identity_failures == 1
    assert watch.approval_calls == []
    assert watch.module._port_generation_alerted == {}
    assert watch.events[0][1]["process_identity_complete"] is False


def test_role_transition_is_immediate_with_unchanged_endpoint_key(watch):
    watch.rows.append(_row())
    watch.module._watch_ollama_port()
    expected_key = tuple(watch.module._port_alerted)

    watch.clock[0] += 1
    watch.rows[0]["status"] = "LISTEN"
    watch.module._watch_ollama_port()
    watch.clock[0] += 1
    watch.rows[0]["status"] = "CLOSE_WAIT"
    watch.module._watch_ollama_port()

    assert [details["socket_role"] for _args, details in watch.events] == [
        "local-port-match", "listener", "local-port-match",
    ]
    assert tuple(watch.module._port_alerted) == expected_key
    assert len(watch.module._port_generation_alerted) == 2
    assert all(details["response_authorized"] is False for _args, details in watch.events)


def test_pruning_short_endpoint_window_preserves_latest_role(watch):
    watch.rows.append(_row())
    watch.module._watch_ollama_port()
    watch.clock[0] += 1
    watch.rows[0]["status"] = "LISTEN"
    watch.module._watch_ollama_port()

    # The old 240-second housekeeping TTL cannot forget LISTEN while its
    # previously reported non-listener generation key is still held hourly.
    watch.clock[0] = 1000.0 + 4 * counter_agentic._STALE_AFTER + 2
    watch.module._prune()
    assert len(watch.module._port_endpoint_roles) == 1
    watch.rows[0]["status"] = "ESTABLISHED"
    watch.module._watch_ollama_port()

    assert [details["socket_role"] for _args, details in watch.events] == [
        "local-port-match", "listener", "local-port-match",
    ]


def test_pid_generation_change_reports_immediately(watch):
    watch.rows.append(_row())
    watch.module._watch_ollama_port()
    watch.birth[0] += 1
    watch.module._watch_ollama_port()
    assert len(watch.events) == 2
    assert len(watch.module._port_generation_alerted) == 2
    assert watch.events[0][1]["process_create_time"] != watch.events[1][1]["process_create_time"]


def test_suppressed_count_explicitly_measures_emission_opportunities(watch):
    watch.rows.append(_row())
    watch.module._watch_ollama_port()
    for stamp in (1061.0, 1070.0):
        watch.clock[0] = stamp
        watch.module._watch_ollama_port()
    watch.clock[0] = 1000.0 + counter_agentic._PORT_GENERATION_REALERT_AFTER
    watch.module._watch_ollama_port()

    assert len(watch.rows) == 1 and len(watch.events) == 2
    assert watch.events[-1][1]["suppressed_repeats"] == 2
    assert watch.events[-1][1]["suppressed_repeats_unit"] == "emission-opportunities"


def test_role_eviction_invalidates_older_hourly_history(watch, monkeypatch):
    monkeypatch.setattr(counter_agentic, "_PORT_ENDPOINT_KEYS_MAX", 2)
    # Multiple exact endpoints share one generation/peer/role history, so
    # the generation-key bound alone cannot preserve every latest role.
    target = _row(remote="127.0.0.1:50000")
    related = _row(remote="127.0.0.1:50001")
    watch.rows.extend((target, related))
    watch.module._watch_ollama_port()
    assert len(watch.module._port_generation_alerted) == 1
    target_key = next(key for key in watch.module._port_alerted if key[-1] == target["raddr"])

    watch.clock[0] += 1
    watch.rows[:] = [dict(target, status="LISTEN")]
    watch.module._watch_ollama_port()
    assert len(watch.module._port_generation_alerted) == 2
    for pid in (5000, 5001):
        watch.clock[0] += 1
        watch.rows[:] = [_row(pid=pid)]
        watch.module._watch_ollama_port()
    assert target_key not in watch.module._port_endpoint_roles
    assert all(key[0] != target["pid"] for key in watch.module._port_generation_alerted)

    before = len(watch.events)
    watch.rows[:] = [target]
    watch.module._watch_ollama_port()
    assert len(watch.events) == before + 1
    assert watch.events[-1][1]["socket_role"] == "local-port-match"
    assert len(watch.module._port_endpoint_roles) == len(watch.module._port_alerted) == 2


def test_endpoint_and_generation_caches_are_bounded_and_pruned_together(watch, monkeypatch):
    monkeypatch.setattr(counter_agentic, "_PORT_GENERATION_KEYS_MAX", 3)
    monkeypatch.setattr(counter_agentic, "_PORT_ENDPOINT_KEYS_MAX", 4)
    watch.rows.extend(_row(pid=pid) for pid in range(5000, 5010))
    watch.module._watch_ollama_port()

    assert len(watch.events) == 10
    assert len(watch.module._port_generation_alerted) == 3
    assert len(watch.module._port_alerted) == len(watch.module._port_endpoint_roles) == 4
    assert set(watch.module._port_endpoint_roles) == set(watch.module._port_alerted)
    watch.clock[0] += 2 * counter_agentic._PORT_GENERATION_REALERT_AFTER + 1
    watch.module._prune()
    assert watch.module._port_generation_alerted == {}
    assert watch.module._port_alerted == watch.module._port_endpoint_roles == {}


def test_policy_edits_reset_retained_observation_episodes(watch, monkeypatch):
    pinned = (("fixture.exe", "C:/fixture/fixture.exe", "a" * 64),)
    policy, snapshot_calls = [()], []

    def snapshot():
        snapshot_calls.append(policy[0])
        return policy[0]

    def approval(name, executable, *, policy):
        assert name == "fixture.exe" and executable == "C:/fixture/fixture.exe"
        return policy == pinned

    monkeypatch.setattr(counter_agentic, "policy_snapshot", snapshot)
    monkeypatch.setattr(counter_agentic, "is_digest_pinned_allowed", approval)
    target, other = _row(), _row(pid=4343)
    watch.rows.extend((target, other))
    watch.module._watch_ollama_port()
    originals = deepcopy(watch.events)
    assert len(originals) == 2

    policy[0] = pinned
    watch.clock[0] += 1
    watch.rows[:] = [target]
    approved = watch.module._watch_ollama_port()
    assert approved.complete and approved.unexpected == 0
    assert watch.module._port_alerted == watch.module._port_endpoint_roles == {}
    assert watch.module._port_generation_alerted == {}
    assert watch.events == originals

    policy[0] = ()
    watch.clock[0] += 1
    watch.rows[:] = [target, other]
    revoked = watch.module._watch_ollama_port()
    assert revoked.complete and revoked.unexpected == 2
    assert len(watch.events) == 4 and watch.events[:2] == originals
    assert len(snapshot_calls) == 3  # One immutable policy per sweep.
    assert all(details["response_authorized"] is False for _args, details in watch.events)


def test_verified_approval_resolves_only_its_subject_without_policy_change(watch, monkeypatch):
    pinned = (("fixture.exe", "C:/fixture/fixture.exe", "a" * 64),)
    digest_matches = [False]
    monkeypatch.setattr(counter_agentic, "policy_snapshot", lambda: pinned)

    def approval(name, executable, *, policy):
        assert policy == pinned
        assert name == "fixture.exe" and executable == "C:/fixture/fixture.exe"
        return digest_matches[0]

    monkeypatch.setattr(counter_agentic, "is_digest_pinned_allowed", approval)
    target, other = _row(), _row(pid=4343)
    watch.rows.extend((target, other))
    watch.module._watch_ollama_port()
    originals = deepcopy(watch.events)
    assert len(originals) == 2

    digest_matches[0] = True
    watch.clock[0] += 1
    watch.rows[:] = [target]
    approved = watch.module._watch_ollama_port()
    assert approved.complete and approved.unexpected == 0
    assert all(key[0] == other["pid"] for key in watch.module._port_alerted)
    assert all(key[0] == other["pid"] for key in watch.module._port_generation_alerted)
    assert len(watch.module._port_alerted) == len(watch.module._port_generation_alerted) == 1
    assert watch.events == originals

    digest_matches[0] = False
    watch.clock[0] += 1
    renewed = watch.module._watch_ollama_port()
    assert renewed.complete and renewed.unexpected == 1
    assert len(watch.events) == 3 and watch.events[:2] == originals
    assert watch.events[-1][1]["pid"] == target["pid"]
    assert all(details["response_authorized"] is False for _args, details in watch.events)
