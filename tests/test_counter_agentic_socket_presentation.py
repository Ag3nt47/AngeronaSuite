from __future__ import annotations

import hashlib
import os
from types import SimpleNamespace

import pytest

from angerona.core import breach_state, module_base, threat
from angerona.core.eventbus import BusAuthority, Event, EventBus
from angerona.core.module_base import Severity
from angerona.modules import counter_agentic, soar


@pytest.fixture
def watch(tmp_path, monkeypatch):
    """Inert socket/process records; never enumerate the host or load Config."""
    rows = []
    clock = [1000.0]
    executable = tmp_path / "agent.exe"
    executable.write_bytes(b"fixture executable; never executed")

    class Process:
        def __init__(self, pid):
            self.pid = pid

        def create_time(self):
            return 1234.5

        def name(self):
            return "agent.exe"

        def exe(self):
            return str(executable)

    monkeypatch.setattr(counter_agentic, "_configured_inference_port", lambda: (
        11434, "http://127.0.0.1:11434", "",
    ))
    monkeypatch.setattr(counter_agentic, "list_connections", lambda: rows)
    monkeypatch.setattr(counter_agentic, "psutil", SimpleNamespace(Process=Process))
    monkeypatch.setattr(counter_agentic, "policy_snapshot", lambda: ())
    monkeypatch.setattr(counter_agentic, "time", SimpleNamespace(time=lambda: clock[0]))
    module = counter_agentic.CounterAgenticModule()
    events = []
    module.emit = lambda *args, **kwargs: events.append((args, kwargs))
    return SimpleNamespace(
        module=module, rows=rows, events=events, clock=clock,
        executable=executable, process_type=Process,
    )


def _row(*, status="ESTABLISHED", local="127.0.0.1:50000",
         remote="127.0.0.1:11434", pid=4242):
    return {"status": status, "laddr": local, "raddr": remote, "pid": pid}


@pytest.fixture
def review(watch, monkeypatch):
    """Use the actual producer/bus/classifier/SOAR with no workers or host probes."""
    bus = EventBus()
    bus.arm(BusAuthority(b"s" * 32))
    monkeypatch.delattr(watch.module, "emit")  # Restore BaseModule's real publisher.
    watch.module.bind(bus)
    responder = soar.SOARModule()
    responder._auto = responder._active_defense = False
    responder.bind(bus)
    clock = SimpleNamespace(time=lambda: watch.clock[0])
    monkeypatch.setattr(module_base, "time", clock)
    monkeypatch.setattr(soar, "time", clock)
    monkeypatch.setattr(threat, "time", clock)
    monkeypatch.setattr(soar, "_process_policy_snapshot", lambda: ())
    monkeypatch.setattr(responder, "_is_protected_process", lambda _pid: pytest.fail("host PID probe"))
    monkeypatch.setattr(responder, "_exact_process_contract_ok", lambda _ev: pytest.fail("host identity probe"))
    monkeypatch.setattr(responder, "_contain", lambda *_args: pytest.fail("response execution"))
    monkeypatch.setattr(breach_state, "protect_authority", lambda: pytest.fail("native authority probe"))
    manager = SimpleNamespace(bus=bus, modules={watch.module.name: watch.module, responder.name: responder})
    controller = breach_state.BreachStateController(manager, start=False, clock=clock.time)
    try:
        yield SimpleNamespace(watch=watch, bus=bus, soar=responder, breach=controller)
    finally:
        assert controller.close()


@pytest.mark.parametrize("row,matched,role", [
    (_row(status="LISTEN", local="127.0.0.1:11434", remote=""), "local", "listener"),
    (_row(status="LISTEN", local="0.0.0.0:11434", remote=""), "local", "listener"),
    (_row(), "remote", "remote-port-match"),
    (_row(local="127.0.0.1:11434", remote="127.0.0.1:50000"), "local", "local-port-match"),
    (_row(local="[::1]:11434", remote="[::1]:11434"), "both", "both-port-match"),
    (_row(local="127.0.0.1:11434", remote="203.0.113.4:443"), "local", "local-port-match"),
    (_row(remote="203.0.113.4:11434"), "remote", "remote-port-match"),
    (_row(status="CLOSE_WAIT"), "remote", "remote-port-match"),
    (_row(status="LISTEN"), "remote", "remote-port-match"),
])
def test_socket_evidence_describes_roles_without_claiming_a_connection(
    watch, row, matched, role,
):
    watch.rows.append(row)

    coverage = watch.module._watch_ollama_port()

    assert coverage.complete and coverage.port_connections == coverage.unexpected == 1
    (message, severity), details = watch.events[0]
    assert severity == Severity.HIGH
    assert "owns an observed socket" in message
    assert "connected to" not in message and "hijack" not in message
    assert "does not establish locality, initiator or misuse" in message
    assert details["socket_status"] == row["status"]
    assert details["local_endpoint"] == row["laddr"]
    assert details["remote_endpoint"] == row["raddr"]
    assert details["matched_endpoint"] == matched
    assert details["socket_role"] == role
    assert details["socket_metadata_advisory"] is True
    assert details["disposition"] == "observation"
    assert details["response_authorized"] is False
    assert details["process_create_time"] == 1234.5
    assert details["process_path"] == str(watch.executable)
    assert details["process_identity_complete"] is True
    assert details["authorization_policy"] == "exact-path-sha256-operator-approval"


@pytest.mark.parametrize("status,expected", [
    (None, "UNKNOWN"), (17, "UNKNOWN"), ({"state": "LISTEN"}, "UNKNOWN"),
    ("", "UNKNOWN"), ("listen", "listen"), ("LISTEN\n", "LISTEN�"),
    ("odd-state", "odd-state"),
])
def test_missing_or_odd_status_does_not_claim_a_listener(watch, status, expected):
    row = _row(status=status, local="127.0.0.1:11434", remote="")
    if status is None:
        del row["status"]
    watch.rows.append(row)

    watch.module._watch_ollama_port()

    details = watch.events[0][1]
    assert details["socket_status"] == expected
    assert details["socket_role"] == "local-port-match"


def test_socket_metadata_is_bounded_without_truncating_dedup_identity(watch):
    local = "\n" + "L" * 3000 + ":11434"
    remote = "\r" + "R" * 3000 + ":443"
    watch.rows.append(_row(status="S\n" * 100, local=local, remote=remote))

    watch.module._watch_ollama_port()

    details = watch.events[0][1]
    assert len(details["socket_status"]) == 64
    assert len(details["local_endpoint"]) == len(details["remote_endpoint"]) == 1024
    assert all(value.endswith("…") for value in (
        details["socket_status"], details["local_endpoint"], details["remote_endpoint"],
    ))
    assert all("\n" not in value and "\r" not in value for value in (
        details["socket_status"], details["local_endpoint"], details["remote_endpoint"],
    ))
    assert tuple(watch.module._port_alerted) == (
        (4242, 1234.5, str(watch.executable).casefold(), local, remote),
    )
    # An endpoint differing beyond the presentation cap remains a distinct key.
    watch.rows[0]["laddr"] = local[:-6] + "different:11434"
    watch.module._watch_ollama_port()
    assert len(watch.events) == 2


def test_paired_socket_rows_keep_original_dedup_keys_and_window(watch):
    watch.rows.extend([
        _row(pid=4242),
        _row(pid=4343, local="127.0.0.1:11434", remote="127.0.0.1:50000"),
    ])

    first = watch.module._watch_ollama_port()
    assert first.unexpected == first.port_connections == 2
    assert [details["matched_endpoint"] for _args, details in watch.events] == ["remote", "local"]
    expected_keys = {
        (row["pid"], 1234.5, str(watch.executable).casefold(), row["laddr"], row["raddr"])
        for row in watch.rows
    }
    assert set(watch.module._port_alerted) == expected_keys

    watch.clock[0] += 59.999
    # State is diagnostic only and is intentionally absent from dedup identity.
    watch.rows[0]["status"] = "CLOSE_WAIT"
    watch.module._watch_ollama_port()
    assert len(watch.events) == 2 and watch.module._detections == 2

    watch.clock[0] = 1060.0
    watch.module._watch_ollama_port()
    assert len(watch.events) == 4 and watch.module._detections == 4
    assert set(watch.module._port_alerted) == expected_keys


def test_unavailable_process_identity_still_alerts_with_incomplete_coverage(watch, monkeypatch):
    class Uninspectable(watch.process_type):
        def create_time(self):
            raise PermissionError("fixture identity unavailable")

    monkeypatch.setattr(counter_agentic.psutil, "Process", Uninspectable)
    watch.rows.append(_row(status="LISTEN", local="127.0.0.1:11434", remote=""))

    coverage = watch.module._watch_ollama_port()

    assert not coverage.complete and coverage.identity_failures == coverage.unexpected == 1
    assert watch.events[0][0][1] == Severity.HIGH
    details = watch.events[0][1]
    assert details["socket_role"] == "listener"
    assert details["process_identity_complete"] is False
    assert details["response_authorized"] is False
    assert "fixture identity unavailable" in details["identity_error"]
    assert set(watch.module._port_alerted) == {(4242, 0.0, "", "127.0.0.1:11434", "")}

    watch.clock[0] = 1009.999
    watch.module._watch_ollama_port()
    assert len(watch.events) == 1
    watch.clock[0] = 1010.0
    watch.module._watch_ollama_port()
    assert len(watch.events) == 2


def test_exact_path_digest_approval_remains_required_and_is_not_learned(watch, monkeypatch):
    digest = hashlib.sha256(watch.executable.read_bytes()).hexdigest()
    policy = (("agent.exe", os.path.normcase(os.path.normpath(str(watch.executable))), digest),)
    monkeypatch.setattr(counter_agentic, "policy_snapshot", lambda: policy)
    watch.rows.append(_row(status="LISTEN", local="127.0.0.1:11434", remote=""))

    approved = watch.module._watch_ollama_port()
    assert approved.complete and approved.port_connections == 1 and approved.unexpected == 0
    assert watch.events == [] and watch.module._port_alerted == {}

    # Observing a known basename/listener never updates approval for changed bytes.
    watch.executable.write_bytes(b"substituted fixture executable")
    changed = watch.module._watch_ollama_port()
    assert changed.unexpected == 1 and len(watch.events) == 1
    assert watch.events[0][0][1] == Severity.HIGH
    assert policy[0][2] == digest


def test_nonmatching_ports_and_invalid_pids_remain_excluded(watch):
    watch.rows.extend([
        _row(local="127.0.0.1:11435", remote="127.0.0.1:11433"),
        *[_row(pid=pid) for pid in (None, True, 0, -1, "4242")],
    ])

    coverage = watch.module._watch_ollama_port()

    assert coverage.complete and coverage.observed == 6
    assert coverage.port_connections == coverage.unexpected == 0
    assert watch.events == [] and watch.module._port_alerted == {}


@pytest.mark.parametrize("identity_available", [True, False])
def test_socket_burst_keeps_high_evidence_without_active_or_breach_state(
    review, monkeypatch, identity_available,
):
    watch = review.watch
    if not identity_available:
        class Uninspectable(watch.process_type):
            def create_time(self):
                raise PermissionError("fixture identity unavailable")

        monkeypatch.setattr(counter_agentic.psutil, "Process", Uninspectable)
    watch.rows.extend(
        _row(pid=pid, local=f"127.0.0.1:{50000 + index}")
        for index, pid in enumerate((4242, 4343, 4242, 4343))
    )

    coverage = watch.module._watch_ollama_port()
    leads = review.bus.recent(10)

    assert coverage.observed == coverage.port_connections == coverage.unexpected == 4
    assert coverage.complete is identity_available
    assert coverage.identity_failures == (0 if identity_available else 4)
    assert len(leads) == watch.module._detections == 4
    assert all(event.severity == Severity.HIGH for event in leads)
    assert all(event.details["response_authorized"] is False for event in leads)
    assert all(threat.event_disposition(event) == "observation" for event in leads)
    assert threat.active_threat_events(leads) == []
    assert review.soar.process_pending_once() == 0
    assert review.soar._high_events == [] and not review.soar._under_attack()
    assert review.soar._under_attack_until == 0.0
    assert review.soar._attempts == review.soar._contained == 0
    assert review.bus.recent(10) == leads  # Original HIGH leads remain visible.
    assert all(review.bus.verify(event) for event in leads)
    assert review.breach._events.empty()
    review.breach.process_once()
    assert review.breach.snapshot() == breach_state.BreachDisplaySnapshot()


def test_cadence_and_active_signals_keep_burst_latch_without_aggregate_authority(review):
    producer = review.watch.module
    for stamp, command in ((100.0, "whoami"), (102.0, "echo fixture"),
                           (104.0, "schtasks /query")):
        producer._record(4242, command, stamp)
    [cadence] = review.bus.recent(10)
    assert cadence.module == producer.name and cadence.severity == Severity.HIGH
    assert "Agentic loop fingerprint" in cadence.message
    assert threat.is_active_threat(cadence)
    assert review.soar.process_pending_once() == 1

    originals = [cadence]
    for pid in (4242, 4343, 4242):
        review.bus.publish(Event(
            "Exact Detector", "inert explicit active evidence", Severity.HIGH,
            review.watch.clock[0],
            {"pid": pid, "active_attack": True, "response_authorized": False},
        ))
        originals.append(review.bus.recent(1)[0])
    assert review.soar.process_pending_once() == 3
    [aggregate] = [event for event in review.bus.recent(30)
                   if event.module == review.soar.name and event.severity == Severity.CRITICAL]
    assert len(review.soar._high_events) == 4
    assert review.soar._under_attack_until == review.watch.clock[0] + 60.0
    assert review.soar._under_attack()
    assert "event counts do not confirm an active attack or breach" in aggregate.message
    assert aggregate.details["under_attack"] is True
    assert aggregate.details["pids"] == [4242, 4343]
    assert aggregate.details["disposition"] == "health"
    assert aggregate.details["response_authorized"] is False
    assert threat.event_disposition(aggregate) == "health"
    assert threat.active_threat_events([aggregate]) == []
    assert all(threat.is_active_threat(event) and review.bus.verify(event) for event in originals)
    assert review.bus.verify(aggregate)
    assert review.soar._attempts == review.soar._contained == 0
    assert review.breach._events.empty()
    review.breach.process_once()
    assert review.breach.snapshot() == breach_state.BreachDisplaySnapshot()
