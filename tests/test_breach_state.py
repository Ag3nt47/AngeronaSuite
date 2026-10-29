"""Inert native mesh fixtures; no live collectors, firewall or process actions."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import FrozenInstanceError, replace
from types import SimpleNamespace
import time

import pytest

from angerona.core import breach_state as breach
from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.core.module_base import BaseModule
from angerona.core.response_contract import authorize_response
from angerona.modules.adversary_combat import AdversaryCombat


class NativeFixture(BaseModule):
    # The fixture deliberately represents a reviewed built-in producer. Mesh
    # enrollment, rather than a caller-supplied name, authenticates its event.
    __module__ = "angerona.modules.inert_breach_fixture"
    name = "Inert Native Detector"

    def run(self):
        pass


@contextmanager
def native_graph(tmp_path, **settings):
    config = SimpleNamespace(data_dir=tmp_path, adversary_combat_enabled=True,
        adversary_combat_mode="contain", adversary_combat_min_severity="HIGH",
        adversary_combat_isolate_host=True, adversary_combat_activate_honeypots=False,
        adversary_combat_quarantine_files=False, adversary_combat_block_network=False,
        adversary_combat_process_action="suspend", breach_auto_isolate_enabled=True,
        breach_lifted_cases=[], save=lambda: None)
    for key, value in settings.items():
        setattr(config, key, value)
    bus = EventBus()
    bus.arm(BusAuthority(b"i" * 32))
    bus.activate_mesh()
    native = NativeFixture()
    native.bind(bus)
    combat = AdversaryCombat(tmp_path, rollback_anchor={})
    manager = SimpleNamespace(config=config, bus=bus, modules={native.name: native, combat.name: combat})
    combat.bind(bus)
    combat.bind_manager(manager)
    combat.status = "running"
    combat._response_initialized = True
    publish = bus.enroll_mesh_publisher(native.name, "a" * 64)
    graph = SimpleNamespace(bus=bus, native=native, combat=combat, manager=manager,
                            config=config, publish=publish)
    try:
        yield graph
    finally:
        bus.close_mesh()


def emit(graph, *, severity=Severity.CRITICAL, ts=None, message="Inert exact native active finding", **overrides):
    details = {"finding_code": "native.confirmed.active", "active_attack": True,
               "pid": 41000, "process_create_time": 12345.5,
               **authorize_response(["isolate_host", "terminate_process"],
                                    local_host=True, pid=41000, process_create_time=12345.5)}
    details.update(overrides)
    graph.publish(Event(graph.native.name, message, severity, time.time() if ts is None else ts, details))
    return graph.bus.recent(1)[0]


def execute_next(combat):
    command = combat._queue.get_nowait()
    try:
        combat._execute_breach_command(command)
    finally:
        combat._queue.task_done()
    return combat.breach_action_result(command.request_id)


def test_native_proof_requires_current_mesh_and_exact_unmodified_contract(tmp_path):
    with native_graph(tmp_path) as graph:
        event = emit(graph)
        proof = breach.verified_breach(event, graph.bus, graph.manager.modules)
        assert proof and len(proof.case_id) == 32
        assert proof.event is not event and proof.event.hmac_sig == event.hmac_sig
        assert proof.authorized_actions == {"isolate_host", "terminate_process"}
        assert breach.verified_breach(replace(event, message="tampered"), graph.bus, graph.manager.modules) is None
        graph.bus.freeze_mesh()
        assert breach.verified_breach(event, graph.bus, graph.manager.modules) is None


def test_hmac_only_and_caller_spoofed_native_name_do_not_confirm(tmp_path):
    with native_graph(tmp_path) as graph:
        event = emit(graph)
        archive_bus = EventBus()
        archive_bus.arm(BusAuthority(b"i" * 32))
        assert archive_bus.verify(event)
        assert breach.verified_breach(event, archive_bus, graph.manager.modules) is None
        graph.bus.publish(event)
        spoof = graph.bus.recent(1)[0]
        assert spoof.module == "Unattributed local producer"
        assert breach.verified_breach(spoof, graph.bus, graph.manager.modules) is None


@pytest.mark.parametrize("changes", [
    {"spyware_confirmed": False}, {"breach_confirmed": False}, {"malware_confirmed": False},
    {"observation_only": True}, {"response_authorized": False},
    {"response_contract": {"version": 1, "actions": ["isolate_host"], "targets": {"host": "other"}}},
    {"node_origin": "remote-host"}, {"active_attack": False, "disposition": "exposure"},
    {"active_attack": False, "disposition": "observation"}, {"active_attack": False, "health": True},
    {"finding_code": ""}, {"oversized": "X" * 70000},
])
def test_uncertainty_exposure_remote_and_malformed_native_records_are_not_breaches(tmp_path, changes):
    with native_graph(tmp_path) as graph:
        event = emit(graph, **changes)
        assert breach.verified_breach(event, graph.bus, graph.manager.modules) is None


def test_external_tool_results_cannot_borrow_native_mesh_identity(tmp_path):
    with native_graph(tmp_path) as graph:
        event = emit(graph)
        graph.manager.modules[graph.native.name] = SimpleNamespace(name=graph.native.name)
        assert breach.verified_breach(event, graph.bus, graph.manager.modules) is None


def test_authenticated_practice_producer_is_excluded(tmp_path):
    with native_graph(tmp_path) as graph:
        graph.manager.modules.pop(graph.native.name)
        graph.native.name = "Red Team Simulation"
        graph.manager.modules[graph.native.name] = graph.native
        graph.publish = graph.bus.enroll_mesh_publisher(graph.native.name, "a" * 64)
        event = emit(graph)
        assert graph.bus.verify(event)
        assert breach.verified_breach(event, graph.bus, graph.manager.modules) is None


def test_high_severity_requires_exact_matched_observed_hash(tmp_path):
    with native_graph(tmp_path) as graph:
        assert breach.verified_breach(emit(graph, severity=Severity.HIGH), graph.bus, graph.manager.modules) is None
        event = emit(graph, severity=Severity.HIGH, observed_content_sha256="b" * 64, matched_sha256="b" * 64)
        assert breach.verified_breach(event, graph.bus, graph.manager.modules)
        event = emit(graph, severity=Severity.HIGH, observed_content_sha256="b" * 64, matched_sha256="c" * 64)
        assert breach.verified_breach(event, graph.bus, graph.manager.modules) is None


def test_freshness_and_stable_case_bind_exact_process_generation(tmp_path):
    with native_graph(tmp_path) as graph:
        first = breach.verified_breach(emit(graph), graph.bus, graph.manager.modules)
        second = breach.verified_breach(emit(graph, message="different wording"), graph.bus, graph.manager.modules)
        assert first.case_id == second.case_id
        born = emit(graph, process_create_time=12346.5,
                    **authorize_response(["isolate_host", "terminate_process"], local_host=True, pid=41000, process_create_time=12346.5))
        assert breach.verified_breach(born, graph.bus, graph.manager.modules).case_id != first.case_id
        stale = emit(graph, ts=time.time() - 40)
        assert breach.verified_breach(stale, graph.bus, graph.manager.modules) is None
        assert breach.verified_breach(stale, graph.bus, graph.manager.modules, require_fresh=False).case_id == first.case_id
        future = emit(graph, ts=time.time() + 5)
        assert breach.verified_breach(future, graph.bus, graph.manager.modules) is None


def test_controller_source_observe_latches_literal_evidence_and_held_response(tmp_path, monkeypatch):
    monkeypatch.setattr(breach, "protect_authority", lambda: (False, "Source Observe held"))
    with native_graph(tmp_path) as graph:
        controller = breach.BreachStateController(graph.manager, start=False)
        try:
            original = controller.snapshot()
            event = emit(graph, message="<b>literal</b> token=private-value")
            assert controller.snapshot() is original  # EventBus callback only queues.
            controller.process_once()
            snapshot = controller.snapshot()
            assert type(snapshot) is breach.BreachDisplaySnapshot and snapshot.active
            assert "<b>literal</b>" in snapshot.summary and "private-value" not in snapshot.summary
            assert all(not row.enabled for row in snapshot.actions if row.action in {"isolate", "kill", "patch", "lift_lockdown"})
            result = execute_next(graph.combat)
            assert result["state"] == "held" and "Source" in result["message"]
            controller.process_once()
            assert controller.snapshot().containment_state == "held"
            assert controller.snapshot().active  # Holding a response never clears evidence.
            assert event.hmac_sig == snapshot.details[2][1]
            assert dict(snapshot.details)["Observed PID / birth"] == "41000 / 12345.5"
            assert dict(snapshot.details)["Authorized native actions"] == "isolate_host, terminate_process"
            with pytest.raises(FrozenInstanceError):
                snapshot.active = False
            assert not controller.request_action(snapshot.case_id, "isolate")
            assert not controller.request_action(snapshot.case_id, [])
        finally:
            assert controller.close()


def test_factory_is_singleton_and_no_host_work_is_done_in_constructor_or_ui_methods(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Host/journal IO on caller")
    with native_graph(tmp_path, breach_auto_isolate_enabled=False) as graph:
        monkeypatch.setattr(breach.BreachStateController, "_run", lambda self: self._stop.wait(2))
        monkeypatch.setattr(graph.combat, "list_actions", forbidden)
        monkeypatch.setattr(breach, "protect_authority", forbidden)
        controller = breach.ensure_breach_controller(graph.manager)
        assert breach.ensure_breach_controller(graph.manager) is controller
        assert controller.snapshot() == breach.BreachDisplaySnapshot()
        assert not controller.request_action("f" * 32, "isolate")
        assert controller.close()
        assert not controller.request_action("f" * 32, "investigate")


def test_event_queue_loss_is_visible_and_stop_retires_subscription(tmp_path, monkeypatch):
    monkeypatch.setattr(breach, "protect_authority", lambda: (False, "Source"))
    with native_graph(tmp_path, breach_auto_isolate_enabled=False) as graph:
        controller = breach.BreachStateController(graph.manager, start=False)
        for _ in range(66):
            emit(graph)
        assert controller._events.qsize() == 64
        controller.process_once()
        assert dict(controller.snapshot().details)["Review queue coverage"].startswith("2 notices")
        controller.request_stop()
        depth = controller._events.qsize()
        emit(graph)
        assert controller._events.qsize() == depth
        controller.process_once()
        assert controller._events.qsize() == depth


def test_source_protect_gate_does_not_prompt_for_elevation(monkeypatch):
    monkeypatch.delattr(breach.sys, "frozen", raising=False)
    allowed, reason = breach.protect_authority()
    assert not allowed
    assert "Source Observe" in reason or "unavailable" in reason
