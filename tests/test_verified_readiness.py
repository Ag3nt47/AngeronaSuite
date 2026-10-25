"""Readiness never upgrades declarations or caller-described signed alerts."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
import threading
import time
from dataclasses import replace

import pytest

from angerona.core import attack_coverage
from angerona.core.assurance_receipts import (
    AssuranceChallenge, AssuranceReceiptBroker, ValidatedDetectorObservation,
)
from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.core.module_base import BaseModule
from angerona.core.verified_readiness import (
    DETECTION_TTL_SECONDS, RESPONSE_TTL_SECONDS, VerifiedReadiness,
)
from angerona.modules.file_integrity import FileIntegrityModule
from angerona.modules.network_monitor import NetworkMonitorModule
from angerona.modules.purple_guard import PurpleGuard
from angerona.modules.soar_engine import ActiveResponseSOAR


class _Clock:
    wall = 1_800_000_000.0
    mono = 100.0

    def advance(self, value):
        self.wall += value
        self.mono += value


class _Manager:
    def __init__(self):
        self.bus = EventBus()
        self.bus.arm(BusAuthority(b"r" * 32))
        self.modules = {}
        self.module_trust = {}
        self._shutdown = self._ugcap_paused = False


class _Alive:
    def is_alive(self):
        return True


@pytest.fixture
def world():
    manager, clock = _Manager(), _Clock()
    service = VerifiedReadiness(manager, wall_clock=lambda: clock.wall,
                                monotonic=lambda: clock.mono)
    manager.verified_readiness = service
    manager.assurance_receipt_broker = AssuranceReceiptBroker(
        lambda: manager.modules, on_verified=service.observe_assurance,
    )
    return manager, clock, service


def _sensor(world, cls, *, collected=True):
    manager, clock, service = world
    # Exact installed class with an inert lifecycle fixture. Constructors,
    # collectors, host scans, response code and external integrations never run.
    module = cls.__new__(cls)
    BaseModule.__init__(module)
    module._angerona_origin = "builtin"
    manager.modules[module.name] = module
    manager.module_trust[module.name] = {"origin": "builtin"}
    module._thread = _Alive()
    module._lifecycle_generation = 1
    module._generation_started_at = clock.mono - 2
    module._status = "running"
    module._cycle_count = 1 if collected else 0
    module._last_cycle_completed_at = clock.mono - 1 if collected else 0
    module._last_sleep_interval_seconds = 3
    if collected:
        module._first_cycle_complete.set()
    service.register(module)
    return module


def _row(service, tid="T1071"):
    return next(r for r in service.snapshot(attack_coverage.COVERAGE)["techniques"] if r["tid"] == tid)


def _practice(world, *, checks=None, failure="", publish=True):
    manager, clock, service = world
    detector = _sensor(world, PurpleGuard)
    responder = _sensor(world, ActiveResponseSOAR)
    ticket = service._begin_practice(detector, responder, "T1003", "a" * 32)
    detection = Event(detector.name, "inert marker", Severity.HIGH, clock.wall,
                      {"mitre": "T1003", "practice_verification_id": "a" * 32})
    response = Event(responder.name, "inert marker removed", Severity.INFO, clock.wall,
                     {"trigger_ts": clock.wall, "mitigated": True})
    if publish:
        manager.bus.publish(detection)
        manager.bus.publish(response)
        response, detection = manager.bus.recent(2)
    expected = {
        "positive_control_detected": True, "negative_control_quiet": True,
        "recorder_persisted": True, "response_succeeded": True,
        "postcondition_satisfied": True, "detector_event_persisted": True,
        "response_event_persisted": True,
    }
    if checks:
        expected.update(checks)
    service._finish_practice(ticket, bus=manager.bus, detection=detection, response=response,
                             checks=expected, receipt_id="DRILL-VERIFY-TEST", failure=failure)
    return detector, responder, ticket, detection, response, expected


def test_declarations_and_running_without_work_never_claim_coverage(world, monkeypatch):
    _, _, service = world
    assert _row(service)["stage"] == "declared"
    module = _sensor(world, NetworkMonitorModule, collected=False)
    assert _row(service)["stage"] == "declared"
    monkeypatch.setattr(attack_coverage, "_readiness_ref", lambda: service)
    summary = attack_coverage.summary()
    assert summary["declared_covered"] > 0
    assert summary["covered"] == summary["coverage_pct"] == 0
    module._cycle_count = 1
    module._last_cycle_completed_at = 99
    module._first_cycle_complete.set()
    assert _row(service)["stage"] == "collecting"
    assert attack_coverage.summary()["covered"] == 0


@pytest.mark.parametrize("condition", ["stop", "thread-exit", "generation", "replace", "ugcap", "shutdown",
                                        "degraded", "loss", "unknown-loss", "future-cycle", "old-cycle"])
def test_collection_withdraws_immediately_for_real_gaps(world, condition):
    manager, clock, service = world
    module = _sensor(world, NetworkMonitorModule)
    assert _row(service)["stage"] == "collecting"
    if condition == "stop":
        module._stop.set()  # no wait for a UI refresh worker or future expiry
    elif condition == "thread-exit":
        module._thread = threading.Thread()
    elif condition == "generation":
        module._lifecycle_generation += 1
        module._generation_started_at = clock.mono
        module._first_cycle_complete.clear()
    elif condition == "replace":
        manager.modules[module.name] = object()
    elif condition == "ugcap":
        manager._ugcap_paused = True
    elif condition == "shutdown":
        manager._shutdown = True
    elif condition == "degraded":
        module.health = 55
        module.health_note = "collection denied"
    elif condition == "loss":
        module._bus_overflow_count = 1
    elif condition == "unknown-loss":
        module._bus_overflow_count = None
    elif condition == "future-cycle":
        module._last_cycle_completed_at = clock.mono + 1
    elif condition == "old-cycle":
        module._last_cycle_completed_at = clock.mono - 40
    assert _row(service)["stage"] == "declared"
    assert _row(service)["gaps"]


def test_actor_name_signed_generic_events_and_dict_reports_cannot_create_test_credit(world):
    manager, clock, service = world
    module = _sensor(world, NetworkMonitorModule)
    manager.bus.publish(Event(module.name, "test passed", Severity.INFO, clock.wall,
                              {"mitre": "T1071", "response_verified": True, "checks": "all"}))
    service._finish_practice({"technique": "T1071"}, bus=manager.bus, checks={"all": True})
    assert _row(service)["stage"] == "collecting"
    assert not service.snapshot(attack_coverage.COVERAGE)["history"]


def test_scoped_practice_response_stages_expire_and_stop_keeps_dated_history(world):
    _, clock, service = world
    detector, responder, *_ = _practice(world)
    row = _row(service, "T1003")
    assert row["stage"] == "response-verified"
    assert "inert practice" in row["evidence"]["scope"]
    assert row["evidence"]["observed_at"].endswith("+00:00")
    clock.advance(RESPONSE_TTL_SECONDS + 1)
    for module in (detector, responder):
        module._last_cycle_completed_at = clock.mono
    assert _row(service, "T1003")["stage"] == "detection-tested"
    detector._stop.set()
    assert _row(service, "T1003")["stage"] == "declared"
    assert service.snapshot(attack_coverage.COVERAGE)["history"][0]["outcome"] == "response-verified"
    detector._stop.clear()
    clock.advance(DETECTION_TTL_SECONDS)
    detector._last_cycle_completed_at = clock.mono
    assert _row(service, "T1003")["stage"] == "collecting"
    assert not _row(service, "T1003")["evidence"]["fresh"]


def test_clock_rollback_and_recovery_cannot_resurrect_old_practice_proof(world):
    _, clock, service = world
    detector, responder, *_ = _practice(world)
    assert _row(service, "T1003")["stage"] == "response-verified"
    clock.advance(10)
    assert _row(service, "T1003")["stage"] == "response-verified"
    clock.advance(-20)
    assert _row(service, "T1003")["stage"] == "declared"
    # Return past the old proof timestamp, then past the former clock high-water.
    # Fresh sensor work alone cannot give the old practice receipt fresh credit.
    for delta in (11, 20):
        clock.advance(delta)
        for module in (detector, responder):
            module._last_cycle_completed_at = clock.mono
        row = _row(service, "T1003")
        assert row["stage"] == "collecting" and not row["evidence"]["fresh"]
    detector, responder, *_ = _practice(world)
    assert _row(service, "T1003")["stage"] == "response-verified"
    clock.advance(10)
    _row(service, "T1003")
    for delta in (-5, -40, 50):
        clock.advance(delta)
        for module in (detector, responder):
            module._last_cycle_completed_at = clock.mono
        row = _row(service, "T1003")
        assert row["stage"] not in {"detection-tested", "response-verified"}
        assert not row["evidence"]["fresh"]
    _practice(world)
    assert _row(service, "T1003")["stage"] == "response-verified"


@pytest.mark.parametrize("change", ["negative", "response-failed", "unsigned", "generation", "replay", "future"])
def test_bad_controls_unsigned_stale_generation_replay_and_future_are_rejected(world, change):
    manager, clock, service = world
    if change == "negative":
        _practice(world, checks={"negative_control_quiet": False})
        assert _row(service, "T1003")["stage"] == "collecting"
    elif change == "response-failed":
        _practice(world, checks={"postcondition_satisfied": False}, failure="marker still exists")
        assert _row(service, "T1003")["stage"] == "detection-tested"
    elif change == "unsigned":
        _practice(world, publish=False)
        assert _row(service, "T1003")["stage"] == "collecting"
    else:
        detector, _, ticket, detection, response, checks = _practice(world)
        if change == "generation":
            detector._lifecycle_generation += 1
            assert _row(service, "T1003")["stage"] == "collecting"
        elif change == "future":
            clock.wall -= 20
            assert _row(service, "T1003")["stage"] == "collecting"
            assert not _row(service, "T1003")["evidence"]["fresh"]
        elif change == "replay":
            service._finish_practice(ticket, bus=manager.bus, detection=detection, response=response,
                                     checks=checks, receipt_id="DRILL-VERIFY-TEST")
            assert len(service.snapshot(attack_coverage.COVERAGE)["history"]) == 1


def test_assurance_observer_preserves_consumer_credit_and_rejects_forged_notifications(world, monkeypatch):
    manager, clock, service = world
    producer = _sensor(world, FileIntegrityModule)
    consumer = type("Consumer", (), {"CODE": "CHAOS", "name": "CHAOS"})()
    broker = manager.assurance_receipt_broker
    broker.enroll_consumer(consumer)
    issuer = broker.enroll_producer(producer, code="FIM", module_name=producer.name,
                                    capability_id="angerona.builtin.file_integrity")
    monkeypatch.setattr("angerona.core.assurance_receipts.time.time", lambda: clock.wall)
    challenge = AssuranceChallenge("b" * 32, "fim", "c" * 64, "d" * 64,
                                   "inert fixture target", clock.wall, clock.wall + 20)
    assert broker.register_challenge(consumer, challenge)
    receipt = issuer.issue(producer, challenge.probe_id, observation="file_content_observed",
                           observed_target_digest=challenge.target_digest, observed_at=clock.wall)
    assert broker.verify_and_consume(consumer, receipt, now=clock.wall)
    assert not broker.verify_and_consume(consumer, receipt, now=clock.wall)
    history = service.snapshot(attack_coverage.COVERAGE)["history"]
    assert len(history) == 1 and history[0]["kind"] == "sensor-observation"
    assert _row(service, "T1486")["stage"] == "collecting"
    assert "producer_mac" not in json.dumps(history)
    forged = ValidatedDetectorObservation(producer.name, 1, "e" * 32, "file_content_observed", clock.wall)
    service.observe_assurance(producer, forged)
    service.observe_assurance(producer, replace(forged))
    assert len(service.snapshot(attack_coverage.COVERAGE)["history"]) == 1


def test_observer_exception_does_not_undo_broker_consumption(world, monkeypatch):
    manager, clock, _ = world
    producer = _sensor(world, FileIntegrityModule)
    consumer = type("Consumer", (), {"CODE": "CHAOS", "name": "CHAOS"})()
    def failed(*_args):
        raise RuntimeError("observer failed")
    broker = AssuranceReceiptBroker(lambda: manager.modules, on_verified=failed)
    broker.enroll_consumer(consumer)
    issuer = broker.enroll_producer(producer, code="FIM", module_name=producer.name,
                                    capability_id="angerona.builtin.file_integrity")
    monkeypatch.setattr("angerona.core.assurance_receipts.time.time", lambda: clock.wall)
    challenge = AssuranceChallenge("b" * 32, "fim", "c" * 64, "d" * 64,
                                   "inert fixture target", clock.wall, clock.wall + 20)
    assert broker.register_challenge(consumer, challenge)
    receipt = issuer.issue(producer, challenge.probe_id, observation="file_content_observed",
                           observed_target_digest=challenge.target_digest, observed_at=clock.wall)
    assert broker.verify_and_consume(consumer, receipt, now=clock.wall)
    assert not broker.verify_and_consume(consumer, receipt, now=clock.wall)


def test_snapshot_is_detached_bounded_and_never_calls_module_or_host_collectors(world, monkeypatch):
    _, _, service = world
    module = _sensor(world, NetworkMonitorModule)
    def forbidden(*_args, **_kwargs):
        raise AssertionError("readiness attempted IO or sensor call")
    module.operational_snapshot = forbidden
    module.coverage_snapshot = forbidden
    monkeypatch.setattr("builtins.open", forbidden)
    monkeypatch.setattr("socket.getaddrinfo", forbidden)
    monkeypatch.setattr("psutil.process_iter", forbidden)
    monkeypatch.setattr("psutil.net_connections", forbidden)
    snapshot = service.snapshot(attack_coverage.COVERAGE)
    snapshot["techniques"][0]["gaps"].append("external mutation")
    assert "external mutation" not in str(service.snapshot(attack_coverage.COVERAGE))
    assert len(snapshot["techniques"]) == len(attack_coverage.COVERAGE)


def test_replacement_same_class_same_generation_does_not_inherit_previous_test_proof(world):
    _, _, service = world
    _practice(world)
    assert _row(service, "T1003")["stage"] == "response-verified"
    replacement = _sensor(world, PurpleGuard)
    assert replacement._lifecycle_generation == 1
    assert _row(service, "T1003")["stage"] == "collecting"
    assert service.snapshot(attack_coverage.COVERAGE)["history"][0]["source_identity"].endswith("PurpleGuard")


def test_unarmed_bus_and_invalid_clock_withdraw_proof_instead_of_trusting_verify_default(world):
    manager, clock, service = world
    # EventBus.verify deliberately permits an unarmed development bus. That is
    # not authenticated evidence and must never earn readiness test credit.
    manager.bus._authority = None
    _practice(world)
    assert _row(service, "T1003")["stage"] == "declared"
    clock.wall = float("nan")
    unavailable = service.snapshot(attack_coverage.COVERAGE)
    assert unavailable["available"] is False
    assert unavailable["reason"] == "readiness clock unavailable"


def test_pending_probes_and_history_have_hard_bounds_and_export_no_capabilities(world):
    manager, _, service = world
    detector, responder, *_ = _practice(world)
    tickets = [service._begin_practice(detector, responder, "T1003", f"{n:032x}") for n in range(40)]
    assert sum(ticket is not None for ticket in tickets) == 32
    assert service._begin_practice(detector, responder, "T1003" * 1000, "f" * 32) is None
    assert service._begin_practice(detector, responder, "T1003", "f" * 10000) is None
    for ticket in tickets:
        service._finish_practice(ticket, bus=manager.bus, failure="inert failed control")
    for _ in range(3):
        for n in range(32):
            ticket = service._begin_practice(detector, responder, "T1003", f"{n:032x}")
            service._finish_practice(ticket, bus=manager.bus, failure="inert failed control")
    snapshot = service.snapshot(attack_coverage.COVERAGE)
    assert len(snapshot["history"]) == 64
    serialized = json.dumps(snapshot)
    assert "source_epoch" not in serialized and "producer_mac" not in serialized


def test_private_practice_observer_failure_cannot_change_verifier_outcome(monkeypatch):
    from angerona.core import practice_verification, verified_readiness
    def fail(*_args, **_kwargs):
        raise RuntimeError("inert observer failure")
    monkeypatch.setattr(verified_readiness, "_practice_service", fail)
    assert practice_verification._readiness_begin(object(), object(), object(), "T1003", "a" * 32) == (None, None)
    service = type("BrokenObserver", (), {"_finish_practice": fail})()
    practice_verification._readiness_finish((service, object()), bus=object())


def test_real_inert_marker_verifier_publishes_readiness_only_after_durable_cleanup(tmp_path, monkeypatch):
    from angerona.core import drill_resolution
    from angerona.core.practice_verification import verify_practice_fixes
    from angerona.core.storage import FlightRecorder
    from angerona.modules.purple_guard import install_policies
    from angerona.modules import process_monitor
    from angerona.telemetry.sensors import ProcessSnapshot
    from angerona.modules.adversary_combat import AdversaryCombat, CombatPolicy
    monkeypatch.setattr(process_monitor, "process_snapshot", lambda *a, **k:
        ProcessSnapshot((), time.time(), True, 0, 0, 0, 0, "", True))
    (tmp_path / "bus.key").write_text(bytes(range(32)).hex(), encoding="ascii")
    manager = _Manager()
    recorder = FlightRecorder(tmp_path / "flight-recorder.db")
    manager.recorder = recorder
    manager.bus.arm(recorder.authority)
    manager.bus.subscribe(recorder.record_bus)
    service = manager.verified_readiness = VerifiedReadiness(manager)
    guard, response = PurpleGuard(tmp_path), ActiveResponseSOAR()
    for module in (guard, response):
        module.bind(manager.bus)
        module._angerona_origin = "builtin"
        module._status = "running"
        module._thread = _Alive()
        module._lifecycle_generation = 1
        module._generation_started_at = time.monotonic() - 2
        module._last_cycle_completed_at = time.monotonic() - 1
        module._cycle_count = 1
        module._first_cycle_complete.set()
        manager.modules[module.name] = module
        manager.module_trust[module.name] = {"origin": "builtin"}
        service.register(module)
    # This integration must acquire a fresh issuer lease, so its detector uses
    # a real owned module lifecycle rather than a never-ticking alive stub.
    guard._thread = None
    guard._status = "stopped"
    combat = AdversaryCombat(tmp_path, rollback_anchor={})
    combat.bind(manager.bus)
    combat.bind_manager(manager)
    combat.policy = lambda: CombatPolicy(
        block_network=False, isolate_host=False, activate_honeypots=False,
    )
    manager.modules[combat.name] = combat
    response.bind_manager(manager)
    combat.start()
    deadline = time.monotonic() + 5
    while not combat.response_ready() and time.monotonic() < deadline:
        time.sleep(.01)
    assert combat.response_ready(), combat.health_note
    install_policies([{"mitre": "T1003"}], "readiness-inert-source", tmp_path)
    drill_resolution.apply_contracts(
        [{"mitre": "T1003", "name": "Inert credential marker"}],
        "readiness-inert-source", tmp_path, installed=["T1003"],
    )
    assert _row(service, "T1003")["stage"] == "declared"
    guard.start()
    assert guard._first_cycle_complete.wait(2)
    try:
        result = verify_practice_fixes(
            ["T1003"], source_run_id="readiness-inert-source", data_dir=tmp_path,
            db_path=tmp_path / "flight-recorder.db", bus=manager.bus,
            purple_guard=guard, active_response=response, recorder_timeout=5,
            manager=manager, recorder=recorder,
        )
        assert result["ok"], json.dumps(result, indent=2)
        events = manager.bus.recent(500)
        detection = next(event for event in events
            if event.module == "Purple Remediation Guard"
            and event.details.get("practice_verification_id")
            == result["results"][0]["verification_id"])
        response_event = next(event for event in events
            if event.module == "Active Response SOAR"
            and event.details.get("trigger_ts") == detection.ts
            and event.details.get("mitigated") is True)
        assert manager.bus.verify(detection) and manager.bus.verify(response_event)
        assert response_event.details["delegation_mode"] == "issuer-original-event"
        assert response_event.details["origin_event_digest"] == detection.hmac_sig
        assert response_event.details["queue_request_id"] is None
        assert guard._validation_lease is None
        row = _row(service, "T1003")
        assert row["stage"] == "response-verified", row
        assert not list((tmp_path / "drill-sandbox").glob("*_practice_*.txt"))
        assert row["evidence"]["evidence_id"] == result["results"][0]["receipt_id"]
        assert "inert practice marker" in row["evidence"]["scope"]
        # Real source/response stop invalidates the cache even when its signed
        # receipt remains durable, dated history on disk and in memory.
        BaseModule.stop(guard)
        assert _row(service, "T1003")["stage"] == "declared"
    finally:
        combat.stop()
        recorder.close()
        BaseModule.stop(guard)
        BaseModule.stop(response)


def test_native_qt_coverage_updates_without_heat_events_or_rebuilding_unchanged_rows(tmp_path):
    script = textwrap.dedent(r'''
        from PySide6.QtWidgets import QApplication, QWidget
        from angerona.core import attack_coverage
        from angerona.core.attack_tracker import init_tracker
        from angerona.core.eventbus import EventBus
        from angerona.core.module_base import BaseModule
        from angerona.gui.attack_heatmap import AttackHeatmapWindow
        from angerona.modules.network_monitor import NetworkMonitorModule
        import threading, time
        class Manager: pass
        manager=Manager(); manager.bus=EventBus(); manager.modules={}; manager.module_trust={}
        manager._shutdown=False; manager._ugcap_paused=False
        manager.verified_readiness=attack_coverage.bind_manager(manager)
        module=NetworkMonitorModule.__new__(NetworkMonitorModule); BaseModule.__init__(module)
        module._angerona_origin='builtin'; manager.modules[module.name]=module
        manager.module_trust[module.name]={'origin':'builtin'}
        module.bind(manager.bus)
        # A real, owned native thread exercises lifecycle and current work;
        # collector/run overrides are inert and cannot touch the host.
        def inert():
            module.set_health(100, 'inert test collector completed')
            module.mark_cycle_complete(interval_seconds=3)
            module.generation_stop_event().wait(10)
        module.run=inert; manager.verified_readiness.register(module); module.start()
        assert module.wait_for_first_cycle(2)
        app=QApplication([]); parent=QWidget(); parent.manager=manager
        window=AttackHeatmapWindow(parent)
        def row():
            return next(i for i in range(window._cov_tbl.rowCount())
                        if window._cov_tbl.item(i,0).text().startswith('T1071 '))
        assert window._cov_tbl.item(row(),5).text()=='collecting'
        item=window._cov_tbl.item(row(),5); window._refresh_coverage()
        assert window._cov_tbl.item(row(),5) is item
        module.stop(); module._thread.join(2); window._refresh_coverage()
        assert window._cov_tbl.item(row(),5).text()=='declared'
        assert 'stopped' in window._cov_tbl.item(row(),6).toolTip()
        window.close(); parent.close(); app.processEvents()
        print('native readiness lifecycle and stable table passed')
    ''')
    env = dict(os.environ, QT_QPA_PLATFORM="offscreen", ANGERONA_DATA=str(tmp_path))
    result = subprocess.run([sys.executable, "-c", script], env=env, capture_output=True,
                            text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "native readiness lifecycle" in result.stdout
