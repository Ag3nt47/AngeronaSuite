"""A simulation marker is evidence to inspect, not response authorization."""
from __future__ import annotations

import hashlib
import math
import os
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.core.storage import FlightRecorder
from angerona.core.threat import event_disposition, is_active_threat
from angerona.modules import purple_guard as purple
from angerona.modules.adversary_combat import AdversaryCombat


POLICY = {"T1003": {"state": "CANDIDATE_READY"},
          "T1059": {"state": "CANDIDATE_READY"}}
PRACTICE_RUN = "e05a9c71" * 4


def _supply_contract_inventory(monkeypatch):
    """Supply this offline fixture, while exact child OS receipts stay real.

    This tests issuer/response contracts, not completeness of the operator's
    host inventory. Real Process Monitor lifecycle and fresh-request handling
    still consume a new immutable receipt; no readiness result is mocked.
    """
    from angerona.modules import process_monitor
    from angerona.telemetry.sensors import ProcessSnapshot

    def supplied_inventory(*, max_age=None):
        return ProcessSnapshot(
            processes=(), collected_at=time.time(), complete=True,
            enumerated=0, skipped=0, unreadable=0, identity_incomplete=0,
            error="", enumeration_complete=True,
        )

    monkeypatch.setattr(process_monitor, "process_snapshot", supplied_inventory)


def _runtime(tmp_path):
    bus = EventBus(ring_size=128)
    bus.arm(BusAuthority(b"p" * 32))
    guard = purple.PurpleGuard(tmp_path)
    guard.bind(bus)
    return bus, guard


def _source(bus, **overrides):
    details = {
        "event_type": "process_creation", "pid": 731,
        "process_create_time": 1000.25,
        "cmdline": "python inert ANGERONA_REDTEAM_deadbeef",
        # These are untrusted claims, even on an authenticated transport.
        "run_id": "claimed-run", "step_id": "claimed-step",
        "practice_verification_id": "claimed-practice",
        "lease_id": "claimed-lease", "active_attack": True,
        "response_authorized": True,
    }
    details.update(overrides)
    event = Event("Telemetry Scanner", "untrusted tagged command", Severity.INFO,
                  details=details)
    bus.publish(event)
    return bus.recent(1)[0]


def _refuses_action(bus, event):
    assert bus.verify(event)
    assert event_disposition(event) == "observation"
    assert not is_active_threat(event)
    assert event.details["active_attack"] is False
    assert event.details["response_authorized"] is False
    assert "response_contract" not in event.details
    for key in ("practice_verification_id", "run_id", "step_id", "lease_id",
                "detector_receipt_mac"):
        assert key not in event.details
    combat = object.__new__(AdversaryCombat)
    combat._bus = bus
    combat._mutation_blocked = combat._journal_saturated = False
    combat.policy = lambda: SimpleNamespace(enabled=True, min_severity=Severity.LOW)
    decisions = []
    combat._response_decision = decisions.append
    combat._act_on_process = lambda *a, **k: pytest.fail("marker acted on a process")
    combat._quarantine_file = lambda *a, **k: pytest.fail("marker quarantined a file")
    combat._block_remote_ip = lambda *a, **k: pytest.fail("marker changed firewall")
    combat._handle(event)
    assert decisions == ["not_actionable"]


@pytest.mark.parametrize("kind", ["process", "file"])
def test_unleased_marker_is_authenticated_observation_without_response_authority(tmp_path, kind):
    bus, guard = _runtime(tmp_path)
    if kind == "process":
        source = _source(bus)
        assert bus.verify(source)
        scan = lambda: guard.scan_process_once(POLICY)
    else:
        guard.sandbox.mkdir()
        marker = guard.sandbox / "_redteam_lsass_dump_practice_deadbeef.txt"
        marker.write_text("inert unleased marker", encoding="utf-8")
        scan = lambda: guard.scan_once(POLICY)
    assert scan() == 1
    emitted = [e for e in bus.recent(128) if e.module == guard.name]
    assert len(emitted) == 1
    event = emitted[0]
    assert event.severity == Severity.HIGH
    assert event.details["evidence_type"] == "unleased_simulation_marker"
    assert event.details["detector_verdict"] == "unverified"
    _refuses_action(bus, event)
    assert guard.detected == 0
    assert scan() == 0
    assert len([e for e in bus.recent(128) if e.module == guard.name]) == 1


@pytest.mark.parametrize("kind", ["process", "file"])
def test_forged_nonissuer_lease_cannot_promote_markers(tmp_path, kind):
    bus, guard = _runtime(tmp_path)
    guard._validation_lease = SimpleNamespace(active=True, lease_id="forged")
    if kind == "process":
        _source(bus)
        hits = guard.scan_process_once(POLICY)
    else:
        guard.sandbox.mkdir()
        (guard.sandbox / "_redteam_lsass_dump_forged.txt").write_text("inert")
        hits = guard.scan_once(POLICY)
    assert hits == 0
    assert not [e for e in bus.recent(128) if e.module == guard.name]
    assert guard.detected == 0


@pytest.mark.parametrize("pid,birth", [(True, 100.0), (731, math.inf),
                                      (731, math.nan), (731, None)])
def test_unleased_tuple_variants_cannot_mint_a_contract(tmp_path, pid, birth):
    bus, guard = _runtime(tmp_path)
    _source(bus, pid=pid, process_create_time=birth)
    assert guard.scan_process_once(POLICY) == 1
    _refuses_action(bus, next(e for e in bus.recent(128) if e.module == guard.name))


def test_unleased_observation_does_not_suppress_independent_strong_detection(tmp_path):
    bus, guard = _runtime(tmp_path)
    _source(bus)
    assert guard.scan_process_once(POLICY) == 1
    strong = Event("Independent IOC Detector", "exact malicious content IOC",
        Severity.CRITICAL, details={"active_attack": True, "pid": 731,
            "process_create_time": 1000.25, "response_authorized": True,
            "response_contract": {"version": 1, "actions": ["terminate_process"],
                "targets": {"pid": 731, "process_create_time": 1000.25}}})
    bus.publish(strong)
    event = bus.recent(1)[0]
    assert bus.verify(event)
    assert is_active_threat(event)
    assert AdversaryCombat._response_actions(event) == {"terminate_process"}


@pytest.mark.parametrize("kind", ["process", "file"])
def test_later_issuer_lease_promotes_exact_owned_marker_with_bound_receipt(
        tmp_path, monkeypatch, kind):
    # The fixture owns all artifacts and the fixed inert child. No Combat
    # executor or native firewall provider is constructed.
    _supply_contract_inventory(monkeypatch)
    monkeypatch.setattr(BusAuthority, "_key_path", staticmethod(lambda: tmp_path / "bus.key"))
    recorder = FlightRecorder(tmp_path / "flight-recorder.db")
    bus = EventBus(ring_size=4096)
    bus.arm(recorder.authority)
    bus.subscribe(recorder.record_bus, delivery_budget_ms=60_000)
    guard = purple.PurpleGuard(tmp_path)
    guard.bind(bus)
    target = guard.sandbox
    target.mkdir()
    manager = SimpleNamespace(modules={guard.name: guard}, bus=bus)
    lease = child = None
    if kind == "file":
        marker = target / "_redteam_lsass_dump_owned.txt"
        marker.write_text("inert owned held artifact", encoding="utf-8")
        assert guard.scan_once(POLICY) == 1
    else:
        token = "ANGERONA_REDTEAM_e05a9c71"
        _source(bus, cmdline=f"python {token}", pid=731)
        assert guard.scan_process_once(POLICY) == 1
    assert guard.detected == 0
    try:
        lease = purple.acquire_redteam_validation_lease(
            manager, bus, recorder, tmp_path, target, timeout=3)
        purple.RedTeamValidationLease.consume_for_run(
            lease, run_id=PRACTICE_RUN, target=target, data_root=tmp_path)
        if kind == "file":
            purple.RedTeamValidationLease.register_artifact_handle(
                lease, marker, run_id=PRACTICE_RUN)
            guard.scan_once(POLICY)
        else:
            purple.RedTeamValidationLease.enroll_process_challenge(
                lease, token=token, run_id=PRACTICE_RUN)
            child = subprocess.Popen(
                [getattr(sys, "_base_executable", sys.executable), "-c",
                 "import time; time.sleep(15)", token],
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            bound = purple.RedTeamValidationLease.bind_process_challenge(
                lease, token=token, pid=child.pid, run_id=PRACTICE_RUN)
            assert bound["state"] == "bound"
            guard.scan_process_once(POLICY)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            events = [e for e in bus.recent(4096) if e.module == guard.name
                and e.details.get("receipt_type") == "purple_simulation_validation"
                and e.details.get("evidence_kind") == (
                    "inert_file_marker" if kind == "file" else "nonce_tagged_process")]
            if events:
                break
            time.sleep(.01)
        assert events
        event = events[-1]
        assert bus.verify(event)
        assert event.details["response_authorized"] is True
        assert event.details["lease_id"] == lease.readiness["lease_id"]
        assert purple.RedTeamValidationLease.verify_purple_event(
            lease, event, {"attack_ids": ["T1003" if kind == "file" else "T1059"]})
        if kind == "file":
            assert event.details["response_contract"]["targets"] == {"path": str(marker)}
        else:
            assert event.details["response_contract"]["targets"] == {
                "pid": child.pid, "process_create_time": bound["process_create_time"]}
            assert event.details["source_observation_sha256"]
            assert event.details["practice_verification_id"] == PRACTICE_RUN
            assert hashlib.sha256(os.path.normcase(event.details["exe"]).encode("utf-8")).hexdigest() == bound["executable_sha256"]
            source = next(e for e in reversed(bus.recent(4096))
                if e.module == "Process Monitor"
                and e.details.get("receipt_type") == "native_process_observation"
                and e.details.get("pid") == child.pid)
            forged = Event(source.module, source.message, source.severity,
                details={**source.details, "exe": str(tmp_path / "wrong-python.exe")})
            bus.publish(forged)
            signed_forged = bus.recent(1)[0]
            assert bus.verify(signed_forged)
            # The inner native receipt does not sign the literal exe field.
            # The issuer's separately bound normalized image path must match.
            assert purple.RedTeamValidationLease.verify_process_observation(
                lease, signed_forged, require_live=True)
            assert purple.RedTeamValidationLease.attest_purple_detection(
                lease, guard, technique="T1059",
                observed_target=f"{child.pid}:{token}",
                evidence_kind="nonce_tagged_process", pid=child.pid,
                process_create_time=bound["process_create_time"],
                source_event=signed_forged) == {}
        assert guard.detected >= 1
    finally:
        if child is not None:
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=3)
        threads = [getattr(module, "_thread", None) for module in manager.modules.values()]
        if lease is not None:
            purple.RedTeamValidationLease.release(lease)
        guard.stop()
        for thread in threads:
            if thread is not None:
                thread.join(timeout=3)
                assert not thread.is_alive()
        recorder.close()
