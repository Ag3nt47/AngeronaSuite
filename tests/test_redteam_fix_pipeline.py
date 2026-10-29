from __future__ import annotations

import time
import json
import threading
from types import SimpleNamespace

import pytest

from angerona.core import drill_resolution
from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.core.practice_verification import _find_response, verify_practice_fixes
from angerona.core.storage import FlightRecorder
from angerona.modules.purple_guard import PurpleGuard, install_policies
from angerona.modules.soar import SOARModule
from angerona.modules.soar_engine import ActiveResponseSOAR
from angerona.shark.aar_report import StepVerdict, evaluate


def _key(root) -> None:
    (root / "bus.key").write_text(bytes(range(32)).hex(), encoding="ascii")


def _offline_practice_inventory(monkeypatch):
    from angerona.modules import process_monitor
    from angerona.telemetry.sensors import ProcessSnapshot
    # This fixture supplies only general readiness. The exact owned child is
    # still independently observed by the real native issuer API.
    monkeypatch.setattr(process_monitor, "process_snapshot", lambda *a, **k:
        ProcessSnapshot((), time.time(), True, 0, 0, 0, 0, "", True))


def _shared_practice_combat(root, manager, response):
    from angerona.modules.adversary_combat import AdversaryCombat, CombatPolicy
    combat = AdversaryCombat(root, rollback_anchor={})
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
    return combat


def _assert_issuer_original_response(bus, result):
    verification_id = result["results"][0]["verification_id"]
    events = bus.recent(500)
    detection = next(event for event in events
        if event.module == "Purple Remediation Guard"
        and event.details.get("practice_verification_id") == verification_id)
    response = next(event for event in events
        if event.module == "Active Response SOAR"
        and event.details.get("trigger_ts") == detection.ts
        and event.details.get("mitigated") is True)
    assert bus.verify(detection) and bus.verify(response)
    assert response.details["delegation_mode"] == "issuer-original-event"
    assert response.details["origin_event_digest"] == detection.hmac_sig
    assert response.details["queue_request_id"] is None
    assert not any(event.module in {"Active Response SOAR Request", "Red Team Practice Lab"}
                   for event in events)


def test_active_response_processes_burst_oldest_first(monkeypatch) -> None:
    bus = EventBus()
    module = ActiveResponseSOAR()
    module.bind(bus)
    acted: list[str] = []
    monkeypatch.setenv("ANGERONA_SOAR_KILL_AND_ROLLBACK", "1")
    monkeypatch.setenv("ANGERONA_SOAR_KILL_AND_ROLLBACK_MIN_SEVERITY", "HIGH")
    monkeypatch.setattr(
        module,
        "_event_in_response_scope",
        lambda event: bool((event.details or {}).get("in_scope")),
    )
    monkeypatch.setattr(module, "_kill_and_rollback", lambda event: acted.append(event.message))
    base = time.time()
    bus.publish(Event("Detector", "first", Severity.HIGH, base + 1, {"in_scope": True}))
    bus.publish(Event("Detector", "second", Severity.HIGH, base + 2, {"in_scope": True}))
    bus.publish(Event("Detector", "newest rejected", Severity.HIGH, base + 3,
                      {"in_scope": False}))

    assert module.process_pending_once() == 2
    assert acted == ["first", "second"]
    assert module.process_pending_once() == 0


def test_soar_automation_processes_burst_oldest_first(monkeypatch) -> None:
    bus = EventBus()
    module = SOARModule()
    module.bind(bus)
    handled: list[str] = []
    monkeypatch.setattr(module, "_track_attack", lambda _event: None)
    monkeypatch.setattr(module, "_run_playbook", lambda event: handled.append(event.message))
    base = time.time()
    bus.publish(Event("Detector", "first", Severity.HIGH, base + 1))
    bus.publish(Event("Detector", "second", Severity.HIGH, base + 2))
    bus.publish(Event("Console", "newest ignored", Severity.CRITICAL, base + 3))

    assert module.process_pending_once() == 2
    assert handled == ["first", "second"]
    assert module.process_pending_once() == 0


def test_info_flood_cannot_hide_event_from_active_response(monkeypatch) -> None:
    bus = EventBus(ring_size=3)
    module = ActiveResponseSOAR()
    module.bind(bus)
    acted: list[str] = []
    monkeypatch.setenv("ANGERONA_SOAR_KILL_AND_ROLLBACK", "1")
    monkeypatch.setenv("ANGERONA_SOAR_KILL_AND_ROLLBACK_MIN_SEVERITY", "HIGH")
    monkeypatch.setattr(module, "_event_in_response_scope", lambda _event: True)
    monkeypatch.setattr(module, "_kill_and_rollback", lambda event: acted.append(event.message))

    bus.publish(Event("Detector", "must-survive", Severity.HIGH))
    for index in range(100):
        bus.publish(Event("Telemetry", f"noise-{index}", Severity.INFO))

    assert module.process_pending_once() == 1
    assert acted == ["must-survive"]
    assert module.process_pending_once() == 0


def test_active_response_priority_cursor_preserves_opt_in_medium_floor(
    monkeypatch,
) -> None:
    bus = EventBus(ring_size=3)
    module = ActiveResponseSOAR()
    module.bind(bus)
    acted: list[str] = []
    monkeypatch.setenv("ANGERONA_SOAR_KILL_AND_ROLLBACK", "1")
    monkeypatch.setenv("ANGERONA_SOAR_KILL_AND_ROLLBACK_MIN_SEVERITY", "MEDIUM")
    monkeypatch.setattr(module, "_event_in_response_scope", lambda _event: True)
    monkeypatch.setattr(module, "_kill_and_rollback", lambda event: acted.append(event.message))

    bus.publish(Event(
        "Detector",
        "medium-policy-event",
        Severity.MEDIUM,
        details={"active_attack": True},
    ))

    assert module.process_pending_once() == 1
    assert acted == ["medium-policy-event"]
    assert module.process_pending_once() == 0


def test_info_flood_cannot_hide_event_from_soar_automation(monkeypatch) -> None:
    bus = EventBus(ring_size=3)
    module = SOARModule()
    module.bind(bus)
    handled: list[str] = []
    monkeypatch.setattr(module, "_track_attack", lambda _event: None)
    monkeypatch.setattr(module, "_run_playbook", lambda event: handled.append(event.message))

    bus.publish(Event("Detector", "must-survive", Severity.HIGH))
    for index in range(100):
        bus.publish(Event("Telemetry", f"noise-{index}", Severity.INFO))

    assert module.process_pending_once() == 1
    assert handled == ["must-survive"]
    assert module.process_pending_once() == 0


def test_priority_overflow_never_synthesizes_active_response(monkeypatch) -> None:
    bus = EventBus(ring_size=2, priority_ring_size=2)
    module = ActiveResponseSOAR()
    module.bind(bus)
    acted: list[str] = []
    monkeypatch.setenv("ANGERONA_SOAR_KILL_AND_ROLLBACK", "1")
    monkeypatch.setenv("ANGERONA_SOAR_KILL_AND_ROLLBACK_MIN_SEVERITY", "HIGH")
    monkeypatch.setattr(module, "_event_in_response_scope", lambda _event: True)
    monkeypatch.setattr(module, "_kill_and_rollback", lambda event: acted.append(event.message))

    for index in range(3):
        bus.publish(Event("Detector", f"real-{index}", Severity.HIGH))

    assert module.process_pending_once() == 2
    assert acted == ["real-1", "real-2"]
    assert module.priority_overflow_count == 1
    # The overflow health diagnostic enters the priority lane for visibility,
    # but it is never fed to kill/rollback on the following poll.
    assert module.process_pending_once() == 0
    assert acted == ["real-1", "real-2"]


def test_later_purple_proof_survives_earlier_fim_catch(tmp_path) -> None:
    _key(tmp_path)
    drill_resolution.apply_contracts(
        [{"mitre": "T1003", "name": "Credential Access"}],
        "source-run",
        tmp_path,
        installed=["T1003"],
    )
    started = time.time() + 1
    marker = tmp_path / "drill-sandbox" / "_redteam_lsass_dump_probe.txt"
    history = {
        "run_id": "proof-run",
        "steps": [{
            "stage": "Credential Access (simulated)",
            "technique": "T1003 marker",
            "description": "inert marker",
            "ts_start": started,
            "ts_end": started + 0.1,
            "artifact_paths": [str(marker)],
        }],
    }
    fim = Event(
        "File Integrity Monitor", "file appeared", Severity.HIGH, started + 0.1,
        {"path": str(marker), "evidence_type": "native_analytic_detection",
         "detector_verdict": "positive"},
    )
    purple = Event(
        "Purple Remediation Guard", "candidate detected", Severity.HIGH, started + 0.2,
        {"path": str(marker), "mitre": "T1003",
         "detector_policy": "reviewed-redteam-candidate",
         "evidence_type": "simulation_contract_validation",
         "detector_verdict": "positive"},
    )
    response = Event(
        "Active Response SOAR", "artifact removed", Severity.HIGH, started + 0.3,
        {"path": str(marker), "trigger_ts": purple.ts, "mitigated": True},
    )

    verdicts = evaluate(
        history,
        [fim, purple, response],
        {"Credential Access (simulated)": "detection"},
    )
    assert verdicts[0].catch is fim
    assert verdicts[0].verification_catch is purple
    assert verdicts[0].remediation is response
    metrics = drill_resolution.reconcile_verdicts(
        verdicts,
        "proof-run",
        tmp_path,
    )
    assert metrics["verified_closures"] == 1


def test_rerendering_source_miss_does_not_reopen_verified_fix(tmp_path) -> None:
    _key(tmp_path)
    drill_resolution.apply_contracts(
        [{"mitre": "T1003", "name": "Credential Access"}],
        "source-run",
        tmp_path,
        installed=["T1003"],
    )
    proof = drill_resolution.verify_detector_evidence(
        "T1003",
        "proof-run",
        detector="Purple Remediation Guard",
        event_ts=time.time() + 1,
        event_details={
            "mitre": "T1003",
            "artifact_path": "_redteam_lsass_dump_proof.txt",
            "detector_policy": "reviewed-redteam-candidate",
        },
        data_dir=tmp_path,
    )
    assert proof["ok"]
    drill_resolution.record_findings(
        [{"mitre": "T1003", "name": "Credential Access"}],
        "source-run",
        tmp_path,
        observed_at=time.time() - 10,
    )
    assert drill_resolution.resolution_snapshot(tmp_path)["t1003"]["state"] == (
        drill_resolution.VERIFIED_STATE
    )


def test_one_purple_hit_cannot_hide_a_repeated_technique_miss(tmp_path) -> None:
    _key(tmp_path)
    drill_resolution.apply_contracts(
        [{"mitre": "T1003", "name": "Credential Access"}],
        "source-run",
        tmp_path,
        installed=["T1003"],
    )
    now = time.time()
    proof = Event(
        "Purple Remediation Guard",
        "one occurrence detected",
        Severity.HIGH,
        now,
        {
            "mitre": "T1003",
            "artifact_path": "_redteam_lsass_dump_one.txt",
            "detector_policy": "reviewed-redteam-candidate",
        },
    )
    caught = StepVerdict(
        "Credential Access",
        "T1003 marker",
        "first occurrence",
        now - 1,
        True,
        catch=proof,
        verification_catch=proof,
    )
    missed = StepVerdict(
        "Credential Access",
        "T1003 marker",
        "second occurrence",
        now - 0.5,
        True,
    )

    metrics = drill_resolution.reconcile_verdicts(
        [caught, missed],
        "mixed-run",
        tmp_path,
    )

    assert metrics["verified_closures"] == 0
    assert caught.finding_resolved is False
    assert missed.finding_resolved is False
    assert drill_resolution.resolution_snapshot(tmp_path)["t1003"]["state"] == "APPLIED"


def test_practice_fix_requires_detection_recorder_response_and_cleanup(
    tmp_path, monkeypatch,
) -> None:
    _offline_practice_inventory(monkeypatch)
    _key(tmp_path)
    recorder = FlightRecorder(tmp_path / "flight-recorder.db")
    bus = EventBus()
    bus.arm(recorder.authority)
    bus.subscribe(recorder.record_bus)
    guard = PurpleGuard(tmp_path)
    guard.bind(bus)
    response = ActiveResponseSOAR()
    response.bind(bus)
    manager = SimpleNamespace(bus=bus, recorder=recorder, modules={
        guard.name: guard, response.name: response,
    })
    combat = _shared_practice_combat(tmp_path, manager, response)
    install_policies([{"mitre": "T1003"}], "source-run", tmp_path)
    drill_resolution.apply_contracts(
        [{"mitre": "T1003", "name": "Credential Access"}],
        "source-run",
        tmp_path,
        installed=["T1003"],
    )
    try:
        result = verify_practice_fixes(
            ["T1003"],
            source_run_id="source-run",
            data_dir=tmp_path,
            db_path=tmp_path / "flight-recorder.db",
            bus=bus,
            purple_guard=guard,
            active_response=response,
            manager=manager, recorder=recorder,
            # The production budget is 10 seconds. Keep the test bounded while
            # allowing a loaded Windows runner to finish its SQLite WAL commit.
            recorder_timeout=5.0,
        )
    finally:
        combat.stop()
        recorder.close()

    assert result["ok"], json.dumps(result, indent=2)
    assert result["verified"] == result["total"] == 1
    _assert_issuer_original_response(bus, result)
    assert guard._validation_lease is None
    checks = result["results"][0]["checks"]
    assert all(checks.values())
    assert not list((tmp_path / "drill-sandbox").glob("*_practice_*.txt"))
    closure = drill_resolution.resolution_snapshot(tmp_path)["t1003"]
    assert closure["state"] == drill_resolution.VERIFIED_STATE
    assert closure["verification_mode"] == "practice-probe"
    assert closure["verification_receipt_id"]


@pytest.mark.parametrize("outcome", ["late-success", "priority-overflow"])
def test_practice_observes_committed_receipt_without_repeating_native_action(
    tmp_path, monkeypatch, outcome,
) -> None:
    _offline_practice_inventory(monkeypatch)
    _key(tmp_path)
    recorder = FlightRecorder(tmp_path / "flight-recorder.db")
    bus = EventBus()
    bus.arm(recorder.authority)
    bus.subscribe(recorder.record_bus)
    guard, response = PurpleGuard(tmp_path), ActiveResponseSOAR()
    guard.bind(bus)
    response.bind(bus)
    manager = SimpleNamespace(bus=bus, recorder=recorder, modules={
        guard.name: guard, response.name: response,
    })
    combat = _shared_practice_combat(tmp_path, manager, response)
    install_policies([{"mitre": "T1059"}], "source-run", tmp_path)
    drill_resolution.apply_contracts(
        [{"mitre": "T1059", "name": "Benign Execution"}], "source-run", tmp_path,
        installed=["T1059"],
    )
    release_receipt = threading.Event()
    receipts, observations = [], []
    emit = combat.emit
    observe = response.observe_issuer_completion
    priority_since = bus.priority_since

    def delayed_emit(message, *args, **details):
        if (details.get("trigger_module") == guard.name
                and details.get("action_succeeded") is True
                and details.get("actions") == ["terminate_process"]):
            receipts.append(details)
            # The action has already committed. Release only when the verifier
            # enters observation; no real-time scheduling assumption is needed.
            assert release_receipt.wait(8.0)
        return emit(message, *args, **details)

    def observe_without_dispatch(event, *, timeout):
        observations.append(event.hmac_sig)
        assert 0.0 <= timeout <= 5.0
        release_receipt.set()
        with monkeypatch.context() as patch:
            submit = combat._submit
            observer_thread = threading.get_ident()
            def deny_observer_submission(candidate):
                if (threading.get_ident() == observer_thread
                        and candidate.hmac_sig == event.hmac_sig):
                    pytest.fail("observation resubmitted its original action")
                return submit(candidate)
            patch.setattr(combat, "_submit", deny_observer_submission)
            completed = observe(event, timeout=timeout)
        if outcome == "priority-overflow":
            def overflow(cursor):
                current, events, _overflow = priority_since(cursor)
                return current, events, True
            monkeypatch.setattr(bus, "priority_since", overflow)
        return completed

    monkeypatch.setattr(combat, "emit", delayed_emit)
    monkeypatch.setattr(response, "observe_issuer_completion", observe_without_dispatch)
    try:
        result = verify_practice_fixes(
            ["T1059"], source_run_id="source-run", data_dir=tmp_path,
            db_path=tmp_path / "flight-recorder.db", bus=bus, purple_guard=guard,
            active_response=response, manager=manager, recorder=recorder,
            recorder_timeout=5.0,
        )
        actions = [row for row in combat.list_actions(limit=500)
                   if row.get("action") == "terminate_process" and row.get("status") == "applied"]
    finally:
        release_receipt.set()
        combat.stop()
        recorder.close()
    assert len(receipts) == len(actions) == len(observations) == 1
    assert len(receipts[0]["action_ids"]) == 1
    assert guard._validation_lease is None
    if outcome == "late-success":
        assert result["ok"], json.dumps(result, indent=2)
        _assert_issuer_original_response(bus, result)
        assert all(result["results"][0]["checks"].values())
    else:
        assert not result["ok"]
        assert result["verified"] == 0
        assert "overflowed during response observation" in result["results"][0]["error"]


@pytest.mark.parametrize("broken", ["valid", "digest", "module", "mode", "signature"])
def test_practice_response_summary_requires_exact_signed_original(tmp_path, monkeypatch, broken):
    monkeypatch.setattr(BusAuthority, "_key_path", staticmethod(lambda: tmp_path / "bus.key"))
    recorder = FlightRecorder(tmp_path / "flight-recorder.db")
    try:
        bus = EventBus()
        bus.arm(recorder.authority)
        bus.publish(Event("Purple Remediation Guard", "original", Severity.HIGH))
        trigger = bus.recent(1)[0]
        details = {"trigger_ts": trigger.ts, "trigger_module": trigger.module,
                   "origin_event_digest": trigger.hmac_sig,
                   "delegation_mode": "issuer-original-event", "mitigated": True}
        if broken == "digest": details["origin_event_digest"] = "0" * 64
        elif broken == "module": details["trigger_module"] = "another detector"
        elif broken == "mode": details["delegation_mode"] = "copied metadata"
        bus.publish(Event("Active Response SOAR", "receipt", Severity.HIGH, details=details))
        response = bus.recent(1)[0]
        if broken == "signature":
            response = Event(response.module, "altered receipt", response.severity,
                             ts=response.ts, details=response.details, hmac_sig=response.hmac_sig)
        found = _find_response(bus, trigger, trigger.ts, events=[response])
        assert (found is response) is (broken == "valid")
    finally:
        recorder.close()


def test_process_practice_fix_kills_only_its_tagged_child_and_closes(
    tmp_path, monkeypatch,
) -> None:
    _offline_practice_inventory(monkeypatch)
    _key(tmp_path)
    recorder = FlightRecorder(tmp_path / "flight-recorder.db")
    bus = EventBus()
    bus.arm(recorder.authority)
    bus.subscribe(recorder.record_bus)
    guard = PurpleGuard(tmp_path)
    guard.bind(bus)
    response = ActiveResponseSOAR()
    response.bind(bus)
    manager = SimpleNamespace(bus=bus, recorder=recorder, modules={
        guard.name: guard, response.name: response,
    })
    combat = _shared_practice_combat(tmp_path, manager, response)
    install_policies([{"mitre": "T1059"}], "source-run", tmp_path)
    drill_resolution.apply_contracts(
        [{"mitre": "T1059", "name": "Benign Execution"}],
        "source-run",
        tmp_path,
        installed=["T1059"],
    )
    try:
        result = verify_practice_fixes(
            ["T1059"],
            source_run_id="source-run",
            data_dir=tmp_path,
            db_path=tmp_path / "flight-recorder.db",
            bus=bus,
            purple_guard=guard,
            active_response=response,
            manager=manager, recorder=recorder,
            recorder_timeout=5.0,
        )
    finally:
        combat.stop()
        recorder.close()

    assert result["ok"], json.dumps(result, indent=2)
    _assert_issuer_original_response(bus, result)
    assert guard._validation_lease is None
    assert result["results"][0]["checks"]["response_succeeded"] is True
    assert result["results"][0]["checks"]["postcondition_satisfied"] is True
    closure = drill_resolution.resolution_snapshot(tmp_path)["t1059"]
    assert closure["state"] == drill_resolution.VERIFIED_STATE
    assert closure["verification_mode"] == "practice-probe"
