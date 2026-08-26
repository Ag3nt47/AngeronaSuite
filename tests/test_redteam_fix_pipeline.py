from __future__ import annotations

import time

from angerona.core import drill_resolution
from angerona.core.eventbus import Event, EventBus, Severity
from angerona.core.practice_verification import verify_practice_fixes
from angerona.core.storage import FlightRecorder
from angerona.modules.purple_guard import PurpleGuard, install_policies
from angerona.modules.soar import SOARModule
from angerona.modules.soar_engine import ActiveResponseSOAR
from angerona.shark.aar_report import StepVerdict, evaluate


def _key(root) -> None:
    (root / "bus.key").write_text(bytes(range(32)).hex(), encoding="ascii")


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
        {"path": str(marker)},
    )
    purple = Event(
        "Purple Remediation Guard", "candidate detected", Severity.HIGH, started + 0.2,
        {"path": str(marker), "mitre": "T1003",
         "detector_policy": "reviewed-redteam-candidate"},
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
    tmp_path,
) -> None:
    _key(tmp_path)
    recorder = FlightRecorder(tmp_path / "flight-recorder.db")
    bus = EventBus()
    bus.arm(recorder.authority)
    bus.subscribe(recorder.record_bus)
    guard = PurpleGuard(tmp_path)
    guard.bind(bus)
    response = ActiveResponseSOAR()
    response.bind(bus)
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
            # The production budget is 10 seconds. Keep the test bounded while
            # allowing a loaded Windows runner to finish its SQLite WAL commit.
            recorder_timeout=5.0,
        )
    finally:
        recorder.close()

    assert result["ok"], result
    assert result["verified"] == result["total"] == 1
    checks = result["results"][0]["checks"]
    assert all(checks.values())
    assert not list((tmp_path / "drill-sandbox").glob("*_practice_*.txt"))
    closure = drill_resolution.resolution_snapshot(tmp_path)["t1003"]
    assert closure["state"] == drill_resolution.VERIFIED_STATE
    assert closure["verification_mode"] == "practice-probe"
    assert closure["verification_receipt_id"]


def test_process_practice_fix_kills_only_its_tagged_child_and_closes(
    tmp_path,
) -> None:
    _key(tmp_path)
    recorder = FlightRecorder(tmp_path / "flight-recorder.db")
    bus = EventBus()
    bus.arm(recorder.authority)
    bus.subscribe(recorder.record_bus)
    guard = PurpleGuard(tmp_path)
    guard.bind(bus)
    response = ActiveResponseSOAR()
    response.bind(bus)
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
            recorder_timeout=5.0,
        )
    finally:
        recorder.close()

    assert result["ok"], result
    assert result["results"][0]["checks"]["response_succeeded"] is True
    assert result["results"][0]["checks"]["postcondition_satisfied"] is True
    closure = drill_resolution.resolution_snapshot(tmp_path)["t1059"]
    assert closure["state"] == drill_resolution.VERIFIED_STATE
    assert closure["verification_mode"] == "practice-probe"
