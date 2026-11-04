from __future__ import annotations

import hashlib
import threading
import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core import report_attest
from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.core.storage import FlightRecorder
from angerona.gui.main_window import MainWindow
from angerona.gui.pages import AARDialog
from angerona.modules.purple_guard import (
    PurpleGuard,
    acquire_redteam_validation_lease,
)
from angerona.shark.aar_report import evaluate, generate_aar
from angerona.shark.red_team import (
    REDTEAM_STAGE_CATEGORY,
    RedTeamEngine,
)
from angerona.shark.run_manifest import (
    build_run_history,
    load_verified_history,
    preflight_run,
    write_run_history,
)
from test_cycle27_redteam_validation_lease import _supply_contract_inventory
from test_yara_automatic_response import controlled_runtime as controlled_runtime


_KEY = bytes.fromhex("42" * 32)


def _history(path: Path, started: float | None = None) -> dict:
    ts = time.time() if started is None else started
    return {
        "run_id": "redteam-evidence-split",
        "steps": [{
            "stage": "Credential Access (simulated)",
            "technique": "T1003 marker",
            "description": "inert marker",
            "ts_start": ts,
            "ts_end": ts + 0.1,
            "artifact_paths": [str(path)],
        }],
    }


def _event(
    module: str,
    path: Path,
    severity: Severity,
    ts: float,
    **details,
) -> Event:
    return Event(
        module,
        f"{module} evidence",
        severity,
        ts,
        {"path": str(path), **details},
        hmac_sig="stored-authenticated-event",
    )


def _install_test_keys(monkeypatch, root: Path) -> None:
    key_path = root / "bus.key"
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_text(_KEY.hex(), encoding="ascii")
    monkeypatch.setattr(report_attest, "_key_path", lambda: key_path)
    monkeypatch.setattr(BusAuthority, "_key_path", staticmethod(lambda: key_path))


def _validation_runtime(root: Path):
    bus = EventBus(ring_size=4096)
    recorder = FlightRecorder(root / "flight-recorder.db")
    bus.arm(recorder.authority)
    bus.subscribe(recorder.record_bus, delivery_budget_ms=60_000)
    guard = PurpleGuard(root)
    guard.bind(bus)
    manager = SimpleNamespace(modules={guard.name: guard}, bus=bus)
    return bus, recorder, guard, manager


def test_strict_aar_rejects_raw_info_self_credit_and_failed_response(tmp_path) -> None:
    marker = tmp_path / "_redteam_lsass_dump_probe.txt"
    started = time.time()
    events = [
        _event("Red Team Attack Engine", marker, Severity.CRITICAL, started + 0.1),
        _event(
            "Process Monitor",
            marker,
            Severity.INFO,
            started + 0.2,
            event_type="process_creation",
        ),
        _event(
            "Active Response SOAR",
            marker,
            Severity.CRITICAL,
            started + 0.3,
            mitigated=False,
        ),
    ]

    verdict = evaluate(
        _history(marker, started),
        events,
        REDTEAM_STAGE_CATEGORY,
        require_authenticated=True,
        event_verifier=lambda _event: True,
        native_verifier=lambda _event, _step: True,
        purple_verifier=lambda _event, _step: True,
    )[0]

    assert verdict.observation is events[1]
    assert verdict.catch is None
    assert verdict.native_catch is None
    assert verdict.simulation_validation is None
    assert verdict.remediation is None


def test_strict_aar_splits_native_purple_observation_and_response(tmp_path) -> None:
    marker = tmp_path / "_redteam_lsass_dump_probe.txt"
    started = time.time()
    raw = _event(
        "Process Monitor",
        marker,
        Severity.INFO,
        started + 0.1,
        event_type="process_creation",
    )
    native = _event(
        "File Integrity Monitor",
        marker,
        Severity.MEDIUM,
        started + 0.2,
        evidence_type="native_analytic_detection",
        detector_verdict="positive",
    )
    purple = _event(
        "Purple Remediation Guard",
        marker,
        Severity.HIGH,
        started + 0.3,
        mitre="T1003",
        detector_policy="reviewed-redteam-candidate",
        evidence_type="simulation_contract_validation",
        detector_verdict="positive",
    )
    response = _event(
        "Active Response SOAR",
        marker,
        Severity.HIGH,
        started + 0.4,
        trigger_ts=purple.ts,
        mitigated=True,
    )

    verdict = evaluate(
        _history(marker, started),
        [response, purple, native, raw],
        REDTEAM_STAGE_CATEGORY,
        require_authenticated=True,
        event_verifier=lambda _event: True,
        native_verifier=lambda _event, _step: True,
        purple_verifier=lambda _event, _step: True,
    )[0]

    assert verdict.observation is raw
    assert verdict.native_catch is native
    assert verdict.simulation_validation is purple
    assert verdict.catch is native
    assert verdict.remediation is response


def test_strict_aar_rejects_spoofed_producers_and_all_raw_shapes(tmp_path) -> None:
    marker = tmp_path / "_redteam_lsass_dump_probe.txt"
    started = time.time()
    spoofed_native = _event(
        "Totally Unregistered Detector",
        marker,
        Severity.HIGH,
        started + 0.1,
        evidence_type="native_analytic_detection",
        detector_verdict="positive",
    )
    spoofed_purple = _event(
        "Purple Remediation Guard",
        marker,
        Severity.HIGH,
        started + 0.2,
        mitre="T1003",
        detector_policy="reviewed-redteam-candidate",
        evidence_type="simulation_contract_validation",
        detector_verdict="positive",
    )
    raw_events = [
        _event(
            "Registered Looking Sensor",
            marker,
            Severity.HIGH,
            started + 0.3 + index / 100,
            event_type=event_type,
            evidence_type="native_analytic_detection",
            detector_verdict="positive",
        )
        for index, event_type in enumerate(
            (
                "process_creation",
                "raw_telemetry",
                "sensor_observation",
                "network_observation",
                "file_observation",
                "etw_observation",
            )
        )
    ]

    verdict = evaluate(
        _history(marker, started),
        [spoofed_native, spoofed_purple, *raw_events],
        REDTEAM_STAGE_CATEGORY,
        require_authenticated=True,
        event_verifier=lambda _event: True,
        native_verifier=lambda event, _step: event is not spoofed_native,
        purple_verifier=lambda _event, _step: False,
    )[0]

    assert verdict.observation is spoofed_native
    assert verdict.native_catch is None
    assert verdict.simulation_validation is None
    assert verdict.catch is None


def test_strict_aar_requires_cryptographic_event_verifier(tmp_path) -> None:
    marker = tmp_path / "_redteam_lsass_dump_probe.txt"
    started = time.time()
    fake_hmac = _event(
        "File Integrity Monitor",
        marker,
        Severity.HIGH,
        started + 0.1,
        evidence_type="native_analytic_detection",
        detector_verdict="positive",
    )
    verdict = evaluate(
        _history(marker, started),
        [fake_hmac],
        REDTEAM_STAGE_CATEGORY,
        require_authenticated=True,
        event_verifier=lambda _event: False,
        native_verifier=lambda _event, _step: True,
    )[0]
    assert verdict.observation is None
    assert verdict.catch is None


def test_custom_probe_is_informational_and_filename_cannot_collide(tmp_path) -> None:
    engine = RedTeamEngine(tmp_path / "data", documents_dir=tmp_path / "markers")
    engine.run_id = "custom-collision-test"
    engine._custom = {"name": "lsass_dump_T1003", "payload": "inert text"}
    engine._step_custom((0.0, 0.0))

    step = engine.steps[0]
    marker = Path(step.artifact_paths[0])
    assert marker.name.startswith("_redteam_custom_")
    assert "lsass_dump" not in marker.name.casefold()
    assert "t1003" not in marker.name.casefold()

    purple = _event(
        "Purple Remediation Guard",
        marker,
        Severity.HIGH,
        step.ts_start + 0.1,
        mitre="T1003",
        detector_policy="reviewed-redteam-candidate",
    )
    native = _event(
        "File Integrity Monitor", marker, Severity.HIGH, step.ts_start + 0.05
    )
    verdict = evaluate(
        {"run_id": engine.run_id, "steps": [step.__dict__]},
        [native, purple],
        REDTEAM_STAGE_CATEGORY,
        require_authenticated=True,
        event_verifier=lambda _event: True,
        native_verifier=lambda _event, _step: True,
        purple_verifier=lambda _event, _step: True,
    )[0]
    assert verdict.category == "informational"
    assert verdict.observation is native
    assert verdict.catch is None
    engine.stop_and_clean()


def test_engine_binds_readiness_into_signed_history_and_resets_target(
    tmp_path, monkeypatch
) -> None:
    inventory_ages = _supply_contract_inventory(monkeypatch)
    _install_test_keys(monkeypatch, tmp_path)
    root = tmp_path / "data"
    bus, recorder, guard, manager = _validation_runtime(root)
    engine = RedTeamEngine(root)
    custom_target = tmp_path / "operator-target"
    for name in (
        "_step_initial_access",
        "_step_recon",
        "_step_credential_access",
        "_step_privilege_escalation",
        "_step_defense_evasion",
        "_step_registry_runkey",
        "_step_scheduled_task",
        "_step_wmi_persistence",
        "_step_lateral_movement",
        "_step_c2_beacon",
        "_step_exfil_staging",
        "_step_ransomware_canary",
        "_step_data_destruction",
        "_step_random_processes",
    ):
        monkeypatch.setattr(engine, name, lambda _jitter: None)

    lease = acquire_redteam_validation_lease(
        manager, bus, recorder, root, custom_target, timeout=3
    )
    assert 0.0 in inventory_ages  # Real requested observation consumed fixture input.
    try:
        assert engine.start(
            jitter_range=(0, 0),
            noise_chance=0,
            campaign=True,
            target_dir=custom_target,
            validation_lease=lease,
        )
        assert engine._thread is not None
        engine._thread.join(timeout=5)
        assert not engine.is_running
        assert engine.documents_dir == engine.default_documents_dir

        history = load_verified_history(engine.history_path)
        receipt = history["validation_readiness"]
        assert receipt["policy_count"] == 13
        assert receipt["recorder"]["authenticated"] is True
        assert receipt["bound_run_id"] == history["run_id"]
        assert Path(receipt["bound_target"]) == custom_target.resolve(strict=False)
        assert lease.verify_run_history(history)
    finally:
        lease.release()
        guard.stop()
        recorder.close()


def test_engine_refusal_without_live_lease_preserves_prior_history(tmp_path) -> None:
    engine = RedTeamEngine(tmp_path / "data")
    engine.history_path.parent.mkdir(parents=True, exist_ok=True)
    engine.history_path.write_text("stale-history-sentinel", encoding="utf-8")
    prior_run_id = engine.run_id

    assert not engine.start(
        jitter_range=(0, 0),
        noise_chance=0,
        complexity=1,
        target_dir=tmp_path / "target",
    )
    assert engine.run_id == prior_run_id
    assert engine.history_path.read_text(encoding="utf-8") == "stale-history-sentinel"
    assert engine.cancel_evidence_hold()


def test_engine_rejects_target_mismatch_and_released_lease_replay(
    tmp_path, monkeypatch
) -> None:
    inventory_ages = _supply_contract_inventory(monkeypatch)
    _install_test_keys(monkeypatch, tmp_path)
    root = tmp_path / "runtime"
    target = root / "target-a"
    bus, recorder, guard, manager = _validation_runtime(root)
    lease = acquire_redteam_validation_lease(
        manager, bus, recorder, root, target, timeout=3
    )
    assert 0.0 in inventory_ages  # Real requested observation consumed fixture input.
    engine = RedTeamEngine(root)
    for name in (
        "_step_initial_access",
        "_step_recon",
        "_step_credential_access",
        "_step_privilege_escalation",
        "_step_defense_evasion",
        "_step_registry_runkey",
        "_step_scheduled_task",
        "_step_wmi_persistence",
        "_step_lateral_movement",
        "_step_c2_beacon",
        "_step_exfil_staging",
        "_step_ransomware_canary",
        "_step_data_destruction",
        "_step_random_processes",
    ):
        monkeypatch.setattr(engine, name, lambda _jitter: None)
    try:
        assert not engine.start(
            jitter_range=(0, 0),
            noise_chance=0,
            target_dir=root / "target-b",
            validation_lease=lease,
        )
        assert engine.run_id == ""
        assert engine.start(
            jitter_range=(0, 0),
            noise_chance=0,
            target_dir=target,
            validation_lease=lease,
        )
        assert engine._thread is not None
        engine._thread.join(timeout=5)
        history_before_release = engine.history_path.read_bytes()
        lease.release()
        assert not engine.start(
            jitter_range=(0, 0),
            noise_chance=0,
            target_dir=target,
            validation_lease=lease,
        )
        assert engine.history_path.read_bytes() == history_before_release
    finally:
        lease.release()
        guard.stop()
        recorder.close()


def test_generate_aar_rejects_structural_fake_recorder(tmp_path, monkeypatch) -> None:
    root = tmp_path / "root"
    root.mkdir()
    _install_test_keys(monkeypatch, root)
    marker = root / "drill-sandbox" / "_redteam_lsass_dump_probe.txt"
    started = time.time()
    contract = preflight_run(
        kind="red_team",
        cycles=1,
        jitter_range=(0, 0),
        noise_chance=0,
        target_dir=marker.parent,
    )
    history = build_run_history(
        kind="red_team",
        run_id="fake-recorder-run",
        generated="test",
        steps=_history(marker, started)["steps"],
        preflight=contract,
        status="completed",
    )
    assert write_run_history(root / "redteam_history.json", history)

    class StructuralFakeRecorder:
        def events_in_window(self, *_args, **_kwargs):
            return [_event(
                "File Integrity Monitor",
                marker,
                Severity.HIGH,
                started + 0.1,
                evidence_type="native_analytic_detection",
                detector_verdict="positive",
            )]

    result = generate_aar(
        root,
        history_name="redteam_history.json",
        stage_category=REDTEAM_STAGE_CATEGORY,
        report_basename="redteam_aar",
        recorder=StructuralFakeRecorder(),  # type: ignore[arg-type]
    )
    assert "exact built-in FlightRecorder" in result
    assert not (root / "redteam_aar.json").exists()


def test_generate_aar_ignores_instance_verifiers_that_accept_a_fake_hmac(
    tmp_path, monkeypatch
) -> None:
    inventory_ages = _supply_contract_inventory(monkeypatch)
    root = tmp_path / "root"
    root.mkdir()
    _install_test_keys(monkeypatch, root)
    bus, recorder, guard, manager = _validation_runtime(root)
    target = root / "target"
    marker = target / "_redteam_lsass_dump_instance-spoof.txt"
    started = time.time()
    lease = acquire_redteam_validation_lease(
        manager, bus, recorder, root, target, timeout=3
    )
    assert 0.0 in inventory_ages  # Real requested observation consumed fixture input.
    try:
        run_id = "redteam-instance-verifier-spoof"
        receipt = lease.consume_for_run(
            run_id=run_id,
            target=target,
            data_root=root,
        )
        preflight = preflight_run(
            kind="red_team",
            cycles=1,
            jitter_range=(0, 0),
            noise_chance=0,
            target_dir=target,
        )
        history = build_run_history(
            kind="red_team",
            run_id=run_id,
            generated="2026-08-28 00:00:00",
            steps=[{
                "stage": "Credential Access (simulated)",
                "technique": "T1003 marker",
                "description": "inert marker",
                "ts_start": started,
                "ts_end": started + 0.1,
                "artifact_paths": [str(marker)],
                "ok": True,
            }],
            preflight=preflight,
            status="completed",
        )
        history["validation_readiness"] = receipt
        assert write_run_history(root / "redteam_history.json", history)

        recorder.record_bus(_event(
            "Process Monitor",
            marker,
            Severity.INFO,
            started + 0.05,
            event_type="process_creation",
        ))
        # Storage decoding and the old AAR verifier both dispatched through
        # these writable instance attributes. The production verifier must use
        # the exact BusAuthority/EventBus class implementations instead.
        monkeypatch.setattr(recorder.authority, "verify", lambda _event: True)
        monkeypatch.setattr(bus, "verify", lambda _event: True)

        generate_aar(
            root,
            history_name="redteam_history.json",
            stage_category=REDTEAM_STAGE_CATEGORY,
            title="RED TEAM ATTACK",
            report_basename="redteam_aar",
            recorder=recorder,
            bus=bus,
            manager=manager,
            validation_lease=lease,
        )
        report = json.loads((root / "redteam_aar.json").read_text(encoding="utf-8"))
        assert report["evidence_taxonomy"]["sensor_observation"]["count"] == 0
        assert report["evidence_taxonomy"]["native_analytic_detection"]["count"] == 0
        assert report["detection_caught"] == 0
    finally:
        lease.release()
        guard.stop()
        recorder.close()


def test_redteam_refresh_reloads_attested_report_without_rescoring(
    tmp_path, monkeypatch
) -> None:
    _install_test_keys(monkeypatch, tmp_path)
    text = "RED TEAM ATTACK persisted authenticated report"
    (tmp_path / "redteam_aar.txt").write_text(text, encoding="utf-8")
    payload = report_attest.attest({
        "run_id": "redteam-persisted-001",
        "report_basename": "redteam_aar",
        "report_kind": "red_team",
        "report_text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
    })
    (tmp_path / "redteam_aar.json").write_text(
        json.dumps(payload),
        encoding="utf-8",
    )

    class Body:
        value = ""

        def setPlainText(self, value):
            self.value = value

    dialog = SimpleNamespace(
        data_dir=tmp_path,
        _redteam=True,
        _report_binding={},
        body=Body(),
    )
    AARDialog.refresh(dialog)
    assert dialog.body.value == text
    assert dialog._report_binding["run_id"] == "redteam-persisted-001"
    assert not (tmp_path / "redteam_history.json").exists()
    assert not (tmp_path / "flight-recorder.db").exists()

    (tmp_path / "redteam_aar.txt").write_text(text + " tampered", encoding="utf-8")
    AARDialog.refresh(dialog)
    assert "does not match its authenticated metadata" in dialog.body.value


def test_generate_aar_uses_passed_run_recorder_not_ambient_config(
    tmp_path, monkeypatch
) -> None:
    inventory_ages = _supply_contract_inventory(monkeypatch)
    root = tmp_path / "requested-root"
    other = tmp_path / "unrelated-root"
    root.mkdir()
    other.mkdir()
    _install_test_keys(monkeypatch, root)
    target = root / "drill-sandbox"
    bus, requested, guard, manager = _validation_runtime(root)
    unrelated = FlightRecorder(other / "flight-recorder.db")
    engine = RedTeamEngine(root)
    for name in (
        "_step_initial_access",
        "_step_recon",
        "_step_privilege_escalation",
        "_step_defense_evasion",
        "_step_registry_runkey",
        "_step_scheduled_task",
        "_step_wmi_persistence",
        "_step_lateral_movement",
        "_step_c2_beacon",
        "_step_exfil_staging",
        "_step_ransomware_canary",
        "_step_data_destruction",
        "_step_random_processes",
    ):
        monkeypatch.setattr(engine, name, lambda _jitter: None)
    lease = acquire_redteam_validation_lease(
        manager, bus, requested, root, target, timeout=3
    )
    assert 0.0 in inventory_ages  # Real requested observation consumed fixture input.
    try:
        assert engine.start(
            jitter_range=(0, 0),
            noise_chance=0,
            campaign=True,
            target_dir=target,
            validation_lease=lease,
        )
        assert engine._thread is not None
        engine._thread.join(timeout=5)

        refused = generate_aar(
            root,
            history_name="redteam_history.json",
            stage_category=REDTEAM_STAGE_CATEGORY,
            title="RED TEAM ATTACK",
            report_basename="redteam_aar",
            recorder=unrelated,
            bus=bus,
            manager=manager,
            validation_lease=lease,
        )
        assert "recorder integrity check failed" in refused
        assert not (root / "redteam_aar.json").exists()

        generated = generate_aar(
            root,
            history_name="redteam_history.json",
            stage_category=REDTEAM_STAGE_CATEGORY,
            title="RED TEAM ATTACK",
            report_basename="redteam_aar",
            recorder=requested,
            bus=bus,
            manager=manager,
            validation_lease=lease,
        )
        assert "AFTER-ACTION REPORT" in generated
        report = json.loads((root / "redteam_aar.json").read_text(encoding="utf-8"))
        taxonomy = report["evidence_taxonomy"]
        assert taxonomy["native_analytic_detection"]["count"] == 0
        assert "not real-attack" in report["coverage_interpretation"]
    finally:
        lease.release()
        guard.stop()
        requested.close()
        unrelated.close()


def test_safe_end_to_end_campaign_validates_all_13_pipeline_canaries(
    tmp_path, monkeypatch
) -> None:
    """Exercise inert files/process telemetry only; no exploit or host mutation."""
    inventory_ages = _supply_contract_inventory(monkeypatch)
    _install_test_keys(monkeypatch, tmp_path)
    root = tmp_path / "runtime"
    target = root / "drill-sandbox"
    bus = EventBus(ring_size=2048)
    recorder = FlightRecorder(root / "flight-recorder.db")
    bus.arm(recorder.authority)
    bus.subscribe(recorder.record_bus, delivery_budget_ms=60_000)
    guard = PurpleGuard(root)
    guard.bind(bus)
    manager = SimpleNamespace(
        modules={"Purple Remediation Guard": guard},
        bus=bus,
    )
    lease = acquire_redteam_validation_lease(
        manager, bus, recorder, root, target, timeout=5
    )
    assert 0.0 in inventory_ages  # Real requested observation consumed fixture input.
    engine = RedTeamEngine(root)
    engine.hold_evidence_for_aar()
    try:
        assert engine.start(
            jitter_range=(0, 0),
            noise_chance=0,
            complexity=1,
            campaign=True,
            target_dir=target,
            validation_lease=lease,
        )
        assert engine._thread is not None
        engine._thread.join(timeout=10)
        assert not engine.is_running

        first_marker = Path(next(
            path
            for step in engine.steps
            for path in step.artifact_paths
        ))
        for module, details in (
            (
                "Totally Unregistered Detector",
                {
                    "evidence_type": "native_analytic_detection",
                    "detector_verdict": "positive",
                },
            ),
            (
                "Registered Looking Sensor",
                {
                    "event_type": "process_creation",
                    "evidence_type": "native_analytic_detection",
                    "detector_verdict": "positive",
                },
            ),
            (
                "Purple Remediation Guard",
                {
                    "mitre": "T1566.001",
                    "detector_policy": "reviewed-redteam-candidate",
                    "evidence_type": "simulation_contract_validation",
                    "detector_verdict": "positive",
                },
            ),
        ):
            bus.publish(Event(
                module,
                "adversarial producer-name spoof",
                Severity.HIGH,
                details={"path": str(first_marker), **details},
            ))

        execution = next(
            step for step in engine.steps
            if step.stage == "Benign Execution (simulated)"
        )
        assert execution.pids and execution.correlation_tokens
        bus.publish(Event(
            "Process Monitor",
            "raw tagged process observation",
            Severity.INFO,
            details={
                "event_type": "process_creation",
                "pid": execution.pids[0],
                "process_create_time": time.time(),
                "cmdline": (
                    f"python -c inert {execution.correlation_tokens[0]}"
                ),
            },
        ))

        deadline = time.monotonic() + 6
        techniques: set[str] = set()
        while time.monotonic() < deadline:
            rows = recorder.events_in_window(
                engine.steps[0].ts_start - 2,
                time.time() + 1,
            )
            techniques = {
                str((event.details or {}).get("mitre") or "")
                for event in rows
                if event.module == "Purple Remediation Guard"
            }
            if len(techniques) == 13:
                break
            time.sleep(0.05)
        assert len(techniques) == 13

        generate_aar(
            root,
            history_name="redteam_history.json",
            stage_category=REDTEAM_STAGE_CATEGORY,
            title="RED TEAM ATTACK",
            report_basename="redteam_aar",
            recorder=recorder,
            bus=bus,
            manager=manager,
            validation_lease=lease,
        )
        report = json.loads((root / "redteam_aar.json").read_text(encoding="utf-8"))
        taxonomy = report["evidence_taxonomy"]
        assert taxonomy["denominator"] == 13
        assert taxonomy["simulation_contract_validation"]["count"] == 13
        assert taxonomy["simulation_contract_validation"]["simulation_only"] is True
        assert taxonomy["native_analytic_detection"]["count"] == 0
        assert report["validation_readiness"]["recorder"]["authenticated"] is True
    finally:
        scope = engine.evidence_cleanup_scope()
        engine.release_evidence_after_aar(scope)
        lease.release()
        recorder.close()


@pytest.fixture
def engine_start_refusal_runtime(monkeypatch, request):
    """Only this fault test supplies a real, current, single-owned-PID input.

    Completeness describes this explicit fixture scope, never the host table.
    The real Process Monitor, issuer, recorder and generation gates consume it;
    native detector/campaign coverage is tested by separate live cohorts.
    The shared runtime verifies its initial lease with its own supplier.
    Install this observer after setup and keep it through producer retirement.
    """
    import math
    import os
    from types import MappingProxyType

    import psutil

    from angerona.modules import process_monitor
    from angerona.telemetry.sensors import ProcessSnapshot

    pid = os.getpid()
    owner = psutil.Process(pid)
    birth, image = owner.create_time(), owner.exe()
    observed = []

    def owned_inventory(*, max_age=None):
        row = psutil.Process(pid).as_dict(attrs=(
            "pid", "ppid", "name", "exe", "cmdline", "create_time",
        ))
        # Missing/inaccessible or changed native identity remains a test failure.
        assert row["pid"] == pid and row["create_time"] == birth
        assert math.isfinite(birth) and birth > 0 and row["exe"] == image
        assert isinstance(image, str) and Path(image).is_absolute()
        assert isinstance(row["name"], str) and row["name"]
        assert type(row["ppid"]) is int and row["ppid"] >= 0
        assert isinstance(row["cmdline"], (list, tuple)) and row["cmdline"]
        assert all(isinstance(part, str) for part in row["cmdline"])
        row["cmdline"] = tuple(row["cmdline"])
        snapshot = ProcessSnapshot(
            processes=(MappingProxyType(row),), collected_at=time.time(), complete=True,
            enumerated=1, skipped=0, unreadable=0, identity_incomplete=0,
            error="", enumeration_complete=True,
        )
        observed.append((max_age, snapshot))
        return snapshot

    runtime = request.getfixturevalue("controlled_runtime")
    monkeypatch.setattr(process_monitor, "process_snapshot", owned_inventory)
    yield SimpleNamespace(runtime=runtime, observed=observed, pid=pid, birth=birth, image=image)


@pytest.mark.parametrize("launch_error", [RuntimeError, OSError], ids=["runtime-refusal", "os-refusal"])
def test_gui_session_engine_start_refusal_never_becomes_a_success(
    engine_start_refusal_runtime, monkeypatch, launch_error,
) -> None:
    """A coordinator acknowledgement is not proof that its engine ran."""
    from angerona.gui import main_window as main_ui
    from angerona.gui.simulation_launch import SimulationLaunch
    from angerona.modules import file_integrity, purple_guard, yara_scanner
    from angerona.shark import simulation_session as sessions
    from angerona.shark.shark_attack import SharkAttackEngine

    ctx = engine_start_refusal_runtime.runtime
    inventory_baseline = len(engine_start_refusal_runtime.observed)
    purple_guard.RedTeamValidationLease.release(ctx.lease)
    ctx.lease = None
    ctx.begin_scan()
    narration = []
    red = RedTeamEngine(ctx.root, documents_dir=ctx.target, on_event=narration.append)
    shark = SharkAttackEngine(ctx.root, documents_dir=ctx.target, downloads_dir=ctx.target)

    # Exercise the real legacy entry point's decision and common-route handoff.
    # The common route is observed here; the actual detached launcher is below.
    routed = []
    view = SimpleNamespace(
        red_team_engine=red, shark_engine=shark, _run_simulation=routed.append,
    )
    answers = iter((main_ui.QMessageBox.No, main_ui.QMessageBox.Yes))
    monkeypatch.setattr(main_ui.QMessageBox, "question", lambda *_args: next(answers))
    MainWindow._start_red_team(view)
    assert routed == [] and red._thread is None and shark._thread is None
    MainWindow._start_red_team(view)
    assert routed == [{
        "run_redteam": True, "run_shark": False, "auto_remediate": True,
        "comprehensive": False,
    }]
    cfg = dict(routed[0], intensity="Low", target_dir=str(ctx.target))
    original_cfg = dict(cfg)

    watches = (
        ("fim", file_integrity, file_integrity.watch_roots),
        ("yara", yara_scanner, yara_scanner.scan_roots),
    )
    before_watches = {
        name: {Path(path).resolve(strict=False) for path in getter()}
        for name, _module, getter in watches
    }
    watch_calls = []
    for name, module, _getter in watches:
        actual_register = module.register_runtime_watch
        actual_unregister = module.unregister_runtime_watch

        def register(path, *args, _call=actual_register, _name=name, **kwargs):
            result = _call(path, *args, **kwargs)
            if result is True:
                watch_calls.append((_name, "register", Path(path).resolve(strict=False)))
            return result

        def unregister(path, *args, _call=actual_unregister, _name=name, **kwargs):
            result = _call(path, *args, **kwargs)
            watch_calls.append((_name, "unregister", Path(path).resolve(strict=False)))
            return result

        monkeypatch.setattr(module, "register_runtime_watch", register)
        monkeypatch.setattr(module, "unregister_runtime_watch", unregister)

    entered, permit_failure = threading.Event(), threading.Event()
    attempted = []
    released = []
    actual_start = threading.Thread.start
    actual_release = purple_guard.RedTeamValidationLease.release
    job = SimulationLaunch(
        cfg=cfg, manager=ctx.manager, bus=ctx.bus, storage=ctx.recorder,
        data_root=ctx.root, red_team_engine=red, shark_engine=shark,
    )

    def reject_only_this_engine_thread(worker):
        if worker is red._thread:
            prepared = job.plan.runs[0]
            lease = red._validation_lease
            assert lease is job.session._active_lease and lease.active is True
            assert red.run_id == prepared.run_id
            assert purple_guard.RedTeamValidationLease.authority_matches(
                lease, recorder=ctx.recorder, bus=ctx.bus, manager=ctx.manager,
            )
            attempted.append((worker, lease))
            entered.set()
            assert permit_failure.wait(10), "Fixture did not release its exact start-refusal gate"
            raise launch_error("Synthetic engine-thread launch refusal")
        return actual_start(worker)

    def release(lease):
        was_active = lease.active
        result = actual_release(lease)
        if was_active and not lease.active:
            released.append(lease)
        return result

    monkeypatch.setattr(threading.Thread, "start", reject_only_this_engine_thread)
    monkeypatch.setattr(purple_guard.RedTeamValidationLease, "release", release)
    try:
        job.start()
        assert job.ready.wait(10) and job.success, job.reason
        assert not job.accepted and attempted == []
        assert type(job.session) is sessions.SimulationSession
        assert job.claim() is True and entered.wait(10), job.session.launch_diagnostics()
        assert job.finished.wait(5) and job.accepted, job.reason
        fresh_inventory = engine_start_refusal_runtime.observed[inventory_baseline:]
        assert any(age == 0.0 for age, _snapshot in fresh_inventory)
        assert all(snapshot.enumerated == 1 and len(snapshot.processes) == 1
                   and snapshot.processes[0]["pid"] == engine_start_refusal_runtime.pid
                   and snapshot.processes[0]["create_time"] == engine_start_refusal_runtime.birth
                   and snapshot.processes[0]["exe"] == engine_start_refusal_runtime.image
                   for _age, snapshot in fresh_inventory)

        # The real prepared adapter, preflight, and lease consume have run, but
        # the exact engine Thread has not been created by the OS.
        prepared = job.plan.runs[0]
        worker, lease = attempted[0]
        assert len(attempted) == 1 and worker.ident is None and not worker.is_alive()
        assert job.session.completed_reports() == ()
        assert job.session.performance_snapshot(prepared.run_id).finalized_misses is None
        permit_failure.set()
        assert job.session.finished.wait(10), job.session.snapshot()
        for owned in job.owned_workers():
            if owned.ident is not None:
                owned.join(timeout=5)
            assert not owned.is_alive()

        assert not red.is_running and red._thread is worker and worker.ident is None
        assert job.session.snapshot()["phase"] == "held"
        assert job.session.completed_reports() == ()
        diagnostic, = job.session.launch_diagnostics()
        assert diagnostic.run_id == prepared.run_id
        assert diagnostic.reason_code == "SessionHeld"
        assert "did not accept" in diagnostic.detail
        assert not diagnostic.authenticated_run and not diagnostic.response_authorized
        assert any(
            "worker launch failed" in message and launch_error.__name__ in message
            and "Synthetic engine-thread launch refusal" in message
            for message in narration
        )
        performance = job.session.performance_snapshot(prepared.run_id)
        assert performance.evaluated_steps == 0
        assert performance.native_verified_steps == performance.simulation_verified_steps == 0
        assert performance.detection_verified_steps == performance.containment_verified_steps == 0
        assert performance.finalized_misses is None and performance.final_report_sha256 is None
        assert released == [lease] and lease.active is False
        assert job.session.retirement_snapshot()["custody_released"] is True
        with pytest.raises(purple_guard.RedTeamValidationError):
            purple_guard.RedTeamValidationLease.consume_for_run(
                lease, run_id=prepared.run_id, target=ctx.target, data_root=ctx.root,
            )
        target = ctx.target.resolve(strict=False)
        expected_watch_calls = [
            (name, action, target)
            for name, _module, _getter in watches if target not in before_watches[name]
            for action in ("register", "unregister")
        ]
        assert sorted(watch_calls) == sorted(expected_watch_calls)
        for name, _module, getter in watches:
            assert {Path(path).resolve(strict=False) for path in getter()} == before_watches[name]
        assert not any((ctx.root / name).exists() for name in (
            "redteam_history.json", "redteam_aar.json", "redteam_aar.txt",
        ))
        assert cfg == original_cfg and ctx.config.adversary_combat_mode == "maximum"
        assert ctx.config.adversary_combat_isolate_host is False
        assert ctx.config.adversary_combat_process_action == "none"
        assert ctx.combat.response_snapshot()["host_authority_verified"] is False
        assert job.claim() is False
    finally:
        permit_failure.set()
        job.cancel()
        for owned in job.owned_workers():
            if owned.ident is not None:
                owned.join(timeout=10)
            assert not owned.is_alive(), "Fixture must retire every exact admitted owner"
