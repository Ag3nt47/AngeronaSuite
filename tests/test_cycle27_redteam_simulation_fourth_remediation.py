from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core import report_attest
from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.core.storage import FlightRecorder
from angerona.gui.pages import _load_verified_aar_text
from angerona.modules import purple_guard
from angerona.modules.file_integrity import FileIntegrityModule
from angerona.modules.purple_guard import RedTeamValidationLease
from angerona.shark.aar_report import AARReportResult, generate_aar
from angerona.shark.red_team import REDTEAM_STAGE_CATEGORY, RedTeamEngine
from angerona.shark.run_manifest import (
    build_run_history,
    expected_red_team_plan,
    preflight_run,
    write_run_history,
)


_KEY = bytes.fromhex("73" * 32)


def _install_keys(monkeypatch, root: Path) -> None:
    key_path = root / "bus.key"
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_text(_KEY.hex(), encoding="ascii")
    monkeypatch.setattr(report_attest, "_key_path", lambda: key_path)
    monkeypatch.setattr(BusAuthority, "_key_path", staticmethod(lambda: key_path))


def _runtime(root: Path, monkeypatch, *, include_fim: bool = False):
    _install_keys(monkeypatch, root)
    bus = EventBus(ring_size=4096)
    recorder = FlightRecorder(root / "flight-recorder.db")
    bus.arm(recorder.authority)
    bus.subscribe(recorder.record_bus, delivery_budget_ms=60_000)
    guard = purple_guard.PurpleGuard(root)
    guard.bind(bus)
    modules: dict[str, object] = {guard.name: guard}
    fim = None
    if include_fim:
        fim = FileIntegrityModule()
        fim.bind(bus)
        fim._angerona_contract = SimpleNamespace(  # type: ignore[attr-defined]
            capability_id="angerona.builtin.file_integrity"
        )
        modules[fim.name] = fim
    manager = SimpleNamespace(modules=modules, bus=bus)
    return bus, recorder, guard, fim, manager


def _step_from_plan(row: dict[str, object], started: float) -> dict[str, object]:
    return {
        "stage": row["stage"],
        "technique": row["technique"],
        "description": "inert mandatory fixture",
        "ts_start": started,
        "ts_end": started + 0.01,
        "artifact_paths": [],
        "ok": True,
        "cycle": row["cycle"],
        "plan_step_id": row["plan_step_id"],
    }


def test_missing_mandatory_inventory_withholds_score_and_retains_13_denominator(
    tmp_path: Path, monkeypatch
) -> None:
    bus, recorder, guard, _fim, manager = _runtime(tmp_path, monkeypatch)
    target = tmp_path / "target"
    lease = purple_guard.acquire_redteam_validation_lease(
        manager, bus, recorder, tmp_path, target, timeout=3
    )
    try:
        run_id = "fourth-incomplete-plan"
        readiness = RedTeamValidationLease.consume_for_run(
            lease, run_id=run_id, target=target, data_root=tmp_path
        )
        contract = preflight_run(
            kind="red_team",
            cycles=1,
            jitter_range=(0, 0),
            noise_chance=0,
            target_dir=target,
        )
        plan = expected_red_team_plan(contract.as_dict())
        history = build_run_history(
            kind="red_team",
            run_id=run_id,
            generated="2026-08-28 00:00:00",
            steps=[_step_from_plan(plan[0], time.time())],
            preflight=contract,
            status="completed",
        )
        assert history["status"] == "incomplete"
        assert history["campaign"]["expected_steps"] == 14
        assert len(history["campaign"]["missing_plan_step_ids"]) == 13
        history["validation_readiness"] = readiness
        assert write_run_history(tmp_path / "redteam_history.json", history)

        text = generate_aar(
            tmp_path,
            history_name="redteam_history.json",
            stage_category=REDTEAM_STAGE_CATEGORY,
            title="RED TEAM ATTACK",
            report_basename="redteam_aar",
            recorder=recorder,
            bus=bus,
            manager=manager,
            validation_lease=lease,
        )
        assert isinstance(text, str)
        assert "COVERAGE SCORE WITHHELD" in text
        report = json.loads((tmp_path / "redteam_aar.json").read_text("utf-8"))
        assert report["coverage_score_eligible"] is False
        assert report["evidence_taxonomy"]["denominator"] == 13
        assert report["evidence_taxonomy"]["simulation_contract_validation"]["rate"] is None
    finally:
        RedTeamValidationLease.release(lease)
        guard.stop()
        recorder.close()


def test_target_same_path_new_inode_is_rejected(tmp_path: Path, monkeypatch) -> None:
    bus, recorder, guard, _fim, manager = _runtime(tmp_path, monkeypatch)
    target = tmp_path / "target"
    lease = purple_guard.acquire_redteam_validation_lease(
        manager, bus, recorder, tmp_path, target, timeout=3
    )
    original = tmp_path / "original-target"
    try:
        os.replace(target, original)
        target.mkdir()
        with pytest.raises(purple_guard.RedTeamValidationError, match="stale"):
            RedTeamValidationLease.consume_for_run(
                lease,
                run_id="replacement-target",
                target=target,
                data_root=tmp_path,
            )
    finally:
        RedTeamValidationLease.release(lease)
        guard.stop()
        recorder.close()


def test_arbitrary_info_publisher_without_live_enrollment_gets_no_receipt(
    tmp_path: Path, monkeypatch
) -> None:
    bus, recorder, guard, _fim, manager = _runtime(tmp_path, monkeypatch)
    target = tmp_path / "target"
    lease = purple_guard.acquire_redteam_validation_lease(
        manager, bus, recorder, tmp_path, target, timeout=3
    )
    try:
        RedTeamValidationLease.consume_for_run(
            lease, run_id="no-process-oracle", target=target, data_root=tmp_path
        )
        bus.publish(Event(
            "Process Monitor",
            "fabricated process row",
            Severity.INFO,
            details={
                "event_type": "process_creation",
                "pid": 2_000_000_000,
                "process_create_time": time.time(),
                "cmdline": "python inert ANGERONA_REDTEAM_deadbeef",
            },
        ))
        time.sleep(0.05)
        assert guard.scan_process_once(guard._policy_snapshot()) == 0
        assert not any(
            (event.details or {}).get("detector_receipt_mac")
            for event in recorder.events_in_window(time.time() - 5, time.time() + 1)
            if (event.details or {}).get("mitre") == "T1059"
        )
    finally:
        RedTeamValidationLease.release(lease)
        guard.stop()
        recorder.close()


def test_running_fim_public_emit_is_not_a_native_signing_oracle(
    tmp_path: Path, monkeypatch
) -> None:
    bus, recorder, guard, fim, manager = _runtime(
        tmp_path, monkeypatch, include_fim=True
    )
    assert fim is not None
    keep_alive = threading.Event()
    monkeypatch.setattr(fim, "run", lambda: keep_alive.wait(5))
    fim.start()
    target = tmp_path / "target"
    lease = purple_guard.acquire_redteam_validation_lease(
        manager, bus, recorder, tmp_path, target, timeout=3
    )
    try:
        RedTeamValidationLease.consume_for_run(
            lease, run_id="fim-public-emit", target=target, data_root=tmp_path
        )
        fim.emit(
            "caller-originated synthetic FIM alert",
            Severity.HIGH,
            path=str(target / "_redteam_lsass_dump_fake.txt"),
            evidence_type="native_analytic_detection",
            detector_verdict="positive",
        )
        event = bus.recent(1)[0]
        assert not (event.details or {}).get("detector_receipt_mac")
        assert not purple_guard.verify_validation_native_event(
            lease,
            event,
            manager,
            {"attack_ids": ["T1003"], "technique": "T1003 marker"},
        )
    finally:
        RedTeamValidationLease.release(lease)
        keep_alive.set()
        fim.stop()
        guard.stop()
        recorder.close()


def test_fim_scan_site_can_sign_the_exact_custody_bound_marker(
    tmp_path: Path, monkeypatch
) -> None:
    bus, recorder, guard, fim, manager = _runtime(
        tmp_path, monkeypatch, include_fim=True
    )
    assert fim is not None
    keep_alive = threading.Event()
    monkeypatch.setattr(fim, "run", lambda: keep_alive.wait(5))
    fim.start()
    target = tmp_path / "target"
    lease = purple_guard.acquire_redteam_validation_lease(
        manager, bus, recorder, tmp_path, target, timeout=3
    )
    engine = RedTeamEngine(tmp_path, documents_dir=target)
    try:
        run_id = "fim-scan-site"
        RedTeamValidationLease.consume_for_run(
            lease, run_id=run_id, target=target, data_root=tmp_path
        )
        engine.run_id = run_id
        engine._validation_lease = lease
        marker = engine._marker(
            "_redteam_lsass_dump_scan.txt", "inert scan-site marker"
        )
        monkeypatch.setattr(
            "angerona.modules.file_integrity.watch_roots",
            lambda: [str(target)],
        )
        snapshot = fim._scan()
        assert snapshot, (fim._last_scan_receipt, list(target.iterdir()))
        marker_key = next(
            path
            for path in snapshot
            if os.path.normcase(os.path.abspath(path))
            == os.path.normcase(os.path.abspath(marker))
        )
        assert snapshot[marker_key]
        assert fim._last_scan_receipt["complete"] is True
        fim._evaluate_snapshot(snapshot)
        event = next(
            event for event in reversed(bus.recent(20))
            if event.module == fim.name
            and (event.details or {}).get("detector_receipt_mac")
        )
        assert purple_guard.verify_validation_native_event(
            lease,
            event,
            manager,
            {"attack_ids": ["T1003"], "technique": "T1003 marker"},
        )
        assert engine._sweep_markers(
            target_dir=target, artifact_paths=(marker,)
        ) == 1
        assert not marker.exists()
    finally:
        RedTeamValidationLease.release(lease)
        keep_alive.set()
        fim.stop()
        guard.stop()
        recorder.close()


def test_class_level_verifier_replacement_cannot_redirect_captured_dispatch(
    tmp_path: Path, monkeypatch
) -> None:
    bus, recorder, guard, _fim, manager = _runtime(tmp_path, monkeypatch)
    target = tmp_path / "target"
    lease = purple_guard.acquire_redteam_validation_lease(
        manager, bus, recorder, tmp_path, target, timeout=3
    )
    try:
        RedTeamValidationLease.consume_for_run(
            lease, run_id="class-dispatch", target=target, data_root=tmp_path
        )
        event = Event(
            "File Integrity Monitor",
            "receipt-free row",
            Severity.HIGH,
            details={"path": str(target / "_redteam_lsass_dump_fake.txt")},
        )
        monkeypatch.setattr(
            RedTeamValidationLease,
            "verify_native_event",
            lambda *_args, **_kwargs: True,
        )
        assert not purple_guard.verify_validation_native_event(
            lease,
            event,
            manager,
            {"attack_ids": ["T1003"], "technique": "T1003 marker"},
        )
    finally:
        RedTeamValidationLease.release(lease)
        guard.stop()
        recorder.close()


def test_immutable_report_handoff_rejects_old_pair_before_dialog_binding(
    tmp_path: Path, monkeypatch
) -> None:
    bus, recorder, guard, _fim, manager = _runtime(tmp_path, monkeypatch)
    target = tmp_path / "target"
    lease = purple_guard.acquire_redteam_validation_lease(
        manager, bus, recorder, tmp_path, target, timeout=3
    )
    try:
        run_id = "immutable-report-new"
        readiness = RedTeamValidationLease.consume_for_run(
            lease, run_id=run_id, target=target, data_root=tmp_path
        )
        contract = preflight_run(
            kind="red_team", cycles=1, jitter_range=(0, 0),
            noise_chance=0, target_dir=target,
        )
        plan = expected_red_team_plan(contract.as_dict())
        history = build_run_history(
            kind="red_team", run_id=run_id, generated="2026-08-28 00:00:00",
            steps=[_step_from_plan(plan[0], time.time())],
            preflight=contract, status="completed",
        )
        history["validation_readiness"] = readiness
        assert write_run_history(tmp_path / "redteam_history.json", history)
        result = generate_aar(
            tmp_path,
            history_name="redteam_history.json",
            stage_category=REDTEAM_STAGE_CATEGORY,
            title="RED TEAM ATTACK",
            report_basename="redteam_aar",
            recorder=recorder,
            bus=bus,
            manager=manager,
            validation_lease=lease,
            return_result=True,
        )
        assert type(result) is AARReportResult

        old_text = "older authenticated report"
        old_payload = report_attest.attest({
            "run_id": "immutable-report-old",
            "report_basename": "redteam_aar",
            "report_kind": "red_team",
            "report_text_sha256": hashlib.sha256(
                old_text.encode("utf-8")
            ).hexdigest(),
        })
        (tmp_path / "redteam_aar.txt").write_text(old_text, encoding="utf-8")
        (tmp_path / "redteam_aar.json").write_text(
            json.dumps(old_payload), encoding="utf-8"
        )
        with pytest.raises(ValueError, match="older or different|authenticated head"):
            _load_verified_aar_text(
                tmp_path,
                basename="redteam_aar",
                expected_kind="red_team",
                expected_run_id=result.run_id,
                expected_report_sha256=result.report_sha256,
                expected_head_sha256=result.head_sha256,
                expected_sequence=result.sequence,
            )
    finally:
        RedTeamValidationLease.release(lease)
        guard.stop()
        recorder.close()


def test_maximum_preflight_receives_a_bounded_sufficient_monotonic_deadline(
    tmp_path: Path, monkeypatch
) -> None:
    bus, recorder, guard, _fim, manager = _runtime(tmp_path, monkeypatch)
    target = tmp_path / "target"
    contract = preflight_run(
        kind="red_team",
        cycles=4,
        jitter_range=(60, 60),
        noise_chance=1,
        target_dir=target,
    )
    assert contract.accepted
    admitted = float(contract.budget["admitted_run_ttl_seconds"])
    assert 600 < admitted <= float(contract.budget["max_admitted_run_ttl_seconds"])
    lease = purple_guard.acquire_redteam_validation_lease(
        manager, bus, recorder, tmp_path, target, timeout=3
    )
    try:
        receipt = RedTeamValidationLease.consume_for_run(
            lease,
            run_id="maximum-runtime",
            target=target,
            data_root=tmp_path,
            run_ttl_seconds=admitted,
        )
        state = purple_guard._lease_authority(lease)
        remaining = state.run_deadline_monotonic - time.monotonic()
        assert receipt["run_ttl_seconds"] == admitted
        assert admitted - 2 < remaining <= admitted
    finally:
        RedTeamValidationLease.release(lease)
        guard.stop()
        recorder.close()
