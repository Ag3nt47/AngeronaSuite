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
from angerona.modules import purple_guard
from angerona.modules.file_integrity import FileIntegrityModule
from angerona.modules.purple_guard import RedTeamValidationLease
from angerona.shark.aar_report import (
    AARReportResult,
    generate_aar,
    verified_aar_handoff_text,
)
from angerona.shark.red_team import REDTEAM_STAGE_CATEGORY, RedTeamEngine
from angerona.shark.run_manifest import (
    build_run_history,
    expected_red_team_plan,
    preflight_run,
    write_run_history,
)


_KEY = bytes.fromhex("85" * 32)


def _install_keys(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    key_path = root / "bus.key"
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_text(_KEY.hex(), encoding="ascii")
    monkeypatch.setattr(report_attest, "_key_path", lambda: key_path)
    monkeypatch.setattr(BusAuthority, "_key_path", staticmethod(lambda: key_path))


def _runtime(root: Path, monkeypatch: pytest.MonkeyPatch, *, fim: bool = False):
    _install_keys(monkeypatch, root)
    bus = EventBus(ring_size=4096)
    recorder = FlightRecorder(root / "flight-recorder.db")
    bus.arm(recorder.authority)
    bus.subscribe(recorder.record_bus, delivery_budget_ms=60_000)
    guard = purple_guard.PurpleGuard(root)
    guard.bind(bus)
    modules: dict[str, object] = {guard.name: guard}
    file_monitor = None
    if fim:
        file_monitor = FileIntegrityModule()
        file_monitor.bind(bus)
        file_monitor._angerona_contract = SimpleNamespace(  # type: ignore[attr-defined]
            capability_id="angerona.builtin.file_integrity"
        )
        modules[file_monitor.name] = file_monitor
    manager = SimpleNamespace(modules=modules, bus=bus)
    return bus, recorder, guard, file_monitor, manager


def _step(row: dict[str, object], started: float) -> dict[str, object]:
    return {
        "stage": row["stage"],
        "technique": row["technique"],
        "description": "inert fifth-remediation fixture",
        "ts_start": started,
        "ts_end": started + 0.01,
        "artifact_paths": [],
        "ok": True,
        "cycle": row["cycle"],
        "plan_step_id": row["plan_step_id"],
    }


def _history(
    root: Path,
    receipt: dict,
    *,
    cycles: int = 1,
    jitter: tuple[float, float] = (0.0, 0.0),
    empty: bool = False,
    long_timeline: bool = False,
) -> dict:
    decision = preflight_run(
        kind="red_team",
        cycles=cycles,
        jitter_range=jitter,
        noise_chance=0,
        target_dir=root / "target",
        campaign=True,
    )
    assert decision.accepted
    plan = expected_red_team_plan(decision.as_dict())
    started = time.time()
    rows = [] if empty else [_step(row, started) for row in plan]
    if long_timeline and rows:
        span = 3666.1
        for index, row in enumerate(rows):
            offset = span * index / max(1, len(rows) - 1)
            row["ts_start"] = started + offset
            row["ts_end"] = started + offset + 0.01
    history = build_run_history(
        kind="red_team",
        run_id=str(receipt["bound_run_id"]),
        generated="2026-08-28 00:00:00",
        steps=rows,
        preflight=decision,
        status="incomplete" if empty else "completed",
    )
    history["validation_readiness"] = receipt
    assert write_run_history(root / "redteam_history.json", history)
    return history


def test_t1059_requires_exact_process_monitor_source_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bus, recorder, guard, _fim, manager = _runtime(tmp_path, monkeypatch)
    target = tmp_path / "target"
    lease = purple_guard.acquire_redteam_validation_lease(
        manager, bus, recorder, tmp_path, target, timeout=3
    )
    engine = RedTeamEngine(tmp_path, documents_dir=target)
    try:
        receipt = RedTeamValidationLease.consume_for_run(
            lease, run_id="exact-process-source", target=target, data_root=tmp_path
        )
        assert receipt["process_sensor"]["capability_id"] == (
            "angerona.builtin.process_monitor"
        )
        assert len(receipt["detector_contracts"]) == 13
        assert next(
            row for row in receipt["detector_contracts"]
            if row["technique"] == "T1059"
        )["source_capability_id"] == "angerona.builtin.process_monitor"

        engine.run_id = "exact-process-source"
        engine._validation_lease = lease
        engine._complexity = 1
        engine._threat_level = 1
        engine._proc_mult = 1
        engine._step_random_processes((0, 0))
        execution = engine.steps[-1]
        assert execution.pids and execution.correlation_tokens

        bus.publish(Event(
            "Arbitrary In-Process Publisher",
            "copied live tuple",
            Severity.INFO,
            details={
                "event_type": "process_creation",
                "pid": execution.pids[0],
                "process_create_time": time.time(),
                "cmdline": f"python {execution.correlation_tokens[0]}",
            },
        ))
        deadline = time.monotonic() + 3
        source_rows: list[Event] = []
        purple_rows: list[Event] = []
        while time.monotonic() < deadline:
            rows = recorder.events_in_window(time.time() - 10, time.time() + 1)
            source_rows = [
                row for row in rows
                if row.module == "Process Monitor"
                and (row.details or {}).get("receipt_type")
                == "native_process_observation"
            ]
            purple_rows = [
                row for row in rows
                if row.module == "Purple Remediation Guard"
                and (row.details or {}).get("mitre") == "T1059"
            ]
            if source_rows and purple_rows:
                break
            time.sleep(0.05)
        assert source_rows and purple_rows
        assert all(
            (row.details or {}).get("source_observation_sha256")
            for row in purple_rows
        )
    finally:
        engine._cleanup_probe_processes()
        RedTeamValidationLease.release(lease)
        guard.stop()
        recorder.close()


def test_public_fim_attester_and_mutable_legacy_dispatch_are_not_oracles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bus, recorder, guard, fim, manager = _runtime(tmp_path, monkeypatch, fim=True)
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
            lease, run_id="no-public-oracle", target=target, data_root=tmp_path
        )
        marker = target / "_redteam_lsass_dump_public.txt"
        marker.write_text("inert", encoding="utf-8")
        assert purple_guard.attest_fim_scan_observation(
            fim,
            message="caller supplied",
            severity=Severity.HIGH,
            path=str(marker),
            observed_content_sha256=hashlib.sha256(b"inert").hexdigest(),
            change_kind="created",
        ) == {}
        monkeypatch.setattr(
            purple_guard,
            "_VERIFY_NATIVE_EVENT_BUILTIN",
            lambda *_args, **_kwargs: True,
            raising=False,
        )
        synthetic = Event(
            fim.name,
            "receipt-free row",
            Severity.HIGH,
            details={"path": str(marker)},
        )
        assert not purple_guard.verify_validation_native_event(
            lease,
            synthetic,
            manager,
            {"attack_ids": ["T1003"], "technique": "T1003 marker"},
        )
    finally:
        RedTeamValidationLease.release(lease)
        keep_alive.set()
        fim.stop()
        guard.stop()
        recorder.close()


@pytest.mark.skipif(os.name != "nt", reason="exact handle disposition is Windows-only")
def test_cleanup_never_deletes_a_same_path_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bus, recorder, guard, _fim, manager = _runtime(tmp_path, monkeypatch)
    target = tmp_path / "target"
    lease = purple_guard.acquire_redteam_validation_lease(
        manager, bus, recorder, tmp_path, target, timeout=3
    )
    engine = RedTeamEngine(tmp_path, documents_dir=target)
    backup = target / "held-original.txt"
    try:
        run_id = "object-safe-cleanup"
        RedTeamValidationLease.consume_for_run(
            lease, run_id=run_id, target=target, data_root=tmp_path
        )
        engine.run_id = run_id
        engine._validation_lease = lease
        marker = engine._marker("_redteam_lsass_dump_cleanup.txt", "enrolled")
        original = purple_guard._marker_path_identity
        raced = False

        def replacement(path, *, hold, delete_access=False):
            nonlocal raced
            if delete_access and not raced:
                raced = True
                os.replace(marker, backup)
                marker.write_text("unrelated replacement", encoding="utf-8")
            return original(path, hold=hold, delete_access=delete_access)

        monkeypatch.setattr(purple_guard, "_marker_path_identity", replacement)
        assert not RedTeamValidationLease.remove_registered_artifact(
            lease, marker, run_id=run_id
        )
        assert marker.read_text(encoding="utf-8") == "unrelated replacement"
        assert backup.read_text(encoding="utf-8") == "enrolled"
    finally:
        RedTeamValidationLease.release(lease)
        guard.stop()
        recorder.close()


def test_append_only_head_journal_prevents_rollback_fork_and_handoff_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bus, recorder, guard, _fim, manager = _runtime(tmp_path, monkeypatch)
    target = tmp_path / "target"
    lease = purple_guard.acquire_redteam_validation_lease(
        manager, bus, recorder, tmp_path, target, timeout=3
    )
    try:
        receipt = RedTeamValidationLease.consume_for_run(
            lease, run_id="journal-run", target=target, data_root=tmp_path
        )
        history = _history(tmp_path, receipt)
        first = generate_aar(
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
        assert isinstance(first, AARReportResult)
        saved = {
            suffix: (tmp_path / f"redteam_aar.{suffix}").read_bytes()
            for suffix in ("txt", "json", "head.json")
        }
        second = generate_aar(
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
        assert isinstance(second, AARReportResult) and second.sequence == 2
        for suffix, raw in saved.items():
            (tmp_path / f"redteam_aar.{suffix}").write_bytes(raw)
        third = generate_aar(
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
        assert isinstance(third, AARReportResult) and third.sequence == 3
        head = json.loads(third.head_bytes)
        assert head["previous_head_sha256"] == second.head_sha256
        assert len((tmp_path / "redteam_aar.heads.jsonl").read_text().splitlines()) == 3
        assert verified_aar_handoff_text(third) == third.text
        object.__setattr__(third, "text", "mutated display")
        with pytest.raises(ValueError, match="mutated"):
            verified_aar_handoff_text(third)
    finally:
        RedTeamValidationLease.release(lease)
        guard.stop()
        recorder.close()


def test_max_campaign_query_uses_authenticated_ttl_not_legacy_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bus, recorder, guard, _fim, manager = _runtime(tmp_path, monkeypatch)
    target = tmp_path / "target"
    lease = purple_guard.acquire_redteam_validation_lease(
        manager, bus, recorder, tmp_path, target, timeout=3
    )
    try:
        decision = preflight_run(
            kind="red_team",
            cycles=4,
            jitter_range=(60, 60),
            noise_chance=0,
            target_dir=target,
            campaign=True,
        )
        assert decision.accepted
        admitted = float(decision.budget["admitted_run_ttl_seconds"])
        receipt = RedTeamValidationLease.consume_for_run(
            lease,
            run_id="long-query",
            target=target,
            data_root=tmp_path,
            run_ttl_seconds=admitted,
        )
        history = _history(
            tmp_path,
            receipt,
            cycles=4,
            jitter=(60, 60),
            long_timeline=True,
        )
        observed: list[tuple[float, float]] = []
        original = FlightRecorder.events_in_window

        def capture(self, start, end):
            observed.append((float(start), float(end)))
            return original(self, start, end)

        monkeypatch.setattr(FlightRecorder, "events_in_window", capture)
        result = generate_aar(
            tmp_path,
            window=3600,
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
        assert isinstance(result, AARReportResult)
        assert observed and observed[-1][1] - observed[-1][0] >= admitted + 5
    finally:
        RedTeamValidationLease.release(lease)
        guard.stop()
        recorder.close()


def test_zero_step_redteam_history_writes_signed_planned_denominator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bus, recorder, guard, _fim, manager = _runtime(tmp_path, monkeypatch)
    target = tmp_path / "target"
    lease = purple_guard.acquire_redteam_validation_lease(
        manager, bus, recorder, tmp_path, target, timeout=3
    )
    try:
        receipt = RedTeamValidationLease.consume_for_run(
            lease, run_id="zero-step", target=target, data_root=tmp_path
        )
        _history(tmp_path, receipt, empty=True)
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
        assert isinstance(result, AARReportResult)
        payload = json.loads(result.report_bytes)
        assert report_attest.verify(payload) == "ok"
        assert payload["coverage_score_eligible"] is False
        assert payload["detection_steps"] == 13
        assert payload["evidence_taxonomy"]["denominator"] == 13
        assert payload["evidence_taxonomy"]["simulation_contract_validation"]["rate"] is None
        assert len(payload["verdicts"]) == 14
        assert "zero steps" not in result.text.casefold()
    finally:
        RedTeamValidationLease.release(lease)
        guard.stop()
        recorder.close()
