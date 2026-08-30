from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core import report_attest
from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.core.storage import FlightRecorder
from angerona.gui.pages import AARDialog
from angerona.modules import purple_guard
from angerona.modules.file_integrity import FileIntegrityModule
from angerona.modules.purple_guard import RedTeamValidationLease
from angerona.shark.aar_report import evaluate, generate_aar
from angerona.shark.red_team import REDTEAM_STAGE_CATEGORY, RedTeamEngine
from angerona.shark.run_manifest import (
    build_run_history,
    preflight_run,
    write_run_history,
)


_KEY = bytes.fromhex("5a" * 32)


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


def _one_step_history(
    root: Path,
    target: Path,
    marker: Path,
    receipt: dict,
    *,
    run_id: str,
    started: float,
) -> None:
    contract = preflight_run(
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
        preflight=contract,
        status="completed",
    )
    history["validation_readiness"] = receipt
    assert write_run_history(root / "redteam_history.json", history)


def _signed_report(run_id: str, text: str) -> bytes:
    payload = report_attest.attest({
        "run_id": run_id,
        "report_basename": "redteam_aar",
        "report_kind": "red_team",
        "report_text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
    })
    return json.dumps(payload, sort_keys=True).encode("utf-8")


def test_public_evaluate_default_never_promotes_raw_observation(tmp_path) -> None:
    started = time.time()
    marker = tmp_path / "_redteam_lsass_dump_probe.txt"
    raw = Event(
        "Process Monitor",
        "raw process observation",
        Severity.INFO,
        started + 0.1,
        {"path": str(marker), "event_type": "process_creation"},
    )
    verdict = evaluate(
        {
            "run_id": "strict-default",
            "steps": [{
                "stage": "Credential Access (simulated)",
                "technique": "T1003 marker",
                "description": "inert marker",
                "ts_start": started,
                "ts_end": started + 0.2,
                "artifact_paths": [str(marker)],
            }],
        },
        [raw],
        REDTEAM_STAGE_CATEGORY,
    )[0]
    assert verdict.observation is raw
    assert verdict.native_catch is None
    assert verdict.simulation_validation is None
    assert verdict.catch is None


def test_issuer_identity_rejects_private_target_mutation_and_reregistration(
    tmp_path: Path, monkeypatch
) -> None:
    bus, recorder, guard, _fim, manager = _runtime(tmp_path, monkeypatch)
    target_a = tmp_path / "target-a"
    target_b = tmp_path / "target-b"
    lease = purple_guard.acquire_redteam_validation_lease(
        manager, bus, recorder, tmp_path, target_a, timeout=3
    )
    try:
        lease._target = target_b.resolve(strict=False)
        purple_guard.register_runtime_target(target_b)
        with pytest.raises(
            purple_guard.RedTeamValidationError,
            match="target-mismatched",
        ):
            RedTeamValidationLease.consume_for_run(
                lease,
                run_id="mutated-target",
                target=target_b,
                data_root=tmp_path,
            )
        assert lease.target == target_a.resolve(strict=False)
        assert lease.readiness["target"] == str(target_a.resolve(strict=False))
    finally:
        purple_guard.unregister_runtime_target(target_b)
        RedTeamValidationLease.release(lease)
        guard.stop()
        recorder.close()


def test_stopped_exact_fim_is_not_a_native_receipt_oracle(
    tmp_path: Path, monkeypatch
) -> None:
    bus, recorder, guard, fim, manager = _runtime(
        tmp_path, monkeypatch, include_fim=True
    )
    assert fim is not None and fim.status == "stopped"
    target = tmp_path / "target"
    lease = purple_guard.acquire_redteam_validation_lease(
        manager, bus, recorder, tmp_path, target, timeout=3
    )
    try:
        RedTeamValidationLease.consume_for_run(
            lease,
            run_id="stopped-fim",
            target=target,
            data_root=tmp_path,
        )
        monkeypatch.setattr(
            lease,
            "_native_attestation",
            lambda *_args, **_kwargs: {
                "detector_receipt_mac": "f" * 64,
                "receipt_type": "native_analytic_detection",
            },
        )
        fim.emit(
            "caller-invoked fake file alert",
            Severity.HIGH,
            path=str(target / "_redteam_lsass_dump_fake.txt"),
            evidence_type="native_analytic_detection",
            detector_verdict="positive",
        )
        event = bus.recent(1)[0]
        assert event.module == fim.name
        assert not (event.details or {}).get("detector_receipt_mac")
        assert not RedTeamValidationLease.verify_native_event(
            lease,
            event,
            manager,
            {
                "attack_ids": ["T1003"],
                "technique": "T1003 marker",
            },
        )
    finally:
        RedTeamValidationLease.release(lease)
        guard.stop()
        recorder.close()


def test_generate_aar_ignores_writable_lease_verifier_methods(
    tmp_path: Path, monkeypatch
) -> None:
    bus, recorder, guard, _fim, manager = _runtime(tmp_path, monkeypatch)
    target = tmp_path / "target"
    marker = target / "_redteam_lsass_dump_fake.txt"
    lease = purple_guard.acquire_redteam_validation_lease(
        manager, bus, recorder, tmp_path, target, timeout=3
    )
    try:
        run_id = "instance-lease-verifier"
        receipt = RedTeamValidationLease.consume_for_run(
            lease,
            run_id=run_id,
            target=target,
            data_root=tmp_path,
        )
        started = time.time()
        _one_step_history(
            tmp_path,
            target,
            marker,
            receipt,
            run_id=run_id,
            started=started,
        )
        bus.publish(Event(
            "File Integrity Monitor",
            "event-bus-authenticated but detector-unauthenticated",
            Severity.HIGH,
            started + 0.05,
            {
                "path": str(marker),
                "evidence_type": "native_analytic_detection",
                "detector_verdict": "positive",
            },
        ))
        monkeypatch.setattr(lease, "verify_run_history", lambda _history: True)
        monkeypatch.setattr(
            lease, "verify_native_event", lambda _event, _manager, _step: True
        )
        monkeypatch.setattr(lease, "verify_purple_event", lambda _event, _step: True)

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
        )
        assert "RED TEAM ATTACK" in result
        report = json.loads((tmp_path / "redteam_aar.json").read_text("utf-8"))
        assert report["detection_caught"] == 0
        assert report["evidence_taxonomy"]["native_analytic_detection"]["count"] == 0
    finally:
        RedTeamValidationLease.release(lease)
        guard.stop()
        recorder.close()


def test_redteam_dialog_rejects_older_valid_signed_pair_replay(
    tmp_path: Path, monkeypatch
) -> None:
    _install_keys(monkeypatch, tmp_path)
    current_text = "current authenticated Red Team report"
    current_json = _signed_report("redteam-current", current_text)
    old_text = "older but still valid authenticated report"
    old_json = _signed_report("redteam-old", old_text)
    (tmp_path / "redteam_aar.txt").write_text(current_text, encoding="utf-8")
    (tmp_path / "redteam_aar.json").write_bytes(current_json)

    class Body:
        value = ""

        def setPlainText(self, value):
            self.value = value

    binding: dict[str, str] = {}
    dialog = SimpleNamespace(
        data_dir=tmp_path,
        _redteam=True,
        _report_binding=binding,
        body=Body(),
    )
    AARDialog.refresh(dialog)
    assert dialog.body.value == current_text
    assert binding["run_id"] == "redteam-current"
    pinned_digest = binding["sha256"]

    (tmp_path / "redteam_aar.txt").write_text(old_text, encoding="utf-8")
    (tmp_path / "redteam_aar.json").write_bytes(old_json)
    AARDialog.refresh(dialog)
    assert "older or different" in dialog.body.value or "replaced" in dialog.body.value
    assert binding["run_id"] == "redteam-current"
    assert binding["sha256"] == pinned_digest


def test_wall_clock_rollback_does_not_revive_expired_lease(
    tmp_path: Path, monkeypatch
) -> None:
    bus, recorder, guard, _fim, manager = _runtime(tmp_path, monkeypatch)
    target = tmp_path / "target"
    lease = purple_guard.acquire_redteam_validation_lease(
        manager, bus, recorder, tmp_path, target, timeout=3
    )
    try:
        state = purple_guard._lease_authority(lease)
        state.acquire_deadline_monotonic = time.monotonic() - 0.001
        original_wall = time.time
        monkeypatch.setattr(
            purple_guard.time,
            "time",
            lambda: original_wall() - 365 * 86400,
        )
        with pytest.raises(purple_guard.RedTeamValidationError, match="stale"):
            RedTeamValidationLease.consume_for_run(
                lease,
                run_id="wall-clock-rollback",
                target=target,
                data_root=tmp_path,
            )
    finally:
        RedTeamValidationLease.release(lease)
        guard.stop()
        recorder.close()


def test_marker_hardlinks_are_rejected_before_and_after_consumption(
    tmp_path: Path, monkeypatch
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("benign external content", encoding="utf-8")
    before_alias = target / "_redteam_lsass_dump_before.txt"
    os.link(outside, before_alias)
    bus, recorder, guard, _fim, manager = _runtime(tmp_path, monkeypatch)
    try:
        with pytest.raises(
            purple_guard.RedTeamValidationError,
            match="unsafe marker alias",
        ):
            purple_guard.acquire_redteam_validation_lease(
                manager, bus, recorder, tmp_path, target, timeout=3
            )
        before_alias.unlink()

        lease = purple_guard.acquire_redteam_validation_lease(
            manager, bus, recorder, tmp_path, target, timeout=3
        )
        try:
            RedTeamValidationLease.consume_for_run(
                lease,
                run_id="post-consume-alias",
                target=target,
                data_root=tmp_path,
            )
            after_alias = target / "_redteam_lsass_dump_after.txt"
            os.link(outside, after_alias)
            engine = RedTeamEngine(tmp_path, documents_dir=target)
            engine.run_id = "post-consume-alias"
            engine._validation_lease = lease
            with pytest.raises(FileExistsError):
                engine._marker(after_alias.name, "replacement content")
            assert after_alias not in engine._owned_artifacts
            assert guard.scan_once(guard._policy_snapshot()) == 0
            assert not any(
                (event.details or {}).get("detector_receipt_mac")
                for event in bus.recent(50)
                if (event.details or {}).get("path") == str(after_alias)
            )
            assert outside.read_text(encoding="utf-8") == "benign external content"
        finally:
            RedTeamValidationLease.release(lease)
    finally:
        guard.stop()
        recorder.close()
