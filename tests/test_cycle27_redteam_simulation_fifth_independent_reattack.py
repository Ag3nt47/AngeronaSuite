from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
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
from angerona.modules.process_monitor import ProcessMonitorModule
from angerona.modules.purple_guard import (
    RedTeamValidationError,
    RedTeamValidationLease,
)
from angerona.shark import aar_report
from angerona.shark.aar_report import AARReportResult, generate_aar
from angerona.shark.red_team import REDTEAM_STAGE_CATEGORY
from angerona.shark.run_manifest import (
    build_run_history,
    expected_red_team_plan,
    preflight_run,
    write_run_history,
)


_KEY = bytes.fromhex("93" * 32)


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


def _decision(root: Path, *, cycles: int = 1):
    result = preflight_run(
        kind="red_team",
        cycles=cycles,
        jitter_range=(0.0, 0.0),
        noise_chance=0,
        target_dir=root / "target",
        campaign=True,
    )
    assert result.accepted
    return result


def _history(root: Path, receipt: dict, decision, *, empty: bool = False) -> dict:
    started = time.time()
    plan = expected_red_team_plan(decision.as_dict())
    steps = [] if empty else [
        {
            "stage": row["stage"],
            "technique": row["technique"],
            "description": "inert independent fifth reattack",
            "ts_start": started + index * 0.01,
            "ts_end": started + index * 0.01 + 0.001,
            "artifact_paths": [],
            "ok": True,
            "cycle": row["cycle"],
            "plan_step_id": row["plan_step_id"],
        }
        for index, row in enumerate(plan)
    ]
    history = build_run_history(
        kind="red_team",
        run_id=str(receipt["bound_run_id"]),
        generated="2026-08-28 00:00:00",
        steps=steps,
        preflight=decision,
        status="incomplete" if empty else "completed",
    )
    history["validation_readiness"] = receipt
    return history


def test_direct_canonical_fim_evaluator_cannot_mint_proof_without_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bus, recorder, guard, fim, manager = _runtime(tmp_path, monkeypatch, fim=True)
    assert fim is not None
    keep_alive = threading.Event()
    monkeypatch.setattr(fim, "run", lambda: keep_alive.wait(10.0))
    fim.start()
    target = tmp_path / "target"
    lease = purple_guard.acquire_redteam_validation_lease(
        manager, bus, recorder, tmp_path, target, timeout=3
    )
    marker = target / "_redteam_lsass_dump_direct_eval.txt"
    try:
        run_id = "direct-fim-evaluator"
        RedTeamValidationLease.consume_for_run(
            lease, run_id=run_id, target=target, data_root=tmp_path
        )
        marker.write_text("inert direct evaluator marker", encoding="utf-8")
        RedTeamValidationLease.register_artifact_handle(
            lease, marker, run_id=run_id
        )
        digest = hashlib.sha256(marker.read_bytes()).hexdigest()
        assert fim._last_scan_receipt == {"complete": False, "reason": "not scanned"}

        # No _scan() result or scan/change-token receipt exists. An unrelated
        # in-process caller supplies the evaluator's `current` mapping directly.
        fim._evaluate_snapshot({str(marker.resolve()): digest})

        assert fim._last_scan_receipt == {"complete": False, "reason": "not scanned"}
        event = next(
            row
            for row in reversed(bus.recent(100))
            if row.module == fim.name
            and str((row.details or {}).get("path") or "")
            == str(marker.resolve())
        )
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
        marker.unlink(missing_ok=True)


def test_t1059_readiness_and_os_receipt_reject_receipt_free_exact_tuple(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bus, recorder, guard, _fim, manager = _runtime(tmp_path, monkeypatch)
    target = tmp_path / "target"
    assert "Process Monitor" not in manager.modules
    lease = purple_guard.acquire_redteam_validation_lease(
        manager, bus, recorder, tmp_path, target, timeout=3
    )
    child: subprocess.Popen | None = None
    try:
        receipt = RedTeamValidationLease.consume_for_run(
            lease, run_id="independent-t1059", target=target, data_root=tmp_path
        )
        process_sensor = receipt["process_sensor"]
        process_module = manager.modules["Process Monitor"]
        assert type(process_module).__name__ == "ProcessMonitorModule"
        assert process_sensor["capability_id"] == "angerona.builtin.process_monitor"
        assert process_sensor["provisioned_for_validation"] is True
        assert next(
            row
            for row in receipt["detector_contracts"]
            if row["technique"] == "T1059"
        )["source_capability_id"] == "angerona.builtin.process_monitor"

        token = "ANGERONA_REDTEAM_93a7c10e"
        RedTeamValidationLease.enroll_process_challenge(
            lease, token=token, run_id="independent-t1059"
        )
        child = subprocess.Popen(  # noqa: S603 - fixed interpreter, inert sleep
            [sys.executable, "-c", "import time; time.sleep(10)", token],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        bound = RedTeamValidationLease.bind_process_challenge(
            lease,
            token=token,
            pid=int(child.pid),
            run_id="independent-t1059",
        )
        assert bound["state"] == "bound"
        authority = purple_guard._lease_authority(lease)
        assert (authority.process_challenges or {})[token] == bound
        source = next(
            row
            for row in reversed(bus.recent(100))
            if row.module == "Process Monitor"
            and (row.details or {}).get("receipt_type")
            == "native_process_observation"
            and token in str((row.details or {}).get("cmdline") or "")
        )
        assert RedTeamValidationLease.verify_process_observation(
            lease, source, require_live=True
        )

        spoof = Event(
            "Process Monitor",
            "receipt-free copy of exact live tuple",
            Severity.INFO,
            details={
                "event_type": "process_creation",
                "pid": int(child.pid),
                "process_create_time": bound["process_create_time"],
                "cmdline": f"{sys.executable} {token}",
            },
        )
        assert not RedTeamValidationLease.verify_process_observation(
            lease, spoof, require_live=True
        )
    finally:
        if child is not None:
            child.terminate()
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=3)
        RedTeamValidationLease.release(lease)
        assert "Process Monitor" not in manager.modules
        guard.stop()
        recorder.close()


@pytest.mark.parametrize("observer_outcome", ["false", "exception"])
def test_t1059_binding_fails_closed_when_exact_observation_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    observer_outcome: str,
) -> None:
    bus, recorder, guard, _fim, manager = _runtime(tmp_path, monkeypatch)
    target = tmp_path / "target"
    lease = purple_guard.acquire_redteam_validation_lease(
        manager, bus, recorder, tmp_path, target, timeout=3
    )
    child: subprocess.Popen | None = None
    original_observer = ProcessMonitorModule.observe_validation_process
    injected = RuntimeError("injected exact observation failure")
    try:
        run_id = f"independent-t1059-{observer_outcome}"
        RedTeamValidationLease.consume_for_run(
            lease, run_id=run_id, target=target, data_root=tmp_path
        )
        process_module = manager.modules["Process Monitor"]
        token = (
            "ANGERONA_REDTEAM_8c3f120a"
            if observer_outcome == "false"
            else "ANGERONA_REDTEAM_b70e4d91"
        )
        RedTeamValidationLease.enroll_process_challenge(
            lease, token=token, run_id=run_id
        )
        child = subprocess.Popen(  # noqa: S603 - fixed interpreter, inert sleep
            [sys.executable, "-c", "import time; time.sleep(10)", token],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )

        if observer_outcome == "false":
            monkeypatch.setattr(
                ProcessMonitorModule,
                "observe_validation_process",
                lambda self, pid, **_kwargs: False,
            )
        else:
            def _raise_observer(
                self: object, pid: int, **_kwargs: object
            ) -> bool:
                del self, pid, _kwargs
                raise injected

            monkeypatch.setattr(
                ProcessMonitorModule,
                "observe_validation_process",
                _raise_observer,
            )

        with pytest.raises(RedTeamValidationError) as raised:
            RedTeamValidationLease.bind_process_challenge(
                lease,
                token=token,
                pid=int(child.pid),
                run_id=run_id,
            )
        if observer_outcome == "exception":
            assert raised.value.__cause__ is injected
        else:
            assert raised.value.__cause__ is None

        authority = purple_guard._lease_authority(lease)
        failed = (authority.process_challenges or {})[token]
        assert failed["state"] == "observation_failed"
        assert failed["pid"] == int(child.pid)
        assert failed["run_id"] == run_id
        assert failed["identity_sha256"]
        assert failed["observation_failure"] == (
            "observer_rejected"
            if observer_outcome == "false"
            else "observer_exception"
        )

        # Restoring the canonical producer cannot turn a terminal failed
        # challenge into delayed polling credit while the child is still live.
        monkeypatch.setattr(
            ProcessMonitorModule,
            "observe_validation_process",
            original_observer,
        )
        assert not original_observer(process_module, int(child.pid))
        assert not any(
            row.module == "Process Monitor"
            and (row.details or {}).get("receipt_type")
            == "native_process_observation"
            and token in str((row.details or {}).get("cmdline") or "")
            for row in bus.recent(200)
        )
    finally:
        if child is not None:
            child.terminate()
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=3)
        RedTeamValidationLease.release(lease)
        assert "Process Monitor" not in manager.modules
        guard.stop()
        recorder.close()


def test_t1059_pending_observation_rejects_a_polling_thread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bus, recorder, guard, _fim, manager = _runtime(tmp_path, monkeypatch)
    target = tmp_path / "target"
    lease = purple_guard.acquire_redteam_validation_lease(
        manager, bus, recorder, tmp_path, target, timeout=3
    )
    child: subprocess.Popen | None = None
    bind_thread: threading.Thread | None = None
    prepare_entered = threading.Event()
    allow_prepare = threading.Event()
    errors: list[BaseException] = []
    original_observer = ProcessMonitorModule.observe_validation_process
    token = "ANGERONA_REDTEAM_c62a9e14"
    try:
        run_id = "independent-t1059-pending-poll"
        RedTeamValidationLease.consume_for_run(
            lease, run_id=run_id, target=target, data_root=tmp_path
        )
        process_module = manager.modules["Process Monitor"]
        RedTeamValidationLease.enroll_process_challenge(
            lease, token=token, run_id=run_id
        )
        child = subprocess.Popen(  # noqa: S603 - fixed interpreter, inert sleep
            [sys.executable, "-c", "import time; time.sleep(10)", token],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )

        def _blocked_prepare(
            self: object,
            pid: int,
            *,
            _prepare_only: bool = False,
        ) -> bool | dict[str, object]:
            if _prepare_only:
                prepare_entered.set()
                assert allow_prepare.wait(5.0)
                return False
            return original_observer(self, pid)  # type: ignore[arg-type]

        monkeypatch.setattr(
            ProcessMonitorModule,
            "observe_validation_process",
            _blocked_prepare,
        )

        def _bind() -> None:
            try:
                RedTeamValidationLease.bind_process_challenge(
                    lease, token=token, pid=int(child.pid), run_id=run_id
                )
            except BaseException as exc:  # captured for the test thread
                errors.append(exc)

        bind_thread = threading.Thread(target=_bind, daemon=True)
        bind_thread.start()
        assert prepare_entered.wait(3.0)

        # A Process Monitor inventory caller on another thread sees the exact
        # live tuple, but cannot mint while the binder owns observation_pending.
        assert not original_observer(process_module, int(child.pid))
        assert not any(
            row.module == "Process Monitor"
            and (row.details or {}).get("receipt_type")
            == "native_process_observation"
            and token in str((row.details or {}).get("cmdline") or "")
            for row in bus.recent(200)
        )
        allow_prepare.set()
        bind_thread.join(3.0)
        assert not bind_thread.is_alive()
        assert len(errors) == 1
        assert isinstance(errors[0], RedTeamValidationError)
        failed = (
            purple_guard._lease_authority(lease).process_challenges or {}
        )[token]
        assert failed["state"] == "observation_failed"
        assert failed["observation_failure"] == "observer_rejected"
    finally:
        allow_prepare.set()
        if bind_thread is not None:
            bind_thread.join(3.0)
        if child is not None:
            child.terminate()
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=3)
        RedTeamValidationLease.release(lease)
        guard.stop()
        recorder.close()


def test_t1059_publication_does_not_hold_lease_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bus, recorder, guard, _fim, manager = _runtime(tmp_path, monkeypatch)
    target = tmp_path / "target"
    lease = purple_guard.acquire_redteam_validation_lease(
        manager, bus, recorder, tmp_path, target, timeout=3
    )
    child: subprocess.Popen | None = None
    bind_thread: threading.Thread | None = None
    publication_entered = threading.Event()
    allow_publication = threading.Event()
    errors: list[BaseException] = []
    token = "ANGERONA_REDTEAM_1f84d3b7"

    def _blocking_subscriber(event: Event) -> None:
        if (
            event.module == "Process Monitor"
            and (event.details or {}).get("receipt_type")
            == "native_process_observation"
            and token in str((event.details or {}).get("cmdline") or "")
        ):
            publication_entered.set()
            allow_publication.wait(5.0)

    bus.subscribe(_blocking_subscriber, delivery_budget_ms=10_000)
    try:
        run_id = "independent-t1059-release-during-publish"
        RedTeamValidationLease.consume_for_run(
            lease, run_id=run_id, target=target, data_root=tmp_path
        )
        RedTeamValidationLease.enroll_process_challenge(
            lease, token=token, run_id=run_id
        )
        child = subprocess.Popen(  # noqa: S603 - fixed interpreter, inert sleep
            [sys.executable, "-c", "import time; time.sleep(10)", token],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )

        def _bind() -> None:
            try:
                RedTeamValidationLease.bind_process_challenge(
                    lease, token=token, pid=int(child.pid), run_id=run_id
                )
            except BaseException as exc:  # captured for the test thread
                errors.append(exc)

        bind_thread = threading.Thread(target=_bind, daemon=True)
        bind_thread.start()
        assert publication_entered.wait(3.0)
        started = time.monotonic()
        RedTeamValidationLease.release(lease)
        elapsed = time.monotonic() - started
        assert elapsed < 2.0
        assert bind_thread.is_alive()

        allow_publication.set()
        bind_thread.join(3.0)
        assert not bind_thread.is_alive()
        assert len(errors) == 1
        assert isinstance(errors[0], RedTeamValidationError)
        assert "authority ended" in str(errors[0])
    finally:
        allow_publication.set()
        if bind_thread is not None:
            bind_thread.join(3.0)
        if child is not None:
            child.terminate()
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=3)
        RedTeamValidationLease.release(lease)
        guard.stop()
        recorder.close()


def test_t1059_concurrent_sensor_rebind_cannot_silently_drop_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bus, recorder, guard, _fim, manager = _runtime(tmp_path, monkeypatch)
    target = tmp_path / "target"
    lease = purple_guard.acquire_redteam_validation_lease(
        manager, bus, recorder, tmp_path, target, timeout=3
    )
    child: subprocess.Popen | None = None
    process_module = manager.modules["Process Monitor"]
    replacement_bus = EventBus()
    original_publish = EventBus.publish
    token = "ANGERONA_REDTEAM_96c0e2a5"
    try:
        run_id = "independent-t1059-concurrent-rebind"
        RedTeamValidationLease.consume_for_run(
            lease, run_id=run_id, target=target, data_root=tmp_path
        )
        RedTeamValidationLease.enroll_process_challenge(
            lease, token=token, run_id=run_id
        )
        child = subprocess.Popen(  # noqa: S603 - fixed interpreter, inert sleep
            [sys.executable, "-c", "import time; time.sleep(10)", token],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )

        def _rebind_during_publish(self: EventBus, event: Event) -> None:
            if (
                event.module == "Process Monitor"
                and token in str((event.details or {}).get("cmdline") or "")
            ):
                process_module._bus = replacement_bus
            original_publish(self, event)

        monkeypatch.setattr(
            EventBus,
            "publish",
            _rebind_during_publish,
        )
        with pytest.raises(
            RedTeamValidationError,
            match="authority ended during publication",
        ):
            RedTeamValidationLease.bind_process_challenge(
                lease, token=token, pid=int(child.pid), run_id=run_id
            )

        source = next(
            row
            for row in reversed(bus.recent(200))
            if row.module == "Process Monitor"
            and (row.details or {}).get("receipt_type")
            == "native_process_observation"
            and token in str((row.details or {}).get("cmdline") or "")
        )
        assert source
        assert replacement_bus.recent(20) == []
        failed = (
            purple_guard._lease_authority(lease).process_challenges or {}
        )[token]
        assert failed["state"] == "observation_failed"
        assert (
            failed["observation_failure"]
            == "authority_changed_after_publication"
        )
        assert not RedTeamValidationLease.verify_process_observation(
            lease, source, require_live=True
        )
    finally:
        process_module._bus = bus
        if child is not None:
            child.terminate()
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=3)
        RedTeamValidationLease.release(lease)
        guard.stop()
        recorder.close()


def test_lease_authority_registry_has_no_mutable_verifier_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bus, recorder, guard, _fim, manager = _runtime(tmp_path, monkeypatch)
    target = tmp_path / "target"
    lease = purple_guard.acquire_redteam_validation_lease(
        manager, bus, recorder, tmp_path, target, timeout=3
    )
    try:
        RedTeamValidationLease.consume_for_run(
            lease, run_id="mutable-dispatch", target=target, data_root=tmp_path
        )
        synthetic = Event(
            "File Integrity Monitor",
            "receipt-free synthetic row",
            Severity.HIGH,
            details={"path": str(target / "_redteam_lsass_dump_fake.txt")},
        )
        step = {"attack_ids": ["T1003"], "technique": "T1003 marker"}
        assert not purple_guard.verify_validation_native_event(
            lease, synthetic, manager, step
        )

        authority = purple_guard._lease_authority(lease)
        assert not hasattr(authority, "verify_native_impl")
        with pytest.raises(AttributeError):
            authority.verify_native_impl = lambda *_args, **_kwargs: True
        assert not purple_guard.verify_validation_native_event(
            lease, synthetic, manager, step
        )
    finally:
        RedTeamValidationLease.release(lease)
        guard.stop()
        recorder.close()


def test_rolling_back_only_the_journal_is_detected_by_fixed_head_witness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bus, recorder, guard, _fim, manager = _runtime(tmp_path, monkeypatch)
    target = tmp_path / "target"
    lease = purple_guard.acquire_redteam_validation_lease(
        manager, bus, recorder, tmp_path, target, timeout=3
    )
    try:
        decision = _decision(tmp_path)
        admitted = float(decision.budget["admitted_run_ttl_seconds"])
        receipt = RedTeamValidationLease.consume_for_run(
            lease,
            run_id="journal-only-rollback",
            target=target,
            data_root=tmp_path,
            run_ttl_seconds=admitted,
        )
        history = _history(tmp_path, receipt, decision)
        assert write_run_history(tmp_path / "redteam_history.json", history)

        def generate() -> AARReportResult:
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
            return result

        first = generate()
        journal_path = tmp_path / "redteam_aar.heads.jsonl"
        journal_after_first = journal_path.read_bytes()
        second = generate()
        assert second.sequence == 2

        # Leave the newer fixed text/JSON/head pair untouched. Roll back only
        # the ordinary writable journal to its prior authentic one-row state.
        journal_path.write_bytes(journal_after_first)
        with pytest.raises(ValueError, match="journal rollback detected"):
            generate()

        assert len(aar_report._load_head_journal(journal_path, "redteam_aar")) == 1
        assert json.loads((tmp_path / "redteam_aar.head.json").read_bytes())[
            "sequence"
        ] == 2
        with pytest.raises(ValueError, match="stale|rolled back|current journal"):
            aar_report.verified_aar_handoff_text(first)
        with pytest.raises(ValueError, match="stale|rolled back|current journal"):
            aar_report.verified_aar_handoff_text(second)
    finally:
        RedTeamValidationLease.release(lease)
        guard.stop()
        recorder.close()


@pytest.mark.skipif(os.name != "nt", reason="exact handle disposition is Windows-only")
def test_cleanup_disposes_original_if_replacement_lands_after_delete_handle_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bus, recorder, guard, _fim, manager = _runtime(tmp_path, monkeypatch)
    target = tmp_path / "target"
    lease = purple_guard.acquire_redteam_validation_lease(
        manager, bus, recorder, tmp_path, target, timeout=3
    )
    marker = target / "_redteam_lsass_dump_post_open.txt"
    backup = target / "renamed-original.txt"
    try:
        run_id = "post-open-cleanup"
        RedTeamValidationLease.consume_for_run(
            lease, run_id=run_id, target=target, data_root=tmp_path
        )
        marker.write_text("enrolled original", encoding="utf-8")
        RedTeamValidationLease.register_artifact_handle(
            lease, marker, run_id=run_id
        )
        original_identity = purple_guard._marker_path_identity
        raced = False

        def replace_after_open(path, *, hold, delete_access=False):
            nonlocal raced
            descriptor, identity = original_identity(
                path, hold=hold, delete_access=delete_access
            )
            if delete_access and descriptor is not None and not raced:
                raced = True
                os.replace(marker, backup)
                marker.write_text("unrelated replacement", encoding="utf-8")
            return descriptor, identity

        monkeypatch.setattr(
            purple_guard, "_marker_path_identity", replace_after_open
        )
        assert RedTeamValidationLease.remove_registered_artifact(
            lease, marker, run_id=run_id
        )
        assert marker.read_text(encoding="utf-8") == "unrelated replacement"
        assert not backup.exists()
    finally:
        RedTeamValidationLease.release(lease)
        guard.stop()
        recorder.close()
        marker.unlink(missing_ok=True)
        backup.unlink(missing_ok=True)


def test_history_longer_than_authenticated_ttl_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bus, recorder, guard, _fim, manager = _runtime(tmp_path, monkeypatch)
    target = tmp_path / "target"
    lease = purple_guard.acquire_redteam_validation_lease(
        manager, bus, recorder, tmp_path, target, timeout=3
    )
    try:
        decision = _decision(tmp_path)
        admitted = float(decision.budget["admitted_run_ttl_seconds"])
        receipt = RedTeamValidationLease.consume_for_run(
            lease,
            run_id="ttl-overrun",
            target=target,
            data_root=tmp_path,
            run_ttl_seconds=admitted,
        )
        history = _history(tmp_path, receipt, decision)
        history["steps"][-1]["ts_end"] = (
            float(history["steps"][0]["ts_start"]) + admitted + 0.001
        )
        assert write_run_history(tmp_path / "redteam_history.json", history)
        assert not purple_guard.verify_validation_run_history(lease, history)
    finally:
        RedTeamValidationLease.release(lease)
        guard.stop()
        recorder.close()


def test_zero_step_signed_history_keeps_full_denominator_and_null_score(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bus, recorder, guard, _fim, manager = _runtime(tmp_path, monkeypatch)
    target = tmp_path / "target"
    lease = purple_guard.acquire_redteam_validation_lease(
        manager, bus, recorder, tmp_path, target, timeout=3
    )
    try:
        decision = _decision(tmp_path)
        admitted = float(decision.budget["admitted_run_ttl_seconds"])
        receipt = RedTeamValidationLease.consume_for_run(
            lease,
            run_id="independent-zero-step",
            target=target,
            data_root=tmp_path,
            run_ttl_seconds=admitted,
        )
        history = _history(tmp_path, receipt, decision, empty=True)
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
        assert isinstance(result, AARReportResult)
        payload = json.loads(result.report_bytes)
        assert report_attest.verify(payload) == "ok"
        assert payload["detection_steps"] == 13
        assert len(payload["verdicts"]) == 14
        assert payload["coverage_score_eligible"] is False
        assert payload["evidence_taxonomy"]["simulation_contract_validation"]["rate"] is None
    finally:
        RedTeamValidationLease.release(lease)
        guard.stop()
        recorder.close()
