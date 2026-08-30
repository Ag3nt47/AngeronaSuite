from __future__ import annotations

import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.core.storage import AsyncFlightRecorder, FlightRecorder
from angerona.modules import purple_guard


def _runtime(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        BusAuthority,
        "_key_path",
        staticmethod(lambda: tmp_path / "bus.key"),
    )
    bus = EventBus(ring_size=64)
    recorder = FlightRecorder(tmp_path / "flight-recorder.db")
    bus.arm(recorder.authority)
    worker = AsyncFlightRecorder(recorder, flush_interval=0.01)
    assert worker.start()
    bus.subscribe(worker.submit)
    guard = purple_guard.PurpleGuard(tmp_path)
    guard.bind(bus)
    manager = SimpleNamespace(
        modules={guard.name: guard},
        bus=bus,
    )
    return bus, recorder, worker, guard, manager


def test_validation_lease_temporarily_starts_sensor_and_proves_recorder(
    tmp_path: Path, monkeypatch
) -> None:
    bus, recorder, worker, guard, manager = _runtime(tmp_path, monkeypatch)
    target = tmp_path / "selected-target"
    try:
        lease = purple_guard.acquire_redteam_validation_lease(
            manager,
            bus,
            recorder,
            tmp_path,
            target,
            timeout=3.0,
        )
        assert lease.started_temporarily is True
        assert lease.readiness["policy_count"] == 13
        assert lease.readiness["recorder"]["authenticated"] is True
        assert lease.readiness["recorder"]["persisted"] is True
        assert (
            lease.readiness["recorder"]["recorder_revision_after"]
            > lease.readiness["recorder"]["recorder_revision_before"]
        )
        assert guard.operational_snapshot()["first_cycle_complete"] is True
        assert target.resolve() in purple_guard._runtime_targets_snapshot()
        lease.release()
        assert guard.status == "stopped"
        assert target.resolve() not in purple_guard._runtime_targets_snapshot()
    finally:
        guard.stop()
        assert worker.stop(timeout=3.0)
        recorder.close()


def test_validation_lease_fails_closed_without_recorder_delivery_and_restores_state(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(
        BusAuthority,
        "_key_path",
        staticmethod(lambda: tmp_path / "bus.key"),
    )
    bus = EventBus()
    recorder = FlightRecorder(tmp_path / "flight-recorder.db")
    bus.arm(recorder.authority)
    guard = purple_guard.PurpleGuard(tmp_path)
    guard.bind(bus)
    manager = SimpleNamespace(modules={guard.name: guard}, bus=bus)
    target = tmp_path / "undelivered-target"
    try:
        with pytest.raises(
            purple_guard.RedTeamValidationError,
            match="did not reach the flight recorder",
        ):
            purple_guard.acquire_redteam_validation_lease(
                manager,
                bus,
                recorder,
                tmp_path,
                target,
                timeout=0.2,
            )
        assert guard.status == "stopped"
        assert target.resolve() not in purple_guard._runtime_targets_snapshot()
    finally:
        guard.stop()
        recorder.close()


def test_validation_lease_ignores_instance_methods_that_fake_persistence(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(
        BusAuthority,
        "_key_path",
        staticmethod(lambda: tmp_path / "bus.key"),
    )
    bus = EventBus(ring_size=64)
    recorder = FlightRecorder(tmp_path / "flight-recorder.db")
    bus.arm(recorder.authority)
    guard = purple_guard.PurpleGuard(tmp_path)
    guard.bind(bus)
    manager = SimpleNamespace(modules={guard.name: guard}, bus=bus)
    target = tmp_path / "instance-spoof-target"

    # These replacements would make a ring-only readiness check look healthy.
    # The gate must call FlightRecorder's exact class implementations instead.
    monkeypatch.setattr(recorder, "revision", lambda: 999_999)
    monkeypatch.setattr(
        recorder,
        "recent_in_window",
        lambda *_args, **_kwargs: bus.recent(64),
    )
    try:
        with pytest.raises(
            purple_guard.RedTeamValidationError,
            match="did not reach the flight recorder",
        ):
            purple_guard.acquire_redteam_validation_lease(
                manager,
                bus,
                recorder,
                tmp_path,
                target,
                timeout=0.2,
            )
        assert FlightRecorder.revision(recorder) == 0
        assert guard.status == "stopped"
        assert target.resolve() not in purple_guard._runtime_targets_snapshot()
    finally:
        guard.stop()
        recorder.close()


def test_tagged_process_probe_survives_general_event_flood(
    tmp_path: Path,
) -> None:
    bus = EventBus(ring_size=32)
    guard = purple_guard.PurpleGuard(tmp_path)
    guard.bind(bus)
    purple_guard.ensure_redteam_validation_pack(tmp_path)
    observed: list[Event] = []
    bus.subscribe(observed.append)
    guard.start()
    try:
        assert guard.wait_for_first_cycle(2.0)
        bus.publish(
            Event(
                "Process Monitor",
                "raw process observation",
                Severity.INFO,
                details={
                    "event_type": "process_creation",
                    "pid": 4242,
                    "cmdline": "python -c pass ANGERONA_REDTEAM_deadbeef",
                    "process_create_time": 123.5,
                },
            )
        )
        for index in range(1000):
            bus.publish(Event("Noise", f"event-{index}", Severity.INFO))
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and not any(
            event.module == guard.name
            and (event.details or {}).get("mitre") == "T1059"
            for event in observed
        ):
            time.sleep(0.025)
        assert any(
            event.module == guard.name
            and (event.details or {}).get("mitre") == "T1059"
            for event in observed
        )
    finally:
        guard.stop()


def test_custom_marker_cannot_collide_with_builtin_technique_tokens() -> None:
    marker = Path("_redteam_custom_lsass_dump_amsi_bypass_deadbeef.txt")
    assert purple_guard.classify_marker(marker) is None


def test_policy_loss_degrades_with_exact_evidence_and_one_alert(tmp_path: Path) -> None:
    bus = EventBus()
    guard = purple_guard.PurpleGuard(tmp_path)
    guard.bind(bus)

    guard._update_policy_health(0)
    initial = guard.operational_snapshot()
    assert initial["health"] == 70
    assert "learning-only" in str(initial["health_note"])
    assert initial["health_evidence"]["source_path"].endswith("purple_guard.py")

    guard._update_policy_health(13)
    assert guard.health == 100
    guard._update_policy_health(0)
    guard._update_policy_health(0)

    degraded = guard.operational_snapshot()
    assert degraded["health"] == 25
    assert "disappeared or became unreadable" in str(degraded["health_note"])
    alerts = [
        event
        for event in bus.recent(20)
        if (event.details or {}).get("finding_code") == "purple_guard.policy_lost"
    ]
    assert len(alerts) == 1


def test_validation_rejects_ring_only_structural_recorder(
    tmp_path: Path, monkeypatch
) -> None:
    bus, recorder, worker, guard, manager = _runtime(tmp_path, monkeypatch)

    class RingOnlyRecorder:
        def revision(self):
            return 0

        def recent_in_window(self, *_args, **_kwargs):
            return bus.recent(64)

    try:
        with pytest.raises(
            purple_guard.RedTeamValidationError,
            match="exact built-in FlightRecorder",
        ):
            purple_guard.acquire_redteam_validation_lease(
                manager,
                bus,
                RingOnlyRecorder(),
                tmp_path,
                tmp_path / "target",
            )
    finally:
        guard.stop()
        assert worker.stop(timeout=3.0)
        recorder.close()


def test_validation_rejects_foreign_root_recorder(
    tmp_path: Path, monkeypatch
) -> None:
    bus, recorder, worker, guard, manager = _runtime(tmp_path, monkeypatch)
    foreign = FlightRecorder(tmp_path / "foreign" / "flight-recorder.db")
    try:
        with pytest.raises(
            purple_guard.RedTeamValidationError,
            match="does not belong to the simulation data root",
        ):
            purple_guard.acquire_redteam_validation_lease(
                manager,
                bus,
                foreign,
                tmp_path,
                tmp_path / "target",
            )
    finally:
        guard.stop()
        assert worker.stop(timeout=3.0)
        recorder.close()
        foreign.close()


def test_validation_rejects_closed_canonical_recorder(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(
        BusAuthority,
        "_key_path",
        staticmethod(lambda: tmp_path / "bus.key"),
    )
    recorder = FlightRecorder(tmp_path / "flight-recorder.db")
    bus = EventBus()
    bus.arm(recorder.authority)
    guard = purple_guard.PurpleGuard(tmp_path)
    guard.bind(bus)
    manager = SimpleNamespace(modules={guard.name: guard}, bus=bus)
    recorder.close()

    with pytest.raises(
        purple_guard.RedTeamValidationError,
        match="closed or unverifiable",
    ):
        purple_guard.acquire_redteam_validation_lease(
            manager,
            bus,
            recorder,
            tmp_path,
            tmp_path / "target",
        )
    assert guard.status == "stopped"


def test_validation_rejects_equal_key_but_different_authority_object(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(
        BusAuthority,
        "_key_path",
        staticmethod(lambda: tmp_path / "bus.key"),
    )
    recorder = FlightRecorder(tmp_path / "flight-recorder.db")
    bus = EventBus()
    bus.arm(BusAuthority.load())
    guard = purple_guard.PurpleGuard(tmp_path)
    guard.bind(bus)
    manager = SimpleNamespace(modules={guard.name: guard}, bus=bus)
    try:
        with pytest.raises(
            purple_guard.RedTeamValidationError,
            match="exact authority instance",
        ):
            purple_guard.acquire_redteam_validation_lease(
                manager,
                bus,
                recorder,
                tmp_path,
                tmp_path / "target",
            )
    finally:
        recorder.close()


def test_lease_is_exact_target_bound_and_single_use(
    tmp_path: Path, monkeypatch
) -> None:
    bus, recorder, worker, guard, manager = _runtime(tmp_path, monkeypatch)
    target = tmp_path / "target-a"
    lease = purple_guard.acquire_redteam_validation_lease(
        manager, bus, recorder, tmp_path, target, timeout=3
    )
    try:
        with pytest.raises(AttributeError):
            lease.target = (tmp_path / "target-b").resolve()  # type: ignore[misc]
        assert lease.target == target.resolve()
        with pytest.raises(
            purple_guard.RedTeamValidationError,
            match="target-mismatched",
        ):
            lease.consume_for_run(
                run_id="wrong-target",
                target=tmp_path / "target-b",
                data_root=tmp_path,
            )
        receipt = lease.consume_for_run(
            run_id="one-run",
            target=target,
            data_root=tmp_path,
        )
        assert receipt["bound_target"] == str(target.resolve(strict=False))
        assert receipt["bound_run_id"] == "one-run"
        with pytest.raises(
            purple_guard.RedTeamValidationError,
            match="consumed",
        ):
            lease.consume_for_run(
                run_id="replay",
                target=target,
                data_root=tmp_path,
            )
    finally:
        lease.release()
        guard.stop()
        assert worker.stop(timeout=3.0)
        recorder.close()


def test_lease_release_revokes_unconsumed_nonce(
    tmp_path: Path, monkeypatch
) -> None:
    bus, recorder, worker, guard, manager = _runtime(tmp_path, monkeypatch)
    target = tmp_path / "target"
    lease = purple_guard.acquire_redteam_validation_lease(
        manager, bus, recorder, tmp_path, target, timeout=3
    )
    lease.release()
    try:
        with pytest.raises(purple_guard.RedTeamValidationError, match="released"):
            lease.consume_for_run(
                run_id="revoked",
                target=target,
                data_root=tmp_path,
            )
        assert guard.status == "stopped"
    finally:
        guard.stop()
        assert worker.stop(timeout=3.0)
        recorder.close()


def test_lease_is_invalidated_by_policy_change(
    tmp_path: Path, monkeypatch
) -> None:
    bus, recorder, worker, guard, manager = _runtime(tmp_path, monkeypatch)
    target = tmp_path / "target"
    lease = purple_guard.acquire_redteam_validation_lease(
        manager, bus, recorder, tmp_path, target, timeout=3
    )
    purple_guard.policy_path(tmp_path).write_text(
        '{"version": 1, "techniques": {}}',
        encoding="utf-8",
    )
    try:
        with pytest.raises(purple_guard.RedTeamValidationError, match="stale"):
            lease.consume_for_run(
                run_id="policy-changed",
                target=target,
                data_root=tmp_path,
            )
    finally:
        lease.release()
        guard.stop()
        assert worker.stop(timeout=3.0)
        recorder.close()


def test_lease_is_invalidated_by_sensor_restart(
    tmp_path: Path, monkeypatch
) -> None:
    bus, recorder, worker, guard, manager = _runtime(tmp_path, monkeypatch)
    target = tmp_path / "target"
    lease = purple_guard.acquire_redteam_validation_lease(
        manager, bus, recorder, tmp_path, target, timeout=3
    )
    guard.stop()
    guard.start()
    assert guard.wait_for_first_cycle(2)
    try:
        with pytest.raises(purple_guard.RedTeamValidationError, match="stale"):
            lease.consume_for_run(
                run_id="sensor-restarted",
                target=target,
                data_root=tmp_path,
            )
    finally:
        lease.release()
        guard.stop()
        assert worker.stop(timeout=3.0)
        recorder.close()


def test_guard_refuses_overlapping_active_leases(
    tmp_path: Path, monkeypatch
) -> None:
    bus, recorder, worker, guard, manager = _runtime(tmp_path, monkeypatch)
    lease = purple_guard.acquire_redteam_validation_lease(
        manager, bus, recorder, tmp_path, tmp_path / "target-a", timeout=3
    )
    try:
        with pytest.raises(
            purple_guard.RedTeamValidationError,
            match="already has an active",
        ):
            purple_guard.acquire_redteam_validation_lease(
                manager,
                bus,
                recorder,
                tmp_path,
                tmp_path / "target-b",
                timeout=3,
            )
        assert guard.operational_snapshot()["thread_alive"] is True
        assert (tmp_path / "target-a").resolve() in (
            purple_guard._runtime_targets_snapshot()
        )
        assert (tmp_path / "target-b").resolve() not in (
            purple_guard._runtime_targets_snapshot()
        )
    finally:
        lease.release()
        guard.stop()
        assert worker.stop(timeout=3.0)
        recorder.close()
