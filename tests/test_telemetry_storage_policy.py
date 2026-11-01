"""Worker observations and policy publication never become a caller I/O gate."""
from __future__ import annotations

import threading

import pytest

from angerona.core.telemetry_storage_policy import (
    MIB, RecorderStorageHeld, TelemetryStorageBudget,
)


def facts(**changes):
    result = dict(db_bytes=4096, wal_bytes=0, shm_bytes=32768, free_bytes=4096 * MIB,
                  parent_identity=(1, 2), db_identity=(1, 3))
    result.update(changes)
    return result


def policy(budget, **changes):
    values = dict(blocked=False, db_target_bytes=256 * MIB,
                  wal_target_bytes=64 * MIB, min_free_bytes=2048 * MIB)
    values.update(changes)
    return budget.configure(**values)


def test_unconfigured_and_setter_getter_are_memory_only(tmp_path):
    budget = TelemetryStorageBudget(tmp_path / "events.db")
    budget.clock = lambda: pytest.fail("getter/setter sampled a clock")
    budget.sampler = lambda _path: pytest.fail("getter/setter probed storage")
    old = budget.snapshot()
    assert old["state"] == "unconfigured" and old["configured"] is False
    assert old["db_target_bytes"] is None and old["db_bytes"] is None
    assert old["facts_generation"] == 0 and old["facts_stale"] is True
    assert policy(budget)["accepted"] is True
    view = budget.snapshot()
    assert view["state"] == "unmeasured" and view["policy_generation"] == 1
    assert view["durable"] is False and view["no_response_reserve"] is True
    view["db_target_bytes"] = 1
    assert budget.snapshot()["db_target_bytes"] == 256 * MIB


@pytest.mark.parametrize("changes", [
    {"blocked": 1}, {"db_target_bytes": True}, {"db_target_bytes": 16 * MIB - 1},
    {"db_target_bytes": 16384 * MIB + 1}, {"wal_target_bytes": 4 * MIB - 1},
    {"wal_target_bytes": 1024 * MIB + 1}, {"min_free_bytes": 512 * MIB - 1},
    {"min_free_bytes": 65536 * MIB + 1},
])
def test_invalid_policy_never_changes_active_generation(tmp_path, changes):
    budget = TelemetryStorageBudget(tmp_path / "events.db")
    assert policy(budget)["accepted"]
    assert policy(budget, **changes)["accepted"] is False
    assert budget.snapshot()["policy_generation"] == 1


@pytest.mark.parametrize("change,reason", [
    ({"db_bytes": 256 * MIB}, "db_target"),
    ({"wal_bytes": 64 * MIB}, "wal_target"),
    ({"free_bytes": 2048 * MIB}, "free_floor"),
])
def test_observed_targets_hold_without_any_write(tmp_path, change, reason):
    budget = TelemetryStorageBudget(tmp_path / "events.db")
    policy(budget)
    budget.clock = lambda: 10.0
    budget.sampler = lambda _path: facts(**change)
    budget.refresh_on_worker()
    with pytest.raises(RecorderStorageHeld) as held:
        budget.admit(1)
    assert held.value.reason == reason and held.value.progress.completed == 0
    assert budget.snapshot()["state"] == "held"


def test_own_acknowledged_write_refreshes_without_one_second_delay(tmp_path):
    budget = TelemetryStorageBudget(tmp_path / "events.db")
    policy(budget)
    budget.clock = lambda: 10.0
    calls = []
    budget.sampler = lambda _path: calls.append(True) or facts()
    budget.refresh_on_worker()
    lease = budget.admit(100)
    budget.release(lease, wrote=True)
    assert budget.snapshot()["state"] != "ready"
    budget.refresh_on_worker()  # Same fake clock: own dirty write is not a parked retry.
    assert len(calls) == 2 and budget.snapshot()["state"] == "ready"


def test_capacity_and_failed_probes_are_rate_bounded(tmp_path):
    budget = TelemetryStorageBudget(tmp_path / "events.db")
    policy(budget)
    now = [10.0]
    budget.clock = lambda: now[0]
    calls = []
    budget.sampler = lambda _path: calls.append(True) or facts(free_bytes=1)
    for _ in range(10):
        budget.refresh_on_worker()
    assert len(calls) == 1
    now[0] += 1
    budget.refresh_on_worker()
    assert len(calls) == 2


def test_old_probe_cannot_clear_new_operator_block(tmp_path):
    budget = TelemetryStorageBudget(tmp_path / "events.db")
    policy(budget)
    budget.clock = lambda: 10.0
    entered, release = threading.Event(), threading.Event()
    setter_completed = threading.Event()
    errors = []
    receipts = []

    def sample(_path):
        entered.set()
        if not release.wait(30):
            raise AssertionError("fixture release deadline")
        return facts()

    def run():
        try:
            budget.refresh_on_worker()
        except BaseException as exc:
            errors.append(exc)

    budget.sampler = sample
    worker = threading.Thread(target=run, name="StorageFactsGenerationFixture")

    def set_policy():
        try:
            receipts.append(policy(budget, blocked=True))
        except BaseException as exc:
            errors.append(exc)
        finally:
            setter_completed.set()

    setter = threading.Thread(target=set_policy, name="StoragePolicySetterFixture")
    try:
        worker.start()
        assert entered.wait(5)
        setter.start()
        assert setter_completed.wait(5), "setter waited for blocked probe I/O"
        assert receipts[0]["accepted"]
    finally:
        release.set()
        for owned in (worker, setter):
            if owned.ident is not None:
                owned.join(5)
    assert not worker.is_alive() and not setter.is_alive() and not errors
    view = budget.snapshot()
    assert view["state"] == "held" and view["reason_code"] == "operator_blocked"
    assert view["policy_generation"] == 2 and view["facts_generation"] == 0


def test_inflight_lease_can_finish_but_next_unit_obeys_new_block(tmp_path):
    budget = TelemetryStorageBudget(tmp_path / "events.db")
    policy(budget)
    budget.clock = lambda: 10.0
    budget.sampler = lambda _path: facts()
    budget.refresh_on_worker()
    lease = budget.admit(100)
    policy(budget, blocked=True)
    budget.release(lease, wrote=True)
    with pytest.raises(RecorderStorageHeld) as held:
        budget.admit(100)
    assert held.value.reason == "operator_blocked"


def test_identity_change_and_expired_facts_never_admit_as_ready(tmp_path):
    budget = TelemetryStorageBudget(tmp_path / "events.db")
    policy(budget)
    now = [10.0]
    budget.clock = lambda: now[0]
    budget.sampler = lambda _path: facts()
    budget.refresh_on_worker()
    now[0] = 16.0
    with pytest.raises(RecorderStorageHeld) as held:
        budget.admit(1)
    assert held.value.reason == "facts_stale"
    budget.sampler = lambda _path: facts(db_identity=(1, 99))
    budget.refresh_on_worker()
    assert budget.snapshot()["reason_code"] == "identity_changed"
