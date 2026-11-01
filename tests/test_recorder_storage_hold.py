"""Storage holds preserve admitted originals and never become fallback failures."""
from __future__ import annotations

import dataclasses
import threading
import time

import pytest

from angerona.core import storage
from angerona.core.eventbus import BusAuthority, Event
from angerona.core.telemetry_storage_policy import MIB, RecorderStorageHeld


@pytest.fixture
def recorder(tmp_path, monkeypatch):
    authority = BusAuthority(bytes(range(32)))
    monkeypatch.setattr(BusAuthority, "load", lambda: authority)
    value = storage.FlightRecorder(tmp_path / "events.db")
    value._storage_budget.sampler = lambda _path: dict(
        db_bytes=4096, wal_bytes=0, shm_bytes=32768, free_bytes=4096 * MIB,
        parent_identity=(1, 2), db_identity=(1, 3))
    try:
        yield value
    finally:
        runtime = value._storage_runtime
        if runtime is not None:
            runtime.stop(timeout=5)
            assert runtime.retirement_snapshot()["workers_retired"]
        value.close()


def configure(recorder, **changes):
    policy = dict(blocked=False, db_target_bytes=256 * MIB,
                  wal_target_bytes=64 * MIB, min_free_bytes=2048 * MIB)
    policy.update(changes)
    assert recorder.configure_storage_policy(**policy)["accepted"]


def signed(recorder, message="inert"):
    event = Event("storage-fixture", message, ts=1.0)
    return dataclasses.replace(event, hmac_sig=recorder.authority.sign(event))


def wait_for(predicate):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError("owned fixture condition did not complete")


def test_bare_direct_library_stays_explicitly_unconfigured(recorder):
    recorder._storage_budget.sampler = lambda _path: pytest.fail("unconfigured probe")
    recorder.record(signed(recorder))
    assert len(recorder.recent()) == 1
    assert recorder.storage_budget_snapshot()["configured"] is False
    assert recorder.storage_budget_snapshot()["state"] == "unconfigured"


@pytest.mark.parametrize("writer", ["single", "batch", "spool", "replay"])
def test_typed_hold_cannot_insert_spill_retry_or_sleep(recorder, monkeypatch, writer):
    configure(recorder, blocked=True)
    event = signed(recorder)
    monkeypatch.setattr(storage.time, "sleep", lambda *_: pytest.fail("hold retried/slept"))
    monkeypatch.setattr(storage, "_dlq_write_exclusive", lambda *_: pytest.fail("hold spooled"))
    before = recorder._db.total_changes
    with pytest.raises(RecorderStorageHeld) as held:
        if writer == "single":
            recorder.record_bus(event)
        elif writer == "batch":
            recorder.record_batch_bus([event])
        elif writer == "spool":
            recorder._route_batch_to_dlq([event])
        else:
            recorder.replay_dlq()
    assert held.value.reason == "operator_blocked"
    assert held.value.progress.completed == 0
    assert recorder._db.total_changes == before
    assert not recorder._db.in_transaction


def test_current_full_dlq_expansion_is_in_unit_bound(recorder):
    configure(recorder)
    recorder._storage_refresh_on_worker()
    event = signed(recorder, "é" * 200000)
    assert len(event.message.encode("utf-8")) < MIB
    with pytest.raises(RecorderStorageHeld) as held:
        recorder.record_bus(event)
    assert held.value.reason == "unit_too_large" and recorder.recent() == []


def test_known_commit_with_held_maintenance_never_respools(recorder, monkeypatch):
    configure(recorder)
    recorder._storage_refresh_on_worker()
    monkeypatch.setattr(recorder, "PRUNE_EVERY", 1)
    monkeypatch.setattr(recorder, "_prune_locked", lambda: (_ for _ in ()).throw(
        RecorderStorageHeld("free_floor", 1)))
    monkeypatch.setattr(recorder, "_route_batch_to_dlq", lambda *_a, **_kw: pytest.fail("committed row respilled"))
    result = recorder.record_batch_bus([signed(recorder)])
    assert result.persisted == 1 and result.dlq == 0
    assert len(recorder.recent()) == 1 and recorder.revision() > 0
    assert recorder.storage_budget_snapshot()["maintenance_deferred"] == 1


def test_configured_ready_stop_drains_normal_accepted_queue(recorder):
    configure(recorder)
    worker = storage.AsyncFlightRecorder(recorder, batch_size=4)
    assert worker.start()
    for index in range(12):
        worker.submit(signed(recorder, f"event-{index}"))
    assert worker.stop(timeout=5)
    retirement = worker.retirement_snapshot()
    assert retirement["workers_retired"] and retirement["drained"]
    assert retirement["pending_events"] == 0 and len(recorder.recent()) == 12


def test_operator_hold_preserves_exact_pending_and_stop_retires_without_drain(recorder):
    configure(recorder)
    worker = storage.AsyncFlightRecorder(recorder)
    event = signed(recorder)
    # Admit bounded memory before workers start, as a controlled queued fixture.
    worker._queue.put_nowait(event)
    with worker._metrics_lock:
        worker._accepted += 1
        worker._storage_pending_events += 1
    configure(recorder, blocked=True)
    assert worker.start()
    wait_for(lambda: worker.recovery_snapshot()["storage_held"])
    assert worker.stop(timeout=5) is False
    view = worker.retirement_snapshot()
    assert view["workers_retired"] and not view["drained"] and view["pending_events"] == 1
    assert recorder.recent() == []
    slot = worker._storage_slots["primary"]
    assert slot is not None and slot["events"][0] is event
    assert event.hmac_sig == recorder.authority.sign(event)
    assert worker.recovery_snapshot()["dlq_failures"] == 0


def test_oversized_review_discard_is_exact_explicit_and_gap_latched(recorder):
    configure(recorder)
    worker = storage.AsyncFlightRecorder(recorder)
    event = signed(recorder, "x" * MIB)
    assert worker.start()
    worker.submit(event)
    wait_for(lambda: recorder.held_unit_review("primary").get("discard_allowed"))
    review = recorder.held_unit_review("primary")
    assert worker._storage_slots["primary"]["events"][0] is event
    assert recorder.recent() == []
    fields = ("lane", "token", "policy_generation", "worker_generation", "pending_generation")
    request = {key: review[key] for key in fields}
    stale = dict(request, pending_generation=request["pending_generation"] + 1)
    assert recorder.discard_held_unit(**stale)["accepted"] is False
    assert recorder.discard_held_unit(**request)["discarded_events"] == 1
    assert recorder.discard_held_unit(**request)["accepted"] is False
    view = worker.recovery_snapshot()
    assert view["storage_user_discarded"] == 1 and view["coverage_gap"] is True
    worker.submit(signed(recorder, "following accepted evidence"))
    assert worker.stop(timeout=5)
    assert len(recorder.recent()) == 1
    assert recorder.storage_budget_snapshot()["storage_user_discarded"] == 1


def test_new_held_rejection_is_counted_once_without_io(recorder, monkeypatch):
    configure(recorder, blocked=True)
    worker = storage.AsyncFlightRecorder(recorder)
    assert worker.start()
    monkeypatch.setattr(recorder, "_storage_unit_bytes", lambda *_: pytest.fail("publisher serialized storage"))
    for _ in range(3):
        with pytest.raises(storage.RecorderAdmissionRejected) as held:
            worker.submit(signed(recorder))
        assert held.value.reason == "storage_hold"
    view = worker.recovery_snapshot()
    assert view["healthy"] is True and view["rejection_storage_hold"] == 3
    assert view["admission_rejected"] == 3 and view["dlq_failures"] == 0
    assert view["coverage_gap"] is True


def test_one_runtime_owner_cannot_be_replaced_or_reset(recorder):
    first = storage.AsyncFlightRecorder(recorder)
    with pytest.raises(RuntimeError, match="runtime owner"):
        storage.AsyncFlightRecorder(recorder)
    assert first.start() and first.stop(timeout=5)
    with pytest.raises(RuntimeError, match="runtime owner"):
        storage.AsyncFlightRecorder(recorder)
    assert first.start() and first.stop(timeout=5)


def test_concurrent_runtime_constructors_have_one_lifetime_owner(recorder):
    barrier = threading.Barrier(2)
    owners, errors = [], []

    def construct():
        try:
            barrier.wait(timeout=5)
            owners.append(storage.AsyncFlightRecorder(recorder))
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=construct, name=f"RecorderOwnerFixture-{index}")
               for index in range(2)]
    try:
        for thread in threads:
            thread.start()
    finally:
        for thread in threads:
            if thread.ident is not None:
                thread.join(5)
    assert not any(thread.is_alive() for thread in threads)
    assert len(owners) == len(errors) == 1 and isinstance(errors[0], RuntimeError)
    assert recorder._storage_runtime is owners[0]


def test_mid_route_hold_carries_only_written_prefix(recorder, monkeypatch):
    events = [signed(recorder, "a"), signed(recorder, "b")]
    monkeypatch.setattr(recorder, "DLQ_SEGMENT_BYTES", 1)
    calls = []

    def append(_text, _bytes, **_kwargs):
        calls.append(True)
        if len(calls) == 1:
            configure(recorder, blocked=True)
            return True
        raise RecorderStorageHeld("operator_blocked", 1)

    monkeypatch.setattr(recorder, "_append_dlq_chunk", append)
    with pytest.raises(RecorderStorageHeld) as held:
        recorder._route_batch_to_dlq(events)
    assert held.value.progress.completed == held.value.progress.spooled == 1
    assert held.value.progress.persisted == 0 and len(calls) == 2


def test_configured_spool_capacity_parks_without_caller_replay_or_wait(recorder, monkeypatch):
    fillers = [signed(recorder, "signed existing spool one"), signed(recorder, "signed existing spool two")]
    incoming = signed(recorder)
    assert recorder._route_batch_to_dlq(fillers) == 2
    existing = recorder._active_dlq_path().read_bytes()
    entry_bytes = len(recorder._dlq_entry(incoming, time.time()).encode("utf-8"))
    # Every entry fits individually; only their aggregate exhausts capacity.
    limit = len(existing) + entry_bytes // 2
    assert entry_bytes < limit < len(existing) + entry_bytes
    monkeypatch.setattr(recorder, "DLQ_MAX_BYTES", limit)
    configure(recorder)
    recorder._storage_refresh_on_worker()
    monkeypatch.setattr(recorder, "replay_dlq", lambda **_kw: pytest.fail("caller replayed capacity"))
    monkeypatch.setattr(recorder._dlq_capacity, "wait", lambda **_kw: pytest.fail("caller waited for capacity"))
    with pytest.raises(RecorderStorageHeld) as held:
        recorder._route_batch_to_dlq([incoming])
    assert held.value.reason == "spool_capacity" and held.value.progress.completed == 0
    assert recorder._storage_budget._reserved == 0
    assert recorder._active_dlq_path().read_bytes() == existing


def test_later_replay_hold_reports_committed_prefix_and_keeps_source(recorder, monkeypatch):
    assert recorder._route_batch_to_dlq([signed(recorder, "one"), signed(recorder, "two")]) == 2
    configure(recorder)
    recorder._storage_refresh_on_worker()
    monkeypatch.setattr(recorder, "DLQ_REPLAY_BATCH", 1)
    original = recorder._insert_replay_batch
    calls = []

    def first_then_hold(events, segment):
        if calls:
            raise RecorderStorageHeld("free_floor", 1)
        calls.append(True)
        return original(events, segment)

    monkeypatch.setattr(recorder, "_insert_replay_batch", first_then_hold)
    with pytest.raises(RecorderStorageHeld) as held:
        recorder.replay_dlq()
    assert held.value.replay_progress.inserted == 1
    assert held.value.replay_progress.segments_completed == held.value.replay_progress.failures == 0
    assert len(recorder.recent()) == 1 and recorder.dlq_status()["segments"] >= 1


def test_oversized_durable_line_is_preserved_while_later_valid_event_replays(recorder):
    big, small = signed(recorder, "é" * 200000), signed(recorder, "after oversized")
    assert recorder._route_batch_to_dlq([big, small]) == 2
    configure(recorder)
    recorder._storage_refresh_on_worker()
    result = recorder.replay_dlq()
    assert result.inserted == 1 and result.segments_completed == result.failures == 0
    assert recorder.recent()[0].message == small.message
    assert recorder.dlq_status()["segments"] >= 1
    assert recorder.storage_budget_snapshot()["replay_deferred"] >= 1


def test_running_legacy_adapter_can_enter_configured_hold_without_losing_input(recorder):
    worker = storage.AsyncFlightRecorder(recorder)
    assert worker.start()
    configure(recorder)
    worker.submit(signed(recorder, "new policy"))
    wait_for(lambda: worker.recovery_snapshot()["storage_pending_events"] == 0
             and len(recorder.recent()) == 1)
    assert worker.stop(timeout=5)


def test_oversized_reason_survives_allow_or_target_policy_change(recorder):
    configure(recorder)
    worker = storage.AsyncFlightRecorder(recorder)
    assert worker.start()
    worker.submit(signed(recorder, "x" * MIB))
    wait_for(lambda: recorder.held_unit_review("primary").get("discard_allowed"))
    configure(recorder)
    assert recorder.storage_budget_snapshot()["reason_code"] == "unit_too_large"
    assert worker.recovery_snapshot()["storage_reason"] == "unit_too_large"


def test_configured_primary_relief_clears_saturation_before_new_admission(recorder, monkeypatch):
    configure(recorder)
    worker = storage.AsyncFlightRecorder(recorder, queue_capacity=1, batch_size=1)
    entered, release = threading.Event(), threading.Event()
    original = recorder.record_batch_bus

    def gated(events):
        entered.set()
        if not release.wait(30):
            raise AssertionError("fixture release deadline")
        return original(events)

    monkeypatch.setattr(recorder, "record_batch_bus", gated)
    try:
        assert worker.start()
        worker.submit(signed(recorder, "first"))
        assert entered.wait(5)
        worker.submit(signed(recorder, "second"))
        worker.submit(signed(recorder, "overflow"))
        assert worker._primary_saturated.is_set()
        release.set()
        wait_for(lambda: worker._persisted >= 2)
        before = worker._accepted
        worker.submit(signed(recorder, "primary restored"))
        assert worker._accepted == before + 1
    finally:
        release.set()
        worker.stop(timeout=5)
    assert worker.retirement_snapshot()["workers_retired"]


def test_failed_sql_and_spool_ack_remains_gap_after_policy_ready(recorder, monkeypatch):
    configure(recorder)
    original = recorder._db

    class BrokenInsert:
        def __getattr__(self, name):
            return getattr(original, name)

        def executemany(self, sql, parameters):
            if sql.startswith("INSERT INTO events"):
                raise storage.sqlite3.OperationalError("inert database failure")
            return original.executemany(sql, parameters)

    recorder._db = BrokenInsert()
    monkeypatch.setattr(recorder, "_DLQ_RETRY_DELAY", 0)
    monkeypatch.setattr(recorder, "_route_batch_to_dlq", lambda *_a, **_kw: 0)
    worker = storage.AsyncFlightRecorder(recorder)
    assert worker.start()
    worker.submit(signed(recorder))
    wait_for(lambda: worker.recovery_snapshot()["storage_write_failures"] == 1)
    assert worker.stop(timeout=5)
    recorder._storage_refresh_on_worker()
    view = recorder.storage_budget_snapshot()
    assert view["state"] == "ready" and view["storage_pending_events"] == 0
    assert view["storage_write_failures"] == 1 and view["coverage_gap"] is True


def test_unconfigured_capacity_stop_preserves_slot_and_restart_drains_it(recorder, monkeypatch):
    original_db = recorder._db
    database_released = threading.Event()
    capacity_waiting = threading.Event()
    original_wait = recorder._dlq_capacity.wait
    fillers = [signed(recorder, "signed legacy spool one"), signed(recorder, "signed legacy spool two")]
    event = signed(recorder, "legacy retained input")
    assert recorder._route_batch_to_dlq(fillers) == 2
    existing = recorder._active_dlq_path().read_bytes()
    entry_bytes = len(recorder._dlq_entry(event, time.time()).encode("utf-8"))
    limit = len(existing) + entry_bytes // 2
    assert entry_bytes < limit < len(existing) + entry_bytes

    class LockedDatabase:
        def __getattr__(self, name):
            return getattr(original_db, name)

        def executemany(self, sql, parameters):
            if sql.startswith("INSERT INTO events") and not database_released.is_set():
                raise storage.sqlite3.OperationalError("inert database lock")
            return original_db.executemany(sql, parameters)

    def observe_capacity_wait(timeout=None):
        capacity_waiting.set()
        return original_wait(timeout=timeout)

    recorder._db = LockedDatabase()
    monkeypatch.setattr(recorder, "_DLQ_RETRY_DELAY", 0)
    monkeypatch.setattr(recorder, "DLQ_MAX_BYTES", limit)
    monkeypatch.setattr(recorder._dlq_capacity, "wait", observe_capacity_wait)
    worker = storage.AsyncFlightRecorder(recorder)
    try:
        assert worker.start()
        worker.submit(event)
        assert capacity_waiting.wait(5), "fixture never reached the full legacy spool"
        assert worker.stop(timeout=5) is False
        retirement = worker.retirement_snapshot()
        assert retirement["workers_retired"] and not retirement["drained"]
        assert retirement["pending_events"] == 1
        assert worker._storage_slots["primary"]["events"][0] is event
        assert recorder.storage_budget_snapshot()["configured"] is False
        assert recorder.recent() == []
        # Real replay attempted capacity relief, but the same DB gate prevented
        # a receipt/event commit and preserved the complete signed source.
        with recorder._dlq_lock:
            sources = recorder._segment_paths_locked(include_quarantine=False)
            assert any(path.read_bytes() == existing for path in sources)
        database_released.set()
        assert worker.start()
        wait_for(lambda: worker.retirement_snapshot()["pending_events"] == 0)
        assert worker.stop(timeout=5) is True
        assert worker.retirement_snapshot()["drained"] is True
        rows = recorder.recent()
        incoming = [row for row in rows if row.hmac_sig == event.hmac_sig]
        assert len(incoming) == 1 and incoming[0].message == event.message
        assert recorder.authority.verify(incoming[0])
        assert recorder.storage_budget_snapshot()["configured"] is False
        # Normal maintenance may also replay the prefilled source after release.
        # Its custody must remain either in that exact source or in signed SQL.
        with recorder._dlq_lock:
            preserved = any(path.read_bytes() == existing for path in
                            recorder._segment_paths_locked(include_quarantine=False))
        assert preserved or all(any(row.hmac_sig == filler.hmac_sig and recorder.authority.verify(row)
                                    for row in rows) for filler in fillers)
    finally:
        database_released.set()
        worker._storage_wake.set()
        with recorder._dlq_capacity:
            recorder._dlq_capacity.notify_all()
        worker.stop(timeout=5)
    assert worker.retirement_snapshot()["workers_retired"]
