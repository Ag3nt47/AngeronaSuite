"""Real fixture SQLite commits with inert faults, never an operator ledger."""
from __future__ import annotations

import dataclasses
import json
import sqlite3

import pytest

from angerona.core.eventbus import BusAuthority, Event, Severity
from angerona.core.storage import BatchRecordResult, FlightRecorder


@pytest.fixture
def recorder(tmp_path, monkeypatch):
    authority = BusAuthority(b"c" * 32)
    monkeypatch.setattr(
        "angerona.core.storage.BusAuthority.load",
        classmethod(lambda cls: authority),
    )
    instance = FlightRecorder(tmp_path / "events.db")
    monkeypatch.setattr(instance, "_DLQ_RETRY_DELAY", 0)
    try:
        yield instance
    finally:
        instance.close()


def _events(recorder, count=2):
    return [
        dataclasses.replace(event, hmac_sig=recorder.authority.sign(event))
        for event in (
            Event("commit-fixture", f"original-{index}", details={"index": index})
            for index in range(count)
        )
    ]


class _DatabaseProbe:
    """Delegate to owned SQLite; inject only the selected deterministic fault."""

    def __init__(self, database, error_type=sqlite3.OperationalError):
        self.database = database
        self.error_type = error_type
        self.commits = 0
        self.rollbacks = 0
        self.postcommit_max_queries = 0
        self.reject_postcommit_max = False
        self.max_failures = 0
        self.insert_failures = 0
        self.insert_attempts = 0
        self.delete_failures = 0

    def __getattr__(self, name):
        return getattr(self.database, name)

    def _after_insert(self, statement):
        if statement.startswith("INSERT INTO events "):
            self.insert_attempts += 1
            if self.insert_failures:
                self.insert_failures -= 1
                raise self.error_type("fixture error after uncommitted INSERT")

    def execute(self, statement, *args, **kwargs):
        if statement == "SELECT COALESCE(MAX(id), 0) FROM events" and self.max_failures:
            assert self.database.in_transaction
            self.max_failures -= 1
            raise self.error_type("fixture precommit revision query error")
        if statement == "SELECT COALESCE(MAX(id), 0) FROM events" and self.commits:
            self.postcommit_max_queries += 1
            if self.reject_postcommit_max:
                raise self.error_type("fixture postcommit revision query error")
        cursor = self.database.execute(statement, *args, **kwargs)
        self._after_insert(statement)
        if statement.startswith("DELETE FROM events WHERE id IN ("):
            if self.delete_failures:
                self.delete_failures -= 1
                raise self.error_type("fixture error after maintenance DELETE")
        return cursor

    def executemany(self, statement, *args, **kwargs):
        cursor = self.database.executemany(statement, *args, **kwargs)
        self._after_insert(statement)
        return cursor

    def commit(self):
        self.database.commit()
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1
        self.database.rollback()


def _install_probe(recorder, error_type=sqlite3.OperationalError):
    probe = _DatabaseProbe(recorder._db, error_type)
    recorder._db = probe
    return probe


def _write(recorder, lane, events):
    if lane == "single":
        assert len(events) == 1
        recorder.record_bus(events[0])
        return None
    if lane == "batch":
        return recorder.record_batch_bus(events)
    assert lane == "replay"
    assert recorder._route_batch_to_dlq(events) == len(events)
    return recorder.replay_dlq(max_segments=1)


def _assert_result(result, lane, inserted, duplicates=0):
    if lane == "single":
        assert result is None
    elif lane == "batch":
        assert result == BatchRecordResult(inserted, 0)
    else:
        assert result.processed == inserted + duplicates
        assert result.inserted == inserted
        assert result.duplicates == duplicates
        assert result.quarantined == result.failures == 0
        assert result.segments_completed == 1


def _assert_originals(recorder, events):
    stored = recorder.recent(20)
    assert len(stored) == len(events)
    assert {event.hmac_sig for event in stored} == {
        event.hmac_sig for event in events
    }
    assert all(recorder.authority.verify(event) for event in stored)
    assert recorder.dlq_status()["segments"] == 0
    assert not recorder._db.in_transaction


@pytest.mark.parametrize("lane", ["batch", "replay"])
@pytest.mark.parametrize("error_type", [sqlite3.OperationalError, RuntimeError])
def test_revision_lookup_does_not_fail_after_a_returned_commit(
    recorder, lane, error_type
):
    events = _events(recorder)
    probe = _install_probe(recorder, error_type)
    probe.reject_postcommit_max = True
    delivered = events if lane == "batch" else [*events, events[0]]

    result = _write(recorder, lane, delivered)

    _assert_result(result, lane, len(events), int(lane == "replay"))
    _assert_originals(recorder, events)
    assert recorder.revision() == 2
    # Replay separately commits receipt retirement after segment deletion.
    assert probe.commits == (2 if lane == "replay" else 1)
    assert probe.insert_attempts == 1
    assert probe.postcommit_max_queries == probe.rollbacks == 0


@pytest.mark.parametrize("lane", ["batch", "replay"])
@pytest.mark.parametrize("error_type", [sqlite3.OperationalError, RuntimeError])
def test_revision_lookup_failure_before_commit_rolls_back_before_retry_or_hold(
    recorder, lane, error_type
):
    events = _events(recorder)
    probe = _install_probe(recorder, error_type)
    probe.max_failures = 1

    result = _write(recorder, lane, events)

    assert probe.rollbacks == 1 and not probe.in_transaction
    if error_type is sqlite3.OperationalError:
        _assert_result(result, lane, len(events))
        _assert_originals(recorder, events)
        assert recorder.revision() == 2
        assert probe.insert_attempts == 2
    else:
        assert recorder.recent(20) == []
        assert recorder.revision() == probe.commits == 0
        if lane == "batch":
            assert result == BatchRecordResult(0, len(events))
        else:
            assert result.inserted == result.duplicates == 0
            assert result.segments_completed == 0 and result.failures == 1
            assert probe.execute("SELECT COUNT(*) FROM dlq_replay_receipts").fetchone() == (0,)
        assert recorder.dlq_status()["segments"] == 1


@pytest.mark.parametrize("lane", ["single", "batch", "replay"])
@pytest.mark.parametrize("error_type", [sqlite3.OperationalError, RuntimeError])
def test_failed_postcommit_maintenance_cannot_retry_or_spill_committed_input(
    recorder, monkeypatch, lane, error_type
):
    events = _events(recorder, 1 if lane == "single" else 2)
    probe = _install_probe(recorder)
    monkeypatch.setattr(recorder, "PRUNE_EVERY", 1)
    maintenance_calls = []

    def failed_maintenance():
        # Model an escaping maintenance fault; production pruning also handles
        # its own ordinary errors. The INSERT really committed before this.
        assert not probe.in_transaction
        assert recorder.revision() == len(events)
        probe.execute("DELETE FROM events WHERE message=?", (events[0].message,))
        assert probe.in_transaction
        maintenance_calls.append(True)
        raise error_type("fixture postcommit maintenance failure")

    monkeypatch.setattr(recorder, "_prune_locked", failed_maintenance)
    result = _write(recorder, lane, events)

    _assert_result(result, lane, len(events))
    _assert_originals(recorder, events)
    assert maintenance_calls == [True]
    assert recorder.revision() == len(events)
    assert probe.insert_attempts == probe.rollbacks == 1


@pytest.mark.parametrize("error_type", [sqlite3.OperationalError, RuntimeError])
def test_internally_caught_retention_error_rolls_back_only_maintenance(
    recorder, monkeypatch, error_type
):
    events = _events(recorder)
    probe = _install_probe(recorder, error_type)
    probe.delete_failures = 1
    monkeypatch.setattr(recorder, "MAX_ROWS", 0)
    monkeypatch.setattr(recorder, "PRUNE_EVERY", 1)

    assert recorder.record_batch_bus(events) == BatchRecordResult(2, 0)

    _assert_originals(recorder, events)
    assert recorder.revision() == 2
    assert probe.insert_attempts == probe.commits == probe.rollbacks == 1


@pytest.mark.parametrize("lane", ["single", "batch", "replay"])
@pytest.mark.parametrize(
    ("error_type", "failures", "succeeds"),
    [(sqlite3.OperationalError, 1, True),
     (sqlite3.OperationalError, 3, False), (RuntimeError, 1, False)],
)
def test_precommit_partial_insert_still_rolls_back_and_retries_or_preserves_dlq(
    recorder, lane, error_type, failures, succeeds
):
    events = _events(recorder, 1 if lane == "single" else 2)
    probe = _install_probe(recorder, error_type)
    probe.insert_failures = failures

    result = _write(recorder, lane, events)

    assert probe.rollbacks == failures
    if succeeds:
        _assert_result(result, lane, len(events))
        _assert_originals(recorder, events)
        assert probe.insert_attempts == 2
        assert recorder.revision() == len(events)
    else:
        assert recorder.recent(20) == []
        assert recorder.revision() == probe.commits == 0
        assert not probe.in_transaction
        if lane == "batch":
            assert result == BatchRecordResult(0, len(events))
        elif lane == "replay":
            assert result.inserted == result.duplicates == 0
            assert result.segments_completed == 0 and result.failures == 1
            assert probe.execute("SELECT COUNT(*) FROM dlq_replay_receipts").fetchone() == (0,)
        else:
            assert result is None
        # The fallback/source holds exactly the original signed records.
        paths = recorder._segment_paths_locked(include_quarantine=False)
        assert len(paths) == 1
        payloads = [json.loads(line) for line in paths[0].read_text(
            encoding="utf-8"
        ).splitlines()]
        assert [item["hmac_sig"] for item in payloads] == [
            event.hmac_sig for event in events
        ]
        assert all(recorder._decode_dlq_event(json.dumps(item)) for item in payloads)


@pytest.mark.parametrize("lane", ["single", "batch", "replay"])
@pytest.mark.parametrize("error_type", [sqlite3.OperationalError, RuntimeError])
def test_revision_cache_fault_does_not_reclassify_known_committed_rows(
    recorder, lane, error_type
):
    events = _events(recorder, 1 if lane == "single" else 2)
    probe = _install_probe(recorder)
    real_lock = recorder._revision_lock

    class FailFirstAcquire:
        failed = False

        def __enter__(self):
            if not self.failed:
                self.failed = True
                raise error_type("fixture revision cache fault")
            return real_lock.__enter__()

        def __exit__(self, *args):
            return real_lock.__exit__(*args)

    recorder._revision_lock = FailFirstAcquire()
    result = _write(recorder, lane, events)

    _assert_result(result, lane, len(events))
    _assert_originals(recorder, events)
    assert probe.insert_attempts == 1
    assert recorder.revision() == 0  # Cache publication failed, not the commit.
    followup = Event("commit-fixture", "later-cache-publication")
    recorder.record(followup)
    assert recorder.revision() == len(events) + 1
    assert len(recorder.recent(20)) == len(events) + 1


def test_revision_retains_committed_id_when_retention_removes_the_newest_row(
    recorder, monkeypatch
):
    recorder.record(Event("commit-fixture", "protected", severity=Severity.HIGH))
    monkeypatch.setattr(recorder, "MAX_ROWS", 1)
    monkeypatch.setattr(recorder, "PRUNE_EVERY", 1)

    assert recorder.record_batch_bus(_events(recorder, 1)) == BatchRecordResult(1, 0)

    assert [event.message for event in recorder.recent(20)] == ["protected"]
    assert recorder.revision() == 2
