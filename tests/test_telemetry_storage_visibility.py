"""Storage holds describe incomplete recording without granting recovery authority."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest

from angerona.core import status_report
from angerona.core.eventbus import EventBus
from angerona.core.runtime_healer import RuntimeHealer
from angerona.core.runtime_metrics import RuntimeMetrics, validate_metrics


def _view(**changes):
    result = dict(schema=1, configured=True, state="held", reason_code="db_target",
        policy_generation=2, facts_generation=2, blocked=False,
        db_target_bytes=256 * 1024**2, wal_target_bytes=64 * 1024**2,
        min_free_bytes=2048 * 1024**2, unit_limit_bytes=1048576,
        db_bytes=257 * 1024**2, wal_bytes=0, shm_bytes=0, free_bytes=4096 * 1024**2,
        facts_observed_monotonic=100.0, facts_age_seconds=0.0, facts_stale=False,
        probe_pending=False, storage_pending_events=3, parked_primary_events=1,
        parked_overflow_events=0, rejection_storage_hold=5, storage_user_discarded=1,
        storage_write_failures=2, storage_hold_attempts=2, replay_deferred=1, maintenance_deferred=1,
        coverage_gap=True, scope="telemetry-writer-only", shared_database=True,
        no_os_quota=True, no_response_reserve=True, durable=False)
    result.update(changes)
    return result


def _no_io(*_args, **_kwargs):
    raise AssertionError("cached storage projection attempted I/O")


def test_storage_projection_copies_whitelist_without_sampling_or_sql(monkeypatch):
    source = _view(private_path="private-fixture", raw_event={"message": "untrusted"})
    original = copy.deepcopy(source)
    storage = SimpleNamespace(storage_budget_snapshot=lambda: source,
                              _db=SimpleNamespace(execute=_no_io))
    with monkeypatch.context() as guard:
        guard.setattr(status_report.time, "time", _no_io)
        guard.setattr(status_report.time, "monotonic", _no_io)
        guard.setattr(status_report.os, "stat", _no_io)
        guard.setattr(Path, "read_bytes", _no_io)
        view = status_report._telemetry_storage_snapshot(storage)
        text = status_report.telemetry_storage_status_text(view)
    assert view["state"] == "held" and view["storage_pending_events"] == 3
    assert "private" not in json.dumps(view) and "raw_event" not in view
    assert "pending=3" in text and "rejected=5" in text and "user_discarded=1" in text
    assert "write_failures=2" in text
    assert "Replay deferral attempts=1" in text and "not current backlog counts" in text
    assert "may be lost on exit" in text and "not a drive quota" in text
    assert source == original
    view["storage_pending_events"] = 99
    assert source == original


@pytest.mark.parametrize("changes", [
    {"schema": True}, {"configured": 1}, {"state": "healthy"},
    {"reason_code": "private-error"}, {"scope": "global"}, {"durable": True},
    {"no_os_quota": False}, {"no_response_reserve": False},
    {"shared_database": False}, {"storage_pending_events": True},
    {"storage_user_discarded": -1}, {"rejection_storage_hold": 1 << 63},
    {"coverage_gap": False}, {"facts_age_seconds": float("nan")},
    {"facts_observed_monotonic": float("inf")}, {"db_bytes": -1},
    {"free_bytes": False}, {"unit_limit_bytes": 2097152},
    {"configured": False}, {"state": "unconfigured"},
    {"state": "ready", "facts_stale": True},
    {"state": "ready", "probe_pending": True},
    {"state": "ready", "facts_generation": 1},
    {"state": "ready", "blocked": True},
    {"state": "ready", "free_bytes": None},
    {"db_target_bytes": None}, {"wal_target_bytes": 1},
    {"min_free_bytes": 511 * 1024**2}, {"facts_generation": 3},
    {"parked_primary_events": 4}, {"state": "ready", "facts_age_seconds": None},
    {"storage_write_failures": True}, {"storage_write_failures": -1},
])
def test_invalid_storage_observation_has_unknown_counts_not_clean_zeros(changes):
    result = status_report._telemetry_storage_view(_view(**changes))
    assert result["state"] == "unavailable"
    assert "storage_pending_events" not in result
    assert "coverage_gap" not in result
    text = status_report.telemetry_storage_status_text(result)
    assert "counts unknown" in text and "pending=0" not in text and "private" not in text


def test_missing_and_failed_readers_remain_unavailable():
    broken = SimpleNamespace(storage_budget_snapshot=lambda: (_ for _ in ()).throw(
        RuntimeError("private-fixture-error")))
    for storage in (None, object(), broken):
        result = status_report._telemetry_storage_snapshot(storage)
        assert result["state"] == "unavailable" and "storage_pending_events" not in result
        assert "private" not in json.dumps(result)


@pytest.mark.parametrize("key", ["db_bytes", "facts_age_seconds", "coverage_gap",
                                  "state", "rejection_storage_hold"])
def test_incomplete_dto_does_not_pass_missing_fields_as_nullable_facts(key):
    source = _view()
    del source[key]
    result = status_report._telemetry_storage_view(source)
    assert result["state"] == "unavailable" and "storage_pending_events" not in result


def test_ready_view_preserves_separate_latched_gap_and_pending_memory():
    view = status_report._telemetry_storage_view(_view(state="ready", reason_code="",
                                                      db_bytes=40 * 1024**2))
    assert view["state"] == "ready" and view["storage_pending_events"] == 3
    assert view["coverage_gap"] is True and view["storage_user_discarded"] == 1
    text = status_report.telemetry_storage_status_text(view)
    assert "Zero gaps do not prove complete history" in text


def test_capacity_recovery_does_not_clear_failed_recording_gap():
    view = status_report._telemetry_storage_view(_view(state="ready", reason_code="",
        db_bytes=40 * 1024**2, storage_pending_events=0, parked_primary_events=0,
        rejection_storage_hold=0, storage_user_discarded=0, storage_write_failures=1))
    assert view["state"] == "ready" and view["coverage_gap"] is True
    assert view["storage_pending_events"] == 0 and view["storage_write_failures"] == 1
    assert "write_failures=1" in status_report.telemetry_storage_status_text(view)
    view["coverage_gap"] = False
    assert "storage_write_failures" not in status_report._telemetry_storage_view(view)


def test_unconfigured_library_is_explicitly_unenforced_and_no_sample_unknown():
    result = status_report._telemetry_storage_view(_view(configured=False,
        state="unconfigured", reason_code="unconfigured", policy_generation=0,
        facts_generation=0, db_target_bytes=None, wal_target_bytes=None,
        min_free_bytes=None, db_bytes=None, wal_bytes=None, shm_bytes=None,
        free_bytes=None, facts_observed_monotonic=None, facts_age_seconds=None,
        facts_stale=True, storage_pending_events=0, parked_primary_events=0,
        rejection_storage_hold=0, storage_user_discarded=0, storage_write_failures=0, coverage_gap=False))
    assert result["configured"] is False and result["state"] == "unconfigured"
    assert result["free_bytes"] is None and result["facts_age_seconds"] is None


def test_status_json_and_text_include_cached_hold_without_raw_details(tmp_path, monkeypatch):
    source = _view()
    storage = SimpleNamespace(count_since=lambda _since: 0,
                              storage_budget_snapshot=lambda: source)
    monkeypatch.setattr(status_report, "_optional_audit_snapshot", lambda: None)
    reporter = status_report.StatusReporter(EventBus(), storage,
        SimpleNamespace(modules={}, is_enabled=lambda _name: False),
        SimpleNamespace(data_dir=tmp_path, runtime_chill_active=True,
                        ollama_host="local", ollama_model="fixture"))
    assert reporter._write(force=True)
    value = json.loads((tmp_path / "diagnostics/status.json").read_text())
    assert value["telemetry_storage"]["storage_pending_events"] == 3
    text = (tmp_path / "diagnostics/status.txt").read_text()
    assert "Telemetry storage: held" in text and "pending=3" in text
    assert "guaranteed response reserve" in text


def test_healthy_parked_workers_are_evidence_not_restart_authorization():
    repairs = []
    health = dict(healthy=True, stopping=False, worker_alive=True, dlq_worker_alive=True,
        storage_held=True, storage_policy_generation=2, storage_pending_events=3,
        rejection_storage_hold=5, storage_user_discarded=1, storage_write_failures=2, coverage_gap=True)
    service = SimpleNamespace(recovery_snapshot=lambda: health,
                              recover=lambda: repairs.append("unexpected"))
    healer = RuntimeHealer(service, service, EventBus(),
        SimpleNamespace(runtime_chill_active=False), clock=lambda: 100.0)
    for _ in range(4):
        healer.run_once()
    result = healer.snapshot()["components"]["flight_recorder"]
    assert result["state"] == "healthy" and not repairs
    assert result["evidence"]["storage_held"] is True
    assert result["evidence"]["storage_pending_events"] == 3
    assert result["evidence"]["storage_user_discarded"] == 1
    assert result["evidence"]["storage_write_failures"] == 2


def test_runtime_drop_total_counts_explicit_discards_once_not_hold_subset_twice():
    queue = SimpleNamespace(qsize=lambda: 0, maxsize=4)
    recorder = SimpleNamespace(_metrics_lock=threading.Lock(), _queue=queue,
        _overflow_queue=queue, _dlq_failures=2, _admission_rejected=3,
        _rejection_storage_hold=3, _storage_user_discarded=4)
    metrics = RuntimeMetrics(gui=False, recorder=recorder,
                             clock=lambda: 100.0, wall_clock=lambda: 200.0)
    view = metrics.snapshot()
    assert view["dropped_events"] == 9 and view["queues"][1]["dropped"] == 0
    assert "explicit volatile-event discards" in view["drop_scope"]
    validate_metrics(view, pid=metrics.pid, process_started_at=metrics.process_started_at,
                     now=200.0)
