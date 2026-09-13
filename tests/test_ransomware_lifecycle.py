"""Synthetic filename and disposable-file checks; no live profile scans."""
from __future__ import annotations

import os
from pathlib import Path
import random
from threading import Event
from types import SimpleNamespace

import pytest

from angerona.core.eventbus import EventBus, Severity
from angerona.modules import ransomware_heuristics as ransomware
from angerona.modules.watchdog_monitor import WatchdogMonitor


def _reference_pairs(disappeared, appeared):
    available = set(appeared)
    result = []
    for old in sorted(disappeared):
        folded, stem = old.casefold(), Path(old).stem.casefold()
        match = next((new for new in sorted(available) if (
            new.casefold().startswith(folded + ".")
            or folded.startswith(new.casefold() + ".")
            or (stem and Path(new).stem.casefold() == stem)
        )), None)
        if match is not None:
            available.remove(match)
            result.append((old, match))
    return result


def test_indexed_pairing_preserves_exact_greedy_reference():
    rng = random.Random(27)
    names = {
        "", ".", "..", ".hidden", ".hidden.txt", "a", "a.", "a..",
        "A.TXT", "a.txt", "a.txt.locked", "a.txt.locked.more", "A.locked",
        "b.txt", "b.bin", "b", "Straße.txt", "STRASSE.bin", "STRASSE.TXT.locked",
    }
    names.update(f"{stem}.{suffix}" for stem in ("a", "A", "b", "c", "x.y")
                 for suffix in ("txt", "bin", "locked", "txt.locked"))
    names = sorted(names)
    for _ in range(150):
        old = set(rng.sample(names, rng.randrange(len(names))))
        new = set(rng.sample(names, rng.randrange(len(names))))
        assert ransomware._rename_pairs(old, new) == _reference_pairs(old, new)


def test_disjoint_pairing_normalizes_each_name_once():
    calls = []

    class Name(str):
        def casefold(self):
            calls.append(1)
            return super().casefold()

    old = {Name(f"old-{n:05d}.txt") for n in range(1000)}
    new = {Name(f"new-{n:05d}.locked") for n in range(1000)}
    assert ransomware._rename_pairs(old, new) == []
    assert len(calls) == 2000


def test_pairing_stops_without_returning_a_partial_pair_set():
    with pytest.raises(ransomware._ScanCancelled):
        ransomware._rename_pairs({"a.txt"}, {"a.txt.locked"}, should_stop=lambda: True)


@pytest.fixture
def module(tmp_path):
    sensor = ransomware.RansomwareHeuristicsModule()
    sensor._change_state_root = tmp_path / "state"
    sensor.bind(EventBus())
    return sensor


def test_chunk_cancellation_never_returns_an_incomplete_proof(monkeypatch):
    cancelled = [False]
    reads = []

    def read(_fd, size):
        reads.append(size)
        cancelled[0] = True
        return b"A" * size

    monkeypatch.setattr(ransomware, "os", SimpleNamespace(
        lseek=lambda *_: None, read=read, SEEK_SET=os.SEEK_SET,
    ))
    with pytest.raises(ransomware._ScanCancelled):
        ransomware.RansomwareHeuristicsModule._read_content_sample(
            123, ((0, 131072),), complete=True, should_stop=lambda: cancelled[0],
        )
    assert reads == [65536]


def test_cancelled_candidate_verification_closes_holds_without_alert(module, tmp_path, monkeypatch):
    root = tmp_path / "watched"
    root.mkdir()
    (root / "sample.bin").write_bytes(bytes(range(256)) * 32)
    candidates, _, _ = module._scan_root(root, 1000.0)
    assert len(candidates) == 1
    verify = module._verify_held_candidate_sample
    held = []

    def cancel_after_verify(*args):
        result = verify(*args)
        held.append(result[1])
        module.stop()
        return result

    monkeypatch.setattr(module, "_verify_held_candidate_sample", cancel_after_verify)
    with pytest.raises(ransomware._ScanCancelled):
        module._evaluate_entropy(candidates, 1000.0)
    assert module._bus.recent(10) == []
    assert not module._flagged
    assert not module.first_cycle_complete
    with pytest.raises(OSError):
        os.fstat(held[0])


class _CancelAtPublication:
    def __init__(self, stopped):
        self.stopped = stopped

    def __enter__(self):
        self.stopped.set()

    def __exit__(self, *_args):
        return False


def test_stop_at_entropy_publication_does_not_consume_cooldown(module, tmp_path, monkeypatch):
    root = tmp_path / "watched"
    root.mkdir()
    (root / "sample.bin").write_bytes(bytes(range(256)) * 32)
    candidates, _, _ = module._scan_root(root, 1000.0)
    monkeypatch.setattr(module, "_lifecycle_lock", _CancelAtPublication(module._stop))
    with pytest.raises(ransomware._ScanCancelled):
        module._evaluate_entropy(candidates, 1000.0)
    assert module._flagged == {}
    assert module._bus.recent(10) == []


def test_stop_at_storm_publication_does_not_consume_rename_evidence(module, tmp_path, monkeypatch):
    directory = module._directory_key(tmp_path)
    module._rename_times.extend([(1000.0, directory)] * ransomware.RENAME_THRESHOLD)
    module._rename_evidence.append((1000.0, directory, "old", "new"))
    monkeypatch.setattr(module, "_lifecycle_lock", _CancelAtPublication(module._stop))
    module._check_rename_rate(1000.0)
    assert len(module._rename_times) == ransomware.RENAME_THRESHOLD
    assert len(module._rename_evidence) == 1
    assert module._bus.recent(10) == []


def test_stop_after_wait_does_not_start_another_tick(module, monkeypatch):
    monkeypatch.setattr(module, "_load_change_state", lambda: None)
    monkeypatch.setattr(module, "_commit_change_cycle", lambda **_: None)
    monkeypatch.setattr(ransomware, "_default_watch_dirs", lambda: [])
    before_stop = []

    def sleep(_seconds, *, cycle_complete):
        assert cycle_complete is False
        before_stop.append(module._cycle_count)
        module.stop()

    monkeypatch.setattr(module, "sleep", sleep)
    monkeypatch.setattr(module, "_tick", lambda: pytest.fail("post-stop tick"))
    module.run()
    assert module._cycle_count == before_stop[0]


def test_cancelled_root_does_not_commit_publish_or_correlate(module, tmp_path, monkeypatch):
    module._watch_dirs = [tmp_path]

    def scan(*_):
        module.stop()
        return [], {}, module._empty_coverage()

    monkeypatch.setattr(module, "_scan_root", scan)
    monkeypatch.setattr(module, "_commit_change_cycle", lambda **_: pytest.fail("late commit"))
    monkeypatch.setattr(module, "_check_rename_rate", lambda *_: pytest.fail("late response correlation"))
    module._tick()
    assert not module.first_cycle_complete


def test_cancelled_evaluation_does_not_commit_or_correlate(module, tmp_path, monkeypatch):
    module._watch_dirs = [tmp_path]
    monkeypatch.setattr(module, "_scan_root", lambda *_: ([object()], {}, module._empty_coverage()))
    monkeypatch.setattr(module, "_evaluate_entropy", lambda *_: module.stop() or 0)
    monkeypatch.setattr(module, "_commit_change_cycle", lambda **_: pytest.fail("late commit"))
    monkeypatch.setattr(module, "_check_rename_rate", lambda *_: pytest.fail("late response correlation"))
    module._tick()
    assert module._cycle_count == 1  # completed root, never the cancelled evaluation
    assert module._coverage["pending_phase"]
    assert module._coverage["complete"] is False


def test_cancelled_commit_does_not_acquire_writer_lease(module, monkeypatch):
    module.stop()
    monkeypatch.setattr(module, "_change_writer_lease", lambda: pytest.fail("late writer lease"))
    with pytest.raises(ransomware._ScanCancelled):
        module._commit_change_cycle(complete=True)


def _prepared_commit(module, monkeypatch):
    module._change_cycle_active = True
    monkeypatch.setattr(module, "_read_change_witness", lambda: (0, 0, "0" * 64))
    monkeypatch.setattr(module, "_change_state_document", lambda *_a, **_k: ("a" * 64, b"fixture"))


def test_stop_during_preparation_prevents_durable_transition(module, monkeypatch):
    _prepared_commit(module, monkeypatch)
    monkeypatch.setattr(module, "_change_state_document", lambda *_a, **_k: module.stop() or ("a" * 64, b"fixture"))
    monkeypatch.setattr(module, "_write_change_transition", lambda **_: pytest.fail("late durable transaction"))
    with pytest.raises(ransomware._ScanCancelled):
        module._commit_change_cycle_under_lease(complete=False)


def test_already_started_transaction_finishes_coherently_after_stop(module, monkeypatch):
    _prepared_commit(module, monkeypatch)
    phases = []

    def transition(**_):
        phases.append("transition")
        module.stop()

    monkeypatch.setattr(module, "_write_change_transition", transition)
    monkeypatch.setattr(module, "_write_change_state", lambda *_a, **_k: phases.append("state") or "a" * 64)
    monkeypatch.setattr(module, "_write_change_witness", lambda *_: phases.append("witness"))
    monkeypatch.setattr(module, "_remove_change_transition", lambda: phases.append("remove"))
    module._commit_change_cycle_under_lease(complete=False)
    assert phases == ["transition", "state", "witness", "remove"]
    assert module._change_scan_epoch == 1
    assert module._bus.recent(10) == []
    assert not module.first_cycle_complete


def test_obsolete_generation_cannot_publish_or_commit(module):
    stopped = module._stop
    module._run_context.stop_event = stopped
    module._stop = Event()
    old_health = module.health
    module.emit("late", Severity.HIGH)
    module.set_health(0, "late")
    assert not module._publish_progress(module._empty_coverage(), stopped)
    with pytest.raises(ransomware._ScanCancelled):
        module._commit_change_cycle(complete=True)
    assert module._bus.recent(10) == []
    assert module.health == old_health
    assert not module.first_cycle_complete


@pytest.mark.parametrize("fault,roots,truncated,expected", [
    ("invalid witness", 1, 0, 60), ("", 0, 0, 50), ("", 1, 1, 65),
])
def test_progress_preserves_stronger_coverage_degradation(module, fault, roots, truncated, expected):
    module._change_state_fault = fault
    coverage = module._empty_coverage()
    coverage.update(roots=roots, truncated=truncated)
    assert module._publish_progress(coverage, module._stop, "candidate verification")
    assert module.health == expected
    assert "pending=" in module.health_note
    assert not module._coverage["complete"]


def test_completed_root_progress_prevents_whole_sweep_deadline(module, monkeypatch):
    now = [100.0]
    monkeypatch.setattr(ransomware.time, "monotonic", lambda: now[0])
    module._watch_dirs = [Path(f"fixture-{n}") for n in range(3)]
    module._thread = SimpleNamespace(is_alive=lambda: True)
    module.status = "running"
    module._generation_started_at = now[0]
    module._watchdog_deadline_at = 130.0
    pending = []

    def scan(*_):
        now[0] += 20.0
        assert WatchdogMonitor._module_fault(module.operational_snapshot()) is None
        if module.first_cycle_complete:
            pending.append(module.coverage_snapshot())
        coverage = module._empty_coverage()
        coverage["roots"] = 1
        return [], {}, coverage

    monkeypatch.setattr(module, "_scan_root", scan)
    monkeypatch.setattr(module, "_commit_change_cycle", lambda **_: None)
    module._tick()
    assert now[0] == 160.0
    assert module._cycle_count == 4
    assert all(item["pending_phase"] and not item["complete"] for item in pending)
    assert module._coverage["complete"] is True
    assert WatchdogMonitor._module_fault(module.operational_snapshot()) is None
    now[0] += 31.0
    assert "deadline missed" in WatchdogMonitor._module_fault(module.operational_snapshot())
