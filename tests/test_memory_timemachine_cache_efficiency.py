"""Bounded inert sweeps cover MTM cache saturation and delivery semantics."""
from __future__ import annotations

import queue
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from angerona.modules import memory_timemachine as mtm


def _sweep_fixture(monkeypatch, rows):
    module = mtm.MemoryTimeMachineModule()
    monkeypatch.setattr(mtm, "psutil", SimpleNamespace(
        net_connections=lambda **_: [],
        process_iter=lambda _attrs: iter(SimpleNamespace(info={"pid": pid}) for pid in rows),
    ))
    monkeypatch.setattr(module, "_process_strings", lambda proc, _connections: rows[proc.info["pid"]])
    # No OS collectors, bus, or ring are opened in these fixtures.
    monkeypatch.setattr(module, "set_health", lambda *_args: None)
    return module


@pytest.mark.parametrize("count", [256, 257, 512])
def test_unchanged_full_process_sweeps_do_not_thrash_at_257_pids(monkeypatch, count):
    rows = {pid: ["unchanged-image.exe", "unchanged-command", "unchanged-directory"]
            for pid in range(1, count + 1)}
    module = _sweep_fixture(monkeypatch, rows)
    forwarded = []
    for _ in range(3):
        before = module._forwarded
        module._sweep()
        forwarded.append(module._forwarded - before)
    assert forwarded == [count * 3, 0, 0]
    assert module.delta_queue.qsize() == count
    assert module._cached_fingerprints == count * 3
    # Changed and newly arriving evidence must still be admitted immediately.
    rows[1].append("new evidence")
    rows[count + 1] = ["new process evidence"]
    module._sweep()
    assert module._forwarded == count * 3 + 2


def test_pid_window_and_aggregate_fingerprint_budgets_remain_bounded(monkeypatch):
    module = mtm.MemoryTimeMachineModule()
    monkeypatch.setattr(module, "_MAX_PIDS", 8)
    monkeypatch.setattr(module, "_WINDOW", 4)
    monkeypatch.setattr(module, "_MAX_FINGERPRINTS", 12)
    for pid in range(32):
        assert module.delta_for(pid, [f"observation {index}" for index in range(9)])
        assert len(module._caches) <= 8
        assert all(len(window) <= 4 for window in module._caches.values())
        assert module._cached_fingerprints == sum(map(len, module._caches.values()))
        assert module._cached_fingerprints <= 12
        assert all(set(window) == module._cache_sets[key] for key, window in module._caches.items())
    assert module.delta_for(0, ["observation 8"]) == ["observation 8"]  # eviction loses suppression only


def test_repeated_observations_do_not_copy_or_rewrite_committed_cache(monkeypatch):
    module = mtm.MemoryTimeMachineModule()
    module.delta_for(1, [f"value-{index}" for index in range(4096)])

    def forbidden_copy(*_args, **_kwargs):
        raise AssertionError("unchanged sweep copied its historical window")

    monkeypatch.setattr(mtm, "deque", forbidden_copy)
    assert module.delta_for(1, ["value-40", "value-4095"], commit=False) == []
    assert module.delta_for(1, ["value-40", "value-4095"]) == []
    assert module._cached_fingerprints == 4096


def test_long_strings_commit_original_identity_only_after_queue_admission(monkeypatch):
    original = "long-command-" + "x" * 6000
    module = _sweep_fixture(monkeypatch, {1: [original]})
    module.delta_queue = queue.Queue(maxsize=1)
    module.delta_queue.put_nowait({"sentinel": True})
    module._sweep()
    assert module._cached_fingerprints == 0
    assert module.delta_for(1, [original], commit=False) == [original]
    module.delta_queue.get_nowait()
    module._sweep()
    admitted = module.delta_queue.get_nowait()["delta"]
    assert len(admitted) == 1
    assert len(admitted[0].encode()) <= module._MAX_STRING_BYTES
    assert "truncated sha256=" in admitted[0]
    assert original not in admitted
    module._sweep()
    assert module.delta_queue.empty()
    assert module._forwarded == 1
    assert module._cached_fingerprints == 1


def test_partial_chunk_backpressure_retries_only_unadmitted_originals(monkeypatch):
    originals = [f"command-{index}-" + "x" * 6000 for index in range(3)]
    module = _sweep_fixture(monkeypatch, {1: originals})
    monkeypatch.setattr(module, "_MAX_DELTA_STRINGS", 1)
    module.delta_queue = queue.Queue(maxsize=1)
    for expected in range(3):
        module._sweep()
        payload = module.delta_queue.get_nowait()
        assert payload["delta"][0].startswith(f"command-{expected}-")
        assert module.delta_for(1, originals, commit=False) == originals[expected + 1:]
    module._sweep()
    assert module.delta_queue.empty()
    assert module._forwarded == 3


def test_concurrent_cache_updates_preserve_accounting_and_selftest_cleanup(monkeypatch):
    module = mtm.MemoryTimeMachineModule()
    monkeypatch.setattr(module, "_MAX_PIDS", 32)
    monkeypatch.setattr(module, "_MAX_FINGERPRINTS", 128)
    with ThreadPoolExecutor(max_workers=4) as workers:
        list(workers.map(lambda index: module.delta_for(index % 40, [f"string-{index}"]), range(400)))
    assert module._cached_fingerprints == sum(map(len, module._caches.values()))
    assert module._cached_fingerprints <= 128
    assert len(module._caches) <= 32
    assert module.self_test()[0]
    assert module._cached_fingerprints == sum(map(len, module._caches.values()))
    assert -1 not in module._caches


def test_completed_inventory_retires_exited_pids_and_readmits_reused_pid(monkeypatch):
    rows = {1: ["same-image.exe"], 2: ["other-image.exe"]}
    module = _sweep_fixture(monkeypatch, rows)
    module._sweep()
    assert module._cached_fingerprints == 2
    del rows[1]
    module._sweep()
    assert set(module._caches) == {2}
    assert module._cached_fingerprints == 1
    rows[1] = ["same-image.exe"]
    module._sweep()
    assert module._forwarded == 3
    assert module._cached_fingerprints == 2


@pytest.mark.parametrize("failure", ["iterator", "invalid_pid", "stopped"])
def test_incomplete_inventory_does_not_retire_unseen_cached_pids(monkeypatch, failure):
    module = _sweep_fixture(monkeypatch, {1: ["first-image"], 2: ["second-image"]})
    module._sweep()

    def incomplete_inventory(_attrs):
        yield SimpleNamespace(info={"pid": 1})
        if failure == "iterator":
            raise RuntimeError("incomplete process inventory")
        if failure == "invalid_pid":
            yield SimpleNamespace(info={"pid": None})
        else:
            module.generation_stop_event().set()

    monkeypatch.setattr(mtm.psutil, "process_iter", incomplete_inventory)
    module._sweep()
    assert set(module._caches) == {1, 2}
    assert module._cached_fingerprints == 2


def test_completed_inventory_during_selftest_preserves_its_synthetic_cache(monkeypatch):
    module = _sweep_fixture(monkeypatch, {})
    delta_for = module.delta_for
    first_observation = True

    def interleaved_delta(pid, strings, **kwargs):
        nonlocal first_observation
        result = delta_for(pid, strings, **kwargs)
        if first_observation:
            first_observation = False
            module._sweep()
        return result

    monkeypatch.setattr(module, "delta_for", interleaved_delta)
    assert module.self_test()[0]
    assert module._cached_fingerprints == 0
    assert not module._caches
