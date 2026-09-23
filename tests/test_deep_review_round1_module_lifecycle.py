"""Native-resource-free lifecycle regression fixtures for the deep review."""
from __future__ import annotations

import threading
from types import SimpleNamespace

from angerona.modules import memory_timemachine as mtm


def test_memory_sweep_does_not_admit_late_work_or_write_retired_ring(monkeypatch):
    module = mtm.MemoryTimeMachineModule()
    module.status = "running"
    writes = []
    emitted = []

    class FakeRing:
        closed = False

        def close(self):
            self.closed = True

        def push(self, value):
            writes.append((self.closed, value))
            return True

        def depth(self):
            return len(writes)

        def overwrite_count(self):
            return 0

    ring = FakeRing()
    module._ring = ring
    fake_process = SimpleNamespace(info={"pid": 123456})
    monkeypatch.setattr(mtm, "psutil", SimpleNamespace(
        net_connections=lambda **_kwargs: [],
        process_iter=lambda _fields: iter([fake_process]),
    ))
    monkeypatch.setattr(module, "emit", lambda *args, **kwargs: emitted.append(args))

    def collection_returns_after_stop(_process, _connections):
        module.stop()
        return ["inert late process metadata"]

    monkeypatch.setattr(module, "_process_strings", collection_returns_after_stop)
    module._sweep()
    assert module.stopping
    assert not writes, "retired sweep wrote its already-closed native ring"
    assert module.delta_queue.empty(), "retired sweep admitted a new triage payload"
    assert not emitted, "retired sweep emitted new activity after stop"


def test_memory_closed_ring_observations_and_repeated_close_are_safe(tmp_path):
    ring = mtm._SpscRing(tmp_path / 'ring.mmap', slots=2)
    for _ in range(3):
        ring.push(b'inert receipt')
    module = mtm.MemoryTimeMachineModule()
    module._ring = ring
    ring.close()
    ring.close()
    assert ring.depth() == 0
    assert ring.overwrite_count() == 1
    assert ring.pop() is None
    assert not ring.push(b'late receipt')
    assert module.stats()['ring_available'] is False
    assert module.stats()['ring_depth'] == 0


def test_memory_restart_waits_for_collector_and_retires_only_its_ring(monkeypatch, tmp_path):
    from angerona.core import config

    module = mtm.MemoryTimeMachineModule()
    module._RESTART_JOIN_TIMEOUT = 0.01
    entered, release, second = threading.Event(), threading.Event(), threading.Event()
    rings = []
    original_ring = mtm._SpscRing

    def new_ring(path):
        if rings:
            assert rings[-1]._closed
        ring = original_ring(path, slots=2)
        rings.append(ring)
        if len(rings) == 2:
            second.set()
        return ring

    calls = []

    def collect(*_args):
        calls.append(True)
        if len(calls) == 1:
            entered.set()
            assert release.wait(3)
            return ['inert retired metadata']
        return []

    monkeypatch.setattr(config, 'Config', lambda: SimpleNamespace(data_dir=tmp_path))
    monkeypatch.setattr(mtm, '_SpscRing', new_ring)
    monkeypatch.setattr(mtm, 'psutil', SimpleNamespace(
        net_connections=lambda **_kw: [],
        process_iter=lambda _fields: iter([SimpleNamespace(info={'pid': 424242})]),
    ))
    monkeypatch.setattr(module, '_process_strings', collect)
    monkeypatch.setattr(module, 'emit', lambda *_a, **_kw: None)
    module.start()
    try:
        assert entered.wait(1)
        module.stop()
        assert not rings[0]._closed
        assert module.stats()['ring_available']
        module.start()
        assert len(rings) == 1
        release.set()
        assert second.wait(2)
        assert rings[0]._closed
        assert not rings[1]._closed
        assert module.delta_queue.empty()
        assert module._forwarded == 0
        assert module._caches == {}
    finally:
        release.set()
        module.stop()
        if module._thread:
            module._thread.join(2)
        if module._restart_waiter:
            module._restart_waiter.join(2)
    assert all(ring._closed for ring in rings)
    assert module._ring is None


def test_memory_missing_collector_closes_its_ring(monkeypatch, tmp_path):
    from angerona.core import config

    module = mtm.MemoryTimeMachineModule()
    rings = []
    original_ring = mtm._SpscRing

    def new_ring(path):
        ring = original_ring(path, slots=2)
        rings.append(ring)
        return ring

    monkeypatch.setattr(config, 'Config', lambda: SimpleNamespace(data_dir=tmp_path))
    monkeypatch.setattr(mtm, '_SpscRing', new_ring)
    monkeypatch.setattr(mtm, 'psutil', None)
    module.run()
    assert module.health == 0
    assert module._ring is None
    assert rings[0]._closed
