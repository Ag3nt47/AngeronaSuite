from __future__ import annotations

import queue
from collections import namedtuple

from angerona.modules import memory_timemachine as mtm


class _Proc:
    def __init__(self, pid: int = 731, marker: str = "novel-marker") -> None:
        self.info = {"pid": pid}
        self.marker = marker

    def as_dict(self, attrs):
        return {
            "cmdline": [self.marker],
            "exe": "worker.exe",
            "name": "worker.exe",
            "cwd": "C:/work",
        }

    def connections(self):
        return []


def _install_psutil(monkeypatch, processes) -> None:
    class FakePsutil:
        @staticmethod
        def net_connections(kind):
            assert kind == "inet"
            return []

        @staticmethod
        def process_iter(attrs):
            assert attrs == ["pid"]
            return iter(processes)

    monkeypatch.setattr(mtm, "psutil", FakePsutil())


def test_queue_backpressure_does_not_commit_undelivered_delta(monkeypatch) -> None:
    proc = _Proc(marker="retry-this-observation")
    _install_psutil(monkeypatch, [proc])
    module = mtm.MemoryTimeMachineModule()
    module.delta_queue = queue.Queue(maxsize=1)
    module.delta_queue.put_nowait({"sentinel": True})

    module._sweep()

    assert module._forwarded == 0
    assert module._queue_drops > 0
    assert module.delta_for(proc.info["pid"], [proc.marker], commit=False) == [proc.marker]
    assert module.health <= 40  # no ring plus an explicit delivery gap

    module.delta_queue.get_nowait()
    module._sweep()
    payload = module.delta_queue.get_nowait()

    assert proc.marker in payload["delta"]
    assert module._forwarded > 0
    assert module.delta_for(proc.info["pid"], [proc.marker], commit=False) == []


def test_ring_overwrite_counter_survives_reopen_and_degrades_health(
    tmp_path, monkeypatch
) -> None:
    path = tmp_path / "telemetry.mmap"
    ring = mtm._SpscRing(path, slots=2)
    assert ring.push(b"one")
    assert ring.push(b"two")
    assert not ring.push(b"three")
    assert ring.overwrite_count() == 1
    ring.close()

    reopened = mtm._SpscRing(path, slots=2)
    assert reopened.overwrite_count() == 1
    _install_psutil(monkeypatch, [])
    module = mtm.MemoryTimeMachineModule()
    module._ring = reopened
    module._ring_overwrites = reopened.overwrite_count()
    module._sweep()
    assert module.health <= 70
    assert "overwritten" in module.health_note.lower()
    reopened.close()


def test_environment_collection_never_exposes_values(monkeypatch) -> None:
    Conn = namedtuple("Conn", "pid laddr raddr")

    class Proc(_Proc):
        def open_files(self):
            return []

        def environ(self):
            return {"ANGERONA_SECRET_NAME": "raw-secret-value-should-never-appear"}

        def connections(self):
            return [Conn(self.info["pid"], ("127.0.0.1", 4), ())]

    monkeypatch.setenv("ANGERONA_MTM_OPEN_FILES", "1")
    module = mtm.MemoryTimeMachineModule()
    strings = module._process_strings(Proc())

    rendered = " ".join(strings)
    assert "ENV_KEY:ANGERONA_SECRET_NAME" in rendered
    assert "raw-secret-value-should-never-appear" not in rendered


def test_ring_contains_only_pseudonymous_receipts(tmp_path, monkeypatch) -> None:
    marker = "super-secret-commandline-value"
    proc = _Proc(marker=marker)
    _install_psutil(monkeypatch, [proc])
    path = tmp_path / "telemetry.mmap"
    ring = mtm._SpscRing(path, slots=16)
    module = mtm.MemoryTimeMachineModule()
    module._ring = ring

    module._sweep()
    ring.close()

    mapped = path.read_bytes()
    assert marker.encode() not in mapped
    assert b"731\t" in mapped


def test_missing_ring_health_is_not_overwritten_by_a_clean_sweep(monkeypatch) -> None:
    _install_psutil(monkeypatch, [])
    module = mtm.MemoryTimeMachineModule()
    module.set_health(40, "ring unavailable: denied")

    module._sweep()

    assert module.health <= 40
    assert "ring unavailable" in module.health_note.lower()
