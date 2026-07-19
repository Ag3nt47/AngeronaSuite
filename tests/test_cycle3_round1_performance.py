from __future__ import annotations

import threading
import time
from collections import namedtuple

from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity


def test_eventbus_subscription_is_idempotent_and_recent_is_exact() -> None:
    bus = EventBus(ring_size=500)

    class Sink:
        def __init__(self) -> None:
            self.events = []

        def on_event(self, event) -> None:
            self.events.append(event)

    sink = Sink()
    for _ in range(20):
        bus.subscribe(sink.on_event)
    for i in range(500):
        bus.publish(Event("test", str(i), ts=float(i)))

    assert len(sink.events) == 500
    assert [event.message for event in bus.recent(3)] == ["499", "498", "497"]
    # Preserve the pre-existing edge semantics for external callers.
    assert len(bus.recent(0)) == 500
    assert len(bus.recent(-2)) == 498


def test_dashboard_reads_use_a_separate_zero_wait_connection(tmp_path, monkeypatch) -> None:
    from angerona.core import storage

    authority = BusAuthority(b"x" * 32)
    monkeypatch.setattr(
        storage.BusAuthority, "load", classmethod(lambda cls: authority)
    )
    recorder = storage.FlightRecorder(tmp_path / "events.db")
    try:
        recorder.record(Event("test", "one", Severity.HIGH, ts=10.0))
        assert recorder._ui_db.execute("PRAGMA busy_timeout").fetchone()[0] == 0

        # Preserve the existing writer-busy contract: skip immediately.
        with recorder._lock:
            rows = recorder.try_recent(10)
            count = recorder.try_count_since(0.0)
        assert rows is None and count is None

        rows = recorder.try_recent(10)
        count = recorder.try_count_since(0.0)
        assert rows is not None and [row.message for row in rows] == ["one"]
        assert count == 1

        # Contention on the UI connection itself is a skip, not a wait.
        assert recorder._ui_lock.acquire(blocking=False)
        started = time.perf_counter()
        try:
            assert recorder.try_recent(10) is None
            assert recorder.try_count_since(0.0) is None
        finally:
            recorder._ui_lock.release()
        assert time.perf_counter() - started < 0.05
    finally:
        recorder.close()


def test_memory_time_machine_uses_one_equivalent_connection_snapshot(monkeypatch) -> None:
    from angerona.modules import memory_timemachine as mtm

    Conn = namedtuple("Conn", "pid laddr raddr")

    class Proc:
        def __init__(self, pid: int, connections: list) -> None:
            self.info = {"pid": pid}
            self._connections = connections
            self.connection_calls = 0

        def as_dict(self, attrs):
            return {"cmdline": [f"worker-{self.info['pid']}"], "exe": "worker.exe",
                    "name": "worker.exe", "cwd": "C:/work"}

        def connections(self):
            self.connection_calls += 1
            return self._connections

    c1 = Conn(101, ("127.0.0.1", 1001), ("1.1.1.1", 443))
    c2 = Conn(202, ("127.0.0.1", 1002), ("8.8.8.8", 53))
    procs = [Proc(101, [c1]), Proc(202, [c2])]

    class FakePsutil:
        def __init__(self) -> None:
            self.bulk_calls = 0

        def net_connections(self, kind):
            assert kind == "inet"
            self.bulk_calls += 1
            return [c1, c2]

        def process_iter(self, attrs):
            assert attrs == ["pid"]
            return iter(procs)

    fake = FakePsutil()
    monkeypatch.setattr(mtm, "psutil", fake)
    module = mtm.MemoryTimeMachineModule()
    module._sweep()

    assert fake.bulk_calls == 1
    assert [proc.connection_calls for proc in procs] == [0, 0]
    payloads = [module.delta_queue.get_nowait(), module.delta_queue.get_nowait()]
    assert {payload["pid"] for payload in payloads} == {101, 202}
    rendered = {text for payload in payloads for text in payload["delta"]}
    assert str(c1.laddr) in " ".join(rendered)
    assert str(c2.raddr) in " ".join(rendered)


def test_memory_time_machine_falls_back_when_bulk_rows_are_unattributed(monkeypatch) -> None:
    from angerona.modules import memory_timemachine as mtm

    Conn = namedtuple("Conn", "pid laddr raddr")
    attributed = Conn(101, ("127.0.0.1", 1001), ("1.1.1.1", 443))
    unattributed = Conn(None, ("0.0.0.0", 0), ("2.2.2.2", 443))

    class Proc:
        info = {"pid": 101}
        calls = 0

        def as_dict(self, attrs):
            return {"cmdline": ["worker"], "exe": "worker.exe",
                    "name": "worker.exe", "cwd": "C:/work"}

        def connections(self):
            self.calls += 1
            return [attributed]

    proc = Proc()

    class FakePsutil:
        @staticmethod
        def net_connections(kind):
            return [unattributed]

        @staticmethod
        def process_iter(attrs):
            return iter([proc])

    monkeypatch.setattr(mtm, "psutil", FakePsutil())
    module = mtm.MemoryTimeMachineModule()
    module._sweep()

    assert proc.calls == 1
    payload = module.delta_queue.get_nowait()
    assert str(attributed.raddr) in " ".join(payload["delta"])


def test_speculative_cooldown_state_expires_without_changing_live_cooldowns(monkeypatch) -> None:
    from angerona.modules import speculative_triage as spec

    module = spec.SpeculativeTriageModule()
    module._last_prewarm = {1: 1.0, 2: 95.0}
    module._last_cooldown_cleanup = 1.0
    monkeypatch.setattr(spec.time, "time", lambda: 100.0)

    assert module.speculate({"pid": 3, "message": "marker"})
    assert 1 not in module._last_prewarm
    assert module._last_prewarm[2] == 95.0
    assert not module.speculate({"pid": 2, "message": "still cooling"})


def test_cancelled_eco_wakeup_cannot_start_a_later_module() -> None:
    from angerona.core.eco_wakeup import EcoWakeupWorker
    from angerona.core.module_base import BaseModule

    entered = threading.Event()
    release = threading.Event()
    started: list[str] = []

    class SlowStart(BaseModule):
        name = "first"

        def start(self, initial_delay: float = 0.0) -> None:
            started.append(self.name)
            entered.set()
            assert release.wait(1.0)
            super().start(initial_delay)

        def run(self) -> None:
            while not self.stopping:
                self.sleep(0.01)

    class Later(SlowStart):
        name = "second"

    first, second = SlowStart(), Later()
    worker = EcoWakeupWorker([first, second], health_timeout=1.0, min_settle=0.0)
    runner = threading.Thread(target=worker.run)
    runner.start()
    assert entered.wait(1.0)

    cancelled = threading.Event()
    cancel_thread = threading.Thread(target=lambda: (worker.cancel(), cancelled.set()))
    cancel_thread.start()
    time.sleep(0.02)
    assert not cancelled.is_set()  # cancel is serialized with the active start
    release.set()
    cancel_thread.join(1.0)
    runner.join(1.0)
    try:
        assert cancelled.is_set()
        assert started == ["first"]
    finally:
        first.stop()
        second.stop()
