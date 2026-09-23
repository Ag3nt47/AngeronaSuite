from contextlib import nullcontext
from types import SimpleNamespace
import sys

import pytest

from angerona.core.operational_slo import (
    PerformanceBudget, ProcessTreeSampler, RuntimeSample, SoakEvidence,
)


class Process:
    def __init__(self, pid, *, cpu=1.0, writes=100):
        self.pid = pid
        self.cpu = cpu
        self.writes = writes
        self.birth = float(pid)
        self.running = True
        self.descendants = []

    def create_time(self):
        return self.birth

    def is_running(self):
        return self.running

    def children(self, recursive):
        assert recursive
        return self.descendants

    def oneshot(self):
        return nullcontext()

    def memory_info(self):
        return SimpleNamespace(rss=1024 * 1024)

    def num_threads(self):
        return 2

    def num_fds(self):
        return 3

    def cpu_times(self):
        return SimpleNamespace(user=self.cpu, system=0.0)

    def io_counters(self):
        return SimpleNamespace(read_bytes=50, write_bytes=self.writes)


def _sampler(monkeypatch, *roots):
    registry = {proc.pid: proc for proc in roots}
    monkeypatch.setitem(sys.modules, "psutil", SimpleNamespace(
        Process=registry.__getitem__, cpu_count=lambda: 4,
    ))
    return ProcessTreeSampler(roots[0].pid, additional_pids=tuple(registry)[1:])


def test_trees_deduplicate_roots_preserve_departed_cpu_io_and_unix_fds(monkeypatch):
    root, child = Process(1), Process(2, cpu=3, writes=300)
    root.descendants = [child]
    sampler = _sampler(monkeypatch, root, child)
    first = sampler.sample()
    assert first.process_count == 2 and first.rss_mb == 2
    assert first.threads == 4 and first.handles == 6
    assert first.cpu_seconds == 4 and first.write_bytes == 400
    assert first.resource_unknowns == ()

    # A separately specified root exiting terminates coverage; it is never
    # silently dropped or rebound to a later process with the same PID.
    child.running = False
    with pytest.raises(RuntimeError, match="original process root"):
        sampler.sample()


def test_child_exit_and_pid_reuse_keep_cumulative_counters(monkeypatch):
    root, child = Process(1), Process(2, cpu=3, writes=300)
    root.descendants = [child]
    sampler = _sampler(monkeypatch, root)
    assert sampler.sample().cpu_seconds == 4
    root.descendants = []
    root.cpu = 2
    assert sampler.sample().cpu_seconds == 5
    replacement = Process(2, cpu=2, writes=200)
    replacement.birth = 2000.0
    root.descendants = [replacement]
    final = sampler.sample()
    assert final.cpu_seconds == 7 and final.write_bytes == 600


def test_temporarily_missing_child_does_not_double_count_its_lifetime(monkeypatch):
    root, child = Process(1), Process(2, cpu=10)
    root.descendants = [child]
    sampler = _sampler(monkeypatch, root)
    assert sampler.sample().cpu_seconds == 11
    root.descendants = []
    assert sampler.sample().cpu_seconds == 11
    root.descendants = [child]
    child.cpu = 11
    assert sampler.sample().cpu_seconds == 12


def test_unavailable_io_is_explicit_unknown_and_cannot_pass_soak(monkeypatch):
    root = Process(1)
    root.io_counters = lambda: (_ for _ in ()).throw(PermissionError())
    sampler = _sampler(monkeypatch, root)
    evidence = SoakEvidence(PerformanceBudget())
    first = sampler.sample()
    evidence.add(first)
    evidence.add(sampler.sample())
    assert first.write_bytes is None and first.read_bytes is None
    assert not evidence.evaluate().passed
    assert "process disk I/O counters incomplete" in evidence.evaluate().unknowns


def test_cpu_io_budgets_and_resource_peaks_survive_sample_eviction():
    evidence = SoakEvidence(PerformanceBudget(
        max_rss_growth_mb=10, max_dropped_events=10, max_write_mb_per_second=1,
    ), max_samples=2)
    def sample(t, rss, drops, cpu, writes):
        return RuntimeSample(t, rss, 1, 1, 0, dropped_events=drops,
                             cpu_seconds=cpu, write_bytes=writes, logical_cpus=4)
    evidence.add(sample(0, 1, 0, 0, 0))
    evidence.add(sample(1, 100, 3, 4, 2 * 1024 * 1024))
    evidence.add(sample(2, 1, 0, 4, 2 * 1024 * 1024))
    evidence.add(sample(3, 1, 2, 8, 2 * 1024 * 1024))
    result = evidence.evaluate()
    assert not result.passed
    assert result.indicators["rss_growth_mb"] == 99
    assert result.indicators["dropped_events_delta"] == 5
    assert result.indicators["max_write_mb_per_second"] == 2
    assert result.indicators["p95_cpu_percent"] == 100
    assert result.unknowns == ("dropped-event counter reset 1 time(s)",)


def test_identity_change_during_measurement_withholds_counters(monkeypatch):
    root, child = Process(1), Process(2, cpu=100)
    root.descendants = [child]
    sampler = _sampler(monkeypatch, root)
    def changed():
        child.running = False
        return SimpleNamespace(read_bytes=1000, write_bytes=1000)
    child.io_counters = changed
    result = sampler.sample()
    assert result.process_count == 1 and result.cpu_seconds == 1
    assert "process resource collection incomplete" in result.resource_unknowns
