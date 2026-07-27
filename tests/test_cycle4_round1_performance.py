from __future__ import annotations

import os
import tempfile
import time
import unittest
from pathlib import Path

from angerona.core.attack_tracker import AttackTracker, TechniqueHeat
from angerona.core.eventbus import Event, EventBus, Severity
from angerona.core.status_report import StatusReporter
from angerona.modules.compliance_mapper import ComplianceMapperModule
from angerona.modules.self_healer import SelfHealer


class _Manager:
    modules: dict = {}

    @staticmethod
    def is_enabled(_name: str) -> bool:
        return True


class _Storage:
    @staticmethod
    def count_since(_cutoff: float) -> int:
        return 0


class _Config:
    data_dir = "."
    ollama_host = "http://127.0.0.1:11434"
    ollama_model = "test"


class _CountingBus(EventBus):
    def __init__(self) -> None:
        super().__init__()
        self.recent_calls: list[int] = []

    def recent(self, limit: int = 100):
        self.recent_calls.append(limit)
        return super().recent(limit)


class Cycle4Round1PerformanceTests(unittest.TestCase):
    def test_attack_tracker_retention_is_bounded_and_order_preserved(self) -> None:
        cell = TechniqueHeat("T1059", "Shell", "TA0002", "Command Shell")
        for i in range(250):
            cell.record(f"event-{i}")
        self.assertEqual(len(cell.event_ids), 100)
        self.assertEqual(list(cell.event_ids), [f"event-{i}" for i in range(150, 250)])

        tracker = AttackTracker()
        tracker._cells["T1059"] = cell
        self.assertEqual(
            tracker.snapshot()["matrix"]["T1059"]["event_ids"],
            [f"event-{i}" for i in range(240, 250)],
        )

    def test_compliance_history_keeps_exact_last_2000_without_slice(self) -> None:
        module = ComplianceMapperModule()
        module._incidents.extend({"i": i} for i in range(2_105))
        self.assertEqual(len(module._incidents), 2_000)
        self.assertEqual(module._incidents[0], {"i": 105})
        self.assertEqual(module._incidents[-1], {"i": 2_104})

    def test_self_healer_skips_unchanged_directory_and_finds_new_file_once(self) -> None:
        healer = SelfHealer()
        with tempfile.TemporaryDirectory() as tmp:
            snap_dir = Path(tmp)
            (snap_dir / "old.json").write_text("{}", encoding="utf-8")
            healer._prime_snapshot_dir(snap_dir)
            self.assertEqual(healer._new_snapshots(snap_dir), [])

            before = snap_dir.stat().st_mtime_ns
            fresh = snap_dir / "fresh.json"
            fresh.write_text("{}", encoding="utf-8")
            # Filesystems with coarse metadata timestamps still get a
            # deterministic invalidation in the test.
            if snap_dir.stat().st_mtime_ns == before:
                forced = max(time.time_ns(), before + 1_000_000_000)
                os.utime(snap_dir, ns=(forced, forced))

            self.assertEqual(healer._new_snapshots(snap_dir), [fresh])
            self.assertEqual(healer._new_snapshots(snap_dir), [])

    def test_status_report_reuses_one_consistent_bus_snapshot(self) -> None:
        bus = _CountingBus()
        for i in range(75):
            bus.publish(Event("test", f"event-{i}", Severity.INFO, ts=float(i + 1)))
        reporter = StatusReporter(bus, _Storage(), _Manager(), _Config())
        snapshot = reporter._snapshot()
        self.assertEqual(bus.recent_calls, [200])
        self.assertEqual(len(snapshot["recent_events"]), 60)
        self.assertEqual(snapshot["recent_events"][0]["message"], "event-74")


if __name__ == "__main__":
    unittest.main()
