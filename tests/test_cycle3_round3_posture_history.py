"""Round-3 gates for the non-blocking ARIA posture-history HUD path."""
from __future__ import annotations

import tempfile
import threading
import time
import unittest
from pathlib import Path

from angerona.core.posture_history import PostureHistory, _HUD_CACHE_KEYS


class PostureHistoryHudTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.history = PostureHistory(str(Path(self._tmp.name) / "posture.db"))
        base = 1_000_000.0
        for i in range(240):
            self.history.record((i * 7) % 101, ts=base + i)
        self.history.flush()

    def tearDown(self) -> None:
        self.history.close()
        self._tmp.cleanup()

    def test_sparkline_matches_original_downsample_contract(self) -> None:
        points = self.history.downsample(32)
        blocks = "▁▂▃▄▅▆▇█"
        lo = min(point.score for point in points)
        hi = max(point.score for point in points)
        span = (hi - lo) or 1
        expected = "".join(
            blocks[min(7, (point.score - lo) * 7 // span)] for point in points
        )
        self.assertEqual(self.history.sparkline(32), expected)

    def test_busy_ui_snapshot_returns_cached_values_immediately(self) -> None:
        spark = self.history.sparkline(32)
        trend = self.history.trend(86_400.0)

        self.assertTrue(self.history._ui_lock.acquire(timeout=1.0))
        try:
            started = time.perf_counter()
            self.assertEqual(self.history.sparkline(32), spark)
            self.assertEqual(self.history.trend(86_400.0), trend)
            elapsed = time.perf_counter() - started
        finally:
            self.history._ui_lock.release()

        self.assertLess(elapsed, 0.025)

    def test_writer_lock_never_blocks_hud_reads(self) -> None:
        expected = self.history.sparkline(32)
        self.assertTrue(self.history._lock.acquire(timeout=1.0))
        try:
            started = time.perf_counter()
            actual = self.history.sparkline(32)
            elapsed = time.perf_counter() - started
        finally:
            self.history._lock.release()

        self.assertEqual(actual, expected)
        self.assertLess(elapsed, 0.200)

    def test_cache_is_bounded_and_width_edges_are_safe(self) -> None:
        self.assertEqual(self.history.sparkline(0), "")
        self.assertEqual(self.history.sparkline(-4), "")
        for width in range(1, _HUD_CACHE_KEYS * 3):
            self.assertLessEqual(len(self.history.sparkline(width)), width)
        self.assertLessEqual(len(self.history._spark_cache), _HUD_CACHE_KEYS)

    def test_parallel_record_and_hud_reads_are_thread_safe(self) -> None:
        failures: list[BaseException] = []

        def reader() -> None:
            try:
                for _ in range(100):
                    self.assertLessEqual(len(self.history.sparkline(32)), 32)
                    self.assertIn(
                        self.history.trend(3600.0)["direction"],
                        {"up", "down", "flat", "n/a"},
                    )
            except BaseException as exc:  # captured and asserted on main thread
                failures.append(exc)

        readers = [threading.Thread(target=reader) for _ in range(6)]
        for thread in readers:
            thread.start()
        for i in range(400):
            self.history.record(i % 101)
        for thread in readers:
            thread.join(timeout=5.0)
            self.assertFalse(thread.is_alive())
        self.history.flush()
        self.assertFalse(failures, failures)
        self.assertEqual(self.history.count(), 640)


if __name__ == "__main__":
    unittest.main()
