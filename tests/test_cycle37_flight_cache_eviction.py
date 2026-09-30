"""The bounded flight cache evicts the exact oldest successful insertion."""
from __future__ import annotations

from angerona.modules.flight_cache import FlightCache, FlightCacheModule


def test_eviction_retains_exact_newest_rows_and_read_visibility() -> None:
    cache = FlightCache(cap=3)
    try:
        for index in range(1, 8):
            cache.put(float(index), "fixture", 20, f"event-{index}", {"index": index})

        assert cache.count() == 3
        assert [row["message"] for row in cache.recent(10)] == [
            "event-7", "event-6", "event-5",
        ]
        assert cache.query("SELECT COUNT(*) AS n FROM events")[0]["n"] == 3
    finally:
        cache.close()


def test_failed_insert_gap_does_not_evict_wrong_row() -> None:
    cache = FlightCache(cap=3)
    try:
        for index in range(1, 4):
            cache.put(float(index), "fixture", 20, f"event-{index}")

        # A failed SQLite insert advances the module's sequence counter. The
        # next successful put must still remove the oldest *stored* row.
        cache._db.execute(
            "CREATE TRIGGER reject_four BEFORE INSERT ON events "
            "WHEN NEW.id = 4 BEGIN SELECT RAISE(ABORT, 'fixture failure'); END"
        )
        cache.put(4.0, "fixture", 20, "rejected")
        cache._db.execute("DROP TRIGGER reject_four")
        cache.put(5.0, "fixture", 20, "event-5")

        assert cache.count() == 3
        assert [row["id"] for row in cache.recent(10)] == [5, 3, 2]
        assert cache.query("SELECT COUNT(*) AS n FROM events")[0]["n"] == 3
    finally:
        cache.close()


def test_module_offline_contract_still_passes() -> None:
    ok, detail = FlightCacheModule().self_test()
    assert ok, detail
