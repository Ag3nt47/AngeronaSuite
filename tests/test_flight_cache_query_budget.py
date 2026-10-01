"""Optional cache queries must release the producer lock after bounded work."""
import pytest
import threading

import angerona.modules.flight_cache as cache_module
from angerona.modules.flight_cache import FlightCache


def test_recursive_query_budget_does_not_poison_later_writes():
    cache = FlightCache(cap=10)
    try:
        with pytest.raises(ValueError, match="SQLite work budget"):
            cache.query(
                "WITH RECURSIVE counter(n) AS (SELECT 1 UNION ALL "
                "SELECT n+1 FROM counter WHERE n<1000000) SELECT sum(n) FROM counter"
            )
        cache.put(1, "fixture", 0, "after interrupted query", {})
        assert cache.query("SELECT message FROM events")[0]["message"] == "after interrupted query"
        assert cache.query("SELECT COUNT(*) AS n FROM events")[0]["n"] == 1
    finally:
        cache.close()


def test_expanding_query_has_visible_row_limit():
    cache = FlightCache(cap=2)
    try:
        cache.put(1, "fixture", 0, "one", {})
        cache.put(2, "fixture", 0, "two", {})
        with pytest.raises(ValueError, match="result-row budget"):
            cache.query("SELECT a.message FROM events a CROSS JOIN events b")
        assert len(cache.recent()) == 2
    finally:
        cache.close()


def test_details_serialization_does_not_hold_cache_lock(monkeypatch):
    cache = FlightCache(cap=2)
    serializing, release, read_done = threading.Event(), threading.Event(), threading.Event()

    def serialize(_details):
        serializing.set()
        assert release.wait(10)
        return "{}"

    monkeypatch.setattr(cache_module.json, "dumps", serialize)
    writer = threading.Thread(target=lambda: cache.put(1, "fixture", 0, "one", {}))

    def read():
        cache.recent()
        read_done.set()

    reader = threading.Thread(target=read)
    writer.start()
    try:
        assert serializing.wait(10)
        reader.start()
        assert read_done.wait(2), "serialization blocked an unrelated cache reader"
    finally:
        release.set()
        writer.join(10)
        if reader.ident is not None:
            reader.join(10)
        cache.close()
    assert not writer.is_alive() and not reader.is_alive()
