from __future__ import annotations

from angerona.modules.etw_realtime_sensor import _PidNameCache


def test_etw_pid_name_cache_is_bounded_and_retains_active_parents(monkeypatch) -> None:
    monkeypatch.setattr(_PidNameCache, "_seed", lambda self: None)
    cache = _PidNameCache(max_entries=3)

    cache.set(1, "parent.exe")
    cache.set(2, "child-2.exe")
    cache.set(3, "child-3.exe")
    assert cache.get(1) == "parent.exe"  # mark the active parent most-recent

    cache.set(4, "child-4.exe")
    assert len(cache._map) == 3
    assert list(cache._map) == [3, 1, 4]
    assert cache.get(1) == "parent.exe"
    assert 2 not in cache._map


def test_etw_pid_name_cache_refreshes_reused_pid(monkeypatch) -> None:
    monkeypatch.setattr(_PidNameCache, "_seed", lambda self: None)
    cache = _PidNameCache(max_entries=2)
    cache.set(42, "old.exe")
    cache.set(42, "new.exe")
    assert cache.get(42) == "new.exe"
    assert len(cache._map) == 1
