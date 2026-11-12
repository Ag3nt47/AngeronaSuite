from __future__ import annotations

import os

from angerona.core import uiwatchdog


class _Ticks:
    """Let the watcher loop run a fixed number of samples."""

    def __init__(self, count: int) -> None:
        self.left = count

    def wait(self, _timeout: float) -> bool:
        self.left -= 1
        return self.left < 0

    def set(self) -> None:
        self.left = -1


def _sample(watchdog, monkeypatch, *, now: float, samples: int = 1):
    dumps = []
    monkeypatch.setattr(uiwatchdog.time, "monotonic", lambda: now)
    monkeypatch.setattr(
        watchdog, "_dump",
        lambda age, **_kw: dumps.append((age, watchdog._reported_threshold)) or True,
    )
    watchdog._stop = _Ticks(samples)
    watchdog._run()
    return dumps


def test_startup_budget_applies_only_before_the_first_beat(tmp_path, monkeypatch):
    watchdog = uiwatchdog.UiWatchdog(
        tmp_path / "n.log", stall_seconds=5.0, startup_stall_seconds=45.0
    )
    watchdog._last_beat = 0.0
    # Ten seconds of window construction is inside the startup budget.
    assert _sample(watchdog, monkeypatch, now=10.0) == []
    # A startup that never reaches its first beat is still reported (the
    # 60-second minimum dump interval also applies from process start).
    assert _sample(watchdog, monkeypatch, now=70.0) == [(70.0, 45.0)]


def test_first_beat_restores_the_ordinary_threshold(tmp_path, monkeypatch):
    watchdog = uiwatchdog.UiWatchdog(
        tmp_path / "n.log", stall_seconds=5.0, startup_stall_seconds=45.0
    )
    monkeypatch.setattr(uiwatchdog.time, "monotonic", lambda: 100.0)
    watchdog.beat()
    assert _sample(watchdog, monkeypatch, now=170.0) == [(70.0, 5.0)]


def test_default_keeps_one_threshold_and_budget_never_shrinks_it(tmp_path, monkeypatch):
    plain = uiwatchdog.UiWatchdog(tmp_path / "a.log", stall_seconds=5.0)
    plain._last_beat = 0.0
    assert _sample(plain, monkeypatch, now=70.0) == [(70.0, 5.0)]
    clamped = uiwatchdog.UiWatchdog(
        tmp_path / "b.log", stall_seconds=5.0, startup_stall_seconds=1.0
    )
    assert clamped.startup_stall_seconds == 5.0


def test_ollama_startup_budget_is_bounded(monkeypatch):
    from angerona.core.ollama_lifecycle import configured_startup_timeout

    monkeypatch.delenv("ANGERONA_OLLAMA_STARTUP_SECONDS", raising=False)
    assert configured_startup_timeout() == 90.0
    for raw, expected in (("120", 120.0), ("9999", 120.0), ("1", 30.0),
                          ("nan", 90.0), ("abc", 90.0), ("", 90.0)):
        monkeypatch.setenv("ANGERONA_OLLAMA_STARTUP_SECONDS", raw)
        assert configured_startup_timeout() == expected
    assert os.environ["ANGERONA_OLLAMA_STARTUP_SECONDS"] == ""
