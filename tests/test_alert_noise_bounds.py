from __future__ import annotations

from angerona.modules import forensics, packet_sniffer


def test_forensic_hold_alert_is_rate_limited_per_reason(monkeypatch):
    module = forensics.ForensicsModule()
    events, health = [], []
    monkeypatch.setattr(module, "emit", lambda *a, **k: events.append((a, k)))
    monkeypatch.setattr(module, "set_health", lambda *a, **k: health.append(a))
    clock = [100.0]
    monkeypatch.setattr(forensics.time, "monotonic", lambda: clock[0])

    module._held("not active")
    module._held("not active")
    module._held("not active")
    module._held("delivery gap")
    assert len(events) == 2
    # Health still reflects every hold, including the suppressed repeats.
    assert len(health) == 4

    clock[0] += forensics._HELD_REPEAT_S + 1
    module._held("not active")
    assert len(events) == 3
    assert events[-1][1]["repeats_since_last_report"] == 2
    assert events[-1][1]["response_authorized"] is False


def test_forensic_hold_dedup_state_is_bounded(monkeypatch):
    module = forensics.ForensicsModule()
    monkeypatch.setattr(module, "emit", lambda *a, **k: None)
    monkeypatch.setattr(module, "set_health", lambda *a, **k: None)
    for index in range(forensics._HELD_KEYS_MAX * 3):
        module._held(f"reason {index}")
    assert len(module._held_recent) <= forensics._HELD_KEYS_MAX


def test_packet_sniffer_budgets_cover_one_whole_capture_cycle():
    window = packet_sniffer._CAPTURE_WINDOW_SECONDS
    assert packet_sniffer._WORKER_HARD_DEADLINE >= window + 30.0
    module = packet_sniffer.PacketSnifferModule
    assert module.startup_cycle_timeout > packet_sniffer._WORKER_HARD_DEADLINE
    assert module.watchdog_work_budget_seconds > packet_sniffer._WORKER_HARD_DEADLINE
    assert module.startup_cycle_timeout <= 300.0
