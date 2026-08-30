from __future__ import annotations


def test_network_state_prunes_closed_sockets_and_expired_pid_identities(monkeypatch):
    from angerona.modules import network_monitor

    module = network_monitor.NetworkMonitorModule()
    now = 10_000.0
    active = (10, "203.0.113.10:443")
    closed = (11, "203.0.113.11:443")
    module._seen = {active, closed}
    module._known_pid_hosts = {
        (10, "203.0.113.10"): now,
        (11, "203.0.113.11"): now - network_monitor.NOVELTY_WINDOW_S - 1,
    }
    module._known_hosts = {
        "203.0.113.10": now,
        "203.0.113.11": now - network_monitor.NOVELTY_WINDOW_S * 2 - 1,
    }

    module._prune_state({active}, now)

    assert module._seen == {active}
    assert (10, "203.0.113.10") in module._known_pid_hosts
    assert (11, "203.0.113.11") not in module._known_pid_hosts
    assert "203.0.113.11" not in module._known_hosts


def test_network_recent_state_has_a_hard_cap():
    from angerona.modules import network_monitor

    values = {f"host-{index}": float(index) for index in range(30)}
    trimmed = network_monitor.NetworkMonitorModule._trim_recent(values, maximum=7)

    assert len(trimmed) == 7
    assert min(trimmed.values()) == 23.0


def test_forensics_distinguishes_pid_reuse_and_bounds_history(monkeypatch):
    from angerona.modules import forensics

    module = forensics.ForensicsModule()
    monkeypatch.setattr(
        module,
        "_process_identity",
        lambda pid, details: (pid, float(details["create_time"])),
    )
    assert module._capture_needed(42, {"create_time": 1}, now=100.0)
    assert not module._capture_needed(42, {"create_time": 1}, now=101.0)
    assert module._capture_needed(42, {"create_time": 2}, now=102.0)

    module._captured = {
        (index, float(index)): float(index)
        for index in range(forensics._CAPTURE_MAX + 50)
    }
    module._capture_needed(99_999, {"create_time": 3}, now=20_000.0)
    assert len(module._captured) <= forensics._CAPTURE_MAX + 1


def test_heal_snapshot_scan_is_bounded_to_current_regular_candidates(tmp_path):
    from angerona.modules.self_healer import SelfHealer

    module = SelfHealer()
    (tmp_path / "keep.json").write_text("{}", encoding="utf-8")
    (tmp_path / "new.json").write_text("{}", encoding="utf-8")

    candidates, overflow = module._snapshot_candidates(tmp_path)

    assert [path.name for path in candidates] == ["keep.json", "new.json"]
    assert overflow is False
