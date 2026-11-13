from __future__ import annotations

import hashlib
import hmac
import json

import pytest


def test_recovery_state_round_trip_and_tamper_rejection(tmp_path) -> None:
    from angerona.resilience.recovery_state import (
        RecoveryStateError,
        RecoveryStateStore,
    )

    now = [100.0]
    path = tmp_path / "supervisor.json"
    key = bytes(range(32))
    store = RecoveryStateStore(
        "peer-watchdog",
        path=path,
        key=key,
        clock=lambda: now[0],
    )
    store.update_component(
        "core",
        {
            "failures": [90.0, 95.0],
            "safe_mode": True,
            "safe_mode_since": 95.0,
            "next_restart_at": 0.0,
            "last_state": "dead",
            "last_diagnostic_sha256": "a" * 64,
            "state_fault": False,
        },
    )

    restored = RecoveryStateStore(
        "peer-watchdog",
        path=path,
        key=key,
        clock=lambda: now[0],
    ).component("core")
    assert restored["failures"] == [90.0, 95.0]
    assert restored["safe_mode"] is True
    assert restored["last_state"] == "dead"

    document = json.loads(path.read_text(encoding="utf-8"))
    document["components"]["core"]["last_state"] = "alive"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(RecoveryStateError, match="authentication"):
        store.component("core")


def test_dead_component_uses_durable_backoff_before_restart(
    tmp_path, monkeypatch
) -> None:
    from angerona.resilience import diagnostics, shutdown_token, supervisor
    from angerona.resilience.recovery_state import RecoveryStateStore

    now = [100.0]
    key = bytes(range(32))
    monkeypatch.setenv("ANGERONA_DIAG_DIR", str(tmp_path / "diagnostics"))
    monkeypatch.setattr(shutdown_token, "_load_key", lambda: key)
    monkeypatch.setattr(shutdown_token, "is_standdown_requested", lambda: False)
    store = RecoveryStateStore(
        "test-watchdog",
        path=tmp_path / "state.json",
        key=key,
        clock=lambda: now[0],
    )
    sup = supervisor.ProcessSupervisor(
        state_namespace="test-watchdog",
        state_store=store,
        clock=lambda: now[0],
        initial_backoff_s=1.0,
        max_backoff_s=8.0,
    )
    component = sup.add("core", ["core"])
    monkeypatch.setattr(sup, "_pop_restart_requests", lambda: set())
    monkeypatch.setattr(sup, "_assess", lambda _component: "dead")
    launches: list[str] = []
    monkeypatch.setattr(
        sup,
        "_spawn",
        lambda current: launches.append(current.name) or True,
    )

    assert sup.tick()["core"] == "backoff(dead)"
    assert launches == []
    assert component.next_restart_at == 101.0
    assert store.component("core")["next_restart_at"] == 101.0
    assert component.last_diagnostic_sha256

    now[0] = 100.5
    assert sup.tick()["core"] == "backoff(dead)"
    assert launches == []

    now[0] = 101.0
    assert sup.tick()["core"] == "respawned(dead)"
    assert launches == ["core"]
    assert store.component("core")["next_restart_at"] == 0.0

    now[0] = 102.0
    assert sup.tick()["core"] == "backoff(dead)"
    assert component.next_restart_at == 104.0
    assert store.component("core")["failures"] == [100.0, 102.0]
    assert diagnostics.diag_dir().joinpath(
        "recovery_test-watchdog_core.json"
    ).exists()


def test_safe_mode_survives_supervisor_restart_and_manual_reset(
    tmp_path, monkeypatch
) -> None:
    from angerona.resilience import shutdown_token, supervisor
    from angerona.resilience.recovery_state import RecoveryStateStore

    now = [200.0]
    key = bytes(range(32))
    monkeypatch.setenv("ANGERONA_DIAG_DIR", str(tmp_path / "diagnostics"))
    monkeypatch.setattr(shutdown_token, "_load_key", lambda: key)
    monkeypatch.setattr(shutdown_token, "is_standdown_requested", lambda: False)
    state_path = tmp_path / "state.json"

    def new_supervisor():
        store = RecoveryStateStore(
            "peer-watchdog",
            path=state_path,
            key=key,
            clock=lambda: now[0],
        )
        return supervisor.ProcessSupervisor(
            state_namespace="peer-watchdog",
            state_store=store,
            clock=lambda: now[0],
            initial_backoff_s=1.0,
            max_backoff_s=4.0,
        )

    first = new_supervisor()
    component = first.add("core", ["core"], max_failures=2)
    monkeypatch.setattr(first, "_pop_restart_requests", lambda: set())
    monkeypatch.setattr(first, "_assess", lambda _component: "dead")
    monkeypatch.setattr(first, "_spawn", lambda _component: True)

    assert first.tick()["core"] == "backoff(dead)"
    now[0] = 201.0
    assert first.tick()["core"] == "respawned(dead)"
    now[0] = 202.0
    assert first.tick()["core"] == "safe_mode"
    assert component.safe_mode is True

    second = new_supervisor()
    restored = second.add("core", ["core"], max_failures=2)
    assert restored.safe_mode is True
    assert list(restored._failures) == [200.0, 202.0]

    monkeypatch.setattr(second, "_pop_restart_requests", lambda: {"core"})
    monkeypatch.setattr(second, "_capture_recovery_snapshot", lambda *_args: None)
    monkeypatch.setattr(second, "_terminate", lambda _component: True)
    launches: list[str] = []
    monkeypatch.setattr(
        second,
        "_spawn",
        lambda current: launches.append(current.name) or True,
    )
    assert second.tick()["core"] == "manual_restart"
    assert launches == ["core"]
    assert second._state_store.component("core")["safe_mode"] is False


def test_tampered_state_preserves_original_through_budgeted_and_manual_recovery(
    tmp_path, monkeypatch
) -> None:
    from types import SimpleNamespace

    from angerona.resilience import shutdown_token, supervisor
    from angerona.resilience.recovery_state import RecoveryStateError, RecoveryStateStore

    wall, mono = [100.0], [0.0]
    key = bytes(range(32))
    path = tmp_path / "state.json"
    store = RecoveryStateStore("watchdog", path=path, key=key, clock=lambda: wall[0])
    store.clear_component("core")
    tampered = json.loads(path.read_text(encoding="utf-8"))
    tampered["components"]["core"]["last_state"] = "dead"
    path.write_text(json.dumps(tampered), encoding="utf-8")
    original = path.read_bytes()

    class Reader:
        def __init__(self, _name):
            pass

        def read(self):
            return None

    monkeypatch.setenv("ANGERONA_DIAG_DIR", str(tmp_path / "diagnostics"))
    monkeypatch.setattr(shutdown_token, "_load_key", lambda: key)
    monkeypatch.setattr(shutdown_token, "is_standdown_requested", lambda: False)
    monkeypatch.setattr(supervisor.hb, "HeartbeatReader", Reader)
    sup = supervisor.ProcessSupervisor(
        state_namespace="watchdog", state_store=store,
        clock=lambda: wall[0], monotonic_clock=lambda: mono[0],
        initial_backoff_s=1.0, max_backoff_s=8.0,
    )
    notices, launches = [], []
    sup.on_event = lambda level, message, details: notices.append((level, message, details))
    component = sup.add("core", ["core"], max_failures=2, window_s=600.0)
    assert component.safe_mode is False and component.state_fault is True
    assert path.read_bytes() == original

    # Keep real admission/backoff logic, with inert launch and waiter boundaries.
    monkeypatch.setattr(sup, "_pop_restart_requests", lambda: set())
    monkeypatch.setattr(sup, "_assess", lambda _component: "dead")
    monkeypatch.setattr(sup, "_capture_recovery_snapshot", lambda *_args: None)
    monkeypatch.setattr(sup, "_arm_startup", lambda _component: None)
    monkeypatch.setattr(supervisor, "try_claim_spawn", lambda _name: True)
    monkeypatch.setattr(supervisor, "threading", SimpleNamespace(
        Thread=lambda **_kwargs: SimpleNamespace(start=lambda: None)))

    def launch(*_args, **_kwargs):
        launches.append(mono[0])
        return SimpleNamespace(pid=4242, poll=lambda: 0)

    monkeypatch.setattr(supervisor, "spawn_detached", launch)
    assert sup.tick()["core"] == "backoff(durability_gap)"
    assert list(component._failures) == [100.0] and not launches
    wall[0], mono[0] = 159.9, 59.9
    assert sup.tick()["core"] == "backoff(durability_gap)"
    assert not launches and path.read_bytes() == original

    wall[0], mono[0] = 160.0, 60.0
    monkeypatch.setattr(shutdown_token, "is_standdown_requested", lambda: True)
    assert sup.tick()["core"] == "standdown"
    monkeypatch.setattr(shutdown_token, "is_standdown_requested", lambda: False)
    sup.launch_guard = lambda _component: False
    assert sup.tick()["core"] == "source-integrity-held"
    assert not launches and list(component._failures) == [100.0]
    sup.launch_guard = None
    wall[0], mono[0] = 161.0, 61.0
    assert sup.tick()["core"] == "respawned(dead)"
    assert launches == [61.0] and path.read_bytes() == original

    # Failed persistence cannot erase the process-local crash budget either.
    wall[0], mono[0] = 162.0, 62.0
    assert sup.tick()["core"] == "safe_mode"
    assert component.safe_mode and list(component._failures) == [100.0, 162.0]
    assert len(component._pressure) == 2 and launches == [61.0]
    gaps = [details for _level, _message, details in notices
            if details.get("in_memory_recovery_budget") is True]
    assert len(gaps) == 1 and gaps[0]["original_preserved"] is True
    assert gaps[0]["response_authorized"] is False

    # This seam represents a command already admitted by the signed parser.
    monkeypatch.setattr(sup, "_pop_restart_requests", lambda: {"core"})
    monkeypatch.setattr(sup, "_terminate", lambda _component: True)
    assert sup.tick()["core"] == "manual_restart"
    assert launches == [61.0, 62.0] and not component.safe_mode
    assert component.state_fault is True and path.read_bytes() == original
    with pytest.raises(RecoveryStateError, match="authentication"):
        store.component("core")


def test_recovery_snapshot_is_bounded_authenticated_and_path_free(
    tmp_path, monkeypatch
) -> None:
    from angerona.resilience import diagnostics

    key = bytes(range(32))
    monkeypatch.setenv("ANGERONA_DIAG_DIR", str(tmp_path))
    digest = diagnostics.write_recovery_snapshot(
        "Core ../bad",
        "SUSPENDED",
        namespace="Peer Watchdog",
        heartbeat={"pid": 123, "count": 9, "flags": 1, "ts_ns": 0},
        failure_count=2,
        restart_count=4,
        safe_mode=False,
        next_restart_at=123.5,
        key=key,
    )
    path = tmp_path / "recovery_peer-watchdog_core-bad.json"
    raw = path.read_bytes()
    document = json.loads(raw)
    signature = document.pop("hmac_sha256")
    canonical = json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")

    assert digest == hashlib.sha256(raw).hexdigest()
    assert hmac.compare_digest(
        signature,
        hmac.new(key, canonical, hashlib.sha256).hexdigest(),
    )
    assert len(raw) < 16 * 1024
    assert "C:\\" not in raw.decode("utf-8")
    assert "../" not in raw.decode("utf-8")


def test_stopped_component_is_not_restarted(monkeypatch) -> None:
    from angerona.resilience import shutdown_token, supervisor

    monkeypatch.setattr(shutdown_token, "is_standdown_requested", lambda: False)
    sup = supervisor.ProcessSupervisor()
    sup.add("core", ["core"])
    monkeypatch.setattr(sup, "_pop_restart_requests", lambda: set())
    monkeypatch.setattr(sup, "_assess", lambda _component: "stopped")
    launches: list[str] = []
    monkeypatch.setattr(sup, "_spawn", lambda current: launches.append(current.name))

    assert sup.tick()["core"] == "stopped"
    assert launches == []
