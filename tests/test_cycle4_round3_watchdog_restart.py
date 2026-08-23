from __future__ import annotations

import json
import sys
import time
from types import SimpleNamespace


def test_watchdog_allows_busy_core_heartbeat_jitter() -> None:
    from angerona.resilience import manager, watchdog

    assert watchdog._CORE_STALE_AFTER_SECONDS >= 10.0
    assert watchdog._SCANNER_STALE_AFTER_SECONDS >= 8.0
    assert manager._WATCHDOG_STALE_AFTER_SECONDS >= 8.0


def test_watchdog_recovers_an_invalidated_heartbeat(monkeypatch) -> None:
    from angerona.resilience import watchdog

    calls = []

    class BrokenWriter:
        def beat(self):
            calls.append("broken-beat")
            raise ValueError("mapping closed")

        def close(self):
            calls.append("broken-close")

    class ReplacementWriter:
        def __init__(self, name, token_raw=b""):
            calls.append((name, token_raw))

        def beat(self):
            calls.append("replacement-beat")

    monkeypatch.setattr(watchdog.hb, "HeartbeatWriter", ReplacementWriter)

    replacement = watchdog._refresh_heartbeat(BrokenWriter(), b"token")

    assert isinstance(replacement, ReplacementWriter)
    assert calls == [
        "broken-beat",
        "broken-close",
        ("watchdog", b"token"),
        "replacement-beat",
    ]


def test_watchdog_ignores_unverifiable_standdown_without_crashing(monkeypatch) -> None:
    from angerona.resilience import watchdog

    statuses = []
    monkeypatch.setattr(
        watchdog.tok,
        "is_standdown_requested",
        lambda: (_ for _ in ()).throw(RuntimeError("unreadable authority")),
    )
    monkeypatch.setattr(
        watchdog.diag,
        "write_status",
        lambda *args: statuses.append(args) or True,
    )

    assert watchdog._standdown_requested() is False
    assert statuses[0][1] == "degraded"


def test_dead_heartbeat_pid_bypasses_live_process_grace(
    tmp_path, monkeypatch
) -> None:
    from angerona.resilience import heartbeat

    path = tmp_path / "core.hb"
    writer = heartbeat.HeartbeatWriter("core", path=path)
    reader = heartbeat.HeartbeatReader("core", path=path)
    assert reader.classify(stale_after_s=12.0) == "alive"
    monkeypatch.setattr(heartbeat, "pid_alive", lambda _pid: False)
    reader._prev_change_ts = time.time()

    assert reader.classify(stale_after_s=12.0) == "dead"
    writer.close()


def test_core_restart_uses_a_target_specific_authenticated_inbox(
    tmp_path, monkeypatch
):
    from angerona.resilience import heartbeat, shutdown_token, supervisor

    key = bytes(range(32))
    monkeypatch.setattr(heartbeat, "_data_dir", lambda: tmp_path)
    monkeypatch.setattr(shutdown_token, "_load_key", lambda: key)

    paths = supervisor.request_restart("core")

    assert paths == [tmp_path / "ipc" / "restart.core.cmd"]
    payload = json.loads(paths[0].read_text(encoding="utf-8"))
    assert payload["targets"] == ["core"]
    assert len(payload["sig"]) == 64


def test_unrelated_supervisor_cannot_consume_the_core_restart(
    tmp_path, monkeypatch
):
    from angerona.resilience import heartbeat, shutdown_token, supervisor

    monkeypatch.setattr(heartbeat, "_data_dir", lambda: tmp_path)
    monkeypatch.setattr(shutdown_token, "_load_key", lambda: bytes(range(32)))
    [core_command] = supervisor.request_restart("core")

    core_side = supervisor.ProcessSupervisor()
    core_side.add("scanner", ["scanner"])
    assert core_side._pop_restart_requests() == set()
    assert core_command.exists()

    watchdog_side = supervisor.ProcessSupervisor()
    watchdog_side.add("core", ["core"])
    assert watchdog_side._pop_restart_requests() == {"core"}
    assert not core_command.exists()


def test_manual_core_restart_clears_safe_mode_and_respawns(
    tmp_path, monkeypatch
):
    from angerona.resilience import heartbeat, shutdown_token, supervisor

    monkeypatch.setattr(heartbeat, "_data_dir", lambda: tmp_path)
    monkeypatch.setattr(shutdown_token, "_load_key", lambda: bytes(range(32)))
    sup = supervisor.ProcessSupervisor()
    component = sup.add("core", ["core"])
    component.safe_mode = True
    component._failures.extend([1.0, 2.0, 3.0])
    calls = []
    monkeypatch.setattr(
        sup,
        "_terminate",
        lambda current: calls.append(("stop", current.name)) or True,
    )
    monkeypatch.setattr(sup, "_spawn", lambda current: calls.append(("start", current.name)))

    supervisor.request_restart("core")
    actions = sup.tick()

    assert actions["core"] == "manual_restart"
    assert component.safe_mode is False
    assert list(component._failures) == []
    assert calls == [("stop", "core"), ("start", "core")]


def test_manual_restart_does_not_spawn_when_safe_termination_fails(
    tmp_path, monkeypatch
) -> None:
    from angerona.resilience import heartbeat, shutdown_token, supervisor

    monkeypatch.setattr(heartbeat, "_data_dir", lambda: tmp_path)
    monkeypatch.setattr(shutdown_token, "_load_key", lambda: bytes(range(32)))
    sup = supervisor.ProcessSupervisor()
    sup.add("core", ["core"])
    calls = []
    monkeypatch.setattr(sup, "_terminate", lambda current: False)
    monkeypatch.setattr(sup, "_spawn", lambda current: calls.append(current.name))

    supervisor.request_restart("core")
    actions = sup.tick()

    assert actions["core"] == "manual_restart_failed"
    assert calls == []


def test_dead_core_is_automatically_respawned_by_watchdog(monkeypatch) -> None:
    from angerona.resilience import shutdown_token, supervisor

    monkeypatch.setattr(shutdown_token, "is_standdown_requested", lambda: False)
    now = [100.0]
    sup = supervisor.ProcessSupervisor(clock=lambda: now[0])
    component = sup.add("core", ["core"])
    calls = []
    monkeypatch.setattr(sup, "_pop_restart_requests", lambda: set())
    monkeypatch.setattr(sup, "_assess", lambda current: "dead")
    monkeypatch.setattr(sup, "_register_failure", lambda current: False)
    monkeypatch.setattr(sup, "_capture_recovery_snapshot", lambda *_args: None)
    monkeypatch.setattr(
        sup,
        "_spawn",
        lambda current: calls.append(current.name) or True,
    )

    first = sup.tick()
    now[0] = component.next_restart_at
    actions = sup.tick()

    assert first["core"] == "backoff(dead)"
    assert actions["core"] == "respawned(dead)"
    assert calls == ["core"]
    assert component.safe_mode is False


def test_adopted_core_is_terminated_by_verified_heartbeat_identity(
    monkeypatch
) -> None:
    from angerona.resilience import heartbeat, supervisor

    expected = str(__import__("pathlib").Path(sys.executable).resolve())
    calls = []

    class FakeProcess:
        def exe(self):
            return expected

        def cmdline(self):
            return [expected, "-m", "angerona"]

        def terminate(self):
            calls.append("terminate")

        def wait(self, timeout):
            calls.append(("wait", timeout))

        def kill(self):
            calls.append("kill")

    monkeypatch.setitem(
        sys.modules,
        "psutil",
        SimpleNamespace(Process=lambda pid: FakeProcess()),
    )
    monkeypatch.setattr(heartbeat, "pid_alive", lambda pid: pid == 4242)
    sup = supervisor.ProcessSupervisor()
    component = sup.add("core", [expected, "-m", "angerona"])
    component.proc = None
    component.reader = SimpleNamespace(read=lambda: {"pid": 4242})

    assert sup._terminate(component)
    assert calls == ["terminate", ("wait", 3)]
    assert component._dead is True


def test_watchdog_window_exposes_core_restart_control() -> None:
    from pathlib import Path

    source = Path(
        "src/angerona/resilience/status_ui.py"
    ).read_text(encoding="utf-8")
    assert 'QPushButton("Restart Angerona Core")' in source
    assert 'self._request_restart("core", "Angerona Core")' in source
