from __future__ import annotations

import os
from pathlib import Path

from angerona.core.eventbus import EventBus
from angerona.core.eventbus import Severity
from angerona.core.module_manager import ModuleManager
from angerona.platforms.linux.observe import LinuxObserveCollector


class _Config:
    module_states: dict[str, bool] = {}

    def save(self) -> None:
        pass


def test_linux_discovery_exposes_rootless_observe_without_windows_imports() -> None:
    manager = ModuleManager(EventBus(), _Config(), target_platform="linux")
    manager.discover()

    assert "Linux Observe Sensor" in manager.modules
    assert "Linux eBPF Sensor" in manager.modules
    assert "macOS Observe Sensor" not in manager.modules
    assert not manager.discovery_errors
    inventory = {row["name"]: row for row in manager.capability_inventory()}
    assert inventory["Linux Observe Sensor"]["available"] is True
    assert inventory["Linux Observe Sensor"]["capability_mode"] == "detect"


def test_linux_observe_baselines_and_emits_only_new_privacy_minimized_state() -> None:
    processes = [{
        "pid": 10,
        "ppid": 1,
        "name": "baseline",
        "executable": "/usr/bin/baseline",
        "create_time": 10.0,
        "uid": 1000,
        "command_line_collected": False,
    }]
    connections = [{
        "pid": 10,
        "local": "10.0.0.2:50000",
        "remote": "203.0.113.7:443",
        "transport": "tcp",
        "status": "established",
    }]
    posture = {"kernel_release": "6.12", "apparmor_enabled": True}
    collector = LinuxObserveCollector(
        lambda: list(processes),
        lambda: list(connections),
        lambda: dict(posture),
        network_every=1,
        posture_every=1,
        clock=lambda: 100.0,
    )
    assert collector.poll() == []

    processes.append({
        "pid": 11,
        "ppid": 10,
        "name": "new-app",
        "executable": "/opt/new-app/bin/new-app",
        "create_time": 20.0,
        "uid": 1000,
        "command_line_collected": False,
    })
    connections.append({
        "pid": 11,
        "local": "10.0.0.2:50001",
        "remote": "198.51.100.8:443",
        "transport": "tcp",
        "status": "established",
    })
    posture["apparmor_enabled"] = False
    events = collector.poll()

    assert {(event.kind, event.action) for event in events} == {
        ("process", "start"),
        ("network", "connect"),
        ("security", "posture_change"),
    }
    process_event = next(event for event in events if event.kind == "process")
    assert process_event.platform == "linux"
    assert process_event.process["command_line_collected"] is False
    assert "command_line" not in process_event.process
    assert "username" not in process_event.process


def test_linux_observe_degrades_when_network_inventory_is_not_permitted() -> None:
    collector = LinuxObserveCollector(
        lambda: [],
        lambda: (_ for _ in ()).throw(PermissionError("denied")),
        lambda: {},
        network_every=1,
    )
    assert collector.poll() == []
    assert collector.degraded_reasons
    assert "network observation unavailable" in collector.degraded_reasons[0]


def test_linux_fast_path_flags_deleted_and_writable_memory_execution() -> None:
    from angerona.core.sensor_events import SensorEvent
    from angerona.modules.linux_observe import LinuxObserveModule

    deleted = SensorEvent(
        platform="linux",
        sensor="angerona.linux.observe",
        kind="process",
        action="start",
        process={"pid": 20, "uid": 1000, "executable": "/opt/tool (deleted)"},
    )
    shared_root = SensorEvent(
        platform="linux",
        sensor="angerona.linux.observe",
        kind="process",
        action="start",
        process={"pid": 21, "uid": 0, "executable": "/dev/shm/payload"},
    )
    normal = SensorEvent(
        platform="linux",
        sensor="angerona.linux.observe",
        kind="process",
        action="start",
        process={"pid": 22, "uid": 1000, "executable": "/usr/bin/bash"},
    )

    assert LinuxObserveModule.classify(deleted)[0] == Severity.HIGH
    assert LinuxObserveModule.classify(shared_root)[0] == Severity.CRITICAL
    assert LinuxObserveModule.classify(normal)[0] == Severity.INFO


def test_linux_uses_private_xdg_state_root(monkeypatch, tmp_path: Path) -> None:
    from angerona.core import data_paths

    state = tmp_path / "state"
    monkeypatch.setattr(data_paths.sys, "platform", "linux")
    monkeypatch.delenv("ANGERONA_DATA", raising=False)
    monkeypatch.setenv("XDG_STATE_HOME", str(state))
    monkeypatch.setattr(data_paths.sys, "frozen", False, raising=False)
    # The suite is executing on Windows while simulating Linux path selection;
    # NTFS does not expose POSIX 0700 mode bits. Linux CI exercises the real
    # hardener through the normal data_dir() fixture.
    monkeypatch.setattr(data_paths, "_harden_posix_data_root", lambda _path: None)
    data_paths._canonical_data_path.cache_clear()
    data_paths._ready_source_roots.clear()

    root = data_paths.data_dir()

    assert root == state / "angerona"
    assert os.environ["ANGERONA_DATA"] == str(root)


def test_linux_secret_store_uses_secret_service_without_a_reference_file(
    monkeypatch,
    tmp_path: Path,
) -> None:
    from angerona.core import secure_store
    from angerona.platforms.linux import secret_service

    stored: dict[str, bytes] = {}
    monkeypatch.setattr(secure_store.sys, "platform", "linux")
    monkeypatch.setattr(
        secret_service,
        "read_blob",
        lambda service, account: stored.get(f"{service}:{account}"),
    )
    monkeypatch.setattr(
        secret_service,
        "write_blob",
        lambda service, account, payload: stored.__setitem__(
            f"{service}:{account}", payload
        ),
    )

    reference = secure_store.write_secret_map({"TEST_LINUX_SECRET": "value"}, tmp_path)

    assert secure_store.read_secret_map(tmp_path) == {"TEST_LINUX_SECRET": "value"}
    assert reference == tmp_path / "secrets.secret-service-reference"
    assert not reference.exists()
    os.environ.pop("TEST_LINUX_SECRET", None)


def test_linux_secret_store_refuses_overwrite_when_keyring_is_locked(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import pytest

    from angerona.core import secure_store
    from angerona.platforms.linux import secret_service

    writes: list[bytes] = []
    monkeypatch.setattr(secure_store.sys, "platform", "linux")
    monkeypatch.setattr(
        secret_service,
        "read_blob",
        lambda _service, _account: (_ for _ in ()).throw(
            secret_service.SecretServiceError("locked")
        ),
    )
    monkeypatch.setattr(
        secret_service,
        "write_blob",
        lambda _service, _account, payload: writes.append(payload),
    )

    with pytest.raises(RuntimeError, match="refusing to overwrite"):
        secure_store.write_secret_map({"TEST_LINUX_SECRET": "replacement"}, tmp_path)
    assert writes == []


def test_secret_tool_receives_secret_on_stdin_never_argv(monkeypatch) -> None:
    import subprocess

    from angerona.platforms.linux import secret_service

    calls: list[tuple[list[str], bytes | None]] = []

    def fake_run(argv, **kwargs):
        calls.append((list(argv), kwargs.get("input")))
        if "lookup" in argv:
            return subprocess.CompletedProcess(argv, 0, stdout=b'{"A":"B"}\n', stderr=b"")
        return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(secret_service.shutil, "which", lambda _name: "/usr/bin/secret-tool")
    monkeypatch.setattr(secret_service.subprocess, "run", fake_run)

    payload = b'{"TOKEN":"not-on-command-line"}'
    secret_service.write_blob("service", "account", payload)
    assert secret_service.read_blob("service", "account") == b'{"A":"B"}'
    assert calls[0][1] == payload
    assert all(payload.decode() not in argument for argument in calls[0][0])


def test_linux_xdg_autostart_round_trip(monkeypatch, tmp_path: Path) -> None:
    from angerona.core import autostart

    monkeypatch.setattr(autostart.sys, "platform", "linux")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setattr(
        autostart,
        "_target_action",
        lambda: ("/opt/Angerona Suite/python", "-m angerona", "/opt/Angerona Suite"),
    )

    assert autostart.enable_autostart() is True
    path = tmp_path / "config" / "autostart" / "angerona.desktop"
    text = path.read_text(encoding="utf-8")
    assert "X-Angerona-Autostart=true" in text
    assert 'Exec="/opt/Angerona Suite/python" "-m" "angerona"' in text
    assert autostart.is_enabled() is True
    assert autostart.disable_autostart() is True
    assert not path.exists()
