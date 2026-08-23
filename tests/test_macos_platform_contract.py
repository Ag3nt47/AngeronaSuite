from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from angerona.core.eventbus import EventBus
from angerona.core.module_base import BaseModule
from angerona.core.module_manager import ModuleManager
from angerona.core.platforms import declared_platforms_from_source, normalize_platform
from angerona.core.sensor_events import SensorEvent, SensorEventError
from angerona.platforms.macos.native_bridge import (
    AuthenticatedNativeBridge,
    NativeBridgeError,
    encode_for_test,
)
from angerona.platforms.macos.observe import MacOSObserveCollector


class _Config:
    module_states: dict[str, bool] = {}

    def save(self) -> None:
        pass


def test_platform_names_and_legacy_modules_fail_closed(tmp_path: Path) -> None:
    assert normalize_platform("darwin") == "macos"
    assert normalize_platform("win32") == "windows"
    legacy = tmp_path / "legacy.py"
    legacy.write_text("VALUE = 1\n", encoding="utf-8")
    portable = tmp_path / "portable.py"
    portable.write_text(
        "SUPPORTED_PLATFORMS = ('windows', 'macos')\n",
        encoding="utf-8",
    )
    assert declared_platforms_from_source(legacy) == frozenset({"windows"})
    assert declared_platforms_from_source(portable) == frozenset(
        {"windows", "macos"}
    )


def test_module_manager_never_starts_an_unavailable_capability(
    monkeypatch, tmp_path: Path,
) -> None:
    starts: list[str] = []

    class WindowsOnly(BaseModule):
        name = "Windows only"

        def start(self, initial_delay: float = 0.0) -> None:
            starts.append(self.name)

        def self_test(self) -> tuple[bool, str]:
            raise AssertionError("an unavailable capability must not be exercised")

        def run(self) -> None:
            return

    class MacObserve(BaseModule):
        name = "Mac observe"
        supported_platforms = ("macos",)
        capability_mode = "observe"

        def start(self, initial_delay: float = 0.0) -> None:
            starts.append(self.name)

        def run(self) -> None:
            return

    manager = ModuleManager(EventBus(), _Config(), target_platform="darwin")
    windows = WindowsOnly()
    mac = MacObserve()
    windows.bind(manager.bus)
    mac.bind(manager.bus)
    manager.modules = {windows.name: windows, mac.name: mac}

    manager.start_enabled(sequential_cycles=False, min_settle=0)

    assert starts == ["Mac observe"]
    assert manager.is_enabled("Windows only") is False
    rows = {row["name"]: row for row in manager.capability_inventory()}
    assert rows["Windows only"]["available"] is False
    assert rows["Mac observe"]["available"] is True
    assert rows["Mac observe"]["capability_mode"] == "observe"

    class MacDisabled(MacObserve):
        name = "Mac disabled"

        def self_test(self) -> tuple[bool, str]:
            raise AssertionError("an operator-disabled capability must not run")

    class MacChillPaused(MacObserve):
        name = "Mac Chill paused"

        def self_test(self) -> tuple[bool, str]:
            raise AssertionError("a Chill-paused capability must not run")

    disabled = MacDisabled()
    chill_paused = MacChillPaused()
    for module in (disabled, chill_paused):
        module.bind(manager.bus)
    chill_paused._chill_paused = True
    manager.modules.update({
        disabled.name: disabled,
        chill_paused.name: chill_paused,
    })
    manager.config.module_states = {disabled.name: False}

    # The dashboard self-test must preserve the same availability contract:
    # non-native capabilities are expected skips, never Critical failures or
    # candidates for the GUI's automatic repair action.
    from angerona.core.selftest import SelfTestRunner

    import angerona.core.selftest as selftest_module
    runner = SelfTestRunner(manager, manager.bus)
    report_path = tmp_path / "selftest_failures.json"
    monkeypatch.setattr(selftest_module, "_failure_log_path", lambda: report_path)
    progress: list[tuple[int, int]] = []
    report = runner.run(
        timeout=0.1,
        progress_cb=lambda done, total: progress.append((done, total)),
    )
    assert "[SKIP] Windows only" in report
    assert "[SKIP] Mac disabled — disabled by operator configuration" in report
    assert "[SKIP] Mac Chill paused — paused by Chill Mode" in report
    assert "Result: 1 passed, 1 failed, 3 skipped." in report
    assert {row["module"] for row in runner.last_skips} == {
        "Windows only", "Mac disabled", "Mac Chill paused",
    }
    assert runner.last_failures == [{
        "module": "Mac observe",
        "detail": "status=stopped, health=100%",
        "repairable": False,
    }]
    assert progress == sorted(progress)
    assert progress[-1] == (5, 5)
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert payload["skipped"] == 3
    assert payload["skips"] == runner.last_skips
    assert payload["failures"] == runner.last_failures
    assert not any(
        event.module == "Self-Test" and "Windows only" in event.message
        for event in manager.bus.recent(20)
    )

    class SafeMac(BaseModule):
        name = "Safe Mac lifecycle"
        supported_platforms = ("macos",)

        def run(self) -> None:
            return

    safe = SafeMac()
    assert runner._is_repairable(safe, "status=stopped, health=100%")
    assert not runner._is_repairable(safe, "test timed out after 1s")

    # An explicit targeted diagnostic still runs for an operator-disabled
    # native module; only the all-module dashboard sweep treats it as a skip.
    targeted = SelfTestRunner(manager, manager.bus)
    targeted_report = targeted.run(names=[disabled.name], timeout=0.1)
    assert "[FAIL] Mac disabled" in targeted_report
    assert "[SKIP] Mac disabled" not in targeted_report
    assert targeted.last_failures[0]["repairable"] is False


def test_normalized_sensor_event_round_trip_and_bounds() -> None:
    event = SensorEvent(
        platform="darwin",
        sensor="angerona.macos.observe",
        kind="process",
        action="start",
        event_id="a" * 32,
        observed_at=123.0,
        process={
            "pid": 42,
            "name": "safe-app",
            "command_line_collected": False,
        },
        privacy_classes=("process",),
    )
    restored = SensorEvent.from_dict(event.as_dict())
    assert restored.as_dict() == event.as_dict()
    bus_event = restored.to_event("macOS Observe Sensor")
    assert bus_event.details["sensor_event"]["platform"] == "macos"
    with pytest.raises(SensorEventError, match="exceeds"):
        SensorEvent(
            platform="macos",
            sensor="x",
            kind="process",
            action="start",
            process={"name": "x" * 5000},
        )


def test_macos_observe_baselines_before_emitting_new_activity() -> None:
    processes = [{
        "pid": 10,
        "ppid": 1,
        "name": "baseline",
        "executable": "/usr/bin/baseline",
        "create_time": 10.0,
        "command_line_collected": False,
    }]
    connections = [{
        "pid": 10,
        "local": "10.0.0.2:50000",
        "remote": "203.0.113.7:443",
        "transport": "tcp",
        "status": "established",
    }]
    collector = MacOSObserveCollector(
        lambda: list(processes),
        lambda: list(connections),
        network_every=1,
        clock=lambda: 100.0,
    )
    assert collector.poll() == []

    processes.append({
        "pid": 11,
        "ppid": 10,
        "name": "new-app",
        "executable": "/Applications/New.app/Contents/MacOS/New",
        "create_time": 20.0,
        "command_line_collected": False,
    })
    connections.append({
        "pid": 11,
        "local": "10.0.0.2:50001",
        "remote": "198.51.100.8:443",
        "transport": "tcp",
        "status": "established",
    })
    events = collector.poll()
    assert {(event.kind, event.action) for event in events} == {
        ("process", "start"),
        ("network", "connect"),
    }
    assert all(
        "command_line" not in event.process or
        event.process.get("command_line_collected") is False
        for event in events
    )

    degraded = MacOSObserveCollector(
        lambda: list(processes),
        lambda: (_ for _ in ()).throw(PermissionError("denied")),
        network_every=1,
    )
    assert degraded.poll() == []
    assert degraded.degraded_reasons
    assert "network observation unavailable" in degraded.degraded_reasons[0]


def test_native_bridge_authenticates_fresh_events_and_blocks_replay() -> None:
    key = b"k" * 32
    event = SensorEvent(
        platform="macos",
        sensor="angerona.endpoint-security",
        kind="process",
        action="exec",
        event_id="b" * 32,
        observed_at=1000.0,
        process={"pid": 7, "name": "launchd"},
    )
    packet = encode_for_test(
        event,
        key,
        sent_at=1000.0,
        nonce="c" * 32,
    )
    bridge = AuthenticatedNativeBridge(key, clock=lambda: 1000.0)
    assert bridge.decode(packet).event_id == event.event_id
    with pytest.raises(NativeBridgeError, match="replay"):
        bridge.decode(packet)


def test_native_bridge_rejects_tampering() -> None:
    key = b"z" * 32
    event = SensorEvent(
        platform="macos",
        sensor="angerona.endpoint-security",
        kind="file",
        action="write",
        event_id="d" * 32,
        observed_at=2000.0,
        file={"path": "/tmp/example"},
    )
    packet = json.loads(
        encode_for_test(event, key, sent_at=2000.0, nonce="e" * 32)
    )
    packet["event"]["action"] = "unlink"
    tampered = json.dumps(packet, separators=(",", ":")).encode()
    bridge = AuthenticatedNativeBridge(key, clock=lambda: 2000.0)
    with pytest.raises(NativeBridgeError, match="signature"):
        bridge.decode(tampered)
    nonfinite = encode_for_test(
        event,
        key,
        sent_at=float("nan"),
        nonce="f" * 32,
    )
    with pytest.raises(NativeBridgeError, match="sent_at"):
        bridge.decode(nonfinite)


def test_macos_secret_store_uses_keychain_without_writing_a_file(
    monkeypatch,
    tmp_path: Path,
) -> None:
    from angerona.core import secure_store
    from angerona.platforms.macos import keychain

    stored: dict[str, bytes] = {}
    monkeypatch.setattr(secure_store.sys, "platform", "darwin")
    monkeypatch.setattr(
        keychain,
        "read_blob",
        lambda service, account: stored.get(f"{service}:{account}"),
    )
    monkeypatch.setattr(
        keychain,
        "write_blob",
        lambda service, account, payload: stored.__setitem__(
            f"{service}:{account}", payload
        ),
    )

    reference = secure_store.write_secret_map({"TEST_SECRET": "value"}, tmp_path)
    assert secure_store.read_secret_map(tmp_path) == {"TEST_SECRET": "value"}
    assert reference == tmp_path / "secrets.keychain-reference"
    assert not reference.exists()
    os.environ.pop("TEST_SECRET", None)


def test_macos_secret_write_refuses_to_replace_an_unreadable_keychain_item(
    monkeypatch,
    tmp_path: Path,
) -> None:
    from angerona.core import secure_store
    from angerona.platforms.macos import keychain

    writes: list[bytes] = []
    monkeypatch.setattr(secure_store.sys, "platform", "darwin")
    monkeypatch.setattr(
        keychain,
        "read_blob",
        lambda _service, _account: (_ for _ in ()).throw(
            keychain.KeychainError("locked")
        ),
    )
    monkeypatch.setattr(
        keychain,
        "write_blob",
        lambda _service, _account, payload: writes.append(payload),
    )

    with pytest.raises(RuntimeError, match="refusing to overwrite"):
        secure_store.write_secret_map({"TEST_SECRET": "replacement"}, tmp_path)
    assert writes == []
