from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import struct
import threading
import time
from types import SimpleNamespace

import pytest

from angerona.core.engine_control import EngineControl
from angerona.core import engine_transport as transport
from angerona.core.engine_transport import EngineError, EngineServer, exchange, read_discovery
from angerona.core.eventbus import Event, EventBus, Severity
from angerona.core.module_base import BaseModule
from angerona.core.persistent_engine import EngineClient


class SampleModule(BaseModule):
    name = "Sample sensor"

    def self_test(self):
        return True, "sample check passed"


class Manager:
    def __init__(self):
        self.module = SampleModule()
        self.modules = {self.module.name: self.module}
        self.enabled = True
        self.restarts = []

    def module_usage(self, name):
        return SimpleNamespace(enabled=self.enabled, eligible=True, state="enabled", reason="Test sensor")

    def is_enabled(self, name):
        return self.enabled

    def set_enabled(self, name, enabled):
        self.enabled = enabled

    def restart_module_generation(self, name, module, generation):
        self.restarts.append((name, module, generation))
        return True


@pytest.fixture
def running(tmp_path):
    control = EngineControl(threading.Event())
    manager = Manager()
    config = SimpleNamespace(eco_mode=False, alert_retention_enabled=True,
                             alert_retention_days=30, alert_retention_max_mib=256,
                             save=lambda: None)
    control.attach(manager, EventBus(), config, None)
    server = EngineServer(tmp_path / "engine", control.dispatch)
    control.instance = server.instance
    server.start()
    control.ready()
    client = EngineClient(tmp_path / "engine")
    try:
        yield control, manager, server, client
    finally:
        control.close()
        server.close()


def wait_operation(client, receipt):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        status = client.operation_status(receipt["id"])
        if status["state"] in {"completed", "failed"}:
            return status
        time.sleep(0.01)
    pytest.fail("operation did not finish")


def test_real_loopback_reconnect_and_gui_detach_leave_engine_alive(running):
    control, manager, server, client = running
    first = client.status()
    del client  # Desktop client lifetime has no authority to stop protection.
    second = EngineClient(server.directory).status()
    assert first["instance"] == second["instance"] == server.instance
    assert second["state"] == "ready"
    assert not control.stop.is_set()
    assert second["enabled_count"] == 1


def test_discovery_is_private_and_never_exposed_in_status(running):
    _control, _manager, server, client = running
    transport.verify_private(server.directory, directory=True)
    transport.verify_private(server.directory / "endpoint.json")
    record = read_discovery(server.directory)
    assert record["key"] not in json.dumps(client.status())
    assert record["key"] not in repr(client)


def test_actual_challenge_authentication_rejects_wrong_key_without_dispatch(running):
    _control, _manager, server, client = running
    record = read_discovery(server.directory)
    with socket.create_connection(("127.0.0.1", record["port"]), timeout=2) as sock:
        hello = transport.receive(sock, 8192)
        body = {"instance": hello["instance"], "challenge": hello["challenge"],
                "nonce": "a" * 32, "request": {"operation": "stop_engine", "confirmation": "stop-protection"}}
        transport.send(sock, transport._wrap(body, b"x" * 32, b"request\0"), 8192)
        assert sock.recv(1) == b""
    assert client.status()["state"] == "ready"


def test_replay_is_rejected_on_a_new_connection(running):
    _control, _manager, server, client = running
    record = read_discovery(server.directory)
    key = bytes.fromhex(record["key"])
    with socket.create_connection(("127.0.0.1", record["port"]), timeout=2) as sock:
        hello = transport.receive(sock, 8192)
        request = transport._wrap({"instance": server.instance, "challenge": hello["challenge"],
                                   "nonce": "b" * 32, "request": {"operation": "status"}}, key, b"request\0")
        transport.send(sock, request, 8192)
        assert transport.receive(sock, transport.MAX_RESPONSE)["body"]["ok"] is True
    with socket.create_connection(("127.0.0.1", record["port"]), timeout=2) as sock:
        fresh = transport.receive(sock, 8192)
        assert fresh["challenge"] != hello["challenge"]
        transport.send(sock, request, 8192)
        assert sock.recv(1) == b""
    assert client.status()["state"] == "ready"


def test_frame_bounds_fail_before_body_allocation(running):
    _control, _manager, server, client = running
    record = read_discovery(server.directory)
    with socket.create_connection(("127.0.0.1", record["port"]), timeout=2) as sock:
        transport.receive(sock, 8192)
        sock.sendall(struct.pack("!I", 2**31))
        assert sock.recv(1) == b""
    assert client.status()["state"] == "ready"


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"a":NaN}', b'[]', b'null'])
def test_strict_json(raw):
    with pytest.raises(EngineError):
        transport.decode(raw)


@pytest.mark.parametrize("payload", [
    {"operation": "shell", "command": "anything"},
    {"operation": "status", "path": "secret"},
    {"operation": "events", "cursor": True},
    {"operation": "settings_patch", "settings": {"ollama_host": "https://bad"}},
    {"operation": "settings_patch", "settings": {"alert_retention_days": True}},
    {"operation": "settings_patch", "settings": {"alert_retention_days": 0}},
    {"operation": "settings_patch", "settings": {"alert_retention_max_mib": 16385}},
    {"operation": "module_restart", "name": "Missing"},
    {"operation": "module_enable", "name": "Sample sensor", "enabled": "false"},
    {"operation": "stop_engine", "confirmation": True},
])
def test_closed_catalog_rejects_unknown_or_malformed_controls(running, payload):
    _control, _manager, server, _client = running
    with pytest.raises(EngineError, match="Request rejected"):
        exchange(server.directory, payload)


def test_typed_controls_and_generation_bound_restart(running):
    control, manager, _server, client = running
    receipt = client.restart_module("Sample sensor")
    assert wait_operation(client, receipt)["result"] == {"restarted": True}
    assert manager.restarts == [("Sample sensor", manager.module, manager.module.lifecycle_generation)]
    result = wait_operation(client, client.self_test("Sample sensor"))
    assert result["result"]["passed"] is True
    assert wait_operation(client, client.set_module("Sample sensor", False))["result"]["enabled"] is False
    with pytest.raises(EngineError):
        client.restart_module("Sample sensor")
    result = wait_operation(client, client.patch_settings({"alert_retention_days": 7}))
    assert result["result"]["settings"]["alert_retention_days"] == 7
    assert control.config.alert_retention_days == 7


def test_events_are_paginated_without_skips_and_exclude_raw_details(running):
    control, _manager, _server, client = running
    for index in range(450):
        control.bus.publish(Event(module="source", message=str(index), severity=Severity.MEDIUM,
                                  details={"token": "DO_NOT_EXPORT"}))
    cursor = 0
    seen = []
    for _ in range(3):
        result = client.events(cursor)
        cursor = result["cursor"]
        seen.extend(item["revision"] for item in result["events"])
        assert "DO_NOT_EXPORT" not in json.dumps(result)
    assert seen == list(range(1, 451))
    assert cursor == 450


def test_escaped_unicode_event_pages_fit_transport_and_drain_every_revision(running):
    control, _manager, _server, client = running
    for _ in range(200):
        control.bus.publish(Event(module="source", message="\U0001f680" * 1000, severity=Severity.HIGH))
    cursor = 0
    observed = []
    while cursor < 200:
        result = client.events(cursor)
        assert len(transport.canonical(result)) < transport.MAX_RESPONSE - 1024
        assert result["cursor"] > cursor
        cursor = result["cursor"]
        observed.extend(item["revision"] for item in result["events"])
    assert observed == list(range(1, 201))


def test_smallest_retention_quota_matches_core_policy(running):
    control, _manager, _server, client = running
    result = wait_operation(client, client.patch_settings({"alert_retention_max_mib": 8}))
    assert result["state"] == "completed"
    assert control.config.alert_retention_max_mib == 8


def test_failed_setting_save_rolls_back_live_config(running):
    control, _manager, _server, client = running
    def fail():
        raise OSError("disk full")
    control.config.save = fail
    status = wait_operation(client, client.patch_settings({"alert_retention_days": 10}))
    assert status["state"] == "failed"
    assert control.config.alert_retention_days == 30


def test_queue_and_receipts_are_bounded():
    control = EngineControl(threading.Event())
    manager = Manager()
    control.attach(manager, EventBus(), SimpleNamespace(eco_mode=False), None)
    control.state = "ready"  # Leave worker stopped to fill its finite queue.
    for _ in range(16):
        control.dispatch({"operation": "module_restart", "name": "Sample sensor"})
    with pytest.raises(EngineError, match="queue is full"):
        control.dispatch({"operation": "module_restart", "name": "Sample sensor"})
    assert len(control._operations) == 16


def test_explicit_stop_confirmation_sets_shared_stop_event(running):
    control, _manager, _server, client = running
    receipt = client.stop_engine(confirmation="stop-protection")
    assert wait_operation(client, receipt)["state"] == "completed"
    assert control.stop.is_set()


def test_discovery_rejects_hardlinks(tmp_path):
    directory = transport.private_directory(tmp_path / "engine")
    path = directory / "endpoint.json"
    path.write_text("{}", encoding="utf-8")
    if os.name != "nt":
        path.chmod(0o600)
    os.link(path, directory / "other")
    with pytest.raises(EngineError, match="Unsafe"):
        read_discovery(directory)


def test_service_templates_use_exact_argv_and_bounded_restart():
    from angerona.core.engine_service import launchd_plist, systemd_unit
    import plistlib
    command = ["/opt/with spaces/python", "-I", "-c", "print('$HOME %U')"]
    unit = systemd_unit(command, Path("/private/state"))
    assert "Restart=on-failure" in unit and "StartLimitBurst=3" in unit
    assert "$$HOME %%U" in unit and "NoNewPrivileges=yes" in unit
    document = plistlib.loads(launchd_plist(command, Path("/private/state")))
    assert document["ProgramArguments"] == command
    assert document["KeepAlive"] == {"SuccessfulExit": False}


def test_source_scm_host_fails_before_native_dispatch():
    from angerona.core.engine_windows_service import require_package_service
    with pytest.raises(PermissionError, match="signed frozen"):
        require_package_service()


def test_spawn_environment_excludes_credentials_and_python_path(monkeypatch):
    from angerona.core.persistent_engine import _child_environment
    monkeypatch.setenv("OPENAI_API_KEY", "do-not-inherit")
    monkeypatch.setenv("PYTHONPATH", "untrusted")
    monkeypatch.setenv("ANGERONA_EXTERNAL_MODULES", "1")
    monkeypatch.setenv("SYSTEMROOT", "C:\\Windows")
    environment = _child_environment()
    assert "OPENAI_API_KEY" not in environment
    assert "PYTHONPATH" not in environment
    assert "ANGERONA_EXTERNAL_MODULES" not in environment
    assert environment["SYSTEMROOT"] == "C:\\Windows"
