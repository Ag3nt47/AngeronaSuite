from __future__ import annotations

import importlib
import json
import os
import socket
import sys
import threading
import time
import types
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from angerona.core import fleet_service
from angerona.core.fleet_control_plane import FleetControlPlane
from angerona.core.fleet_service import FleetLoopbackService, sign_request


def _wait_for_handlers(service: FleetLoopbackService, count: int = 1) -> None:
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        server = service._server
        if server is not None and server._active_handlers == count:
            return
        time.sleep(0.005)
    raise AssertionError(f"Fleet handler count did not reach {count}")


def _partial_request(port: int) -> socket.socket:
    connection = socket.create_connection(("127.0.0.1", port), timeout=2)
    connection.sendall(
        b"POST /v1/tenants/tenant-a/devices HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\nContent-Type: application/json\r\n"
        b"Content-Length: 100\r\n\r\n{}"
    )
    return connection


def _signed_get(port: int, key: bytes, path: str, nonce: str):
    headers = sign_request(key, "GET", path, nonce=nonce)
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", headers=headers
    )
    return urllib.request.urlopen(request, timeout=2)


def test_partial_requests_repeatably_drain_and_release_replay_ledger(tmp_path):
    for attempt in range(15):
        root = tmp_path / str(attempt)
        plane = FleetControlPlane(root / "fleet.db", {"tenant-a": b"a" * 32})
        service = FleetLoopbackService(
            plane,
            b"s" * 32,
            root / "replay",
            port=0,
            client_timeout_seconds=30,
        )
        blocker = _partial_request(service.start())
        _wait_for_handlers(service)
        try:
            started = time.monotonic()
            assert service.stop(timeout=0.35)
            assert time.monotonic() - started < 1.0
            assert service._server is None
            assert service.auth._replay._db is None
            ledger = root / "replay.sqlite3"
            moved = root / "replay.closed.sqlite3"
            os.replace(ledger, moved)
            os.replace(moved, ledger)
        finally:
            blocker.close()
            service.stop()
            plane.close()


def test_shutdown_covers_handler_setup_race(tmp_path, monkeypatch):
    original_reader = fleet_service._ShutdownAwareSocketReader

    for attempt in range(10):
        entered = threading.Event()
        release = threading.Event()

        class PausedSetupReader(original_reader):
            def __init__(self, *args, **kwargs):
                entered.set()
                assert release.wait(2.0)
                super().__init__(*args, **kwargs)

        monkeypatch.setattr(
            fleet_service, "_ShutdownAwareSocketReader", PausedSetupReader
        )
        root = tmp_path / str(attempt)
        plane = FleetControlPlane(root / "fleet.db", {"tenant-a": b"a" * 32})
        service = FleetLoopbackService(
            plane, b"s" * 32, root / "replay", port=0
        )
        blocker = socket.create_connection(
            ("127.0.0.1", service.start()), timeout=2
        )
        assert entered.wait(2.0)
        result: list[bool] = []
        stopper = threading.Thread(
            target=lambda: result.append(service.stop(timeout=0.75))
        )
        stopper.start()
        assert service._server is not None
        assert service._server._shutdown_event.wait(1.0)
        release.set()
        stopper.join(2.0)
        try:
            assert not stopper.is_alive()
            assert result == [True]
            assert service.auth._replay._db is None
        finally:
            release.set()
            blocker.close()
            service.stop()
            plane.close()


def test_replay_survives_partial_request_shutdown(tmp_path):
    key = b"s" * 32
    path = "/v1/tenants/tenant-a/devices"
    nonce = "cycle-seven-replay-nonce-12345"
    plane = FleetControlPlane(tmp_path / "fleet.db", {"tenant-a": b"a" * 32})
    service = FleetLoopbackService(
        plane, key, tmp_path / "replay", port=0, client_timeout_seconds=30
    )
    port = service.start()
    assert json.load(_signed_get(port, key, path, nonce))["ok"]
    blocker = _partial_request(port)
    _wait_for_handlers(service)
    try:
        assert service.stop(timeout=0.5)
        assert service.auth._replay._db is None
        with pytest.raises(urllib.error.HTTPError) as replayed:
            _signed_get(service.start(), key, path, nonce)
        assert replayed.value.code == 401
    finally:
        blocker.close()
        service.stop()
        plane.close()


def test_legacy_engine_defaults_use_canonical_data_root(tmp_path, monkeypatch):
    root = tmp_path / "runtime"
    monkeypatch.setenv("ANGERONA_DATA", str(root))
    monkeypatch.delenv("EDR_FLIGHT_DB", raising=False)

    defense = importlib.reload(importlib.import_module(
        "angerona.engines.unified_defense_engine"
    ))
    viewer = importlib.reload(importlib.import_module(
        "angerona.engines.unified_edr"
    ))
    persistence = importlib.reload(importlib.import_module(
        "angerona.engines.persistence"
    ))

    assert defense.STATUS_FILE == root / "edr_status.json"
    assert viewer.STATUS_FILE == root / "edr_status.json"
    assert persistence.DB_PATH == root / "ude_telemetry.db"


def test_relative_flight_recorder_override_stays_under_data_root(
    tmp_path, monkeypatch
):
    root = tmp_path / "runtime"
    monkeypatch.setenv("ANGERONA_DATA", str(root))
    monkeypatch.setenv("EDR_FLIGHT_DB", "legacy/custom.db")
    persistence = importlib.reload(importlib.import_module(
        "angerona.engines.persistence"
    ))
    assert persistence.DB_PATH == root / "legacy" / "custom.db"


def test_defense_payload_is_staged_in_runtime_temp_and_removed(
    tmp_path, monkeypatch
):
    class FakeBaseModel:
        def __init__(self, **values):
            self.__dict__.update(values)

        def model_dump(self):
            return dict(self.__dict__)

    pydantic = types.ModuleType("pydantic")
    pydantic.BaseModel = FakeBaseModel
    pydantic.Field = lambda **_kwargs: None
    monkeypatch.setitem(sys.modules, "pydantic", pydantic)
    monkeypatch.setitem(sys.modules, "ollama", types.ModuleType("ollama"))
    sys.modules.pop("angerona.engines.defense_monitor", None)
    monitor = importlib.import_module("angerona.engines.defense_monitor")
    runtime_tmp = tmp_path / "runtime" / "tmp"
    runtime_tmp.mkdir(parents=True)
    observed: dict[str, object] = {}

    def fake_run_hidden(command):
        payload = Path(command[-1])
        observed["command"] = command
        observed["payload"] = payload
        observed["data"] = json.loads(payload.read_text(encoding="utf-8"))

    monkeypatch.setattr(monitor, "runtime_temp_dir", lambda: runtime_tmp)
    monkeypatch.setattr(monitor, "run_hidden", fake_run_hidden)
    incident = monitor.SecurityIncident(
        threat_detected=True,
        category="Malicious Process",
        severity="High",
        target_identifier="1234",
        reasoning="focused remediation test",
        recommended_action="Kill Process",
    )

    monitor.trigger_mitigation_gate(incident)

    payload = observed["payload"]
    assert isinstance(payload, Path)
    assert payload.parent == runtime_tmp
    assert not payload.exists()
    command = observed["command"]
    assert "-Command" not in command
    assert command[-2] == "-PayloadPath"
    assert observed["data"]["target_identifier"] == "1234"
