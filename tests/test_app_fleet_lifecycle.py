import os
from pathlib import Path
from types import SimpleNamespace

from angerona.app import AngeronaApp


def _app(tmp_path: Path, *, enabled: bool = True):
    app = AngeronaApp.__new__(AngeronaApp)
    app.config = SimpleNamespace(
        fleet_service_enabled=enabled,
        fleet_service_port=0,
        fleet_tenant_id="local",
        data_dir=tmp_path,
    )
    app._fleet_plane = None
    app._fleet_service = None
    app._endpoint_identity = None
    app._blackbox_note = lambda _message: None
    return app


def test_app_starts_and_stops_opt_in_fleet_service(tmp_path, monkeypatch):
    monkeypatch.setenv("ANGERONA_FLEET_SERVICE_KEY", "s" * 48)
    app = _app(tmp_path)
    assert app._start_fleet_service()
    assert app._fleet_service is not None
    assert app._endpoint_identity is not None
    snapshot = app.enterprise_runtime_snapshot()
    assert snapshot["fleet_service"] == "running"
    assert snapshot["fleet_transport"] == "loopback"
    assert snapshot["endpoint_identity"] == "active"
    assert snapshot["registered_devices"] == 1
    assert snapshot["fleet_ingestion"] == "unknown"
    assert snapshot["stored_events"] == 0
    assert snapshot["duplicate_retries"] == 0
    assert snapshot["uncertain_clock_events"] == 0
    assert len(snapshot["fleet_api_contract_sha256"]) == 64
    devices = app._fleet_plane.devices("local")
    assert devices[0].device_id == app._endpoint_identity.device_id
    assert devices[0].hostname_token.startswith("tok_")
    assert os.environ.get("COMPUTERNAME", "") not in devices[0].hostname_token
    assert app._fleet_service.stop()
    app._fleet_service = None
    app._fleet_plane.close()
    app._fleet_plane = None


def test_app_fleet_service_is_off_by_default(tmp_path, monkeypatch):
    monkeypatch.delenv("ANGERONA_FLEET_SERVICE_KEY", raising=False)
    app = _app(tmp_path, enabled=False)
    assert not app._start_fleet_service()
    assert app._fleet_service is None
    assert app._fleet_plane is None
    assert app._endpoint_identity is None


def test_app_fleet_service_fails_closed_without_protected_key(
    tmp_path, monkeypatch
):
    monkeypatch.delenv("ANGERONA_FLEET_SERVICE_KEY", raising=False)
    app = _app(tmp_path)
    messages = []
    app._blackbox_note = messages.append
    assert not app._start_fleet_service()
    assert app._fleet_service is None
    assert app._fleet_plane is None
    assert app._endpoint_identity is None
    assert messages == [
        "local fleet service unavailable (ValueError); see Startup Health for impact."
    ]
