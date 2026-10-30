"""Optional witnessing cannot delay protection or lose an uncertain reader."""
from __future__ import annotations

from dataclasses import replace
import json
from types import SimpleNamespace

import pytest

from angerona.core import recorder_integrity as enrollment
from angerona.core import recorder_integrity_runtime as runtime
from angerona.core.config import Config
from angerona.core.eventbus import EventBus, Severity
from angerona.core.recorder_epoch_worker import RecorderEpochStatus


def test_disabled_default_never_constructs_witness_worker_or_resolves_credentials(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, "RecorderEpochWorker", lambda **_kwargs: pytest.fail("disabled worker constructed"))
    monkeypatch.setattr(enrollment, "client_from_settings", lambda *_args: pytest.fail("credentials read"))
    config = Config(data_dir=tmp_path)
    assert enrollment.provider_from_config(config) is None
    owner = runtime.RecorderIntegrityRuntime(config, EventBus(), None)
    assert owner.latest_status().state == "disabled"
    assert not owner.start()
    assert owner.stop()
    assert not tuple(tmp_path.iterdir())


def test_enabled_malformed_enrollment_stays_held_and_resolution_is_lazy(tmp_path, monkeypatch):
    config = Config(data_dir=tmp_path, recorder_witness_enabled=True)
    calls = []
    def reject(*_args):
        calls.append("worker-resolve")
        raise enrollment.RecorderEnrollmentError("inert unavailable enrollment")
    monkeypatch.setattr(enrollment, "client_from_settings", reject)
    provider = enrollment.provider_from_config(config)
    assert provider.latest_status().state == "not-checked" and not calls
    with pytest.raises(enrollment.RecorderEnrollmentError):
        provider.read_recorder_head()
    assert calls == ["worker-resolve"] and provider.latest_status().state == "enrollment-held"


def test_recorder_request_key_is_scrubbed_even_when_protected_store_is_empty(tmp_path, monkeypatch):
    from angerona.core import secure_store
    import os
    monkeypatch.setenv(enrollment.KEY_NAME, "inert-parent-environment-value")
    monkeypatch.setattr(secure_store, "read_secret_map", lambda *_args: {})
    secure_store.load_into_environment(tmp_path)
    assert enrollment.KEY_NAME not in os.environ


def test_saved_public_settings_round_trip_without_changing_other_preferences(tmp_path, monkeypatch):
    from angerona.core import data_paths
    monkeypatch.setattr(data_paths, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(Config, "_load_dotenv", staticmethod(lambda *_args: None))
    monkeypatch.delenv("ANGERONA_ARIA_PUSH_URL", raising=False)
    config = Config(data_dir=tmp_path, ollama_model="operator-owned-choice", recorder_witness_archive_mib=8)
    config.save()
    saved = json.loads(config.settings_path.read_text())
    assert saved["recorder_witness_archive_mib"] == 8
    assert enrollment.KEY_NAME not in saved
    loaded = Config.load()
    assert loaded.ollama_model == "operator-owned-choice" and loaded.recorder_witness_archive_mib == 8
    # Invalid opt-in is a held enrollment, not silently disabled on load.
    saved.update(recorder_witness_enabled=True, recorder_witness_endpoint="http://127.0.0.1/bad",
                 recorder_witness_archive_mib=-1)
    config.settings_path.write_text(json.dumps(saved))
    held = Config.load()
    assert held.recorder_witness_enabled is True and held.recorder_witness_archive_mib == 16
    before = config.settings_path.read_bytes()
    with pytest.raises(enrollment.RecorderEnrollmentError):
        held.save()
    assert config.settings_path.read_bytes() == before


@pytest.mark.parametrize("changes", [
    {"recorder_witness_enabled": "true"}, {"recorder_witness_archive_mib": True},
    {"recorder_witness_archive_mib": 65}, {"recorder_witness_endpoint": "https://127.0.0.1/v1/authority"},
    {"recorder_witness_endpoint": "https://169.254.169.254/v1/authority"},
    {"recorder_witness_endpoint": "https://8.8.8.8/v1/authority"},
    {"recorder_witness_endpoint": "https://192.168.1.2/v1/authority?secret=x"},
    {"recorder_witness_client_key_path": "relative-key.pem"},
    {"recorder_witness_authority_public_key": "<html>untrusted</html>"},
])
def test_invalid_enrollment_is_refused_before_settings_replacement(changes):
    with pytest.raises(enrollment.RecorderEnrollmentError):
        enrollment.validate_settings({**enrollment.DEFAULTS, **changes})


def test_owner_retained_when_start_or_retirement_is_uncertain(tmp_path, monkeypatch):
    class Worker:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
        def start(self):
            raise RuntimeError("inert failed thread start")
        def request_stop(self):
            self.stopped = True
        def stop(self, timeout):
            self.stopped = True
            return False
    monkeypatch.setattr(runtime, "RecorderEpochWorker", Worker)
    owner = runtime.RecorderIntegrityRuntime(Config(data_dir=tmp_path, recorder_witness_enabled=True), EventBus(), object())
    exact = owner.worker
    with pytest.raises(RuntimeError):
        owner.start()
    owner.request_stop()
    assert owner.stop() is False and owner.worker is exact and exact.stopped


def test_status_transitions_report_loss_without_trust_or_response_authority(tmp_path):
    bus = EventBus()
    events = []
    bus.subscribe(events.append)
    owner = runtime.RecorderIntegrityRuntime(Config(data_dir=tmp_path), bus, None)
    loss = RecorderEpochStatus(state="coverage-loss", reason="Previously signed rows are unavailable", known_missing_rows=3)
    owner._observe(loss)
    owner._observe(replace(loss, revision=2))
    owner._observe(replace(loss, state="changed", changed_rows=1))
    assert len(events) == 2 and events[0].severity == Severity.MEDIUM and events[1].severity == Severity.HIGH
    assert events[0].details["missing_rows"] == 3
    assert not any(event.details["response_authorized"] for event in events)
    assert all(event.details["response_authority"] == "unattributed-advisory" for event in events)


def test_factory_composes_real_pinned_transport_and_remote_floor_with_separate_keys(tmp_path, monkeypatch):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from angerona.core import personal_sentinel_authority as sdk, secure_store
    from angerona.core.sentinel_remote_floor import RawSignedFloorClient
    request_key, authority_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    private = request_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()).decode("ascii")
    def read(names, root, strict):
        assert names == (enrollment.KEY_NAME,) and root == tmp_path and strict is True
        return {enrollment.KEY_NAME: private}
    monkeypatch.setattr(secure_store, "read_secret_values", read)
    monkeypatch.setattr(sdk.StandardHttpsGatewayTransport, "send", lambda *_args: pytest.fail("unexpected network access"))
    values = {**enrollment.DEFAULTS, "recorder_witness_enabled": True, "recorder_witness_independent_host": True,
        "recorder_witness_endpoint": "https://192.168.10.12/v1/authority",
        "recorder_witness_certificate_sha256": "a" * 64,
        "recorder_witness_authority_public_key": authority_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii"),
        "recorder_witness_installation_id": "b" * 32, "recorder_witness_client_id": "c" * 32,
        "recorder_witness_client_certificate_path": str(tmp_path / "enrolled-client.pem"),
        "recorder_witness_client_key_path": str(tmp_path / "client-tls-key.pem")}
    client = enrollment.client_from_settings(values, tmp_path)
    assert type(client) is sdk.PersonalSentinelAuthorityClient
    assert type(client.transport) is sdk.PinnedHttpsSentinelTransport
    assert type(client.response_floor) is RawSignedFloorClient
    assert client.response_floor.transport is client.transport
    # A different label cannot turn the host's signing key into an independent authority.
    values["recorder_witness_authority_public_key"] = request_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
    with pytest.raises(ValueError):
        enrollment.client_from_settings(values, tmp_path)
    assert not tuple(tmp_path.iterdir())


def test_headless_pending_integrity_reader_retains_sqlite_and_graph(monkeypatch):
    from angerona.core import headless
    monkeypatch.setattr(headless, "_HEADLESS_RETIREMENT_HOLD", None)
    import threading
    resource = headless._HeadlessResources(threading.Event(), None, SimpleNamespace())
    calls = []
    resource.storage = SimpleNamespace(close=lambda: calls.append("storage-closed"))
    resource.recorder_integrity = SimpleNamespace(request_stop=lambda: calls.append("reader-fenced"), stop=lambda **_kwargs: False)
    with pytest.raises(headless.HeadlessRetirementPending):
        resource.close()
    assert calls == ["reader-fenced"]
    assert headless._HEADLESS_RETIREMENT_HOLD is resource


def test_gui_stop_never_closes_authoritative_sqlite_with_live_integrity_reader(tmp_path, monkeypatch):
    from angerona.app import AngeronaApp
    calls = []
    inert = SimpleNamespace(stop=lambda **_kwargs: True)
    window = SimpleNamespace(_close_operations_service=lambda: None)
    app = SimpleNamespace(reporter=inert, _mcp=None, _fleet_service=None, _fleet_plane=None,
        _endpoint_identity=None, manager=SimpleNamespace(stop_all=lambda: None), window=window,
        sentinel_lens_service=None, process_baseline=None, flight_recorder_worker=inert,
        evidence_ingestion=None, evidence_store=None,
        storage=SimpleNamespace(close=lambda: calls.append("storage-closed")),
        recorder_integrity_runtime=SimpleNamespace(stop=lambda **_kwargs: False))
    AngeronaApp._shutdown_services_and_stores(app)
    assert calls == []
