from __future__ import annotations

import json
import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from angerona.core.config import Config
from angerona.core.durable_outbox import DurableOutbox
from angerona.core.eventbus import Event, EventBus, Severity
from angerona.modules.remote_bridge import RemoteBridge
from angerona.modules.siem_forwarder import SIEMForwarderModule


def test_integration_settings_round_trip_and_publish_nonsecrets(tmp_path, monkeypatch) -> None:
    for name in (
        "ANGERONA_SIEM_HOST",
        "ANGERONA_SIEM_PORT",
        "ANGERONA_SIEM_PROTO",
        "ANGERONA_BRIDGE_MODE",
        "ANGERONA_BRIDGE_PEER",
        "ANGERONA_IOC_FEED",
        "ANGERONA_IOC_FEED_SHA256",
    ):
        monkeypatch.delenv(name, raising=False)

    cfg = Config(data_dir=tmp_path)
    cfg.siem_host = "collector.example.test"
    cfg.siem_port = 6514
    cfg.siem_protocol = "tls"
    cfg.siem_min_severity = "HIGH"
    cfg.remote_bridge_mode = "SENDER"
    cfg.remote_bridge_peer = "receiver.example.test:47924"
    cfg.remote_bridge_node_id = "sensor-west"
    cfg.ioc_feed_url = "https://intel.example.test/iocs.json"
    cfg.ioc_feed_sha256 = "a" * 64
    cfg.save()

    persisted = json.loads(cfg.settings_path.read_text(encoding="utf-8"))
    assert persisted["siem_host"] == "collector.example.test"
    assert persisted["remote_bridge_peer"] == "receiver.example.test:47924"
    assert "ANGERONA_BRIDGE_KEY" not in persisted
    assert os.environ["ANGERONA_SIEM_HOST"] == "collector.example.test"
    assert os.environ["ANGERONA_BRIDGE_MODE"] == "SENDER"
    assert os.environ["ANGERONA_IOC_FEED_SHA256"] == "a" * 64

    assert persisted["siem_min_severity"] == "HIGH"


def test_integration_validation_refuses_implicit_plaintext_and_routable_bind(tmp_path) -> None:
    cfg = Config(data_dir=tmp_path)
    cfg.siem_protocol = "udp"
    with pytest.raises(ValueError, match="plaintext approval"):
        cfg.validate_integration_settings()

    cfg.siem_protocol = "tls"
    cfg.remote_bridge_mode = "RECEIVER"
    cfg.remote_bridge_bind = "0.0.0.0"
    with pytest.raises(ValueError, match="Non-loopback"):
        cfg.validate_integration_settings()

    cfg.remote_bridge_allow_nonloopback = True
    cfg.validate_integration_settings()


def test_remote_bridge_refuses_routable_listener_without_approval(monkeypatch) -> None:
    monkeypatch.setenv("ANGERONA_BRIDGE_BIND", "0.0.0.0")
    monkeypatch.setenv("ANGERONA_BRIDGE_PORT", "47924")
    monkeypatch.delenv("ANGERONA_BRIDGE_ALLOW_NONLOOPBACK", raising=False)
    module = RemoteBridge()
    module._mode = "RECEIVER"
    module._key = b"k" * 32
    module._crypto_ok = True
    monkeypatch.setattr(module, "sleep", lambda _seconds: module.stop())

    module.run()

    assert module.health == 40
    assert "non-loopback" in module.health_note
    assert module._srv is None


def test_settings_exposes_canonical_integrations_page(tmp_path) -> None:
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication, QLineEdit

    from angerona.gui.pages import SettingsDialog

    app = QApplication.instance() or QApplication([])
    dialog = SettingsDialog(Config(data_dir=tmp_path), lambda: None, lambda _t: None)
    try:
        assert dialog._select_tab("Integrations")
        assert dialog._siem_host.placeholderText()
        assert dialog._bridge_key.echoMode() == QLineEdit.Password
        assert dialog._ioc_sha256.placeholderText()
        assert "Integrations" in dialog._settings_sandbox_btn.text()
    finally:
        dialog.close()
        app.processEvents()


def test_remote_queue_integrity_survives_transport_key_rotation(
    tmp_path, monkeypatch
) -> None:
    from angerona.core import data_paths

    monkeypatch.setattr(data_paths, "data_dir", lambda: tmp_path)
    first = RemoteBridge()
    first._key = b"a" * 32
    sender = first._open_sender_outbox()
    sender.enqueue("pending", {"event": {"event_id": "1" * 64}}, now=10)
    sender.close()
    inbox = first._open_receiver_inbox()
    inbox.enqueue("delivered", {"payload_sha256": "2" * 64}, now=10)
    inbox.complete_pending("delivered")
    inbox.close()

    rotated = RemoteBridge()
    rotated._key = b"b" * 32
    sender = rotated._open_sender_outbox()
    assert [item.item_id for item in sender.claim("worker", now=20)] == ["pending"]
    sender.close()
    inbox = rotated._open_receiver_inbox()
    assert inbox.is_delivered("delivered")
    inbox.close()


def test_remote_auth_denial_flood_is_aggregated(monkeypatch) -> None:
    bridge = RemoteBridge()
    emitted: list[tuple] = []
    now = [1.0]
    monkeypatch.setattr(bridge, "emit", lambda *args, **kwargs: emitted.append((args, kwargs)))
    bridge._clock = lambda: now[0]

    for _ in range(10_000):
        bridge._record_auth_denial(("203.0.113.7", 1234), "invalid proof")

    assert bridge.denied == 10_000
    assert len(emitted) == 1
    now[0] = 12.0
    bridge._record_auth_denial(("203.0.113.7", 1234), "invalid proof")
    assert len(emitted) == 2
    assert emitted[-1][1]["suppressed_since_last"] == 9_999


def test_exporters_drain_before_staging_when_capacity_recovers(
    tmp_path, monkeypatch
) -> None:
    remote_bus = EventBus(ring_size=10, priority_ring_size=10)
    remote = RemoteBridge()
    remote._key = b"r" * 32
    remote.bind(remote_bus)
    remote._sender_outbox = DurableOutbox(
        tmp_path / "remote-full.sqlite3", b"q" * 32, max_items=100
    )
    for index in range(100):
        event_id = f"{index:064x}"
        remote._sender_outbox.enqueue(
            f"old-{index}", {"event": {"event_id": event_id}}, now=index
        )
    remote_bus.publish(Event("sensor", "new", Severity.HIGH, 200.0, {}))
    monkeypatch.setattr(remote, "_forward_payload", lambda *_args: True)

    remote._sender_delivery_cycle(("127.0.0.1", 47924))

    assert remote._bus_priority_revision == remote_bus.priority_revision()
    assert remote._sender_outbox.stats().pending == 0
    remote._sender_outbox.close()

    siem_bus = EventBus(ring_size=10)
    siem = SIEMForwarderModule()
    siem.bind(siem_bus)
    siem.min_sev = Severity.INFO
    siem._outbox = DurableOutbox(
        tmp_path / "siem-full.sqlite3", b"s" * 32, max_items=100
    )
    for index in range(100):
        siem._outbox.enqueue(f"old-{index}", {"cef": f"CEF:{index}"}, now=index)
    siem_bus.publish(Event("sensor", "new", Severity.HIGH, 200.0, {}))
    monkeypatch.setattr(siem, "_send", lambda _payload: None)

    siem._delivery_cycle()

    assert siem._bus_revision == siem_bus.revision()
    assert siem._outbox.stats().pending == 0
    siem._outbox.close()
