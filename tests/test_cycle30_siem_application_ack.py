from __future__ import annotations

import json

import pytest

from angerona.core.durable_outbox import DurableOutbox
from angerona.modules import siem_forwarder
from angerona.modules.siem_forwarder import SIEMForwarderModule


class _Response:
    def __init__(self, receipt: dict, status: int = 200) -> None:
        self.status = status
        self._body = json.dumps(receipt).encode("utf-8")

    def read(self, _limit: int) -> bytes:
        return self._body


class _Connection:
    response = _Response({"accepted": True, "ack_id": "event-1"})
    instances: list["_Connection"] = []

    def __init__(self, host, port, *, timeout, context) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.context = context
        self.request_args = None
        self.closed = False
        self.instances.append(self)

    def request(self, *args, **kwargs) -> None:
        self.request_args = (args, kwargs)

    def getresponse(self):
        return self.response

    def close(self) -> None:
        self.closed = True


def _patch_https(monkeypatch) -> None:
    _Connection.instances.clear()
    monkeypatch.setattr(siem_forwarder.ssl, "create_default_context", lambda **_kwargs: object())
    monkeypatch.setattr(siem_forwarder.http.client, "HTTPSConnection", _Connection)


def test_https_requires_exact_idempotent_application_ack(monkeypatch) -> None:
    _patch_https(monkeypatch)
    module = SIEMForwarderModule()
    module.host = "siem.example"
    module.port = 443

    module._send_https("CEF:payload", "event-1")

    connection = _Connection.instances[-1]
    assert connection.closed
    args, kwargs = connection.request_args
    assert args[:2] == ("POST", "/api/events")
    assert kwargs["headers"]["Idempotency-Key"] == "event-1"
    assert json.loads(kwargs["body"])["id"] == "event-1"


def test_mismatched_https_ack_is_rejected_and_row_remains(tmp_path, monkeypatch) -> None:
    _patch_https(monkeypatch)
    _Connection.response = _Response({"accepted": True, "ack_id": "other-event"})
    module = SIEMForwarderModule()
    module.host = "siem.example"
    module.port = 443
    module.proto = "https"
    module._outbox = DurableOutbox(tmp_path / "siem.sqlite3", b"s" * 32)
    module._outbox.enqueue("event-1", {"cef": "CEF:payload"})

    module._drain_outbox()

    assert module._application_acks == 0
    assert module._fails == 1
    assert module._outbox.stats().pending == 1
    module._outbox.close()


def test_exact_https_ack_deletes_durable_row(tmp_path, monkeypatch) -> None:
    _patch_https(monkeypatch)
    _Connection.response = _Response({"accepted": True, "ack_id": "event-1"})
    module = SIEMForwarderModule()
    module.host = "siem.example"
    module.port = 443
    module.proto = "https"
    module._outbox = DurableOutbox(tmp_path / "siem.sqlite3", b"s" * 32)
    module._outbox.enqueue("event-1", {"cef": "CEF:payload"})

    module._drain_outbox()

    assert module._application_acks == 1
    assert module._sent == 1
    assert module._outbox.stats().pending == 0
    module._outbox.close()


def test_unsafe_https_path_is_rejected(monkeypatch) -> None:
    _patch_https(monkeypatch)
    monkeypatch.setenv("ANGERONA_SIEM_HTTPS_PATH", "//attacker.example/override")
    module = SIEMForwarderModule()
    module.host = "siem.example"
    module.port = 443

    with pytest.raises(ValueError, match="bounded absolute path"):
        module._send_https("CEF:payload", "event-1")
    assert not _Connection.instances
